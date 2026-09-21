package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// deliveryTimeout bounds one destination's delivery attempt (SMTP
// handshake or webhook POST) -- not an operator-tunable setting, same
// rationale as cmd/server's other hardcoded internal timeouts (e.g.
// oidcTransactionTTL): nothing in the product spec calls for tuning it,
// and a stuck attempt must not stall the whole delivery job tick.
const deliveryTimeout = 10 * time.Second

// signatureHeader carries the webhook body's HMAC-SHA256 signature
// (hex-encoded, "sha256=" prefixed like GitHub's own webhook signature
// header) whenever Config.WebhookSecret is set -- absent entirely when
// it isn't, since an unsigned webhook to a destination that doesn't
// verify signatures is a deliberate, valid choice (see Config's own
// comment).
const signatureHeader = "X-Approve-Auth-Signature"

// Destination is where one application's notification should go --
// resolved by the caller (the delivery job) from that application's own
// notify_email/notify_webhook_url override, falling back to Config's
// defaults. Either field empty means that channel is skipped for this
// delivery, not an error.
type Destination struct {
	Email      string
	WebhookURL string
}

// Config is internal/notify's own subset of internal/config.Config --
// transport/credential settings only. EmailFrom and the default
// email/webhook destinations are NOT here: they're business-rule
// settings (migration 000019's global_settings, live-editable from the
// admin console's Settings page), resolved fresh per delivery batch by
// DeliverPending instead of fixed at construction time -- see its own
// comment.
type Config struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	// WebhookSecret, if set, HMAC-SHA256-signs every outbound webhook
	// body -- global only, shared across every application's webhook
	// (see internal/config.Config.NotifyWebhookSecret's own comment on
	// why this isn't a per-application secret). This one stays static
	// config, unlike EmailFrom/the defaults: it's a credential, and
	// secrets never move into a plain DB column.
	WebhookSecret string
	// AdminOrigin backs Event.AdminConsoleURL (endpoint-review.md F3):
	// the deployment's own configured admin console origin, never
	// requester-controlled input.
	AdminOrigin string
}

// Dispatcher delivers one Event to a Destination via email and/or
// webhook, whichever Destination fields are non-empty.
type Dispatcher struct {
	cfg        Config
	httpClient *http.Client
}

func New(cfg Config) *Dispatcher {
	return &Dispatcher{cfg: cfg, httpClient: &http.Client{Timeout: deliveryTimeout}}
}

// DeliverResult reports each channel's own outcome (endpoint-review.md
// F4: "track successful delivery separately for each channel and avoid
// replaying completed channels") -- Attempted is false for a channel
// Deliver never tried at all (Destination left it empty, or -- for
// email specifically -- SMTPHost isn't configured or emailFrom didn't
// resolve), distinct from Attempted-true-with-a-nil-error, which means
// it was tried and succeeded.
type DeliverResult struct {
	EmailAttempted   bool
	EmailErr         error
	WebhookAttempted bool
	WebhookErr       error
}

// Err joins both channels' errors (errors.Join of zero errors is nil),
// matching Deliver's old combined-error return for callers that don't
// need per-channel detail.
func (r DeliverResult) Err() error {
	return errors.Join(r.EmailErr, r.WebhookErr)
}

// Deliver attempts every channel Destination names, reporting each
// channel's own outcome so a caller can persist per-channel success
// and never re-attempt a channel that already succeeded on a prior
// call (endpoint-review.md F4). emailFrom is resolved by the caller
// from global_settings (DeliverPending, once per batch) -- if
// SMTPHost is configured but emailFrom resolves empty (nobody has set
// it on the Settings page yet), email is skipped with a log line
// rather than attempted with a malformed From address; this isn't
// treated as a delivery failure to retry, since retrying can't fix a
// missing setting.
func (d *Dispatcher) Deliver(ctx context.Context, emailFrom string, dest Destination, e Event) DeliverResult {
	var result DeliverResult
	if dest.Email != "" && d.cfg.SMTPHost != "" {
		if emailFrom == "" {
			log.Printf("notify: skipping email to %s: notify_email_from is not set (admin console Settings page)", dest.Email)
		} else {
			result.EmailAttempted = true
			if err := d.sendEmail(ctx, emailFrom, dest.Email, e); err != nil {
				result.EmailErr = fmt.Errorf("email: %w", err)
			}
		}
	}
	if dest.WebhookURL != "" {
		result.WebhookAttempted = true
		if err := d.sendWebhook(ctx, dest.WebhookURL, e); err != nil {
			result.WebhookErr = fmt.Errorf("webhook: %w", err)
		}
	}
	return result
}

// sendEmail replicates net/smtp.SendMail's own connect/STARTTLS/AUTH/
// MAIL/RCPT/DATA sequence manually rather than calling SendMail
// directly (endpoint-review.md F1/F4: "the inspected SMTP path ignores
// the provided context") -- SendMail has no context-aware entry point
// and no way to bound its dial or protocol exchange at all, so a
// hanging SMTP server could otherwise stall a delivery-job tick
// indefinitely. Dialing via ctx and setting a connection deadline from
// it (falling back to deliveryTimeout when ctx carries none) bounds the
// whole exchange the same way sendWebhook's http.Client timeout does.
func (d *Dispatcher) sendEmail(ctx context.Context, from, to string, e Event) error {
	msg := buildEmailMessage(from, to, e)
	addr := fmt.Sprintf("%s:%d", d.cfg.SMTPHost, d.cfg.SMTPPort)

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(deliveryTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("setting connection deadline for %s: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, d.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("starting SMTP session with %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: d.cfg.SMTPHost}); err != nil {
			return fmt.Errorf("STARTTLS with %s: %w", addr, err)
		}
	}
	if d.cfg.SMTPUsername != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", d.cfg.SMTPUsername, d.cfg.SMTPPassword, d.cfg.SMTPHost)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("authenticating to %s: %w", addr, err)
			}
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM to %s: %w", addr, err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO %s via %s: %w", to, addr, err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA to %s: %w", addr, err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("writing message body to %s: %w", addr, err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("closing message body to %s: %w", addr, err)
	}
	return client.Quit()
}

// buildEmailMessage is a pure function (no I/O) so it can be unit
// tested directly without a real SMTP server. It deliberately never
// includes the request's own label/message (endpoint-review.md F3 --
// see RequestCreatedPayload's own comment); ApplicationDisplayName is
// admin-controlled but still sanitized before use in the Subject header
// as cheap defense in depth.
func buildEmailMessage(from, to string, e Event) []byte {
	// Sanitized once and reused for both the Subject header and the
	// body's own "Application: ..." line -- a stray CRLF in this value
	// would otherwise produce a line in the body that merely looks like
	// a header to a human reader, even though no compliant mail parser
	// treats anything after the first blank line as a header.
	displayName := sanitizeHeaderValue(e.ApplicationDisplayName)
	subject := fmt.Sprintf("Approve: new access request for %s", displayName)

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeaderValue(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeaderValue(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString("A new access request is waiting for approval.\r\n\r\n")
	fmt.Fprintf(&b, "Application: %s (%s)\r\n", displayName, e.ApplicationHostname)
	fmt.Fprintf(&b, "Verification code: %s\r\n", e.VerificationCode)
	fmt.Fprintf(&b, "Requested at: %s\r\n", e.RequestedAt.Format(time.RFC1123))
	if e.AdminConsoleURL != "" {
		fmt.Fprintf(&b, "\r\nAny label or message the requester supplied is not verified -- review it directly in the admin console before acting on it: %s\r\n", e.AdminConsoleURL)
	}
	return []byte(b.String())
}

func sanitizeHeaderValue(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func (d *Dispatcher) sendWebhook(ctx context.Context, url string, e Event) error {
	body, err := json.Marshal(newWebhookBody(e))
	if err != nil {
		return fmt.Errorf("marshaling webhook body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if d.cfg.WebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(d.cfg.WebhookSecret))
		mac.Write(body)
		req.Header.Set(signatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
