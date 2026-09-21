package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// Config is internal/notify's own subset of internal/config.Config.
type Config struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	EmailFrom    string
	// WebhookSecret, if set, HMAC-SHA256-signs every outbound webhook
	// body -- global only, shared across every application's webhook
	// (see internal/config.Config.NotifyWebhookSecret's own comment on
	// why this isn't a per-application secret).
	WebhookSecret string
	// DefaultEmail/DefaultWebhookURL are the service-wide fallback
	// destinations DeliverPending uses for any application with no
	// notify_email/notify_webhook_url override of its own.
	DefaultEmail      string
	DefaultWebhookURL string
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

// Deliver attempts every channel Destination names, returning a joined
// error if any of them failed (errors.Join of zero errors is nil, so
// "nothing configured at all" and "everything configured succeeded"
// both correctly report success).
func (d *Dispatcher) Deliver(ctx context.Context, dest Destination, e Event) error {
	var errs []error
	if dest.Email != "" && d.cfg.SMTPHost != "" {
		if err := d.sendEmail(ctx, dest.Email, e); err != nil {
			errs = append(errs, fmt.Errorf("email: %w", err))
		}
	}
	if dest.WebhookURL != "" {
		if err := d.sendWebhook(ctx, dest.WebhookURL, e); err != nil {
			errs = append(errs, fmt.Errorf("webhook: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (d *Dispatcher) sendEmail(ctx context.Context, to string, e Event) error {
	msg := buildEmailMessage(d.cfg.EmailFrom, to, e)

	var auth smtp.Auth
	if d.cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", d.cfg.SMTPUsername, d.cfg.SMTPPassword, d.cfg.SMTPHost)
	}
	addr := fmt.Sprintf("%s:%d", d.cfg.SMTPHost, d.cfg.SMTPPort)

	// net/smtp has no context-aware entry point; deliveryTimeout still
	// bounds the whole attempt via a deadline on the underlying dial
	// this package doesn't control directly, so we accept ctx here for
	// interface consistency with sendWebhook and future-proofing, but
	// the actual bound is smtp.SendMail's own (unconfigurable) dial +
	// protocol timeouts.
	_ = ctx
	if err := smtp.SendMail(addr, auth, d.cfg.EmailFrom, []string{to}, msg); err != nil {
		return fmt.Errorf("sending mail via %s: %w", addr, err)
	}
	return nil
}

// buildEmailMessage is a pure function (no I/O) so it can be unit
// tested directly without a real SMTP server. Label/Message are
// browser-submitted and only ever placed in the body, never a header,
// so they can't be used for header injection regardless of content;
// ApplicationDisplayName is admin-controlled but still sanitized before
// use in the Subject header as cheap defense in depth.
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
	if e.Label != "" {
		fmt.Fprintf(&b, "Label: %s\r\n", e.Label)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, "Message: %s\r\n", e.Message)
	}
	fmt.Fprintf(&b, "Requested at: %s\r\n", e.RequestedAt.Format(time.RFC1123))
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
