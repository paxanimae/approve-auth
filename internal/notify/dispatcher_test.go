package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frid-iks/approve-auth/internal/notify"
)

func testEvent() notify.Event {
	return notify.Event{
		Type: notify.EventRequestCreated, ApplicationHostname: "app-a.example.test", ApplicationDisplayName: "App A",
		RequestID: "req-1", VerificationCode: "ABC123", Label: "Lobby TV", Message: "please approve",
		RequestedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestDeliver_WebhookSendsSignedJSONBody(t *testing.T) {
	const secret = "topsecret"
	var gotBody []byte
	var gotSignature string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		gotSignature = r.Header.Get("X-Approve-Auth-Signature")
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := notify.New(notify.Config{WebhookSecret: secret})
	if err := d.Deliver(context.Background(), notify.Destination{WebhookURL: srv.URL}, testEvent()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("unmarshaling received body: %v", err)
	}
	if body["event"] != notify.EventRequestCreated || body["verification_code"] != "ABC123" || body["application_hostname"] != "app-a.example.test" {
		t.Errorf("unexpected webhook body: %+v", body)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSignature != wantSig {
		t.Errorf("signature header = %q, want %q", gotSignature, wantSig)
	}
}

func TestDeliver_WebhookOmitsSignatureWhenNoSecretConfigured(t *testing.T) {
	var gotSignature string
	sawHeader := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSignature, sawHeader = r.Header.Get("X-Approve-Auth-Signature"), r.Header.Get("X-Approve-Auth-Signature") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := notify.New(notify.Config{})
	if err := d.Deliver(context.Background(), notify.Destination{WebhookURL: srv.URL}, testEvent()); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if sawHeader {
		t.Errorf("signature header unexpectedly present: %q", gotSignature)
	}
}

func TestDeliver_WebhookNon2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := notify.New(notify.Config{})
	if err := d.Deliver(context.Background(), notify.Destination{WebhookURL: srv.URL}, testEvent()); err == nil {
		t.Fatal("Deliver: expected an error for a 500 response, got nil")
	}
}

func TestDeliver_NothingConfiguredIsNotAnError(t *testing.T) {
	d := notify.New(notify.Config{})
	if err := d.Deliver(context.Background(), notify.Destination{}, testEvent()); err != nil {
		t.Errorf("Deliver with no destination configured: got %v, want nil (vacuous success)", err)
	}
}

func TestDeliver_EmailSkippedWhenSMTPHostNotConfigured(t *testing.T) {
	// Email destination set, but no SMTPHost -- email must be silently
	// skipped (feature is opt-in via NotifySMTPHost), not attempted and
	// not an error.
	d := notify.New(notify.Config{})
	if err := d.Deliver(context.Background(), notify.Destination{Email: "ops@example.test"}, testEvent()); err != nil {
		t.Errorf("Deliver with email destination but no SMTP host: got %v, want nil", err)
	}
}

func TestBuildEmailMessage_SanitizesHeaderInjectionAndIncludesBody(t *testing.T) {
	e := testEvent()
	e.ApplicationDisplayName = "Evil\r\nBcc: attacker@example.test"

	msg := notify.BuildEmailMessageForTest("sender@example.test", "ops@example.test", e)
	text := string(msg)

	lines := strings.Split(text, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Bcc:") {
			t.Errorf("header injection succeeded: found injected header line %q", line)
		}
	}
	if !strings.Contains(text, "Verification code: ABC123") {
		t.Errorf("message body missing verification code: %s", text)
	}
	if !strings.Contains(text, "Label: Lobby TV") {
		t.Errorf("message body missing label: %s", text)
	}
}
