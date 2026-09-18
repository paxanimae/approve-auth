package adminsession_test

import (
	"context"
	"errors"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/adminsession"
)

func TestAnonymous_ValidateSessionAlwaysSucceedsWithFixedIdentity(t *testing.T) {
	anon, err := adminsession.NewAnonymous("vpn-perimeter", "VPN-authenticated operator", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	ctx := context.Background()

	for _, token := range []string{"", "garbage", "anything-at-all"} {
		info, err := anon.ValidateSession(ctx, token)
		if err != nil {
			t.Fatalf("ValidateSession(%q): %v", token, err)
		}
		if info.Subject != "vpn-perimeter" || info.DisplayName != "VPN-authenticated operator" || info.Role != "administrator" {
			t.Errorf("ValidateSession(%q) = %+v, want the fixed configured identity", token, info)
		}
	}
}

func TestAnonymous_ValidateSessionReturnsStableCSRFToken(t *testing.T) {
	anon, err := adminsession.NewAnonymous("anonymous", "Anonymous", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	ctx := context.Background()

	first, err := anon.ValidateSession(ctx, "")
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	second, err := anon.ValidateSession(ctx, "")
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if first.CSRFToken == "" {
		t.Fatal("expected a non-empty CSRF token")
	}
	if first.CSRFToken != second.CSRFToken {
		t.Error("expected the same CSRF token across calls -- the frontend caches it from one /me call")
	}
}

func TestAnonymous_BeginLoginBouncesBackToReturnTo(t *testing.T) {
	anon, err := adminsession.NewAnonymous("anonymous", "Anonymous", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	ctx := context.Background()

	result, err := anon.BeginLogin(ctx, "/requests")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if result.RedirectURL != "/requests" {
		t.Errorf("RedirectURL = %q, want /requests", result.RedirectURL)
	}

	result, err = anon.BeginLogin(ctx, "https://evil.example.test/")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if result.RedirectURL != "/" {
		t.Errorf("RedirectURL = %q, want / (non-relative return_to must not pass through)", result.RedirectURL)
	}
}

func TestAnonymous_HandleCallbackIsUnreachable(t *testing.T) {
	anon, err := adminsession.NewAnonymous("anonymous", "Anonymous", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	_, _, err = anon.HandleCallback(context.Background(), "state", "code")
	if !errors.Is(err, adminsession.ErrInvalidState) {
		t.Errorf("HandleCallback error = %v, want ErrInvalidState", err)
	}
}

func TestAnonymous_LogoutIsANoOp(t *testing.T) {
	anon, err := adminsession.NewAnonymous("anonymous", "Anonymous", "administrator")
	if err != nil {
		t.Fatalf("NewAnonymous: %v", err)
	}
	if err := anon.Logout(context.Background(), "anything", "anything"); err != nil {
		t.Errorf("Logout: %v, want nil", err)
	}
}
