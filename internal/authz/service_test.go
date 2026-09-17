package authz_test

import (
	"context"
	"errors"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/authz"
)

func TestService_DecideNotImplemented(t *testing.T) {
	svc := authz.New()
	if svc == nil {
		t.Fatal("New() returned nil")
	}

	_, err := svc.Decide(context.Background(), authz.AuthRequest{})
	if !errors.Is(err, authz.ErrNotImplemented) {
		t.Errorf("Decide: got error %v, want ErrNotImplemented", err)
	}
}
