package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/admin"
)

func TestService_NotImplemented(t *testing.T) {
	svc := admin.New()
	if svc == nil {
		t.Fatal("New() returned nil")
	}

	if err := svc.Approve(context.Background(), admin.ApproveInput{}); !errors.Is(err, admin.ErrNotImplemented) {
		t.Errorf("Approve: got error %v, want ErrNotImplemented", err)
	}
	if err := svc.Revoke(context.Background(), admin.RevokeInput{}); !errors.Is(err, admin.ErrNotImplemented) {
		t.Errorf("Revoke: got error %v, want ErrNotImplemented", err)
	}
}
