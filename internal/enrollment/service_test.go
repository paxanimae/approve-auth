package enrollment_test

import (
	"context"
	"errors"
	"testing"

	"github.com/frid-iks/traefik-manual-proxy/internal/enrollment"
)

func TestService_SubmitRequestNotImplemented(t *testing.T) {
	svc := enrollment.New()
	if svc == nil {
		t.Fatal("New() returned nil")
	}

	_, err := svc.SubmitRequest(context.Background(), enrollment.SubmitRequestInput{})
	if !errors.Is(err, enrollment.ErrNotImplemented) {
		t.Errorf("SubmitRequest: got error %v, want ErrNotImplemented", err)
	}
}
