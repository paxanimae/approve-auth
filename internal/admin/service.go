package admin

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("admin: not implemented until Milestone 3")

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Approve(_ context.Context, _ ApproveInput) error {
	return ErrNotImplemented
}

func (s *Service) Revoke(_ context.Context, _ RevokeInput) error {
	return ErrNotImplemented
}
