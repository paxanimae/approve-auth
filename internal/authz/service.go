package authz

import (
	"context"
	"errors"
)

// ErrNotImplemented marks every method in this package until Milestone 2
// implements the actual allow/deny decision.
var ErrNotImplemented = errors.New("authz: not implemented until Milestone 2")

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Decide(_ context.Context, _ AuthRequest) (Decision, error) {
	return Decision{}, ErrNotImplemented
}
