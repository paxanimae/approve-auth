package enrollment

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("enrollment: not implemented until Milestone 2")

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) SubmitRequest(_ context.Context, _ SubmitRequestInput) (SubmitRequestResult, error) {
	return SubmitRequestResult{}, ErrNotImplemented
}
