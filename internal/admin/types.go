package admin

import "time"

// ApproveInput is what POST /api/v1/requests/{id}/approve carries (spec
// section 9).
type ApproveInput struct {
	RequestID   string
	ExpiresAt   time.Time
	Label       string
	PrivateNote string
	ApprovedBy  string
}

type RevokeInput struct {
	AuthorizationID string
	Reason          string
	RevokedBy       string
}
