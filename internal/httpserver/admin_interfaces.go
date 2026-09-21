package httpserver

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/store"
)

// AdminActions is the internal/admin.Service surface the admin API's
// mutating endpoints need.
type AdminActions interface {
	Approve(ctx context.Context, in admin.ApproveInput) (admin.ApproveResult, error)
	Deny(ctx context.Context, in admin.DenyInput) error
	Revoke(ctx context.Context, in admin.RevokeInput) error
	Renew(ctx context.Context, in admin.RenewInput) error
	CreateApplication(ctx context.Context, in admin.CreateApplicationInput) (store.Application, error)
	UpdateApplication(ctx context.Context, in admin.UpdateApplicationInput) (store.Application, error)
	DisableApplication(ctx context.Context, in admin.DisableApplicationInput) (admin.DisableApplicationResult, error)
	EnableApplication(ctx context.Context, in admin.EnableApplicationInput) (store.Application, error)
	AddRequestNote(ctx context.Context, in admin.AddRequestNoteInput) (store.RequestNote, error)
	AddAuthorizationNote(ctx context.Context, in admin.AddAuthorizationNoteInput) (store.AuthorizationNote, error)
}

// AdminReadStore is the read-only listing/detail surface the admin API's
// GET endpoints need directly from internal/store -- no business rules
// apply to a read, so there's no need to route it through internal/admin.
type AdminReadStore interface {
	GetApplicationByID(ctx context.Context, id uuid.UUID) (store.Application, bool, error)
	ListApplications(ctx context.Context) ([]store.Application, error)
	GetApprovalRequestByID(ctx context.Context, id uuid.UUID) (store.ApprovalRequest, bool, error)
	ListApprovalRequests(ctx context.Context, applicationID *uuid.UUID, status string, limit int) ([]store.ApprovalRequest, error)
	GetAuthorizationByID(ctx context.Context, id uuid.UUID) (store.Authorization, bool, error)
	ListAuthorizations(ctx context.Context, applicationID *uuid.UUID, approvedBy *string, activeOnly bool, limit int) ([]store.Authorization, error)
	ListAuditEvents(ctx context.Context, p store.ListAuditEventsParams) ([]store.AuditEvent, error)
	RecordAuditEvent(ctx context.Context, actorType, actorSubject, action, reason string) error
	GetOverviewCounts(ctx context.Context, expiringSoonWindow, recentWindow time.Duration) (store.OverviewCounts, error)
	ListRequestNotes(ctx context.Context, requestID uuid.UUID) ([]store.RequestNote, error)
	ListAuthorizationNotes(ctx context.Context, authorizationID uuid.UUID) ([]store.AuthorizationNote, error)
}
