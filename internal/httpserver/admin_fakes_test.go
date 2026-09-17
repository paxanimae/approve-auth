package httpserver_test

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/traefik-manual-proxy/internal/admin"
	"github.com/frid-iks/traefik-manual-proxy/internal/adminsession"
	"github.com/frid-iks/traefik-manual-proxy/internal/store"
)

// fakeAdminSessions is a minimal stand-in for internal/adminsession.Service,
// for tests that only care about routing/listener separation, not the real
// OIDC/session business logic (that's internal/adminsession's own tests).
type fakeAdminSessions struct{}

func (fakeAdminSessions) BeginLogin(context.Context, string) (adminsession.BeginLoginResult, error) {
	return adminsession.BeginLoginResult{RedirectURL: "https://idp.example.test/authorize"}, nil
}
func (fakeAdminSessions) HandleCallback(context.Context, string, string) (string, string, error) {
	return "", "", adminsession.ErrInvalidState
}
func (fakeAdminSessions) ValidateSession(context.Context, string) (adminsession.SessionInfo, error) {
	return adminsession.SessionInfo{}, adminsession.ErrNoSession
}
func (fakeAdminSessions) Logout(context.Context, string, string) error { return nil }

// fakeAdminActions is a minimal stand-in for internal/admin.Service.
type fakeAdminActions struct{}

func (fakeAdminActions) Approve(context.Context, admin.ApproveInput) (admin.ApproveResult, error) {
	return admin.ApproveResult{}, admin.ErrConflict
}
func (fakeAdminActions) Deny(context.Context, admin.DenyInput) error {
	return admin.ErrConflict
}
func (fakeAdminActions) Revoke(context.Context, admin.RevokeInput) error {
	return admin.ErrConflict
}
func (fakeAdminActions) Renew(context.Context, admin.RenewInput) error {
	return admin.ErrConflict
}
func (fakeAdminActions) CreateApplication(context.Context, admin.CreateApplicationInput) (store.Application, error) {
	return store.Application{}, admin.ErrDuplicateHostname
}
func (fakeAdminActions) UpdateApplication(context.Context, admin.UpdateApplicationInput) (store.Application, error) {
	return store.Application{}, admin.ErrConflict
}
func (fakeAdminActions) DisableApplication(context.Context, admin.DisableApplicationInput) (admin.DisableApplicationResult, error) {
	return admin.DisableApplicationResult{}, admin.ErrConflict
}
func (fakeAdminActions) EnableApplication(context.Context, admin.EnableApplicationInput) (store.Application, error) {
	return store.Application{}, admin.ErrConflict
}

// fakeAdminReadStore is a minimal stand-in for internal/store's read-only
// listing/detail surface used by the admin API's GET endpoints.
type fakeAdminReadStore struct{}

func (fakeAdminReadStore) GetApplicationByID(context.Context, uuid.UUID) (store.Application, bool, error) {
	return store.Application{}, false, nil
}
func (fakeAdminReadStore) ListApplications(context.Context) ([]store.Application, error) {
	return nil, nil
}
func (fakeAdminReadStore) GetApprovalRequestByID(context.Context, uuid.UUID) (store.ApprovalRequest, bool, error) {
	return store.ApprovalRequest{}, false, nil
}
func (fakeAdminReadStore) ListApprovalRequests(context.Context, *uuid.UUID, string, int) ([]store.ApprovalRequest, error) {
	return nil, nil
}
func (fakeAdminReadStore) GetAuthorizationByID(context.Context, uuid.UUID) (store.Authorization, bool, error) {
	return store.Authorization{}, false, nil
}
func (fakeAdminReadStore) ListAuthorizations(context.Context, *uuid.UUID, bool, int) ([]store.Authorization, error) {
	return nil, nil
}
func (fakeAdminReadStore) ListAuditEvents(context.Context, store.ListAuditEventsParams) ([]store.AuditEvent, error) {
	return nil, nil
}
func (fakeAdminReadStore) RecordAuditEvent(context.Context, string, string, string, string) error {
	return nil
}
func (fakeAdminReadStore) GetOverviewCounts(context.Context, time.Duration, time.Duration) (store.OverviewCounts, error) {
	return store.OverviewCounts{}, nil
}
