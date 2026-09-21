package httpserver_test

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/adminsession"
	"github.com/frid-iks/approve-auth/internal/store"
)

// fakeAdminSessions is a minimal, configurable stand-in for
// internal/adminsession.Service, for tests that only care about the HTTP
// translation layer (cookies, status codes, middleware gating) -- the
// real OIDC/session business logic has its own tests in
// internal/adminsession.
type fakeAdminSessions struct {
	beginLoginResult adminsession.BeginLoginResult
	beginLoginErr    error
	callbackToken    string
	callbackReturn   string
	callbackErr      error
	session          adminsession.SessionInfo
	validateErr      error
	logoutErr        error
}

func (f fakeAdminSessions) BeginLogin(context.Context, string) (adminsession.BeginLoginResult, error) {
	if f.beginLoginErr != nil {
		return adminsession.BeginLoginResult{}, f.beginLoginErr
	}
	result := f.beginLoginResult
	if result.RedirectURL == "" {
		result.RedirectURL = "https://idp.example.test/authorize"
	}
	return result, nil
}
func (f fakeAdminSessions) HandleCallback(context.Context, string, string) (string, string, error) {
	if f.callbackErr != nil {
		return "", "", f.callbackErr
	}
	return f.callbackToken, f.callbackReturn, nil
}
func (f fakeAdminSessions) ValidateSession(context.Context, string) (adminsession.SessionInfo, error) {
	if f.validateErr != nil {
		return adminsession.SessionInfo{}, f.validateErr
	}
	return f.session, nil
}
func (f fakeAdminSessions) Logout(context.Context, string, string) error { return f.logoutErr }

// fakeAdminActions is a minimal, configurable stand-in for
// internal/admin.Service.
type fakeAdminActions struct {
	approveResult admin.ApproveResult
	approveErr    error
	denyErr       error
	revokeErr     error
	renewErr      error

	createApplicationResult  store.Application
	createApplicationErr     error
	updateApplicationResult  store.Application
	updateApplicationErr     error
	disableApplicationResult admin.DisableApplicationResult
	disableApplicationErr    error
	enableApplicationResult  store.Application
	enableApplicationErr     error

	addRequestNoteResult       store.RequestNote
	addRequestNoteErr          error
	addAuthorizationNoteResult store.AuthorizationNote
	addAuthorizationNoteErr    error

	grantApplicationOwnerErr  error
	revokeApplicationOwnerErr error

	clearAuthorizationFlagErr error

	updateGlobalSettingsResult store.GlobalSettings
	updateGlobalSettingsErr    error
}

func (f fakeAdminActions) Approve(context.Context, admin.ApproveInput) (admin.ApproveResult, error) {
	return f.approveResult, f.approveErr
}
func (f fakeAdminActions) Deny(context.Context, admin.DenyInput) error { return f.denyErr }
func (f fakeAdminActions) Revoke(context.Context, admin.RevokeInput) error {
	return f.revokeErr
}
func (f fakeAdminActions) Renew(context.Context, admin.RenewInput) error {
	return f.renewErr
}
func (f fakeAdminActions) CreateApplication(context.Context, admin.CreateApplicationInput) (store.Application, error) {
	return f.createApplicationResult, f.createApplicationErr
}
func (f fakeAdminActions) UpdateApplication(context.Context, admin.UpdateApplicationInput) (store.Application, error) {
	return f.updateApplicationResult, f.updateApplicationErr
}
func (f fakeAdminActions) DisableApplication(context.Context, admin.DisableApplicationInput) (admin.DisableApplicationResult, error) {
	return f.disableApplicationResult, f.disableApplicationErr
}
func (f fakeAdminActions) EnableApplication(context.Context, admin.EnableApplicationInput) (store.Application, error) {
	return f.enableApplicationResult, f.enableApplicationErr
}
func (f fakeAdminActions) AddRequestNote(context.Context, admin.AddRequestNoteInput) (store.RequestNote, error) {
	return f.addRequestNoteResult, f.addRequestNoteErr
}
func (f fakeAdminActions) AddAuthorizationNote(context.Context, admin.AddAuthorizationNoteInput) (store.AuthorizationNote, error) {
	return f.addAuthorizationNoteResult, f.addAuthorizationNoteErr
}
func (f fakeAdminActions) ClearAuthorizationFlag(context.Context, admin.ClearAuthorizationFlagInput) error {
	return f.clearAuthorizationFlagErr
}
func (f fakeAdminActions) GrantApplicationOwner(context.Context, admin.GrantApplicationOwnerInput) error {
	return f.grantApplicationOwnerErr
}
func (f fakeAdminActions) RevokeApplicationOwner(context.Context, admin.RevokeApplicationOwnerInput) error {
	return f.revokeApplicationOwnerErr
}
func (f fakeAdminActions) UpdateGlobalSettings(context.Context, admin.UpdateGlobalSettingsInput) (store.GlobalSettings, error) {
	return f.updateGlobalSettingsResult, f.updateGlobalSettingsErr
}

// fakeAdminReadStore is a minimal, configurable stand-in for
// internal/store's read-only listing/detail surface used by the admin
// API's GET endpoints.
type fakeAdminReadStore struct {
	applications     []store.Application
	application      store.Application
	applicationFound bool
	applicationErr   error

	requests     []store.ApprovalRequest
	request      store.ApprovalRequest
	requestFound bool
	requestErr   error

	authorizations     []store.Authorization
	authorizationsMine []store.Authorization // returned instead of authorizations when ListAuthorizations receives a non-nil approvedBy, so tests can distinguish the two
	authorization      store.Authorization
	authorizationFound bool
	authorizationErr   error

	auditEvents []store.AuditEvent
	auditErr    error
	recordErr   error

	overviewCounts store.OverviewCounts
	overviewErr    error

	requestNotes          []store.RequestNote
	requestNotesErr       error
	authorizationNotes    []store.AuthorizationNote
	authorizationNotesErr error

	applicationOwners    []string
	applicationOwnersErr error
	ownedApplicationIDs  []uuid.UUID
	ownedApplicationsErr error

	globalSettings    store.GlobalSettings
	globalSettingsErr error
}

func (f fakeAdminReadStore) GetApplicationByID(context.Context, uuid.UUID) (store.Application, bool, error) {
	return f.application, f.applicationFound, f.applicationErr
}
func (f fakeAdminReadStore) ListApplications(context.Context) ([]store.Application, error) {
	return f.applications, f.applicationErr
}
func (f fakeAdminReadStore) GetApprovalRequestByID(context.Context, uuid.UUID) (store.ApprovalRequest, bool, error) {
	return f.request, f.requestFound, f.requestErr
}
func (f fakeAdminReadStore) ListApprovalRequests(context.Context, *uuid.UUID, string, int, []uuid.UUID) ([]store.ApprovalRequest, error) {
	return f.requests, f.requestErr
}
func (f fakeAdminReadStore) GetAuthorizationByID(context.Context, uuid.UUID) (store.Authorization, bool, error) {
	return f.authorization, f.authorizationFound, f.authorizationErr
}
func (f fakeAdminReadStore) ListAuthorizations(_ context.Context, _ *uuid.UUID, approvedBy *string, _ bool, _ int, _ []uuid.UUID) ([]store.Authorization, error) {
	if approvedBy != nil {
		return f.authorizationsMine, f.authorizationErr
	}
	return f.authorizations, f.authorizationErr
}
func (f fakeAdminReadStore) ListAuditEvents(context.Context, store.ListAuditEventsParams) ([]store.AuditEvent, error) {
	return f.auditEvents, f.auditErr
}
func (f fakeAdminReadStore) RecordAuditEvent(context.Context, string, string, string, string) error {
	return f.recordErr
}
func (f fakeAdminReadStore) GetOverviewCounts(context.Context, time.Duration, time.Duration) (store.OverviewCounts, error) {
	return f.overviewCounts, f.overviewErr
}
func (f fakeAdminReadStore) ListRequestNotes(context.Context, uuid.UUID) ([]store.RequestNote, error) {
	return f.requestNotes, f.requestNotesErr
}
func (f fakeAdminReadStore) ListAuthorizationNotes(context.Context, uuid.UUID) ([]store.AuthorizationNote, error) {
	return f.authorizationNotes, f.authorizationNotesErr
}
func (f fakeAdminReadStore) ListApplicationOwners(context.Context, uuid.UUID) ([]string, error) {
	return f.applicationOwners, f.applicationOwnersErr
}
func (f fakeAdminReadStore) GetOwnedApplicationIDs(context.Context, string) ([]uuid.UUID, error) {
	return f.ownedApplicationIDs, f.ownedApplicationsErr
}
func (f fakeAdminReadStore) GetGlobalSettings(context.Context) (store.GlobalSettings, error) {
	return f.globalSettings, f.globalSettingsErr
}
