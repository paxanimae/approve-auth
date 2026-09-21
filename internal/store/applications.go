package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateApplication registers a new application. hostname is lowercased
// before insert -- the migration's CHECK constraint would reject a mixed-
// case value outright, but normalizing here gives a clearer error path
// than a raw constraint violation for the common case of a caller not
// having lowercased it themselves.
func (db *DB) CreateApplication(ctx context.Context, hostname, displayName, description string, defaultDuration, maxDuration time.Duration, contactInfo, notifyEmail, notifyWebhookURL string) (Application, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: begin: %w", hostname, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	app, err := scanApplication(tx.QueryRow(ctx, `
		INSERT INTO applications (hostname, display_name, description, default_duration_seconds, max_duration_seconds, contact_info, notify_email, notify_webhook_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+applicationColumns,
		strings.ToLower(hostname), displayName, description,
		int32(defaultDuration.Seconds()), int32(maxDuration.Seconds()), nullableText(contactInfo), nullableText(notifyEmail), nullableText(notifyWebhookURL),
	))
	if err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: %w", hostname, err)
	}

	// ActorSubject is empty: cmd/admin has no identity system of its own
	// yet (no OIDC integration until Milestone 4) -- still worth an
	// audit row naming the action and the application it created.
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", Action: "application.created", ApplicationID: &app.ID,
	}); err != nil {
		return Application{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("store: creating application %q: commit: %w", hostname, err)
	}
	return app, nil
}

// GetApplicationByHostname returns (app, true, nil) if found, (Application{}, false, nil)
// if no application is registered for hostname.
func (db *DB) GetApplicationByHostname(ctx context.Context, hostname string) (Application, bool, error) {
	app, err := scanApplication(db.Pool.QueryRow(ctx, `SELECT `+applicationColumns+` FROM applications WHERE hostname = $1`, strings.ToLower(hostname)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, false, nil
	}
	if err != nil {
		return Application{}, false, fmt.Errorf("store: looking up application %q: %w", hostname, err)
	}
	return app, true, nil
}

const applicationColumns = `id, hostname, display_name, description, enabled, default_duration_seconds, max_duration_seconds, created_at, updated_at, archived_at, version, contact_info, notify_email, notify_webhook_url, revoke_policy_ip_changed, revoke_policy_user_agent_changed, revoke_policy_inactivity_exceeded, allow_anonymous_message`

func scanApplication(row scanner) (Application, error) {
	var app Application
	err := row.Scan(
		&app.ID, &app.Hostname, &app.DisplayName, &app.Description, &app.Enabled,
		&app.DefaultDurationSeconds, &app.MaxDurationSeconds,
		&app.CreatedAt, &app.UpdatedAt, &app.ArchivedAt, &app.Version, &app.ContactInfo,
		&app.NotifyEmail, &app.NotifyWebhookURL,
		&app.RevokePolicyIPChanged, &app.RevokePolicyUserAgentChanged, &app.RevokePolicyInactivityExceeded,
		&app.AllowAnonymousMessage,
	)
	return app, err
}

// GetApplicationByID is the admin API's lookup, as opposed to
// GetApplicationByHostname which the public/authorization listeners use.
func (db *DB) GetApplicationByID(ctx context.Context, id uuid.UUID) (Application, bool, error) {
	app, err := scanApplication(db.Pool.QueryRow(ctx, `SELECT `+applicationColumns+` FROM applications WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, false, nil
	}
	if err != nil {
		return Application{}, false, fmt.Errorf("store: looking up application %s: %w", id, err)
	}
	return app, true, nil
}

// ListApplications is the admin API's GET /applications (spec section 9):
// every registered application, alphabetical by hostname since there's no
// pagination need at the scale this service targets (a bounded, admin-
// managed registry, not a high-cardinality list).
func (db *DB) ListApplications(ctx context.Context) ([]Application, error) {
	rows, err := db.Pool.Query(ctx, `SELECT `+applicationColumns+` FROM applications ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("store: listing applications: %w", err)
	}
	defer rows.Close()

	var out []Application
	for rows.Next() {
		app, err := scanApplication(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning application: %w", err)
		}
		out = append(out, app)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: listing applications: %w", err)
	}
	return out, nil
}

// UpdateApplicationParams carries PATCH /applications/{id}'s optional
// fields (spec section 9: "update name/policy; host immutable" -- hostname
// itself is intentionally absent here, not just unhandled, since the
// migration's trigger would reject any attempt to change it anyway).
type UpdateApplicationParams struct {
	DisplayName     *string
	Description     *string
	DefaultDuration *time.Duration
	MaxDuration     *time.Duration
	// ContactInfo: nil means leave unchanged; a non-nil pointer sets it,
	// normalizing "" to NULL (use the global default) the same way
	// CreateApplication does.
	ContactInfo *string
	// NotifyEmail/NotifyWebhookURL: same nil-means-unchanged,
	// empty-string-means-clear-to-global-default convention as
	// ContactInfo above.
	NotifyEmail      *string
	NotifyWebhookURL *string
	// RevokePolicy{IPChanged,UserAgentChanged,InactivityExceeded}: same
	// nil-means-unchanged, empty-string-means-clear-to-global-default
	// convention as ContactInfo above. A non-empty value must already
	// be a valid revokepolicy.Action -- validated by the caller
	// (internal/httpserver), matching how other input validation in
	// this API is done at the HTTP layer, not here.
	RevokePolicyIPChanged          *string
	RevokePolicyUserAgentChanged   *string
	RevokePolicyInactivityExceeded *string
	// AllowAnonymousMessage: nil means leave unchanged; a non-nil
	// pointer sets it outright (there's no "inherit a default" state
	// for this one -- every application has its own real true/false).
	AllowAnonymousMessage *bool
}

// UpdateApplication applies only the fields the caller set, using the
// existing value for anything left nil -- a caller reads-modifies-writes
// one field without having to resend the whole resource. Returns
// ErrConflict if expectedVersion doesn't match the current row (spec
// section 7: "stale If-Match produces 409 with current state").
func (db *DB) UpdateApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, p UpdateApplicationParams, updatedBy string) (Application, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return Application{}, fmt.Errorf("store: updating application %s: begin: %w", id, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, err := scanApplication(tx.QueryRow(ctx, `SELECT `+applicationColumns+` FROM applications WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, ErrConflict
	}
	if err != nil {
		return Application{}, fmt.Errorf("store: updating application %s: locking: %w", id, err)
	}
	if current.Version != expectedVersion {
		return Application{}, ErrConflict
	}

	displayName := current.DisplayName
	if p.DisplayName != nil {
		displayName = *p.DisplayName
	}
	description := current.Description
	if p.Description != nil {
		description = *p.Description
	}
	defaultSeconds := current.DefaultDurationSeconds
	if p.DefaultDuration != nil {
		defaultSeconds = int32(p.DefaultDuration.Seconds())
	}
	maxSeconds := current.MaxDurationSeconds
	if p.MaxDuration != nil {
		maxSeconds = int32(p.MaxDuration.Seconds())
	}
	contactInfo := current.ContactInfo
	if p.ContactInfo != nil {
		contactInfo = p.ContactInfo
		if *contactInfo == "" {
			contactInfo = nil
		}
	}
	notifyEmail := current.NotifyEmail
	if p.NotifyEmail != nil {
		notifyEmail = p.NotifyEmail
		if *notifyEmail == "" {
			notifyEmail = nil
		}
	}
	notifyWebhookURL := current.NotifyWebhookURL
	if p.NotifyWebhookURL != nil {
		notifyWebhookURL = p.NotifyWebhookURL
		if *notifyWebhookURL == "" {
			notifyWebhookURL = nil
		}
	}
	revokePolicyIPChanged := current.RevokePolicyIPChanged
	if p.RevokePolicyIPChanged != nil {
		revokePolicyIPChanged = p.RevokePolicyIPChanged
		if *revokePolicyIPChanged == "" {
			revokePolicyIPChanged = nil
		}
	}
	revokePolicyUserAgentChanged := current.RevokePolicyUserAgentChanged
	if p.RevokePolicyUserAgentChanged != nil {
		revokePolicyUserAgentChanged = p.RevokePolicyUserAgentChanged
		if *revokePolicyUserAgentChanged == "" {
			revokePolicyUserAgentChanged = nil
		}
	}
	revokePolicyInactivityExceeded := current.RevokePolicyInactivityExceeded
	if p.RevokePolicyInactivityExceeded != nil {
		revokePolicyInactivityExceeded = p.RevokePolicyInactivityExceeded
		if *revokePolicyInactivityExceeded == "" {
			revokePolicyInactivityExceeded = nil
		}
	}
	allowAnonymousMessage := current.AllowAnonymousMessage
	if p.AllowAnonymousMessage != nil {
		allowAnonymousMessage = *p.AllowAnonymousMessage
	}

	app, err := scanApplication(tx.QueryRow(ctx, `
		UPDATE applications
		SET display_name = $1, description = $2, default_duration_seconds = $3, max_duration_seconds = $4,
		    contact_info = $5, notify_email = $6, notify_webhook_url = $7,
		    revoke_policy_ip_changed = $8, revoke_policy_user_agent_changed = $9, revoke_policy_inactivity_exceeded = $10,
		    allow_anonymous_message = $11,
		    updated_at = now(), version = version + 1
		WHERE id = $12
		RETURNING `+applicationColumns,
		displayName, description, defaultSeconds, maxSeconds, contactInfo, notifyEmail, notifyWebhookURL,
		revokePolicyIPChanged, revokePolicyUserAgentChanged, revokePolicyInactivityExceeded, allowAnonymousMessage, id,
	))
	if err != nil {
		return Application{}, fmt.Errorf("store: updating application %s: %w", id, err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: updatedBy, Action: "application.updated", ApplicationID: &app.ID,
	}); err != nil {
		return Application{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("store: updating application %s: commit: %w", id, err)
	}
	return app, nil
}

// DisableApplication implements spec section 7: "Application disable
// revokes all live authorizations and cancels pending requests in the
// same transaction." Returns the number of requests canceled and
// authorizations revoked alongside the updated application, so the admin
// API and its confirmation UI can show the affected count.
func (db *DB) DisableApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, reason, disabledBy string) (app Application, canceledRequests, revokedAuthorizations int, err error) {
	tx, txErr := db.Pool.Begin(ctx)
	if txErr != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: begin: %w", id, txErr)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var version int32
	if err := tx.QueryRow(ctx, `SELECT version FROM applications WHERE id = $1 FOR UPDATE`, id).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Application{}, 0, 0, ErrConflict
		}
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: locking: %w", id, err)
	}
	if version != expectedVersion {
		return Application{}, 0, 0, ErrConflict
	}

	app, err = scanApplication(tx.QueryRow(ctx, `
		UPDATE applications SET enabled = false, updated_at = now(), version = version + 1
		WHERE id = $1
		RETURNING `+applicationColumns, id))
	if err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: %w", id, err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: disabledBy, Action: "application.disabled", ApplicationID: &app.ID, Reason: reason,
	}); err != nil {
		return Application{}, 0, 0, err
	}

	canceledRows, err := tx.Query(ctx, `
		UPDATE approval_requests SET status = 'canceled', version = version + 1
		WHERE application_id = $1 AND status IN ('pending', 'approved')
		RETURNING id`, id)
	if err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: canceling requests: %w", id, err)
	}
	var canceledRequestIDs []uuid.UUID
	for canceledRows.Next() {
		var rid uuid.UUID
		if err := canceledRows.Scan(&rid); err != nil {
			canceledRows.Close()
			return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: scanning canceled request: %w", id, err)
		}
		canceledRequestIDs = append(canceledRequestIDs, rid)
	}
	canceledRows.Close()
	if err := canceledRows.Err(); err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: canceling requests: %w", id, err)
	}
	for _, rid := range canceledRequestIDs {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "admin", ActorSubject: disabledBy, Action: "request.canceled",
			ApplicationID: &app.ID, RequestID: &rid, Reason: "application disabled",
		}); err != nil {
			return Application{}, 0, 0, err
		}
	}

	revokedRows, err := tx.Query(ctx, `
		UPDATE authorizations SET revoked_at = now(), revocation_reason = $2, version = version + 1
		WHERE application_id = $1 AND revoked_at IS NULL
		RETURNING id, request_id`, id, "application disabled")
	if err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: revoking authorizations: %w", id, err)
	}
	type revoked struct{ authID, reqID uuid.UUID }
	var revokedAuths []revoked
	for revokedRows.Next() {
		var rv revoked
		if err := revokedRows.Scan(&rv.authID, &rv.reqID); err != nil {
			revokedRows.Close()
			return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: scanning revoked authorization: %w", id, err)
		}
		revokedAuths = append(revokedAuths, rv)
	}
	revokedRows.Close()
	if err := revokedRows.Err(); err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: revoking authorizations: %w", id, err)
	}
	for _, rv := range revokedAuths {
		if err := insertAuditEvent(ctx, tx, auditParams{
			ActorType: "admin", ActorSubject: disabledBy, Action: "authorization.revoked",
			ApplicationID: &app.ID, RequestID: &rv.reqID, AuthorizationID: &rv.authID, Reason: "application disabled",
		}); err != nil {
			return Application{}, 0, 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, 0, 0, fmt.Errorf("store: disabling application %s: commit: %w", id, err)
	}
	return app, len(canceledRequestIDs), len(revokedAuths), nil
}

// EnableApplication implements spec section 9: "Enable new enrollment
// only" -- it does not restore any authorization that disable revoked
// (spec section 7: "reenabling it does not restore previous access").
func (db *DB) EnableApplication(ctx context.Context, id uuid.UUID, expectedVersion int32, enabledBy string) (Application, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return Application{}, fmt.Errorf("store: enabling application %s: begin: %w", id, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var version int32
	if err := tx.QueryRow(ctx, `SELECT version FROM applications WHERE id = $1 FOR UPDATE`, id).Scan(&version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Application{}, ErrConflict
		}
		return Application{}, fmt.Errorf("store: enabling application %s: locking: %w", id, err)
	}
	if version != expectedVersion {
		return Application{}, ErrConflict
	}

	app, err := scanApplication(tx.QueryRow(ctx, `
		UPDATE applications SET enabled = true, updated_at = now(), version = version + 1
		WHERE id = $1
		RETURNING `+applicationColumns, id))
	if err != nil {
		return Application{}, fmt.Errorf("store: enabling application %s: %w", id, err)
	}
	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: enabledBy, Action: "application.enabled", ApplicationID: &app.ID,
	}); err != nil {
		return Application{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Application{}, fmt.Errorf("store: enabling application %s: commit: %w", id, err)
	}
	return app, nil
}
