package store

import (
	"context"
	"fmt"
	"time"
)

// GlobalSettings mirrors global_settings' single row (migration
// 000019) -- the deployment-wide business-rule defaults an
// administrator edits live from the admin console's Settings page,
// instead of the static YAML config every other setting still uses.
type GlobalSettings struct {
	// ContactInfo/NotifyEmailFrom/NotifyDefaultEmail/NotifyDefaultWebhookURL
	// are nil when unset -- distinct from an empty string, since an
	// application's own override still needs to distinguish "inherit
	// this" from "this is set to nothing at all" in principle, even
	// though these global values have no further fallback of their own.
	ContactInfo             *string
	NotifyEmailFrom         *string
	NotifyDefaultEmail      *string
	NotifyDefaultWebhookURL *string

	// RevokePolicy{IPChanged,UserAgentChanged,InactivityExceeded} are
	// NOT NULL (unlike the nullable fields above) -- every deployment
	// always has *some* default action for each signal, even if that
	// default is "off".
	RevokePolicyIPChanged          string
	RevokePolicyUserAgentChanged   string
	RevokePolicyInactivityExceeded string
	RevocationInactivityThreshold  time.Duration

	// MessageRetention (migration 000022, endpoint-review.md F5): how
	// long an approval_requests row's label/message fields survive
	// before being redacted, independent of the request record's own
	// (much longer) retention -- always positive, no "unset" state.
	MessageRetention time.Duration

	UpdatedAt time.Time
	Version   int32
}

const globalSettingsColumns = `contact_info, notify_email_from, notify_default_email, notify_default_webhook_url, revoke_policy_ip_changed, revoke_policy_user_agent_changed, revoke_policy_inactivity_exceeded, revocation_inactivity_threshold_seconds, message_retention_seconds, updated_at, version`

func scanGlobalSettings(row scanner) (GlobalSettings, error) {
	var s GlobalSettings
	var thresholdSeconds, messageRetentionSeconds int32
	err := row.Scan(
		&s.ContactInfo, &s.NotifyEmailFrom, &s.NotifyDefaultEmail, &s.NotifyDefaultWebhookURL,
		&s.RevokePolicyIPChanged, &s.RevokePolicyUserAgentChanged, &s.RevokePolicyInactivityExceeded,
		&thresholdSeconds, &messageRetentionSeconds, &s.UpdatedAt, &s.Version,
	)
	s.RevocationInactivityThreshold = time.Duration(thresholdSeconds) * time.Second
	s.MessageRetention = time.Duration(messageRetentionSeconds) * time.Second
	return s, err
}

// GetGlobalSettings reads the single global_settings row -- migration
// 000019 both creates the table and seeds this one row, so a query
// against `WHERE singleton` always finds exactly it.
func (db *DB) GetGlobalSettings(ctx context.Context) (GlobalSettings, error) {
	s, err := scanGlobalSettings(db.Pool.QueryRow(ctx, `SELECT `+globalSettingsColumns+` FROM global_settings WHERE singleton`))
	if err != nil {
		return GlobalSettings{}, fmt.Errorf("store: getting global settings: %w", err)
	}
	return s, nil
}

// UpdateGlobalSettingsParams carries PATCH /api/v1/settings's optional
// fields -- nil means leave unchanged, matching
// UpdateApplicationParams's own convention. An empty string clears one
// of the four nullable fields back to unset; the three revocation-
// policy actions and the inactivity threshold have no "unset" state
// (NOT NULL columns with their own defaults), so a non-nil pointer for
// those always sets a real value, never clears one.
type UpdateGlobalSettingsParams struct {
	ContactInfo             *string
	NotifyEmailFrom         *string
	NotifyDefaultEmail      *string
	NotifyDefaultWebhookURL *string

	// Validated by the caller (internal/httpserver) against
	// revokepolicy.Action.Valid() before reaching this method.
	RevokePolicyIPChanged          *string
	RevokePolicyUserAgentChanged   *string
	RevokePolicyInactivityExceeded *string
	RevocationInactivityThreshold  *time.Duration
	// MessageRetention: nil means leave unchanged; a non-nil value must
	// be positive (checked by the caller, internal/admin, before
	// reaching here -- same convention as RevocationInactivityThreshold).
	MessageRetention *time.Duration
}

// UpdateGlobalSettings applies only the fields the caller set, using
// the existing value for anything left nil. Returns ErrConflict if
// expectedVersion doesn't match the current row (the same optimistic-
// concurrency convention every other mutation in this package uses).
func (db *DB) UpdateGlobalSettings(ctx context.Context, expectedVersion int32, p UpdateGlobalSettingsParams, updatedBy string) (GlobalSettings, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return GlobalSettings{}, fmt.Errorf("store: updating global settings: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, err := scanGlobalSettings(tx.QueryRow(ctx, `SELECT `+globalSettingsColumns+` FROM global_settings WHERE singleton FOR UPDATE`))
	if err != nil {
		return GlobalSettings{}, fmt.Errorf("store: updating global settings: locking: %w", err)
	}
	if current.Version != expectedVersion {
		return GlobalSettings{}, ErrConflict
	}

	contactInfo := current.ContactInfo
	if p.ContactInfo != nil {
		contactInfo = p.ContactInfo
		if *contactInfo == "" {
			contactInfo = nil
		}
	}
	notifyEmailFrom := current.NotifyEmailFrom
	if p.NotifyEmailFrom != nil {
		notifyEmailFrom = p.NotifyEmailFrom
		if *notifyEmailFrom == "" {
			notifyEmailFrom = nil
		}
	}
	notifyDefaultEmail := current.NotifyDefaultEmail
	if p.NotifyDefaultEmail != nil {
		notifyDefaultEmail = p.NotifyDefaultEmail
		if *notifyDefaultEmail == "" {
			notifyDefaultEmail = nil
		}
	}
	notifyDefaultWebhookURL := current.NotifyDefaultWebhookURL
	if p.NotifyDefaultWebhookURL != nil {
		notifyDefaultWebhookURL = p.NotifyDefaultWebhookURL
		if *notifyDefaultWebhookURL == "" {
			notifyDefaultWebhookURL = nil
		}
	}
	revokeIPChanged := current.RevokePolicyIPChanged
	if p.RevokePolicyIPChanged != nil {
		revokeIPChanged = *p.RevokePolicyIPChanged
	}
	revokeUAChanged := current.RevokePolicyUserAgentChanged
	if p.RevokePolicyUserAgentChanged != nil {
		revokeUAChanged = *p.RevokePolicyUserAgentChanged
	}
	revokeInactivity := current.RevokePolicyInactivityExceeded
	if p.RevokePolicyInactivityExceeded != nil {
		revokeInactivity = *p.RevokePolicyInactivityExceeded
	}
	threshold := current.RevocationInactivityThreshold
	if p.RevocationInactivityThreshold != nil {
		threshold = *p.RevocationInactivityThreshold
	}
	messageRetention := current.MessageRetention
	if p.MessageRetention != nil {
		messageRetention = *p.MessageRetention
	}

	settings, err := scanGlobalSettings(tx.QueryRow(ctx, `
		UPDATE global_settings
		SET contact_info = $1, notify_email_from = $2, notify_default_email = $3, notify_default_webhook_url = $4,
		    revoke_policy_ip_changed = $5, revoke_policy_user_agent_changed = $6, revoke_policy_inactivity_exceeded = $7,
		    revocation_inactivity_threshold_seconds = $8, message_retention_seconds = $9, updated_at = now(), version = version + 1
		WHERE singleton
		RETURNING `+globalSettingsColumns,
		contactInfo, notifyEmailFrom, notifyDefaultEmail, notifyDefaultWebhookURL,
		revokeIPChanged, revokeUAChanged, revokeInactivity, int32(threshold.Seconds()), int32(messageRetention.Seconds()),
	))
	if err != nil {
		return GlobalSettings{}, fmt.Errorf("store: updating global settings: %w", err)
	}

	if err := insertAuditEvent(ctx, tx, auditParams{
		ActorType: "admin", ActorSubject: updatedBy, Action: "global_settings.updated",
	}); err != nil {
		return GlobalSettings{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return GlobalSettings{}, fmt.Errorf("store: updating global settings: commit: %w", err)
	}
	return settings, nil
}
