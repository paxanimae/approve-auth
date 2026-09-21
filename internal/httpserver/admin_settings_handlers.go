package httpserver

import (
	"net/http"
	"time"

	"github.com/frid-iks/approve-auth/internal/admin"
	"github.com/frid-iks/approve-auth/internal/revokepolicy"
)

// validateRequiredRevokePolicyAction accepts nil (field omitted, leave
// unchanged) or any of internal/revokepolicy's four recognized
// actions -- unlike validateOptionalRevokePolicyAction, an empty
// string is rejected: global_settings' revoke_policy_* columns
// (migration 000019) are NOT NULL with no "unset" state, so a caller
// that sends this field at all must send a real action.
func validateRequiredRevokePolicyAction(v *string) bool {
	return v == nil || revokepolicy.Action(*v).Valid()
}

// --- GET /api/v1/settings ---

func getSettingsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := readStore.GetGlobalSettings(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load settings")
			return
		}
		writeJSON(w, http.StatusOK, newGlobalSettingsDTO(settings))
	}
}

// --- PATCH /api/v1/settings ---

type updateSettingsRequest struct {
	Version                              int32   `json:"version"`
	ContactInfo                          *string `json:"contact_info"`
	NotifyEmailFrom                      *string `json:"notify_email_from"`
	NotifyDefaultEmail                   *string `json:"notify_default_email"`
	NotifyDefaultWebhookURL              *string `json:"notify_default_webhook_url"`
	RevokePolicyIPChanged                *string `json:"revoke_policy_ip_changed"`
	RevokePolicyUserAgentChanged         *string `json:"revoke_policy_user_agent_changed"`
	RevokePolicyInactivityExceeded       *string `json:"revoke_policy_inactivity_exceeded"`
	RevocationInactivityThresholdSeconds *int64  `json:"revocation_inactivity_threshold_seconds"`
	// MessageRetentionSeconds: nil leaves it unchanged (endpoint-review.md F5).
	MessageRetentionSeconds *int64 `json:"message_retention_seconds"`
}

func updateSettingsHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body updateSettingsRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.ContactInfo != nil && len(*body.ContactInfo) > 500 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "contact_info must be at most 500 characters")
			return
		}
		if body.NotifyEmailFrom != nil && len(*body.NotifyEmailFrom) > 320 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "notify_email_from must be at most 320 characters")
			return
		}
		if body.NotifyDefaultEmail != nil && len(*body.NotifyDefaultEmail) > 320 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "notify_default_email must be at most 320 characters")
			return
		}
		if body.NotifyDefaultWebhookURL != nil && !validateNotifyWebhookURL(*body.NotifyDefaultWebhookURL) {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "notify_default_webhook_url must be an absolute http(s) URL")
			return
		}
		if !validateRequiredRevokePolicyAction(body.RevokePolicyIPChanged) || !validateRequiredRevokePolicyAction(body.RevokePolicyUserAgentChanged) || !validateRequiredRevokePolicyAction(body.RevokePolicyInactivityExceeded) {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "revoke_policy_* fields must be one of off/warn/flag_for_review/revoke")
			return
		}
		if body.RevocationInactivityThresholdSeconds != nil && *body.RevocationInactivityThresholdSeconds <= 0 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "revocation_inactivity_threshold_seconds must be positive")
			return
		}
		if body.MessageRetentionSeconds != nil && *body.MessageRetentionSeconds <= 0 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "message_retention_seconds must be positive")
			return
		}

		in := admin.UpdateGlobalSettingsInput{
			ExpectedVersion: body.Version,
			ContactInfo:     body.ContactInfo, NotifyEmailFrom: body.NotifyEmailFrom, NotifyDefaultEmail: body.NotifyDefaultEmail, NotifyDefaultWebhookURL: body.NotifyDefaultWebhookURL,
			RevokePolicyIPChanged: body.RevokePolicyIPChanged, RevokePolicyUserAgentChanged: body.RevokePolicyUserAgentChanged,
			RevokePolicyInactivityExceeded: body.RevokePolicyInactivityExceeded, UpdatedBy: actorSubject(r),
		}
		if body.RevocationInactivityThresholdSeconds != nil {
			d := time.Duration(*body.RevocationInactivityThresholdSeconds) * time.Second
			in.RevocationInactivityThreshold = &d
		}
		if body.MessageRetentionSeconds != nil {
			d := time.Duration(*body.MessageRetentionSeconds) * time.Second
			in.MessageRetention = &d
		}

		settings, err := actions.UpdateGlobalSettings(r.Context(), in)
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, newGlobalSettingsDTO(settings))
	}
}
