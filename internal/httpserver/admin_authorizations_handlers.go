package httpserver

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/admin"
)

// --- GET /api/v1/authorizations ---

func listAuthorizationsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID, ok := parseOptionalApplicationIDQuery(w, r)
		if !ok {
			return
		}
		activeOnly := r.URL.Query().Get("active_only") != "false"
		// mine=true is "My Approvals" -- resolved server-side to the
		// caller's own stable subject, never a client-supplied identity,
		// so it can't be used to probe for who else approved something
		// beyond what the unfiltered list already shows.
		var approvedBy *string
		if r.URL.Query().Get("mine") == "true" {
			subject := actorSubject(r)
			approvedBy = &subject
		}
		auths, err := readStore.ListAuthorizations(r.Context(), appID, approvedBy, activeOnly, parseLimitQuery(r))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to list authorizations")
			return
		}
		dtos := make([]authorizationDTO, len(auths))
		for i, a := range auths {
			dtos[i] = newAuthorizationDTO(a)
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorizations": dtos})
	}
}

// --- GET /api/v1/authorizations/{id} ---

func getAuthorizationHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		auth, found, err := readStore.GetAuthorizationByID(r.Context(), id)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load authorization")
			return
		}
		if !found {
			writeAPIError(w, http.StatusNotFound, "not_found", "no such authorization")
			return
		}
		writeJSON(w, http.StatusOK, newAuthorizationDTO(auth))
	}
}

// --- POST /api/v1/authorizations/{id}/renew ---

type renewAuthorizationBody struct {
	Version      int32     `json:"version"`
	NewExpiresAt time.Time `json:"new_expires_at"`
	Reason       string    `json:"reason"`
}

func renewAuthorizationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body renewAuthorizationBody
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.NewExpiresAt.IsZero() {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "new_expires_at is required")
			return
		}

		if err := actions.Renew(r.Context(), admin.RenewInput{
			AuthorizationID: id.String(), ExpectedVersion: body.Version, NewExpiresAt: body.NewExpiresAt, RenewedBy: actorSubject(r),
		}); err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"renewed": true})
	}
}

// --- POST /api/v1/authorizations/{id}/revoke ---

type revokeAuthorizationBody struct {
	Version int32  `json:"version"`
	Reason  string `json:"reason"`
}

func revokeAuthorizationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body revokeAuthorizationBody
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Reason == "" {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "reason is required")
			return
		}

		if err := actions.Revoke(r.Context(), admin.RevokeInput{
			AuthorizationID: id.String(), ExpectedVersion: body.Version, Reason: body.Reason, RevokedBy: actorSubject(r),
		}); err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
	}
}

// bulkItemInput is one entry of the explicit ID+version list spec
// section 9 requires for both bulk endpoints (maximum 100).
type bulkItemInput struct {
	ID      string `json:"id"`
	Version int32  `json:"version"`
}

// bulkItemResult is one entry's outcome -- spec section 9: "return 200
// with per-item success/error results, each item transactionally
// independent... do not silently skip failures."
type bulkItemResult struct {
	ID      string `json:"id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func validateBulkItems(w http.ResponseWriter, items []bulkItemInput) bool {
	if len(items) == 0 || len(items) > 100 {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "items must contain between 1 and 100 entries")
		return false
	}
	return true
}

// --- POST /api/v1/authorizations/bulk-renew ---

type bulkRenewRequest struct {
	Items        []bulkItemInput `json:"items"`
	DurationDays int             `json:"duration_days"`
	Reason       string          `json:"reason"`
}

// bulkRenewHandler adds duration_days to each authorization's own
// current expiry (spec section 10: "Renew presets add 7/30/90 days to
// the existing end date") -- it reads each row via readStore first
// specifically to compute that per-row new expiry, then calls the same
// AdminActions.Renew every single-item renew uses, so both paths share
// the exact same validation and audit trail.
func bulkRenewHandler(actions AdminActions, readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body bulkRenewRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if !validateBulkItems(w, body.Items) {
			return
		}
		if body.DurationDays <= 0 {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "duration_days must be positive")
			return
		}

		actor := actorSubject(r)
		results := make([]bulkItemResult, len(body.Items))
		for i, item := range body.Items {
			results[i] = renewOneBulkItem(r, actions, readStore, actor, body.DurationDays, item)
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	}
}

func renewOneBulkItem(r *http.Request, actions AdminActions, readStore AdminReadStore, actor string, durationDays int, item bulkItemInput) bulkItemResult {
	result := bulkItemResult{ID: item.ID}
	authID, err := uuid.Parse(item.ID)
	if err != nil {
		result.Error = "invalid_id"
		return result
	}
	current, found, err := readStore.GetAuthorizationByID(r.Context(), authID)
	if err != nil || !found {
		result.Error = "not_found"
		return result
	}
	newExpiresAt := current.ExpiresAt.Add(time.Duration(durationDays) * 24 * time.Hour)
	if err := actions.Renew(r.Context(), admin.RenewInput{
		AuthorizationID: item.ID, ExpectedVersion: item.Version, NewExpiresAt: newExpiresAt, RenewedBy: actor,
	}); err != nil {
		_, code, _ := adminErrorDetails(err)
		result.Error = code
		return result
	}
	result.Success = true
	return result
}

// --- POST /api/v1/authorizations/bulk-revoke ---

type bulkRevokeRequest struct {
	Items  []bulkItemInput `json:"items"`
	Reason string          `json:"reason"`
}

func bulkRevokeHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body bulkRevokeRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if !validateBulkItems(w, body.Items) {
			return
		}
		if body.Reason == "" {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "reason is required")
			return
		}

		actor := actorSubject(r)
		results := make([]bulkItemResult, len(body.Items))
		for i, item := range body.Items {
			result := bulkItemResult{ID: item.ID}
			if _, err := uuid.Parse(item.ID); err != nil {
				result.Error = "invalid_id"
				results[i] = result
				continue
			}
			if err := actions.Revoke(r.Context(), admin.RevokeInput{
				AuthorizationID: item.ID, ExpectedVersion: item.Version, Reason: body.Reason, RevokedBy: actor,
			}); err != nil {
				_, code, _ := adminErrorDetails(err)
				result.Error = code
			} else {
				result.Success = true
			}
			results[i] = result
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	}
}
