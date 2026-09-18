package httpserver

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/admin"
)

// --- GET /api/v1/requests ---

func listRequestsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID, ok := parseOptionalApplicationIDQuery(w, r)
		if !ok {
			return
		}
		reqs, err := readStore.ListApprovalRequests(r.Context(), appID, r.URL.Query().Get("status"), parseLimitQuery(r))
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to list requests")
			return
		}
		dtos := make([]requestDTO, len(reqs))
		for i, req := range reqs {
			dtos[i] = newRequestDTO(req)
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": dtos})
	}
}

// --- GET /api/v1/requests/{id} ---

func getRequestHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		req, found, err := readStore.GetApprovalRequestByID(r.Context(), id)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load request")
			return
		}
		if !found {
			writeAPIError(w, http.StatusNotFound, "not_found", "no such request")
			return
		}
		writeJSON(w, http.StatusOK, newRequestDTO(req))
	}
}

// --- POST /api/v1/requests/{id}/approve ---

type approveRequestBody struct {
	Version     int32      `json:"version"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Label       string     `json:"label"`
	PrivateNote string     `json:"private_note"`
}

func approveRequestHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body approveRequestBody
		if !decodeJSONBody(w, r, &body) {
			return
		}

		in := admin.ApproveInput{
			RequestID: id.String(), ExpectedVersion: body.Version,
			Label: body.Label, PrivateNote: body.PrivateNote, ApprovedBy: actorSubject(r),
		}
		if body.ExpiresAt != nil {
			in.ExpiresAt = *body.ExpiresAt
		}

		result, err := actions.Approve(r.Context(), in)
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"authorization_id": result.AuthorizationID, "expires_at": result.ExpiresAt})
	}
}

// --- POST /api/v1/requests/{id}/deny ---

type denyRequestBody struct {
	Version       int32  `json:"version"`
	Reason        string `json:"reason"`
	PublicMessage string `json:"public_message"`
}

func denyRequestHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body denyRequestBody
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Reason == "" {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "reason is required")
			return
		}

		if err := actions.Deny(r.Context(), admin.DenyInput{
			RequestID: id.String(), ExpectedVersion: body.Version, Reason: body.Reason, PublicMessage: body.PublicMessage, DeniedBy: actorSubject(r),
		}); err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"denied": true})
	}
}

// parseOptionalApplicationIDQuery is shared by the requests and
// authorizations list handlers.
func parseOptionalApplicationIDQuery(w http.ResponseWriter, r *http.Request) (*uuid.UUID, bool) {
	v := r.URL.Query().Get("application_id")
	if v == "" {
		return nil, true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "invalid application_id")
		return nil, false
	}
	return &id, true
}

// parseLimitQuery caps at spec section 9's list maximum (200), defaulting
// to its default (50); this is the simple limit-only listing described
// in ListApprovalRequests/ListAuthorizations, not yet full cursor
// pagination.
func parseLimitQuery(r *http.Request) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			return n
		}
	}
	return 50
}
