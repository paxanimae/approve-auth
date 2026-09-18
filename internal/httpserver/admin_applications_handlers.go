package httpserver

import (
	"net/http"
	"time"

	"github.com/frid-iks/approve-auth/internal/admin"
)

// --- GET /api/v1/applications ---

func listApplicationsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apps, err := readStore.ListApplications(r.Context())
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to list applications")
			return
		}
		dtos := make([]applicationDTO, len(apps))
		for i, a := range apps {
			dtos[i] = newApplicationDTO(a)
		}
		writeJSON(w, http.StatusOK, map[string]any{"applications": dtos})
	}
}

// --- POST /api/v1/applications ---

type createApplicationRequest struct {
	Hostname               string `json:"hostname"`
	DisplayName            string `json:"display_name"`
	Description            string `json:"description"`
	DefaultDurationSeconds int64  `json:"default_duration_seconds"`
	MaxDurationSeconds     int64  `json:"max_duration_seconds"`
}

func createApplicationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body createApplicationRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Hostname == "" || body.DisplayName == "" {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "hostname and display_name are required")
			return
		}

		app, err := actions.CreateApplication(r.Context(), admin.CreateApplicationInput{
			Hostname: body.Hostname, DisplayName: body.DisplayName, Description: body.Description,
			DefaultDuration: time.Duration(body.DefaultDurationSeconds) * time.Second,
			MaxDuration:     time.Duration(body.MaxDurationSeconds) * time.Second,
		})
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, newApplicationDTO(app))
	}
}

// --- GET /api/v1/applications/{id} ---

func getApplicationHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		app, found, err := readStore.GetApplicationByID(r.Context(), id)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load application")
			return
		}
		if !found {
			writeAPIError(w, http.StatusNotFound, "not_found", "no such application")
			return
		}
		writeJSON(w, http.StatusOK, newApplicationDTO(app))
	}
}

// --- PATCH /api/v1/applications/{id} ---

type updateApplicationRequest struct {
	Version                int32   `json:"version"`
	DisplayName            *string `json:"display_name"`
	Description            *string `json:"description"`
	DefaultDurationSeconds *int64  `json:"default_duration_seconds"`
	MaxDurationSeconds     *int64  `json:"max_duration_seconds"`
}

func updateApplicationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body updateApplicationRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}

		in := admin.UpdateApplicationInput{
			ApplicationID: id.String(), ExpectedVersion: body.Version,
			DisplayName: body.DisplayName, Description: body.Description, UpdatedBy: actorSubject(r),
		}
		if body.DefaultDurationSeconds != nil {
			d := time.Duration(*body.DefaultDurationSeconds) * time.Second
			in.DefaultDuration = &d
		}
		if body.MaxDurationSeconds != nil {
			d := time.Duration(*body.MaxDurationSeconds) * time.Second
			in.MaxDuration = &d
		}

		app, err := actions.UpdateApplication(r.Context(), in)
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, newApplicationDTO(app))
	}
}

// --- POST /api/v1/applications/{id}/disable ---

type disableApplicationRequest struct {
	Version int32  `json:"version"`
	Reason  string `json:"reason"`
}

func disableApplicationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body disableApplicationRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if body.Reason == "" {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "reason is required")
			return
		}

		result, err := actions.DisableApplication(r.Context(), admin.DisableApplicationInput{
			ApplicationID: id.String(), ExpectedVersion: body.Version, Reason: body.Reason, DisabledBy: actorSubject(r),
		})
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"application":            newApplicationDTO(result.Application),
			"canceled_requests":      result.CanceledRequests,
			"revoked_authorizations": result.RevokedAuthorizations,
		})
	}
}

// --- POST /api/v1/applications/{id}/enable ---

type enableApplicationRequest struct {
	Version int32 `json:"version"`
}

func enableApplicationHandler(actions AdminActions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseUUIDPathParam(w, r)
		if !ok {
			return
		}
		var body enableApplicationRequest
		if !decodeJSONBody(w, r, &body) {
			return
		}

		app, err := actions.EnableApplication(r.Context(), admin.EnableApplicationInput{
			ApplicationID: id.String(), ExpectedVersion: body.Version, EnabledBy: actorSubject(r),
		})
		if err != nil {
			mapAdminError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, newApplicationDTO(app))
	}
}
