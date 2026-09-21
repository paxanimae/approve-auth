package httpserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/frid-iks/approve-auth/internal/store"
)

// The admin API responses below carry explicit snake_case JSON tags
// (spec section 9: "JSON uses snake_case") -- the store package's plain
// PascalCase structs are an internal implementation detail, not a wire
// contract, so every response is its own small DTO conversion rather
// than serializing a store.* type directly.

type applicationDTO struct {
	ID                     string     `json:"id"`
	Hostname               string     `json:"hostname"`
	DisplayName            string     `json:"display_name"`
	Description            string     `json:"description"`
	Enabled                bool       `json:"enabled"`
	DefaultDurationSeconds int32      `json:"default_duration_seconds"`
	MaxDurationSeconds     int32      `json:"max_duration_seconds"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	ArchivedAt             *time.Time `json:"archived_at,omitempty"`
	Version                int32      `json:"version"`
	// ContactInfo is omitted entirely when this application has no
	// override and uses the global config default instead -- nil, not
	// an empty string, distinguishes "inherits the default" from "opts
	// out with no contact info at all" for the console to display.
	ContactInfo *string `json:"contact_info,omitempty"`
}

func newApplicationDTO(a store.Application) applicationDTO {
	return applicationDTO{
		ID: a.ID.String(), Hostname: a.Hostname, DisplayName: a.DisplayName, Description: a.Description,
		Enabled: a.Enabled, DefaultDurationSeconds: a.DefaultDurationSeconds, MaxDurationSeconds: a.MaxDurationSeconds,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt, ArchivedAt: a.ArchivedAt, Version: a.Version,
		ContactInfo: a.ContactInfo,
	}
}

type requestDTO struct {
	ID                     string     `json:"id"`
	ApplicationID          string     `json:"application_id"`
	ApplicationHostname    string     `json:"application_hostname"`
	ApplicationDisplayName string     `json:"application_display_name"`
	VerificationCode       string     `json:"verification_code"`
	Label                  *string    `json:"label,omitempty"`
	Message                *string    `json:"message,omitempty"`
	Status                 string     `json:"status"`
	RequestedAt            time.Time  `json:"requested_at"`
	DeadlineAt             time.Time  `json:"deadline_at"`
	DecidedAt              *time.Time `json:"decided_at,omitempty"`
	DecidedBy              *string    `json:"decided_by,omitempty"`
	ClaimDeadlineAt        *time.Time `json:"claim_deadline_at,omitempty"`
	ClaimedAt              *time.Time `json:"claimed_at,omitempty"`
	PublicDecisionMessage  *string    `json:"public_decision_message,omitempty"`
	PrivateNote            *string    `json:"private_note,omitempty"`
	SourceIP               *string    `json:"source_ip,omitempty"`
	// SourceGeoCountry/SourceGeoCity: both omitted when no GeoIP
	// database is configured, or the lookup simply didn't resolve --
	// never an error either way (internal/geoip).
	SourceGeoCountry *string `json:"source_geo_country,omitempty"`
	SourceGeoCity    *string `json:"source_geo_city,omitempty"`
	UserAgent        *string `json:"user_agent,omitempty"`
	Version          int32   `json:"version"`
}

func newRequestDTO(r store.ApprovalRequest) requestDTO {
	dto := requestDTO{
		ID: r.ID.String(), ApplicationID: r.ApplicationID.String(),
		ApplicationHostname: r.ApplicationHostname, ApplicationDisplayName: r.ApplicationDisplayName,
		VerificationCode: r.VerificationCode,
		Label:            r.Label, Message: r.Message, Status: r.Status, RequestedAt: r.RequestedAt, DeadlineAt: r.DeadlineAt,
		DecidedAt: r.DecidedAt, DecidedBy: r.DecidedBy, ClaimDeadlineAt: r.ClaimDeadlineAt, ClaimedAt: r.ClaimedAt,
		PublicDecisionMessage: r.PublicDecisionMessage, PrivateNote: r.PrivateNote, UserAgent: r.UserAgent, Version: r.Version,
		SourceGeoCountry: r.SourceGeoCountry, SourceGeoCity: r.SourceGeoCity,
	}
	// Requests submitted without a device label rely on this (plus
	// UserAgent) as the admin's only way to tell devices apart -- see
	// the request page's auto-submit behavior in app.js.
	if r.SourceIP != nil {
		s := r.SourceIP.String()
		dto.SourceIP = &s
	}
	return dto
}

type authorizationDTO struct {
	ID                     string     `json:"id"`
	ApplicationID          string     `json:"application_id"`
	ApplicationHostname    string     `json:"application_hostname"`
	ApplicationDisplayName string     `json:"application_display_name"`
	RequestID              string     `json:"request_id"`
	Label                  *string    `json:"label,omitempty"`
	ApprovedBy             string     `json:"approved_by"`
	ApprovedAt             time.Time  `json:"approved_at"`
	ActivatedAt            *time.Time `json:"activated_at,omitempty"`
	ExpiresAt              time.Time  `json:"expires_at"`
	RevokedAt              *time.Time `json:"revoked_at,omitempty"`
	RevokedBy              *string    `json:"revoked_by,omitempty"`
	RevocationReason       *string    `json:"revocation_reason,omitempty"`
	LastSeenAt             *time.Time `json:"last_seen_at,omitempty"`
	LastSeenUserAgent      *string    `json:"last_seen_user_agent,omitempty"`
	Version                int32      `json:"version"`
}

func newAuthorizationDTO(a store.Authorization) authorizationDTO {
	return authorizationDTO{
		ID: a.ID.String(), ApplicationID: a.ApplicationID.String(),
		ApplicationHostname: a.ApplicationHostname, ApplicationDisplayName: a.ApplicationDisplayName,
		RequestID: a.RequestID.String(),
		Label:     a.Label, ApprovedBy: a.ApprovedBy, ApprovedAt: a.ApprovedAt, ActivatedAt: a.ActivatedAt,
		ExpiresAt: a.ExpiresAt, RevokedAt: a.RevokedAt, RevokedBy: a.RevokedBy, RevocationReason: a.RevocationReason,
		LastSeenAt: a.LastSeenAt, LastSeenUserAgent: a.LastSeenUserAgent, Version: a.Version,
	}
}

// noteDTO is the shared shape for both request_notes and
// authorization_notes rows -- distinct source tables, identical fields,
// so one DTO covers both rather than two structurally-duplicate ones.
type noteDTO struct {
	ID            string    `json:"id"`
	AuthorSubject string    `json:"author_subject"`
	Body          string    `json:"body"`
	CreatedAt     time.Time `json:"created_at"`
}

func newRequestNoteDTO(n store.RequestNote) noteDTO {
	return noteDTO{ID: n.ID.String(), AuthorSubject: n.AuthorSubject, Body: n.Body, CreatedAt: n.CreatedAt}
}

func newAuthorizationNoteDTO(n store.AuthorizationNote) noteDTO {
	return noteDTO{ID: n.ID.String(), AuthorSubject: n.AuthorSubject, Body: n.Body, CreatedAt: n.CreatedAt}
}

type auditEventDTO struct {
	ID              string    `json:"id"`
	OccurredAt      time.Time `json:"occurred_at"`
	ActorType       string    `json:"actor_type"`
	ActorSubject    *string   `json:"actor_subject,omitempty"`
	Action          string    `json:"action"`
	ApplicationID   *string   `json:"application_id,omitempty"`
	RequestID       *string   `json:"request_id,omitempty"`
	AuthorizationID *string   `json:"authorization_id,omitempty"`
	CorrelationID   string    `json:"correlation_id"`
	Reason          *string   `json:"reason,omitempty"`
	Outcome         string    `json:"outcome"`
}

func newAuditEventDTO(e store.AuditEvent) auditEventDTO {
	dto := auditEventDTO{
		ID: e.ID.String(), OccurredAt: e.OccurredAt, ActorType: e.ActorType, ActorSubject: e.ActorSubject,
		Action: e.Action, CorrelationID: e.CorrelationID.String(), Reason: e.Reason, Outcome: e.Outcome,
	}
	if e.ApplicationID != nil {
		s := e.ApplicationID.String()
		dto.ApplicationID = &s
	}
	if e.RequestID != nil {
		s := e.RequestID.String()
		dto.RequestID = &s
	}
	if e.AuthorizationID != nil {
		s := e.AuthorizationID.String()
		dto.AuthorizationID = &s
	}
	return dto
}

// decodeJSONBody enforces spec section 9's "Maximum JSON body size is 16
// KiB" and maps a malformed body to the standard structured error.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeAPIError(w, http.StatusBadRequest, "malformed_request", "could not parse request body")
		return false
	}
	return true
}

// parseUUIDPathParam extracts and parses the {id} path parameter every
// admin detail/mutation route uses, writing a 404 (spec section 9:
// "unknown records 404") if it's not a well-formed UUID -- a malformed
// ID can never match a real row, so there's no need to distinguish it
// from a syntactically valid but nonexistent one.
func parseUUIDPathParam(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "not_found", "no such record")
		return uuid.UUID{}, false
	}
	return id, true
}
