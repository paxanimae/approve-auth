package httpserver

import (
	"encoding/csv"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/paxanimae/approve-auth/internal/store"
)

// --- GET /api/v1/audit-events ---

func listAuditEventsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := parseAuditEventsQuery(w, r)
		if !ok {
			return
		}
		events, err := readStore.ListAuditEvents(r.Context(), p)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to list audit events")
			return
		}
		dtos := make([]auditEventDTO, len(events))
		for i, e := range events {
			dtos[i] = newAuditEventDTO(e)
		}
		writeJSON(w, http.StatusOK, map[string]any{"audit_events": dtos})
	}
}

func parseAuditEventsQuery(w http.ResponseWriter, r *http.Request) (store.ListAuditEventsParams, bool) {
	q := r.URL.Query()
	p := store.ListAuditEventsParams{ActorSubject: q.Get("actor_subject"), Action: q.Get("action"), Outcome: q.Get("outcome")}

	if v := q.Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "invalid application_id")
			return store.ListAuditEventsParams{}, false
		}
		p.ApplicationID = &id
	}
	if v := q.Get("occurred_after"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "occurred_after must be an RFC3339 timestamp")
			return store.ListAuditEventsParams{}, false
		}
		p.OccurredAfter = t
	}
	if v := q.Get("occurred_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, "invalid_input", "occurred_before must be an RFC3339 timestamp")
			return store.ListAuditEventsParams{}, false
		}
		p.OccurredBefore = t
	}
	p.Limit = parseLimitQuery(r)
	return p, true
}

// --- GET /api/v1/audit-events/export ---

// exportAuditEventsHandler streams a CSV of the filtered audit log,
// capped at spec section 9's 10,000-row export maximum (store.
// ListAuditEvents already caps there), sanitizing spreadsheet formula
// prefixes (spec section 9/11: "Sanitize spreadsheet formula prefixes in
// CSV exports") and recording the export itself as its own audit event
// (spec section 9: "audit the export itself").
func exportAuditEventsHandler(readStore AdminReadStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := parseAuditEventsQuery(w, r)
		if !ok {
			return
		}
		p.Limit = 10000

		events, err := readStore.ListAuditEvents(r.Context(), p)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to export audit events")
			return
		}

		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="audit-events.csv"`)
		w.Header().Set("Cache-Control", "no-store")

		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "occurred_at", "actor_type", "actor_subject", "action", "application_id", "request_id", "authorization_id", "correlation_id", "reason", "outcome"})
		for _, e := range events {
			_ = cw.Write([]string{
				e.ID.String(), e.OccurredAt.Format(time.RFC3339), e.ActorType, csvSafe(derefStr(e.ActorSubject)), csvSafe(e.Action),
				uuidOrEmpty(e.ApplicationID), uuidOrEmpty(e.RequestID), uuidOrEmpty(e.AuthorizationID),
				e.CorrelationID.String(), csvSafe(derefStr(e.Reason)), e.Outcome,
			})
		}
		cw.Flush()

		_ = readStore.RecordAuditEvent(r.Context(), "admin", actorSubject(r), "audit.exported", "")
	}
}

// csvSafe prefixes a leading quote onto any value that would otherwise
// be interpreted as a spreadsheet formula when the export is opened in
// Excel/Sheets (=, +, -, @, or a leading tab/carriage return).
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func uuidOrEmpty(p *uuid.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

// --- GET /api/v1/overview ---

func overviewHandler(readStore AdminReadStore, expiringSoonWindow, recentWindow time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		counts, err := readStore.GetOverviewCounts(r.Context(), expiringSoonWindow, recentWindow)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "failed to load overview counts")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"pending":                   counts.Pending,
			"active":                    counts.Active,
			"expiring_soon":             counts.ExpiringSoon,
			"revoked_or_expired_recent": counts.RevokedOrExpiredRecent,
		})
	}
}
