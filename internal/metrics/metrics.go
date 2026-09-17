// Package metrics defines the Prometheus metrics spec section 15 lists,
// registered once at package init and exported on the Ops listener's
// GET /metrics (spec section 15: "Restrict metrics to operations
// access" -- the Ops listener is already "internal monitoring network
// only," per spec section 2's listener table).
//
// Every label set here is deliberately low-cardinality (spec section
// 15: "Application ID labels are allowed only for a bounded registered
// set; never label by cookie, IP, request ID, or session ID") --
// callers pass a category/action/reason string, never a raw identifier.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuthDecisions counts every ForwardAuth /auth decision by category
	// (allow/unknown_host/missing_or_invalid_credential/revoked_or_disabled)
	// and its specific reason.
	AuthDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "manual_approval_auth_decisions_total",
		Help: "ForwardAuth /auth decisions by category and reason.",
	}, []string{"category", "reason"})

	// AuthDecisionDuration is the /auth handler's end-to-end latency
	// (spec section 15: "auth latency histogram"; section 15's
	// performance target is p95 <=50ms, p99 <=150ms).
	AuthDecisionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "manual_approval_auth_decision_duration_seconds",
		Help:    "Latency of the /auth ForwardAuth decision.",
		Buckets: prometheus.DefBuckets,
	})

	// AdminActions counts approve/deny/renew/revoke by outcome
	// (success/conflict/error).
	AdminActions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "manual_approval_admin_actions_total",
		Help: "Admin approve/deny/renew/revoke actions by action and outcome.",
	}, []string{"action", "outcome"})

	// PollErrors counts GET /status errors by reason.
	PollErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "manual_approval_poll_errors_total",
		Help: "GET /__manual-approval/status errors by reason.",
	}, []string{"reason"})

	// ClaimErrors counts POST /claim errors by reason.
	ClaimErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "manual_approval_claim_errors_total",
		Help: "POST /__manual-approval/claim errors by reason.",
	}, []string{"reason"})

	// RateLimitRejections counts requests rejected by a rate limit, by
	// which limit rejected them (spec section 11, control 6).
	RateLimitRejections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "manual_approval_rate_limit_rejections_total",
		Help: "Requests rejected by a rate limit, by limit name.",
	}, []string{"limit"})

	// AuditInsertFailures counts audit_events insert failures -- spec
	// section 12: "Mutations fail if their audit event cannot commit,"
	// so this should track failed *mutations*, not just failed audit
	// writes with an otherwise-successful mutation (that combination
	// cannot happen by construction).
	AuditInsertFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "manual_approval_audit_insert_failures_total",
		Help: "Mutations that failed because their audit event could not commit.",
	})

	// PendingRequests, ActiveAuthorizations, and ExpiringSoonAuthorizations
	// are periodically set from store.GetOverviewCounts (spec section
	// 15: "active/pending/expiring counts").
	PendingRequests = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "manual_approval_pending_requests",
		Help: "Current count of pending approval requests.",
	})
	ActiveAuthorizations = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "manual_approval_active_authorizations",
		Help: "Current count of active (claimed, unexpired, unrevoked) authorizations.",
	})
	ExpiringSoonAuthorizations = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "manual_approval_expiring_soon_authorizations",
		Help: "Current count of active authorizations expiring within the configured window.",
	})

	// CleanupLastSuccessTimestamp is the Unix time each retention/
	// cleanup job (internal/worker) last completed successfully (spec
	// section 15: "cleanup lag"). Recording the timestamp rather than a
	// continuously-ticking lag value is the standard Prometheus pattern:
	// alerting computes `time() - this > 900` for section 15's ">15
	// minutes" threshold instead of the app needing its own ticker to
	// keep a lag gauge current between runs.
	CleanupLastSuccessTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "manual_approval_cleanup_last_success_timestamp_seconds",
		Help: "Unix timestamp each retention/cleanup job last completed successfully.",
	}, []string{"job"})

	// Ready is 1 once this replica has completed startup and is
	// serving all four listeners (spec section 15: "ready replicas";
	// section 15's alert is "zero ready replicas immediately").
	Ready = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "manual_approval_ready",
		Help: "1 once this replica has completed startup, 0 otherwise.",
	})
)
