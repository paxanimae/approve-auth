DROP ROLE IF EXISTS approve_auth_maintenance;
DROP ROLE IF EXISTS approve_auth_app;

REVOKE ALL PRIVILEGES ON
    applications,
    enrollment_contexts,
    approval_requests,
    authorizations,
    credentials,
    claim_results,
    admin_sessions,
    oidc_transactions,
    audit_events,
    rate_limit_buckets,
    idempotency_records
FROM app_runtime, app_maintenance;

DROP ROLE IF EXISTS app_maintenance;
DROP ROLE IF EXISTS app_runtime;
