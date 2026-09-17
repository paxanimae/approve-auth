-- Two NOLOGIN group roles enforce audit-log immutability at the database
-- level (spec section 11, control 10): the runtime role can insert audit
-- events but never update or delete them; only a separate maintenance role,
-- used solely by retention jobs, can delete them.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_runtime') THEN
        CREATE ROLE app_runtime NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_maintenance') THEN
        CREATE ROLE app_maintenance NOLOGIN;
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    applications,
    enrollment_contexts,
    approval_requests,
    authorizations,
    credentials,
    claim_results,
    admin_sessions,
    oidc_transactions
TO app_runtime;

-- audit_events: insert-only for the runtime role. No UPDATE, no DELETE.
GRANT SELECT, INSERT ON audit_events TO app_runtime;

-- rate_limit_buckets / idempotency_records: the runtime role manages these
-- directly (increment counters, expire idempotency entries), so it keeps
-- DELETE here unlike audit_events.
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_buckets, idempotency_records TO app_runtime;

GRANT SELECT, DELETE ON audit_events TO app_maintenance;
GRANT SELECT, DELETE ON rate_limit_buckets, idempotency_records TO app_maintenance;
GRANT SELECT, DELETE ON approval_requests, authorizations TO app_maintenance;

-- Concrete LOGIN roles for local dev/CI convenience only. Production
-- deployments provision their own credentials via secrets management and
-- simply `GRANT app_runtime TO <prod_user>;` / `GRANT app_maintenance TO
-- <prod_user>;` -- see docs/dev-environment.md.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'manual_approval_app') THEN
        CREATE ROLE manual_approval_app LOGIN PASSWORD 'devpassword' IN ROLE app_runtime;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'manual_approval_maintenance') THEN
        CREATE ROLE manual_approval_maintenance LOGIN PASSWORD 'devpassword' IN ROLE app_maintenance;
    END IF;
END
$$;
