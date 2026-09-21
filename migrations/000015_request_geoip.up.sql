-- Coarse GeoIP enrichment of a request's source_ip (country/city from a
-- MaxMind GeoLite2-City lookup, best-effort -- see internal/geoip).
-- Both NULL means either no GeoIP database is configured, or the
-- lookup simply didn't resolve (private/reserved/unknown address).
-- Deliberately reuses source_ip's own 30-day redaction window (see
-- RedactOldClientMetadata) rather than a separate retention category:
-- this is derived from source_ip, so it has no reason to outlive it.
ALTER TABLE approval_requests ADD COLUMN source_geo_country TEXT;
ALTER TABLE approval_requests ADD COLUMN source_geo_city TEXT;
