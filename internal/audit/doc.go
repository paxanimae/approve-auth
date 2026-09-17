// Package audit records audit_events. It is the only package permitted to
// write that table, and it never issues UPDATE or DELETE -- the database
// grants for the runtime role enforce that independently (see
// migrations/000012_roles_and_grants.up.sql), but this package's own API
// has no method that could do so either.
package audit
