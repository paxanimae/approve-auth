// Package store owns the PostgreSQL connection pool and schema migrations.
// It is the only package that talks to the database directly; it defines
// no repository/business methods yet (see models.go) -- those land in the
// milestone that adds the code calling them.
package store
