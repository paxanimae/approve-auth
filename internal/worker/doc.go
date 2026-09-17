// Package worker will hold the cleanup/expiry/retention jobs (spec
// section 12) that run against PostgreSQL using advisory locks and
// bounded batches. Job is an interface only -- no scheduler exists yet.
package worker
