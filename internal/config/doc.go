// Package config loads and validates service configuration from a mounted
// YAML file, environment-variable overrides, and Docker-secret ("_FILE")
// paths. Invalid configuration is a startup error: Load never returns a
// Config that Validate would reject.
package config
