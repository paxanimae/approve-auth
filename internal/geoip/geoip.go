// Package geoip resolves a client IP to a coarse (country, city) via a
// locally-loaded MaxMind GeoLite2-City (or commercial GeoIP2-City)
// database -- never a network call, never something that can slow down
// or fail a real request. Deployments that don't want this simply leave
// geoip_database_path unset (see internal/config) and get Noop, which
// always reports "unresolved" -- callers never need to nil-check which
// one they have.
//
// This package intentionally does not bundle a database file: MaxMind's
// license terms require each user to register for their own free
// GeoLite2 account and download it themselves (see
// docs/dev-environment.md for the exact steps) -- approve-auth cannot
// do that on anyone's behalf.
package geoip

import (
	"net"

	"github.com/oschwald/geoip2-golang"
)

// Lookup is the interface enrollment.Service depends on, so tests can
// substitute a fake without a real .mmdb file.
type Lookup interface {
	// Lookup resolves ip to a coarse location. ok is false for a
	// private/reserved/malformed/unresolvable address, or whenever the
	// underlying database has nothing for it -- never an error, since
	// this is best-effort enrichment, not something a request should
	// ever fail over.
	Lookup(ip string) (country, city string, ok bool)
}

// Noop is used whenever no GeoIP database is configured.
type Noop struct{}

func (Noop) Lookup(string) (country, city string, ok bool) { return "", "", false }

// MaxMind wraps a memory-mapped GeoLite2-City database file.
type MaxMind struct {
	reader *geoip2.Reader
}

// Open memory-maps the .mmdb file at path. Callers must Close it on
// shutdown to release the mapping.
func Open(path string) (*MaxMind, error) {
	reader, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MaxMind{reader: reader}, nil
}

func (m *MaxMind) Close() error {
	return m.reader.Close()
}

func (m *MaxMind) Lookup(ip string) (country, city string, ok bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", false
	}
	record, err := m.reader.City(parsed)
	if err != nil || record == nil {
		return "", "", false
	}
	country = record.Country.Names["en"]
	city = record.City.Names["en"]
	if country == "" && city == "" {
		return "", "", false
	}
	return country, city, true
}
