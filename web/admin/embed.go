// Package admin embeds the built Svelte admin console (spec section 2:
// "Serve compiled admin assets from the Go binary") so cmd/server stays a
// single self-contained binary. dist is produced by `npm run build`
// (scripts/dev.sh web-build) and is gitignored -- the Docker build's Node
// stage runs that build before the Go stage compiles this package, and
// local development needs it run at least once too (see
// docs/dev-environment.md).
package admin

import "embed"

//go:embed dist
var Dist embed.FS
