// Package public embeds the server-rendered HTML templates and the small
// vanilla-JS/CSS assets for the no-JS-required TV request/waiting pages
// (spec section 2/5), so cmd/server stays a single self-contained binary.
// Only the asset-serving mechanism is wired up in Milestone 1 -- the
// templates render real content starting Milestone 2.
package public

import "embed"

//go:embed assets
var Assets embed.FS

//go:embed templates
var Templates embed.FS
