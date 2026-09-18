# Public pages (TV request/waiting flow)

Server-rendered `html/template` plus a small progressive-enhancement
vanilla-JS file -- no bundler, no framework, no build step. These pages
must work with keyboard/remote input and retain a manual refresh path with
JavaScript disabled entirely (spec section 2/5): a reception TV browser is
not guaranteed to run arbitrary modern JavaScript reliably.

Milestone 1 wires up only the asset-serving mechanism (`GET
/__approve-auth/assets/*`, embedded via `embed.go` and served by
`internal/httpserver`) and this placeholder template, to validate that
path early. The actual request/waiting/claim pages render real content
starting Milestone 2 -- see `docs/threat-model.md` and spec section 5 for
what each state (pending, approved, denied, expired, revoked, ...) needs
to show.
