// Package version holds this build's version string, set at build time
// via -ldflags "-X github.com/frid-iks/approve-auth/internal/version.Version=..."
// (see Dockerfile's VERSION build arg) -- never bump this by hand here.
package version

// Version must stay a var, not a const: the linker's -X flag can only
// override package-level string variables. Left as "dev" for any build
// that doesn't pass the ldflags (a bare `go build`/`docker build` with
// no --build-arg), so an unversioned build never silently claims to be
// a stale real version.
var Version = "dev"
