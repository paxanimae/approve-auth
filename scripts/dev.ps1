# Containerized dev commands. No Go/Node/mkcert install is required on the
# host -- every command below runs inside a pinned Docker image, mounting the
# repo as a bind volume. See docs/tested-versions.md for why these tags.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("build", "vet", "test", "tidy", "fmt", "web-install", "web-build", "web-check", "shell")]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$GoImage = "golang:1.25.14"
$NodeImage = "node:22.23.2"

function Invoke-Go {
    param([string[]]$GoArgs)
    $netArgs = @()
    if ($env:DEV_NETWORK) { $netArgs = @("--network", $env:DEV_NETWORK) }
    docker run --rm `
        -v "${Root}:/workspace" `
        -v traefik-manual-proxy-gomod:/go/pkg/mod `
        -w /workspace `
        -e GOCACHE=/workspace/.gocache `
        -e GOFLAGS=-mod=mod `
        -e "TEST_DATABASE_URL=$($env:TEST_DATABASE_URL)" `
        @netArgs `
        $GoImage @GoArgs
}

function Invoke-Node {
    param([string[]]$NodeArgs)
    docker run --rm `
        -v "${Root}\web\admin:/workspace" `
        -w /workspace `
        $NodeImage @NodeArgs
}

switch ($Command) {
    "build"        { Invoke-Go @("go", "build", "./...") }
    "vet"          { Invoke-Go @("go", "vet", "./...") }
    "test" {
        # -p 1: packages share one real Postgres instance via TEST_DATABASE_URL
        # and some (internal/store) drop/recreate the whole schema mid-test, so
        # running package test binaries concurrently races.
        if ($env:TEST_DATABASE_URL) {
            Invoke-Go (@("go", "test", "./...", "-race", "-p", "1") + $Rest)
        } else {
            Invoke-Go (@("go", "test", "./...", "-race") + $Rest)
        }
    }
    "tidy"         { Invoke-Go @("go", "mod", "tidy") }
    "fmt"          { Invoke-Go @("gofmt", "-l", "-w", ".") }
    "web-install"  { Invoke-Node @("npm", "install") }
    "web-build"    { Invoke-Node @("npm", "run", "build") }
    "web-check"    { Invoke-Node @("npm", "run", "check") }
    "shell"        { Invoke-Go @("bash") }
}
