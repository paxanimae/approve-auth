# Generates the dev-only secret files deploy/dev/docker-compose.yml's
# migrate/approve-auth services mount from ./secrets (gitignored --
# deploy/dev/secrets/ never exists in a fresh checkout or CI runner).
# None of these are real secrets: the database credentials are the fixed
# dev-only role/password migrations/000012_roles_and_grants.up.sql
# already creates for local dev/CI convenience, and the OIDC client
# secret is never checked by cmd/mock-oidc. Only the two AES-256 keys
# are randomly generated, entirely inside a container -- nothing
# installed on this machine -- and only because internal/config
# requires a well-formed 32-byte key, not because their actual value
# matters for a database that's recreated on every run.
#
# Safe to run repeatedly: existing files are left alone, so it never
# clobbers keys a long-running local stack already has data encrypted
# under.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Dir = Join-Path $Root "deploy\dev\secrets"
$OpenSSLImage = "alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

function Write-IfMissing {
    param([string]$Name, [string]$Value)
    $path = Join-Path $Dir $Name
    if (Test-Path $path) {
        Write-Host "Skipping $Name (already exists)"
        return
    }
    [System.IO.File]::WriteAllText($path, $Value)
    Write-Host "Wrote $Name"
}

function New-AesKeyIfMissing {
    param([string]$Name)
    $path = Join-Path $Dir $Name
    if (Test-Path $path) {
        Write-Host "Skipping $Name (already exists)"
        return
    }
    $key = (docker run --rm $OpenSSLImage rand -base64 32) -join ""
    [System.IO.File]::WriteAllText($path, $key)
    Write-Host "Wrote $Name"
}

Write-IfMissing "database-url-superuser.txt" "postgres://postgres:devpassword@db:5432/approve_auth?sslmode=disable"
Write-IfMissing "database-url.txt" "postgres://approve_auth_app:devpassword@db:5432/approve_auth?sslmode=disable"
Write-IfMissing "oidc-client-secret.txt" "dev-placeholder-oidc-client-secret"
New-AesKeyIfMissing "claim-encryption-key.txt"
New-AesKeyIfMissing "oidc-state-key.txt"

Write-Host "Dev secrets ready in $Dir"
