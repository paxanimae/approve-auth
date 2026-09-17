# Generates a dev-only CA plus a server cert (the manual-approval
# service's Authorization listener identity) and a client cert (what
# Traefik presents to it), entirely inside a container -- nothing
# installed or trusted on this machine. Used by the real-Traefik
# integration test and by deploy/dev/docker-compose.yml's traefik service.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Dir = Join-Path $Root "deploy\dev\mtls"
$OpenSSLImage = "alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

New-Item -ItemType Directory -Force -Path $Dir | Out-Null

function Invoke-OpenSSL {
    param([string[]]$OpenSSLArgs)
    docker run --rm -v "${Dir}:/certs" -w /certs $OpenSSLImage @OpenSSLArgs
}

Invoke-OpenSSL @("req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-days", "3650", `
    "-keyout", "ca-key.pem", "-out", "ca-cert.pem", "-subj", "/CN=manual-approval-dev-ca")

Invoke-OpenSSL @("req", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", `
    "-keyout", "server-key.pem", "-out", "server.csr", "-subj", "/CN=manual-approval", `
    "-addext", "subjectAltName=DNS:manual-approval")
Invoke-OpenSSL @("x509", "-req", "-in", "server.csr", "-CA", "ca-cert.pem", "-CAkey", "ca-key.pem", "-CAcreateserial", `
    "-out", "server-cert.pem", "-days", "365", "-copy_extensions", "copyall")

Invoke-OpenSSL @("req", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", `
    "-keyout", "traefik-client-key.pem", "-out", "traefik-client.csr", "-subj", "/CN=traefik-client")
Invoke-OpenSSL @("x509", "-req", "-in", "traefik-client.csr", "-CA", "ca-cert.pem", "-CAkey", "ca-key.pem", "-CAcreateserial", `
    "-out", "traefik-client-cert.pem", "-days", "365")

Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Dir "*.csr"), (Join-Path $Dir "*.srl")

Write-Host "Generated dev mTLS material in $Dir"
