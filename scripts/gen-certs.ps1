# Generates self-signed dev-only TLS certs for the two-host local test
# stack (deploy/dev/docker-compose.yml's app-a/app-b services), entirely
# inside a container -- nothing is installed or trusted on this machine.
#
# Browsers will show a certificate warning for these -- that's expected.
# (mkcert would avoid that by installing a locally-trusted CA into the OS
# trust store, a host-side change this script deliberately doesn't make.)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$CertsDir = Join-Path $Root "deploy\dev\certs"
$OpenSSLImage = "alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb"

New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

function New-HostCert {
    param([string]$HostName)
    docker run --rm -v "${CertsDir}:/certs" $OpenSSLImage req -x509 -nodes `
        -newkey ec -pkeyopt ec_paramgen_curve:P-256 `
        -days 365 `
        -keyout "/certs/$HostName-key.pem" `
        -out "/certs/$HostName.pem" `
        -subj "/CN=$HostName" `
        -addext "subjectAltName=DNS:$HostName"
}

New-HostCert -HostName "app-a.localtest.me"
New-HostCert -HostName "app-b.localtest.me"
New-HostCert -HostName "protected.localtest.me"

Write-Host "Generated self-signed dev certs in $CertsDir"
Write-Host "Browsers will show a certificate warning for these -- see this script's header comment."
