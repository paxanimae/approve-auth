# Downloads a GeoLite2-City.mmdb from https://github.com/P3TERX/GeoLite.mmdb
# -- a community mirror that re-publishes MaxMind's free GeoLite2
# databases without requiring a MaxMind account -- into deploy/dev/geoip/,
# entirely inside a container (nothing installed on this machine). That
# directory is gitignored: this repo never bundles/ships the file itself,
# only automates fetching your own copy.
#
# releases/latest/download/<name> always resolves to the mirror's current
# release, so this never needs a version to pin.
#
# For a commercial deployment, or if you'd rather use MaxMind's own
# account-gated download instead of this mirror, see the "Optional: GeoIP
# enrichment" section of docs/dev-environment.md for that alternative path.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$GeoipDir = Join-Path $Root "deploy\dev\geoip"
$CurlImage = "curlimages/curl:8.11.0"
$Url = "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"

New-Item -ItemType Directory -Force -Path $GeoipDir | Out-Null

docker run --rm -v "${GeoipDir}:/out" $CurlImage `
    -fL --retry 3 -o /out/GeoLite2-City.mmdb $Url

Write-Host "Downloaded GeoLite2-City.mmdb into $GeoipDir"
Write-Host "deploy/dev/docker-compose.yml already mounts this directory -- uncomment the approve-auth service's GEOIP_DATABASE_PATH line there, then:"
Write-Host "  docker compose -f deploy/dev/docker-compose.yml up -d approve-auth"
