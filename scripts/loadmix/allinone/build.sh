#!/bin/bash
# Builds the sastlink-allinone:test bench image. Cross-compiles the api and
# migrate binaries for the container's linux/arm64 (docker-proxy target), then
# builds the image from this directory. The api binary is built with PGO auto so
# cmd/api/default.pgo is honored when present.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"

cd "$ROOT"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -pgo=auto -o "$HERE/api" ./cmd/api
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$HERE/migrate" ./cmd/migrate
docker build -t sastlink-allinone:test "$HERE"

rm -f "$HERE/api" "$HERE/migrate"
echo "built sastlink-allinone:test"
