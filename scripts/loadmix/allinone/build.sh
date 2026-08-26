#!/bin/bash
# Builds the sastlink-allinone:test bench image: cross-compiles api and migrate
# for the container architecture, then builds the image from this directory (api
# built with -pgo=auto so cmd/api/default.pgo is honored).
#
# Target arch is read from the Docker daemon rather than hardcoded: an emulated
# wrong-arch binary still produces plausible latency numbers — the worst outcome
# for a bench harness. Override with BENCH_GOARCH if needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${BENCH_GOARCH:-}" ]; then
  case "$(docker info --format '{{.Architecture}}')" in
    x86_64 | amd64) BENCH_GOARCH=amd64 ;;
    aarch64 | arm64) BENCH_GOARCH=arm64 ;;
    *)
      echo "cannot map Docker architecture '$(docker info --format '{{.Architecture}}')' to a GOARCH; set BENCH_GOARCH" >&2
      exit 1
      ;;
  esac
fi
echo "building for linux/$BENCH_GOARCH"

cd "$ROOT"
GOOS=linux GOARCH="$BENCH_GOARCH" CGO_ENABLED=0 go build -pgo=auto -o "$HERE/api" ./cmd/api
GOOS=linux GOARCH="$BENCH_GOARCH" CGO_ENABLED=0 go build -o "$HERE/migrate" ./cmd/migrate
docker build -t sastlink-allinone:test "$HERE"

rm -f "$HERE/api" "$HERE/migrate"
echo "built sastlink-allinone:test"
