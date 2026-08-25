#!/usr/bin/env bash
# usage: scripts/split-test-packages.sh unit|integration
#
# Splits `go list ./...` into the two test batches CI runs in parallel:
#   - unit:        packages whose tests need no external services
#   - integration: packages whose tests start Testcontainers (PostgreSQL/Redis)
#
# The split is dynamic, not a hardcoded list: a package belongs to the
# integration batch if and only if one of its *_test.go files imports the
# internal testutil package (which is what provisions the containers). A new
# package that gains container tests therefore lands in the right job by
# itself, and a test that needs a database cannot silently run without one.
# The test-split job in ci.yml asserts the two batches partition ./... exactly.
set -euo pipefail

mode=${1:?usage: split-test-packages.sh unit|integration}
case "$mode" in
  unit|integration) ;;
  *) echo "::error::mode must be unit or integration, got: $mode" >&2; exit 1 ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Exact import string, quoted: a subpackage such as testutil/redis (if one ever
# appears) imports a different string and must be judged on its own merits.
import_pattern='"github.com/NJUPT-SAST/sast-link-backend-v2/internal/testutil"'

selected=0
for pkg in $(go list ./...); do
  dir=$(go list -f '{{.Dir}}' "$pkg")
  needs_docker=0
  for f in "$dir"/*_test.go; do
    [ -e "$f" ] || continue
    if grep -qF "$import_pattern" "$f"; then
      needs_docker=1
      break
    fi
  done
  if { [ "$mode" = integration ] && [ "$needs_docker" = 1 ]; } ||
     { [ "$mode" = unit ] && [ "$needs_docker" = 0 ]; }; then
    printf '%s\n' "$pkg"
    selected=1
  fi
done

# An empty batch is a real signal (say, every integration test was deleted) —
# fail loudly so the workflow is edited instead of silently diverging.
if [ "$selected" = 0 ]; then
  echo "::error::no packages selected for mode $mode" >&2
  exit 1
fi