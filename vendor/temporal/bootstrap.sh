#!/usr/bin/env bash
# bootstrap.sh — build the vendored Temporal durable-execution server binary.
#
# Idempotent; artifact lands in vendor/temporal/bin/temporal-server.
# Framework seam (staged): durable execution backend for long-running loop
# instances; docker-compose service remains the default path (Phase 3b) — see
# vendor/README.md.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/bin/temporal-server"

if [ "${1:-}" = "--check" ]; then
    [ -x "$OUT" ] && exit 0
    echo "temporal not bootstrapped — run: $0 (or use the docker-compose service)" >&2
    exit 1
fi

if [ -x "$OUT" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "temporal already bootstrapped: $OUT (FORCE=1 to rebuild)"
    exit 0
fi

command -v go >/dev/null 2>&1 || { echo "error: go not found on PATH — install Go, or run Temporal via docker-compose" >&2; exit 1; }
mkdir -p "$HERE/bin"
(cd "$HERE" && go build -o "$OUT" ./cmd/server)
echo "temporal → $OUT"
