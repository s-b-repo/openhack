#!/usr/bin/env bash
# bootstrap.sh — build the vendored Dynamic Context Runtime into a
# self-contained binary at vendor/subnext/bin/dcr.
#
# Idempotent: skips the build when bin/dcr exists and is executable. Re-run
# with FORCE=1 to rebuild from the tracked source.
#
# Resolution order used by bridges (see packages/core/src/session/dcr.ts):
#   1. $DCR_BIN — explicit override
#   2. <repo>/vendor/subnext/bin/dcr — this script's output (preferred)
#   3. `dcr` on PATH — legacy external install
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/bin/dcr"

if [ -x "$OUT" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "dcr already bootstrapped: $OUT (FORCE=1 to rebuild)"
    exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo not found on PATH — install Rust (https://rustup.rs) to bootstrap dcr" >&2
    exit 1
fi

echo "Building dcr (release)…"
(cd "$HERE" && cargo build --release)

mkdir -p "$HERE/bin"
cp "$HERE/target/release/dcr" "$OUT"
chmod +x "$OUT"
echo "dcr → $OUT"
