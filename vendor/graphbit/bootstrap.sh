#!/usr/bin/env bash
# bootstrap.sh — build the vendored GraphBit high-performance agentic framework
# (Rust library crate).
#
# Idempotent; artifacts land in vendor/graphbit/target/release/.
# Framework seam (staged): native Rust agent-runtime library for future
# low-overhead bridges — see vendor/README.md.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--check" ]; then
    ls "$HERE"/target/release/libgraphbit* >/dev/null 2>&1 || \
        ls "$HERE"/target/release/libgraph_bit* >/dev/null 2>&1 || {
        echo "graphbit not bootstrapped — run: $0" >&2
        exit 1
    }
    exit 0
fi

if "$HERE/bootstrap.sh" --check >/dev/null 2>&1 && [ "${FORCE:-0}" != "1" ]; then
    echo "graphbit already bootstrapped: $HERE/target/release (FORCE=1 to rebuild)"
    exit 0
fi

command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found on PATH — install Rust (https://rustup.rs)" >&2; exit 1; }
(cd "$HERE" && cargo build --release)
echo "graphbit → $HERE/target/release"
