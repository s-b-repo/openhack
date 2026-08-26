#!/usr/bin/env bash
# bootstrap.sh — build a self-contained venv for the vendored mini-swe-agent
# (SWE-bench-grade minimal coding agent CLI).
#
# Idempotent; artifacts land in vendor/mini-swe-agent/.venv. Resolution:
#   1. explicit override by caller   2. this .venv   3. PATH
# Framework seam (staged): alternative execution agent for automode loop
# instances — see vendor/README.md.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

if [ "${1:-}" = "--check" ]; then
    [ -x "$VENV/bin/mini" ] && exit 0
    echo "mini-swe-agent not bootstrapped — run: $0" >&2
    exit 1
fi

if [ -x "$VENV/bin/mini" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "mini-swe-agent already bootstrapped: $VENV/bin/mini (FORCE=1 to rebuild)"
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$HERE"
echo "mini-swe-agent → $VENV/bin/mini"
