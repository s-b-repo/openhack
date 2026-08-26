#!/usr/bin/env bash
# bootstrap.sh — build a self-contained venv for the vendored GPT Researcher
# (deep research agent).
#
# Idempotent; artifacts land in vendor/gpt-researcher/.venv.
# Framework seam (staged): osint deep-research provider behind the `osint`
# agent role — see vendor/README.md. Entry points after bootstrap:
#   .venv/bin/python cli.py --help     # research CLI
#   .venv/bin/uvicorn backend.main:app # hosted API
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

if [ "${1:-}" = "--check" ]; then
    [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import gpt_researcher" >/dev/null 2>&1 && exit 0
    echo "gpt-researcher not bootstrapped — run: $0" >&2
    exit 1
fi

if "$HERE/bootstrap.sh" --check >/dev/null 2>&1 && [ "${FORCE:-0}" != "1" ]; then
    echo "gpt-researcher already bootstrapped: $VENV (FORCE=1 to rebuild)"
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$HERE"
echo "gpt-researcher → $VENV (CLI: .venv/bin/python cli.py)"
