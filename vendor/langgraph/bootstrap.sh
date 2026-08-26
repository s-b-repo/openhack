#!/usr/bin/env bash
# bootstrap.sh — build a self-contained venv for the vendored LangGraph
# orchestration library (libs/langgraph + its CLI).
#
# Idempotent; artifacts land in vendor/langgraph/.venv.
# Framework seam (staged): graph-orchestration runtime for manager-tier
# experiments — see vendor/README.md. The npm package @langchain/langgraph is
# the wired integration; this venv covers the Python-side reference tooling.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"

if [ "${1:-}" = "--check" ]; then
    [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import langgraph" >/dev/null 2>&1 && exit 0
    echo "langgraph not bootstrapped — run: $0" >&2
    exit 1
fi

if "$HERE/bootstrap.sh" --check >/dev/null 2>&1 && [ "${FORCE:-0}" != "1" ]; then
    echo "langgraph already bootstrapped: $VENV (FORCE=1 to rebuild)"
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$HERE/libs/langgraph" || {
    echo "warning: editable install of libs/langgraph failed — installing from PyPI instead" >&2
    "$VENV/bin/pip" install --quiet langgraph
}
echo "langgraph → $VENV"
