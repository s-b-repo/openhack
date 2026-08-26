#!/usr/bin/env bash
# bootstrap.sh — build a self-contained venv for the vendored DeepAgents
# library (LangChain's deep-agents scaffolding).
#
# Idempotent; artifacts land in vendor/deepagents/.venv.
# Framework seam (staged): planner/sub-agent scaffolding reference for the
# manager tier — see vendor/README.md.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
LIB="$HERE/libs/deepagents"

if [ "${1:-}" = "--check" ]; then
    [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import deepagents" >/dev/null 2>&1 && exit 0
    echo "deepagents not bootstrapped — run: $0" >&2
    exit 1
fi

if "$HERE/bootstrap.sh" --check >/dev/null 2>&1 && [ "${FORCE:-0}" != "1" ]; then
    echo "deepagents already bootstrapped: $VENV (FORCE=1 to rebuild)"
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found" >&2; exit 1; }
[ -d "$LIB" ] || { echo "error: $LIB not found in this checkout" >&2; exit 1; }
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$LIB" || {
    echo "warning: editable install failed — installing from PyPI instead" >&2
    "$VENV/bin/pip" install --quiet deepagents
}
echo "deepagents → $VENV"
