#!/usr/bin/env bash
# Bootstrap the vendored Lattice engine (vendor/lattice).
#
# Creates an isolated venv inside vendor/lattice/.venv and installs the engine
# in editable mode so OpenHack's structural code-audit bridge
# (.openhack/tool/lattice-codeaudit.sh) can run it WITHOUT any global/PATH
# install. Idempotent — safe to re-run; skips work when the venv already works.
#
# Optional extras:
#   OPENHACK_LATTICE_EXTRAS="mcp,cpp,symbolic" ./bootstrap.sh
#   (default: "mcp" — the MCP server deps; add cpp/symbolic for those frontends)
#
# Usage:
#   vendor/lattice/bootstrap.sh [--force]
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="$HERE/.venv"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

ENGINE_OK() {
  [ -x "$VENV/bin/lattice" ] && "$VENV/bin/lattice" --help >/dev/null 2>&1
}

if [ "$FORCE" -eq 0 ] && ENGINE_OK; then
  echo "bootstrap: vendored lattice already OK at $VENV/bin/lattice"
  exit 0
fi

PYTHON="${OPENHACK_LATTICE_PYTHON:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || { echo "bootstrap: $PYTHON not found on PATH" >&2; exit 2; }

echo "bootstrap: creating venv at $VENV ($PYTHON)"
"$PYTHON" -m venv "$VENV"

echo "bootstrap: pip install -e .[${OPENHACK_LATTICE_EXTRAS:-mcp}]"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$HERE[${OPENHACK_LATTICE_EXTRAS:-mcp}]"

if ENGINE_OK; then
  echo "bootstrap: OK — $(readlink -f "$VENV/bin/lattice")"
else
  echo "bootstrap: installed but 'lattice --help' failed — inspect $VENV" >&2
  exit 2
fi

# Optional: enable the ts/js LSP frontend. multilspy insists on installing
# typescript + typescript-language-server via npm into its own static dir; do
# it here once so audits don't have to. Best-effort — offline hosts just lose
# ts/js coverage and every report lists it as a blind spot.
STATIC_DIR="$(find "$VENV/lib" -maxdepth 7 -type d -path '*multilspy*typescript_language_server/static' 2>/dev/null | head -1)"
if [ -n "$STATIC_DIR" ] && [ ! -e "$STATIC_DIR/ts-lsp/node_modules/.bin/typescript-language-server" ] && command -v npm >/dev/null 2>&1; then
  if mkdir -p "$STATIC_DIR/ts-lsp" && (cd "$STATIC_DIR/ts-lsp" && npm install --no-audit --no-fund --silent typescript typescript-language-server >/dev/null 2>&1); then
    echo "bootstrap: ts/js LSP frontend installed"
  else
    echo "bootstrap: npm offline/failed — ts/js will be a blind spot (python/go/rust unaffected)" >&2
  fi
fi
