#!/usr/bin/env bash
# Chunked Lattice sweep for large source trees.
#
# A single multilspy TS-LSP session chokes (transient BufferError / timeout) on
# trees with hundreds of files, so this splits the tree into chunks of first-
# level subdirectories (+ loose files), materializes each chunk under /tmp, and
# runs the standard lattice-codeaudit bridge per chunk — writing every report
# under .openhack/codeaudit/<label>-chunk<i>/.
#
# Usage: bash script/lattice-sweep-chunked.sh <src-dir> <label> [chunk-dirs-per-run]
set -eu

SRC="${1:?usage: lattice-sweep-chunked.sh <src-dir> <label> [chunk-dirs-per-run]}"
LABEL="${2:?label required}"
PER="${3:-8}"

REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"

mapfile -t ITEMS < <(
  {
    find "$SRC" -mindepth 1 -maxdepth 1 -type d | sort
    find "$SRC" -mindepth 1 -maxdepth 1 -type f \( -name '*.ts' -o -name '*.tsx' \) | sort
  }
)

TOTAL=${#ITEMS[@]}
[ "$TOTAL" -gt 0 ] || { echo "sweep: no items under $SRC"; exit 0; }

WORKROOT="/tmp/opencode/sweep-$(echo "$SRC" | tr '/' '_')"
rm -rf "$WORKROOT"; mkdir -p "$WORKROOT"

CHUNK=0; i=0; SUM_CRIT=0; SUM_HIGH=0; SUM_MED=0; SUM_LOW=0; FAILED=0
declare -a SUMMARIES=()

for item in "${ITEMS[@]}"; do
  if (( i % PER == 0 )); then
    CHUNK=$((CHUNK + 1))
    CDIR="$WORKROOT/chunk$CHUNK"
    mkdir -p "$CDIR"
  fi
  mkdir -p "$CDIR/$(dirname "$item")"
  cp -r "$item" "$CDIR/$item"
  i=$((i + 1))
  if (( i % PER == 0 || i == TOTAL )); then
    echo "── chunk $CHUNK ($i/$TOTAL items) ──"
    # typescript-language-server resolves tsserver by walking up from the
    # workspace root; chunk copies live outside the repo, so give each one a
    # node_modules symlink back to the real tree.
    ln -sfn "$REPO/node_modules" "$CDIR/node_modules"
    OUT=".openhack/codeaudit/${LABEL}-chunk${CHUNK}"
    LINE="$(OPENHACK_CODEAUDIT_DIR="$OUT" LATTICE_LSP_TIMEOUT=60 LATTICE_LEG_TIMEOUT=300 \
      bash .openhack/tool/lattice-codeaudit.sh "$CDIR/$SRC" --quiet 2>&1 | grep LATTICE_CODEAUDIT || true)"
    if [ -z "$LINE" ]; then
      echo "sweep: chunk $CHUNK produced no summary — counting as failed"
      FAILED=$((FAILED + 1))
      continue
    fi
    echo "$LINE"
    SUMMARIES+=("$LINE")
    v() { echo "$LINE" | grep -o "$1=[0-9]*" | cut -d= -f2; }
    SUM_CRIT=$((SUM_CRIT + $(v critical))); SUM_HIGH=$((SUM_HIGH + $(v high)))
    SUM_MED=$((SUM_MED + $(v medium)));     SUM_LOW=$((SUM_LOW + $(v low)))
  fi
done

echo ""
echo "LATTICE_SWEEP label=$LABEL chunks=$CHUNK failed=$FAILED items=$TOTAL critical=$SUM_CRIT high=$SUM_HIGH medium=$SUM_MED low=$SUM_LOW"
