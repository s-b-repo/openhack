#!/usr/bin/env bash
# lattice-codeaudit — OpenHack bridge to the Lattice structural-analysis engine.
#
# Auto-audits a source tree (any mix of ts/js/py/go/rs/rb/sol/c/cpp/cu/sh/sql)
# by running the Lattice CLI legs — hunt (ranked bugs), secaudit (attack surface
# + source→sink reachability with taint labels), diagnose (cycles / dead code /
# stubs) and triage (severity × blast radius ranking) — and writes JSON +
# Markdown reports to .openhack/codeaudit/ (override with --out or
# OPENHACK_CODEAUDIT_DIR).
#
# Usage:
#   lattice-codeaudit <path> [--langs auto|csv] [--out dir] [--quiet]
#
# Exit codes: 0 = no critical/high findings · 1 = critical/high findings ·
#             2 = audit could not run at all
set -u

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

TARGET=""
LANGS="auto"
OUTDIR="${OPENHACK_CODEAUDIT_DIR:-.openhack/codeaudit}"
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --langs) LANGS="$2"; shift 2 ;;
    --langs=*) LANGS="${1#*=}"; shift ;;
    --out) OUTDIR="$2"; shift 2 ;;
    --out=*) OUTDIR="${1#*=}"; shift ;;
    --quiet|-q) QUIET=1; shift ;;
    -h|--help) usage ;;
    -*) echo "lattice-codeaudit: unknown option $1" >&2; usage ;;
    *) TARGET="$1"; shift ;;
  esac
done

[ -n "$TARGET" ] || usage
[ -d "$TARGET" ] || { echo "lattice-codeaudit: not a directory: $TARGET" >&2; exit 2; }

# ── engine resolution ────────────────────────────────────────────────────────
# The framework vendors the Lattice source at vendor/lattice/ (bootstrap with
# `vendor/lattice/bootstrap.sh`). Resolution order:
#   1. $OPENHACK_LATTICE_BIN — explicit override
#   2. <repo>/vendor/lattice/.venv/bin/lattice — the vendored, self-contained
#      engine (preferred: no global install, pinned to the framework's copy)
#   3. `lattice` on PATH — legacy external install (~/Downloads/Lattice-main)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENDORED_LATTICE="$REPO_ROOT/vendor/lattice"

LATTICE_BIN="${OPENHACK_LATTICE_BIN:-}"
if [ -n "$LATTICE_BIN" ] && [ ! -x "$LATTICE_BIN" ]; then
  echo "lattice-codeaudit: OPENHACK_LATTICE_BIN is set but not executable: $LATTICE_BIN" >&2
  exit 2
fi
if [ -z "$LATTICE_BIN" ] && [ -x "$VENDORED_LATTICE/.venv/bin/lattice" ]; then
  LATTICE_BIN="$VENDORED_LATTICE/.venv/bin/lattice"
fi
if [ -n "$LATTICE_BIN" ]; then
  lattice() { "$LATTICE_BIN" "$@"; }
elif command -v lattice >/dev/null 2>&1; then
  : # fall through — PATH install still works
else
  echo "lattice-codeaudit: no Lattice engine found." >&2
  echo "  vendored: run \`$VENDORED_LATTICE/bootstrap.sh\` then retry" >&2
  echo "  (or set OPENHACK_LATTICE_BIN=/path/to/lattice)" >&2
  exit 2
fi

TARGET="$(readlink -f "$TARGET")"
mkdir -p "$OUTDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
NAME="$(basename "$TARGET")"
WORK="$OUTDIR/$NAME-$STAMP"
mkdir -p "$WORK"

say() { [ "$QUIET" -eq 1 ] || echo "lattice-codeaudit: $*"; }

# Bound every LSP/bridge wait so one broken frontend can't stall the audit.
export LATTICE_LSP_TIMEOUT="${LATTICE_LSP_TIMEOUT:-60}"
LAT_TIMEOUT="${LATTICE_LEG_TIMEOUT:-600}"
# `timeout` execs binaries, not shell functions — resolve the engine once and
# call it directly whether it came from the vendored venv, an override, or PATH.
if [ -n "${LATTICE_BIN:-}" ]; then
  lat() { timeout "$LAT_TIMEOUT" "$LATTICE_BIN" "$@"; }
else
  lat() { timeout "$LAT_TIMEOUT" lattice "$@"; }
fi

# ── language resolution ──────────────────────────────────────────────────────
# `auto` lets Lattice detect + union everything it can. If that fails (missing
# native toolchain, gate failure), fall back to per-language passes so one
# broken frontend never blanks the whole audit.
#
# Ingest is retried once on failure: multilspy's LSP transport has a known
# transient BufferError/pipe race on larger trees — a retry succeeds where a
# single attempt would wrongly record the whole language as a blind spot.
try_ingest() { # try_ingest <lang> [extra ingest args...]
  local lang="$1"; shift
  lat ingest "$TARGET" --lang "$lang" --project openhack-codeaudit \
       --allow-partial "$@" >/dev/null 2>&1 && return 0
  say "pass [$lang]: ingest attempt 1 failed — retrying once"
  sleep 1
  lat ingest "$TARGET" --lang "$lang" --project openhack-codeaudit \
       --allow-partial "$@" >/dev/null 2>&1
}

declare -a PASSES=()
if [ "$LANGS" = "auto" ]; then
  if try_ingest auto --out "$WORK/graph-auto.json"; then
    PASSES+=("auto")
  else
    say "'auto' ingest failed; falling back to per-language passes"
    declare -A LANG_SET=()
    while IFS= read -r f; do
      case "${f##*.}" in
        ts|tsx) LANG_SET["ts"]=1 ;;
        js|jsx|mjs|cjs) LANG_SET["js"]=1 ;;
        py) LANG_SET["py"]=1 ;;
        go) LANG_SET["go"]=1 ;;
        rs) LANG_SET["rs"]=1 ;;
        rb) LANG_SET["rb"]=1 ;;
        sol) LANG_SET["sol"]=1 ;;
        c|h) LANG_SET["c"]=1 ;;
        cpp|cc|cxx|hpp|hh) LANG_SET["cpp"]=1 ;;
        cu|cuh) LANG_SET["cu"]=1 ;;
        sh|bash) LANG_SET["sh"]=1 ;;
        sql) LANG_SET["sql"]=1 ;;
      esac
    done <<< "$(find "$TARGET" \
      -type d \( -name node_modules -o -name .git -o -name .venv -o -name venv \) -prune \
      -o -type f -print 2>/dev/null)"
    if [ "${#LANG_SET[@]}" -eq 0 ]; then
      echo "lattice-codeaudit: no auditable source files under $TARGET" >&2
      exit 2
    fi
    for l in ts js py go rs rb sol c cpp cu sh sql; do
      [ -n "${LANG_SET[$l]:-}" ] && PASSES+=("$l")
    done
  fi
else
  IFS=',' read -r -a PASSES <<< "$LANGS"
fi

[ "${#PASSES[@]}" -gt 0 ] || { echo "lattice-codeaudit: no usable language pass" >&2; exit 2; }

run_leg() { # run_leg <lang> <leg> [extra args...]
  local lang="$1" leg="$2"; shift 2
  lat "$leg" "$TARGET" --lang "$lang" "$@" \
    >"$WORK/$lang-$leg.txt" 2>"$WORK/$lang-$leg.err"
}

# ── audit passes ─────────────────────────────────────────────────────────────
declare -a OK_LANGS=() FAILED_LANGS=()
CRIT_HIGH=0
for l in "${PASSES[@]}"; do
  say "pass [$l]: hunt + secaudit + diagnose + triage on $NAME"
  if ! try_ingest "$l" --out "$WORK/$l-graph.json"; then
    say "pass [$l]: ingest failed — recorded as a blind spot"
    FAILED_LANGS+=("$l")
    continue
  fi
  run_leg "$l" secaudit --out "$WORK/$l-secaudit.json" || true
  run_leg "$l" hunt --fail-on-bugs --out "$WORK/$l-hunt.json" || true
  run_leg "$l" diagnose --out "$WORK/$l-diagnose.json" || true
  run_leg "$l" triage --out "$WORK/$l-triage.json" || true
  OK_LANGS+=("$l")
done

# ── severity rollup across passes ────────────────────────────────────────────
rollup() { # rollup <json> → echoes "critical=N high=N medium=N low=N"
  python3 - "$1" <<'PYEOF'
import json, sys, collections
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("critical=0 high=0 medium=0 low=0"); raise SystemExit
items = []
if isinstance(d, list):
    items = [x for x in d if isinstance(x, dict)]
elif isinstance(d, dict):
    for k in ("findings", "bugs", "issues"):
        if isinstance(d.get(k), list):
            items = [x for x in d[k] if isinstance(x, dict)]
            break
    else:
        # diagnose-style: {cycles: [...], dead_code: [...], ...} — only count
        # entries that actually carry a severity field.
        for v in d.values():
            if isinstance(v, list):
                items.extend(x for x in v if isinstance(x, dict) and "severity" in x)
c = collections.Counter(str(f.get("severity", "low")).lower() for f in items)
print(f"critical={c.get('critical',0)} high={c.get('high',0)} medium={c.get('medium',0)} low={c.get('low',0)}")
PYEOF
}

TOTAL_CRIT=0; TOTAL_HIGH=0; TOTAL_MED=0; TOTAL_LOW=0
get_val() { echo "$1" | tr ' ' '\n' | grep "^$2=" | cut -d= -f2; }
for l in "${OK_LANGS[@]}"; do
  for leg in secaudit hunt diagnose; do
    stats="$(rollup "$WORK/$l-$leg.json")"
    TOTAL_CRIT=$((TOTAL_CRIT + $(get_val "$stats" critical)))
    TOTAL_HIGH=$((TOTAL_HIGH + $(get_val "$stats" high)))
    TOTAL_MED=$((TOTAL_MED + $(get_val "$stats" medium)))
    TOTAL_LOW=$((TOTAL_LOW + $(get_val "$stats" low)))
  done
done

# ── markdown report ──────────────────────────────────────────────────────────
REPORT="$WORK/report.md"
{
  echo "# Lattice code-audit — $NAME"
  echo ""
  echo "- **Target:** \`$TARGET\`"
  echo "- **Date:** $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "- **Language passes:** ${OK_LANGS[*]:-none}"
  echo "- **Engine:** ${LATTICE_BIN:-lattice (PATH)}"
  [ "${#FAILED_LANGS[@]}" -gt 0 ] && echo "- **Blind spots (failed legs):** ${FAILED_LANGS[*]}"
  echo "- **Findings:** critical=$TOTAL_CRIT high=$TOTAL_HIGH medium=$TOTAL_MED low=$TOTAL_LOW"
  echo ""
  for l in "${OK_LANGS[@]}"; do
    echo "## Pass: $l"
    echo ""
    for leg in secaudit hunt diagnose triage; do
      if [ -s "$WORK/$l-$leg.json" ]; then
        echo "### $leg"
        echo ""
        echo '```json'
        head -c 20000 "$WORK/$l-$leg.json"
        echo ""
        echo '```'
        echo ""
      elif [ -s "$WORK/$l-$leg.err" ]; then
        echo "### $leg — unavailable"
        echo ""
        echo '```'
        head -5 "$WORK/$l-$leg.err"
        echo '```'
        echo ""
      fi
    done
  done
} > "$REPORT"

LATEST="$OUTDIR/$NAME-latest"
ln -sfn "$(basename "$WORK")" "$LATEST"

say "report: $REPORT"
echo "LATTICE_CODEAUDIT report=$REPORT critical=$TOTAL_CRIT high=$TOTAL_HIGH medium=$TOTAL_MED low=$TOTAL_LOW passes=${OK_LANGS[*]:-none} blind_spots=${FAILED_LANGS[*]:-none} engine=${LATTICE_BIN:-PATH}"

if [ "${#OK_LANGS[@]}" -eq 0 ]; then
  exit 2
elif [ "$TOTAL_CRIT" -gt 0 ] || [ "$TOTAL_HIGH" -gt 0 ]; then
  exit 1
fi
exit 0
