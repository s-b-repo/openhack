# Cross-Language Taint & Arbitrary-Call Test Design

How to carry the trust/taint + arbitrary-call bug classes — validated on real Solidity ground truth
(Damn-Vulnerable-DeFi: `puppet`/`puppet-v2` oracle, `unstoppable` donation, `truster` arbitrary-call) —
to **Python, C/C++, JS/TS, Shell**, and (parser-gated) **Go/Rust/Java**, with real-ground-truth test
suites built to the same genuine-toggle discipline.

Status: **Python is built and validated** (`src/lattice/ingest/python_taint.py`,
`tests/test_python_taint.py`, 12 tests + Bandit-examples corpus check). The other languages are designed
+ adversarially verified here, ready to build in the recommended order.

---

## 1. The architecture: one operator, N ingests

The cross-language-reusable piece is the **operator**, not the Solidity ingest and **not**
`lattice.security.audit`:

| Component | Role | Language coupling |
|---|---|---|
| `lattice.taint.trust_obstructions(deps, sources, sinks, sanitizers)` | the 5th obstruction operator — monotone taint fixpoint over a `{value: {inputs}}` dependency dict + 3 name-sets | **none** — pure dict + sets |
| `lattice.security.audit(net, source_root)` | reachability + JS/TS-shaped argument taint over a Hypernetwork | JS/TS (`_TAINT_SOURCES={req,request,ctx,event}`, `_ASSIGN=/const\|let\|var/`, regex sinks) |
| per-language ingest (`solidity_taint.py`, `python_taint.py`, …) | build the dependency dict + classify source/sink/sanitizer from that language's AST | all the language work lives here |

So **cross-language trust/arbitrary-call is an INGEST gap, not an operator gap.** Every new language
calls `trust_obstructions` verbatim; only the ingest is new. `security.audit` is the right engine **only
for JS/TS** (where its shape already fits); for every other language route to `trust_obstructions`.

## 2. The load-bearing constraint (why some classes carry and some don't)

`trust_obstructions` is **flow-insensitive, name-keyed, monotone**. A genuine SILENT toggle is only
honorable when the safe fix **changes which NAME appears in the value's footprint**:

- **carries** (name-level toggle): `getReserves`→`consult`, param-target→fixed-allowlist,
  `Statement`→`PreparedStatement`, literal-format→tainted-format, `os.system(x)`→`os.system(shlex.quote(x))`
  (the sanitizer name enters / the source name leaves the footprint).
- **does NOT carry** (in-place structural guard): a bounds check `assert len<=cap`, an allowlist
  transform that keeps the same variable, a deserialization class-filter in another method. The source
  name **stays** in the footprint, so the flow-insensitive operator fires on the safe version too. The
  adversarial verification confirmed both `good()` and `bad()` fire on the C command-injection example.

**Design rule:** lead each language with a class whose safe toggle is **name-level**. Classes whose only
fix is a structural guard must be (a) given a position-aware sink extraction (the
`solidity_arbitrary_call._callee_base` trick), or (b) honestly labeled **out-of-model**, never shipped as
a fake toggle.

## 3. The genuine-toggle test discipline (ported from Solidity)

Every class ships a **byte-identical pair** differing ONLY in the source→sink/sanitizer path:

```
test_<class>_FIRES    — the real vulnerable idiom emits the finding
test_<class>_SILENT   — the sanitized/safe version emits nothing
test_toggle_is_genuine — assert FIRES and not SILENT (they differ only on the path)
```

plus a **real named corpus** check (the DVD-equivalent), and **FIRE=lead / SILENCE≠proof** labeling.

---

## 4. Python — BUILT & VALIDATED

`parser`: stdlib `ast` (no deps). `operator`: `trust_obstructions` verbatim. `module`:
`src/lattice/ingest/python_taint.py` (`python_taint_audit`).

| bug class | CWE | source | sink | sanitizer | toggle kind | status |
|---|---|---|---|---|---|---|
| **OS command injection** | 78 | `request.*`, `sys.argv`, `os.environ`, `input()` | `os.system`/`os.popen`/`subprocess.*(shell=True)` | `shlex.quote` | name-level ✅ | **BUILT** |
| SQL injection | 89 | same | `cursor.execute(f"…")` (arg0) | parametrized `execute(sql, params)` | name-level (arg0-vs-arg1) | designed |
| arbitrary exec / deser | 94/502 | same | `eval`/`exec`/`pickle.loads`/`yaml.load`/`getattr`-dispatch | `ast.literal_eval`/`yaml.safe_load`/allowlist | name-level (dotted sink) | designed |
| SSRF | 918 | same | `requests.get(url=…)`/`urlopen` | host allowlist | name-level | designed |
| path traversal | 22 | same | `open`/`send_file`(user path) | `os.path.basename`/allowlist | name-level | designed |

**Three defects the adversarial verifier found, fixed in the built module:**
1. **Inline-source silent-FN** — `os.system(request.args['h'])` with no binding produced nothing (source
   classifier only tagged assigned values). Fix: seed the source-marker NAMES as tainted — the bare
   `request.*` chain in a sink position is tainted without a deps entry. (The exact inline-read FN
   `solidity_taint._return_taint_of` patched.)
2. **Bare-name callee collision** — borrowed `_names_in` collapsed `pickle.loads`/`json.loads` to `loads`.
   Fix: key sinks/sanitizers on the **dotted** callee (`_dotted`).
3. **Sanitizer must win** — the sanitized value's footprint still contains the source name. Fix:
   sanitizer-aware footprint (`_value_names` strips names inside a `shlex.quote(...)` span) **and** bound
   sanitizers passed to the operator.

A fourth slip the **real Bandit corpus** exposed: fixtures all used functions; real scripts wire
source→sink at **module level** (every Bandit example is module-level). Fixed: the module body is
analyzed as an implicit scope (`_analyze_scope(tree, "<module>")`).

**Corpus check (the DVD-equivalent):** the real Bandit `examples/` command-injection files
(`os_system.py`, `os-popen.py`, `subprocess_shell.py`) → **0 findings**, which is *correct*: they are
constant-arg sink-presence tests (`os.system('/bin/echo hi')`), not taint flows. Bandit (a sink linter)
flags them B605/B602; the taint analyzer correctly distinguishes "sink present" from "tainted flow" — zero
false positives on real constant-sink files. The same sink vocabulary **with** a source→sink flow fires.
This is the honest sink-linter-vs-taint-analyzer distinction. (Recommended positive corpus to add: a
PyT/SARD-Python flow set or a cited CVE reproduction; "OWASP BenchmarkPython" is not a reliable artifact —
verify-existence-first.)

## 5. C/C++ — designed (lead with FORMAT-STRING, not command-injection)

`parser`: **pycparser** (pure-Python, present; NOT `cpp.py`'s libclang which is absent). `operator`:
`trust_obstructions` verbatim. New module: `c_taint.py`.

| bug class | CWE | toggle kind | verdict |
|---|---|---|---|
| **format-string** (untrusted as the format arg of `printf`) | 134 | structural: literal-fmt empties the sink set vs tainted-name-in-fmt-position | **SOUND — lead here** |
| `dlopen`/`dlsym(getenv(...))` arbitrary load | 829 | name-level (target derives from `getenv`) | sound |
| command injection (`system`/`popen` of a built string) | 78 | **in-place allowlist guard keeps the name** → fires on safe | **out-of-model unless position-aware** |
| buffer write by untrusted length (`memcpy`) | 787 | `assert(len<=cap)` is a CFG dominator the operator can't see; `&len` out-param invisible to a Decl-init dep builder | out-of-model |

**Why CWE-134 leads:** its safe toggle is the same literal-vs-tainted-name shape as Solidity
arbitrary-call (`literal` vs `param`), so the sanitizer changes the sink set — the operator separates it.
**Real corpus:** Juliet/SARD CWE-134 ships paired `good()`/`bad()` standalone-parseable functions (the
byte-identical toggle, harvested not hand-authored). Caveat: real C needs `cpp -E` preprocessing;
pycparser chokes on system headers — use the self-contained Juliet cases.

## 6. JS/TS — BUILT & VALIDATED (arbitrary-call detector)

`parser`: **@babel/parser** via the packaged `_bridges/jsast/parse.js` node→JSON bridge (handles JS+TS+JSX, the analog
of solc's compact-JSON AST). `operator`: `trust_obstructions` **verbatim**. `module`:
`src/lattice/ingest/js_arbitrary_call.py` (`js_arbitrary_call_audit`), 24 tests.

The port of `solidity_arbitrary_call.py` — the call TARGET derives from untrusted input:
- **dynamic dispatch** `obj[KEY](...)` with an attacker key (high) — the `truster` analog (address-target
  param → dispatch key; fixed state-var target → constant key / allow-listed key SILENT);
- **code execution** `eval` / `new Function` / `require` / `import()` / `vm.runIn*` / `new vm.Script` and
  the **child_process** family `exec`/`spawn`/`execFile`/`fork` (critical).

**SOURCE = usage, not a magic name** (the load-bearing fix): an identifier member-accessed via a request
property (`.body`/`.query`/`.params`/`.headers`/`.cookies`) is the request — so `req`, `r`, `ctx`,
`httpReq` all work, and a local merely *named* `request` does not taint.

**Validated on real ground truth:** OWASP **NodeGoat** `contributions.js` — fires `critical` on
`eval(req.body.preTax)` (`handleContributionsUpdate`), silent on its `parseInt` fix; 0 FP on the Babel
parser library.

**Adversarial verification (workflow w2iuqm74n) — 4 attack lenses executed against the live detector and
found real defects, all fixed:**
1. **child_process family absent** — the canonical Node RCE was invisible; added `exec`/`spawn`/… gated on
   a `require('child_process')` import binding (so `regex.exec(userInput)` does NOT false-fire).
2. **name-keyed source** (HIGH) — `(r,res)=>eval(r.body.code)` was silent (`r≠req`) and `let request=0;
   cb[request]()` falsely fired. Replaced literal `_SOURCE_MARKS` with **usage-based** sourcing — closing
   the abbreviation silent-FN *and* the shadowing FP in one change.
3. **fake sanitizers** — `escape`/`lookup`/`encodeURIComponent` silenced real RCE (`eval(escape(x))`);
   trimmed `_SANITIZERS` to allow-list/validation names only.
4. **callback-boundary taint** — `req.body.ops.forEach(op=>handlers[op]())` was silent; added one-hop
   iterator seeding (tainted receiver → callback param). Plus `new vm.Script(X)` construction.

The operator-carry verdict was confirmed: `trust_obstructions(deps, sources, sinks, sanitizers)` is called
**byte-identically** to the Solidity leg — no JS-specific operator. The same lesson held a third time:
synthetic fixtures used named `function` decls + the exact spelling `req`; real code uses arrow handlers
with abbreviated params — every defect was ingest-side, the operator untouched.

Documented limits (FIRE=lead/SILENCE≠proof): const-object-map allow-list (`require(ALLOWED[k])`) over-flags;
laundered iterator receiver (`const ops=req.body.ops; ops.forEach(...)`) one hop only; `child_process` is
command-injection folded into this detector for recall, not a separate class. **Access-control is
DELIBERATELY not suppressed** (unlike the Solidity `onlyOwner` port): JS auth gates are ad-hoc and an
admin-only `eval` is still a real finding, so suppressing on a heuristic would be a silent-FN.

## 7. Shell — designed (lead with arbitrary-command-exec)

`parser`: extend `shell.py`'s regex/brace-scope walk → `shell_taint.py`. `operator`:
`trust_obstructions` verbatim. `security.audit` is shell-blind (`\beval\s*\(` needs a paren;
`_TAINT_SOURCES` has no `$1`/`$@`).

| bug class | toggle kind | verdict |
|---|---|---|
| **arbitrary command exec** (`$CMD`/`eval $action`, callee from input) | source-token == sink-token, fires with empty deps — the truster twin | **SOUND — lead here** |
| eval-injection (`eval` of `$VAR`) | name-level | sound |
| `curl \| sh` of a fetched URL | **relational/pipeline sink** — operator is SILENT unless the ingest mints a synthetic sink token **and wires a dep edge** to the tainted var | needs explicit synthetic-sink-with-edge contract |
| unquoted `$VAR` word-split | quoting-as-sanitizer; needs quote-state tracking `re` does poorly | separate `trust_obstructions` invocation |

**The single highest-leverage contract:** *every synthetic sink token must appear as a key in
`dependencies` linked to the tainted source tokens* — with a regression that asserts the
bare-token-no-edge case stays silent. **Real risks:** env-var source classification over-taints
`$HOME`/`$PATH` (FP flood); the `[[ $USER == admin ]]` access-control suppressor is the least-proven seam.
**Real corpus:** shellshock-class eval, Codecov-class `curl|bash`, ShellCheck SC2086.

## 8. Go / Rust / Java — parser-gated survey (lead with Java SQLi)

`parser`: tree-sitter (`tree-sitter-go/java/rust`) — **none installed**; no Go/Rust/Java backend in
`lattice/ingest`. Java alternative: JavaParser/Eclipse-JDT subprocess → JSON AST (mirrors how
`solidity_taint.py` consumes solc compact-JSON).

Only **Java SQLi** has a toggle genuine *for this engine* and a machine-readable oracle:
`Statement.executeQuery(concat)` FIRES vs `PreparedStatement(?)+setString` SILENT — a name-level swap,
validated against **OWASP Benchmark v1.2 `expectedresults-1.2.csv` + Juliet/SARD CWE89** (labeled at
scale, the true DVD-equivalent). The other four over-claim: Go/Rust command-injection argv-form, Rust
`from_raw_parts` bounds-assert, Java deser class-filter, Go SSRF / Rust dispatch all need **position-aware
sink extraction** the Solidity taint leg never does (only its arbitrary-call leg does) — build with
explicit arg-position sinks + honest out-of-model labels, after the Java SQLi proof.

---

## 9. Recommended build order

1. ~~**JS/TS arbitrary-call**~~ — **DONE** (`js_arbitrary_call.py`, 24 tests, NodeGoat-validated,
   adversarially hardened). Proved the operator carries to a second non-Solidity language.
2. **Python SQLi + arbitrary-exec** — additive source/sink/sanitizer vocabulary on the proven
   `python_taint.py` skeleton (command-injection already done).
3. **C format-string (CWE-134)** on pycparser + Juliet/SARD corpus.
4. **Shell arbitrary-command-exec** with the synthetic-sink-edge contract.
5. **Java SQLi** (JavaParser→JSON) against the OWASP Benchmark CSV oracle — the first labeled-at-scale
   precision/recall proof of the operator on a non-Solidity corpus.

Each step: new ingest only, `trust_obstructions` unchanged, genuine-toggle tests + a real named corpus,
FIRE=lead / SILENCE≠proof. The invariant from the Solidity work holds — **the operator is sound; every
bug lives in the ingest.**

---

## 10. Accuracy gate (added in the precision + recall sweep)

The FIRES / SILENT / toggle discipline above answers *"does this detector work?"* per class.  The
**accuracy gate** answers the sibling question *"is the whole detector fleet, together, still as good
as it was yesterday?"* — regression-detection for the whole matrix in one go.

### The one file that says what "as good as yesterday" means

`tests/accuracy_baseline.json` is the immovable floor. It carries:

- per-detector unit counts (`fires_pass`, `silent_clean`, `toggles_genuine`, `other`),
- per-corpus true-positive counts (SmartBugs, SolidiFI, OpenZeppelin FP ceiling),
- the aggregate `macro_precision` / `macro_recall` / `f1` snapshot.

It is refreshed by *exactly one* command, which produces a review-visible diff — no baseline can move
silently:

```bash
FOOTINGS_SMARTBUGS=/path/to/smartbugs-curated/dataset \
  python tools/measure_accuracy.py --as-baseline
```

Every other invocation writes to `scratchpad/measure_accuracy.<sha>.json` and does **not** touch the
committed baseline.

### The gate: `pytest -m accuracy`

Guarded by `FOOTINGS_ACCURACY_GATE=1` (mirrors the existing `FOOTINGS_CORPUS_GATE=1` idiom in
`tests/test_corpus_regression.py:27-31`).  Five assertions in `tests/test_accuracy_baseline.py`:

1. **baseline exists** — a committed JSON must be present (fails if the file is missing).
2. **no detector lost a unit test** — the sum of `fires_pass + silent_clean + toggles_genuine + other`
   per detector cannot drop from baseline.  Growing is fine (the sweep adds tests); shrinking is a
   silent test deletion.
3. **no corpus recall regression** — every SmartBugs / SolidiFI category's TP count is ≥ baseline.
4. **no OpenZeppelin FP regression** — `precise_fp` and `highsev_fp` are ≤ baseline (the audited-code
   silence guarantee).
5. **aggregate precision/recall don't regress** — `macro_precision` and `macro_recall` ≥ baseline − 1%
   (a small EPS for float noise, deliberately tighter than the 5% floor the corpus gate uses).

CI runs it in addition to `test_corpus_regression.py`.  Local `pytest` skips it (~8 min run time on
SmartBugs), same as the corpus gate.

### The shared vocab registry

Concurrent with the accuracy gate, `src/lattice/ingest/vocab.py` was introduced as the single source of
truth for cross-language source/sink/sanitizer names — the file that finally makes a "new shell sink"
one-line for every language at once.  It is data-only (stdlib-only, no imports from any detector; the
`test_no_import_from_detectors` test enforces one-way flow) and its public API is three helpers:

```python
from lattice.ingest import vocab
vocab.sources("http_request", "cli", "env", extra={"my_specific_source"})   # -> set[str]
vocab.sinks("shell", extra={"os.system"})                                    # -> set[str]
vocab.sanitizers("shell", extra={"Shellwords"})                              # -> set[str]
```

Detectors haven't been migrated yet — the migration guard tests
(`test_vocab.py::test_<detector>_..._subset_of_vocab_...`) prove every existing local set is already
a subset of the shared vocab, so migration is a mechanical `_ALWAYS_SHELL = vocab.sinks("shell", extra=...)`
in a follow-up PR per detector.  Adding a new term today only needs to land in one place from now on.
