# Dynamic Context Runtime (DCR) — Vendored Component

> Upstream: [github.com/s-b-repo/subnext](https://github.com/s-b-repo/subnext)
> Paper: [Dynamic Context Runtime: Bounded Attention over Unbounded History](https://cybersec.org.za/research-dcr-bounded-attention.html) (DCR-TR-2026-01)

OpenHack's next-generation context management system. Instead of sending the
full conversation history to the model (or compacting/truncating it), DCR
maintains a **dynamic memory graph** and assembles a **budgeted working set**
for each turn — typically **145–259 tokens** from tens of thousands of tokens
of history, with **7/7 correctness** on the benchmark suite.

```
session history → State Indexer → Memory Graph → Relevance Planner → tiny working set → model
```

The model never receives the entire history. Unlike RAG, the runtime does not
retrieve documents — it retrieves *whichever representation is cheapest and
sufficient* for the current query.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [CLI Reference](#cli-reference)
- [Integration with OpenHack](#integration-with-openhack)
- [Verification & Testing](#verification--testing)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Architecture](#architecture)
- [Upstream](#upstream)

---

## Quick Start

```bash
# Build (one command, idempotent)
vendor/subnext/bootstrap.sh

# Verify the binary works
vendor/subnext/bin/dcr demo

# Enable for sessions
export DCR_ENABLED=1
# Or add to openhack config: "dcr": { "enabled": true }
```

That's it. The framework bridge (`packages/core/src/session/dcr.ts`) resolves
the vendored binary automatically.

---

## Installation

### Prerequisites

- **Rust toolchain** (rustc + cargo). Install via [rustup.rs](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```
- Minimum Rust edition: **2024** (rustc ≥ 1.85)
- No other dependencies. The runtime is zero-dependency Rust — hashing, text
  scanning, JSON persistence, and argument parsing are all owned.

### Build

```bash
# From anywhere in the repo:
vendor/subnext/bootstrap.sh

# Force rebuild (e.g. after pulling new source):
FORCE=1 vendor/subnext/bootstrap.sh
```

The script:
1. Checks if `bin/dcr` already exists and is executable (skips if so)
2. Runs `cargo build --release` in the vendored source
3. Copies the binary to `vendor/subnext/bin/dcr`

**Output:** a single ~2 MB statically-optimised binary at `vendor/subnext/bin/dcr`.

### Via the project installer

```bash
# Standard install (bootstraps DCR + Lattice automatically):
bash install.sh

# Full install (everything):
bash install.sh --full

# Preview what will happen:
bash install.sh --dry-run
```

### Binary resolution order

The TypeScript bridge resolves the `dcr` binary in this order:

1. **`$DCR_BIN`** — explicit absolute path override
2. **`<repo>/vendor/subnext/bin/dcr`** — the vendored binary (preferred)
3. **`dcr` on `PATH`** — legacy external install

The bridge walks up to 8 parent directories looking for `vendor/subnext/bin/dcr`,
so it works from any working directory inside the repo.

---

## Configuration

### Enable DCR

**Environment variable** (simplest):
```bash
export DCR_ENABLED=1
```

**OpenHack config** (persistent):
Add to your openhack config (`.openhack/openhack.jsonc` or `~/.config/openhack/openhack.json`):
```jsonc
{
  "dcr": {
    "enabled": true
  }
}
```

### Configuration options

| Option | Config key | Env var | Default | Description |
|---|---|---|---|---|
| Enable | `dcr.enabled` | `DCR_ENABLED=1` | `false` | Turn DCR on for sessions |
| Binary | `dcr.bin` | `DCR_BIN` | `"dcr"` | Path to the dcr binary |
| Budget | `dcr.budget` | — | `1200` | B_attention: max tokens in the working set |
| Recent tail | `dcr.recentTokens` | — | `4000` | Verbatim recent messages budget (tokens) |

### Storage

Per-session stores live under:
```
~/.local/share/openhack/dcr/<sessionID>/
├── memory.dcr.json     # the memory graph (nodes, edges, index)
└── turns/              # immutable per-message spans
    ├── m1.txt
    ├── m2.txt
    └── ...
```

Each message is written as an immutable file (`m<seq>.txt`). The graph is
persisted as JSON (plain mode) or as a tamper-evident `.context` container.

---

## How It Works

### The problem

As sessions grow long (hundreds of turns), the full transcript exceeds what any
model can usefully attend to. Conventional approaches fail in specific ways:

| Approach | Failure mode |
|---|---|
| **Full history** | Provider overflow; model attention degrades on old facts |
| **Sliding window** | Facts outside the window are permanently lost |
| **Compaction/summarization** | Corrected facts may be summarised with their stale values |
| **RAG** | Retrieves by similarity, not by dependency; misses corrections |

### DCR's approach

DCR treats session history as an **append-only audit log** rather than working
memory. The model's attention window is assembled dynamically each turn:

```
                 ┌───────────────┐
incoming context → State Indexer │
                 └───────┬───────┘
                         ↓
              ┌─────────────────────┐
              │ Dynamic Memory Graph│
              └─────────┬───────────┘
                        ↓
       ┌────────────────┼────────────────┐
       ↓                ↓                ↓
   exact spans      semantic states   computations
       ↓                ↓                ↓
       └────────────────┼────────────────┘
                        ↓
                relevance planner
                        ↓
                 tiny active context
                        ↓
                      model
```

### Core mechanisms

**1. Representation Ladder** — the same fact exists at multiple levels of detail:

| Level | What | Cost | When used |
|---|---|---|---|
| **L0** | Raw source spans (verbatim bytes) | Highest | Exact quotes, escalations |
| **L1** | Summaries | Medium | Long spans, overviews |
| **L2** | Structured state (`key = value`) | Lowest | Value lookups, most queries |
| **L3** | Executable derivations (computed values) | Variable | Calculations, joins |

The planner picks the **cheapest sufficient** level for each fact.

**2. Corrections win** — when a fact is corrected later in the session:
- The original claim is marked `superseded` (never deleted)
- The correction is linked via a `supersedes` edge
- Superseded values are **excluded from planning** — they cannot enter the working set
- If a superseded value appears in rendered evidence, it is annotated: `NOTE=contains a value corrected later; current value in <node>`
- Stale derived values (L3 computations whose inputs changed) are detected and marked

**3. Attention budget** — context assembly is a constrained optimisation problem:
- Maximise `U(S)` (utility of the selected set) subject to `Σcost(x) ≤ B_attention`
- Solved with a knapsack algorithm, not a similarity threshold
- The planner scores candidates by query relevance, kind priority (goals and constraints first), recency, and dependency edges

**4. Escalation protocol** — when the compact representation is too thin:
- The model replies with `#ESCALATE <node_id>` to demand raw bytes
- The next planning pass pulls the L0 span into the window, charged against B_attention
- Runtime-native node ids ride the graph's own routing

**5. Provenance** — every fact traces to its source:
- Every claim links to evidence nodes, which link to raw spans
- `explain <node_id>` walks the full audit path
- An answer without a complete audit path scores as a failure in the benchmark

**6. Tamper-evident containers** (optional) — the `.context` format:
- Content-addressed objects under a Merkle root
- Checkpoints chained so editing history invalidates everything after it
- Generation high-water mark prevents rollback
- Tamper-*evident*, not tamper-proof (no signer bundled)

### What the model receives

Instead of the full transcript, the model gets:

```xml
<session-context engine="dcr" tokens="163">
Runtime-assembled working set distilled from earlier in this session.
Every fact below traces to source spans; values marked NOTE were corrected later.

# ACTIVE CONTEXT  (k=163/1200 tokens, 6 of 6 candidates, query type: value_lookup)

## GOALS
[goal_bb087c8dc0f8 L2] restore checkout by 09:00 UTC · conf=0.90 · spans=s_438a2825c8ba

## FACTS (cached state)
[clai_13b53bad17af L2] server.ip = 10.0.9.7 · conf=0.90 · spans=s_86925d2a6e90

## EVIDENCE (raw spans)
[evid_ec21ba00d105 L2] Correction: actually the server ip is 10.0.9.7 ...

NOTE — corrected values:
- "10.0.4.12" was corrected later; current value in: clai_13b53bad17af
</session-context>
```

Plus a **verbatim recent tail** (last ~4000 tokens) so the model sees the
immediate conversational context unmodified.

### Degradation

Any DCR failure (binary not found, runtime error, timeout >5s) silently
degrades the turn to the **legacy full-history path**. Compaction still guards
provider overflow. The session continues normally — the user never sees a
failure, only slightly higher token usage for that turn.

---

## CLI Reference

```
dcr [--store PATH] [--budget N] <command> [options]
```

### Global options

| Option | Default | Description |
|---|---|---|
| `--store PATH` | `.dcr.json` | Memory store path. No extension → tamper-evident container; `.json` → plain JSON |
| `--replica PATH` | — | Extra copy for repair (repeatable) |
| `--budget N` | `1200` | B_attention in tokens |

### Commands

#### Data management

| Command | Description |
|---|---|
| `ingest <path>...` | Index files or directories into the memory runtime |
| `checkpoint` | Seal current state as a new generation (container mode) |
| `verify` | Check a `.context` container: objects, chain, root |
| `scrub [--repair]` | Detect bit rot; repair from a verified replica |
| `quarantine` | List objects that failed verification |
| `stats` | Telemetry report |

#### Querying

| Command | Description |
|---|---|
| `plan <query> [--explain]` | Show the active context that would be assembled (no model call) |
| `ask <query> [--show-context]` | Plan a working set and answer (deterministic line matcher) |
| `explain <node_id>` | Audit path from a node down to raw spans |

#### Demo & benchmarks

| Command | Description |
|---|---|
| `demo` | Worked example through all four ladder levels |
| `bench` | DCR vs full context vs sliding window |
| `bench --scaling` | Does k stay flat as history grows? |
| `bench --ablate` | Which mechanism carries which probe? |
| `bench --mutate` | Is a correction served once the original has dependents? |
| `bench --diverse` | Scaling on a lexically varied corpus, to millions of tokens |
| `bench --baselines` | DCR vs RAG, summarize-all, and recursive context |
| `bench --tamper` | Can the container actually detect tampering? |
| `bench --sweep` | Correctness and cost against B_attention |
| `bench --cache` | How much of each turn is a cacheable prefix? |
| `bench --recall` | Approximate top-k overlap against exact scan |
| `bench --fusion` | Reciprocal rank fusion vs linear blend |
| `bench --poison` | Positive control: can the stale-fact metric fire? |
| `bench --coverage` | Read coverage as history grows |
| `bench --decay` | Does a recency prefilter cost recall? |
| `bench --consolidate` | Correctness when the store is written mid-turn |
| `bench --multihop` | Does graph expansion help on a join? |
| `bench --rebuild` | Cost of destroying and rebuilding the workspace |
| `bench --subject` | Does it identify the subject, or the doc that mentions it? |

### Examples

```bash
# Ingest a directory of turn files
dcr --store session.dcr.json ingest ./turns/

# See what context would be assembled for a query
dcr --store session.dcr.json plan "what is the server IP?"

# Trace how a specific fact was derived
dcr --store session.dcr.json explain clai_13b53bad17af

# Use a tamper-evident container instead of plain JSON
dcr --store ./session-container ingest ./turns/
dcr --store ./session-container checkpoint
dcr --store ./session-container verify

# Run the full benchmark suite
dcr bench
dcr bench --baselines
dcr bench --scaling
dcr bench --ablate
dcr bench --diverse
```

---

## Integration with OpenHack

### TypeScript bridge

The bridge at `packages/core/src/session/dcr.ts` handles all DCR integration:

```
SessionRunner → dcr.ts bridge → vendor/subnext/bin/dcr (subprocess)
```

**Key functions:**

| Function | Purpose |
|---|---|
| `resolveEngineBin(bin)` | Walks up directories to find `vendor/subnext/bin/dcr` |
| `settings(documents)` | Merges DCR config from all config sources |
| `assemble(input)` | Full pipeline: ingest new entries → plan → service escalations → render |
| `assembleEffect(input)` | Effect wrapper that never fails (degrades to `undefined`) |
| `block(assembled)` | Renders the `<session-context>` XML block for the provider |
| `escalations(text)` | Extracts `#ESCALATE <node_id>` tokens from assistant replies |
| `pendingEscalations(entries)` | Finds escalations still owed in the current exchange |
| `recentTail(entries, tokens)` | Selects the verbatim recent tail within budget |
| `disposeAll()` | Clean up all tracked engines |
| `disposeSession(sessionID)` | Clean up a specific session's engine |

### Turn lifecycle

1. **Write** — each new session message is serialised to `m<seq>.txt` in the session's turns directory. Role markers (`[User]:`, `[Tool result]:`) are stripped — the runtime ingests documents, not chat transcripts.

2. **Ingest** — the bridge calls `dcr ingest <turns_dir>`. New files are indexed into the memory graph. Contradictions are detected and logged.

3. **Plan** — the bridge calls `dcr plan <query>` with the latest user message. The planner returns a budgeted working set.

4. **Service escalations** — any `#ESCALATE m<seq>` tokens from the assistant's previous reply are resolved to raw span bytes and prepended to the working set.

5. **Render** — the working set is wrapped in `<session-context>` XML and injected into the provider turn alongside the verbatim recent tail.

6. **Degrade** — any failure at any step returns `undefined`, and the session falls back to the full history path. The `Engine` class enforces a 5-second timeout.

### Engine pool

The bridge maintains a pool of up to 32 `Engine` instances (one per session).
Each engine tracks:
- The `dcr` binary path
- The session's store path (`memory.dcr.json`)
- The session's turns directory
- The budget
- An ingest watermark (so re-ingesting is incremental)

When the pool exceeds 32 engines, the oldest is disposed.

---

## Verification & Testing

### Quick smoke test

```bash
# After bootstrap:
vendor/subnext/bin/dcr demo
```

This runs through all core mechanisms: value lookup after correction, exact
quote routing, escalation protocol, justification via dependency edges,
L3 recompute with memoisation, invalidation on corrected inputs, audit path
tracing, and workspace rebuild.

### Full benchmark suite

```bash
# Core comparison (30 seconds)
vendor/subnext/bin/dcr bench

# Expected output: 7/7 correct, ~145 tokens mean, 189x compression
# Full context: 5/7, sliding window: 2/7

# Against all baselines (~2 minutes)
vendor/subnext/bin/dcr bench --baselines

# Scaling to millions of tokens (~5 minutes)
vendor/subnext/bin/dcr bench --diverse

# Ablation study
vendor/subnext/bin/dcr bench --ablate

# Tamper detection
vendor/subnext/bin/dcr bench --tamper
```

### Manual integration test

```bash
mkdir -p /tmp/dcr-test/turns

# Create test turns simulating an incident
cat > /tmp/dcr-test/turns/m1.txt << 'EOF'
The server IP is 10.0.4.12 and the port is 8080.
EOF

cat > /tmp/dcr-test/turns/m2.txt << 'EOF'
Correction: the server IP is actually 10.0.9.7, we misread the dashboard.
EOF

# Ingest
vendor/subnext/bin/dcr --store /tmp/dcr-test/store.dcr.json ingest /tmp/dcr-test/turns/
# Should show: 1 contradiction detected

# Query — should return the corrected value
vendor/subnext/bin/dcr --store /tmp/dcr-test/store.dcr.json plan "what is the server IP?"
# Should show: server.ip = 10.0.9.7 (not 10.0.4.12)

# Audit trail
vendor/subnext/bin/dcr --store /tmp/dcr-test/store.dcr.json stats

# Clean up
rm -rf /tmp/dcr-test
```

---

## Troubleshooting

### "cargo not found"

Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Then re-run `vendor/subnext/bootstrap.sh`.

### DCR is not activating in sessions

1. Check it's enabled:
   ```bash
   echo $DCR_ENABLED  # should be "1"
   ```
2. Check the binary exists:
   ```bash
   vendor/subnext/bin/dcr --help
   ```
3. Check from the repo root (the bridge walks up looking for `vendor/subnext/bin/dcr`):
   ```bash
   ls vendor/subnext/bin/dcr  # must exist and be executable
   ```

### Sessions seem slower

DCR adds a subprocess call per turn (typically <10ms at 300 turns, <50ms at
80,000 turns). If ingest is slow on first use, it's building the initial
graph — subsequent turns are incremental. The 5-second timeout ensures DCR
never blocks a session for long; if it hits the timeout, that turn degrades
silently.

### Stale data after update

If you update the DCR source and rebuild, existing session stores are
compatible — the graph format is stable. If you need a clean slate:
```bash
rm -rf ~/.local/share/openhack/dcr/<sessionID>/
```

### Container verification fails

```bash
vendor/subnext/bin/dcr --store /path/to/container verify
```
If objects fail verification, use `scrub --repair` with a replica:
```bash
vendor/subnext/bin/dcr --store /path/to/container --replica /path/to/backup scrub --repair
```

---

## Performance

### Benchmark results (measured on this binary)

**Core comparison** (300 turns, 27,362 tokens of history):

| System | Correct | Mean tokens/query | Compression |
|---|---|---|---|
| Full history | 5/7 | 27,362 | 1× |
| Sliding window (8k) | 2/7 | 7,968 | 3.4× |
| RAG (top-k) | 5/7 | 1,168 | 23× |
| Summarize-all | 1/7 | 1,197 | 23× |
| Recursive | 4/7 | 31,074 | 0.9× |
| **DCR** | **7/7** | **145** | **189×** |

**Scaling** (varied corpus):

| Turns | History tokens | Nodes | Mean k | Correct | Ingest | Query |
|---|---|---|---|---|---|---|
| 3,000 | 150k | 2,032 | 219 | 7/7 | 1s | 6ms |
| 10,000 | 513k | 6,762 | 237 | 7/7 | 5s | 22ms |
| 30,000 | 1.56M | 18,473 | 221 | 7/7 | 34s | 24ms |
| 80,000 | 4.19M | 48,651 | 259 | 7/7 | 274s | 49ms |

History grew 28×; active context grew 1.18×.

**Budget sweep** (300 turns):

| B_attention | Correct | Mean k |
|---|---|---|
| 120 | 6/7 | 101 |
| 200 | 7/7 | 138 |
| 300+ | 7/7 | 145 |

Full correctness from budget ≥ 200. Default of 1200 provides comfortable headroom.

### Telemetry

After queries, `dcr stats` reports:
- `tokens_per_query_mean/max` — actual token spend
- `compression_ratio` — history ÷ mean working set
- `escalation_rate` — how often the model needed raw bytes
- `stale_fact_read_rate` — should be 0.0 (superseded facts excluded)
- `audit_path_completeness` — should be 1.0 (every answer traced to source)
- `budget_overflows` — should be 0 (planner respects B_attention)

---

## Architecture

### Source modules

The implementation is zero-dependency Rust in `src/`:

| Module | Purpose |
|---|---|
| `main.rs` | CLI entry point, command dispatch |
| `runtime.rs` | Core runtime: ingest, plan, ask lifecycle |
| `graph.rs` | Typed memory graph (nodes, edges, kinds, supersession) |
| `nodes.rs` | Node types: claim, evidence, decision, goal, constraint, calculation |
| `indexer.rs` | State indexer: extract structured facts from raw text |
| `planner.rs` | Relevance planner: knapsack over scored candidates |
| `policy.rs` | Planning policy: weights, caps, control flags |
| `ladder.rs` | Representation ladder: L0–L3 level management |
| `budget.rs` | Attention budget: constrained optimisation |
| `index.rs` | Vector index with LSH approximate nearest neighbours |
| `embed.rs` | 256-dimensional hashing embedder |
| `spans.rs` | Immutable L0 span storage |
| `execute.rs` | L3 derivation engine with memoisation |
| `speculation.rs` | Speculative prefetch: predict what the model will need |
| `context_store.rs` | Tamper-evident `.context` container |
| `merkle.rs` | Merkle tree for content addressing |
| `trust.rs` | Trust model: verification, chain integrity |
| `hash.rs` | Cryptographic hashing (owned, no dependency) |
| `json.rs` | JSON serialisation (owned, no dependency) |
| `text.rs` | Text processing utilities |
| `tokens.rs` | Token estimation |
| `ids.rs` | Node/span ID generation |
| `scrub.rs` | Bit-rot detection and repair |
| `summarize.rs` | L1 summary generation |
| `llm.rs` | Model interface (deterministic line matcher for benchmarks) |
| `telemetry.rs` | Metrics collection |
| `demo.rs` | Worked example |
| `bench.rs` | Benchmark suite |
| `baselines.rs` | RAG, summarize-all, recursive baselines |

### Data flow

```
          message text
              │
              ▼
    ┌─────────────────┐
    │  State Indexer   │  extract key=value, decisions, goals, evidence
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Memory Graph    │  nodes + typed edges + supersession tracking
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Vector Index    │  LSH-pruned approximate NN + lexical scoring
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Relevance       │  score candidates, expand along graph edges,
    │  Planner         │  pick cheapest sufficient ladder level,
    │                  │  solve knapsack within B_attention
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │  Working Set     │  goals → constraints → facts → evidence
    │  Renderer        │  annotated with provenance and correction notes
    └─────────────────┘
```

---

## Upstream

This directory vendors the reference implementation from
[github.com/s-b-repo/subnext](https://github.com/s-b-repo/subnext). The
upstream repository contains additional material not included in the vendored
copy:

- `docs/` — full specification wiki (concepts, architecture, design decisions)
- `paper/` — the technical report PDF and build tooling
- `IMPLEMENTATION.md` — module map, measurements, and honest limitations
- `RESULTS.md` — full benchmark numbers with caveats
- `CONTRIBUTING.md` — contribution guidelines
- `CREDITS.md` — who changed which claim
- `examples/` — custom embedder, integration examples
- `tests/` — property tests and regression suite

For the full specification and design rationale, see the upstream repo or the
[paper](https://cybersec.org.za/research-dcr-bounded-attention.html).

### Keeping the vendor in sync

```bash
# Pull latest from upstream:
cd vendor/subnext
git fetch origin
git merge origin/main  # or cherry-pick specific commits

# Rebuild:
FORCE=1 bash bootstrap.sh

# Verify:
./bin/dcr bench
```

---

## License

[MIT](LICENSE) for the code in `src/`.
