# Dynamic Context Runtime (DCR)

> Specification wiki **plus a working implementation** of it.
> The design lives in [`docs/`](docs/); the runtime lives in [`src/`](src/) —
> zero-dependency Rust, see [IMPLEMENTATION.md](IMPLEMENTATION.md).

```bash
cargo run --release -- demo    # worked example: correction, exact quote, justification, recompute
cargo run --release -- bench   # DCR vs full context vs sliding window
cargo run --release -- bench --baselines   # …and vs RAG, summarize-all, recursive
```

**Thesis:** RLMs (Recursive Language Models) don't solve context rot. They move the problem
out of the transformer's fixed attention window and into a program. That is the right primitive,
but the next step is a **dynamic context runtime**: unlimited external state plus a small,
planned working set.

> unlimited history ≠ unlimited attention

Concretely that means two cooperating systems: a small high-attention **Reasoner** and an
unbounded **Memory Runtime** that decides which representation to hand it. See
[the two-system split](docs/architecture/two-system-split.md).

## The shift

```text
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

The model never receives the entire context. Unlike RAG, the runtime does not retrieve
documents — it retrieves *whichever representation is cheapest and sufficient* for the
current computation.

## Core ideas

| Idea | One line |
|---|---|
| [Representation ladder](docs/concepts/representation-ladder.md) | Same context exists as L0 raw / L1 summaries / L2 vectors / L3 executable derivations. |
| [Stateful memory](docs/concepts/stateful-memory.md) | `M_t = (R_t, S_t, C_t, E_t)`; context evolves instead of being reread. |
| [Facts as cache](docs/concepts/fact-cache.md) | Replace 10k tokens of reasoning with ~20 structured state objects + provenance. |
| [Context as a graph](docs/concepts/context-graph.md) | Retrieval follows dependency edges, not similarity. |
| [Speculative context](docs/concepts/speculative-context.md) | Predict `P(m_i | q_t, S_t)` and prefetch before the model asks. |
| [Context as a state machine](docs/concepts/state-machine.md) | Transcript becomes an append-only audit log, not working memory. |
| [Attention budget](docs/concepts/attention-budget.md) | Context assembly as constrained optimization: max `U(S)` s.t. `Σcost(x) ≤ B_attention`. |
| [Cost model](docs/concepts/cost-model.md) | Aim at `O(k + r)` instead of `O(N²)` while `N` keeps growing. |
| [Context integrity](docs/architecture/context-integrity.md) | Memory a reasoner trusts has to prove it returned what it stored. |

## Architecture

- [Overview](docs/architecture/overview.md)
- [Two-system split: Reasoner + Memory Runtime](docs/architecture/two-system-split.md)
- [State Indexer](docs/architecture/state-indexer.md)
- [Memory Graph](docs/architecture/memory-graph.md)
- [Relevance Planner](docs/architecture/relevance-planner.md)
- [Runtime decision policy](docs/architecture/decision-policy.md)
- [Provenance & evidence](docs/architecture/provenance.md)
- [Context integrity: the `.context` container](docs/architecture/context-integrity.md)
- [Failure modes](docs/architecture/failure-modes.md)
- [Workspace rebuild](docs/architecture/workspace-rebuild.md)

## Also

- [Comparison: RLM vs RAG vs DCR](docs/comparison.md)
- [Alternatives considered](docs/alternatives.md)
- [Architecture audit, Aug 2026](docs/audit-2026-08.md)
- [Open questions](docs/open-questions.md)
- [Glossary](docs/glossary.md)
- [Roadmap](docs/roadmap.md)
- [FAQ](docs/faq.md)

## Implementation

`src/` is a zero-dependency Rust implementation of this specification: the
immutable L0 store, the representation ladder, the typed memory graph with
enforced provenance, the attention-budget knapsack, the relevance planner, the
escalation protocol, speculative prefetch, the tamper-evident `.context`
container, and the telemetry the evaluation design asks for. See
[IMPLEMENTATION.md](IMPLEMENTATION.md) for the module map, the measurements, and
the honest limitations.

Measured on a 300-turn synthetic incident transcript (27k tokens of history,
`B_attention` = 1200): **145 tokens per query — 189x less attention than the full
history.** On a lexically varied corpus the working set holds at **4.19 million
tokens of history and 48,651 state nodes, answering from 259 tokens per query,
7/7.** Against baselines that
also retrieve, DCR answers 7/7 probes where top-k RAG answers 5/7 at 8x the
tokens, and uniform summarisation answers 1/7.
On a second corpus built so similarity is misleading and refusing is sometimes
correct, **DCR scores 2/5 and loses to recursive map-reduce** — it serves a
derived figure whose inputs were corrected, and answers a question history never
addresses. Both are real, neither is fixed, and both are reported.
Full numbers, scaling table, and caveats: [RESULTS.md](RESULTS.md).

Memory is persisted either as a plain JSON file or as a **`.context`
container** — content-addressed objects under a Merkle root, checkpoints chained
so that editing history invalidates everything after it, and a generation
high-water mark that refuses a rollback. An edited JSON store reloads silently;
an edited container does not load. Without a signer this is tamper-*evident*,
not tamper-proof, and [says so](docs/architecture/context-integrity.md#9-what-this-does-not-defend-against).

## Where this fits

DCR is built for one shape of problem: **a conversation or process that keeps
producing facts, where earlier facts get corrected, and where the answer has to
be traceable.** If your workload is not that shape, the machinery costs more than
it returns and the honest recommendation is not to use it.

Which model to put behind it is a separate question, and one this repository
deliberately does not measure — the benchmark reasoner is a deterministic line
matcher so that results describe context assembly rather than model quality.
[Choosing a model](docs/choosing-a-model.md) gives selection criteria by category
(coding, security work, automation, extraction, embeddings, local) and says
up front that it is judgement rather than evidence.

### Good fits

**Long-running agent loops.** The original motivation. An agent working a task
over hundreds of turns accumulates state faster than any window holds it, and
the failure is silent — a fluent answer built on a detail that was corrected
three hundred turns ago. Every probe here resolves to raw source spans, so a
wrong answer is attributable rather than mysterious.

**Anything where a correction must win.** Incident response, ops runbooks,
case management, long-lived tickets. The design treats revision as a first-class
event: nothing is deleted, a correction supersedes rather than overwrites, and
superseded material is excluded from planning while remaining in the record.
`bench --mutate` measures whether the correction is actually served once the
original has accumulated dependents, which is the case that breaks naive
retrieval.

**Regulated or auditable settings.** An unsourced fact cannot enter the graph —
insertion raises rather than degrades — and every answer walks back to the spans
that grounded it. Correctness in the benchmark is gated on that path being
complete, so an answer that looks right but cannot be traced scores as a failure.

**Tamper-evident record keeping.** The `.context` container stores
content-addressed objects under a Merkle root with checkpoints chained so that
editing history invalidates every generation after it. Useful where the question
is not only "what did the system know" but "can anyone show it was not edited
afterwards". Without a signer this is tamper-*evident*, not tamper-proof.

**Cost-sensitive deployments over large histories.** 4.19 million tokens of
history answered from 259 tokens per query is a different cost structure from
feeding a long window, and it does not degrade with history length in the way a
sliding window does. That counts *assembled* tokens and not
billable ones. Re-planning every turn produces a different context every turn, so
consecutive contexts share only a 6-token header — `bench --cache` measures the
cacheable prefix at **2.8%**, 36 of 1,293 tokens. A cache-friendly assembler
sending *more* tokens could be cheaper per turn under a provider that discounts
cached prefixes, and that comparison has not been run.

### Poor fits

**Short single-turn work.** One document, one question, no corrections. The
indexing, the graph and the knapsack are pure overhead — use retrieval, or just
put the document in the prompt.

**Tasks needing the full text verbatim.** DCR deliberately serves the cheapest
sufficient representation. It can escalate to raw bytes when a probe demands an
exact quote, and it charges for that, but if most of your queries need the whole
source then bounded attention is the wrong objective.

**Semantic search over paraphrase.** The bundled embedder is a 256-dimensional
hashing embedding, not a learned one; it finds material that shares vocabulary.
`bench --channels` now measures how much that makes the lexical and vector
channels agree, instead of asserting it: they share 2.7x more than chance, and
195 of 220 ranked positions across the probe set came from exactly one channel.
So "correlated rather than independent evidence" was directionally right and
overstated. What is still unmeasured is paraphrase itself — the seven probes are
answerable by vocabulary overlap. Swapping in a learned embedder is a
constructor argument (`Ladder::embedder`, see `examples/custom_embedder.rs`),
and it costs the offline, deterministic property every figure here depends on.

**~~Reasoners that cannot signal.~~ Retracted.** This said a harness unable to
emit `#ESCALATE` loses the exact-quote and buried-detail probes, citing the
ablation's 6/7. That row was grading the unserved protocol token as the answer,
so it could not have passed. Measured properly — reasoner cannot signal, runtime
keeps the mechanism — correctness is 7/7: the router sends `QuoteExact` to L0 at
plan time, and the buried detail survives the L1 summary. Struck through rather
than deleted because it stood here as a reason not to use this.
[The full retraction](docs/use-cases.md#reasoners-that-cannot-signal--retracted).

**High-concurrency writes.** The consistency path is exercised and priced
(`bench --consolidate`) but it is single-threaded. Nothing here runs two turns
at once and no lock is exercised. Do not deploy it under concurrent ingest on
the strength of these numbers.

**Very large N where planning cost matters.** Retrieval is not the bottleneck —
an LSH index prunes ~96% of scored vectors, on the corpus with 21 distinct
documents, which does not separate pruned vectors from pruned duplicates.
`bench --recall` prices that pruning: top-12 overlap with the exact scan is
**54.8% at 3,000 turns** (100% at 300), correctness unchanged at 7/7. Doubling
the tables makes recall *worse*, not better, because larger candidate sets trip
the exact-scan fallback less often. The
cost was in the planner, and `bench --stages` now clocks each stage separately
and publishes what it rejected. Scoring dominated and grew with history despite a
candidate set capped at 120: `available()` and `cost()` each concatenated a
node's whole span list, and corroboration grows that list with N — 3,529 spans
concatenated per query at 3,000 turns, now 612. That is a constant factor, not a
change of complexity. Planning is still not shown to be sub-linear and `O(k + r)`
remains established for attention only.

### If you are evaluating it

Run `bench --ablate` first. It reports which mechanisms carry which probes,
including two that carry nothing on the standard corpus. It measures *those*
probes on *that* corpus — your workload is the thing it does not measure — but it
is the cheapest thing here to re-run against your own material, which is the only
way to answer the question for you.

If you are sizing any benchmark, the check that separates length from difficulty
costs one line: **does the count of distinct documents grow with N, or only the
token count?** That is how the problem was found here — by counting what the
generator emitted, not by reasoning about it.

## Paper

[**Dynamic Context Runtime: Bounded Attention over Unbounded History**](paper/dcr-bounded-attention.pdf)
(DCR-TR-2026-01) — the design, the implementation, and four measured results,
including an ablation that names which mechanisms carry which probes and reports
two that carry nothing. Also readable
[in the browser](https://cybersec.org.za/research-dcr-bounded-attention.html).

Every table in it reproduces offline:

```bash
cargo run --release -- bench              # context-rot comparison
cargo run --release -- bench --scaling    # does k stay flat as history grows?
cargo run --release -- bench --diverse    # scaling on a varied corpus, to 4.19M tokens
cargo run --release -- bench --sweep      # correctness against B_attention
cargo run --release -- bench --ablate     # which mechanism carries which probe?
cargo run --release -- bench --mutate     # is a correction served once the original has dependents?
cargo run --release -- bench --multihop   # does graph expansion buy anything on a join?
cargo run --release -- bench --coverage   # how much of the store is ever read back?
cargo run --release -- bench --poison     # positive control: can the stale metric fire?
cargo run --release -- bench --decay      # does a recency prefilter cost recall?
cargo run --release -- bench --consolidate # a write landing mid-turn
cargo run --release -- bench --cache      # how much of the assembled context is a cacheable prefix?
cargo run --release -- bench --recall     # what does the approximate index actually miss?
cargo run --release -- bench --fusion     # rank fusion, and what the seed floor is buying
```

The PDF and the web version are both generated from `paper/paper.frag.html` by
`python3 paper/build.py`, so the prose cannot drift between them.

## Status

Specification plus reference implementation. Contributions are docs, critiques,
worked examples, and code — see [CONTRIBUTING.md](CONTRIBUTING.md).

Several results here exist because readers proposed the instrument. Who changed
which claim, which artifact moved, and what stayed disputed: [CREDITS.md](CREDITS.md).

License: [MIT](LICENSE) for the code in `src/`, `tests/`, and `examples/`; [CC BY 4.0](LICENSE-DOCS) for the specification in `docs/` and the technical report in `paper/`.
