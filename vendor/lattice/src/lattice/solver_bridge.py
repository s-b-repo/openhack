# src/lattice/solver_bridge.py
"""SSH bridge to the z6 solver suite — gives Footings' hard computations validated legs.

Calls the gated solver on the z6 over SSH (independent of the agent-side MCP). Each
call returns the solver's result *and* its contract envelope (params_fingerprint,
solver.result.v1 certificate). Enabled by setting FOOTINGS_SOLVER=1; off by default
so the local legs stay the deterministic baseline.

Correctness guard: the bridge never trusts the solver blindly. For min-feedback-arc-set
it verifies the returned cut actually makes the subgraph acyclic; if not, it returns
None so compute.py falls back to the local greedy leg. The solver gives the *optimal*
legs, Footings keeps the *correctness* guarantee.
"""
from __future__ import annotations
import json
import os
import shlex
import subprocess

_DEFAULT_HOST = "straylight@192.168.0.165"
_DEFAULT_ROOT = "/home/straylight/Solver"


def _host() -> str:
    return os.environ.get("FOOTINGS_SOLVER_HOST", _DEFAULT_HOST)


def _remote_cmd() -> str:
    """Remote command, built per call (env read at call time, not import time). The
    solver root is shell-quoted — an env var must never smuggle shell onto the z6."""
    root = os.environ.get("FOOTINGS_SOLVER_ROOT", _DEFAULT_ROOT)
    return (f"cd {shlex.quote(root)} && .venv/bin/python -c "
            "'import sys,json,solver_core as sc; r=json.load(sys.stdin); "
            "print(json.dumps(sc.run(r[\"name\"], r[\"params\"])))'")


def enabled() -> bool:
    return os.environ.get("FOOTINGS_SOLVER", "") in ("1", "true", "ssh")


def call(name: str, params: dict, timeout: int = 20):
    """Run a solver on the z6 by name; return its result dict (with _contract), or None."""
    try:
        proc = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", _host(), _remote_cmd()],
            input=json.dumps({"name": name, "params": params}),
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return None
        out = json.loads(proc.stdout.strip())
        # sc.run returns [result, node_id]; result may carry _contract/_inputs envelope.
        return out[0] if isinstance(out, list) and out else out
    except Exception:
        return None


def min_cycles(nodes: list, edges: list):
    """Solver leg for topology.obstruction_witnesses. For UNWEIGHTED minimal cycles the
    local BFS leg is already optimal (shortest realizing cycle per H₁ class), so this returns
    None — the caller keeps the exact local result. Reserved for the weighted/constrained case
    (edge costs, or cycles required to satisfy a typed-constraint algebra), where the minimal
    *valid* witness becomes a genuine optimization the z6 should own. Returning None is the
    honest default until that algebra is wired onto the edges."""
    return None


# --- min feedback arc set as a QUBO (linear-ordering / back-edge penalty) ---

def _has_cycle(nodes, edges) -> bool:
    adj = {n: [] for n in nodes}
    for a, b in edges:
        if a in adj:
            adj[a].append(b)
    color = {n: 0 for n in nodes}

    def dfs(u):
        color[u] = 1
        for v in adj.get(u, ()):
            if v in color and (color[v] == 1 or (color[v] == 0 and dfs(v))):
                return True
        color[u] = 2
        return False

    return any(color[n] == 0 and dfs(n) for n in nodes)


def _min_fas_qubo(nodes: list, edges: list, penalty: float | None = None):
    """Build a SYMMETRIC Q for min-FAS via node ordering. Vars y[i,p] = node i at
    position p. Objective: back edges (u after v for edge u->v). Penalty: one-hot
    per node and per position (a node holds exactly one slot, a slot one node).
    deadbolt minimizes x^T Q x over a symmetric Q, so pair coefficients are split."""
    n = len(nodes)
    if penalty is None:
        penalty = len(edges) + 2.0       # must dominate the objective to hold constraints
    vidx = {(i, p): i * n + p for i in range(n) for p in range(n)}
    N = n * n
    Q = [[0.0] * N for _ in range(N)]
    nat = {node: i for i, node in enumerate(nodes)}

    def diag(a, w):
        Q[a][a] += w

    def pair(a, b, w):                    # symmetric: split across Q[a][b] and Q[b][a]
        Q[a][b] += w / 2.0
        Q[b][a] += w / 2.0

    # (sum_p y_ip - 1)^2  ->  diagonal -P, pair +2P, per node (over positions)
    for i in range(n):
        for p in range(n):
            diag(vidx[(i, p)], -penalty)
            for q in range(p + 1, n):
                pair(vidx[(i, p)], vidx[(i, q)], 2 * penalty)
    # ... and per position (over nodes)
    for p in range(n):
        for i in range(n):
            for j in range(i + 1, n):
                pair(vidx[(i, p)], vidx[(j, p)], 2 * penalty)
    # objective: edge u->v costs 1 when pos(u)=p > pos(v)=q  (a back edge)
    for u, v in edges:
        iu, iv = nat[u], nat[v]
        for p in range(n):
            for q in range(p):
                pair(vidx[(iu, p)], vidx[(iv, q)], 1.0)
    return Q, vidx


def min_hitting_set(sets: list):
    """Solver leg for barriers.min_barrier_set — optimal minimum hitting set as a QUBO.
    `sets` is a list of vertex-id sets (the interior of each attack path). Returns the
    chosen vertex set, or None to fall back to greedy. barriers.py verifies coverage
    before trusting, so an imperfect solve is safe (it just falls back)."""
    if not enabled():
        return None
    candidates = sorted(set().union(*sets)) if sets else []
    n = len(candidates)
    if n == 0 or n > 24:                  # keep the exact QUBO small
        return None
    idx = {v: i for i, v in enumerate(candidates)}
    P = 2.0
    Q = [[0.0] * n for _ in range(n)]
    for i in range(n):
        Q[i][i] += 1.0                    # minimize the count of gates
    for S in sets:                        # penalize an uncovered set: P*(1 - sum_{v in S} x_v)^2
        members = [idx[v] for v in S if v in idx]
        for i in members:
            Q[i][i] += -P
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                Q[members[a]][members[b]] += P
                Q[members[b]][members[a]] += P
    res = call("deadbolt", {"Q": Q})
    if not res:
        return None
    x = res.get("x") or res.get("solution") or res.get("assignment")
    if x is None or len(x) != n:
        return None
    return {candidates[i] for i in range(n) if x[i]}


def min_feedback_arc_set(nodes: set, edges: list):
    """Solver leg for compute.min_feedback_arc_set. Returns the cut edge list, or None
    to fall back to local. Verifies the cut breaks all cycles before trusting it."""
    if not enabled():
        return None
    node_list = sorted(nodes)
    n = len(node_list)
    if n < 2 or n > 8:                    # QUBO is n^2 vars; keep exact solves small
        return None
    Q, vidx = _min_fas_qubo(node_list, edges)
    res = call("deadbolt", {"Q": Q})
    if not res:
        return None
    x = res.get("x") or res.get("solution") or res.get("assignment")
    if x is None or len(x) != n * n:
        return None
    pos = {}
    for i, node in enumerate(node_list):
        for p in range(n):
            if x[vidx[(i, p)]]:
                pos[node] = p
    if len(pos) != n:
        return None
    cut = [(u, v) for (u, v) in edges if pos.get(u, -1) > pos.get(v, n)]
    remaining = [e for e in edges if e not in cut]
    if _has_cycle(node_list, remaining):
        return None                       # solver cut didn't work -> local fallback
    return cut
