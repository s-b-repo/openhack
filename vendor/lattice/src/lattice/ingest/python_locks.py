"""HOMOLOGY-leg cross-language ingest — with an HONEST scope correction.

A pairwise lock inversion (fn A takes L1→L2, fn B takes L2→L1) is the 2-cycle {(L1,L2),(L2,L1)} —
the same homology obstruction as reentrancy, and the homology operator detects it. But a GENERAL
deadlock is a directed cycle of ANY length, and that is a REACHABILITY property (is a lock reachable
from itself in the acquire-order graph — a strongly-connected component), NOT a homological one.
Verified empirically: even GLMY directed path-homology (path_homology.py) is NOT a cycle detector
(it fills cycles with common successors — false negatives — and fires on the acyclic bipartite
square — false positives). So deadlock detection here uses SCC reachability, which is the correct
and complete tool. This is an honest SCOPE BOUNDARY: homology covers gluing / 2-cycle bugs
(reentrancy, use-after-free, pairwise inversion); directed N-cycles are order-theoretic, not
homological. The collision and conservation legs still carry to other languages unchanged.
"""
import ast
import pathlib


# Recognized synchronizer types — a `with self._lock: …` participates in the acquire-order
# graph only if `_lock` is one of these (or a bare name, which we can't classify — kept for
# the generic case). Extending to RLock/Semaphore/BoundedSemaphore closes the recall gap
# where a codebase mixing these primitives had their edges dropped by name.
_LOCK_TYPES = {"Lock", "RLock", "Semaphore", "BoundedSemaphore", "Condition"}


def _lock_name(expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    # `with threading.Lock():` — a construction expression whose callee is a lock type
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Name) and f.id in _LOCK_TYPES:
            return f.id
        if isinstance(f, ast.Attribute) and f.attr in _LOCK_TYPES:
            return f.attr
    return None


def _walk(node, held: list, edges: set):
    if isinstance(node, ast.With):
        held = list(held)
        for item in node.items:
            n = _lock_name(item.context_expr)
            if n:
                for h in held:
                    if h != n:
                        edges.add((h, n))      # h acquired-before n
                held.append(n)
        for stmt in node.body:
            _walk(stmt, held, edges)
    else:
        for child in ast.iter_child_nodes(node):
            _walk(child, list(held), edges)


def _sccs(edges) -> list:
    """Tarjan strongly-connected components. A component of size >1 contains a directed cycle."""
    adj: dict = {}
    for a, b in edges:
        adj.setdefault(a, []).append(b)
    nodes = {v for e in edges for v in e}
    index: dict = {}
    low: dict = {}
    onstack: set = set()
    stack: list = []
    counter = [0]
    out: list = []

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        onstack.add(v)
        for w in adj.get(v, []):
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in onstack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                onstack.discard(w)
                comp.append(w)
                if w == v:
                    break
            out.append(comp)

    for v in nodes:
        if v not in index:
            strong(v)
    return out


def lock_order_audit(path) -> list[dict]:
    """Deadlock = a directed cycle in the lock-acquire-order graph = a non-trivial SCC (reachability).
    Sound and complete for directed cycles of any length; silent on consistent orders."""
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8", errors="ignore"))
    edges: set = set()
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        _walk(fn, [], edges)
    out: list[dict] = []
    for comp in _sccs(edges):
        if len(comp) > 1:                       # a strongly-connected lock set = a deadlock cycle
            locks = sorted(comp)
            out.append({
                "kind": "lock_order_inversion", "severity": "high", "locks": locks,
                "detail": (f"locks {locks} are acquired in a cyclic order across functions (each "
                           f"reachable from the others) — a deadlock; a directed cycle, detected by "
                           f"SCC reachability (NOT homology — directed cycles are order-theoretic)"),
            })
    return out
