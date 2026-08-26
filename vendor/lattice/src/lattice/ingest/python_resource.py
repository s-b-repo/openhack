"""A MINIMAL second-language ingest — proof that Footings' obstruction engine carries beyond
Solidity. It maps Python (not Solidity) onto the SAME abstract conservation operator: a resource
(file handle, lock, connection) is a conserved quantity that must net to zero at function exit;
an `open()`/`acquire()` with no matching `close()`/`release()` is a non-zero q-drift — the exact
same leak the engine detects as an unbacked token mint. The engine (`conservation_obstructions`)
is untouched; only this ~50-line adapter is language-specific. Carrying to Rust/C/Go = another
adapter producing the same (operations, functional) abstraction; the math is shared.
"""
import ast
import pathlib
from lattice.typed_chain import ConservedFunctional, conservation_obstructions

# acquire calls (+1 held) and their matching release method (-1 held). Extended in the
# accuracy sweep to close the recall gap around async clients, executors and thread pools —
# each was silently missed by the leak audit because the acquire-side constructor name
# wasn't recognized. `shutdown` is added on the release side for ThreadPoolExecutor /
# ProcessPoolExecutor / AsyncClient.aclose (the latter's Python 3.10+ async API).
_ACQUIRE = {"open", "acquire", "connect", "Lock", "socket",
            "AsyncClient", "AsyncSession", "ThreadPoolExecutor", "ProcessPoolExecutor",
            "TCPConnector", "ClientSession"}
_RELEASE = {"close", "release", "disconnect", "shutdown", "aclose"}
_HELD = ConservedFunctional(id="held_resources", weights={"held": +1})


def _net_held(fn: ast.FunctionDef) -> int:
    """Net resource delta of a function body: acquires that aren't balanced by a release or a
    `with`-statement (which both acquires AND releases at block exit, so it nets to zero)."""
    held = 0
    for node in ast.walk(fn):
        # `with open(...) as f:` — context manager acquires and releases — nets to 0
        if isinstance(node, ast.With):
            continue
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
            # a bare acquire NOT inside a `with` (walk visits with-items too, so subtract them)
            if name in _ACQUIRE and not _in_with(fn, node):
                held += 1
            elif name in _RELEASE:
                held -= 1
    return held


def _in_with(fn: ast.FunctionDef, target: ast.Call) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                if item.context_expr is target:
                    return True
    return False


def resource_audit(path) -> list[dict]:
    """Run the SHARED conservation operator over a Python file's per-function resource ledger."""
    src = pathlib.Path(path).read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(src)
    out: list[dict] = []
    for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        net = _net_held(fn)
        operations = [{"op": fn.name, "deltas": {"held": net}, "line": fn.lineno}]
        for o in conservation_obstructions(operations, _HELD):
            drift = o["drift"]
            out.append({
                "kind": "resource_leak" if drift > 0 else "over_release",
                "severity": "high", "function": fn.name, "line": fn.lineno,
                "detail": (f"{abs(drift)} resource(s) acquired but never released" if drift > 0
                           else f"{abs(drift)} more releases than acquires (double-free / use-after-release)"),
            })
    return out
