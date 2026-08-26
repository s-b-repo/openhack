# src/lattice/cuda.py
"""CUDA host/device data-crossing analysis — the GPU analogue of library exposure.

A kernel launch and a cudaMemcpy are boundary crossings between CPU and GPU. This surfaces
WHAT crosses: the arguments handed to a kernel (`kernel<<<g,b>>>(args)` — the data the GPU
gets) and the direction of each cudaMemcpy (host->device / device->host). Same idea as
exposure.py's "what's accessible to the callee", read from your side of the boundary.
"""
from __future__ import annotations
import pathlib
import re
from dataclasses import dataclass, field

_LAUNCH = re.compile(r"\b(\w+)\s*<<<[^>]*>>>\s*\(([^;]*?)\)\s*;", re.S)
_MEMCPY = re.compile(r"\bcudaMemcpy(?:Async)?\s*\(([^;]*?)\)\s*;", re.S)
_DIR = {"cudaMemcpyHostToDevice": "host_to_device",
        "cudaMemcpyDeviceToHost": "device_to_host",
        "cudaMemcpyDeviceToDevice": "device_to_device",
        "cudaMemcpyHostToHost": "host_to_host"}


@dataclass
class Crossing:
    file: str
    line: int
    kind: str                 # "kernel_launch" | "memcpy"
    direction: str            # host_to_device | device_to_host | ... | unknown
    kernel: str = ""
    crosses: list = field(default_factory=list)   # the args/data that cross
    detail: str = ""

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "kind": self.kind,
                "direction": self.direction, "kernel": self.kernel,
                "crosses": self.crosses, "detail": self.detail}


def _split_args(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def cuda_crossings(source_root) -> list[Crossing]:
    root = pathlib.Path(source_root)
    out: list[Crossing] = []
    for path in sorted(p for ext in ("*.cu", "*.cuh") for p in root.rglob(ext)):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in _LAUNCH.finditer(text):
            args = [a for a in _split_args(m.group(2)) if a]
            out.append(Crossing(file=rel, line=text.count("\n", 0, m.start()) + 1,
                                kind="kernel_launch", direction="host_to_device",
                                kernel=m.group(1), crosses=args,
                                detail=f"{m.group(1)}<<<...>>>({', '.join(args)})"))
        for m in _MEMCPY.finditer(text):
            args = _split_args(m.group(1))
            direction = next((_DIR[k] for k in _DIR if k in m.group(1)), "unknown")
            dst, src = (args[0] if args else "?"), (args[1] if len(args) > 1 else "?")
            out.append(Crossing(file=rel, line=text.count("\n", 0, m.start()) + 1,
                                kind="memcpy", direction=direction,
                                crosses=[src], detail=f"cudaMemcpy {src} -> {dst} ({direction})"))
    return out
