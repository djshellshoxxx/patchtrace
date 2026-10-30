"""Synthetic-only R7 bounded slicing benchmark; not a real-binary accuracy test."""
from __future__ import annotations

import json
import platform
import statistics
import time
import tracemalloc

from tools.research.r7.slicer import Op, Scope, slice_ops


def make_graph(size: int) -> tuple[Op, ...]:
    ops = []
    for i in range(size):
        # Each eight-op chain is independent; only one chain is relevant to the seed.
        inputs = ("param:input", "const:1") if i % 8 == 0 else (f"u:v{i - 1}", "const:1")
        ops.append(Op(uid=f"n{i}", rva=0x1000 + 4 * i, opcode="INT_ADD", inputs=inputs,
                      output=f"u:v{i}"))
    return tuple(ops)


def measure(size: int, repetitions: int = 30) -> dict:
    ops = make_graph(size)
    scope = Scope("a" * 64, 0x1000, "b" * 64)
    seed = f"n{size - 1}"
    timings = []
    for _ in range(repetitions):
        start = time.perf_counter()
        result = slice_ops(ops, seed, scope)
        timings.append((time.perf_counter() - start) * 1000)
    tracemalloc.start()
    result = slice_ops(ops, seed, scope)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"input_ops": size, "slice_ops": len(result.sites), "reduction_vs_input_percent":
            round(100 * (1 - len(result.sites) / size), 2), "unknowns": list(result.unknowns),
            "median_ms": round(statistics.median(timings), 4),
            "p95_ms": round(sorted(timings)[int(0.95 * (len(timings) - 1))], 4),
            "peak_tracemalloc_kib": round(peak / 1024, 2),
            "repetitions": repetitions}


def main() -> None:
    data = {"kind": "R7 synthetic-only, non-native feasibility measurement",
            "python": platform.python_version(), "system": platform.platform(),
            "results": [measure(n) for n in (128, 1024, 4096)]}
    print(json.dumps(data, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
