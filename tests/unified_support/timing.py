"""Small in-process fixture timing harness. UNVERIFIED: measurements not run.

This caps fixture construction/test helper work only. It never substitutes for G-U5 fresh-process RSS,
60k/250k IR, Windows frozen measurements, extraction or UI call counts.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Measurement:
    name: str
    repetitions: int
    seconds: tuple[float, ...]
    budget_seconds: float
    passed: bool


def measure[T](name: str, operation: Callable[[], T], *, repetitions: int = 3,
            budget_seconds: float = 5.0, clock: Callable[[], float] = perf_counter) -> Measurement:
    """An inclusive wall-clock budget per repetition; no sleep or process spawning."""
    if not name or type(repetitions) is not int or not 1 <= repetitions <= 5 or budget_seconds <= 0:
        raise ValueError("invalid measurement configuration")
    samples = []
    for _ in range(repetitions):
        start = clock()
        operation()
        elapsed = clock() - start
        if elapsed < 0:
            raise ValueError("clock moved backwards")
        samples.append(elapsed)
        if elapsed > budget_seconds:
            break
    return Measurement(name, repetitions, tuple(samples), budget_seconds,
                       len(samples) == repetitions and all(s <= budget_seconds for s in samples))
