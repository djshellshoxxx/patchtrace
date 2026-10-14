"""Deterministic helpers shared by the dev pipeline (spec §7.3)."""
from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from dataclasses import dataclass

from patchtrace.calibration.artifact import canonical_json, digest, strict_json

__all__ = ['Row', 'canonical_json', 'det_normal', 'det_uniform', 'digest', 'r12', 'sha256_bytes', 'strict_json',
           'weighted_quantile']


def det_uniform(seed, *key) -> float:
    """Platform-independent PRNG substitute: sha256 of the joined key -> [0, 1).

    Uses 13 hex digits (52 bits) / 2**52, which is exact in a double and strictly < 1.0. (The spec's draft
    `int(h[:16], 16) / 2**64` can round to exactly 1.0 because a double has a 53-bit mantissa.)"""
    h = hashlib.sha256('|'.join(map(str, (seed,) + key)).encode()).hexdigest()
    return int(h[:13], 16) / 2**52


def det_normal(seed, *key) -> float:
    """Standard normal via Box-Muller over two det_uniform draws."""
    u1 = max(det_uniform(seed, *key, 'n1'), 1e-300)
    u2 = det_uniform(seed, *key, 'n2')
    return math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


def r12(value: float) -> float:
    """Round to 12 significant digits for serialisation."""
    return float(f'{value:.12g}')


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def weighted_quantile(values: Sequence[float], weights: Sequence[float], q: float) -> float:
    pairs = sorted(zip(values, weights, strict=True))
    total = math.fsum(weights)
    acc = 0.0
    for value, weight in pairs:
        acc += weight
        if acc >= q * total - 1e-12:
            return value
    return pairs[-1][0]


@dataclass(frozen=True)
class Row:
    """One labelled candidate. `w` is the inverse inclusion probability (natural) or 1 (adversarial)."""
    id: str
    group: str
    x: tuple[float, ...]
    y: int
    w: float = 1.0
    stratum: str = 'natural'
    profile: str = 'G'
    subtype: str | None = None
    abstain: bool = False
