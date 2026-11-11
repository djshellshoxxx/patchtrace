"""Blind audit of the symbol-derived labels (SPEC-33 s7). Pure: sampler, review queue, error-rate report.

The sampler draws from the labelled candidates, and from truth only when there are none (the key says which). The census
takes every `same` label whose body size changed by more than `size_change`; the random stratum takes `rate` of the rest,
decided by `det_uniform(seed, 'audit', pair, match_id)`. The queue shows bytes and sizes, never a name, a symbol label or
an engine output. The report bounds the error one-sided (Clopper-Pearson) and weights strata by population share.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..common import det_uniform
from ..stats import clopper_pearson_upper
from .contracts import AuditItem, AuditKey
from .paths import TierWError

RATE = 0.05
SIZE_CHANGE = 0.40
MIN_REVIEWED = 30
MAX_ERROR = 0.02
PREVIEW_BYTES = 128
ANSWERS = ('same', 'different', 'no-counterpart', 'indeterminate')
STRATA = ('census', 'random')


@dataclass(frozen=True)
class AuditCandidate:
    pair: str
    match_id: str
    answer: Literal['same', 'different']
    older_rva: int | None
    newer_rva: int | None
    older_size: int | None = None
    newer_size: int | None = None


@dataclass(frozen=True)
class SideView:
    size: int | None
    body_sha256: str | None
    preview: bytes


class SideReader(Protocol):
    def read(self, pair: str, side: Literal['older', 'newer'], rva: int | None) -> SideView: ...


def _is_census(c: AuditCandidate, size_change: float) -> bool:
    if c.answer != 'same' or not c.older_size or c.newer_size is None:
        return False
    return abs(c.newer_size - c.older_size) / c.older_size > size_change


def sample_audit(candidates: Sequence[AuditCandidate], truth: Sequence[AuditCandidate], *, corpus_id: str, seed: str,
                 rate: float = RATE, size_change: float = SIZE_CHANGE, created: str = '') -> AuditKey:
    """Hidden key for one audit. `candidates` are the labelled engine matches; `truth` is used only when empty."""
    if not 0 < rate <= 1 or size_change <= 0:
        raise TierWError('PT-TIERW-INPUT', 'rate must be in (0, 1] and size_change positive')
    population, rows = ('candidates', candidates) if candidates else ('truth', truth)
    counts: Counter[str] = Counter()
    items = []
    for c in sorted(rows, key=lambda r: (r.pair, r.match_id)):
        census = _is_census(c, size_change)
        counts['census' if census else 'random'] += 1
        if census or det_uniform(seed, 'audit', c.pair, c.match_id) < rate:
            items.append(AuditItem(pair=c.pair, match_id=c.match_id, A=c.answer,
                                   stratum='census' if census else 'random', p_incl=1.0 if census else rate))
    return AuditKey(contract='tier-w-audit-key/1', tier='W', corpus_id=corpus_id, population=population, seed=seed,
                    rate=rate, size_change=size_change, created=created,
                    population_counts={s: counts[s] for s in STRATA}, items=tuple(items))


def queue_header(key: AuditKey) -> dict:
    return {'contract': 'tier-w-review/1', 'tier': 'W', 'corpus_id': key.corpus_id, 'population': key.population,
            'items': len(key.items), 'single_annotator': True}


def queue_records(key: AuditKey, sides: Mapping[tuple[str, str], tuple[int | None, int | None]],
                  reader: SideReader) -> list[dict]:
    """Review items in a seed-shuffled order (census does not cluster). `sides[(pair, match_id)]` = (older, newer) RVA.
    No symbol label, name or engine output enters a record."""
    out = []
    for item in sorted(key.items, key=lambda i: det_uniform(key.seed, 'order', i.pair, i.match_id)):
        older_rva, newer_rva = sides[(item.pair, item.match_id)]
        record: dict = {'pair': item.pair, 'match_id': item.match_id, 'stratum': item.stratum}
        for side, rva in (('older', older_rva), ('newer', newer_rva)):
            view = reader.read(item.pair, side, rva)
            record[side] = {'rva': rva, 'size': view.size, 'body_sha256': view.body_sha256,
                            'preview_hex': view.preview[:PREVIEW_BYTES].hex()}
        out.append(record)
    return out


class StratumResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    population: int = Field(ge=0)
    reviewed: int = Field(ge=0)
    indeterminate: int = Field(ge=0)
    errors: int = Field(ge=0)
    error: float | None
    upper: float | None


class AuditReport(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    contract: Literal['tier-w-audit-report/1']
    tier: Literal['W']
    corpus_id: str = Field(max_length=64)
    population: Literal['candidates', 'truth']
    strata: dict[Literal['census', 'random'], StratumResult]
    unknown_items: int = Field(ge=0)
    symbol_audit_error: float | None
    symbol_audit_error_upper: float | None
    reviewed: int = Field(ge=0)
    indeterminate: int = Field(ge=0)
    status: Literal['insufficient', 'weak', 'ok']
    single_annotator: bool = True


def _stratum(population: int, rows: Iterable[tuple[str, str]]) -> StratumResult:
    """`rows` = (symbol answer, human answer). Human `same` is y=1; `different` and `no-counterpart` are y=0."""
    reviewed = errors = indeterminate = 0
    for symbol, human in rows:
        if human == 'indeterminate':
            indeterminate += 1
            continue
        reviewed += 1
        errors += (human == 'same') != (symbol == 'same')
    return StratumResult(population=population, reviewed=reviewed, indeterminate=indeterminate, errors=errors,
                         error=errors / reviewed if reviewed else None,
                         upper=clopper_pearson_upper(errors, reviewed) if reviewed else None)


def audit_report(key: AuditKey, answers: Mapping[tuple[str, str], str]) -> AuditReport:
    """Error rate of the symbol labels against the owner's answers (s7.3)."""
    bad = sorted({a for a in answers.values() if a not in ANSWERS})
    if bad:
        raise TierWError('PT-TIERW-INPUT', f'unknown audit answers {bad[:3]}')
    index = {(i.pair, i.match_id): i for i in key.items}
    unknown = sum(1 for k in answers if k not in index)
    strata = {s: _stratum(key.population_counts.get(s, 0),
                          [(i.A, answers[k]) for k, i in index.items() if i.stratum == s and k in answers])
              for s in STRATA}
    total = sum(r.population for r in strata.values())
    live = [r for r in strata.values() if r.population]
    complete = bool(total) and all(r.reviewed for r in live)
    point = upper = None
    if complete:
        point = sum(r.population / total * r.error for r in live)
        upper = sum(r.population / total * r.upper for r in live)
    reviewed = sum(r.reviewed for r in strata.values())
    status = 'insufficient' if reviewed < MIN_REVIEWED or point is None else 'weak' if point > MAX_ERROR else 'ok'
    return AuditReport(contract='tier-w-audit-report/1', tier='W', corpus_id=key.corpus_id, population=key.population,
                       strata=strata, unknown_items=unknown, symbol_audit_error=point,
                       symbol_audit_error_upper=upper, reviewed=reviewed,
                       indeterminate=sum(r.indeterminate for r in strata.values()), status=status)

