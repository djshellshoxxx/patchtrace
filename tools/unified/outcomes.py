"""`unified-outcomes/1`: what a unified run said about the pairs of the corpus, reduced to what the gates read (08 s1).

One document is one run (a platform, a repetition): per pair the rows' decision and materiality keyed by RVA, the
planted function of a mutant, and a digest of the rows so that two runs can be compared without keeping the rows.
`collect` joins stored `UnifiedMatch` rows with a SPEC-32 label document; it never recomputes a verdict. Dev-only,
never shipped.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from tools.calibration.common import digest, strict_json
from tools.calibration.tier_r import contracts as C

CONTRACT = 'unified-outcomes/1'
Orientation = Literal['forward', 'swapped']


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class OutcomeRow(_Strict):
    older: tuple[int, ...]
    newer: tuple[int, ...]
    decision: str
    materiality: str


class Planted(_Strict):
    name: str
    older_rva: int
    newer_rva: int


class PairOutcome(_Strict):
    pair_id: C.Ident
    labels_sha256: C.Sha256
    orientation: Orientation = 'forward'
    planted: Planted | None = None
    rows: tuple[OutcomeRow, ...]
    rows_sha256: C.Sha256


class OutcomeSet(_Strict):
    contract: Literal['unified-outcomes/1']
    run: C.Ident
    platform: str
    pairs: tuple[PairOutcome, ...]
    outcomes_sha256: C.Sha256


def row_of(match) -> OutcomeRow:
    """From a stored `UnifiedMatch`: the RVAs of both sides and the two verdict words, nothing else."""
    return OutcomeRow(older=tuple(s.rva for s in match.older), newer=tuple(s.rva for s in match.newer),
                      decision=match.decision, materiality=match.materiality)


def planted_of(doc: C.KnownAnswerLabels) -> Planted | None:
    if doc.stratum != 'mutation':
        return None
    hits = [f for f in doc.functions if f.label == 'changed' and f.identity == 'same']
    if len(hits) != 1:
        raise C.ContractError(f'{doc.pair_id}: a mutant label document needs exactly one planted function, '
                              f'has {len(hits)}')
    return Planted(name=hits[0].name, older_rva=hits[0].old_rva, newer_rva=hits[0].new_rva)


def collect_rows(out: Iterable[OutcomeRow], doc: C.KnownAnswerLabels, *, orientation: Orientation = 'forward') -> PairOutcome:
    rows = tuple(sorted(out, key=lambda r: (r.older, r.newer, r.decision, r.materiality)))
    return PairOutcome(pair_id=doc.pair_id, labels_sha256=doc.digest_sha256, orientation=orientation,
                       planted=planted_of(doc), rows=rows,
                       rows_sha256=digest({'rows': [r.model_dump(mode='json') for r in rows]}, 'none'))


def collect(matches: Iterable, doc: C.KnownAnswerLabels, *, orientation: Orientation = 'forward') -> PairOutcome:
    return collect_rows((row_of(m) for m in matches), doc, orientation=orientation)


def build(run: str, platform: str, pairs: Iterable[PairOutcome]) -> OutcomeSet:
    ordered = sorted(pairs, key=lambda p: (p.pair_id, p.orientation))
    keys = [(p.pair_id, p.orientation) for p in ordered]
    if len(keys) != len(set(keys)):
        raise C.ContractError('a pair occurs twice in one run')
    body = {'contract': CONTRACT, 'run': run, 'platform': platform,
            'pairs': [p.model_dump(mode='json') for p in ordered]}
    return OutcomeSet.model_validate_json(json.dumps({**body, 'outcomes_sha256': digest(body, 'outcomes_sha256')}))


def dump(outcomes: OutcomeSet) -> bytes:
    return C.dump_json(outcomes.model_dump(mode='json'))


def load(data: bytes) -> OutcomeSet:
    try:
        raw = strict_json(data)
        outcomes = OutcomeSet.model_validate_json(data)
    except (ValueError, ValidationError) as exc:
        raise C.ContractError(f'outcomes invalid: {exc}') from None
    if digest(raw, 'outcomes_sha256') != outcomes.outcomes_sha256:
        raise C.ContractError('outcomes digest mismatch (edited after generation)')
    return outcomes
