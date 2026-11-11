"""`unified-outcomes/1`: what a unified run said about the pairs of the corpus, reduced to what the gates read (08 s1).

One document is one run (a platform, a repetition): per pair the rows' decision and materiality keyed by RVA, the
planted function of a mutant, and a digest of the rows so that two runs can be compared without keeping the rows.
`collect` joins stored `UnifiedMatch` rows with a SPEC-32 label document; it never recomputes a verdict. Dev-only,
never shipped.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from patchtrace.unified.contracts import SEMANTIC_CLASSES
from tools.calibration.common import digest, strict_json
from tools.calibration.tier_r import contracts as C

CONTRACT = 'unified-outcomes/1'
Orientation = Literal['forward', 'swapped']


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Basis(_Strict):
    """One support of a row joined to its atom: who said it, at which tier, in which evidence class."""
    component: str
    tier: str
    cls: str
    source: str
    step: str


class OutcomeRow(_Strict):
    older: tuple[int, ...]
    newer: tuple[int, ...]
    decision: str
    materiality: str
    basis: tuple[Basis, ...] = ()           # the supports of the row (G-U3 per pass, G-U7 per component and class pair)
    truth: str = ''                         # right / wrong / unknown for a one-to-one row against the labels, '' when not joined
    edited: str = ''                        # edited / not-edited: the label of the older function (G-U6 false leads)
    ghidriff_exact: bool = False            # an atom of Ghidriff's SymbolsHash or ExactBytes correlator (G-U3, A/A)
    legacy: tuple[str, ...] = ()            # legacy tools whose output flags the pair as changed (G-U6)
    proof: str = ''                 # the proof of the stored change facts (`COS-PSEUDO/1`, ...), '' when none was joined
    cheap_semantic: bool = False    # a semantic delta from a channel other than the decompiler's C6 (G-U4 cross-tier check)


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
    legacy_tools: tuple[str, ...] = ()      # legacy tools that produced output for this pair; absence is not a negative vote


class OutcomeSet(_Strict):
    contract: Literal['unified-outcomes/1']
    run: C.Ident
    platform: str
    pairs: tuple[PairOutcome, ...]
    outcomes_sha256: C.Sha256


GHIDRIFF_EXACT = ('SymbolsHash', 'ExactBytesFunctionHasher')


def basis_of(match) -> tuple[Basis, ...]:
    return tuple(Basis(component=s.component, tier=s.tier, cls=match.atoms[s.atom_index].cls,
                       source=match.atoms[s.atom_index].source, step=match.atoms[s.atom_index].step)
                 for s in match.support)


def row_of(match, fact=None, labels: Truth | None = None, legacy: Iterable[str] = ()) -> OutcomeRow:
    """From a stored `UnifiedMatch`: the RVAs of both sides and the two verdict words; with the row's stored
    `ChangeFacts` also its proof and whether a cheap-tier semantic delta stands beside it, with the label index the
    truth of a one-to-one row, with `legacy` the tools that flag it."""
    older, newer = tuple(s.rva for s in match.older), tuple(s.rva for s in match.newer)
    cheap = fact is not None and any(d.cls in SEMANTIC_CLASSES and d.channel != 'C6' for d in fact.deltas)
    truth, edited = labels.judge(older, newer) if labels is not None else ('', '')
    return OutcomeRow(older=older, newer=newer, decision=match.decision, materiality=match.materiality,
                      basis=basis_of(match), truth=truth, edited=edited,
                      ghidriff_exact=any(a.source == 'ghidriff' and a.step in GHIDRIFF_EXACT for a in match.atoms),
                      legacy=tuple(sorted(legacy)),
                      proof=(fact.proof or '') if fact is not None else '', cheap_semantic=cheap)


class Truth:
    """The label document as two RVA indexes: what a one-to-one row should pair, and whether its function was edited."""

    def __init__(self, doc: C.KnownAnswerLabels):
        self.by_old = {f.old_rva: f for f in doc.functions if f.old_rva is not None}
        self.by_new = {f.new_rva: f for f in doc.functions if f.new_rva is not None}

    def judge(self, older: tuple[int, ...], newer: tuple[int, ...]) -> tuple[str, str]:
        """(truth, edited): `right` when the labels pair exactly these two functions, `wrong` when they pair the older
        one with another function, say it has no counterpart or pair the newer one with another; else `unknown`."""
        if len(older) != 1 or len(newer) != 1:
            return '', ''
        f = self.by_old.get(older[0])
        if f is None:
            g = self.by_new.get(newer[0])
            return ('wrong' if g is not None and g.identity == 'same' else 'unknown'), ''
        edited = 'edited' if f.label == 'changed' else 'not-edited' if f.label in ('unchanged', 'cosmetic') else ''
        if f.identity == 'same':
            return ('right' if f.new_rva == newer[0] else 'wrong'), edited
        return ('wrong' if f.identity == 'no-counterpart' else 'unknown'), edited


def planted_of(doc: C.KnownAnswerLabels) -> Planted | None:
    if doc.stratum != 'mutation':
        return None
    hits = [f for f in doc.functions if f.label == 'changed' and f.identity == 'same']
    if len(hits) != 1:
        raise C.ContractError(f'{doc.pair_id}: a mutant label document needs exactly one planted function, '
                              f'has {len(hits)}')
    return Planted(name=hits[0].name, older_rva=hits[0].old_rva, newer_rva=hits[0].new_rva)


def collect_rows(out: Iterable[OutcomeRow], doc: C.KnownAnswerLabels, *, orientation: Orientation = 'forward',
                 legacy_tools: Iterable[str] = ()) -> PairOutcome:
    rows = tuple(sorted(out, key=lambda r: (r.older, r.newer, r.decision, r.materiality)))
    return PairOutcome(pair_id=doc.pair_id, labels_sha256=doc.digest_sha256, orientation=orientation,
                       planted=planted_of(doc), rows=rows, legacy_tools=tuple(sorted(legacy_tools)),
                       rows_sha256=digest({'rows': [r.model_dump(mode='json') for r in rows]}, 'none'))


def collect(matches: Iterable, doc: C.KnownAnswerLabels, *, orientation: Orientation = 'forward',
            facts: Mapping[str, Any] | None = None, flagged: Mapping[str, frozenset[str]] | None = None) -> PairOutcome:
    """`facts` maps `row_id` to the stored `ChangeFacts`; without it the rows carry no proof. `flagged` maps a legacy
    tool to the ids of its Ghidriff-side matches it calls changed; the tool is then listed as having run on the pair."""
    facts, flagged = facts or {}, flagged or {}
    labels = Truth(doc)
    rows = (row_of(m, facts.get(m.row_id), labels, [t for t, ids in flagged.items() if m.ghidriff_match_id in ids])
            for m in matches)
    return collect_rows(rows, doc, orientation=orientation, legacy_tools=flagged)


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
