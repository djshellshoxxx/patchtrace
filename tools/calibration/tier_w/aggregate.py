"""`tier-w-aggregate/1`: the only Tier-W product the owner may read out (SPEC-33 s12, LBL s8.2). Local only (O1).

Numbers only: no names, RVAs, hashes, pair ids or KB numbers can enter, because the builder reads counts and lineage
sums, never records. Engines and conditions are never pooled. A cell with fewer than `MIN_CELL` truth pairs or scored
matches is suppressed and only counted. Lineage intervals are bootstraps over lineages (the independent unit), flagged
`anti_conservative` below 30 lineages by the shared core.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..common import r12, sha256_bytes
from ..evalcore.boot import B_COUNT, Interval, lineage_bootstrap
from .audit import AuditReport
from .contracts import Family, PairsDoc
from .evaluate import NON_EXPORTED, TAG_ALL
from .paths import dumps

CONTRACT = 'tier-w-aggregate/1'
MIN_CELL = 30
BANNER = 'Derived from Microsoft binaries. Local only (O1). Review before quoting.'
CLASSES: tuple[Family, ...] = ('kernel', 'driver', 'usermode-dll')
Tool = Annotated[str, Field(pattern=r'^[A-Za-z0-9._+ -]{1,64}$')]


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class IntervalOut(_Strict):
    point: float | None
    lo: float | None
    hi: float | None
    n_lineages: int = Field(ge=0)
    undefined: int = Field(ge=0)
    anti_conservative: bool


class MetricCell(_Strict):
    status: Literal['scored'] = 'scored'
    scored: int = Field(ge=MIN_CELL)
    truth: int = Field(ge=MIN_CELL)
    found: int = Field(ge=0)
    precision: float | None
    recall: float | None
    f1: float | None
    precision_lineage: IntervalOut
    recall_lineage: IntervalOut


class CircularCell(_Strict):
    status: Literal['insufficient-labels']
    reason: Literal['circular']


class ClassCount(_Strict):
    families: int = Field(ge=0)
    pairs: int = Field(ge=0)
    lineages: int = Field(ge=0)
    candidates: int = Field(ge=0)


class AuditBlock(_Strict):
    status: Literal['insufficient', 'weak', 'ok', 'missing']
    error: float | None
    upper: float | None
    n: int = Field(ge=0)


class Aggregate(_Strict):
    contract: Literal['tier-w-aggregate/1']
    tier: Literal['W']
    banner: str
    classes: dict[Family, ClassCount]
    metrics: dict[str, dict[str, dict[str, MetricCell | CircularCell]]]
    audit: AuditBlock
    shift: dict[str, float] = Field(default_factory=dict, max_length=32)
    tools: dict[str, Tool] = Field(default_factory=dict, max_length=32)
    suppressed_cells: int = Field(ge=0)
    min_cell: int = MIN_CELL
    report_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


def class_counts(pairs: PairsDoc, candidates_by_pair: Mapping[str, int] | None = None) -> dict[Family, ClassCount]:
    """Counts by class. Lineage = one file name (its build line chain); no name leaves this function."""
    candidates_by_pair = candidates_by_pair or {}
    family_of = {b.id: b.family for b in pairs.binaries}
    out = {}
    for family in CLASSES:
        mine = [p for p in pairs.pairs if family_of.get(p.newer) == family]
        out[family] = ClassCount(families=len({b.file_name for b in pairs.binaries if b.family == family}),
                                 pairs=len(mine), lineages=len({p.file_name for p in mine}),
                                 candidates=sum(candidates_by_pair.get(p.id, 0) for p in mine))
    return out


def _interval(per_lineage: Mapping[str, float], b_count: int, seed: str) -> IntervalOut:
    obs = {k: (k, v) for k, v in per_lineage.items()}
    iv: Interval = lineage_bootstrap(obs, b_count, seed)
    rnd = lambda v: None if v is None else r12(v)  # noqa: E731
    return IntervalOut(point=rnd(iv.point), lo=rnd(iv.lo), hi=rnd(iv.hi), n_lineages=len(obs),
                       undefined=iv.undefined, anti_conservative=iv.anti_conservative)


def _cell(overall: Mapping, lineages: Mapping[str, Mapping], b_count: int, seed: str) -> MetricCell | None:
    scored = overall['correct'] + overall['wrong']
    if scored < MIN_CELL or overall['truth'] < MIN_CELL:
        return None
    rnd = lambda v: None if v is None else r12(v)  # noqa: E731
    return MetricCell(
        scored=scored, truth=overall['truth'], found=overall['found'], precision=rnd(overall['precision']),
        recall=rnd(overall['recall']), f1=rnd(overall['f1']),
        precision_lineage=_interval({k: v['precision'] for k, v in lineages.items() if v['precision'] is not None},
                                    b_count, f'{seed}|precision'),
        recall_lineage=_interval({k: v['recall'] for k, v in lineages.items() if v['recall'] is not None},
                                 b_count, f'{seed}|recall'))


def _metrics(evaluation: Mapping, b_count: int) -> tuple[dict, int]:
    metrics: dict = {}
    suppressed = 0
    for engine, conditions in sorted(evaluation['cells'].items()):
        for condition, cell in sorted(conditions.items()):
            if cell['status'] != 'scored':
                metrics.setdefault(engine, {})[condition] = {
                    TAG_ALL: CircularCell(status=cell['status'], reason=cell['reason'])}
                continue
            out = {}
            for tag, overall in cell['tags'].items():
                made = _cell(overall, cell['tag_lineages'].get(tag, {}), b_count, f'{engine}|{condition}|{tag}')
                if made is None:
                    suppressed += 1
                else:
                    out[tag] = made
            metrics.setdefault(engine, {})[condition] = out
    return metrics, suppressed


def _audit_block(report: AuditReport | None) -> AuditBlock:
    if report is None:
        return AuditBlock(status='missing', error=None, upper=None, n=0)
    return AuditBlock(status=report.status, error=report.symbol_audit_error,
                      upper=report.symbol_audit_error_upper, n=report.reviewed)


def aggregate(evaluation: Mapping, *, classes: Mapping[Family, ClassCount], audit: AuditReport | None = None,
              shift: Mapping[str, float] | None = None, tools: Mapping[str, str] | None = None,
              b_count: int = B_COUNT) -> Aggregate:
    """Build the aggregate from a `tier-w-evaluation/1` document. Deterministic: same input, same `report_sha256`."""
    if evaluation.get('contract') != 'tier-w-evaluation/1':
        raise ValueError('not a tier-w-evaluation/1 document')
    metrics, suppressed = _metrics(evaluation, b_count)
    body = dict(contract=CONTRACT, tier='W', banner=BANNER, classes=dict(classes), metrics=metrics,
                audit=_audit_block(audit), shift=dict(shift or {}), tools=dict(tools or {}),
                suppressed_cells=suppressed, report_sha256='0' * 64)
    draft = Aggregate(**body)
    unsigned = draft.model_dump(mode='json', exclude={'report_sha256'})
    return draft.model_copy(update={'report_sha256': sha256_bytes(dumps(unsigned))})


def to_json(doc: Aggregate) -> bytes:
    return dumps(doc.model_dump(mode='json'))


def _pct(value: float | None) -> str:
    return 'n/a' if value is None else f'{value:.3f}'


def render_markdown(doc: Aggregate) -> str:
    lines = [f'> {doc.banner}', '', '# Tier W aggregate', '', f'Report SHA-256: `{doc.report_sha256}`', '',
             '## Counts by class', '', '| class | families | pairs | lineages | candidates |', '|---|---|---|---|---|']
    lines += [f'| {k} | {c.families} | {c.pairs} | {c.lineages} | {c.candidates} |' for k, c in doc.classes.items()]
    lines += ['', f'## Audit: {doc.audit.status} (n={doc.audit.n}, error={_pct(doc.audit.error)}, '
                  f'upper={_pct(doc.audit.upper)})', '', '## Metrics (never pooled across engines or conditions)']
    for engine, conditions in doc.metrics.items():
        for condition, cells in conditions.items():
            lines += ['', f'### {engine}, {condition}', '', '| cell | scored | truth | precision | recall | F1 |',
                      '|---|---|---|---|---|---|']
            for tag, cell in cells.items():
                if isinstance(cell, CircularCell):
                    lines.append(f'| {tag} | insufficient-labels ({cell.reason}) | | | | |')
                else:
                    lines.append(f'| {tag}{" (headline)" if tag == NON_EXPORTED else ""} | {cell.scored} | '
                                 f'{cell.truth} | {_pct(cell.precision)} | {_pct(cell.recall)} | {_pct(cell.f1)} |')
    lines += ['', f'Cells under n = {doc.min_cell} suppressed: {doc.suppressed_cells}.', '']
    return '\n'.join(lines)


__all__ = ['Aggregate', 'ClassCount', 'MetricCell', 'aggregate', 'class_counts', 'render_markdown', 'to_json']
