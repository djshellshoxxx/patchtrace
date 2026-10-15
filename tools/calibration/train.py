"""Tier R label-training run (LBL-15; dev-only, never ships): `python -m tools.calibration.train {run, shift, report}`.

Inputs are `tier-r-feature-rows/1` documents: one per pair, holding the pair provenance (both images), the candidate rows
of the engine outputs in `features/1` column order, and the engine-run digests. They are built here from
`known-answer-labels/1` documents plus `tier-r-engine-output/1` files (`run --labels --outputs`), read from a folder
(`--rows`), or taken from the `features` list of a `shard.py merge` provenance file (`--merge`, optionally checked
against its `--aggregate` report). Nothing but aggregate-safe tables travels between CI shards and this run.

Order of work, each step failing closed: split audit (`guards.audit_manifest` must have no violation, else `PT-KA-LEAK`,
exit 1) -> controls (A/A, noise, mutation pairs) are excluded from evidence and counted -> rows (indeterminate and
ambiguous candidates excluded and counted; groups from `lineage.identity_groups(hub_max_lineages=3)`) -> minimum-sample
guards (below them: a report with every gate `insufficient-data`, no fit) -> `fit.run_pipeline` (grouped nested CV,
calibrator on out-of-fold rows, Learn-then-Test tau, lineage-bootstrap intervals) -> shift ladder -> `calibration-report/1`
with `TIER_R_CLAIM`. G1 is evaluated; G0, G2 and G3 are `insufficient-data` by construction. The artifact is `experimental`,
displays nothing, is written only on `--artifact` and is never bundled.

The result is a pipeline check on test builds of open-source code. It carries no real-world accuracy claim, and the
report text enforces that (`report.verify_tier_r_report`). Output is deterministic: the same inputs give byte-identical
`report.json` (no clock, sorted ids, canonical JSON).

Feature adapter limits (stated, not hidden): engine outputs carry RVAs, a changed flag and an optional similarity only, so
`G.ratio`/`G.unchanged` and `R.similarity` come from those, sizes from the labels, callee counts are 0, match-type flags
are 0, and engine-agreement flags compare which engines proposed the same pair. Columns that are constant over the
whole run are dropped before fitting (label-free) and counted. BinDiff outputs are not used until BinExport pairs exist.
Exit codes as SPEC-32 s12: 0 ok, 1 findings (leakage), 2 usage or contract error, 3 BLOCKED (input not available here).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from patchtrace.calibration.artifact import digest as artifact_digest
from patchtrace.calibration.artifact import parse_artifact
from patchtrace.calibration.features import FEATURE_SCHEMA, SPEC_BY_NAME, feature_names
from patchtrace.calibration.scope import SCOPE_TEXT

from . import shift as SH
from .common import Row, canonical_json, digest, strict_json
from .contracts import ContractError as CorpusContractError
from .cv import CVConfig, CVError
from .fit import impute, medians, run_pipeline
from .gates import evaluate_gates
from .guards import RowError, audit_manifest, canonical_manifest_sha256, evidence_pairs, validate_rows
from .lineage import CandidateIdentity, identity_groups
from .report import TIER_R_CLAIM, make_tier_r_report, render_markdown, verify_tier_r_report
from .tier_r import annotate as A
from .tier_r import contracts as C
from .tier_r import evaluate as E
from .tier_r import manifest as M
from .tier_r import report_schemas as RS

OK, FINDINGS, USAGE, BLOCKED = 0, 1, 2, 3
ROWS_CONTRACT = 'tier-r-feature-rows/1'
MERGE_CONTRACT = 'tier-r-merge/1'
FEATURE_ENGINES = ('ghidriff', 'rz-diff')           # BinDiff waits for BinExport pairs (plan 7.3)
PREREG_PLACEHOLDER = 'unlocked-placeholder'
TOOLCHAIN_CLASS = {'mingw-gcc': 'gcc', 'mingw-clang': 'clang', 'msvc-free': 'clang', 'clang-cl': 'clang',
                   'msvc': 'msvc'}
MAX_ROWS_PER_PAIR = 200_000
HUB_MAX_LINEAGES = 3
# Minimum sample before any fit (below: report with every gate insufficient-data, never a number).
FIT_MIN = {'rows': 200, 'positives': 30, 'negatives': 30}
EXCLUDED_KEYS = ('indeterminate', 'unlabelled-side')


class TrainError(Exception):
    def __init__(self, code: str, message: str, exit_code: int = USAGE):
        super().__init__(f'{code}: {message}')
        self.code, self.exit_code = code, exit_code


# ---- configuration ----------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class TrainConfig:
    """Frozen values of docs/plans/c9-preregistration-v1.md section 5; `smoke` lowers cost only and is recorded."""
    k_outer: int = 5
    k_inner: int = 5
    c_grid: tuple[float, ...] = (0.01, 0.1, 1.0, 10.0)
    seed: int = 1
    b_count: int = 2000
    null_sims: int = 1000
    rung_b_count: int = 500
    rung_null_sims: int = 200
    hub_max_lineages: int = HUB_MAX_LINEAGES
    with_m1: bool = True
    ablate: bool = True
    smoke: bool = False

    @classmethod
    def smoke_config(cls) -> TrainConfig:
        return cls(k_inner=3, c_grid=(0.1, 1.0), b_count=200, null_sims=100, rung_b_count=100, rung_null_sims=50,
                   with_m1=False, ablate=False, smoke=True)

    def as_dict(self) -> dict:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(self).items()}

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.as_dict())).hexdigest()


def train_key(*, manifest_sha: str, label_set_sha: str, engine_run_digests: Sequence[str], config_digest: str,
              prereg_sha: str | None) -> str:
    """SHA-256(manifest sha, label-set sha, engine-run digests, features/1, config digest, preregistration sha or
    the placeholder). Order of the digests does not matter."""
    return hashlib.sha256(canonical_json({
        'manifest_sha256': manifest_sha, 'label_set_sha256': label_set_sha,
        'engine_run_digests': sorted(set(engine_run_digests)), 'feature_schema': FEATURE_SCHEMA,
        'config_digest': config_digest, 'prereg_sha256': prereg_sha or PREREG_PLACEHOLDER})).hexdigest()


# ---- tier-r-feature-rows/1 --------------------------------------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class EngineRun(_Strict):
    engine: Literal['rz-diff', 'ghidriff']
    version: str | None = Field(default=None, max_length=200)
    output_sha256: C.Sha256


class RowDoc(_Strict):
    id: str = Field(min_length=1, max_length=300)
    y: Literal[0, 1]
    identities: tuple[str, ...] = Field(max_length=4)
    x: tuple[float | None, ...] = Field(max_length=128)


class PairRows(_Strict):
    """Candidate rows of one pair in `features/1` column order, with the provenance the split audit needs."""
    contract: Literal['tier-r-feature-rows/1']
    pair_id: C.Ident
    stratum: C.Stratum
    project: C.Ident
    lineage: C.Ident
    family: str = Field(min_length=1, max_length=64, pattern=r'^[a-z0-9-]+$')
    older: C.ImageSide
    newer: C.ImageSide
    label_digest: C.Sha256
    profile: Literal['G', 'G+R']
    columns: tuple[str, ...] = Field(max_length=128)
    engine_runs: tuple[EngineRun, ...] = ()
    excluded: dict[str, int] = Field(default_factory=dict)
    rows: tuple[RowDoc, ...] = Field(default=(), max_length=MAX_ROWS_PER_PAIR)
    digest_sha256: C.Sha256


def _finish(doc: dict) -> dict:
    doc = {k: v for k, v in doc.items() if k != 'digest_sha256'}
    doc['digest_sha256'] = digest(doc)
    return doc


def load_pair_rows(data: bytes | str | Mapping) -> PairRows:
    raw = canonical_json(data) if isinstance(data, Mapping) else (data.encode() if isinstance(data, str) else data)
    try:
        strict_json(raw)
        doc = PairRows.model_validate_json(raw)
    except (ValueError, ValidationError) as exc:
        raise TrainError('PT-KA-EVAL', f'not a valid {ROWS_CONTRACT} document: {str(exc)[:300]}') from None
    if digest(json.loads(raw)) != doc.digest_sha256:
        raise TrainError('PT-KA-EVAL', f'{doc.pair_id}: feature rows digest mismatch (tampered or truncated)')
    expected = feature_names(doc.profile)
    if doc.columns != expected:
        raise TrainError('PT-KA-EVAL', f'{doc.pair_id}: columns are not the {FEATURE_SCHEMA} columns of profile {doc.profile}')
    if any(len(r.x) != len(doc.columns) for r in doc.rows):
        raise TrainError('PT-KA-EVAL', f'{doc.pair_id}: a row does not have one value per column')
    if len({r.id for r in doc.rows}) != len(doc.rows):
        raise TrainError('PT-KA-EVAL', f'{doc.pair_id}: duplicate row ids')
    return doc


# ---- building rows from labels and engine outputs ---------------------------------------------------------------------

def profile_for(engines: Sequence[str]) -> str:
    used = set(engines) & set(FEATURE_ENGINES)
    if not used:
        raise TrainError('PT-KA-BLOCKED', 'no usable engine output (need rz-diff and/or ghidriff)', BLOCKED)
    return 'G+R' if 'rz-diff' in used else 'G'


def toolchain_of(side: C.ImageSide) -> str:
    return side.build.profile


def _output_from_doc(doc: RS.EngineOutputDoc) -> E.EngineOutput:
    preds = tuple(E.Prediction(p.old_rva, p.new_rva, p.changed, p.similarity_milli, p.old_name, p.new_name)
                  for p in doc.predictions)
    return E.EngineOutput(doc.engine, 'ok', version=doc.version, predictions=preds,
                          old_only=frozenset(doc.old_only_rvas), new_only=frozenset(doc.new_only_rvas),
                          implicit_unchanged=doc.implicit_unchanged, ignored_unaddressed=doc.ignored_unaddressed)


def load_outputs(folder: Path) -> dict[tuple[str, str, str], tuple[E.EngineOutput, str]]:
    """`tier-r-engine-output/1` files keyed by (older image sha, newer image sha, engine) with the SHA-256 of the
    canonical document (the engine-run digest). Symbols must be hidden; a duplicate key is an error."""
    found: dict[tuple[str, str, str], tuple[E.EngineOutput, str]] = {}
    for path in sorted(Path(folder).rglob('*.json')):
        raw = path.read_bytes()
        try:
            head = strict_json(raw)
        except ValueError:
            continue
        if not isinstance(head, dict) or head.get('contract') != RS.OUTPUT_CONTRACT:
            continue
        try:
            doc = RS.load_engine_output(raw)
        except (C.ContractError, ValueError) as exc:
            raise TrainError('PT-KA-EVAL', f'{path.name}: {str(exc)[:300]}') from None
        if doc.symbols != 'hidden':
            raise TrainError('PT-KA-EVAL', f'{path.name}: engine output with visible symbols cannot feed training')
        key = (doc.older_sha256, doc.newer_sha256, doc.engine)
        if key in found:
            raise TrainError('PT-KA-EVAL', f'{path.name}: second engine output for the same pair and engine')
        found[key] = (_output_from_doc(doc), hashlib.sha256(canonical_json(head)).hexdigest())
    return found


def _log_size(size: int | None) -> float | None:
    return math.log(size) if size else None


def candidate_features(profile: str, *, toolchain: str, ghid, rz, fo: C.FunctionLabel, fn: C.FunctionLabel,
                       rz_touch: tuple[set[int], set[int]] | None, old_rva: int, new_rva: int) -> list[float | None]:
    """Values in `feature_names(profile)` order; see the module docstring for the adapter limits."""
    v: dict[str, float | None] = {}
    ratio = None if ghid is None or ghid.similarity_milli is None else ghid.similarity_milli / 1000
    v['G.ratio'], v['G.ratio.missing'] = ratio, float(ratio is None)
    v['G.unchanged'] = float(ghid is not None and not ghid.changed)
    for name in (n for n in feature_names(profile) if n.startswith('G.mt.')):
        v[name] = 0.0
    v['G.n_match_types'] = 0.0
    v['R.similarity'] = None if rz is None or rz.similarity_milli is None else rz.similarity_milli / 1000
    sizes = {'older': fo.old_size or None, 'newer': fn.new_size or None}
    for side, size in sizes.items():
        v[f'S.log_size_{side}'] = _log_size(size)
        v[f'S.log_size_{side}.missing'] = float(not size)
        v[f'S.log_callees_{side}'] = 0.0
    both = sizes['older'] and sizes['newer']
    v['S.size_ratio'] = min(sizes.values()) / max(sizes.values()) if both else None
    v['S.size_ratio.missing'] = float(not both)
    v['S.thunk'] = float(fo.name.startswith('thunk_') or fn.name.startswith('thunk_'))
    cls = TOOLCHAIN_CLASS.get(toolchain, 'unknown')
    cats = {'P.symbols': 'none', 'P.arch': 'x64', 'P.toolchain': cls, 'P.binexport_producer': 'none'}
    for name in feature_names(profile):
        for cat, level in cats.items():
            if name.startswith(cat + '='):
                v[name] = float(name == f'{cat}={level}')
    both_proposed = ghid is not None and rz is not None
    v['X.agree_B'] = v['X.absent_B'] = 0.0
    v['X.agree_R'] = float(both_proposed)
    v['X.absent_R'] = float(rz_touch is not None and old_rva not in rz_touch[0] and new_rva not in rz_touch[1])
    v['X.log_alternatives'] = 0.0
    return [v[n] for n in feature_names(profile)]


def _touch(out: E.EngineOutput | None) -> tuple[set[int], set[int]] | None:
    if out is None:
        return None
    return {p.old_rva for p in out.predictions}, {p.new_rva for p in out.predictions}


def build_pair_rows(labels: C.KnownAnswerLabels, outputs: Mapping[str, tuple[E.EngineOutput, str]],
                    profile: str) -> PairRows:
    """One `tier-r-feature-rows/1` document. Natural rows are the candidates an engine proposed (a truth pair no engine
    proposed is a miss, not a row); `different` and `no-counterpart` candidates are y = 0; indeterminate and ambiguous
    candidates are excluded and counted."""
    used = {e: pair for e, pair in outputs.items() if e in FEATURE_ENGINES and pair[0].status == 'ok'}
    cands, skipped = A.candidates(labels, {e: pair[0] for e, pair in used.items()})
    by_old = {f.old_rva: f for f in labels.functions if f.old_rva is not None}
    by_new = {f.new_rva: f for f in labels.functions if f.new_rva is not None}
    pred = {e: {(p.old_rva, p.new_rva): p for p in pair[0].predictions} for e, pair in used.items()}
    touch = {e: _touch(pair[0]) for e, pair in used.items()}
    excluded: Counter = Counter(skipped)
    rows = []
    for c in cands:
        if not c.engines:
            continue
        if c.answer == 'indeterminate':
            excluded['indeterminate'] += 1
            continue
        fo, fn = by_old[c.old_rva], by_new[c.new_rva]
        key = (c.old_rva, c.new_rva)
        x = candidate_features(profile, toolchain=toolchain_of(labels.older), ghid=pred.get('ghidriff', {}).get(key),
                               rz=pred.get('rz-diff', {}).get(key), fo=fo, fn=fn,
                               rz_touch=touch.get('rz-diff'), old_rva=c.old_rva, new_rva=c.new_rva)
        names = sorted({f'src:{f.name}|{f.file or ""}' for f in (fo, fn)})
        rows.append({'id': f'{labels.pair_id}|{c.match_id}', 'y': 1 if c.answer == 'same' else 0,
                     'identities': names, 'x': x})
    runs = [{'engine': e, 'version': pair[0].version, 'output_sha256': pair[1]} for e, pair in sorted(used.items())]
    doc = {'contract': ROWS_CONTRACT, 'pair_id': labels.pair_id, 'stratum': labels.stratum, 'project': labels.project,
           'lineage': labels.lineage, 'family': labels.family, 'older': labels.older.model_dump(mode='json'),
           'newer': labels.newer.model_dump(mode='json'), 'label_digest': labels.digest_sha256, 'profile': profile,
           'columns': list(feature_names(profile)), 'engine_runs': runs, 'excluded': dict(sorted(excluded.items())),
           'rows': sorted(rows, key=lambda r: r['id'])}
    return load_pair_rows(canonical_json(_finish(doc)))


def build_from_labels(labels_dir: Path, outputs_dir: Path) -> list[PairRows]:
    docs = E.load_label_dir(labels_dir)
    if not docs:
        raise TrainError('PT-KA-BLOCKED', f'no known-answer-labels/1 documents in {labels_dir}', BLOCKED)
    found = load_outputs(outputs_dir)
    per_pair = {d.pair_id: {e: pair for (o, n, e), pair in found.items() if (o, n) == (d.older.sha256, d.newer.sha256)}
                for d in docs}
    profile = profile_for([e for pairs in per_pair.values() for e in pairs])
    return [build_pair_rows(d, per_pair[d.pair_id], profile) for d in sorted(docs, key=lambda d: d.pair_id)]


def read_rows_dir(folder: Path) -> list[PairRows]:
    out = []
    for path in sorted(Path(folder).glob('*.json')):
        raw = path.read_bytes()
        try:
            head = strict_json(raw)
        except ValueError:
            continue
        if isinstance(head, dict) and head.get('contract') == ROWS_CONTRACT:
            out.append(load_pair_rows(raw))
    if not out:
        raise TrainError('PT-KA-BLOCKED', f'no {ROWS_CONTRACT} documents in {folder}', BLOCKED)
    return out


def read_merge(merge_path: Path, aggregate_path: Path | None = None) -> tuple[list[PairRows], dict]:
    """`tier-r-merge/1` provenance (digest checked) -> its feature-row documents; with the merged aggregate report, its
    SHA must match the provenance and every shared pair must carry the same label digest."""
    try:
        prov = json.loads(Path(merge_path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise TrainError('PT-KA-EVAL', f'merge provenance unreadable: {exc}') from None
    if not isinstance(prov, dict) or prov.get('contract') != MERGE_CONTRACT:
        raise TrainError('PT-KA-EVAL', f'not a {MERGE_CONTRACT} document')
    if digest(prov, 'merge_sha256') != prov.get('merge_sha256'):
        raise TrainError('PT-KA-EVAL', 'merge provenance digest mismatch')
    docs = [load_pair_rows(item) for item in prov.get('features', ()) if isinstance(item, dict)
            and item.get('contract') == ROWS_CONTRACT]
    info = {'merge_sha256': prov['merge_sha256'], 'aggregate_report_sha256': prov.get('report_sha256'),
            'failing_cases': len(prov.get('failing_cases') or ())}
    if not docs:
        raise TrainError('PT-KA-BLOCKED', f'merge provenance carries no {ROWS_CONTRACT} documents (the shards did not '
                         'emit feature rows)', BLOCKED)
    if aggregate_path is not None:
        try:
            agg = json.loads(Path(aggregate_path).read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise TrainError('PT-KA-EVAL', f'aggregate report unreadable: {exc}') from None
        if digest(agg, 'report_sha256') != agg.get('report_sha256') or agg.get('report_sha256') != prov.get('report_sha256'):
            raise TrainError('PT-KA-EVAL', 'aggregate report does not match the merge provenance')
        ref = {r['pair_id']: r['labels_digest'] for r in agg.get('inputs', ())}
        bad = sorted(d.pair_id for d in docs if d.pair_id in ref and ref[d.pair_id] != d.label_digest)
        if bad:
            raise TrainError('PT-KA-EVAL', f'feature rows disagree with the aggregate label digests: {bad[:5]}')
        info['pairs_in_aggregate'] = len(ref)
    return docs, info


# ---- assembling the corpus --------------------------------------------------------------------------------------------

@dataclass
class Bundle:
    docs: list[PairRows]
    manifest: dict
    audit: dict
    evidence_ids: set[str]
    controls: Counter = field(default_factory=Counter)


def assemble_manifest(docs: Sequence[PairRows], tool_git: str = 'unknown') -> dict:
    """The same `calibration-corpus/1` document `tier_r.manifest.build_manifest` makes from the label documents."""
    stubs = [SimpleNamespace(pair_id=d.pair_id, project=d.project, lineage=d.lineage, family=d.family,
                             stratum=d.stratum, older=d.older, newer=d.newer) for d in docs]
    try:
        return M.build_manifest(stubs, tool_git=tool_git)
    except (M.ManifestError, CorpusContractError, ValueError) as exc:
        raise TrainError('PT-KA-EVAL', f'corpus manifest: {str(exc)[:300]}') from None


def assemble(docs: Sequence[PairRows], tool_git: str = 'unknown') -> Bundle:
    docs = sorted(docs, key=lambda d: d.pair_id)
    if len({d.pair_id for d in docs}) != len(docs):
        raise TrainError('PT-KA-EVAL', 'duplicate pair ids among the feature-row documents')
    if len({(d.profile, d.columns) for d in docs}) != 1:
        raise TrainError('PT-KA-EVAL', 'feature-row documents mix profiles or columns')
    manifest = assemble_manifest(docs, tool_git)
    audit = audit_manifest(manifest)
    if audit['violations']:
        raise TrainError('PT-KA-LEAK', 'split audit failed before any fit: ' + '; '.join(audit['violations'][:5]),
                         FINDINGS)
    evidence = {p['id'] for p in evidence_pairs(manifest)}
    controls = Counter(d.stratum for d in docs if d.pair_id not in evidence)
    return Bundle(list(docs), manifest, audit, evidence, controls)


def build_rows(bundle: Bundle, cfg: TrainConfig) -> tuple[list[Row], dict[str, SH.RowInfo], list[str], list[str], dict]:
    """(rows, row info, kept column names, kinds, stats). Rows are imputed with run-wide medians and constant columns
    are dropped (both label-free)."""
    docs = [d for d in bundle.docs if d.pair_id in bundle.evidence_ids]
    cols = docs[0].columns if docs else feature_names('G')
    entries = [(d, r) for d in docs for r in d.rows]
    cand = [CandidateIdentity(r.id, d.lineage, r.identities) for d, r in entries]
    grouping = identity_groups(cand, hub_max_lineages=cfg.hub_max_lineages) if cand else None
    dicts = [dict(zip(cols, r.x, strict=True)) for _, r in entries]
    med = medians(dicts, cols)
    full = [impute(d, cols, med) for d in dicts]
    keep = [j for j in range(len(cols)) if len({v[j] for v in full}) > 1]
    names = [cols[j] for j in keep]
    kinds = [SPEC_BY_NAME[n].kind for n in names]
    rows, info = [], {}
    for (d, r), vec in zip(entries, full, strict=True):
        rows.append(Row(r.id, grouping.group_of[r.id], tuple(vec[j] for j in keep), r.y, 1.0, 'natural',
                        d.profile, d.stratum))
        info[r.id] = SH.RowInfo(toolchain_of(d.older), d.family, d.lineage)
    excluded: Counter = Counter()
    for d in docs:
        excluded.update(d.excluded)
    stats = {'excluded': dict(sorted(excluded.items())), 'pruned_constant_columns': len(cols) - len(keep),
             'seen_body': 0 if grouping is None else len(grouping.seen_body),
             'hub_identities': 0 if grouping is None else len(grouping.hub_identities),
             'merged_lineages': 0 if grouping is None else grouping.merged_lineages,
             'largest_group_share': 0.0 if grouping is None else grouping.largest_share,
             'pairs_without_rows': sorted(d.pair_id for d in docs if not d.rows)}
    return rows, info, names, kinds, stats


# ---- guards, gates, domain --------------------------------------------------------------------------------------------

def sample_guard(rows: Sequence[Row], cfg: TrainConfig) -> list[str]:
    """Reasons the run cannot fit (empty when it can). Group floor: every outer and inner fold needs whole groups."""
    pos = sum(1 for r in rows if r.y)
    out = []
    if len(rows) < FIT_MIN['rows']:
        out.append(f'natural rows {len(rows)} < {FIT_MIN["rows"]}')
    if pos < FIT_MIN['positives']:
        out.append(f'positive rows {pos} < {FIT_MIN["positives"]}')
    if len(rows) - pos < FIT_MIN['negatives']:
        out.append(f'negative rows {len(rows) - pos} < {FIT_MIN["negatives"]}')
    groups = len({r.group for r in rows})
    if groups < cfg.k_outer + cfg.k_inner:
        out.append(f'CV groups {groups} < {cfg.k_outer + cfg.k_inner} (k_outer + k_inner)')
    return out


G023_REASON = {'G0': 'Tier R carries no Tier W families, kinds, symbol audit or second annotator',
               'G2': 'Tier R is never used for G2', 'G3': 'Tier R is never used for G3'}


def tier_r_gates(evaluation: Mapping | None, reasons: Sequence[str] = ()) -> dict:
    """G1 from the pipeline numbers; G0, G2, G3 insufficient-data by construction (empty dataset and profile)."""
    gates = evaluate_gates({}, {}, pipeline=evaluation)
    for gate, reason in G023_REASON.items():
        if gates[gate]['status'] != 'insufficient-data':          # cannot happen with empty inputs; fail closed anyway
            raise TrainError('PT-KA-EVAL', f'{gate} must stay insufficient-data for Tier R alone')
        gates[gate] = {'status': 'insufficient-data', 'reasons': (reason,)}
    if evaluation is None:
        gates['G1'] = {'status': 'insufficient-data', 'reasons': tuple(reasons) or ('no Tier R pipeline results',)}
    return gates


def scope_ids(n_lineages: int, toolchains: Sequence[str]) -> list[str]:
    ids = ['no-windows-system-binaries', 'open-source-c-only', 'test-compilers-only', 'x64-only',
           'stripped-images-only', 'symbols-hidden-only', 'engine-versions-pinned', 'planted-changes-synthetic']
    if n_lineages < 40:
        ids.append('few-lineages')
    if 'msvc' in toolchains:
        ids.remove('test-compilers-only')
    return [i for i in ids if i in SCOPE_TEXT]


# ---- the run ----------------------------------------------------------------------------------------------------------

@dataclass
class TrainResult:
    report: dict
    artifact: dict | None
    shift: dict
    train_key: str


def run_training(docs: Sequence[PairRows], cfg: TrainConfig | None = None, *, prereg_sha: str | None = None,
                 tool_git: str = 'unknown', origin: str = 'rows', extra: Mapping | None = None) -> TrainResult:
    cfg = cfg or TrainConfig()
    bundle = assemble(docs, tool_git)
    manifest_sha = canonical_manifest_sha256(bundle.manifest)
    label_set_sha = hashlib.sha256(canonical_json(sorted(
        (d.pair_id, d.label_digest) for d in bundle.docs))).hexdigest()
    runs = sorted({r.output_sha256 for d in bundle.docs for r in d.engine_runs})
    key = train_key(manifest_sha=manifest_sha, label_set_sha=label_set_sha, engine_run_digests=runs,
                    config_digest=cfg.digest(), prereg_sha=prereg_sha)
    profile = bundle.docs[0].profile
    rows, info, names, kinds, stats = build_rows(bundle, cfg)
    lineages = sorted({d.lineage for d in bundle.docs if d.pair_id in bundle.evidence_ids})
    toolchains = sorted({toolchain_of(d.older) for d in bundle.docs if d.pair_id in bundle.evidence_ids})
    versions: dict[str, set[str]] = {}
    for d in bundle.docs:
        for r in d.engine_runs:
            versions.setdefault(r.engine, set()).add(r.version or 'unknown')
    pos = sum(1 for r in rows if r.y)
    dataset = {'tier': 'R', 'corpus_id': bundle.manifest['corpus_id'], 'origin': origin, 'train_key': key,
               'feature_schema': FEATURE_SCHEMA, 'profile': profile, 'config': cfg.as_dict(),
               'config_digest': cfg.digest(), 'preregistered': prereg_sha is not None,
               'n_pairs': len(bundle.docs), 'n_pairs_evidence': len(bundle.evidence_ids),
               'controls_excluded': dict(sorted(bundle.controls.items())), 'n_lineages': len(lineages),
               'n_families': len({info[r.id].family for r in rows}), 'toolchains': toolchains,
               'n_natural': len(rows), 'n_positive': pos, 'n_negative': len(rows) - pos,
               'engines': {e: sorted(v) for e, v in sorted(versions.items())}, 'engine_runs': len(runs),
               'roles': bundle.audit.get('roles', {}), 'audit_warnings': bundle.audit['warnings'],
               'columns_used': len(names), 'claim_scope': 'pipeline-check-on-test-builds', **stats, **dict(extra or {})}
    reasons = sample_guard(rows, cfg)
    evaluation = None
    artifact = None
    ladder = SH.ladder_not_run('no fit was run: ' + '; '.join(reasons) if reasons else 'no fit was run')
    if not reasons:
        try:
            validate_rows(rows)
            result = _fit(rows, names, kinds, profile, cfg, key, versions, toolchains, lineages, manifest_sha,
                          label_set_sha, prereg_sha, tool_git)
        except (CVError, RowError) as exc:
            reasons = [f'fit not possible: {str(exc)[:300]}']
        else:
            evaluation, artifact = result.evaluation, result.artifact
            base = {'coverage': (evaluation.get('coverage') or {}).get('point')}
            prec = evaluation.get('precision') or {}
            base.update(precision=prec.get('point'), precision_lo=prec.get('lo'), precision_hi=prec.get('hi'))
            tau = (evaluation.get('tau_selection') or {}).get('tau')
            ladder = SH.run_ladder(rows, info, kinds=kinds, cv=_cv(cfg, kinds), tau=None if tau is None else tau['tau'],
                                   baseline=base, cfg=SH.LadderConfig(cfg.rung_b_count, cfg.rung_null_sims))
    gates = tier_r_gates(evaluation, reasons)
    per = dict(evaluation) if evaluation is not None else {
        'status': 'insufficient-data', 'reasons': list(reasons), 'n_natural': len(rows),
        'n_groups': len({r.group for r in rows})}
    per['gates'] = gates
    per['shift'] = ladder
    report = make_tier_r_report(
        prereg_sha=prereg_sha, corpus_manifest_sha=manifest_sha, label_set_sha=label_set_sha, tool_git=tool_git,
        dataset=dataset, per_profile={profile: per},
        known_limits=[f'insufficient: {r}' for r in reasons] +
        ([] if prereg_sha else ['preregistration not locked: the run key uses the placeholder']) +
        (['smoke configuration: reduced bootstrap and CV effort, not the preregistered values'] if cfg.smoke else []),
        amendments=[])
    return TrainResult(report, artifact, ladder, key)


def _cv(cfg: TrainConfig, kinds: Sequence[str]) -> CVConfig:
    return CVConfig(k_outer=cfg.k_outer, k_inner=cfg.k_inner, c_grid=cfg.c_grid, seed=cfg.seed,
                    scale=tuple(k == 'num' for k in kinds))


def _fit(rows, names, kinds, profile, cfg, key, versions, toolchains, lineages, manifest_sha, label_set_sha, prereg_sha,
         tool_git):
    pos_w = sum(r.w for r in rows if r.y)
    domain = {'engines': {e: sorted(v) for e, v in sorted(versions.items())}, 'toolchains': list(toolchains),
              'arch': ['x64'], 'corpus_id': 'known-answer-tier-r', 'n_pairs': 0, 'n_lineages': len(lineages),
              'prevalence': pos_w / sum(r.w for r in rows),
              'known_blind_spots': [SCOPE_TEXT['no-windows-system-binaries'], SCOPE_TEXT['planted-changes-synthetic']],
              'evidence_tiers': ['tier-r'], 'windows_system_binaries': 'none',
              'scope_ids': scope_ids(len(lineages), toolchains)}
    created = dt.date(1970, 1, 2)                       # fixed: the run is a pure function of its inputs
    result = run_pipeline(rows, names=names, kinds=kinds, profile=profile, cfg=_cv(cfg, kinds), b_count=cfg.b_count,
                          created=created, model_id=f'tier-r-{key[:12]}', domain=domain, synthetic=True,
                          dataset={'tier': 'R', 'n_rows': len(rows)}, with_m1=cfg.with_m1, null_sims=cfg.null_sims,
                          ablate=cfg.ablate)
    # The artifact predates the final report, so it cites none: it stays experimental and is never promoted.
    result.artifact['evidence'].update(preregistration_sha256=prereg_sha, corpus_manifest_sha256=manifest_sha,
                                       label_set_sha256=label_set_sha, tool_git=tool_git, gates={},
                                       report_sha256=None)
    result.artifact['digest_sha256'] = artifact_digest(result.artifact)
    parse_artifact(canonical_json(result.artifact), today=created)
    result.evaluation.pop('gates', None)
    return result


# ---- CLI --------------------------------------------------------------------------------------------------------------

def _prereg_sha(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as exc:
        raise TrainError('PT-KA-EVAL', f'preregistration unreadable: {exc}') from None


def _inputs(args) -> tuple[list[PairRows], str, dict]:
    modes = [bool(args.labels), bool(args.rows), bool(args.merge)]
    if sum(modes) != 1:
        raise TrainError('PT-KA-EVAL', 'give exactly one of --labels (with --outputs), --rows or --merge')
    if args.labels:
        if not args.outputs:
            raise TrainError('PT-KA-EVAL', '--labels needs --outputs (a folder of tier-r-engine-output/1 files)')
        return build_from_labels(Path(args.labels), Path(args.outputs)), 'labels+outputs', {}
    if args.rows:
        return read_rows_dir(Path(args.rows)), 'rows', {}
    docs, info = read_merge(Path(args.merge), Path(args.aggregate) if args.aggregate else None)
    return docs, 'merge', {'merge': info}


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _run(args, only_shift: bool = False) -> tuple[int, dict]:
    docs, origin, extra = _inputs(args)
    cfg = TrainConfig.smoke_config() if args.smoke else TrainConfig()
    result = run_training(docs, cfg, prereg_sha=_prereg_sha(args.prereg), tool_git=args.tool_git, origin=origin,
                          extra=extra)
    out = Path(args.out)
    summary = {'train_key': result.train_key, 'report_sha256': result.report['report_sha256'],
               'gates': {g: v['status'] for g, v in sorted(result.report['gates'].items())}}
    if only_shift:
        _write(out / 'shift.json', canonical_json(result.shift) + b'\n')
        summary.update(command='shift', status='ok', shift=(out / 'shift.json').as_posix(),
                       rungs=[{'rung': r['rung'], 'held_out': r['held_out'], 'status': r['status']}
                              for r in result.shift['rungs']])
        return OK, summary
    _write(out / 'report.json', canonical_json(result.report) + b'\n')
    _write(out / 'report.md', render_markdown(result.report).encode('utf-8'))
    summary.update(command='run', status='ok', report=(out / 'report.json').as_posix())
    if args.artifact and result.artifact is not None:
        _write(out / 'artifact.dev-only.json', canonical_json(result.artifact) + b'\n')
        summary['artifact'] = (out / 'artifact.dev-only.json').as_posix()
    elif args.artifact:
        summary['artifact'] = None
    return OK, summary


def _report(args) -> tuple[int, dict]:
    try:
        report = json.loads(Path(args.report).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise TrainError('PT-KA-EVAL', f'report unreadable: {exc}') from None
    try:
        verify_tier_r_report(report)
    except ValueError as exc:
        raise TrainError('PT-KA-EVAL', str(exc)[:400]) from None
    text = render_markdown(report)
    if args.out:
        _write(Path(args.out), text.encode('utf-8'))
    else:
        sys.stdout.write(text)
    return OK, {'command': 'report', 'status': 'ok', 'claim': TIER_R_CLAIM, 'report_sha256': report['report_sha256']}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='python -m tools.calibration.train',
                                     description='Tier R label training (dev-only). Exit: 0 ok, 1 findings (split '
                                                 'leakage), 2 usage/contract error, 3 BLOCKED.')
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name, help_ in (('run', 'audit, fit, evaluate and write calibration-report/1'),
                        ('shift', 'run the pipeline and write only the shift ladder (shift.json)')):
        p = sub.add_parser(name, help=help_)
        p.add_argument('--labels', help='folder of known-answer-labels/1 documents (needs --outputs)')
        p.add_argument('--outputs', help='folder of tier-r-engine-output/1 files')
        p.add_argument('--rows', help='folder of tier-r-feature-rows/1 documents')
        p.add_argument('--merge', help='tier-r-merge/1 provenance file written by shard.py merge')
        p.add_argument('--aggregate', help='merged tier-r-report/1 aggregate to cross-check with --merge')
        p.add_argument('--prereg', help='locked preregistration file; its SHA-256 enters the train key')
        p.add_argument('--out', required=True, help='output folder')
        p.add_argument('--tool-git', default='unknown')
        p.add_argument('--smoke', action='store_true', help='reduced effort (recorded in the report)')
        p.add_argument('--artifact', action='store_true',
                       help='also write artifact.dev-only.json (experimental, display none, never bundled)')
    p = sub.add_parser('report', help='verify a Tier R report and render report.md')
    p.add_argument('report')
    p.add_argument('--out')
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        if args.cmd == 'report':
            code, doc = _report(args)
        else:
            code, doc = _run(args, only_shift=args.cmd == 'shift')
    except TrainError as exc:
        print(json.dumps({'command': args.cmd, 'status': 'blocked' if exc.exit_code == BLOCKED else 'error',
                          'code': exc.code, 'error': str(exc)[:600]}, indent=1, sort_keys=True), file=sys.stderr)
        return exc.exit_code
    print(json.dumps(doc, indent=1, sort_keys=True), file=sys.stderr if args.cmd == 'report' and not args.out else sys.stdout)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
