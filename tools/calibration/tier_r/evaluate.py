"""SPEC-32 s10 evaluator: score engines against `known-answer-labels/1` documents and emit `tier-r-report/1`.

Engines: rz-diff through the production secondary adapter (`registry.build_registry` + `scheduler.run_engines`),
BinDiff from a user-placed `.BinDiff` file through `secondary.bindiff.import_bindiff`, Ghidriff from a user-placed raw
JSON through `normalization.normalize_ghidriff`. A missing tool or missing import is `blocked` with its reason, never a
silent skip and never a zero score.

Scoring of one pair (all counts are integers; ratios are computed only from summed counts):
- truth pairs T: records with identity `same` and a label other than `ambiguous` (`truth_same` = |T|).
- a predicted pair (old, new) touching at least one non-ambiguous labelled record is scored; it is correct iff it is in T.
  A prediction touching only ambiguous or unlabelled functions is ignored (`ignored_predictions`).
- identity precision = tp / (tp + fp), recall = tp / |T|.
- on correct pairs: engine "changed" vs truth `changed` gives changed-set precision/recall; the false-positive rate is the
  share of correctly matched `unchanged` + `cosmetic` functions the engine flags (cosmetic reported apart).
- Ghidriff lists only added/deleted/modified functions: with `implicit_unchanged` a truth pair mentioned by none of those
  lists counts as matched and unchanged (identity numbers are then an upper bound, stated in the report notes).
Mocked or canned engine output in tests is synthetic and never live evidence (AGENTS.md).
"""
from __future__ import annotations

import math
import os
import re
import shutil
import threading
import typing
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from patchtrace.jobs import run_process
from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError, SecondaryMatchSet
from patchtrace.secondary.engine_env import engine_env
from patchtrace.secondary.registry import build_registry
from patchtrace.secondary.scheduler import ProjectRef, run_engines

from ..common import digest, r12, strict_json
from ..evalcore import protocols as EP
from ..evalcore import report as ER
from . import contracts as C
from . import report_schemas as RS

ENGINES = ('rz-diff', 'bindiff', 'ghidriff')   # the engines this module can drive or import
ENGINE_ORDER = typing.get_args(C.Engine)         # report order of every engine, incl. unified and attention
COUNT_KEYS = ('pairs', 'truth_same', 'identity_tp', 'identity_fp', 'identity_fn', 'changed_truth', 'changed_tp',
              'changed_fp', 'changed_fn', 'matched_negatives', 'cosmetic_matched', 'cosmetic_flagged',
              'ignored_predictions', 'ambiguous_records')
MAX_WRONG = 1000
MAX_IMPORT_BYTES = 256 * 1024 * 1024
IMPLICIT_NOTE = ('ghidriff lists only added/deleted/modified functions: truth pairs it does not mention are counted as '
                 'matched and unchanged, so its identity numbers are an upper bound')


@dataclass(frozen=True)
class Prediction:
    old_rva: int
    new_rva: int
    changed: bool
    similarity_milli: int | None = None
    old_name: str | None = None
    new_name: str | None = None
    order_key: tuple | None = None               # lead-list sort key; default (similarity, name), smaller first


@dataclass(frozen=True)
class EngineOutput:
    engine: str
    status: str                                  # ok | blocked | failed
    version: str | None = None
    reason: str | None = None
    predictions: tuple[Prediction, ...] = ()
    old_only: frozenset[int] = frozenset()       # old functions the engine reports without a counterpart
    new_only: frozenset[int] = frozenset()
    implicit_unchanged: bool = False
    ignored_unaddressed: int = 0


def blocked(engine: str, reason: str) -> EngineOutput:
    return EngineOutput(engine, 'blocked', reason=_clean(reason))


def failed(engine: str, reason: str) -> EngineOutput:
    return EngineOutput(engine, 'failed', reason=_clean(reason))


def _clean(text: str, limit: int = 400) -> str:
    return re.sub(r'[\x00-\x1f\x7f]+', ' ', str(text)).strip()[:limit]


class Provider(Protocol):
    engine: str

    def __call__(self, labels: C.KnownAnswerLabels, symbols: str) -> EngineOutput: ...


class StaticProvider:
    """Pre-computed output per pair id (tests and replays); a pair without an entry is blocked."""

    def __init__(self, engine: str, outputs: Mapping[str, EngineOutput]):
        self.engine, self.outputs = engine, dict(outputs)

    def __call__(self, labels, symbols):
        return self.outputs.get(labels.pair_id) or blocked(self.engine, f'no recorded output for {labels.pair_id}')


# ---- normalising engine results to RVAs --------------------------------------------------------------------------------

def to_rva(address: int, image_base: int) -> int:
    """Engines report virtual addresses (BinExport, rizin, Ghidra) or already-relative ones: subtract the base once."""
    return address - image_base if address >= image_base else address


def from_match_set(engine: str, match_set: SecondaryMatchSet, image_base: int) -> EngineOutput:
    base = 0 if match_set.image_base_subtracted == 'yes' else image_base
    predictions, old_only, new_only = [], set(), set()
    for m in match_set.matches:
        if m.older_address is None or m.newer_address is None:
            (old_only if m.newer_address is None else new_only).add(
                to_rva(m.older_address if m.newer_address is None else m.newer_address, base))
            continue
        changed = m.similarity_milli < 1000
        if engine == 'rz-diff':
            changed = changed or m.match_type != 'COMPLETE'
        predictions.append(Prediction(to_rva(m.older_address, base), to_rva(m.newer_address, base), changed,
                                      m.similarity_milli, m.older_name, m.newer_name))
    return EngineOutput(engine, 'ok', version=match_set.engine_version, predictions=tuple(predictions),
                        old_only=frozenset(old_only), new_only=frozenset(new_only))


_HEX = re.compile(r'(?:0x)?([0-9a-fA-F]{1,16})$')


def _ghidra_address(text: object) -> int | None:
    if not isinstance(text, str):
        return None
    found = _HEX.search(text.strip().rsplit(':', 1)[-1])
    return int(found.group(1), 16) if found else None


def from_ghidriff(raw: dict, labels: C.KnownAnswerLabels, symbols: str) -> EngineOutput:
    """Raw Ghidriff PDiff JSON -> output, through the production `verify_diff_identity` + `normalize_ghidriff`."""
    from patchtrace.models import AnalysisRun, Artifact, ComparisonProject
    from patchtrace.normalization import normalize_ghidriff, verify_diff_identity
    older_sha, newer_sha = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
    run = AnalysisRun(status='completed')
    project = ComparisonProject(
        name=labels.pair_id, runs=[run],
        artifacts=[Artifact(side='older', name=labels.older.file_name, sha256=older_sha, size=max(labels.older.size, 1),
                            relative_path='older/image'),
                   Artifact(side='newer', name=labels.newer.file_name, sha256=newer_sha, size=max(labels.newer.size, 1),
                            relative_path='newer/image')])
    verify_diff_identity(raw, project)
    base = labels.older.image_base
    predictions, old_only, new_only, unaddressed = [], set(), set(), 0
    for match in normalize_ghidriff(raw, project, run.id):
        old = match.older[0] if match.older else None
        new = match.newer[0] if match.newer else None
        old_addr = _ghidra_address(old.address) if old else None
        new_addr = _ghidra_address(new.address) if new else None
        if match.category == 'removed':
            if old_addr is None:
                unaddressed += 1
            else:
                old_only.add(to_rva(old_addr, base))
        elif match.category == 'added':
            if new_addr is None:
                unaddressed += 1
            else:
                new_only.add(to_rva(new_addr, base))
        elif old_addr is None or new_addr is None:
            unaddressed += 1
        else:
            ratio = (old.metadata or {}).get('upstream_similarity')
            milli = round(ratio * 1000) if isinstance(ratio, int | float) and not isinstance(ratio, bool) else None
            predictions.append(Prediction(to_rva(old_addr, base), to_rva(new_addr, base), True, milli,
                                          old.metadata.get('upstream_name'), new.metadata.get('upstream_name')))
    return EngineOutput('ghidriff', 'ok', version=raw.get('program_options', {}).get('version')
                        if isinstance(raw.get('program_options'), dict)
                        and isinstance(raw['program_options'].get('version'), str) else None,
                        predictions=tuple(predictions), old_only=frozenset(old_only), new_only=frozenset(new_only),
                        implicit_unchanged=True, ignored_unaddressed=unaddressed)


def to_engine_pairs(out: EngineOutput, symbols: str) -> EP.EnginePairs:
    """The scorer-neutral view of one engine run. Flagged rows are ordered by ascending native similarity, then
    name (an unknown similarity sorts last), unless the output carries its own `order_key` (attention, unified)."""
    rows, seen = [], set()
    for p in out.predictions:
        if (p.old_rva, p.new_rva) in seen:
            continue
        seen.add((p.old_rva, p.new_rva))
        key = None
        if p.changed:
            sim = math.inf if p.similarity_milli is None else p.similarity_milli
            key = p.order_key or (sim, p.old_name or p.new_name or '')
        rows.append(EP.EnginePair(p.old_rva, p.new_rva, p.changed,
                                  None if p.similarity_milli is None else p.similarity_milli / 1000, key))
    rows += [EP.EnginePair(rva, None, None, identity='unpaired') for rva in sorted(out.old_only)]
    rows += [EP.EnginePair(None, rva, None, identity='unpaired') for rva in sorted(out.new_only)]
    return EP.EnginePairs(out.engine, out.version, symbols, tuple(rows), out.implicit_unchanged)


def engine_output_doc(out: EngineOutput, labels: C.KnownAnswerLabels, symbols: str) -> dict:
    older, newer = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
    return {'contract': RS.OUTPUT_CONTRACT, 'engine': out.engine, 'version': out.version, 'symbols': symbols,
            'older_sha256': older, 'newer_sha256': newer, 'implicit_unchanged': out.implicit_unchanged,
            'predictions': [{'old_rva': p.old_rva, 'new_rva': p.new_rva, 'changed': p.changed,
                             'similarity_milli': p.similarity_milli, 'old_name': p.old_name, 'new_name': p.new_name}
                            for p in sorted(out.predictions, key=lambda p: (p.old_rva, p.new_rva))],
            'old_only_rvas': sorted(out.old_only), 'new_only_rvas': sorted(out.new_only),
            'ignored_unaddressed': out.ignored_unaddressed}


# ---- scoring ----------------------------------------------------------------------------------------------------------

def _ambiguous(f: C.FunctionLabel) -> bool:
    return f.label == 'ambiguous' or f.identity == 'ambiguous'


def score_pair(labels: C.KnownAnswerLabels, out: EngineOutput) -> tuple[dict[str, int], list[dict]]:
    """(integer counts, wrong-match rows) of one engine on one pair. Pure and order independent."""
    by_old = {f.old_rva: f for f in labels.functions if f.old_rva is not None}
    by_new = {f.new_rva: f for f in labels.functions if f.new_rva is not None}
    truth = {(f.old_rva, f.new_rva): f for f in labels.functions if f.identity == 'same' and not _ambiguous(f)}
    n = dict.fromkeys(COUNT_KEYS, 0)
    n['pairs'], n['truth_same'] = 1, len(truth)
    n['ambiguous_records'] = sum(1 for f in labels.functions if _ambiguous(f))
    wrong: list[dict] = []

    def credit(record: C.FunctionLabel, flagged: bool) -> None:
        n['identity_tp'] += 1
        if record.label == 'changed':
            n['changed_truth'] += 1
            n['changed_tp' if flagged else 'changed_fn'] += 1
        else:  # unchanged or cosmetic
            n['matched_negatives'] += 1
            n['changed_fp'] += flagged
            if record.label == 'cosmetic':
                n['cosmetic_matched'] += 1
                n['cosmetic_flagged'] += flagged

    unique = {}
    for p in out.predictions:
        unique.setdefault((p.old_rva, p.new_rva), p)
    mentioned_old = {p.old_rva for p in unique.values()} | set(out.old_only)
    mentioned_new = {p.new_rva for p in unique.values()} | set(out.new_only)
    for key in sorted(unique):
        p = unique[key]
        ro, rn = by_old.get(p.old_rva), by_new.get(p.new_rva)
        touched = [r for r in (ro, rn) if r is not None and not _ambiguous(r)]
        if not touched:
            n['ignored_predictions'] += 1
            continue
        if key in truth:
            credit(truth[key], p.changed)
            continue
        n['identity_fp'] += 1
        same_o = ro if ro is not None and ro.identity == 'same' and not _ambiguous(ro) else None
        same_n = rn if rn is not None and rn.identity == 'same' and not _ambiguous(rn) else None
        kind = ('wrong-counterpart' if same_o or same_n else
                'paired-no-counterpart' if any(r.identity == 'no-counterpart' for r in touched) else 'paired-unlabelled')
        wrong.append({'pair_id': labels.pair_id, 'engine': out.engine, 'kind': kind, 'old_rva': p.old_rva,
                      'new_rva': p.new_rva, 'old_name': (ro.name if ro else p.old_name),
                      'new_name': (rn.name if rn else p.new_name),
                      'expected_new_rva': same_o.new_rva if same_o else None,
                      'expected_old_rva': same_n.old_rva if same_n else None,
                      'similarity_milli': p.similarity_milli})
    if out.implicit_unchanged:
        for key, record in truth.items():
            if key not in unique and key[0] not in mentioned_old and key[1] not in mentioned_new:
                credit(record, False)
    n['identity_fn'] = n['truth_same'] - n['identity_tp']
    return n, wrong


def _ratio(num: int, den: int) -> float | None:
    return r12(num / den) if den else None


def metrics_from_counts(n: Mapping[str, int]) -> dict:
    out = {k: int(n[k]) for k in COUNT_KEYS}
    out.update(identity_precision=_ratio(n['identity_tp'], n['identity_tp'] + n['identity_fp']),
               identity_recall=_ratio(n['identity_tp'], n['truth_same']),
               changed_precision=_ratio(n['changed_tp'], n['changed_tp'] + n['changed_fp']),
               changed_recall=_ratio(n['changed_tp'], n['changed_truth']),
               fp_rate=_ratio(n['changed_fp'], n['matched_negatives']))
    return out


def sum_counts(rows: Iterable[Mapping[str, int]]) -> dict[str, int]:
    total = dict.fromkeys(COUNT_KEYS, 0)
    for row in rows:
        for k in COUNT_KEYS:
            total[k] += row[k]
    return total


# ---- providers ------------------------------------------------------------------------------------------------------

def image_path(store: Path, side: C.ImageSide, symbols: str) -> tuple[Path, str]:
    sha = side.sha256 if symbols == 'hidden' else side.debug_sha256
    return Path(store) / 'images' / sha / side.file_name, sha


class RzDiffProvider:
    """rz-diff through `build_registry` + `run_engines` (the production adapter, pinned-rizin argv, bounded output)."""
    engine = 'rz-diff'

    def __init__(self, store: Path, *, executable: str | None = None, environ: Mapping[str, str] | None = None,
                 runner: Callable = run_process, deadline: float = 1800.0, run: Callable = run_engines):
        self.store, self.executable, self.runner, self.deadline, self.run = Path(store), executable, runner, deadline, run
        self.environ = os.environ if environ is None else environ

    def __call__(self, labels, symbols):
        exe = self.executable or shutil.which('rz-diff', path=self.environ.get('PATH'))
        if not exe:
            return blocked(self.engine, 'rz-diff executable not found (install the pinned rizin or pass --rz-diff)')
        (older, osha), (newer, nsha) = (image_path(self.store, s, symbols) for s in (labels.older, labels.newer))
        missing = [p.name for p in (older, newer) if not p.is_file()]
        if missing:
            return blocked(self.engine, f'engine image(s) not in the store: {", ".join(missing)}')
        outcomes = self.run(ProjectRef(older, newer, osha, nsha), ['rz-diff'], cancel=threading.Event(),
                            env=engine_env(self.environ, 'rz-diff'), registry=build_registry(rz_diff=exe),
                            runner=self.runner, per_engine_timeout={'rz-diff': self.deadline})
        outcome = outcomes[0]
        if outcome.match_set is not None:
            return from_match_set(self.engine, outcome.match_set, labels.older.image_base)
        message = outcome.error.message if outcome.error else outcome.run.status
        if outcome.run.status == 'unsupported':
            return blocked(self.engine, message)
        return failed(self.engine, f'{outcome.run.status}: {message}')


class BindiffImportProvider:
    """`<imports>/<pair_id>.BinDiff` placed by the user, read by the production hardened importer."""
    engine = 'bindiff'

    def __init__(self, imports: Path | None):
        self.imports = None if imports is None else Path(imports)

    def __call__(self, labels, symbols):
        path = None if self.imports is None else self.imports / f'{labels.pair_id}.BinDiff'
        if path is None or not path.is_file():
            return blocked(self.engine, 'no BinDiff installation was driven and no imported '
                           f'{labels.pair_id}.BinDiff exists in the imports folder')
        osha, nsha = (s.sha256 if symbols == 'hidden' else s.debug_sha256 for s in (labels.older, labels.newer))
        try:
            match_set = import_bindiff(path, osha, nsha)
        except SecondaryError as exc:
            return failed(self.engine, exc.message)
        return from_match_set(self.engine, match_set, labels.older.image_base)


class GhidriffImportProvider:
    """`<imports>/<pair_id>.ghidriff.json` (raw PDiff JSON) placed by the user, read by `normalize_ghidriff`."""
    engine = 'ghidriff'

    def __init__(self, imports: Path | None):
        self.imports = None if imports is None else Path(imports)

    def __call__(self, labels, symbols):
        path = None if self.imports is None else self.imports / f'{labels.pair_id}.ghidriff.json'
        if path is None or not path.is_file():
            return blocked(self.engine, f'no imported {labels.pair_id}.ghidriff.json exists in the imports folder '
                           '(Ghidra/Java/Ghidriff are not run by this tool)')
        try:
            if path.stat().st_size > MAX_IMPORT_BYTES:
                return failed(self.engine, 'ghidriff JSON exceeds 256 MiB')
            raw = strict_json(path.read_bytes())
            return from_ghidriff(raw, labels, symbols)
        except (OSError, ValueError, RecursionError) as exc:
            return failed(self.engine, f'ghidriff import rejected: {exc}')


def default_providers(store: Path, imports: Path | None = None, *, rz_diff: str | None = None,
                      engines: Sequence[str] = ENGINES) -> list[Provider]:
    imports = Path(imports) if imports is not None else Path(store) / 'imports'
    made = {'rz-diff': lambda: RzDiffProvider(store, executable=rz_diff),
            'bindiff': lambda: BindiffImportProvider(imports),
            'ghidriff': lambda: GhidriffImportProvider(imports)}
    return [made[e]() for e in ENGINES if e in engines]


# ---- the report -------------------------------------------------------------------------------------------------------

@dataclass
class _EngineAcc:
    results: list = field(default_factory=list)   # (pair_id, stratum, status, reason, counts|None, sha|None, version)


COMPLETION_WARNING = 0.9


def evaluate(labels_docs: Sequence[C.KnownAnswerLabels], providers: Sequence[Provider], **kwargs) -> dict:
    """Run every provider on every pair and return the finalized `tier-r-report/1` document (no timestamps)."""
    return evaluate_full(labels_docs, providers, **kwargs)[0]


def evaluate_full(labels_docs: Sequence[C.KnownAnswerLabels], providers: Sequence[Provider], *,
                  symbols: str = 'hidden', notes: Sequence[str] = (), max_wrong: int = MAX_WRONG,
                  shift_lineages: Collection[str] = (), b_count: int = ER.boot.B_COUNT) -> tuple[dict, dict]:
    """(report, paired deltas). The deltas (engine vs engine, per stratum and population, with sd, minimum detectable
    delta and achieved power) have no field in `tier-r-report/1` yet, so they are returned beside it, not hashed in it.
    `b_count` is the lineage-bootstrap size (2,000; 500 in smoke)."""
    if symbols not in ('hidden', 'visible'):
        raise C.ContractError('symbols must be hidden or visible')
    docs = sorted(labels_docs, key=lambda d: d.pair_id)
    if len({d.pair_id for d in docs}) != len(docs):
        raise C.ContractError('duplicate pair_id in the evaluation set')
    by_engine = {p.engine: _EngineAcc() for p in providers}
    wrong_all: list[dict] = []
    all_notes = list(notes)
    if symbols == 'visible':
        all_notes.append('symbols visible: engines saw the debug image; not comparable with hidden-symbol results')
    runs: dict[str, list[ER.Run]] = defaultdict(list)
    for provider in sorted(providers, key=lambda p: ENGINE_ORDER.index(p.engine)):
        acc = by_engine[provider.engine]
        for labels in docs:
            try:
                out = provider(labels, symbols)
            except Exception as exc:  # noqa: BLE001 - isolation: one pair must not end the run; only the class is kept
                out = failed(provider.engine, f'provider raised {type(exc).__name__}')
            counts = sha = None
            if out.status == 'ok':
                counts, wrong = score_pair(labels, out)
                runs[provider.engine].append(ER.Run(labels, to_engine_pairs(out, symbols)))
                wrong_all += wrong
                sha = RS.output_sha256(engine_output_doc(out, labels, symbols))
                if out.implicit_unchanged and IMPLICIT_NOTE not in all_notes:
                    all_notes.append(IMPLICIT_NOTE)
            acc.results.append((labels.pair_id, labels.stratum, out.status, out.reason, counts, sha, out.version))
    pairs, strata, engines = [], defaultdict(dict), []
    for engine in ENGINE_ORDER:
        if engine not in by_engine:
            continue
        rows = by_engine[engine].results
        ok = [r for r in rows if r[2] == 'ok']
        bad = [r for r in rows if r[2] != 'ok']
        status = ('blocked' if not rows else 'ok' if not bad else 'partial' if ok
                  else 'failed' if any(r[2] == 'failed' for r in bad) else 'blocked')
        reason = None
        if not rows:
            reason = 'no label documents to evaluate'
        elif bad:
            reason = _clean(f'{bad[0][3]}' + (f' (and {len(bad) - 1} more pairs)' if len(bad) > 1 else ''), 500)
        if rows and len(ok) / len(rows) < COMPLETION_WARNING:
            all_notes.append(f'{engine}: only {len(ok)} of {len(rows)} pairs completed (below 90%); '
                             'metrics cover completed pairs only')
        engines.append({'engine': engine, 'status': status, 'version': next((r[6] for r in ok if r[6]), None),
                        'reason': reason, 'runs': len(ok), 'failures': sum(1 for r in bad if r[2] == 'failed')})
        for pid, stratum, st, why, counts, sha, _ in rows:
            pairs.append({'pair_id': pid, 'stratum': stratum, 'engine': engine, 'status': st,
                          'reason': None if st == 'ok' else _clean(why or '', 500),
                          'metrics': metrics_from_counts(counts) if counts else None, 'output_sha256': sha})
        for stratum in sorted({r[1] for r in ok}):
            strata[stratum][engine] = metrics_from_counts(sum_counts(r[4] for r in ok if r[1] == stratum))
    wrong_all.sort(key=lambda w: (w['pair_id'], ENGINE_ORDER.index(w['engine']), -1 if w['old_rva'] is None else w['old_rva'],
                                  -1 if w['new_rva'] is None else w['new_rva']))
    report = {'contract': 'tier-r-report/1', 'symbols': symbols,
              'inputs': [{'pair_id': d.pair_id, 'stratum': d.stratum, 'labels_digest': d.digest_sha256} for d in docs],
              'engines': engines, 'strata': {k: strata[k] for k in sorted(strata)}, 'pairs': pairs,
              'wrong_matches': wrong_all[:max_wrong], 'wrong_matches_truncated': max(0, len(wrong_all) - max_wrong),
              'notes': all_notes, 'report_sha256': '0' * 64}
    attempts = [(e, r[1], r[2]) for e, acc in by_engine.items() for r in acc.results]
    fields, deltas = ER.build_blocks(docs, runs, attempts, symbols=symbols, shift_lineages=shift_lineages,
                                     b_count=b_count)
    return finalize_report({**report, **fields}), deltas


def finalize_report(report: dict) -> dict:
    doc = C.validate_json(C.TierRReport, report).model_dump(mode='json')
    doc['report_sha256'] = digest(doc, 'report_sha256')
    C.load_report(C.dump_json(doc))  # the written form must load again
    return doc


def blocked_engines(report: Mapping) -> list[dict]:
    return [e for e in report['engines'] if e['status'] in ('blocked', 'failed')]


# ---- Markdown -----------------------------------------------------------------------------------------------------

def _fmt(value) -> str:
    return 'n/a' if value is None else f'{value:.3f}' if isinstance(value, float) else str(value)


def _cell(text) -> str:
    return re.sub(r'[|\r\n`<>]', ' ', '' if text is None else str(text))[:120]


def _iv(iv: Mapping | None) -> str:
    if not iv or iv['point'] is None:
        return 'n/a'
    span = '' if iv['lo'] is None else f' [{iv["lo"]:.3f}, {iv["hi"]:.3f}]'
    return f'{iv["point"]:.3f}{span}' + (' (anti-conservative)' if iv['anti_conservative'] else '')


def _block_lines(report: Mapping) -> list[str]:
    """Coverage, per-label cells and rank blocks: descriptive, one row per engine, never pooled."""
    lines = []
    if report.get('coverage'):
        lines += ['', f'## Coverage (lineages: {report.get("lineages")})', '',
                  '| engine | stratum | attempted | completed | blocked | failed |', '|---|---|---|---|---|---|']
        lines += [f'| {c["engine"]} | {c["stratum"]} | {c["attempted"]} | {c["completed"]} | {c["blocked"]} | '
                  f'{c["failed"]} |' for c in report['coverage']]
    for stratum, per_engine in (report.get('labels') or {}).items():
        lines += ['', f'## Per-label outcomes, stratum {stratum}', '',
                  '| engine | truth label | paired correct | paired wrong | unpaired | abstained | flagged | rate |',
                  '|---|---|---|---|---|---|---|---|']
        lines += [f'| {e} | {label} | {c["paired_correct"]} | {c["paired_wrong"]} | {c["unpaired"]} | '
                  f'{c["abstained"]} | {c["flagged"]} | {_iv(c["rate"])} |'
                  for e in ENGINE_ORDER if e in per_engine for label, c in per_engine[e].items()]
    for stratum, per_engine in (report.get('rank') or {}).items():
        lines += ['', f'## Fix rank, stratum {stratum}', '',
                  '| engine | population | pairs | lineages | found | pool median | hit@1 | hit@3 | hit@10 | MRR | nDCG@10 |',
                  '|---|---|---|---|---|---|---|---|---|---|---|']
        lines += [f'| {e} | {b["population"]} | {b["pairs"]} | {b["lineages"]} | {b["found_in_pool"]} | '
                  f'{_fmt(b["pool_median"])} | {_iv(b["hit_at"]["1"])} | {_iv(b["hit_at"]["3"])} | '
                  f'{_iv(b["hit_at"]["10"])} | {_iv(b["mrr"])} | {_iv(b["ndcg10"])} |'
                  for e in ENGINE_ORDER if e in per_engine for b in [per_engine[e]]]
    return lines


def render_markdown(report: Mapping, max_wrong: int = 50) -> str:
    lines = ['# Tier R evaluation (tier-r-report/1)', '', f'- report_sha256: `{report["report_sha256"]}`',
             f'- symbols: {report["symbols"]}', f'- pairs: {len(report["inputs"])}', '', '## Engines', '',
             '| engine | status | version | runs | failures | reason |', '|---|---|---|---|---|---|']
    for e in report['engines']:
        status = 'BLOCKED' if e['status'] == 'blocked' else e['status']
        lines.append(f'| {e["engine"]} | {status} | {_cell(e["version"])} | {e["runs"]} | {e["failures"]} | '
                     f'{_cell(e["reason"])} |')
    cols = ('pairs', 'truth_same', 'identity_precision', 'identity_recall', 'changed_precision', 'changed_recall',
            'fp_rate', 'cosmetic_matched', 'cosmetic_flagged', 'ignored_predictions', 'ambiguous_records')
    for stratum, per_engine in report['strata'].items():
        lines += ['', f'## Stratum {stratum}', '', '| engine | ' + ' | '.join(cols) + ' |',
                  '|---|' + '---|' * len(cols)]
        for engine in ENGINE_ORDER:
            if engine in per_engine:
                lines.append(f'| {engine} | ' + ' | '.join(_fmt(per_engine[engine][c]) for c in cols) + ' |')
    lines += _block_lines(report)
    lines += ['', '## Wrong matches', '']
    wrong = report['wrong_matches']
    if not wrong:
        lines.append('none')
    else:
        lines += ['| pair | engine | kind | old | new | expected | names |', '|---|---|---|---|---|---|---|']
        for w in wrong[:max_wrong]:
            expected = (f'new {w["expected_new_rva"]:#x}' if w['expected_new_rva'] is not None else
                        f'old {w["expected_old_rva"]:#x}' if w['expected_old_rva'] is not None else '-')
            old = '-' if w['old_rva'] is None else f'{w["old_rva"]:#x}'
            new = '-' if w['new_rva'] is None else f'{w["new_rva"]:#x}'
            lines.append(f'| {_cell(w["pair_id"])} | {w["engine"]} | {w["kind"]} | {old} | {new} | {expected} | '
                         f'{_cell(w["old_name"])} / {_cell(w["new_name"])} |')
        hidden = len(wrong) - min(len(wrong), max_wrong) + report['wrong_matches_truncated']
        if hidden:
            lines.append(f'\n{hidden} more wrong matches are in the JSON report or were truncated.')
    if report['notes']:
        lines += ['', '## Notes', ''] + [f'- {_cell(n)}' for n in report['notes']]
    return '\n'.join(lines) + '\n'


def load_label_dir(folder: Path) -> list[C.KnownAnswerLabels]:
    return [C.load_labels(p.read_bytes()) for p in sorted(Path(folder).glob('*.json'))]
