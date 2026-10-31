"""Run one dev-only R1 pilot using existing primary, secondary and unified APIs.

Targets are never executed. Raw evidence/projects remain in the private work area;
the output is a research receipt, not a new persisted product contract. Candidate
scores are explicitly exploratory until a separate exact-digest review is supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import platform
import sys
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from patchtrace import backend as backend_module
from patchtrace.backend import BackendConfig
from patchtrace.ingestion import safe_path
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline
from patchtrace.unified.ir.place import place_ir
from tools.live_unified_check import EXTRACT_TIMEOUT_S, Side, file_sha256
from tools.unified.live_pairs import image_path, outcome_of

from ..common import canonical_json, strict_json
from ..evalcore.engines.ghidriff import MAX_IMPORT_BYTES, normalized
from ..evalcore.engines.rzdiff import RzDiffProvider
from . import contracts as C
from .research_audit import supplemental_metrics
from .research_observers import ghidriff_observations


def function_key(function) -> list:
    return [function.file, function.name, function.variant, function.old_rva, function.new_rva]


def select_truth(doc: C.KnownAnswerLabels, review: Mapping | None) -> tuple[C.KnownAnswerLabels, dict]:
    scope = {'original_labels_sha256': doc.digest_sha256}
    if review is None:
        return doc, {**scope, 'status': 'exploratory-candidates', 'reviewer': None}
    if (not isinstance(review, Mapping) or review.get('pair_id') != doc.pair_id
            or review.get('labels_digest_sha256') != doc.digest_sha256):
        raise ValueError('review must bind the exact pair and label digest')
    for field in ('reviewer', 'review_kind'):
        if not isinstance(review.get(field), str) or not review[field].strip():
            raise ValueError(f'review needs {field}')
    actual = {tuple(function_key(f)) for f in doc.functions}
    groups = []
    for field in ('accepted_keys', 'ambiguous_keys'):
        values = review.get(field)
        if not isinstance(values, list) or any(not isinstance(v, list) or len(v) != 5 for v in values):
            raise ValueError(f'invalid {field}')
        try:
            keys = {tuple(v) for v in values}
        except TypeError as exc:
            raise ValueError('function keys must contain scalar values') from exc
        if len(keys) != len(values) or not keys <= actual:
            raise ValueError(f'duplicate or unknown {field}')
        groups.append(keys)
    accepted, ambiguous = groups
    if accepted & ambiguous or accepted | ambiguous != actual:
        raise ValueError('review must classify each supplied function once')
    body = doc.model_dump(mode='json')
    for function in body['functions']:
        key = tuple(function[k] for k in ('file', 'name', 'variant', 'old_rva', 'new_rva'))
        if key in ambiguous:
            function.update(identity='ambiguous', label='ambiguous', check='unchecked')
    selected = C.load_labels(C.dump_json(C.finalize_labels(body)))
    return selected, {**scope, 'status': 'reviewed-selection', 'reviewer': review['reviewer'],
                      'review_kind': review['review_kind'], 'accepted_records': len(accepted),
                      'ambiguous_records': len(ambiguous), 'selection_sha256': selected.digest_sha256,
                      'review_sha256': hashlib.sha256(canonical_json(review)).hexdigest()}


def unified_observations(rows) -> tuple[list, dict]:
    observations, decisions, materialities, abstained = [], Counter(), Counter(), 0
    for row in rows:
        decisions[row.decision] += 1
        materialities[row.materiality] += 1
        if row.decision == 'matched' and len(row.older) == len(row.newer) == 1:
            flag = {'material': True, 'unchanged': False, 'cosmetic': False}.get(row.materiality)
            observations.append((row.older[0], row.newer[0], flag))
        elif row.decision == 'older-only' and len(row.older) == 1 and not row.newer:
            observations.append((row.older[0], None, None))
        elif row.decision == 'newer-only' and len(row.newer) == 1 and not row.older:
            observations.append((None, row.newer[0], None))
        else:
            abstained += 1
    return observations, {'rows': sum(decisions.values()), 'decisions': dict(sorted(decisions.items())),
                          'materialities': dict(sorted(materialities.items())), 'abstained_rows': abstained}


def verify_project(doc: C.KnownAnswerLabels, project) -> None:
    actual = {a.side: a.sha256 for a in project.artifacts}
    if len(project.artifacts) != 2 or actual != {'older': doc.older.sha256, 'newer': doc.newer.sha256}:
        raise ValueError('primary project artifact binding does not match labels')


def _failure(exc: Exception) -> dict:
    return {'status': 'failed', 'error_type': type(exc).__name__, 'reason': str(exc)[:2000]}


def _execution_provenance(run, *, resumed: bool) -> dict:
    """Describe recorded execution without granting fresh credit to cached or reused output."""
    if run.backend != 'ghidriff':
        provenance, executed = 'persisted-import-or-sample', False
    elif 'cache_origin' in run.settings:
        provenance, executed = 'persisted-native-cache', False
    elif resumed:
        provenance, executed = 'persisted-native', False
    else:
        provenance, executed = 'executed-now', True
    return {'execution_provenance': provenance, 'native_execution_in_this_invocation': executed}


def _score(truth, observations: list) -> dict:
    return {'observations': observations, 'metrics': supplemental_metrics(truth, observations)}


def _unified(service, doc, truth, backend, work) -> dict:
    start = time.monotonic()
    run = next(r for r in reversed(service.project.runs) if r.status == 'completed')
    gzf = service.root / 'runs' / run.id / 'unified' / 'gzf'
    work.mkdir(parents=True, exist_ok=False)
    sides, extraction = [], {}
    try:
        for label, own, other in (('older', doc.older, doc.newer), ('newer', doc.newer, doc.older)):
            artifact = next(a for a in service.project.artifacts if a.side == label)
            side = Side(label, safe_path(service.root, artifact.relative_path), other.sha256, backend, work)
            sides.append(side)
            program = gzf / f'{label}.gzf'
            built = side.run('gzf', program, file_sha256(program))
            place_ir(service.root, run.id, built['directory'])
            extraction[label] = {'artifact_sha256': own.sha256,
                                 'content_digest': built['manifest'].content_digest,
                                 'extract_seconds': built['extract_seconds'],
                                 'ingest_seconds': built['ingest_seconds']}
        report = pipeline.run_unified(service, pipeline.UnifiedOptions(backend=backend, timeout_s=EXTRACT_TIMEOUT_S))
        outcome = outcome_of(service, truth, 'forward')
        observations, coverage = unified_observations(outcome.rows)
        result = {'status': report.status, 'wall_s': time.monotonic() - start, 'coverage': coverage,
                  'extraction': extraction, 'outcome': outcome.model_dump(mode='json'), **_score(truth, observations)}
        start = time.monotonic()
        cached = pipeline.run_unified(service, pipeline.UnifiedOptions(backend=backend, timeout_s=EXTRACT_TIMEOUT_S))
        result['warm_cache'] = {'status': cached.status, 'wall_s': time.monotonic() - start,
                                'rows_sha256': outcome_of(service, truth, 'forward').rows_sha256}
        return result
    finally:
        for side in sides:
            side.close()


def run_pilot(doc: C.KnownAnswerLabels, store: Path, backend: BackendConfig, work: Path, *,
              rz_diff: str | None = None, unified: bool = False, review: Mapping | None = None,
              primary_project: Path | None = None) -> dict:
    truth, scope = select_truth(doc, review)
    work = Path(work).resolve()
    repository = Path(__file__).resolve().parents[3]
    if work.is_relative_to(repository) or Path(store).resolve().is_relative_to(repository):
        raise ValueError('private work and binary store must be outside the repository')
    work.mkdir(parents=True, exist_ok=True)
    result = {'pair_id': doc.pair_id, 'labels_sha256': doc.digest_sha256, 'truth_scope': scope,
              'platform': platform.platform(), 'python': platform.python_version(), 'target_executed': False,
              'older': doc.older.model_dump(mode='json'), 'newer': doc.newer.model_dump(mode='json'),
              'peak_process_tree_memory_bytes': None,
              'memory_note': 'not measured; wall clocks are sequential local observations, not isolated benchmarks',
              'engines': {}}
    engines = result['engines']
    start = time.monotonic()
    service = None
    completed = False
    try:
        if primary_project is None:
            service = ProjectService.create(image_path(store, doc.older), image_path(store, doc.newer),
                                            doc.pair_id, work / 'primary')
            raw_path, run = backend_module.run_comparison(backend, service.project, service.root,
                                                         threading.Event(), lambda _e: None)
            if run.status != 'completed':
                engines['ghidriff'] = {'status': 'blocked' if run.status == 'identical' else 'failed',
                                      'backend_status': run.status, 'reason': run.error or
                                      'backend identical-hash shortcut; engine was not executed',
                                      'wall_s': time.monotonic() - start}
            else:
                service.apply_analysis(raw_path, run)
        else:
            service = ProjectService.open(primary_project)
            verify_project(doc, service.project)
            run = next(r for r in reversed(service.project.runs) if r.status == 'completed')
            raw_path = safe_path(service.root, run.raw_path)
        if run.status == 'completed':
            completed = True
            if raw_path.stat().st_size > MAX_IMPORT_BYTES:
                raise ValueError('raw Ghidriff input exceeds size limit')
            data = raw_path.read_bytes()
            if hashlib.sha256(data).hexdigest() != run.raw_sha256:
                raise ValueError('raw Ghidriff digest no longer matches persisted run')
            raw = strict_json(data)
            normalized(raw, doc, 'hidden', run.raw_sha256)
            # The optional projection is explicit and records unscored external namespaces.
            from .research_observers import ghidriff_image_projection
            projected, coverage = ghidriff_image_projection(raw)
            observed = ghidriff_observations(projected, old_base=doc.older.image_base, new_base=doc.newer.image_base)
            engines['ghidriff'] = {'status': 'ok', 'raw_sha256': run.raw_sha256, 'raw_path': str(raw_path),
                                  'resumed_primary': primary_project is not None,
                                  'run_id': run.id, 'backend': run.backend, 'backend_version': run.backend_version,
                                  **_execution_provenance(run, resumed=primary_project is not None),
                                  'wall_s': None if primary_project else time.monotonic() - start,
                                  'settings': run.settings, 'stats': raw.get('stats'), 'coverage': coverage,
                                  **_score(truth, observed)}
        if unified and completed:
            try:
                engines['unified'] = _unified(service, doc, truth, backend, work / 'extraction')
            except Exception as exc:
                engines['unified'] = _failure(exc)
        else:
            engines['unified'] = {'status': 'not-run', 'reason': 'not selected or no completed primary run'}
    except Exception as exc:
        engines['ghidriff'] = _failure(exc)
        engines['unified'] = {'status': 'not-run', 'reason': 'primary preparation or observation failed'}
    finally:
        if service is not None:
            service.close()
    if rz_diff:
        start = time.monotonic()
        try:
            if doc.older.image_base != doc.newer.image_base:
                raise ValueError('legacy rz-diff reducer uses one image base; unequal-base pilot is not supported')
            output = RzDiffProvider(store, executable=rz_diff, deadline=backend.timeout_seconds)(doc, 'hidden')
            engines['rz-diff'] = {'status': output.status, 'reason': output.reason, 'version': output.version,
                                  'wall_s': time.monotonic() - start}
            if output.status == 'ok':
                observed = [(p.old_rva, p.new_rva, p.changed) for p in output.predictions]
                observed += [(rva, None, None) for rva in sorted(output.old_only)]
                observed += [(None, rva, None) for rva in sorted(output.new_only)]
                engines['rz-diff'].update(_score(truth, observed))
        except Exception as exc:
            engines['rz-diff'] = _failure(exc)
    else:
        engines['rz-diff'] = {'status': 'not-run', 'reason': 'no executable selected'}
    engines['bindiff'] = {'status': 'blocked', 'reason': 'no verified BinDiff/BinExport configured for this pilot'}
    return result


def _receipt_path(work: Path, output: Path) -> Path:
    """Bind a new receipt to the selected private work root before any engine work."""
    work, output = Path(work), Path(output)
    if any(not path.is_absolute() or '..' in path.parts for path in (work, output)):
        raise ValueError('work and receipt paths must be absolute without traversal')
    if any(part.is_symlink() for path in (work, output) for part in (path, *path.parents)):
        raise ValueError('work and receipt paths cannot contain symlinks')
    root = work.resolve()
    if root.is_relative_to(Path(__file__).resolve().parents[3]):
        raise ValueError('private work and receipt must be outside the repository')
    if output.parent.resolve() != root or output.suffix != '.json':
        raise ValueError('receipt must be a new .json file directly inside the private work directory')
    target = safe_path(root, output.name)
    if target.exists():
        raise ValueError('receipt already exists; choose a new work directory or receipt name')
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--store', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new absolute .json path directly inside --work')
    parser.add_argument('--ghidra-dir', type=Path, required=True)
    parser.add_argument('--java-home', default='')
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--rz-diff')
    parser.add_argument('--unified', action='store_true')
    parser.add_argument('--review', type=Path)
    parser.add_argument('--primary-project', type=Path)
    args = parser.parse_args(argv)
    try:
        output = _receipt_path(args.work, args.output)
        doc = C.load_labels(args.labels.read_bytes())
        review = None if args.review is None else strict_json(args.review.read_bytes())
        backend = BackendConfig(str(Path(args.python).absolute()), str(args.ghidra_dir.resolve()),
                                args.timeout, java_home=args.java_home, retain_gzf=True)
        receipt = run_pilot(doc, args.store, backend, args.work, rz_diff=args.rz_diff, unified=args.unified,
                            review=review, primary_project=args.primary_project)
        data = C.dump_json(receipt)
        with _receipt_path(args.work, output).open('xb') as stream:
            stream.write(data)
        print(f'{doc.pair_id}: ' + ', '.join(f'{name}={value["status"]}' for name, value in receipt['engines'].items()))
        if any(v['status'] == 'failed' for v in receipt['engines'].values()):
            return 1
        return 0 if any(v['status'] in {'ok', 'cached', 'partial'} for v in receipt['engines'].values()) else 3
    except (ValueError, OSError) as exc:
        print(f'pilot error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
