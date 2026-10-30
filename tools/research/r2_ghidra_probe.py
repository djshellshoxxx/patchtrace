"""Bounded native Ghidra extraction and production unified compute on existing synthetic PE pairs.

Never executes target binaries or accesses a corpus/calibration/locked evaluation.
The work root must be new, under an existing trusted parent; existing roots and
symlinks are rejected. The fresh --output report is confined to this checkout's
research results directory; checkpoints update only the report created by this run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests'), str(ROOT / 'tools')]

from live_unified_check import Side, function_lines  # noqa: E402
from unified_support.pairs import pair_for  # noqa: E402

from patchtrace.backend import BackendConfig, run_comparison  # noqa: E402
from patchtrace.service import ProjectService  # noqa: E402
from patchtrace.unified import compute, store  # noqa: E402
from patchtrace.unified.addressing import AddressMap, layout_from_reader  # noqa: E402
from patchtrace.unified.extract import script_sha256  # noqa: E402
from patchtrace.unified.ir.reader import IrReader  # noqa: E402
from patchtrace.unified.sources import GhidriffRun, RawGhidriff, SourceInputs  # noqa: E402
from tools.research.r2_paths import report_destination, write_report_json  # noqa: E402


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def failure(exc: Exception) -> dict:
    return {'type': type(exc).__name__, 'message': str(exc), 'code': getattr(exc, 'code', None),
            'reason': getattr(exc, 'reason', None), 'diagnostics': getattr(exc, 'diagnostics', None)}


def probe_pair(kind: str, backend: BackendConfig, work: Path) -> dict:
    fixture = pair_for(kind, seed=0)
    case = work / kind
    case.mkdir()
    paths = [case / f'{label}.dll' for label in ('older', 'newer')]
    for path, image in zip(paths, (fixture.older, fixture.newer), strict=True):
        path.write_bytes(image.data)
    out = {'kind': kind, 'seed': 0, 'truth': [
        {'older_rvas': list(a), 'newer_rvas': list(b), 'change': change}
        for a, b, change in fixture.rva_relations()],
        'truth_origin': 'existing unified_support.pairs.pair_for; known by construction, not inferred from symbols',
        'symbol_visibility': 'Fixture exports are present and visible to Ghidra and the ladder; no PDB/downloads.',
        'artifact_sha256': dict(zip(('older', 'newer'), fixture.digests, strict=True)),
        'sides': {}, 'status': 'started'}
    sides = {}
    extracted = {}
    readers = []
    try:
        for index, label in enumerate(('older', 'newer')):
            side = Side(label, paths[index], fixture.digests[1-index], backend, case)
            sides[label] = side
            started = time.perf_counter()
            result = side.run('analyze')
            extracted[label] = result
            records = function_lines(result['jsonl'])
            out['sides'][label] = {
                'wall_extract_plus_ingest_s': time.perf_counter() - started,
                'extract_seconds_rounded_by_existing_Side': result['extract_seconds'],
                'ingest_seconds_rounded_by_existing_Side': result['ingest_seconds'],
                'probe': result['probe'], 'stderr_tail': result['stderr_tail'],
                'ir_jsonl_sha256': sha(result['jsonl']),
                'manifest': result['manifest'].model_dump(mode='json'),
                'functions': [{'rva': r['rva'], 'name': r['name'], 'instruction_count': len(r['insns']),
                               'flags': r.get('flags', [])} for r in records],
            }
            print(f'NATIVE-SIDE-SUCCESS {kind} {label} functions={len(records)}', flush=True)
        for label in ('older', 'newer'):
            readers.append(IrReader.open(extracted[label]['directory']))
        layouts = AddressMap(*(layout_from_reader(sides[label].reader) for label in ('older', 'newer')))
        ir = compute.IrInputs(*readers, *(tuple((s.start, s.end) for s in sides[label].pe.sections)
                                        for label in ('older', 'newer')))
        # No fabricated Ghidriff table or analyst anchor is supplied. The required raw-key slot
        # carries the empty-byte digest, explicitly marked missing, and sources=() excludes it.
        inputs = SourceInputs(*fixture.digests, GhidriffRun('r2-native-ladder-only', 'not-run',
                              RawGhidriff(status='missing', sha256=sha(b''))), matches=())
        result_dir = case / 'unified'
        result_dir.mkdir()
        started = time.perf_counter()
        manifest = compute.compute_result(inputs, layouts, result_dir=result_dir, sources=(), ir=ir)
        rows = list(store.read_rows(result_dir, manifest))
        facts = list(store.read_facts(result_dir, manifest))
        one_to_one_truth = {(a[0], b[0]) for a, b, _change in fixture.rva_relations() if len(a) == len(b) == 1}
        predicted = {(r.older[0].rva, r.newer[0].rva) for r in rows
                     if r.decision == 'matched' and len(r.older) == len(r.newer) == 1}
        out['compute'] = {'wall_s': time.perf_counter() - started,
                          'sources': 'native Ghidra IR -> production ladder/fusion/facts; no Ghidriff/manual/secondary atoms',
                          'manifest': manifest.model_dump(mode='json'),
                          'rows': [r.model_dump(mode='json') for r in rows],
                          'facts': [r.model_dump(mode='json') for r in facts],
                          'decision_counts': dict(Counter(r.decision for r in rows)),
                          'materiality_counts': dict(Counter(r.materiality for r in rows)),
                          'matched_one_to_one_pairs': [list(p) for p in sorted(predicted)],
                          'truth_one_to_one_pairs': [list(p) for p in sorted(one_to_one_truth)],
                          'correct_matched_one_to_one_pairs': len(predicted & one_to_one_truth),
                          'note': 'N:M construction relations are not flattened into one-to-one truth.'}
        out['status'] = 'complete'
    except Exception as exc:
        out.update(status='error', error=failure(exc))
        print(f'NATIVE-ERROR {kind}: {exc}', flush=True)
    finally:
        for reader in readers:
            reader.close()
        for side in sides.values():
            side.close()
    return out


def primary_attempt(backend: BackendConfig, work: Path) -> dict:
    case = work / 'constant-changed'
    service = None
    events = []
    started = time.perf_counter()
    try:
        service = ProjectService.create(case / 'older.dll', case / 'newer.dll', 'R2 native synthetic probe',
                                        work / 'primary-project')
        path, run = run_comparison(backend, service.project, service.root, threading.Event(),
                                   lambda e: events.append({'stage': e.stage, 'message': e.message}))
        raw = path.read_bytes() if path and path.is_file() else None
        return {'status': run.status, 'wall_s': time.perf_counter()-started,
                'error': run.error, 'events': events, 'raw_sha256': sha(raw) if raw else None,
                'raw_document': json.loads(raw) if raw else None}
    except Exception as exc:
        return {'status': 'error', 'wall_s': time.perf_counter()-started, 'error': failure(exc), 'events': events}
    finally:
        if service is not None:
            service.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', required=True)
    parser.add_argument('--ghidra-dir', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True, help='New private directory; parent must exist')
    parser.add_argument('--output', type=Path, required=True,
                        help='Fresh report inside this checkout docs/research/unified-matching-r2/results')
    parser.add_argument('--kinds', default='constant-changed,condition-changed,added-check,moved,split,merged')
    parser.add_argument('--primary-attempt', action='store_true')
    args = parser.parse_args()
    args.output = report_destination(args.output, checkout_root=ROOT)
    if args.output.exists():
        raise FileExistsError('report already exists; choose a fresh report destination')
    # Do not resolve the final component: a dangling symlink must fail, not create its target.
    work = args.work.absolute()
    work.mkdir(mode=0o700)
    report = {'research_only': True, 'status': 'initializing', 'cases': []}
    output_created = False

    def save() -> None:
        nonlocal output_created
        write_report_json(args.output, report, checkout_root=ROOT, replace=output_created)
        output_created = True

    # Claim a new report atomically before metadata subprocesses or native extraction.
    save()
    for name in ('tmp', 'cache', 'config', 'data'):
        (work / name).mkdir(exist_ok=True)
    tempfile.tempdir = str(work / 'tmp')
    for key, folder in (('TMPDIR', 'tmp'), ('XDG_CACHE_HOME', 'cache'), ('XDG_CONFIG_HOME', 'config'),
                        ('XDG_DATA_HOME', 'data')):
        os.environ[key] = str(work / folder)
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    backend = BackendConfig(args.python, str(args.ghidra_dir.resolve()), timeout_seconds=120,
                            no_cache=True, restrict_env=True)
    properties = (args.ghidra_dir / 'Ghidra/application.properties').read_text()
    report.update({'synthetic_only': True, 'native_extraction': True, 'status': 'running',
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'production_baseline': 'a04f5a299a8d4afef023261e52e08d14678cf1e7',
              'started_utc': datetime.now(UTC).isoformat(), 'platform': platform.platform(),
              'python': sys.version, 'versions': {p: importlib.metadata.version(p)
                                                for p in ('ghidriff', 'pyghidra', 'JPype1')},
              'java_version': subprocess.run(['java', '-version'], capture_output=True, text=True).stderr,
              'ghidra_properties': properties, 'ghidra_properties_sha256': sha(properties.encode()),
              'extractor_script_sha256': script_sha256(), 'work_directory': str(work),
              'target_execution': False})
    save()
    for kind in args.kinds.split(','):
        report['cases'].append(probe_pair(kind, backend, work))
        save()
    if args.primary_attempt:
        report['ghidriff_primary_attempt'] = primary_attempt(backend, work)
    report['finished_utc'] = datetime.now(UTC).isoformat()
    report['status'] = 'finished'
    save()
    print(json.dumps({'cases': [(c['kind'], c['status']) for c in report['cases']],
                      'ghidriff': report.get('ghidriff_primary_attempt', {}).get('status')}), flush=True)


if __name__ == '__main__':
    main()
