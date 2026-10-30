"""Native cJSON development probe with two reviewed positives; never execute targets.

Matcher inputs are copied engine DLLs and their native analysis only. The unblinded
review selection is read after matching, solely for the bounded observation report.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

if __package__:
    from .r2_paths import regular_input, report_destination, write_report_json
else:
    from r2_paths import regular_input, report_destination, write_report_json

ROOT = Path(__file__).resolve().parents[2]
SHAS = ('bed3ef087fd07161a14154d38c683b3f648611114bf9794bf91fba123d6f2d48',
        'd3837c837ffff4eb90342b2b9d5d29cd023f72d3858c3a405a015cc180e963b4')
MAX_INPUT_BYTES = 256 * 1024 * 1024  # bounded developer-selected DLL/executable inputs
MAX_ACCEPTANCE_BYTES = 4 * 1024 * 1024


def digest(path):
    result = hashlib.sha256()
    with regular_input(path, max_bytes=MAX_INPUT_BYTES).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def read_acceptance(path):
    selected = regular_input(path, max_bytes=MAX_ACCEPTANCE_BYTES)
    with selected.open('rb') as stream:
        content = stream.read(MAX_ACCEPTANCE_BYTES + 1)
    if len(content) > MAX_ACCEPTANCE_BYTES:
        raise ValueError('selected input exceeds size limit')
    return json.loads(content)


def write_raw_jsonl(path, content):
    # The caller supplies a fixed side label beneath the fresh private work root.
    # Exclusive creation refuses an unexpected existing leaf, including a dangling symlink.
    with Path(path).open('xb') as stream:
        stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('production-root', 'pilot-store', 'ghidra-dir', 'rz-diff', 'acceptance', 'output', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    # Report ownership is this script checkout, independently of the caller-selected production source tree.
    output = report_destination(args.output, checkout_root=ROOT)
    if output.exists():
        raise FileExistsError('report already exists; choose a fresh report filename')
    work = args.work.absolute()
    work.mkdir(mode=0o700)  # no implicit parents, reuse, or resolving a final symlink to another directory
    report = {'kind': 'r2-native-cjson-development/1', 'status': 'preflight', 'work_directory': str(work)}
    write_report_json(output, report, checkout_root=ROOT)

    def save(document):
        # Only checkpoints of the report this invocation successfully created may replace it.
        write_report_json(output, document, checkout_root=ROOT, replace=True)

    root = args.production_root.resolve()
    for folder in ('tmp', 'cache', 'config', 'data'):
        (work / folder).mkdir()
    tempfile.tempdir = str(work / 'tmp')
    for key, folder in (('TMPDIR', 'tmp'), ('XDG_CACHE_HOME', 'cache'), ('XDG_CONFIG_HOME', 'config'),
                        ('XDG_DATA_HOME', 'data')):
        os.environ[key] = str(work / folder)
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    sys.path[:0] = [str(root / 'src'), str(root / 'tools')]
    from live_unified_check import Side, function_lines

    from patchtrace.backend import BackendConfig
    from patchtrace.jobs import run_process
    from patchtrace.secondary.engine_env import engine_env
    from patchtrace.secondary.registry import build_registry
    from patchtrace.secondary.scheduler import ProjectRef, run_engines
    from patchtrace.unified import compute, store
    from patchtrace.unified.addressing import AddressMap, layout_from_reader
    from patchtrace.unified.extract import script_sha256
    from patchtrace.unified.ir.reader import IrReader
    from patchtrace.unified.limits import Budget
    from patchtrace.unified.sources import GhidriffRun, LoadedSecondary, RawGhidriff, SourceInputs
    from patchtrace.unified.sources.secondary import SecondaryAdapter

    began = time.perf_counter()
    report = {'kind': 'r2-native-cjson-development/1', 'started_utc': datetime.now(UTC).isoformat(),
              'status': 'running', 'target_execution': False, 'role': 'development', 'locked_set_consumed': False,
              'mocked': False, 'peak_process_tree_rss': None, 'rss_reason': 'not instrumented',
              'production_root': str(root), 'production_commit': subprocess.check_output(
                  ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
              'match_policy': compute.MATCH_POLICY_VERSION, 'python': sys.version, 'platform': platform.platform(),
              'versions': {p: importlib.metadata.version(p) for p in ('ghidriff', 'pyghidra', 'JPype1')},
              'extractor_script_sha256': script_sha256(), 'work_directory': str(work), 'sides': {},
              'primary_ghidriff': 'not run/reused; no fabricated primary matches supplied',
              'decompiler_channel': 'no primary text or on-demand S3b decompile; C6 unavailable',
              'symbol_visibility': '92 PE exports remain per R1 review; names inherent in DLL are matcher inputs',
              'calibration': 'not used; ordinal evidence only', 'native_processes': []}
    save(report)
    sides, readers = {}, []
    extracted = {}
    try:
        args.rz_diff = regular_input(args.rz_diff, max_bytes=MAX_INPUT_BYTES)
        paths = []
        for label, sha in zip(('older', 'newer'), SHAS, strict=True):
            source = regular_input(args.pilot_store / 'images' / sha / 'cjson.dll', max_bytes=MAX_INPUT_BYTES)
            if digest(source) != sha:
                raise ValueError(f'{label} source SHA mismatch')
            target = work / f'{label}.dll'
            shutil.copyfile(source, target)
            if digest(target) != sha:
                raise ValueError(f'{label} private copy SHA mismatch')
            paths.append(target)
            report['sides'][label] = {'source_path': str(source), 'artifact_sha256': sha,
                                      'copy_sha256': digest(target), 'bytes': target.stat().st_size}
        backend = BackendConfig(sys.executable, str(args.ghidra_dir.resolve()), timeout_seconds=600,
                                no_cache=True, restrict_env=True)
        for i, label in enumerate(('older', 'newer')):
            side = Side(label, paths[i], SHAS[1 - i], backend, work)
            sides[label] = side
            start = time.perf_counter()
            result = side.run('analyze')
            extracted[label] = result
            raw_path = work / f'{label}-native-ir.jsonl'
            write_raw_jsonl(raw_path, result['jsonl'])
            records = function_lines(result['jsonl'])
            report['sides'][label].update(status='ok', wall_s=time.perf_counter() - start,
                probe=result['probe'], manifest=result['manifest'].model_dump(mode='json'),
                raw_jsonl_path=str(raw_path), raw_jsonl_sha256=digest(raw_path),
                stderr_tail=result['stderr_tail'], function_count=len(records),
                functions=[{'rva': r['rva'], 'name': r['name'], 'instruction_count': len(r['insns'])} for r in records])
            save(report)
            print(f'EXTRACTED {label} {len(records)} functions', flush=True)
            readers.append(IrReader.open(result['directory']))
        addr = AddressMap(*(layout_from_reader(sides[label].reader) for label in ('older', 'newer')))
        ir = compute.IrInputs(*readers, *(tuple((s.start, s.end) for s in sides[label].pe.sections)
                                         for label in ('older', 'newer')))
        base_inputs = SourceInputs(*SHAS, GhidriffRun('r2-cjson-native-ladder', 'not-run',
                                   RawGhidriff('missing', sha256=hashlib.sha256(b'').hexdigest())), matches=())
        computations = {}

        def compute_one(label, inputs, selected):
            directory = work / label
            directory.mkdir()
            start = time.perf_counter()
            manifest = compute.compute_result(inputs, addr, result_dir=directory, sources=selected, ir=ir)
            store.verify_result_dir(directory)
            rows, facts = list(store.read_rows(directory, manifest)), list(store.read_facts(directory, manifest))
            result = {'status': 'ok', 'wall_s': time.perf_counter() - start,
                      'manifest': manifest.model_dump(mode='json'), 'directory': str(directory),
                      'decision_counts': dict(Counter(r.decision for r in rows)),
                      'materiality_counts': dict(Counter(r.materiality for r in rows)),
                      'rows': [r.model_dump(mode='json') for r in rows],
                      'facts': [f.model_dump(mode='json') for f in facts],
                      'all_predictions_outside_reviewed_selection': 'unreviewed, not false or true'}
            computations[label] = (rows, facts)
            report[label] = result
            save(report)

        compute_one('unified_ladder_only', base_inputs, ())
        env = engine_env(dict(os.environ), 'rz-diff')
        registry = build_registry(rz_diff=str(args.rz_diff.resolve()))
        cancel = threading.Event()
        capability = registry['rz-diff'].probe(env, cancel)
        report['rizin_capability'] = capability.model_dump(mode='json')
        report['rizin_executable_sha256'] = digest(args.rz_diff)
        if not capability.supported or not capability.version.startswith('0.9.1'):
            raise ValueError('Expected available rz-diff 0.9.1')

        def recording_runner(argv, **kwargs):
            start = time.perf_counter()
            result = run_process(argv, **kwargs)
            report['native_processes'].append({'argv': list(argv), 'returncode': result.returncode,
                'reason': result.reason, 'wall_s': time.perf_counter() - start,
                'stdout': result.log_tail, 'stderr': result.stderr_tail,
                'stdout_sha256': hashlib.sha256(result.log_tail.encode()).hexdigest(),
                'stdout_total': result.stdout_total})
            return result

        (outcome,) = run_engines(ProjectRef(*paths, *SHAS), ['rz-diff'], cancel=cancel, env=env,
            registry=registry, runner=recording_runner, per_engine_timeout={'rz-diff': 180.0})
        report['rizin_run'] = outcome.run.model_dump(mode='json')
        if outcome.match_set is not None:
            report['rizin_match_set'] = outcome.match_set.model_dump(mode='json')
            loaded = LoadedSecondary('r2-cjson-rzdiff', outcome.match_set)
            combined = SourceInputs(*SHAS, base_inputs.run, matches=(), secondary=(loaded,))
            compute_one('unified_with_rzdiff', combined, ('rz-diff',))
            rz_atoms = SecondaryAdapter().atoms(combined, addr, Budget()).atoms
        else:
            report['rizin_error'] = str(outcome.error)
            rz_atoms = ()
        # Review identities enter only this reporting phase, after all matcher executions.
        acceptance = read_acceptance(args.acceptance)
        report['review'] = {'acceptance_sha256': digest(args.acceptance),
            'labels_digest_sha256': acceptance['labels_digest_sha256'], 'accepted_count': len(acceptance['accepted_keys']),
            'unaccepted_count': len(acceptance['ambiguous_keys']), 'kind': acceptance['review_kind'],
            'exposure': acceptance['provenance']['exposure'], 'source_provenance': acceptance['provenance']['sides'],
            'no_precision_f1_fpr_claim': True, 'N_to_M_accuracy': 'excluded; only two reviewed 1:1 positives',
            'targets': []}
        for source, name, clone, old, new in acceptance['accepted_keys']:
            target = {'source': source, 'name': name, 'clone': clone, 'older_rva': old, 'newer_rva': new,
                      'rzdiff_proposed_exact_pair': any(a.older_rva == old and a.newer_rva == new for a in rz_atoms)}
            for label, (rows, facts) in computations.items():
                exact = next((r for r in rows if len(r.older) == len(r.newer) == 1
                              and (r.older[0].rva, r.newer[0].rva) == (old, new)), None)
                touched = [r for r in rows if any(s.rva == old for s in r.older)
                           or any(s.rva == new for s in r.newer)]
                target[label] = {'exact_pair_present': exact is not None,
                    'accepted_matched': exact is not None and exact.decision == 'matched',
                    'row': exact.model_dump(mode='json') if exact else None,
                    'touching_rows': [r.model_dump(mode='json') for r in touched],
                    'facts': next((f.model_dump(mode='json') for f in facts if exact and f.row_id == exact.row_id), None)}
            report['review']['targets'].append(target)
        report['status'] = 'complete' if outcome.match_set is not None else 'partial-rizin-failed'
    except Exception as exc:
        report.update(status='failed', error={'type': type(exc).__name__, 'message': str(exc),
                                             'code': getattr(exc, 'code', None), 'reason': getattr(exc, 'reason', None)})
        raise
    finally:
        for reader in readers:
            reader.close()
        for side in sides.values():
            side.close()
        report['wall_s'] = time.perf_counter() - began
        save(report)


if __name__ == '__main__':
    main()
