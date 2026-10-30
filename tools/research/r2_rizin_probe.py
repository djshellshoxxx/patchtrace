"""Bounded native rz-diff smoke on EXISTING authored PE fixtures; never execute targets.

Uses the production scheduler, allow-listed environment, adapter and strict parser.
Only fixture hashes/truth, parsed native observations and small raw streams are saved.
Report writes stay in the checkout results directory; existing reports require the
explicit append operation. Archive/tool reads remain explicit caller selections,
bounded regular files, and are verified by pin and exact archive-member equality.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import struct
import sys
import tarfile
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]

from unified_support.nuisance import nuisance_pair  # noqa: E402
from unified_support.pairs import KINDS, pair_for  # noqa: E402

from patchtrace.jobs import run_process  # noqa: E402
from patchtrace.secondary.engine_env import engine_env  # noqa: E402
from patchtrace.secondary.registry import build_registry  # noqa: E402
from patchtrace.secondary.scheduler import ProjectRef, run_engines  # noqa: E402
from tools.research.r2_paths import (  # noqa: E402
    read_report_json,
    regular_input,
    report_destination,
    write_report_json,
)

PIN = '0.9.1'
ARCHIVE_SHA256 = '9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf'
RELEASE_URL = 'https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz'


def digest(path):
    h = hashlib.sha256()
    with regular_input(path, max_bytes=512 * 1024 * 1024).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def image_base(data):
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    return struct.unpack_from('<Q', data, pe + 24 + 24)[0]


def score(pair, matches):
    """Only explicit relation identities are scored; no Cartesian true-negative set."""
    old_known = set(dict(pair.older.functions).values())
    new_known = set(dict(pair.newer.functions).values())
    truth = {(old[0], new[0]) for old, new, _change in pair.rva_relations() if len(old) == len(new) == 1}
    grouped = {(o, n) for old, new, _change in pair.rva_relations() if len(old) != 1 or len(new) != 1
               for o in old for n in new}
    bases = image_base(pair.older.data), image_base(pair.newer.data)
    observations = []
    for match in matches:
        item = match.model_dump(mode='json')
        for field, base in zip(('older_address', 'newer_address'), bases, strict=True):
            value = item[field]
            item[field.replace('address', 'rva')] = None if value is None else value - base if value >= base else value
        observations.append(item)
    candidates = {(m['older_rva'], m['newer_rva']) for m in observations
                  if m['older_rva'] is not None and m['newer_rva'] is not None}
    by_old, by_new = defaultdict(set), defaultdict(set)
    for old, new in candidates:
        by_old[old].add(new)
        by_new[new].add(old)
    counts = Counter({'true_predicted': 0, 'false_predicted': 0, 'unknown_predicted': 0,
                      'ambiguous_predicted': 0, 'group_relation_unscored': 0})
    correct = set()
    labels = {}
    for old, new in sorted(candidates):
        if old not in old_known or new not in new_known:
            label = 'unknown_predicted'
        elif (old, new) in grouped:
            label = 'group_relation_unscored'
        elif len(by_old[old]) > 1 or len(by_new[new]) > 1:
            label = 'ambiguous_predicted'
        elif (old, new) in truth:
            label = 'true_predicted'
            correct.add((old, new))
        else:
            label = 'false_predicted'
        counts[label] += 1
        labels[(old, new)] = label
    for item in observations:
        edge = item['older_rva'], item['newer_rva']
        item['assessment'] = labels.get(edge, 'one_sided_observation')
    return {'counts': dict(counts), 'eligible_truth_pairs': len(truth),
            'missed_eligible_truth_pairs': len(truth - correct),
            'one_sided_observations': sum(m['older_rva'] is None or m['newer_rva'] is None for m in observations),
            'unique_two_sided_proposals': len(candidates), 'duplicate_two_sided_proposals': sum(
                m['older_rva'] is not None and m['newer_rva'] is not None for m in observations) - len(candidates),
            'observations': observations}


def main(args):
    start = time.monotonic()
    result = {'kind': 'r2-native-rizin-existing-fixtures/1', 'mocked': False, 'status': 'running',
              'production_path': 'engine_env + registry.RzDiffAdapter + scheduler.run_engines + rzdiff.interpret/parse_output',
              'python': platform.python_version(), 'platform': platform.platform(), 'cases': [],
              'max_total_seconds': args.total_seconds, 'per_case_timeout_seconds': 60,
              'notes': ['Only rz-diff is executed; target PE files are never executed or loaded.',
                        'Fixtures are authored tiny PE analogues, not compiler output or an independent corpus.',
                        'All fixture functions are exported; names can reveal identity and inflate native matching yield.',
                        'Exact .pdata extents and tiny bodies do not establish realistic analysis or extent recovery.',
                        'inlined/split/merged relations are excluded from 1:1 truth scoring.',
                        'True/false count unique two-sided proposals with known function-entry RVAs and eligible 1:1 truth.',
                        'Unknown addresses, endpoint ambiguities and N:M relation proposals are counted separately.',
                        'No true-negative count, specificity, semantic-equivalence or final unified acceptance is inferred.',
                        'Archive pin was recorded in repository CI from an official-asset stream; not upstream-published checksum.']}

    def save():
        write_report_json(args.output, result, checkout_root=ROOT, replace=args.output_created)
        args.output_created = True

    save()
    args.archive = regular_input(args.archive, max_bytes=512 * 1024 * 1024)
    args.rz_diff = regular_input(args.rz_diff, max_bytes=256 * 1024 * 1024)
    result['tool'] = {'path': str(args.rz_diff.resolve()), 'executable_sha256': digest(args.rz_diff),
                      'archive_path': str(args.archive.resolve()), 'archive_sha256': digest(args.archive),
                      'expected_archive_sha256': ARCHIVE_SHA256, 'release_url': RELEASE_URL,
                      'pin_source': '.github/workflows/live-rizin.yml ubuntu-latest matrix'}
    if result['tool']['archive_sha256'] != ARCHIVE_SHA256:
        raise ValueError('archive does not match repository pin')
    with tarfile.open(args.archive, 'r:xz') as archive:
        members = [m for m in archive.getmembers() if m.name.removeprefix('./') == 'bin/rz-diff' and m.isfile()]
        if len(members) != 1:
            raise ValueError('archive must contain exactly one bin/rz-diff')
        with archive.extractfile(members[0]) as stream:
            archive_executable_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
        result['tool']['archive_executable_sha256'] = archive_executable_sha
        result['tool']['archive_member'] = members[0].name
        if archive_executable_sha != result['tool']['executable_sha256']:
            raise ValueError('executed binary differs from verified archive member')
    save()
    cancel = threading.Event()
    timer = threading.Timer(max(1, args.total_seconds - (time.monotonic() - start)), cancel.set)
    timer.daemon = True
    timer.start()
    try:
        with tempfile.TemporaryDirectory(prefix='patchtrace-r2-rizin-') as tmp:
            tmp = Path(tmp)
            # Keep tool installation and R1's directories read-only; settings/cache belong to this probe.
            home = tmp / 'home'
            home.mkdir()
            base_env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / 'data'),
                            XDG_CACHE_HOME=str(home / 'cache'), TMPDIR=str(tmp))
            env = engine_env(base_env, 'rz-diff')
            registry = build_registry(rz_diff=str(args.rz_diff.resolve()))
            capability = registry['rz-diff'].probe(env, cancel)
            result['capability'] = capability.model_dump(mode='json')
            if not capability.supported or capability.version != PIN:
                raise ValueError(f'native capability does not match pin: {capability}')
            version_result = run_process([str(args.rz_diff.resolve()), '-v'], cwd=tmp, env=env, cancel=cancel,
                                         timeout_seconds=30, log_limit=65536)
            result['tool']['version_stdout'] = version_result.log_tail
            for seed in args.seeds:
                for kind in (*KINDS, 'address-shift'):
                    if cancel.is_set():
                        raise TimeoutError('probe total deadline reached')
                    pair = nuisance_pair(kind, seed) if kind == 'address-shift' else pair_for(kind, seed)
                    case_dir = tmp / f'{kind}-{seed}'
                    case_dir.mkdir()
                    older, newer = case_dir / 'older.exe', case_dir / 'newer.exe'
                    pair.older.write(older)
                    pair.newer.write(newer)
                    oldsha, newsha = pair.digests
                    case = {'kind': kind, 'seed': seed, 'older_sha256': oldsha, 'newer_sha256': newsha,
                            'truth_rva_relations': pair.rva_relations(), 'older_functions': pair.older.functions,
                            'newer_functions': pair.newer.functions, 'native_processes': [],
                            'eligible_truth_pairs': sum(len(o) == len(n) == 1 for o, n, _ in pair.rva_relations()),
                            'excluded_group_relations': sum(len(o) != 1 or len(n) != 1 for o, n, _ in pair.rva_relations())}
                    result['cases'].append(case)

                    def recording_runner(argv, case=case, **kwargs):
                        began = time.monotonic()
                        native = run_process(argv, **kwargs)
                        case['native_processes'].append({'argv': list(argv), 'returncode': native.returncode,
                            'reason': native.reason, 'wall_s': time.monotonic() - began,
                            'stdout': native.log_tail, 'stderr': native.stderr_tail,
                            'stdout_sha256': hashlib.sha256(native.log_tail.encode()).hexdigest()})
                        return native

                    (outcome,) = run_engines(ProjectRef(older, newer, oldsha, newsha), ['rz-diff'],
                        cancel=cancel, env=env, registry=registry, runner=recording_runner,
                        per_engine_timeout={'rz-diff': 60.0})
                    case['run'] = outcome.run.model_dump(mode='json')
                    if outcome.match_set is None:
                        case['error'] = None if outcome.error is None else str(outcome.error)
                        case['unscored_eligible_truth_pairs'] = case['eligible_truth_pairs']
                    else:
                        case.update(score(pair, outcome.match_set.matches))
                        case['parsed_output_sha256'] = outcome.match_set.file_sha256
                    save()
                    print(f'{kind}:{seed} {outcome.run.status} {case.get("counts", case.get("error"))}', flush=True)
    finally:
        timer.cancel()
        result['wall_s'] = time.monotonic() - start
        expected = len(args.seeds) * (len(KINDS) + 1)
        result['status'] = 'passed' if len(result['cases']) == expected and all(
            c.get('run', {}).get('status') == 'ok' for c in result['cases']) else 'failed'
        totals = Counter()
        for case in result['cases']:
            totals.update(case.get('counts', {}))
            for key in ('eligible_truth_pairs', 'missed_eligible_truth_pairs', 'one_sided_observations',
                        'unscored_eligible_truth_pairs', 'excluded_group_relations'):
                totals[key] += case.get(key, 0)
        result['totals'] = dict(totals)
        result['run_counts'] = dict(Counter(c.get('run', {}).get('status', 'unfinished') for c in result['cases']))
        save()
    return 0 if result['status'] == 'passed' else 1


def orientation_diagnostics(args):
    """Append raw side-order diagnostics without rewriting the initial production attempts."""
    result = read_report_json(args.output, checkout_root=ROOT)
    args.rz_diff = regular_input(args.rz_diff, max_bytes=256 * 1024 * 1024)
    if digest(args.rz_diff) != result['tool']['executable_sha256']:
        raise ValueError('orientation probe executable changed since initial verification')
    shift = nuisance_pair('address-shift', 0)
    split = pair_for('split', 0)
    merged = pair_for('merged', 0)
    cases = [('shift-forward', shift.older, shift.newer), ('shift-reverse', shift.newer, shift.older),
             ('one-recovered-vs-two', shift.older, split.newer),
             ('two-recovered-vs-one', split.newer, shift.older),
             ('two-recovered-vs-two', split.newer, merged.older)]
    diagnostics = []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='patchtrace-r2-rizin-orientation-') as tmp:
        tmp = Path(tmp)
        home = tmp / 'home'
        home.mkdir()
        env = engine_env(dict(os.environ, HOME=str(home), TMPDIR=str(tmp),
                         XDG_CACHE_HOME=str(home / 'cache'), XDG_DATA_HOME=str(home / 'data')), 'rz-diff')
        registry = build_registry(rz_diff=str(args.rz_diff.resolve()))
        for label, old, new in cases:
            older, newer = tmp / 'input0.exe', tmp / 'input1.exe'
            old.write(older)
            new.write(newer)
            oldsha, newsha = digest(older), digest(newer)
            row = {'label': label, 'input0_sha256': oldsha, 'input1_sha256': newsha,
                   'input0_functions': old.functions, 'input1_functions': new.functions, 'native_processes': []}

            def runner(argv, row=row, **kwargs):
                native = run_process(argv, **kwargs)
                row['native_processes'].append({'argv': list(argv), 'returncode': native.returncode,
                    'reason': native.reason, 'stdout': native.log_tail, 'stderr': native.stderr_tail})
                return native

            (outcome,) = run_engines(ProjectRef(older, newer, oldsha, newsha), ['rz-diff'],
                cancel=threading.Event(), env=env, registry=registry, runner=runner,
                per_engine_timeout={'rz-diff': 60.0})
            row['run'] = outcome.run.model_dump(mode='json')
            row['observations'] = [] if outcome.match_set is None else [m.model_dump(mode='json')
                                                                      for m in outcome.match_set.matches]
            diagnostics.append(row)
            print(label, row['run']['status'], row['observations'], flush=True)
    result['orientation_diagnostics'] = diagnostics
    result['orientation_diagnostics_wall_s'] = time.monotonic() - started
    result['pinned_source_findings'] = {
        'ref': 'v0.9.1', 'tree_sha': 'c3a90e9226d977f58f4e9c75f78fa6b07afe13c7',
        'matching_source': 'https://github.com/rizinorg/rizin/blob/v0.9.1/librz/arch/similarity.c',
        'matching_blob_sha': '8544259e17a692bcb3c1d8858f104745cd0cba4c',
        'serializer_source': 'https://github.com/rizinorg/rizin/blob/v0.9.1/librz/main/rz-diff.c',
        'serializer_blob_sha': '3be455f898e91b906ed2d2307060f41c0833450e',
        'orientation': 'similarity.c568-574 swaps lists iff list_a has one recovered function; callback525-556 emits pair_a from original list_b and pair_b from original list_a without restoring orientation. Normal callback472-519 preserves order.',
        'serializer': 'rz-diff.c2042-2047/2211-2219 writes pair_a as original, pair_b as modified.',
        'analysis': 'rz-diff.c2365-2385 always analyzes both files for -t functions; -B is not needed on this path.',
        'empty_output': 'core_diff_show2132-2164 returns void on no file0 functions; graphs_files later marks success, hence exit0 with empty stdout and stderr diagnostic.'}
    result['diagnostic_findings'] = [x for x in result.get('diagnostic_findings', []) if 'Native help' not in x]
    write_report_json(args.output, result, checkout_root=ROOT, replace=True)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rz-diff', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seeds', type=int, nargs='+', default=[0, 1])
    parser.add_argument('--total-seconds', type=int, default=900)
    parser.add_argument('--append-orientation', action='store_true')
    args = parser.parse_args()
    try:
        args.output = report_destination(args.output, checkout_root=ROOT)
    except ValueError as exc:
        parser.error(str(exc))
    args.output_created = False
    try:
        status = orientation_diagnostics(args) if args.append_orientation else main(args)
    except Exception as exc:  # preserve native evidence on setup/runtime failures
        message = f'{type(exc).__name__}: {exc}'
        # Never clobber an earlier report when the initial exclusive publication failed.
        if args.output_created or args.append_orientation:
            result = read_report_json(args.output, checkout_root=ROOT) if args.output.exists() else {}
            result.update(status='failed', fatal_error=message)
            write_report_json(args.output, result, checkout_root=ROOT, replace=True)
        print(message, file=sys.stderr)
        status = 1
    sys.exit(status)
