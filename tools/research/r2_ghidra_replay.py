"""Replay preserved native Ghidra IR through another production tree, without extraction.

Invoke with absolute PYTHONPATH=<production>/src:<production>/tests. Inputs are opened
read-only; all new compute parts live in a fresh private --work directory under an
existing trusted parent. Existing work roots and symlinks are rejected. The explicit
--output report is fresh and confined to this script checkout's research results
directory, and is written once after replay. This is a policy/integration
comparison, not a fresh extraction or an accuracy benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

import patchtrace
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.unified import compute, store
from patchtrace.unified.addressing import AddressMap, layout_from_reader
from patchtrace.unified.ir.ladder_port import ReaderMnemonics, ReaderSide
from patchtrace.unified.ir.pe_tables import read_pe_tables
from patchtrace.unified.ir.reader import IrReader
from patchtrace.unified.ladder.engine import run_ladder
from patchtrace.unified.ladder.residual import pass_table
from patchtrace.unified.sources import GhidriffRun, RawGhidriff, SourceInputs
from tools.research.r2_paths import report_destination, write_report_json

ROOT = Path(__file__).resolve().parents[2]
CASE_KINDS = frozenset({'constant-changed', 'condition-changed', 'added-check', 'moved', 'split', 'merged'})


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def tree(root: Path) -> dict:
    paths = ('src/patchtrace/unified/compute.py', 'src/patchtrace/unified/sources/ladder.py',
             'src/patchtrace/unified/fusion/arbiter.py', 'src/patchtrace/unified/facts/verdict.py',
             'src/patchtrace/unified/registry.py')
    return {'head': git(root, 'rev-parse', 'HEAD'), 'tree': git(root, 'rev-parse', 'HEAD^{tree}'),
            'status': git(root, 'status', '--short'),
            'production_source_sha256': {p: digest(root / p) for p in paths}}


def summarize(rows) -> dict:
    return {'decision_counts': dict(Counter(r.decision for r in rows)),
            'materiality_counts': dict(Counter(r.materiality for r in rows)),
            'rows': [r.model_dump(mode='json') for r in rows]}


def replay(case: dict, preserved: Path, work: Path) -> dict:
    kind = case.get('kind')
    if not isinstance(kind, str) or kind not in CASE_KINDS:
        raise ValueError('Unsupported replay case kind')
    case_dir = preserved / kind
    readers = []
    artifacts = []
    before = {}
    for label in ('older', 'newer'):
        before[f'{label}_dll'] = digest(case_dir / f'{label}.dll')
        for name in ('manifest.json', 'ir.sqlite3'):
            before[f'{label}_ir_{name}'] = digest(case_dir / f'{label}-1-ir' / name)
    result = {'kind': kind, 'truth': case['truth'], 'symbol_visibility': case['symbol_visibility'],
              'baseline': {'manifest': case['compute']['manifest'],
                           'decision_counts': case['compute']['decision_counts'],
                           'materiality_counts': case['compute']['materiality_counts'],
                           'rows': case['compute']['rows']},
              'preserved_input_sha256_before': before}
    try:
        for label in ('older', 'newer'):
            artifacts.append(VerifiedArtifactReader.open_path(case_dir / f'{label}.dll'))
            readers.append(IrReader.open(case_dir / f'{label}-1-ir', verify=True))
        layouts = AddressMap(*(layout_from_reader(a) for a in artifacts))
        sections = [tuple((s.start, s.end) for s in read_pe_tables(a).sections) for a in artifacts]
        ir = compute.IrInputs(*readers, *sections)
        # Observe actual correspondence groups separately: an absent display limitation can
        # mean zero groups were generated, rather than that a generated N:M group was shown.
        correspondence = run_ladder(ReaderSide(readers[0]), ReaderSide(readers[1]), passes=pass_table(
            older=ReaderMnemonics(readers[0]), newer=ReaderMnemonics(readers[1])))
        result['ladder_observations'] = {
            'group_count': len(correspondence.groups),
            'older_only': [{'fid': item.fid, 'reason': item.reason} for item in correspondence.older_only],
            'newer_only': [{'fid': item.fid, 'reason': item.reason} for item in correspondence.newer_only]}
        inputs = SourceInputs(case['artifact_sha256']['older'], case['artifact_sha256']['newer'],
                              GhidriffRun('r2-native-ladder-only', 'not-run',
                                          RawGhidriff(status='missing', sha256=hashlib.sha256(b'').hexdigest())),
                              matches=())
        output = work / kind
        output.mkdir()
        started = time.perf_counter()
        manifest = compute.compute_result(inputs, layouts, result_dir=output, sources=(), ir=ir,
                                          created_utc=case['compute']['manifest']['created_utc'])
        rows = list(store.read_rows(output, manifest))
        facts = list(store.read_facts(output, manifest))
        result['current'] = {**summarize(rows), 'manifest': manifest.model_dump(mode='json'),
                             'facts': [f.model_dump(mode='json') for f in facts],
                             'wall_s': time.perf_counter()-started,
                             'ladder_groups_not_shown': [x for x in manifest.limitations
                                                         if x.startswith('ladder-groups-not-shown')],
                             'automatic_nm_rows': sum(bool(r.older and r.newer) and
                                                      (len(r.older) > 1 or len(r.newer) > 1) for r in rows)}
        old = case['compute']['manifest']
        result['comparison'] = {
            'ir_older_content_digest_equal': old['ir_older']['content_digest'] == manifest.ir_older.content_digest,
            'ir_newer_content_digest_equal': old['ir_newer']['content_digest'] == manifest.ir_newer.content_digest,
            'config_digest_changed': old['config_digest'] != manifest.config_digest,
            'result_id_changed': old['result_id'] != manifest.result_id,
            'baseline_limitations': old['limitations'], 'current_limitations': list(manifest.limitations),
            'baseline_row_count': len(case['compute']['rows']), 'current_row_count': len(rows)}
        result['status'] = 'complete'
    except Exception as exc:
        result.update(status='error', error={'type': type(exc).__name__, 'message': str(exc),
                                            'code': getattr(exc, 'code', None),
                                            'reason': getattr(exc, 'reason', None)})
    finally:
        for reader in readers:
            reader.close()
        for artifact in artifacts:
            artifact.close()
    after = {}
    for label in ('older', 'newer'):
        after[f'{label}_dll'] = digest(case_dir / f'{label}.dll')
        for name in ('manifest.json', 'ir.sqlite3'):
            after[f'{label}_ir_{name}'] = digest(case_dir / f'{label}-1-ir' / name)
    result['preserved_input_sha256_after'] = after
    result['original_inputs_unchanged'] = before == after
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--production-root', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True, help='New private directory; parent must exist')
    parser.add_argument('--output', type=Path, required=True,
                        help='Fresh report inside this script checkout docs/research/unified-matching-r2/results')
    args = parser.parse_args()
    args.output = report_destination(args.output, checkout_root=ROOT)
    if args.output.exists():
        raise FileExistsError('report already exists; choose a fresh report destination')
    root = args.production_root.resolve()
    if not Path(patchtrace.__file__).resolve().is_relative_to(root / 'src'):
        raise RuntimeError('PYTHONPATH did not select the requested production source')
    baseline = json.loads(args.baseline.read_text())
    # Atomic creation rejects existing directories, regular files and even dangling symlinks.
    args.work = args.work.absolute()
    args.work.mkdir(mode=0o700)
    report = {'started_utc': datetime.now(UTC).isoformat(), 'production_before': tree(root),
              'match_policy_version': compute.MATCH_POLICY_VERSION,
              'loaded_patchtrace': str(Path(patchtrace.__file__).resolve()),
              'baseline_report_sha256': digest(args.baseline),
              'preserved_native_inputs': baseline['work_directory'], 'work_directory': str(args.work),
              'native_extraction_repeated': False, 'target_execution': False, 'accuracy_claim': False,
              'sources': 'Same ladder-only inputs as baseline; real primary Ghidriff run is not included as atoms.',
              'cases': []}
    for case in baseline['cases']:
        row = replay(case, Path(baseline['work_directory']), args.work)
        report['cases'].append(row)
        print(json.dumps({'kind': row['kind'], 'status': row['status'],
                          'comparison': row.get('comparison'),
                          'decisions': row.get('current', {}).get('decision_counts')}), flush=True)
    report['production_after'] = tree(root)
    report['production_source_hashes_unchanged_during_replay'] = (
        report['production_before']['production_source_sha256'] ==
        report['production_after']['production_source_sha256'])
    report['finished_utc'] = datetime.now(UTC).isoformat()
    write_report_json(args.output, report, checkout_root=ROOT)
    if any(c['status'] != 'complete' or not c['original_inputs_unchanged'] for c in report['cases']):
        sys.exit(1)


if __name__ == '__main__':
    main()
