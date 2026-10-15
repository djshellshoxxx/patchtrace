"""LBL-14: the never-silent Tier R CI status and the corpus-tier-r workflow invariants. Hermetic: shard files are built in
memory, nothing runs a compiler, rizin or Ghidra."""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import ci_summary as C  # noqa: E402
from tools.calibration.tier_r import shard as S  # noqa: E402
from tools.calibration.tier_r.schemas import example_report  # noqa: E402

WORKFLOW = ROOT / '.github' / 'workflows' / 'corpus-tier-r.yml'


def report(engine: str, statuses: list[str], stratum='authored', prefix='p') -> dict:
    r = copy.deepcopy(example_report())
    base = r['pairs'][0]
    r['inputs'] = [{'pair_id': f'{prefix}{i}', 'stratum': stratum, 'labels_digest': 'f' * 64} for i in range(len(statuses))]
    r['pairs'] = [{**base, 'pair_id': f'{prefix}{i}', 'stratum': stratum, 'engine': engine, 'status': st,
                   'reason': None if st == 'ok' else 'x', 'metrics': base['metrics'] if st == 'ok' else None,
                   'output_sha256': base['output_sha256'] if st == 'ok' else None} for i, st in enumerate(statuses)]
    ok = statuses.count('ok')
    r['engines'] = [{'engine': engine, 'status': 'ok' if ok == len(statuses) else 'partial' if ok else 'blocked',
                     'version': '0.9.1' if ok else None, 'reason': None, 'runs': ok,
                     'failures': statuses.count('failed')}]
    r['strata'] = {stratum: {engine: base['metrics']}} if ok else {}
    r['report_sha256'] = S.digest(r, 'report_sha256')
    return r


def write_shards(directory: Path, reports: list[dict], case_status='ok') -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for i, rep in enumerate(reports):
        doc = {'contract': S.SHARD_CONTRACT, 'shard': i, 'of': len(reports), 'seed': 1, 'plan_sha256': 'b' * 64,
               'subset': 'smoke', 'engines': ['rz-diff'],
               'cases': [{'id': f'suite:g/s{i}', 'status': case_status, 'reason': None, 'digest': None}],
               'labels': [], 'features': [], 'reports': [rep]}
        doc['shard_sha256'] = S.digest(doc, 'shard_sha256')
        (directory / f'shard-{i}.json').write_text(json.dumps(doc), encoding='utf-8')
    return directory


def cell(doc: dict, engine='rz-diff') -> dict:
    return next(r for r in doc['engines'] if r['engine'] == engine)


def test_counts_per_engine_and_stratum_with_report_digest(tmp_path):
    shards = write_shards(tmp_path / 's', [report('rz-diff', ['ok'] * 9 + ['blocked']),
                                           report('rz-diff', ['ok'], stratum='noise', prefix='n')])
    doc = C.summarize(shards)
    row = cell(doc)
    assert doc['contract'] == C.CONTRACT and doc['shards'] == 2
    assert (row['attempted'], row['completed'], row['blocked'], row['failed']) == (11, 10, 1, 0)
    strata = {s['stratum']: s for s in row['strata']}
    assert (strata['authored']['attempted'], strata['authored']['completed']) == (10, 9)
    assert strata['noise']['completion'] == 1.0
    assert doc['report_sha256'] == S.merge(S.load_shards(shards))[0]['report_sha256']
    assert doc['status'] == 'ok' and doc['warnings'] == []     # 10 of 11 is above 90%


def test_completion_below_90_percent_warns_but_does_not_fail(tmp_path):
    doc = C.summarize(write_shards(tmp_path / 's', [report('rz-diff', ['ok'] * 8 + ['failed', 'blocked'])]))
    assert doc['status'] == 'warning' and 'only 8 of 10 pairs completed (below 90%)' in doc['warnings'][0]
    assert (cell(doc)['blocked'], cell(doc)['failed']) == (1, 1)
    assert C.EXIT[doc['status']] == 0


def test_engine_without_any_pair_is_reported_not_omitted(tmp_path):
    shards = write_shards(tmp_path / 's', [report('rz-diff', ['ok'])])
    path = shards / 'shard-0.json'
    doc = json.loads(path.read_text(encoding='utf-8'))
    doc['engines'] = ['rz-diff', 'ghidriff']
    doc['shard_sha256'] = S.digest(doc, 'shard_sha256')
    path.write_text(json.dumps(doc), encoding='utf-8')
    out = C.summarize(shards)
    assert cell(out, 'ghidriff')['attempted'] == 0 and cell(out, 'ghidriff')['completion'] is None
    assert out['status'] == 'warning' and 'ghidriff: no pair was attempted' in out['warnings'][0]


def test_failed_cases_make_the_status_failed(tmp_path):
    doc = C.summarize(write_shards(tmp_path / 's', [report('rz-diff', ['ok'])], case_status='timeout'))
    assert doc['status'] == 'failed' and doc['cases'] == {'timeout': 1} and C.EXIT['failed'] == 1


@pytest.mark.parametrize('damage', ['empty', 'garbage', 'missing'], ids=['empty', 'garbage', 'missing'])
def test_damaged_shard_set_is_an_error_status_never_silence(tmp_path, damage):
    shards = write_shards(tmp_path / 's', [report('rz-diff', ['ok']), report('rz-diff', ['ok'])])
    if damage == 'empty':
        for p in shards.glob('*.json'):
            p.unlink()
    elif damage == 'garbage':
        (shards / 'shard-1.json').write_text('{not json', encoding='utf-8')
    else:
        (shards / 'shard-1.json').unlink()
    doc = C.summarize(shards)
    assert doc['status'] == 'error' and 'shard set rejected' in doc['reason'] and doc['report_sha256'] is None
    out = tmp_path / 'out' / 'ci-summary.json'
    assert C.main(['summarize', '--shards', str(shards), '--out', str(out)]) == C.USAGE
    assert json.loads(out.read_text(encoding='utf-8'))['status'] == 'error'
    assert 'Tier R CI status: error' in out.with_suffix('.md').read_text(encoding='utf-8')


def test_summary_is_deterministic_and_main_writes_both_files(tmp_path, capsys):
    shards = write_shards(tmp_path / 's', [report('rz-diff', ['ok', 'ok'])])
    a, b = tmp_path / 'a' / 'ci-summary.json', tmp_path / 'b' / 'ci-summary.json'
    assert C.main(['summarize', '--shards', str(shards), '--out', str(a)]) == 0
    assert C.main(['summarize', '--shards', str(shards), '--out', str(b)]) == 0
    assert a.read_bytes() == b.read_bytes() and b'\r' not in a.read_bytes()
    assert '| rz-diff | all | 2 | 2 | 0 | 0 |' in a.with_suffix('.md').read_text(encoding='utf-8')
    assert json.loads(capsys.readouterr().out.splitlines()[0])['status'] == 'ok'


def merged(tmp_path: Path, name: str, sha: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / 'tier-r-aggregate.json').write_text(json.dumps({'report_sha256': sha}), encoding='utf-8')
    return d


def test_determinism_compares_report_digests(tmp_path, capsys):
    one, same, other = (merged(tmp_path, 'one', 'a' * 64), merged(tmp_path, 'same', 'a' * 64),
                        merged(tmp_path, 'other', 'b' * 64))
    assert C.main(['determinism', str(one), str(same)]) == 0
    assert C.main(['determinism', str(one), str(other)]) == 1
    assert json.loads(capsys.readouterr().out.splitlines()[-1])['status'] == 'failed'
    assert C.main(['determinism', str(one), str(tmp_path / 'nowhere')]) == C.USAGE


def test_two_real_merges_of_the_same_shards_agree(tmp_path):
    shards = write_shards(tmp_path / 's', [report('rz-diff', ['ok']), report('rz-diff', ['ok'], prefix='q')])
    for name in ('m1', 'm2'):
        S.write_merge(*S.merge(S.load_shards(shards)), tmp_path / name)
    assert C.determinism(tmp_path / 'm1', tmp_path / 'm2')['status'] == 'ok'


# ---- workflow --------------------------------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def wf() -> dict:
    yaml = pytest.importorskip('yaml')
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def test_nightly_smoke_and_noise_run_on_a_pinned_label(wf):
    crons = [s['cron'] for s in wf[True]['schedule']]
    assert len(crons) == 2 and all(re.fullmatch(r'\d+ \d+ \* \* \*', c) for c in crons)
    subset = wf['env']['SUBSET']
    assert crons[1] in subset and "'noise'" in subset and "'smoke'" in subset
    linux = [j['runs-on'] for j in wf['jobs'].values() if 'ubuntu' in str(j['runs-on'])]
    assert linux and set(linux) == {'ubuntu-24.04'}, 'pin the image: ubuntu-latest moves to 26.04'


def test_heavy_matrices_stay_dispatch_only(wf):
    inputs = wf[True]['workflow_dispatch']['inputs']
    assert inputs['subset']['default'] == 'smoke' and inputs['engines']['default'] == 'rz-diff'
    assert wf['env']['ENGINES'] == "${{ inputs.engines || 'rz-diff' }}"     # scheduled runs: rz-diff only


def test_merge_job_runs_determinism_and_the_never_silent_summary(wf):
    steps = wf['jobs']['merge']['steps']
    runs = [s.get('run', '') for s in steps]
    first = next(i for i, r in enumerate(runs) if 'shard merge' in r and '--out merged\n' in r + '\n')
    again = next(i for i, r in enumerate(runs) if '--out merged-again' in r)
    assert first < again and 'ci_summary determinism merged merged-again' in runs[again]
    summary = next(s for s in steps if 'ci_summary summarize' in s.get('run', ''))
    assert summary['if'] == 'always()' and '--out merged/ci-summary.json' in summary['run']


def test_artifacts_hold_only_labels_and_reports(wf):
    paths = [s['with']['path'] for j in wf['jobs'].values() for s in j['steps']
             if str(s.get('uses', '')).startswith('actions/upload-artifact')]
    # the MSVC advisory leg uploads its toolchain probe and status files only
    assert sorted(paths) == ['merged/', 'msvc-toolchain.json\nmsvc-status/\n', 'plan.json', 'shard-out/shard-*.json',
                             'shard-out/shard-*.json']
