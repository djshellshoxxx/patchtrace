"""Tier R sharding (SPEC-32 s13): deterministic plan, fault-tolerant shard run, fail-loud merge. Hermetic: the runner is
a fake, no compiler/rizin/Ghidra/network is needed."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import shard as S  # noqa: E402
from tools.calibration.tier_r.contracts import load_report  # noqa: E402
from tools.calibration.tier_r.schemas import example_report  # noqa: E402


def write_tree(tmp_path: Path) -> Path:
    root = tmp_path / 'repo'
    for name in ('_template/tiny', 'cwe-patterns/arena', 'compiler-noise/loops'):
        d = root / 'corpus/ours' / name
        d.mkdir(parents=True)
        (d / 'suite.json').write_text('{}')
    cat = root / 'tools/calibration/tier_r/catalogue'
    cat.mkdir(parents=True)
    (cat / 'recipes.json').write_text(json.dumps({'recipes': [{'project': 'zlib'}, {'project': 'gpl-thing'}]}))
    card = {'contract': 'case-card/1', 'id': 'zlib-a-to-b', 'project': 'zlib', 'license_spdx': 'Zlib'}
    gpl = {'contract': 'case-card/1', 'id': 'gpl-a-to-b', 'project': 'gpl-thing', 'license_spdx': 'GPL-2.0-only'}
    norec = {'contract': 'case-card/1', 'id': 'x-a-to-b', 'project': 'x', 'license_spdx': 'MIT'}
    (cat / 'releases.json').write_text(json.dumps([card, gpl, norec]))
    return root


def fake_runner(argv, timeout, env, *, fail=(), hang=()):
    step = argv[3:]
    text = ' '.join(step)
    if any(f in text for f in hang):
        return None, '', 'timeout'
    if any(f in text for f in fail):
        return 2, '', None
    if step[0] == 'evaluate':
        return 0, json.dumps(make_report(step[2], 'pair-' + env['PATCHTRACE_CALIB_ROOT'][-8:])), None
    pid = text.replace(' ', '-').replace('/', '_')
    summary = {'contract': 'known-answer-labels/1', 'pair_id': pid[:60], 'stratum': 'authored', 'project': 'p',
               'summary': {'records': 3}, 'digest_sha256': 'a' * 64, 'functions': [{'name': 'SECRET'}],
               'image': 'MZ-bytes'}
    return 0, 'noise line\n' + json.dumps(summary), None


def make_report(engine: str, pair='pair-a', version='0.9.1') -> dict:
    r = copy.deepcopy(example_report())
    r['inputs'] = [{'pair_id': pair, 'stratum': 'authored', 'labels_digest': 'f' * 64}]
    r['engines'] = [{'engine': engine, 'status': 'ok', 'version': version, 'reason': None, 'runs': 1, 'failures': 0}]
    m = r['strata']['authored']['rz-diff']
    r['strata'] = {'authored': {engine: m}}
    r['pairs'] = [{**r['pairs'][0], 'pair_id': pair, 'engine': engine}]
    r['report_sha256'] = S.digest(r, 'report_sha256')
    return r


@pytest.fixture
def tree(tmp_path):
    return write_tree(tmp_path)


def plan_for(tree, **kw):
    kw.setdefault('seed', 7)
    kw.setdefault('shards', 3)
    kw.setdefault('subset', 'full')
    return S.make_plan(tree, **kw)


def run_all(plan, out, **kw):
    runner = kw.pop('runner', fake_runner)
    for i in range(plan['of']):
        S.write_shard(S.run_shard(plan, i, runner=runner, **kw), out)


# ---- plan ------------------------------------------------------------------------------------------------------------

def test_plan_is_deterministic_and_partitions(tree):
    a, b = plan_for(tree), plan_for(tree)
    assert a == b
    flat = [c for s in a['shards'] for c in s['cases']]
    assert len(flat) == len(set(flat)) == a['cases_total']
    assert set(flat) == set(S.enumerate_cases(tree, subset='full', seed=7))
    sizes = [len(s['cases']) for s in a['shards']]
    assert max(sizes) - min(sizes) <= 1


def test_plan_seed_changes_assignment_not_membership(tree):
    a, b = plan_for(tree, seed=1), plan_for(tree, seed=2)
    assert a['shards'] != b['shards']
    assert a['plan_sha256'] != b['plan_sha256']


def test_matrix_shape_for_actions(tree):
    m = S.matrix(plan_for(tree))
    assert set(m) == {'include'}
    for i, item in enumerate(m['include']):
        assert item['shard'] == i and item['of'] == len(m['include']) and isinstance(item['cases'], list)
    json.dumps(m)


def test_shards_clamped_to_case_count(tree):
    plan = S.make_plan(tree, seed=1, shards=50, subset='smoke')
    assert plan['of'] == plan['cases_total'] == len(S.enumerate_cases(tree, subset='smoke', seed=1))


@pytest.mark.parametrize('kwargs', [{'shards': 0}, {'shards': 999}, {'subset': 'bogus'}, {'engines': 'ida'}],
                         ids=['zero', 'too-many', 'bad-subset', 'bad-engine'])
def test_plan_rejects_bad_arguments(tree, kwargs):
    with pytest.raises(S.ShardError):
        plan_for(tree, **kwargs)


def test_cards_filtered_by_recipe_and_licence(tree):
    cards = [c for c in S.enumerate_cases(tree, subset='cards', seed=1)]
    assert cards == ['card:zlib-a-to-b']


def test_subset_smoke_contents(tree):
    cases = S.enumerate_cases(tree, subset='smoke', seed=3)
    assert 'suite:_template/tiny' in cases and 'card:zlib-a-to-b' in cases
    assert any(c.startswith('mutate:_template/tiny:cmp-flip:3000') for c in cases)


# ---- refusal ---------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('case', ['card:ntoskrnl.exe', 'suite:tier-w/afd', 'card:Microsoft-thing', 'aa:tw.pair',
                                  'suite:x/system32'], ids=['kernel', 'tier-w', 'microsoft', 'tw-pair', 'system32'])
def test_microsoft_cases_refused(case):
    with pytest.raises(S.ShardError, match='refused'):
        S.case_steps(case)


def test_family_names_refused():
    with pytest.raises(S.ShardError, match='refused'):
        S.refuse_microsoft('corpus/ours/g/afd.sys')


def test_output_inside_tier_w_refused(tmp_path):
    with pytest.raises(S.ShardError, match='tier-w'):
        S.write_shard({'shard': 0}, tmp_path / 'tier-w' / 'out')


@pytest.mark.parametrize('case', ['bogus', 'suite:../etc', 'mutate:g/n:nope:1', 'card:'], ids=['junk', 'dotdot', 'op', 'empty'])
def test_malformed_case_ids(case):
    with pytest.raises(S.ShardError):
        S.case_steps(case)


def test_case_steps_argv():
    assert S.case_steps('card:zlib-a') == [['fetch', 'zlib-a'], ['build-card', 'zlib-a']]
    assert S.case_steps('mutate:g/n:cmp-flip:12')[0][-4:] == ['--operator', 'cmp-flip', '--seed', '12']


# ---- run-shard -------------------------------------------------------------------------------------------------------

def test_run_shard_aggregate_only_and_deterministic(tree, tmp_path):
    plan = plan_for(tree)
    doc = S.run_shard(plan, 0, runner=fake_runner, scratch=tmp_path / 'scratch')
    again = S.run_shard(plan, 0, runner=fake_runner, scratch=tmp_path / 'scratch')
    assert doc == again
    text = json.dumps(doc)
    assert 'SECRET' not in text and 'MZ-bytes' not in text
    assert doc['labels'] and doc['reports']
    path = S.write_shard(doc, tmp_path / 'out')
    assert path.name == 'shard-0.json'


def test_run_shard_survives_failure_and_timeout(tree):
    plan = plan_for(tree, shards=1)
    doc = S.run_shard(plan, 0, runner=lambda a, t, e: fake_runner(a, t, e, fail=['arena'], hang=['loops']))
    status = {c['id']: c['status'] for c in doc['cases']}
    assert status['suite:cwe-patterns/arena'] == 'failed'
    assert status['suite:compiler-noise/loops'] == 'timeout'
    assert status['suite:_template/tiny'] == 'ok'


def test_run_shard_rejects_tampered_plan(tree):
    plan = plan_for(tree)
    plan['seed'] = 99
    with pytest.raises(S.ShardError, match='digest'):
        S.run_shard(plan, 0, runner=fake_runner)


def test_sanitize_limits():
    assert S.sanitize({'functions': [1], 'a': {'image': 'x', 'b': 1}}) == {'a': {'b': 1}}
    with pytest.raises(S.ShardError):
        S.sanitize({'a': 'x' * 3000})
    with pytest.raises(S.ShardError):
        S.sanitize({'a': float('nan')})


def test_result_text_with_microsoft_marker_refused(tree):
    plan = plan_for(tree, shards=1)

    def bad(argv, timeout, env):
        return 0, json.dumps({'note': 'Microsoft Corporation'}), None
    with pytest.raises(S.ShardError, match='refused'):
        S.run_shard(plan, 0, runner=bad)


# ---- merge -----------------------------------------------------------------------------------------------------------

def shard_dir(tree, tmp_path, **kw):
    plan = plan_for(tree, **kw)
    out = tmp_path / 'shards'
    run_all(plan, out)
    return plan, out


def test_merge_roundtrip_and_digest_stability(tree, tmp_path):
    plan, out = shard_dir(tree, tmp_path)
    r1, p1 = S.merge(S.load_shards(out, plan=plan))
    r2, p2 = S.merge(S.load_shards(out, plan=plan))
    assert r1 == r2 and p1 == p2
    load_report(json.dumps(r1).encode())
    assert [e['engine'] for e in r1['engines']] == ['rz-diff']
    assert r1['engines'][0]['runs'] == plan['of']
    assert r1['strata']['authored']['rz-diff']['pairs'] == plan['of']
    paths = S.write_merge(r1, p1, tmp_path / 'merged')
    assert {p.name for p in paths} == {'tier-r-aggregate.json', 'tier-r-merge.json', 'tier-r-report.md'}
    assert 'Aggregate metrics only' in paths[2].read_text()


def test_merge_sums_counts_and_recomputes_ratios():
    a, b = make_report('rz-diff', 'p1'), make_report('rz-diff', 'p2')
    docs = [shard_doc(0, [a]), shard_doc(1, [b])]
    report, _ = S.merge(docs)
    m = report['strata']['authored']['rz-diff']
    assert m['pairs'] == 2 and m['identity_tp'] == 6 and m['changed_fp'] == 2
    assert m['changed_precision'] == 0.5 and m['identity_recall'] == 1.0 and m['fp_rate'] == 0.5
    assert [p['pair_id'] for p in report['pairs']] == ['p1', 'p2']


def shard_doc(i, reports, of=2, cases=()):
    doc = {'contract': S.SHARD_CONTRACT, 'shard': i, 'of': of, 'seed': 1, 'plan_sha256': 'b' * 64, 'subset': 'smoke',
           'engines': ['rz-diff'], 'cases': list(cases), 'labels': [], 'features': [], 'reports': reports}
    doc['shard_sha256'] = S.digest(doc, 'shard_sha256')
    return doc


def test_merge_rejects_duplicate_pair_across_shards():
    docs = [shard_doc(0, [make_report('rz-diff', 'same')]), shard_doc(1, [make_report('rz-diff', 'same')])]
    with pytest.raises(S.ShardError, match='more than one shard'):
        S.merge(docs)


def test_merge_rejects_mixed_engine_versions():
    docs = [shard_doc(0, [make_report('rz-diff', 'a', '0.9.1')]), shard_doc(1, [make_report('rz-diff', 'b', '0.8.0')])]
    with pytest.raises(S.ShardError, match='different versions'):
        S.merge(docs)


def test_merge_marks_engine_without_results_blocked():
    report, _ = S.merge([shard_doc(0, []), shard_doc(1, [])])
    assert report['engines'][0]['status'] == 'blocked'


@pytest.mark.parametrize('damage', ['missing', 'duplicate', 'foreign-plan', 'tamper', 'rename', 'empty'])
def test_load_shards_fails_loud(tree, tmp_path, damage):
    plan, out = shard_dir(tree, tmp_path)
    files = sorted(out.glob('shard-*.json'))
    if damage == 'missing':
        files[1].unlink()
    elif damage == 'duplicate':
        (out / 'shard-9.json').write_bytes(files[0].read_bytes())
    elif damage == 'foreign-plan':
        other = S.run_shard(plan_for(tree, seed=8), 0, runner=fake_runner)
        S.write_shard(other, out)
    elif damage == 'tamper':
        doc = json.loads(files[0].read_text())
        doc['cases'][0]['status'] = 'ok' if doc['cases'][0]['status'] != 'ok' else 'failed'
        files[0].write_text(json.dumps(doc))
    elif damage == 'rename':
        files[0].rename(out / 'shard-5.json')
    else:
        for f in files:
            f.unlink()
    with pytest.raises(S.ShardError):
        S.load_shards(out, plan=plan)


def test_load_shards_checks_planned_cases(tree, tmp_path):
    plan, out = shard_dir(tree, tmp_path)
    doc = json.loads((out / 'shard-0.json').read_text())
    doc['cases'].pop(0)
    doc['shard_sha256'] = S.digest(doc, 'shard_sha256')
    (out / 'shard-0.json').write_text(json.dumps(doc))
    with pytest.raises(S.ShardError, match='planned cases'):
        S.load_shards(out, plan=plan)


# ---- CLI -------------------------------------------------------------------------------------------------------------

def test_cli_plan_run_merge(tree, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(S, 'default_runner', fake_runner)
    monkeypatch.setattr(S, 'run_shard', _bind_fake(S.run_shard))
    gh = tmp_path / 'gh_out'
    monkeypatch.setenv('GITHUB_OUTPUT', str(gh))
    assert S.main(['plan', '--root', str(tree), '--seed', '5', '--shards', '2', '--subset', 'suites',
                   '--plan-out', str(tmp_path / 'plan.json')]) == 0
    matrix = json.loads(capsys.readouterr().out)
    assert len(matrix['include']) == 2 and gh.read_text().startswith('matrix=')
    for entry in matrix['include']:
        assert S.main(['run-shard', '--shard', str(entry['shard']), '--of', '2', '--seed', '5',
                       '--plan-sha256', entry['plan'], '--cases', json.dumps(entry['cases']),
                       '--subset', 'suites', '--out', str(tmp_path / 'sh')]) == 0
    assert S.main(['merge', '--in', str(tmp_path / 'sh'), '--plan', str(tmp_path / 'plan.json'),
                   '--out', str(tmp_path / 'm')]) == 0
    assert (tmp_path / 'm' / 'tier-r-aggregate.json').is_file()


def _bind_fake(real):
    def run(plan, shard, **kw):
        kw.setdefault('runner', fake_runner)
        return real(plan, shard, **kw)
    return run


WORKFLOW = ROOT / '.github/workflows/corpus-tier-r.yml'


def test_workflow_structure_and_pins():
    text = WORKFLOW.read_text()
    assert '9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf' in text
    assert 'c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120' in text
    for line in text.splitlines():
        if 'uses:' in line:
            assert '@v' in line, line
    yaml = pytest.importorskip('yaml')
    doc = yaml.safe_load(text)
    assert set(doc['jobs']) == {'plan', 'shard', 'merge', 'windows-advisory'}
    assert doc[True]['workflow_dispatch']['inputs'].keys() == {'shards', 'seed', 'engines', 'subset'}
    assert 'tools/calibration/**' in doc[True]['push']['paths']
    assert doc['jobs']['windows-advisory']['continue-on-error'] is True
    assert doc['jobs']['shard']['needs'] == 'plan' and set(doc['jobs']['merge']['needs']) == {'plan', 'shard'}
    assert doc['permissions'] == {'contents': 'read'}


def test_cli_merge_missing_shard_exit_code(tree, tmp_path):
    plan, out = shard_dir(tree, tmp_path)
    next(iter(sorted(out.glob('shard-*.json')))).unlink()
    assert S.main(['merge', '--in', str(out), '--out', str(tmp_path / 'm')]) == 2
