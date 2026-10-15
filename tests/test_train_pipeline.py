"""LBL-15 training run: audit-before-fit, controls excluded, minimum-sample guards, deterministic output, train key,
merge-aggregate input, CLI exit codes. Everything runs on a SYNTHETIC Tier R world (hand-made labels and engine outputs):
it checks the pipeline, never a real engine or real binaries. One test builds the committed template suite with the local
toolchain (BLOCKED, recorded, when it is missing)."""
from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

import pytest
from test_train_helpers import engine_output, make_pair_labels, write_world
from tier_r_helpers import require

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from patchtrace.calibration.scope import TIER_R_CLAIM  # noqa: E402
from tools.calibration import fit as fit_module  # noqa: E402
from tools.calibration import train as T  # noqa: E402
from tools.calibration.common import canonical_json, digest  # noqa: E402
from tools.calibration.lineage import assign_roles  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import manifest as M  # noqa: E402
from tools.calibration.tier_r import schemas as S  # noqa: E402

SMOKE = T.TrainConfig.smoke_config()


def run_cli(*argv) -> int:
    return T.main([str(a) for a in argv])


@pytest.fixture(scope='module')
def world(tmp_path_factory):
    folder = tmp_path_factory.mktemp('world')
    labels, outputs = write_world(folder, n_lineages=14, controls=True)
    return labels, outputs


@pytest.fixture(scope='module')
def docs(world):
    return T.build_from_labels(*world)


@pytest.fixture(scope='module')
def result(docs):
    return T.run_training(docs, SMOKE)


# ---- honest scope of the output -------------------------------------------------------------------------------------

def test_report_carries_the_tier_r_claim_and_only_g1(result):
    report = result.report
    assert report['claim'] == TIER_R_CLAIM
    assert report['dataset']['tier'] == 'R' and report['dataset']['feature_schema'] == 'features/1'
    gates = report['gates']
    assert {g: gates[g]['status'] for g in ('G0', 'G2', 'G3')} == dict.fromkeys(('G0', 'G2', 'G3'), 'insufficient-data')
    assert gates['G1']['status'] in ('pass', 'fail', 'insufficient-data') and gates['G1']['reasons']
    (profile,) = report['per_profile'].values()
    assert profile['gates']['G1'] == gates['G1'] or profile['gates']['G1']['status'] == gates['G1']['status']
    assert 'ablations reported: False' in ' '.join(gates['G1']['reasons'])      # smoke run: G1 cannot pass


def test_artifact_is_experimental_displays_nothing_and_cannot_be_promoted(result):
    art = result.artifact
    assert art['status'] == 'experimental' and art['policy']['display'] == 'none'
    dom = art['calibration_domain']
    assert dom['evidence_tiers'] == ['tier-r'] and dom['windows_system_binaries'] == 'none'
    assert 'no-windows-system-binaries' in dom['scope_ids']
    assert art['evidence']['report_sha256'] is None and art['evidence']['gates'] == {}
    with pytest.raises(fit_module.PromotionError):
        fit_module.promote(art, result.report)


def test_markdown_states_the_claim_and_never_a_percent_or_accuracy_claim(result):
    from tools.calibration.report import render_markdown
    text = render_markdown(result.report)
    assert TIER_R_CLAIM in text and '%' not in text.replace('95% CI', '')
    assert 'Shift ladder' in text and '| tier-w |' in text


# ---- determinism and the train key ----------------------------------------------------------------------------------

def test_two_runs_write_byte_identical_reports(world, tmp_path, capsys):
    args = ('run', '--labels', world[0], '--outputs', world[1], '--smoke', '--artifact')
    assert run_cli(*args, '--out', tmp_path / 'a') == 0
    assert run_cli(*args, '--out', tmp_path / 'b') == 0
    capsys.readouterr()
    for name in ('report.json', 'report.md', 'artifact.dev-only.json'):
        assert (tmp_path / 'a' / name).read_bytes() == (tmp_path / 'b' / name).read_bytes()
    assert json.loads((tmp_path / 'a' / 'report.json').read_text())['dataset']['train_key']


def test_input_order_does_not_change_the_report(docs, result):
    again = T.run_training(list(reversed(docs)), SMOKE)
    assert canonical_json(again.report) == canonical_json(result.report)


KEY = dict(manifest_sha='1' * 64, label_set_sha='2' * 64, engine_run_digests=['3' * 64, '4' * 64],
           config_digest='5' * 64, prereg_sha='6' * 64)


@pytest.mark.parametrize('field,value', [
    pytest.param('manifest_sha', 'a' * 64, id='manifest'), pytest.param('label_set_sha', 'b' * 64, id='labels'),
    pytest.param('engine_run_digests', ['3' * 64], id='engine-runs'),
    pytest.param('config_digest', 'c' * 64, id='config'), pytest.param('prereg_sha', 'd' * 64, id='prereg'),
    pytest.param('prereg_sha', None, id='prereg-placeholder')])
def test_train_key_depends_on_each_component(field, value):
    base = T.train_key(**KEY)
    assert T.train_key(**{**KEY, field: value}) != base
    assert T.train_key(**{**KEY, 'engine_run_digests': KEY['engine_run_digests'][::-1]}) == base


def test_train_key_in_report_follows_config_and_prereg(docs, result, tmp_path):
    prereg = tmp_path / 'prereg.md'
    prereg.write_bytes(b'locked text')
    key = result.report['dataset']['train_key']
    locked = T.run_training(docs, SMOKE, prereg_sha=T._prereg_sha(str(prereg)))
    assert locked.train_key != key and locked.report['prereg_sha256'] and locked.report['dataset']['preregistered']
    assert result.report['prereg_sha256'] is None
    assert any('not locked' in b for b in result.report['blind_spots'])
    other = T.run_training(docs, T.TrainConfig(**{**SMOKE.__dict__, 'seed': 2}))
    assert other.train_key != key


# ---- guards before any fit ------------------------------------------------------------------------------------------

def test_controls_never_count_as_evidence(docs, result):
    controls = sorted(d.pair_id for d in docs if d.stratum in ('aa', 'mutation'))
    assert controls and result.report['dataset']['controls_excluded'] == {'aa': 3, 'mutation': 3}
    bundle = T.assemble(docs)
    rows, *_ = T.build_rows(bundle, SMOKE)
    assert not any(r.id.split('|')[0] in controls for r in rows)
    assert result.report['dataset']['n_pairs'] - result.report['dataset']['n_pairs_evidence'] == len(controls)


def split_violating_docs(tmp_path):
    """Two lineages of different roles that claim the same source project: a leak across the split."""
    names = [f'leak{i:02d}' for i in range(40)]
    roles = assign_roles(names, 'c9-v1')
    a = next(n for n in names if roles[n] == 'dev')
    b = next(n for n in names if roles[n] == 'locked-test')
    docs = []
    for name in (a, b):
        labels = make_pair_labels(name, n_funcs=8)
        raw = labels.model_dump(mode='json')
        for side in ('older', 'newer'):
            raw[side]['source']['suite'] = 'ours/shared'
        raw = C.finalize_labels(raw)
        labels = C.load_labels(C.dump_json(raw))
        docs.append(T.build_pair_rows(labels, {}, 'G'))
    return docs


def test_leakage_audit_blocks_every_fit(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError('a fit ran before the split audit passed')
    monkeypatch.setattr(T, 'run_pipeline', forbidden)
    docs = split_violating_docs(tmp_path)
    with pytest.raises(T.TrainError, match='PT-KA-LEAK') as err:
        T.run_training(docs, SMOKE)
    assert err.value.exit_code == T.FINDINGS
    rows_dir = tmp_path / 'rows'
    rows_dir.mkdir()
    for d in docs:
        (rows_dir / f'{d.pair_id}.json').write_bytes(canonical_json(d.model_dump(mode='json')))
    assert run_cli('run', '--rows', rows_dir, '--out', tmp_path / 'out', '--smoke') == T.FINDINGS
    assert not (tmp_path / 'out' / 'report.json').exists()


def test_one_image_in_two_lineages_is_refused_before_any_fit():
    names = [f'img{i:02d}' for i in range(40)]
    roles = assign_roles(names, 'c9-v1')
    a = next(n for n in names if roles[n] == 'dev')
    b = next(n for n in names if roles[n] == 'locked-test')
    docs = [T.build_pair_rows(make_pair_labels(n, n_funcs=4, tag='same-images'), {}, 'G') for n in (a, b)]
    with pytest.raises(T.TrainError, match='PT-KA-LEAK|PT-KA-EVAL'):
        T.assemble(docs)


def test_minimum_sample_guard_reports_instead_of_fitting(tmp_path, monkeypatch):
    monkeypatch.setattr(T, 'run_pipeline', lambda *a, **k: pytest.fail('fit must not run below the minimum sample'))
    labels, outputs = write_world(tmp_path, n_lineages=3, n_funcs=12)
    docs = T.build_from_labels(labels, outputs)
    res = T.run_training(docs, SMOKE)
    report = res.report
    assert report['claim'] == TIER_R_CLAIM and res.artifact is None
    assert {g['status'] for g in report['gates'].values()} == {'insufficient-data'}
    (profile,) = report['per_profile'].values()
    assert profile['status'] == 'insufficient-data' and any('CV groups' in r or 'rows' in r for r in profile['reasons'])
    rungs = {r['rung']: r for r in res.shift['rungs']}
    assert rungs['tier-w']['status'] == 'not-run'
    assert all(r['status'] in ('insufficient-data', 'not-run') for r in res.shift['rungs'])


def test_indeterminate_and_ambiguous_candidates_are_excluded_and_counted():
    labels = make_pair_labels('amb', n_funcs=8)
    raw = labels.model_dump(mode='json')
    for f in raw['functions']:
        if f['name'] == 'amb_f1':
            f.update(label='ambiguous', identity='ambiguous', change_kind=None, body='different', check='unchecked')
    labels = C.load_labels(C.dump_json(C.finalize_labels(raw)))
    out = engine_output(labels, 'rz-diff')
    out['predictions'] = [p for p in out['predictions'] if p['old_rva'] != 0x1020] + [
        {'old_rva': 0x1020, 'new_rva': 0x1020, 'changed': True, 'similarity_milli': 500, 'old_name': None,
         'new_name': None}]
    out['predictions'].sort(key=lambda p: (p['old_rva'], p['new_rva']))
    from tools.calibration.tier_r import report_schemas as RS
    parsed = RS.load_engine_output(canonical_json(out))
    doc = T.build_pair_rows(labels, {'rz-diff': (T._output_from_doc(parsed), 'e' * 64)}, 'G+R')
    assert doc.excluded == {'indeterminate': 1}
    assert not any(r.id.endswith(f'{0x1020:x}:{0x1020:x}') for r in doc.rows)


def test_assembled_manifest_equals_the_label_manifest(world, docs):
    from tools.calibration.tier_r.evaluate import load_label_dir
    assert T.assemble_manifest(docs) == M.build_manifest(load_label_dir(world[0]))


# ---- input documents ------------------------------------------------------------------------------------------------

def test_feature_rows_digest_and_columns_are_checked(docs):
    good = docs[0].model_dump(mode='json')
    assert T.load_pair_rows(canonical_json(good)).pair_id == docs[0].pair_id
    tampered = copy.deepcopy(good)
    tampered['rows'][0]['y'] = 1 - tampered['rows'][0]['y']
    with pytest.raises(T.TrainError, match='digest mismatch'):
        T.load_pair_rows(canonical_json(tampered))
    bad_cols = copy.deepcopy(good)
    bad_cols['columns'] = bad_cols['columns'][:-1]
    with pytest.raises(T.TrainError, match='columns'):
        T.load_pair_rows(canonical_json(T._finish(bad_cols)))


def test_visible_symbol_outputs_and_duplicates_are_refused(world, tmp_path):
    out = tmp_path / 'outputs'
    out.mkdir()
    first = sorted(world[1].glob('*.json'))[0]
    doc = json.loads(first.read_bytes())
    (out / 'a.json').write_bytes(canonical_json(doc))
    (out / 'b.json').write_bytes(canonical_json(doc))
    with pytest.raises(T.TrainError, match='second engine output'):
        T.load_outputs(out)
    (out / 'b.json').unlink()
    (out / 'a.json').write_bytes(canonical_json(dict(doc, symbols='visible')))
    with pytest.raises(T.TrainError, match='visible symbols'):
        T.load_outputs(out)


# ---- merged shard aggregate as input --------------------------------------------------------------------------------

def make_merge(docs, tmp_path, *, with_aggregate=True):
    prov = {'contract': 'tier-r-merge/1', 'plan_sha256': 'a' * 64, 'seed': 1, 'subset': 'smoke', 'shards': [],
            'cases': [], 'failing_cases': [], 'labels': [],
            'features': sorted((d.model_dump(mode='json') for d in docs), key=canonical_json)}
    agg = copy.deepcopy(S.example_report())
    agg['inputs'] = [{'pair_id': d.pair_id, 'stratum': d.stratum, 'labels_digest': d.label_digest} for d in docs]
    agg['report_sha256'] = digest(agg, 'report_sha256')
    prov['report_sha256'] = agg['report_sha256']
    prov['merge_sha256'] = digest(prov, 'merge_sha256')
    merge, aggregate = tmp_path / 'merge.json', tmp_path / 'aggregate.json'
    merge.write_bytes(canonical_json(prov))
    aggregate.write_bytes(canonical_json(agg))
    return merge, aggregate, prov, agg


def test_merge_input_gives_the_same_run_as_labels_input(docs, result, tmp_path, capsys):
    merge, aggregate, *_ = make_merge(docs, tmp_path)
    assert run_cli('run', '--merge', merge, '--aggregate', aggregate, '--smoke', '--out', tmp_path / 'm') == 0
    capsys.readouterr()
    report = json.loads((tmp_path / 'm' / 'report.json').read_text())
    assert report['dataset']['origin'] == 'merge' and report['dataset']['merge']['merge_sha256']
    assert report['dataset']['train_key'] == result.report['dataset']['train_key']
    assert report['per_profile'] == json.loads(canonical_json(result.report['per_profile']))
    assert report['gates'] == json.loads(canonical_json(result.report['gates']))


@pytest.mark.parametrize('damage,code', [
    pytest.param('merge-digest', T.USAGE, id='merge-digest'),
    pytest.param('aggregate-sha', T.USAGE, id='aggregate-sha'),
    pytest.param('label-digest', T.USAGE, id='label-digest'),
    pytest.param('no-features', T.BLOCKED, id='no-features')])
def test_merge_input_failures_are_loud(docs, tmp_path, capsys, damage, code):
    merge, aggregate, prov, agg = make_merge(docs, tmp_path)
    if damage == 'merge-digest':
        merge.write_bytes(canonical_json(dict(prov, seed=2)))
    elif damage == 'aggregate-sha':
        agg['notes'] = ['edited']
        aggregate.write_bytes(canonical_json(agg))
    elif damage == 'label-digest':
        agg['inputs'][0]['labels_digest'] = 'f' * 64
        agg['report_sha256'] = digest(agg, 'report_sha256')
        prov['report_sha256'] = agg['report_sha256']
        prov['merge_sha256'] = digest(prov, 'merge_sha256')
        aggregate.write_bytes(canonical_json(agg))
        merge.write_bytes(canonical_json(prov))
    else:
        prov['features'] = []
        prov['merge_sha256'] = digest(prov, 'merge_sha256')
        merge.write_bytes(canonical_json(prov))
    assert run_cli('run', '--merge', merge, '--aggregate', aggregate, '--smoke', '--out', tmp_path / 'o') == code
    assert not (tmp_path / 'o' / 'report.json').exists()
    assert capsys.readouterr().err


# ---- CLI ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('argv,code', [
    pytest.param(['run', '--out', 'x'], T.USAGE, id='no-input'),
    pytest.param(['run', '--labels', 'x', '--rows', 'y', '--out', 'x'], T.USAGE, id='two-inputs'),
    pytest.param(['run', '--labels', 'x', '--out', 'x'], T.USAGE, id='labels-without-outputs'),
    pytest.param(['bogus'], T.USAGE, id='bad-command'),
    pytest.param(['report', 'missing-report.json'], T.USAGE, id='report-missing')])
def test_cli_usage_errors_exit_2(argv, code, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert run_cli(*argv) == code


def test_cli_blocked_when_no_engine_output_exists(world, tmp_path, capsys):
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert run_cli('run', '--labels', world[0], '--outputs', empty, '--out', tmp_path / 'o') == T.BLOCKED
    assert 'PT-KA-BLOCKED' in capsys.readouterr().err


def test_shift_subcommand_writes_only_the_ladder(world, tmp_path, capsys):
    assert run_cli('shift', '--labels', world[0], '--outputs', world[1], '--smoke', '--out', tmp_path) == 0
    capsys.readouterr()
    ladder = json.loads((tmp_path / 'shift.json').read_text())
    assert ladder['contract'] == 'calibration-shift/1' and not (tmp_path / 'report.json').exists()
    assert ladder['rungs'][-1]['rung'] == 'tier-w' and ladder['rungs'][-1]['status'] == 'not-run'


def test_report_subcommand_verifies_then_renders(result, tmp_path, capsys):
    path = tmp_path / 'report.json'
    path.write_bytes(canonical_json(result.report))
    assert run_cli('report', path, '--out', tmp_path / 'r.md') == 0
    assert TIER_R_CLAIM in (tmp_path / 'r.md').read_text(encoding='utf-8')
    forged = dict(result.report, claim='Accurate on Windows')
    path.write_bytes(canonical_json(forged))
    capsys.readouterr()
    assert run_cli('report', path) == T.USAGE


# ---- end to end on the committed template suite ----------------------------------------------------------------------

def test_template_suite_end_to_end_under_a_minute(record_live_status, tmp_path, monkeypatch, capsys):
    """Real clang/lld build of corpus/ours/_template/tiny; the engine outputs are SYNTHETIC (a built pair has too few
    functions for any fit, so every gate is insufficient-data and the run still ends with a valid report)."""
    require(record_live_status, 'msvc-free')
    from tools.calibration.tier_r import cli
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'calib'))
    started = time.monotonic()
    assert cli.main(['build-suite', str(ROOT / 'corpus' / 'ours' / '_template' / 'tiny')]) == 0
    capsys.readouterr()
    labels_dir = tmp_path / 'calib' / 'known-answer' / 'labels'
    outputs = tmp_path / 'outputs'
    outputs.mkdir()
    for path in sorted(labels_dir.glob('ours-*.json')):
        labels = C.load_labels(path.read_bytes())
        for engine in ('ghidriff', 'rz-diff'):
            (outputs / f'{labels.pair_id}.{engine}.json').write_bytes(canonical_json(engine_output(labels, engine)))
    only = tmp_path / 'only'
    only.mkdir()
    for path in sorted(labels_dir.glob('ours-*.json')):
        (only / path.name).write_bytes(path.read_bytes())
    assert run_cli('run', '--labels', only, '--outputs', outputs, '--smoke', '--out', tmp_path / 'out') == 0
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert time.monotonic() - started < 60
    assert report['claim'] == TIER_R_CLAIM and report['dataset']['n_natural'] > 0
    assert {g['status'] for g in report['gates'].values()} == {'insufficient-data'}


def test_larger_world_scores_every_shift_rung_with_the_frozen_tau(tmp_path):
    labels, outputs = write_world(tmp_path, n_lineages=27, n_funcs=20)
    res = T.run_training(T.build_from_labels(labels, outputs), SMOKE)
    (profile,) = res.report['per_profile'].values()
    rungs = profile['shift']['rungs']
    scored = [r for r in rungs if r['status'] == 'ok']
    assert {r['rung'] for r in scored} == {'grouped-cv-within-toolchain', 'leave-one-toolchain-out',
                                           'leave-one-family-out'}
    tau = (profile['tau_selection'] or {}).get('tau')
    assert profile['shift']['tau'] == (None if tau is None else tau['tau'])
    assert all(r['n_lineages'] >= 3 and r['forced_accuracy'] is not None for r in scored)
    assert profile['gates']['G1']['status'] == res.report['gates']['G1']['status']
