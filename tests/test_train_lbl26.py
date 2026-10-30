"""LBL-30 (T-03): the LBL-26 pre-lock audit items C-1..C-6 and C-8 in the Tier R training driver. SYNTHETIC data only: no
network, no target binary is executed. C-7 (TIER_R_CLAIM) is covered by test_train_pipeline."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from test_train_helpers import engine_output, make_pair_labels, write_world

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import bootstrap as BS  # noqa: E402
from tools.calibration import evaluate as EV  # noqa: E402
from tools.calibration import train as T  # noqa: E402
from tools.calibration.common import Row, canonical_json  # noqa: E402
from tools.calibration.cv import CVError  # noqa: E402
from tools.calibration.lineage import assign_roles  # noqa: E402
from tools.calibration.report import render_markdown  # noqa: E402
from tools.calibration.tier_r import report_schemas as RS  # noqa: E402

SMOKE = T.TrainConfig.smoke_config()


def run_cli(*argv) -> int:
    return T.main([str(a) for a in argv])


@pytest.fixture(scope='module')
def world(tmp_path_factory):
    return write_world(tmp_path_factory.mktemp('lbl26'), n_lineages=20)


@pytest.fixture(scope='module')
def docs(world):
    return T.build_from_labels(*world)


def restamp(doc: T.PairRows, **changes) -> T.PairRows:
    raw = doc.model_dump(mode='json')
    raw.update(changes)
    return T.load_pair_rows(canonical_json(T._finish(raw)))


def write_docs(folder: Path, docs) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    for d in docs:
        (folder / f'{d.pair_id}.json').write_bytes(canonical_json(d.model_dump(mode='json')))
    return folder


def authored_doc(lineage: str) -> T.PairRows:
    labels = make_pair_labels(lineage, stratum='authored', n_funcs=24, family='fam0')
    outputs = {}
    for engine in T.FEATURE_ENGINES:
        parsed = RS.load_engine_output(canonical_json(engine_output(labels, engine)))
        outputs[engine] = (T._output_from_doc(parsed), 'e' * 64)
    return T.build_pair_rows(labels, outputs, 'G+R')


def no_fit(monkeypatch):
    monkeypatch.setattr(T, 'run_pipeline', lambda *a, **k: pytest.fail('a fit ran although the run must halt'))


# ---- C-1 identity roles ---------------------------------------------------------------------------------------------

def shared_identity_docs(docs):
    roles = assign_roles(sorted({d.lineage for d in docs}), 'c9-v1')
    a = next(d for d in docs if roles[d.lineage] == 'dev')
    b = next(d for d in docs if roles[d.lineage] == 'locked-test')
    out = []
    for doc in docs:
        if doc.pair_id in (a.pair_id, b.pair_id):
            raw = doc.model_dump(mode='json')
            raw['rows'][0]['identities'] = ['src:shared_body|lib/shared.c']      # one non-hub body in two roles
            doc = T.load_pair_rows(canonical_json(T._finish(raw)))
        out.append(doc)
    return out


def test_identity_shared_across_roles_stops_the_run(docs, tmp_path, monkeypatch, capsys):
    no_fit(monkeypatch)
    leaky = shared_identity_docs(docs)
    res = T.run_training(leaky, SMOKE)
    assert res.halt and any('PT-KA-LEAK' in r and 'src:shared_body|lib/shared.c' in r for r in res.halt)
    assert {g['status'] for g in res.report['gates'].values()} == {'insufficient-data'}
    rows_dir = write_docs(tmp_path / 'rows', leaky)
    assert run_cli('run', '--rows', rows_dir, '--out', tmp_path / 'out', '--smoke') == T.FINDINGS
    capsys.readouterr()
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())                  # the report is still written
    assert 'PT-KA-LEAK' in json.dumps(report)


def test_identity_audit_passes_on_a_clean_world(docs):
    assert T.run_training(docs, SMOKE).halt == ()


# ---- C-2 indeterminate share and worst case -------------------------------------------------------------------------

def with_indeterminate(docs, per_pair: int):
    return [restamp(d, excluded={**d.excluded, 'indeterminate': per_pair}) for d in docs]


def test_indeterminate_over_five_percent_adds_worst_case_block(docs):
    res = T.run_training(with_indeterminate(docs, 12), SMOKE)
    (profile,) = res.report['per_profile'].values()
    block = profile['indeterminate']
    assert block['flag_share'] == T.INDETERMINATE_FLAG_SHARE == 0.05
    s = block['strata']['release']
    assert s['share'] > 0.05 and s['flagged'] is True and s['excluded_indeterminate'] == 12 * len(docs)
    worst = s['worst_case']
    assert worst['assumption'].startswith('indeterminate read as y = 0')
    assert worst['precision'] is not None and worst['precision'] <= s['point']['precision']
    assert worst['coverage'] <= s['point']['coverage']
    assert any('indeterminate share' in b for b in res.report['blind_spots'])
    text = render_markdown(res.report)
    assert 'worst case' in text and 'release' in text


def test_indeterminate_under_five_percent_is_not_flagged(docs):
    res = T.run_training(with_indeterminate(docs, 1), SMOKE)
    (profile,) = res.report['per_profile'].values()
    s = profile['indeterminate']['strata']['release']
    assert s['share'] < 0.05 and s['flagged'] is False and s['worst_case'] is None


# ---- C-3 natural only -----------------------------------------------------------------------------------------------

def test_authored_rows_not_in_natural_table(docs, monkeypatch):
    extra = [authored_doc('authz')]
    assert extra[0].rows
    seen = {}
    real = T.run_pipeline

    def spy(rows, **kw):
        seen['rows'] = list(rows)
        return real(rows, **kw)
    monkeypatch.setattr(T, 'run_pipeline', spy)
    base = T.run_training(docs, SMOKE)
    res = T.run_training([*docs, *extra], SMOKE)
    assert seen['rows'] and all(r.stratum == 'natural' for r in seen['rows'])
    assert not any(r.id.startswith(extra[0].pair_id + '|') for r in seen['rows'])
    assert res.report['dataset']['n_natural'] == base.report['dataset']['n_natural']
    table = res.report['dataset']['adversarial_table']['authored']
    assert table['rows'] == len(extra[0].rows) and table['positives'] + table['negatives'] == table['rows']
    assert 'authored' not in (res.report['per_profile']['G+R'].get('strata') or {})


def test_excluded_authored_bridge_does_not_change_natural_groups_or_metrics(docs):
    roles = assign_roles([d.lineage for d in docs], 'c9-v1')
    a, b = [d for d in docs if roles[d.lineage] == 'dev'][:2]
    lineage = next(f'bridge{i}' for i in range(100)
                   if assign_roles([f'bridge{i}'], 'c9-v1')[f'bridge{i}'] == 'dev')
    raw = authored_doc(lineage).model_dump(mode='json')
    raw['rows'][0]['identities'] = [a.rows[0].identities[0], b.rows[0].identities[0]]
    extra = T.load_pair_rows(canonical_json(T._finish(raw)))
    before = T.build_rows(T.assemble(docs), SMOKE)
    after = T.build_rows(T.assemble([*docs, extra]), SMOKE)
    assert {r.id: r.group for r in before[0]} == {r.id: r.group for r in after[0]}
    assert before[:4] == after[:4]
    for field in ('merged_lineages', 'largest_group_share', 'seen_body', 'hub_identities'):
        assert before[4][field] == after[4][field]
    assert after[4]['adversarial_table']['authored']['rows'] == len(extra.rows)
    baseline = T.run_training(docs, SMOKE)
    bridged = T.run_training([*docs, extra], SMOKE)
    assert not baseline.halt and not bridged.halt
    base_profile = baseline.report['per_profile']['G+R']
    bridged_profile = bridged.report['per_profile']['G+R']
    # The authored exclusion accounting grows; the natural fit and headline metrics stay identical.
    assert {k: v for k, v in base_profile.items() if k != 'indeterminate'} == {
        k: v for k, v in bridged_profile.items() if k != 'indeterminate'}
    assert base_profile['indeterminate']['strata']['release'] == bridged_profile['indeterminate']['strata']['release']


def test_excluded_authored_cross_role_identity_remains_in_split_audit(docs, monkeypatch):
    no_fit(monkeypatch)
    roles = assign_roles([d.lineage for d in docs], 'c9-v1')
    natural = next(d for d in docs if roles[d.lineage] == 'dev')
    lineage = next(f'audit{i}' for i in range(100)
                   if assign_roles([f'audit{i}'], 'c9-v1')[f'audit{i}'] == 'locked-test')
    raw = authored_doc(lineage).model_dump(mode='json')
    identity = natural.rows[0].identities[0]
    raw['rows'][0]['identities'] = [identity]
    extra = T.load_pair_rows(canonical_json(T._finish(raw)))
    result = T.run_training([*docs, extra], SMOKE)
    assert result.halt and any('PT-KA-LEAK' in reason and identity in reason for reason in result.halt)


def test_excluded_authored_rows_cannot_turn_a_natural_leak_into_a_hub(docs, monkeypatch):
    no_fit(monkeypatch)
    leaky = shared_identity_docs(docs)
    extras = []
    for i in range(3):
        raw = authored_doc(f'hubpadding{i}').model_dump(mode='json')
        raw['rows'][0]['identities'] = ['src:shared_body|lib/shared.c']
        extras.append(T.load_pair_rows(canonical_json(T._finish(raw))))
    result = T.run_training([*leaky, *extras], SMOKE)
    assert result.halt and any('PT-KA-LEAK' in reason and 'src:shared_body|lib/shared.c' in reason
                               for reason in result.halt)


# ---- C-4 imputation ------------------------------------------------------------------------------------------------

def test_missing_fill_does_not_depend_on_other_rows(docs):
    col = list(docs[0].columns).index('R.similarity')
    target = next(d for d in docs if any(r.x[col] is None for r in d.rows))

    def changed(doc):
        if doc.pair_id == target.pair_id:
            return doc
        raw = doc.model_dump(mode='json')
        for r in raw['rows']:
            if r['x'][col] is not None:
                r['x'][col] = 0.01
        return T.load_pair_rows(canonical_json(T._finish(raw)))

    def mine(bundle_docs):
        rows, _, names, _, _ = T.build_rows(T.assemble(bundle_docs), SMOKE)
        return {r.id: dict(zip(names, r.x, strict=True)) for r in rows if r.id.startswith(target.pair_id + '|')}
    before, after = mine(docs), mine([changed(d) for d in docs])
    assert before and before.keys() == after.keys()
    for rid, vec in before.items():
        common = vec.keys() & after[rid].keys()
        assert {k: vec[k] for k in common} == {k: after[rid][k] for k in common}, rid


def test_run_wide_medians_are_not_used_before_cv():
    assert not hasattr(T, 'medians') and not hasattr(T, 'impute')


# ---- C-5 dev-selected tau -------------------------------------------------------------------------------------------

def test_report_marks_tau_precision_dev_selected(docs):
    res = T.run_training(docs, SMOKE)
    (profile,) = res.report['per_profile'].values()
    assert profile['precision_basis'] == 'dev-selected'
    text = render_markdown(res.report)
    assert 'dev-selected' in text


# ---- C-6 halts ------------------------------------------------------------------------------------------------------

def test_under_30_lineages_halts_with_insufficient_data(docs, tmp_path, monkeypatch, capsys):
    no_fit(monkeypatch)
    res = T.run_training(docs, T.TrainConfig())                          # preregistered config: 20 lineages < 30
    assert any('lineages' in r and '30' in r for r in res.halt)
    assert res.artifact is None and {g['status'] for g in res.report['gates'].values()} == {'insufficient-data'}
    rows_dir = write_docs(tmp_path / 'rows', docs)
    assert run_cli('run', '--rows', rows_dir, '--out', tmp_path / 'out') == T.FINDINGS
    capsys.readouterr()
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    (profile,) = report['per_profile'].values()
    assert profile['status'] == 'insufficient-data'


def test_thirty_lineages_do_not_halt(tmp_path, monkeypatch):
    docs = T.build_from_labels(*write_world(tmp_path, n_lineages=30, n_funcs=12))

    def stop(*a, **k):
        raise CVError('reached the fit')
    monkeypatch.setattr(T, 'run_pipeline', stop)
    res = T.run_training(docs, T.TrainConfig())
    assert res.halt == () and any('reached the fit' in r for r in res.report['per_profile']['G+R']['reasons'])


def test_locked_role_under_12_lineages_halts_only_when_requested(docs, monkeypatch):
    plain = T.run_training(docs, SMOKE)
    assert plain.halt == ()
    no_fit(monkeypatch)
    locked = T.run_training(docs, SMOKE, locked_requested=True)
    assert any('locked-test' in r and '12' in r for r in locked.halt)


# ---- C-8 undefined bootstrap resamples ------------------------------------------------------------------------------

def stat_none_on_g0(rows, preds):
    return None if any(r.group == 'g0' for r in rows) else 1.0


def tiny_rows(n_groups=10):
    return [Row(f'r{g}{k}', f'g{g}', (0.0,), k % 2, 1.0, 'natural') for g in range(n_groups) for k in range(3)]


def test_bootstrap_counts_undefined_and_refuses_over_five_percent():
    rows = tiny_rows()
    preds = {r.id: 0.5 for r in rows}
    out = BS.cluster_bootstrap(rows, preds, stat_none_on_g0, 200, 'u', max_undefined=BS.MAX_UNDEFINED_SHARE)
    assert BS.MAX_UNDEFINED_SHARE == 0.05
    assert out['undefined'] > 10 and out['undefined_share'] == out['undefined'] / 200
    assert out['refused'] is True and out['lo'] is None and out['hi'] is None
    loose = BS.cluster_bootstrap(rows, preds, stat_none_on_g0, 200, 'u')            # no cap: still reported, not refused
    assert loose['refused'] is False and loose['lo'] is not None and loose['undefined'] == out['undefined']


def test_bootstrap_keeps_interval_below_the_cap():
    rows = tiny_rows()
    out = BS.cluster_bootstrap(rows, {r.id: 0.5 for r in rows}, lambda rs, p: 1.0, 100, 'v',
                               max_undefined=BS.MAX_UNDEFINED_SHARE)
    assert out['undefined'] == 0 and out['refused'] is False and out['lo'] == 1.0


def test_headline_precision_interval_is_refused_when_mostly_undefined():
    rows = tiny_rows()
    preds = {r.id: (0.99 if r.group == 'g0' else 0.1) for r in rows}                # only one lineage is ever accepted
    out = EV.evaluate_profile(rows, preds, tau=0.9, b_count=100, null_sims=20, with_slope_ci=False)
    assert out['precision']['refused'] is True and out['precision']['lo'] is None
    assert out['precision']['undefined_share'] > BS.MAX_UNDEFINED_SHARE


def test_report_lists_headline_undefined_shares(docs):
    res = T.run_training(docs, SMOKE)
    (profile,) = res.report['per_profile'].values()
    block = profile['bootstrap_undefined']
    assert {'precision', 'coverage', 'brier'} <= set(block)
    assert all({'undefined', 'share', 'refused'} <= set(v) for v in block.values())
