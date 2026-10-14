"""Shipped calibration runtime (calibration-corpus-and-model.md §6, §9.5, §10): features, artifact loader,
predict, OOD, policy and the display-level seam. All data here is synthetic; no real-data claim."""
from __future__ import annotations

import ast
import copy
import datetime as dt
import json
import math
from pathlib import Path

import pytest

from patchtrace.calibration import display_level
from patchtrace.calibration.artifact import (
    DEV_OVERRIDE_ENV,
    MAX_BYTES,
    ArtifactError,
    canonical_json,
    digest,
    load_artifact,
    load_bundled,
    parse_artifact,
)
from patchtrace.calibration.features import (
    FEATURE_SCHEMA,
    FEATURES,
    ExtractionContext,
    extract,
    extract_all,
    feature_names,
    independence_index,
)
from patchtrace.calibration.ood import mahalanobis2
from patchtrace.calibration.policy import artifact_display_level, decide
from patchtrace.calibration.predict import apply_isotonic, predict, provenance
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.secondary.contracts import AlternativeMatch, SecondaryMatch, SecondaryMatchSet
from patchtrace.secondary.reconcile import reconcile

OLD, NEW = 'a' * 64, 'b' * 64
TODAY = dt.date(2026, 10, 14)
ROOT = Path(__file__).resolve().parents[1]


def fn(side, address, length=None, name=None, callees=()):
    meta = {'upstream_similarity': 0.91} if side == 'o' else {}
    if length is not None:
        meta['length'] = length
    return FunctionRecord(artifact_id=side, run_id='r', name=name or f'f{address}', address=address,
                          callees=list(callees), metadata=meta)


def gmatch(ident, older, newer, *, category='modified', types=('SymbolsHash',), length=(100, 120), name=None):
    olders = older if isinstance(older, list) else [older] if older else []
    return FunctionMatch(id=ident, run_id='r', category=category, match_types=list(types),
                         older=[fn('o', a, length[0], name, ('x', 'y')) for a in olders],
                         newer=[fn('n', newer, length[1], name, ('x',))] if newer else [])


def rz(older, newer, sim=800):
    return SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=older, newer_address=newer,
                          older_name=None, newer_name=None, similarity_milli=sim, similarity_text='x',
                          confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')


def bd(older, newer, sim=900, conf=950, alg='function: name hash matching', flags=('G', 'C')):
    return SecondaryMatch(engine='bindiff', engine_version='8', older_address=older, newer_address=newer,
                          older_name=None, newer_name=None, similarity_milli=sim, similarity_text='x',
                          confidence_milli=conf, confidence_text='x', flags=flags, algorithm=alg)


def mset(engine, *matches, alternatives=()):
    return SecondaryMatchSet(contract='secondary/2', engine=engine, engine_version=matches[0].engine_version,
                             older_sha256=OLD, newer_sha256=NEW, file_sha256='c' * 64, matches=matches,
                             alternatives=alternatives, image_base_subtracted='no')


def reports_for(matches, rz_set=None, bd_set=None):
    return tuple(reconcile(matches, s) for s in (bd_set, rz_set) if s is not None)


# ---- features --------------------------------------------------------------------------------------------

def test_feature_schema_is_unique_and_profiles_nest():
    names = [s.name for s in FEATURES]
    assert len(names) == len(set(names))
    assert set(feature_names('G')) < set(feature_names('G+R')) < set(feature_names('G+B+R'))
    assert not any(n.startswith(('B.', 'R.')) for n in feature_names('G'))
    assert len(feature_names('G+B+R')) <= 64  # artifact feature-count bound
    assert all(f'{s.name}.missing' in names for s in FEATURES if s.missing_ok)


def test_golden_vector_g_b_r_from_stored_reconciliation():
    alt = AlternativeMatch(anchor_side='older', anchor_address=0x1000, candidate=rz(0x1000, 0x9000, 100),
                           source='rz-diff', rank=2)
    matches = [gmatch('m1', '1000', '1000')]
    reports = reports_for(matches, mset('rz-diff', rz(0x1000, 0x1000, 640), alternatives=(alt,)),
                          mset('bindiff', bd(0x1000, 0x1000)))
    ctx = ExtractionContext(symbol_provenance='public', arch='x64', toolchain='msvc', binexport_producer='ghidra')
    row = extract(matches[0], reports, ctx)
    assert row.status == 'ok' and row.profile == 'G+B+R'
    assert [n for n, _ in row.values] == list(feature_names('G+B+R'))
    v = row.as_dict()
    assert v['G.ratio'] == 0.91 and v['G.ratio.missing'] == 0.0
    assert v['G.mt.SymbolsHash'] == 1.0 and v['G.mt.other'] == 0.0 and v['G.n_match_types'] == 1.0
    assert v['B.similarity'] == 0.9 and v['B.confidence'] == 0.95 and v['B.alg.name-hash'] == 1.0
    assert v['B.flag.G'] == v['B.flag.C'] == 1.0 and v['B.flag.I'] == 0.0
    assert v['R.similarity'] == 0.64
    assert v['S.log_size_older'] == pytest.approx(math.log(100)) and v['S.size_ratio'] == pytest.approx(100 / 120)
    assert v['S.log_callees_older'] == pytest.approx(math.log(3)) and v['S.thunk'] == 0.0
    assert v['P.symbols=public'] == 1.0 and v['P.arch=x64'] == 1.0 and v['P.binexport_producer=ghidra'] == 1.0
    assert v['X.agree_B'] == v['X.agree_R'] == 1.0 and v['X.absent_B'] == 0.0
    assert v['X.log_alternatives'] == pytest.approx(math.log(2))
    assert dict(row.categories)['P.toolchain'] == 'msvc'
    assert row.engine_versions == ('bindiff 8', 'rz-diff 0.9.1')


def test_absent_engine_changes_profile_and_missing_values_are_flagged():
    matches = [FunctionMatch(id='m', run_id='r', category='unchanged', match_types=['Weird'],
                             older=[FunctionRecord(artifact_id='o', run_id='r', name='thunk_a', address='2000')],
                             newer=[FunctionRecord(artifact_id='n', run_id='r', name='b', address='2000')])]
    reports = reports_for(matches, mset('rz-diff', rz(0x7000, 0x7000)), mset('bindiff', bd(0x2000, 0x2000)))
    row = extract(matches[0], reports)
    assert row.profile == 'G+B'  # rz-diff absent: family missing -> profile changes, no zero-fill of R
    v = row.as_dict()
    assert 'R.similarity' not in v
    assert v['G.ratio'] is None and v['G.ratio.missing'] == 1.0
    assert v['S.size_ratio'] is None and v['S.size_ratio.missing'] == 1.0
    assert v['G.unchanged'] == 1.0 and v['G.mt.other'] == 1.0 and v['S.thunk'] == 1.0
    assert v['X.absent_R'] == 1.0 and v['X.agree_R'] == 0.0


def test_contested_not_comparable_and_one_sided_produce_no_vector():
    matches = [gmatch('c', '1000', '1000'), gmatch('many', ['3000', '3100'], '3000', category='merged'),
               gmatch('added', None, '5000', category='added'), gmatch('ok', '6000', '6000')]
    reports = reports_for(matches, mset('rz-diff', rz(0x1000, 0x1400), rz(0x6000, 0x6000)))
    rows = {r.match_id: r for r in extract_all(matches, reports)}
    assert rows['c'].status == 'contested' and rows['c'].values == ()
    assert rows['many'].status == 'not-comparable'
    assert rows['added'].status == 'one-sided'
    assert rows['ok'].status == 'ok' and rows['ok'].profile == 'G+R'


def test_extract_requires_one_report_per_engine_and_the_match():
    matches = [gmatch('m', '1000', '1000')]
    rep = reconcile(matches, mset('rz-diff', rz(0x1000, 0x1000)))
    with pytest.raises(ValueError):
        extract(matches[0], (rep, rep))
    with pytest.raises(ValueError):
        extract(gmatch('other', '1000', '1000'), (rep,))


def test_dependency_groups_and_independence_index():
    assert independence_index('G') == 0
    assert independence_index('G+B') == 0           # Ghidra-exported BinExport shares D_ghidra etc.
    assert independence_index('G+B', 'ida') == 0    # still shares D_symbols / D_callgraph
    assert independence_index('G+R') == 1           # raw bytes only
    assert independence_index('G+B+R') == 1
    spec = next(s for s in FEATURES if s.name == 'R.similarity')
    assert spec.depends_on == frozenset({'D_bytes'})


# ---- artifact --------------------------------------------------------------------------------------------

def make_artifact(profile='G+R', **overrides) -> dict:
    names = ['G.ratio', 'R.similarity']
    doc = {'contract': 'patchtrace-calibration-model/1', 'model_id': 'test-model', 'status': 'experimental',
           'target': 'A', 'feature_schema': FEATURE_SCHEMA, 'profile': profile,
           'features': [{'name': n, 'kind': 'num', 'median': 0.5, 'mean': 0.5, 'sd': 0.2, 'coef': 1.0}
                        for n in names],
           'intercept': 2.0, 'base': 'l2-logistic', 'C': 1.0, 'calibrator': {'type': 'platt', 'a': 1.0, 'b': 0.0},
           'policy': {'tau': 0.9, 'tau_low': 0.2, 'display': 'none', 'bands': []},
           'ood': {'names': names, 'mu': [0.5, 0.5], 'chol': [[0.2], [0.0, 0.2]], 'd2_soft': 9.0, 'd2_cut': 12.0,
                   'ranges': {'G.ratio': [0.0, 1.0], 'R.similarity': [0.0, 1.0]},
                   'cat_levels': {'P.arch': ['x64']}, 'engine_versions': ['rz-diff 0.9.1']},
           'calibration_domain': {'engines': {'rz-diff': ['0.9.1']}, 'toolchains': ['clang'], 'arch': ['x64'],
                                  'corpus_id': 'synthetic', 'n_pairs': 0, 'n_lineages': 40, 'prevalence': 0.8,
                                  'known_blind_spots': ['synthetic only']},
           'evidence': {'preregistration_sha256': None, 'report_sha256': None, 'corpus_manifest_sha256': None,
                        'label_set_sha256': None, 'tool_git': 'test', 'gates': {}},
           'created': '2026-10-01', 'expires': '2027-09-30'}
    for key, value in overrides.items():
        doc[key] = value
    doc['digest_sha256'] = digest(doc)
    return doc


def encode(doc) -> bytes:
    return canonical_json(doc)


def test_valid_artifact_loads():
    art = parse_artifact(encode(make_artifact()), today=TODAY)
    assert art.profile == 'G+R' and art.status == 'experimental'
    assert artifact_display_level(art) == 'ordinal'


def _redigest(doc):
    doc['digest_sha256'] = digest(doc)
    return doc


@pytest.mark.parametrize('mutate, needle', [
    (lambda d: d.update(extra=1) or _redigest(d), 'schema'),
    (lambda d: d.update(intercept=3.0), 'digest'),
    (lambda d: _redigest({**d, 'feature_schema': 'features/0'}), 'feature schema'),
    (lambda d: _redigest({**d, 'calibrator': {'type': 'isotonic', 'knots': [[0.0, 0.6], [1.0, 0.4]]}}), 'monotone'),
    (lambda d: _redigest({**d, 'calibrator': {'type': 'isotonic', 'knots': [[0.0, 0.1], [1.0, 1.4]]}}), '[0,1]'),
    (lambda d: _redigest({**d, 'calibrator': {'type': 'platt', 'a': -1.0, 'b': 0.0}}), 'slope'),
    (lambda d: _redigest({**d, 'created': '2025-01-01', 'expires': '2025-12-31'}), 'expired'),
    (lambda d: _redigest({**d, 'expires': '2028-12-31'}), '12 months'),
    (lambda d: _redigest({**d, 'status': 'numeric-ok'}), 'numeric-ok'),
    (lambda d: _redigest({**d, 'status': 'bands-ok'}), 'bands-ok'),
    (lambda d: _redigest({**d, 'policy': {**d['policy'], 'display': 'number'}}), 'display'),
    (lambda d: _redigest({**d, 'policy': {**d['policy'], 'tau_low': 0.95}}), 'tau_low'),
    (lambda d: _redigest({**d, 'profile': 'G'}), 'profile'),
    (lambda d: _redigest({**d, 'features': d['features'] * 2}), 'duplicated'),
    (lambda d: _redigest({**d, 'features': [{**d['features'][0], 'kind': 'flag'}, d['features'][1]]}), 'kind'),
    (lambda d: _redigest({**d, 'ood': {**d['ood'], 'chol': [[0.2], [0.0, -0.2]]}}), 'Cholesky'),
    (lambda d: _redigest({**d, 'ood': {**d['ood'], 'mu': [0.5]}}), 'dimensions'),
    (lambda d: _redigest({**d, 'C': True}), 'schema'),
])
def test_artifact_negatives_degrade_to_no_model(mutate, needle):
    doc = make_artifact()
    doc = mutate(doc) or doc
    with pytest.raises(ArtifactError) as err:
        parse_artifact(encode(doc), today=TODAY)
    assert needle in str(err.value)
    result = load_artifact(encode(doc), today=TODAY)
    assert result.artifact is None and result.reason.startswith('no-model')


def test_artifact_rejects_duplicate_keys_nan_oversize_and_non_json():
    good = encode(make_artifact()).decode()
    dup = good.replace('{"C":1.0,', '{"C":1.0,"C":1.0,', 1)
    assert dup != good
    nan = good.replace('"intercept":2.0', '"intercept":NaN')
    for data in (dup.encode(), nan.encode(), b'\xff\xfe', b'[1, 2]', b' ' * (MAX_BYTES + 1), b'{"a":'):
        assert load_artifact(data, today=TODAY).artifact is None


def test_numeric_ok_requires_evidence_and_passing_gates():
    ev = {'preregistration_sha256': '1' * 64, 'report_sha256': '2' * 64, 'corpus_manifest_sha256': None,
          'label_set_sha256': None, 'tool_git': 't', 'gates': {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}}
    ok = make_artifact(status='numeric-ok', evidence=ev, policy={'tau': 0.9, 'tau_low': None, 'display': 'number',
                                                                 'bands': []})
    art = parse_artifact(encode(ok), today=TODAY)
    assert artifact_display_level(art) == 'numeric'
    failing = make_artifact(status='numeric-ok', evidence={**ev, 'gates': {'G0': 'pass', 'G2': 'pass',
                                                                           'G3': 'insufficient-data'}})
    assert load_artifact(encode(failing), today=TODAY).artifact is None
    bands = make_artifact(status='bands-ok', evidence={**ev, 'gates': {'G0': 'pass', 'G2': 'pass'}},
                          policy={'tau': 0.9, 'tau_low': None, 'display': 'band', 'bands': []})
    assert artifact_display_level(parse_artifact(encode(bands), today=TODAY)) == 'bands'


def test_display_level_is_ordinal_without_artifacts(tmp_path, monkeypatch):
    monkeypatch.delenv(DEV_OVERRIDE_ENV, raising=False)
    assert display_level() == 'ordinal'
    assert display_level('G+B+R') == 'ordinal'
    assert display_level(models={}) == 'ordinal'
    assert load_bundled(tmp_path / 'missing') == {}


def test_display_level_never_raises():
    class Broken(dict):
        def get(self, *_):
            raise RuntimeError('boom')
    assert display_level('G', models=Broken()) == 'ordinal'


def test_bundled_duplicates_cancel_and_dev_override_forces_experimental(tmp_path):
    ev = {'preregistration_sha256': '1' * 64, 'report_sha256': '2' * 64, 'corpus_manifest_sha256': None,
          'label_set_sha256': None, 'tool_git': 't', 'gates': {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}}
    doc = make_artifact(status='numeric-ok', evidence=ev, policy={'tau': 0.9, 'tau_low': None,
                                                                  'display': 'number', 'bands': []})
    (tmp_path / 'a.json').write_bytes(encode(doc))
    loaded = load_bundled(tmp_path, today=TODAY, environ={})
    assert display_level('G+R', models=loaded) == 'numeric'
    (tmp_path / 'b.json').write_bytes(encode(make_artifact(model_id='other')))
    assert load_bundled(tmp_path, today=TODAY, environ={}) == {}  # ambiguous profile -> no model
    (tmp_path / 'bad.json').write_bytes(b'not json')
    override = load_bundled(tmp_path, today=TODAY, environ={DEV_OVERRIDE_ENV: str(tmp_path / 'a.json')})
    result = override['G+R']
    assert result.developer_override and result.artifact.status == 'experimental'
    assert display_level('G+R', models=override) == 'ordinal'


def test_no_shipped_artifact_is_promoted_without_a_qa_citation():
    folder = ROOT / 'src' / 'patchtrace' / 'calibration' / 'models'
    qa = (ROOT / 'docs' / 'qa.md').read_text(encoding='utf-8')
    for path in sorted(folder.glob('*.json')) if folder.is_dir() else []:
        doc = json.loads(path.read_text(encoding='utf-8'))
        if doc.get('status') in ('numeric-ok', 'bands-ok'):
            assert doc['evidence']['report_sha256'] in qa, f'{path.name} promoted without docs/qa.md citation'


def test_runtime_package_has_no_forbidden_imports_or_dynamic_code():
    forbidden = {'pickle', 'joblib', 'numpy', 'sklearn', 'scipy', 'PySide6', 'importlib', 'urllib', 'socket',
                 'http', 'marshal', 'shelve', 'tools'}
    for path in sorted((ROOT / 'src' / 'patchtrace' / 'calibration').glob('*.py')):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or '']
            else:
                names = []
            assert not {n.split('.')[0] for n in names} & forbidden, (path.name, names)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {'eval', 'exec', '__import__', 'compile'}, path.name


# ---- predict / ood / policy -----------------------------------------------------------------------------

def _row_for(ratio_meta=0.91, rz_sim=800, arch='x64', rz_version='0.9.1'):
    matches = [gmatch('m', '1000', '1000')]
    matches[0].older[0].metadata['upstream_similarity'] = ratio_meta
    rs = SecondaryMatchSet(contract='secondary/2', engine='rz-diff', engine_version=rz_version, older_sha256=OLD,
                           newer_sha256=NEW, file_sha256='c' * 64, image_base_subtracted='no',
                           matches=(rz(0x1000, 0x1000, rz_sim).model_copy(update={'engine_version': rz_version}),))
    return extract(matches[0], (reconcile(matches, rs),), ExtractionContext(arch=arch))


def test_predict_matches_hand_computation_and_provenance():
    art = parse_artifact(encode(make_artifact()), today=TODAY)
    row = _row_for()
    pred = predict(row, art)
    z = 2.0 + (0.91 - 0.5) / 0.2 + (0.8 - 0.5) / 0.2
    assert pred.score == pytest.approx(z)
    assert pred.p == round(1 / (1 + math.exp(-z)), 6)
    assert pred.flags == ()
    prov = provenance(pred, art, row)
    assert prov['model_digest_sha256'] == art.digest_sha256 and prov['features'][0][0] == 'G.ratio'
    assert 'never a vulnerability probability' in prov['note']


def test_isotonic_apply_interpolates_and_clamps():
    knots = ((0.0, 0.1), (1.0, 0.5), (2.0, 0.5), (3.0, 0.9))
    assert apply_isotonic(knots, -5) == 0.1 and apply_isotonic(knots, 9) == 0.9
    assert apply_isotonic(knots, 0.5) == pytest.approx(0.3)
    assert apply_isotonic(knots, 1.5) == 0.5


def test_ood_flags_hard_and_soft():
    art = parse_artifact(encode(make_artifact()), today=TODAY)
    assert mahalanobis2([0.7, 0.5], [0.5, 0.5], [[0.2], [0.0, 0.2]]) == pytest.approx(1.0)
    far = predict(_row_for(ratio_meta=1.0, rz_sim=0), art)
    assert 'hard:mahalanobis' in far.flags
    unseen = predict(_row_for(arch='arm64'), art)
    assert 'hard:unseen-level' in unseen.flags
    drift = predict(_row_for(rz_version='0.10.0'), art)
    assert drift.flags == ('soft:engine-version',)


def test_policy_order_table():
    ev = {'preregistration_sha256': '1' * 64, 'report_sha256': '2' * 64, 'corpus_manifest_sha256': None,
          'label_set_sha256': None, 'tool_git': 't', 'gates': {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}}
    numeric = load_artifact(encode(make_artifact(
        status='numeric-ok', evidence=ev, policy={'tau': 0.9, 'tau_low': 0.2, 'display': 'number', 'bands': []})),
        today=TODAY)
    experimental = load_artifact(encode(make_artifact()), today=TODAY)
    models = {'G+R': numeric}
    matches = [gmatch('contested', '1000', '1000'), gmatch('many', ['3000', '3100'], '3000', category='merged'),
               gmatch('nomodel', '4000', '4000')]
    reports = reports_for(matches, mset('rz-diff', rz(0x1000, 0x1400)))
    rows = {r.match_id: r for r in extract_all(matches, reports)}
    assert decide(rows['contested'], models).decision == 'manual'      # model can never override contested
    assert decide(rows['many'], models).reason == 'not-comparable'
    assert decide(rows['nomodel'], models).reason == 'no-model'        # profile G has no model
    high = decide(_row_for(), models)
    assert high.decision == 'auto-accept' and high.shown_p == math.floor(high.prediction.p * 20) / 20
    low = decide(_row_for(ratio_meta=0.1, rz_sim=0), models)  # z = -2.5, inside the hard OOD cut
    assert low.decision == 'likely-wrong' and low.prediction.flags == ('soft:mahalanobis',)
    assert decide(_row_for(arch='arm64'), models).reason == 'ood'
    mid = decide(_row_for(), {'G+R': experimental})
    assert mid.decision == 'review' and mid.shown_p is None            # experimental never auto-accepts
    tampered = copy.deepcopy(make_artifact())
    tampered['intercept'] = 99.0
    assert decide(_row_for(), {'G+R': load_artifact(encode(tampered), today=TODAY)}).reason == 'no-model'
