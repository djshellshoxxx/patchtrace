"""LBL-26 pre-lock audit fixes (docs/audits/20261015-lbl26-pre-lock-audit.md): one regression test per finding."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from test_tier_r_eval_metrics import FUNCS, make_labels, out, pred

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import guards, stats  # noqa: E402
from tools.calibration.channels import leadlist  # noqa: E402
from tools.calibration.channels.leadlist import LeadAA  # noqa: E402
from tools.calibration.common import Row  # noqa: E402
from tools.calibration.fit import dev_negatives  # noqa: E402
from tools.calibration.lineage import CandidateIdentity  # noqa: E402
from tools.calibration.tier_r import annotate as A  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402
from tools.calibration.tier_r import manifest as M  # noqa: E402
from tools.calibration.tier_r import shard as S  # noqa: E402

ENGINE = out(pred(0x1000, 0x1000, False), pred(0x1020, 0x1030, True), pred(0x1080, 0x1080, False))


# ---- LBL26-01: engine negatives of natural pairs belong to the natural stratum -----------------------------------

@pytest.mark.parametrize('stratum, expected', [
    ('release', 'natural'), ('cve', 'natural'), ('control', 'natural'),
    ('mutation', 'adversarial'), ('noise', 'adversarial'), ('aa', 'adversarial'), ('authored', 'adversarial')],
    ids=['release', 'cve', 'control', 'mutation', 'noise', 'aa', 'authored'])
def test_engine_candidates_take_the_stratum_of_their_pair(stratum, expected):
    labels = make_labels(FUNCS, pair_id=f'syn-{stratum}', stratum='release').model_copy(update={'stratum': stratum})
    found, _ = A.candidates(labels, {'rz-diff': ENGINE})
    by_id = {c.match_id: c for c in found}
    assert by_id['1000:1000'].sampling['stratum'] == expected          # engine-proposed truth pair
    assert by_id['1020:1030'].sampling['stratum'] == expected          # engine-proposed wrong pair
    assert by_id['1020:1030'].sampling['stage'] == 'engine-candidate'


def test_natural_stratum_contains_negatives_when_an_engine_proposed_them():
    found, _ = A.candidates(make_labels(FUNCS, pair_id='syn-r', stratum='release'), {'rz-diff': ENGINE})
    natural = [c for c in found if c.sampling['stratum'] == 'natural']
    assert {c.answer for c in natural} >= {'same', 'different'}


def test_truth_pair_no_engine_proposed_is_never_natural():
    labels = make_labels(FUNCS, pair_id='syn-r', stratum='release')
    found, _ = A.candidates(labels, {'rz-diff': ENGINE})
    missed = [c for c in found if not c.engines]
    assert missed and {c.sampling['stratum'] for c in missed} == {'adversarial'}
    assert {c.sampling['stage'] for c in missed} == {'known-answer-truth'}
    label_only, _ = A.candidates(labels, None)
    assert {c.sampling['stratum'] for c in label_only} == {'adversarial'}


# ---- LBL26-02: function identities shared across roles --------------------------------------------------------------

def test_identity_shared_across_roles_is_a_violation():
    cands = [CandidateIdentity('a', 'L1', ('body:x', 'body:y')), CandidateIdentity('b', 'L2', ('body:x',)),
             CandidateIdentity('c', 'L3', ('body:z',))]
    roles = {'L1': 'dev', 'L2': 'locked-test', 'L3': 'dev'}
    violations = guards.audit_identity_roles(cands, roles)
    assert len(violations) == 1 and 'body:x' in violations[0] and 'dev' in violations[0]


def test_hub_identity_across_roles_is_reported_as_seen_body_not_a_violation():
    cands = [CandidateIdentity('a', 'L1', ('body:crt',)), CandidateIdentity('b', 'L2', ('body:crt',))]
    roles = {'L1': 'dev', 'L2': 'shift-test'}
    assert guards.audit_identity_roles(cands, roles, hubs=frozenset({'body:crt'})) == []
    assert guards.audit_identity_roles(cands, roles)


def test_identity_audit_missing_role_fails_closed():
    cands = [CandidateIdentity('a', 'L1', ('body:x',))]
    assert guards.audit_identity_roles(cands, {})


# ---- LBL26-03: A/A false-lead gate needs a pool large enough to show the rate ----------------------------------------

def test_clopper_pearson_upper_matches_closed_forms():
    assert stats.clopper_pearson_upper(0, 100) == pytest.approx(1 - 0.05 ** (1 / 100), abs=1e-9)
    assert stats.clopper_pearson_upper(0, 0) == 1.0
    assert stats.clopper_pearson_upper(5, 5) == 1.0
    assert 0.10 < stats.clopper_pearson_upper(3, 20) < 0.35


def _many(n):
    others = {f'o{i}': i for i in range(1, 11)}
    return [leadlist.LeadPair(f'm{i}', f'LL{i}', 's1', 'h', frozenset({'h'}), {**others, 'h': 0}, {**others, 'h': 11},
                              frozenset({'h'})) for i in range(n)]


@pytest.mark.parametrize('flagged, pool, cond, verdict', [
    (0, 100, None, 'inconclusive'),          # 0 of 100: upper bound ~3 %, not <= 0.1 %
    (0, 2995, True, 'pass'),                 # rule of three: 0 of ~3000 bounds the rate at 0.1 %
    (1, 100, False, 'fail'),                 # point estimate already above the limit
], ids=['zero-of-100', 'zero-of-3000', 'one-of-100'])
def test_aa_false_lead_gate_uses_an_upper_bound(flagged, pool, cond, verdict):
    r = leadlist.score(_many(30), [LeadAA('a', 'LL0', flagged, pool)], b_count=100)
    assert (r.gate['aa_false_lead_rate'], r.gate['verdict']) == (cond, verdict)


# ---- LBL26-04: manifest ----------------------------------------------------------------------------------------------

def _clone(doc, **changes):
    data = doc.model_dump(mode='json')
    data.update(changes)
    data.pop('digest_sha256')
    return C.load_labels(C.dump_json(C.finalize_labels(data)))


def test_manifest_rejects_the_same_image_under_two_projects():
    p1 = make_labels(FUNCS, pair_id='syn-one', stratum='release')
    other = _clone(p1, pair_id='syn-two', lineage='L-other', project='other-project')
    with pytest.raises(M.ManifestError, match='image'):
        M.build_manifest([p1, other])


def test_manifest_split_declaration_is_not_shared_between_documents():
    first = M.build_manifest([make_labels(FUNCS, pair_id='syn-one', stratum='release')])
    first['split']['shift_test_lineages'].append('L-x')
    second = M.build_manifest([make_labels(FUNCS, pair_id='syn-one', stratum='release')])
    assert second['split']['shift_test_lineages'] == [] and M.SPLIT['shift_test_lineages'] == []


def _manifest(lineages):
    return {'binaries': [], 'pairs': [], 'split': {'salt': 'c9-v1', 'shift_test_lineages': []},
            'lineages': [{'id': lid, 'members': []} for lid in lineages]}


def test_audit_warns_about_small_locked_role_and_anti_conservative_total():
    warnings = guards.audit_manifest(_manifest([f'L{i}' for i in range(20)]))['warnings']
    assert any('anti-conservative' in w and '20' in w for w in warnings)
    assert any('locked-test' in w and '12' in w for w in warnings)


# ---- LBL26-05: dev negatives are an effective count, not a sum of weights ----------------------------------------------

def test_dev_negatives_use_the_effective_count():
    rows = [Row(f'n{i}', f'g{i}', (0.0,), 0, 20.0) for i in range(10)] + [Row('p', 'gp', (1.0,), 1, 1.0)]
    assert dev_negatives(rows) == pytest.approx(10.0)         # ten equal weights of 20: Kish n is 10, not 200
    rows.append(Row('adv', 'ga', (0.0,), 0, 1.0, stratum='adversarial'))
    assert dev_negatives(rows) == pytest.approx(10.0)


# ---- LBL26-06: honest scope in every Markdown report -------------------------------------------------------------------

def _report():
    return E.evaluate([make_labels(FUNCS, pair_id='syn-one', stratum='release')], [], symbols='hidden')


def test_markdown_reports_carry_the_tier_r_claim():
    from patchtrace.calibration.scope import TIER_R_CLAIM
    assert TIER_R_CLAIM in E.render_markdown(_report())
    prov = {'plan_sha256': '0' * 64, 'seed': 1, 'subset': 'smoke', 'shards': [], 'failing_cases': []}
    assert TIER_R_CLAIM in S.render_markdown(_report(), prov)
