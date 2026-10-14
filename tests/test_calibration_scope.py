"""Honest-scope runtime (LBL-17): validation ledger, scope copy, Domain invariants, promotion guard.
All documents here are synthetic fixtures; none is evidence about real binaries."""
from __future__ import annotations

import datetime as dt
import json
from types import SimpleNamespace

import pytest
from test_calibration_runtime import TODAY, encode, make_artifact

from patchtrace.calibration.artifact import (
    ArtifactError,
    canonical_json,
    digest,
    load_artifact,
    parse_artifact,
)
from patchtrace.calibration.context import context_from_tools
from patchtrace.calibration.ledger import load_bundled_ledger, load_ledger
from patchtrace.calibration.policy import artifact_display_level
from patchtrace.calibration.scope import (
    BANNED_STEMS,
    SCOPE_IDS,
    SCOPE_TEXT,
    TIER_R_CLAIM,
    ScopeError,
    notice,
    scope_text,
)

SHA = 'a' * 64


def entry(**kw):
    base = {'channel': 'rz-diff', 'facet': 'pairing', 'state': 'synthetic-validated',
            'evidence_tiers': ['tier-r'], 'report_sha256': SHA, 'prereg_sha256': SHA, 'corpus_id': 'c',
            'n_lineages': 37, 'n_pairs': 100, 'tool_versions': {'rz': '0.9'},
            'scope_ids': ['open-source-c-only'], 'measured_on': '2026-10-01', 'expires': '2027-09-30'}
    return {**base, **kw}


def ledger_doc(entries=None, **kw):
    doc = {'contract': 'validation-ledger/1', 'entries': [entry()] if entries is None else entries,
           'created': '2026-10-01', 'expires': '2027-09-30', **kw}
    doc['digest_sha256'] = digest(doc)
    return doc


def redigest(doc):
    doc['digest_sha256'] = digest(doc)
    return doc


def test_ledger_valid_and_missing():
    ok = load_ledger(canonical_json(ledger_doc()), today=TODAY)
    assert ok.reason == 'ok' and ok.state('rz-diff', 'pairing', TODAY) == 'synthetic-validated'
    assert ok.state('ghidriff', 'pairing', TODAY) == 'unvalidated'
    assert load_ledger(None).reason == 'missing'
    assert load_bundled_ledger(__import__('pathlib').Path('/nonexistent/x.json')).reason == 'missing'


@pytest.mark.parametrize('mutate, needle', [
    pytest.param(lambda d: redigest({**d, 'extra': 1}), 'schema', id='extra-key'),
    pytest.param(lambda d: {**d, 'created': '2026-10-02'}, 'digest', id='tampered'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(state='synthetic-validated',
                                                            evidence_tiers=[])]}), 'schema', id='syn-no-tier'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(report_sha256=None)]}), 'schema', id='syn-no-sha'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(state='windows-validated',
                                                            evidence_tiers=['tier-r'])]}), 'schema',
                 id='win-no-tierw'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(
        state='windows-validated', evidence_tiers=['tier-w'],
        scope_ids=['no-windows-system-binaries'])]}), 'schema', id='win-contradiction'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(scope_ids=['made-up'])]}), 'schema', id='bad-scope'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(), entry()]}), 'duplicate', id='dup-entry'),
    pytest.param(lambda d: redigest({**d, 'expires': '2025-12-31', 'created': '2025-01-01'}), 'expired',
                 id='expired'),
    pytest.param(lambda d: redigest({**d, 'expires': '2029-01-01'}), '12 months', id='long-expiry'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry(channel='nope')]}), 'schema', id='bad-channel'),
    pytest.param(lambda d: redigest({**d, 'entries': [entry()] * 65}), 'schema', id='too-many'),
])
def test_ledger_loader_negatives(mutate, needle):
    doc = mutate(ledger_doc())
    raw = canonical_json(doc)
    result = load_ledger(raw, today=TODAY)
    assert result.entries == ()
    assert result.reason == 'expired' if needle == 'expired' else needle in result.reason
    assert result.state('rz-diff', 'pairing', TODAY) == 'unvalidated'


def test_ledger_rejects_non_json_oversize_and_duplicate_keys():
    for raw in (b'not json', b'[]', b'{"a":1,"a":2}', b'{"x":NaN}', b'x' * (64 * 1024 + 1)):
        res = load_ledger(raw, today=TODAY)
        assert res.entries == () and res.reason.startswith('PT-CALIB-LEDGER')


def test_expired_entry_reads_unvalidated():
    res = load_ledger(canonical_json(ledger_doc()), today=TODAY)
    assert res.state('rz-diff', 'pairing', dt.date(2027, 10, 1)) == 'unvalidated'


# ---- promotion guard ------------------------------------------------------------------------------------

EV = {'preregistration_sha256': '1' * 64, 'report_sha256': '2' * 64, 'corpus_manifest_sha256': None,
      'label_set_sha256': None, 'tool_git': 't', 'gates': {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}}
NUM = {'tau': 0.9, 'tau_low': None, 'display': 'number', 'bands': []}


def _domain(**kw):
    base = make_artifact()['calibration_domain']
    return {**base, **kw}


@pytest.mark.parametrize('domain', [
    pytest.param({}, id='no-tiers'),
    pytest.param({'evidence_tiers': ['synthetic', 'tier-r']}, id='tier-r-only'),
    pytest.param({'evidence_tiers': ['tier-r'], 'windows_system_binaries': 'local-measured'}, id='claims-windows'),
    pytest.param({'evidence_tiers': ['tier-r', 'tier-w'], 'windows_system_binaries': 'none'}, id='tierw-no-wsb'),
    pytest.param({'evidence_tiers': ['tier-w'], 'windows_system_binaries': 'local-measured',
                  'scope_ids': ['no-windows-system-binaries']}, id='contradicting-scope'),
])
@pytest.mark.parametrize('status, display, gates', [
    pytest.param('bands-ok', 'band', {'G0': 'pass', 'G2': 'pass'}, id='bands'),
    pytest.param('numeric-ok', 'number', {'G0': 'pass', 'G2': 'pass', 'G3': 'pass'}, id='numeric'),
])
def test_tier_r_only_artifact_cannot_be_promoted(domain, status, display, gates):
    doc = make_artifact(status=status, calibration_domain=_domain(**domain),
                        evidence={**EV, 'gates': gates}, policy={**NUM, 'display': display})
    assert load_artifact(encode(doc), today=TODAY).artifact is None
    # defence in depth: even a post-load copy forced to a promoted status stays ordinal
    good = parse_artifact(encode(make_artifact()), today=TODAY)
    forced = good.model_copy(update={'status': status, 'evidence': good.evidence.model_copy(update={'gates': gates}),
                                     'policy': good.policy.model_copy(update={'display': display}),
                                     'calibration_domain': good.calibration_domain.model_copy(update=domain)})
    assert artifact_display_level(forced) == 'ordinal'


def test_experimental_tier_r_artifact_loads_but_stays_ordinal_and_wsb_claim_rejected():
    doc = make_artifact(calibration_domain=_domain(evidence_tiers=['synthetic', 'tier-r'],
                                                   scope_ids=['no-windows-system-binaries', 'open-source-c-only']))
    art = parse_artifact(encode(doc), today=TODAY)
    assert artifact_display_level(art) == 'ordinal'
    bad = make_artifact(calibration_domain=_domain(windows_system_binaries='published-measured'))
    with pytest.raises(ArtifactError, match='Windows coverage'):
        parse_artifact(encode(bad), today=TODAY)
    with pytest.raises(ArtifactError, match='schema'):
        parse_artifact(encode(make_artifact(calibration_domain=_domain(scope_ids=['made-up']))), today=TODAY)


def test_windows_evidence_artifact_promotes_only_with_tier_w_and_gates():
    dom = _domain(evidence_tiers=['tier-r', 'tier-w'], windows_system_binaries='local-measured')
    doc = make_artifact(status='numeric-ok', calibration_domain=dom, evidence=EV, policy=NUM)
    assert artifact_display_level(parse_artifact(encode(doc), today=TODAY)) == 'numeric'


def test_domain_fields_are_additive_old_documents_still_load():
    doc = make_artifact()
    assert 'evidence_tiers' not in doc['calibration_domain']
    art = parse_artifact(encode(doc), today=TODAY)
    assert art.calibration_domain.evidence_tiers == () and art.calibration_domain.scope_ids == ()


# ---- scope copy -----------------------------------------------------------------------------------------

def _all_copy():
    texts = [TIER_R_CLAIM, *SCOPE_TEXT.values()]
    ledger = load_ledger(canonical_json(ledger_doc([entry(), entry(channel='ghidriff')])), today=TODAY)
    for level in ('ordinal', 'bands'):
        for led in (ledger, load_ledger(None), load_ledger(b'x'), load_ledger(canonical_json(ledger_doc(
                created='2024-01-01', expires='2024-12-31')), today=TODAY)):
            n = notice(level, led, {})
            texts += [n.line, *n.limits_lines, *n.provenance_lines]
    texts += [notice('ordinal', ledger, {'G': SimpleNamespace(artifact=None)}).line]
    return texts


def test_scope_copy_sweep():
    assert set(SCOPE_TEXT) == set(SCOPE_IDS) and len(SCOPE_IDS) == 12
    for text in _all_copy():
        low = text.lower()
        assert len(text) <= 300
        for stem in BANNED_STEMS:
            assert stem not in low, (stem, text)
    with pytest.raises(ScopeError, match='PT-CALIB-SCOPE'):
        scope_text('free text')


def test_notice_states():
    syn = load_ledger(canonical_json(ledger_doc()), today=TODAY)
    win = load_ledger(canonical_json(ledger_doc([entry(
        state='windows-validated', evidence_tiers=['tier-w'], scope_ids=['x64-only'])])), today=TODAY)
    assert notice('ordinal', load_ledger(None), {}).state == 'untested'
    assert notice('ordinal', syn, {}).state == 'tested-synthetic'
    assert 'Not tested on Windows system files' in notice('ordinal', syn, {}).limits_lines[0]
    assert notice('ordinal', win, {}).state == 'tested-synthetic'  # ordinal display never reads as Windows-tested
    assert notice('bands', win, {}).state == 'tested-windows'
    assert notice('bands', load_ledger(b'zz'), {}).state == 'degraded'
    assert notice('bands', load_ledger(canonical_json(ledger_doc(created='2024-01-01', expires='2024-12-31')),
                                       today=TODAY), {}).state == 'expired'
    assert len(notice('bands', syn, {}).provenance_lines) == 1


# ---- context ---------------------------------------------------------------------------------------------

def test_context_from_tools():
    pe = SimpleNamespace(machine=SimpleNamespace(code=0x8664, name='x64'))
    sig = SimpleNamespace(certainty='signature', toolchain='Microsoft Visual C/C++')
    heur = SimpleNamespace(certainty='heuristic', toolchain='gcc')
    ctx = context_from_tools([sig], pe)
    assert (ctx.arch, ctx.toolchain, ctx.symbol_provenance) == ('x64', 'msvc', 'none')
    assert context_from_tools([heur], pe).toolchain == 'unknown'
    assert context_from_tools([], None).arch == 'other'
    assert context_from_tools([sig, SimpleNamespace(certainty='signature', toolchain='clang')], pe
                              ).toolchain == 'unknown'  # conflicting evidence is not guessed


def test_committed_ledger_if_present_is_valid_and_cited():
    from pathlib import Path

    from patchtrace.calibration.ledger import LEDGER_PATH
    if not LEDGER_PATH.is_file():
        return
    res = load_bundled_ledger()
    assert res.reason == 'ok'
    qa = (Path(__file__).resolve().parents[1] / 'docs' / 'qa.md').read_text(encoding='utf-8')
    for e in res.entries:
        if e.state != 'unvalidated':
            assert e.report_sha256 in qa
    json.loads(LEDGER_PATH.read_text(encoding='utf-8'))
