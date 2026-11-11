"""Audit C findings in the CVE enrichment that the CSAF track corrects (C-04, C-05, C-09, C-10).

Provider fixtures are the trimmed real responses of tests/fixtures/cve (see its README); every variant below is
synthetic. Nothing here is live provider evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment import cve, identity
from patchtrace.enrichment.contracts import (
    ChangeSignal,
    DetectorOutcome,
    EnrichmentError,
    RankingConfig,
    SignalSet,
    SourceLocation,
)
from patchtrace.enrichment.ranking import rank
from patchtrace.service import ProjectService

FIX = Path(__file__).parent / 'fixtures' / 'cve'
CVE_ID = 'CVE-2024-38063'
NVD = (FIX / f'nvd_{CVE_ID}.json').read_bytes()
MSRC = (FIX / f'msrc_{CVE_ID}.json').read_bytes()
WHEN = '2026-10-12T03:46:00Z'
H = 'a' * 64


def edited(raw: bytes, fn) -> bytes:
    doc = json.loads(raw)
    fn(doc)
    return json.dumps(doc).encode()


def snap(nvd=NVD, msrc=MSRC):
    responses = {name: body for name, body in (('nvd', nvd), ('msrc', msrc)) if body is not None}
    return cve.normalize(CVE_ID, responses, WHEN)


def pid(name):
    return identity.domain_id('test-pairing', 1, name)


def sig(detector, confidence, pairing, group='1'):
    p = pid(pairing)
    gk = identity.domain_id('test-group', 1, pairing + group)
    loc = SourceLocation(side='newer', artifact_id='a', run_id='r', function_id='f', start_line=1, end_line=1,
                         excerpt_sha256=H)
    return ChangeSignal(signal_id=identity.signal_id(p, detector, 1, gk, [{'n': 0}]), pairing_id=p,
                        match_id='m-' + pairing, detector=detector, detector_version=1, confidence=confidence,
                        group_key=gk, locations=(loc,), rationale='synthetic')


def sset(pairing, signals):
    p = pid(pairing)
    return SignalSet(pairing_id=p, match_id='m-' + pairing, category='modified', signals=tuple(signals),
                     outcomes=(DetectorOutcome(pairing_id=p, detector='BND', status='complete'),), status='complete')


# --- C-04: shared-origin evidence counts once -------------------------------------------------------------------

def sibling_cwe_entry(signals):
    sets = [sset('x', signals)]
    ranking = rank(sets, RankingConfig())
    msrc = edited(MSRC, lambda d: d.update(cveTitle='none', cweList=['CWE-787', 'CWE-125']))  # both map to BND/SIZE
    return cve.contextual_rank(ranking, sets, [], [snap(nvd=None, msrc=msrc)], [], {}).entries[0]


def test_c04_one_signal_is_not_counted_under_two_sibling_cwes():
    entry = sibling_cwe_entry([sig('BND', 'moderate', 'x')])
    assert [c.kind for c in entry.contributions] == ['cwe'] and entry.adjustment == 10


def test_c04_signals_of_one_edit_group_share_one_credit_but_independent_edits_do_not():
    same_edit = sibling_cwe_entry([sig('BND', 'moderate', 'x', '1'), sig('SIZE', 'moderate', 'x', '1')])
    assert [c.kind for c in same_edit.contributions] == ['cwe'] and same_edit.adjustment == 10
    two_edits = sibling_cwe_entry([sig('BND', 'moderate', 'x', '1'), sig('SIZE', 'moderate', 'x', '2')])
    assert [c.kind for c in two_edits.contributions] == ['cwe', 'cwe'] and two_edits.adjustment == 20
    assert len({c.binary_ref for c in two_edits.contributions}) == 2


# --- C-05: provider bodies the snapshot contract cannot hold are typed provider errors ---------------------------

def test_c05_lone_surrogate_in_a_provider_body_is_a_typed_provider_error():
    body = edited(NVD, lambda d: d['vulnerabilities'][0]['cve']['descriptions'][0].update(value='bad \ud800 text'))
    assert b'\\ud800' in body  # strict JSON accepts the escape; the model cannot hold the lone surrogate
    with pytest.raises(EnrichmentError) as info:
        cve.normalize(CVE_ID, {'nvd': body}, WHEN)
    assert info.value.code == 'PT-ENRICH-PROVIDER'


@pytest.mark.parametrize('patch', [
    lambda d: d['vulnerabilities'][0]['cve'].update(references=[{'url': ''}]),
    lambda d: d['vulnerabilities'][0]['cve'].update(published=''),
], ids=['empty-reference-url', 'empty-published'])
def test_c05_values_below_the_snapshot_minimums_are_typed_provider_errors(patch):
    with pytest.raises(EnrichmentError) as info:
        cve.normalize(CVE_ID, {'nvd': edited(NVD, patch)}, WHEN)
    assert info.value.code == 'PT-ENRICH-PROVIDER'


def test_c05_a_rejected_provider_does_not_discard_the_valid_one():
    bad = edited(NVD, lambda d: d['vulnerabilities'][0]['cve']['descriptions'][0].update(value='bad \ud800'))
    warnings: list[str] = []
    (snapshot,) = cli._normalize_available(cve, CVE_ID, {'nvd': bad, 'msrc': MSRC}, WHEN, warnings)
    assert set(snapshot.response_digests) == {'msrc'}
    assert any('nvd' in w and 'rejected' in w for w in warnings)


# --- C-10: CWE identifiers need a token boundary ----------------------------------------------------------------

def test_c10_cwe_identifiers_are_never_invented_from_a_longer_token():
    cwe_list = ['CWE-787: Out-of-bounds Write', 'CWE-20 Improper Input Validation', 'CWE-79', 'CWE-1234567',
                'CWE-125-foo', 'CWE-20abc', 'xCWE-79', 'NVD-CWE-noinfo']
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cweList=cwe_list)))
    assert sorted(c.value for c in s.cwes) == ['CWE-20', 'CWE-787', 'CWE-79']


# --- C-09: --snapshot files are imported as strict, bounded JSON -------------------------------------------------

@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    service.close()
    return root


def correlate(project, path, capsys):
    code = cli.main(['correlate', str(project), '--cve', CVE_ID, '--snapshot', str(path), '--json', '--dry-run'])
    out, err = capsys.readouterr()
    return code, out, err


def test_c09_a_clean_snapshot_file_is_still_accepted(project, tmp_path, capsys):
    path = tmp_path / 'ok.json'
    path.write_text(json.dumps([snap().model_dump(mode='json')], indent=2), encoding='utf-8')
    code, out, _ = correlate(project, path, capsys)
    assert code == 0 and json.loads(out)['result']['snapshot_ids']


@pytest.mark.parametrize('label, make', [
    ('duplicate-key', lambda text: text[:-1] + ', "conflicts": []}'),  # a valid snapshot whose key repeats
    ('nan', lambda text: text.replace('"base_score_tenths": 98', '"base_score_tenths": NaN', 1)),
    ('huge-exponent', lambda text: text.replace('"base_score_tenths": 98', '"base_score_tenths": 1e999', 1)),
    ('lone-surrogate', lambda text: text.replace('"conflicts": []', '"conflicts": ["\\ud800"]', 1)),
], ids=['duplicate-key', 'nan', 'huge-exponent', 'lone-surrogate'])
def test_c09_non_strict_snapshot_files_are_refused(project, tmp_path, capsys, label, make):
    text = make(json.dumps(snap().model_dump(mode='json')))
    assert text != json.dumps(snap().model_dump(mode='json'))
    path = tmp_path / 'bad.json'
    path.write_text(text, encoding='utf-8')
    code, _, err = correlate(project, path, capsys)
    assert code == 2 and 'cannot load snapshot bad.json' in err, err


def test_c09_snapshot_files_beyond_the_size_cap_are_refused_unread(project, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cve, 'MAX_SNAPSHOT_BYTES', 4096)
    path = tmp_path / 'big.json'
    path.write_text(json.dumps([snap().model_dump(mode='json')]) + ' ' * 8192, encoding='utf-8')  # valid, padded
    code, _, err = correlate(project, path, capsys)
    assert code == 2 and 'cannot load snapshot big.json' in err and 'exceeds' in err, err


@pytest.mark.parametrize('field, value, needle', [
    ('snapshot_id', '0' * 64, 'snapshot_id'),
    ('retrieved_at', 'yesterday', 'retrieved_at'),
    ('retrieved_at', '2026-01-01T00:00:00', 'retrieved_at'),
], ids=['forged-id', 'unparseable-time', 'naive-time'])
def test_acq10_import_checks_snapshot_identity_and_time(field, value, needle):
    good = snap().model_dump(mode='json')
    bad = {**good, field: value}
    with pytest.raises(EnrichmentError) as info:
        cve.parse_snapshots(json.dumps([good, bad]).encode())
    assert info.value.code == 'PT-ENRICH-INPUT' and 'snapshot 1' in str(info.value) and needle in str(info.value)


def test_c09_the_loader_reports_typed_errors_for_every_refusal():
    good = json.dumps(snap().model_dump(mode='json')).encode()
    assert [s.cve_id for s in cve.parse_snapshots(good)] == [CVE_ID]
    assert cve.parse_snapshots(b'[' + good + b',' + good + b']')[1].cve_id == CVE_ID
    for raw in (good[:-1] + b', "conflicts": []}', b'{"cve_id": "CVE-2024-38063"}', b'[1]', b'\xff', b'[NaN]'):
        with pytest.raises(EnrichmentError) as info:
            cve.parse_snapshots(raw)
        assert info.value.code == 'PT-ENRICH-INPUT'
    with pytest.raises(EnrichmentError) as info:
        cve.parse_snapshots(b' ' * (cve.MAX_SNAPSHOT_BYTES + 1))
    assert info.value.code == 'PT-ENRICH-LIMIT'
