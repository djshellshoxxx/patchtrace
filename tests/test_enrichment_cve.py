"""B3 CVE normalization and contextual reranking. Provider fixtures are trimmed real
responses (tests/fixtures/cve/README.md); every derived variant below is synthetic."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from patchtrace.enrichment import cve, identity
from patchtrace.enrichment.contracts import (
    ChangeSignal,
    CveSnapshot,
    DetectorOutcome,
    EnrichmentError,
    FeatureTransition,
    RankingConfig,
    SignalSet,
    SourceLocation,
)
from patchtrace.enrichment.ranking import rank

FIX = Path(__file__).parent / 'fixtures' / 'cve'
CVE_ID = 'CVE-2024-38063'
NVD = (FIX / 'nvd_CVE-2024-38063.json').read_bytes()
MSRC = (FIX / 'msrc_CVE-2024-38063.json').read_bytes()
WHEN = '2026-10-12T03:46:00Z'
H = 'a' * 64


def edited(raw: bytes, fn) -> bytes:
    doc = json.loads(raw)
    fn(doc)
    return json.dumps(doc).encode()


def snap(nvd=NVD, msrc=MSRC, cve_id=CVE_ID):
    responses = {}
    if nvd is not None:
        responses['nvd'] = nvd
    if msrc is not None:
        responses['msrc'] = msrc
    return cve.normalize(cve_id, responses, WHEN)


# --- normalization ------------------------------------------------------------

def test_real_fixtures_normalize_with_attribution_and_exact_tenths():
    s = snap()
    assert s.cve_id == CVE_ID and s.normalization_version == cve.NORMALIZATION_VERSION
    assert {(c.source, c.value) for c in s.cwes} == {('msrc', 'CWE-191'), ('nvd', 'CWE-191')}
    assert {(r.source, r.base_score_tenths) for r in s.cvss} == {('msrc', 98), ('nvd:secure@microsoft.com', 98)}
    msrc_cvss = next(r for r in s.cvss if r.source == 'msrc')
    assert msrc_cvss.severity == ''  # MSRC "Critical" is a Microsoft rating, not CVSS severity
    assert ('msrc', 'Windows TCP/IP') in {(p.source, p.value) for p in s.products}
    assert {d.source for d in s.descriptions} == {'msrc', 'nvd'}
    assert s.conflicts == ()  # same base vector despite MSRC temporal metrics
    assert s.feature_ids == ()


def test_nvd_noinfo_is_not_a_cwe():
    assert {c.value for c in snap(msrc=None).cwes} == {'CWE-191'}


def test_snapshot_id_pins_digests_not_retrieval_time():
    a = cve.normalize(CVE_ID, {'nvd': NVD}, '2026-01-01T00:00:00Z')
    b = cve.normalize(CVE_ID, {'nvd': NVD}, '2026-10-12T00:00:00+00:00')
    assert a.snapshot_id == b.snapshot_id and a.retrieved_at != b.retrieved_at
    changed = cve.normalize(CVE_ID, {'nvd': NVD + b' '}, '2026-01-01T00:00:00Z')
    assert changed.snapshot_id != a.snapshot_id
    assert snap().snapshot_id not in (a.snapshot_id,)


def test_wrong_id_200_is_provider_error():
    other = edited(NVD, lambda d: d['vulnerabilities'][0]['cve'].update(id='CVE-2024-38064'))
    with pytest.raises(EnrichmentError) as exc:
        snap(nvd=other, msrc=None)
    assert exc.value.code == 'PT-ENRICH-PROVIDER'
    with pytest.raises(EnrichmentError) as exc:
        snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cveNumber='CVE-2024-1')))
    assert exc.value.code == 'PT-ENRICH-PROVIDER'


def test_nvd_empty_result_for_unknown_cve_is_provider_error():
    empty = b'{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}'
    with pytest.raises(EnrichmentError) as exc:
        snap(nvd=empty, msrc=None)
    assert exc.value.code == 'PT-ENRICH-PROVIDER'


@pytest.mark.parametrize('raw', [b'', b'{', b'\xff\xfe', b'{"a":1,"a":2}', b'{"x":NaN}', b'[]',
                                 b'{"vulnerabilities":"x"}'])
def test_malformed_json_rejected(raw):
    with pytest.raises(EnrichmentError) as exc:
        snap(nvd=raw, msrc=None)
    assert exc.value.code == 'PT-ENRICH-PROVIDER'


def test_oversized_response_rejected():
    with pytest.raises(EnrichmentError) as exc:
        snap(nvd=b' ' * (cve.MAX_RESPONSE_BYTES + 1), msrc=None)
    assert exc.value.code == 'PT-ENRICH-LIMIT'


@pytest.mark.parametrize('score', ['9.85', '11', 'abc', True])
def test_non_tenth_scores_rejected(score):
    with pytest.raises(EnrichmentError):
        snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(baseScore=score)))


@pytest.mark.parametrize('bad', ['CVE-2024-123', 'cve-2024-38063', 'CVE-2024-38063\n', 'CVE-2024-' + '9' * 20, 1])
def test_invalid_cve_id_and_inputs(bad):
    with pytest.raises(EnrichmentError):
        cve.normalize(bad, {'nvd': NVD}, WHEN)


def test_input_validation():
    for responses in ({}, {'other': NVD}):
        with pytest.raises(EnrichmentError):
            cve.normalize(CVE_ID, responses, WHEN)
    with pytest.raises(EnrichmentError):
        cve.normalize(CVE_ID, {'nvd': NVD}, '2026-10-12T00:00:00')  # naive time


def test_missing_cwe_is_empty_not_invented():
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cweList=[])))
    assert s.cwes == () and s.conflicts == ()


def test_conflicting_cwe_and_cvss_recorded_not_merged():
    # Synthetic: MSRC edited to disagree with NVD.
    msrc = edited(MSRC, lambda d: d.update(cweList=['CWE-787: Out-of-bounds Write'], baseScore='8.8',
                                           vectorString='CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'))
    s = snap(msrc=msrc)
    assert any(c.startswith('cwe:') for c in s.conflicts)
    assert any(c.startswith('cvss 3.1:') for c in s.conflicts)
    assert {r.base_score_tenths for r in s.cvss} == {88, 98}  # both kept
    assert {(c.source, c.value) for c in s.cwes} == {('msrc', 'CWE-787'), ('nvd', 'CWE-191')}


def test_conflicting_severity_never_merged():
    def add(d):
        m = d['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31']
        m.append(json.loads(json.dumps(m[0])) | {'source': 'nvd@nist.gov', 'type': 'Primary'})
        m[-1]['cvssData']['baseSeverity'] = 'HIGH'
    s = snap(nvd=edited(NVD, add), msrc=None)
    assert any(c.startswith('severity 3.1:') for c in s.conflicts)
    assert {r.severity for r in s.cvss} == {'HIGH', 'CRITICAL'}


def test_freshness():
    s = snap()
    t = datetime(2026, 10, 12, 3, 46, tzinfo=UTC)
    assert not cve.is_stale(s, t + timedelta(days=7), 7)
    assert cve.is_stale(s, t + timedelta(days=7, seconds=1), 7)
    assert cve.is_stale(s, t - timedelta(seconds=1), 7)  # future retrieval is untrusted
    with pytest.raises(EnrichmentError):
        cve.is_stale(s, t, True)
    with pytest.raises(EnrichmentError):
        cve.is_stale(s, datetime(2026, 10, 12), 7)


def test_cve_module_is_pure():
    code = ('import sys\nimport patchtrace.enrichment.cve\n'
            "bad = {'PySide6', 'subprocess', 'ssl', 'http.client', 'urllib.request'} & set(sys.modules)\n"
            'assert not bad, bad\n')
    src = str(Path(cve.__file__).resolve().parents[2])  # this checkout, not an installed copy
    subprocess.run([sys.executable, '-c', code], check=True, env={'PYTHONPATH': src})


# --- contextual ranking -------------------------------------------------------

def pid(name):
    return identity.domain_id('test-pairing', 1, name)


def sig(detector, confidence, pairing, group='1'):
    p = pid(pairing)
    gk = identity.domain_id('test-group', 1, pairing + group)
    loc = SourceLocation(side='newer', artifact_id='a', run_id='r', function_id='f', start_line=1,
                         end_line=1, excerpt_sha256=H)
    return ChangeSignal(signal_id=identity.signal_id(p, detector, 1, gk, [{'n': 0}]), pairing_id=p,
                        match_id='m-' + pairing, detector=detector, detector_version=1,
                        confidence=confidence, group_key=gk, locations=(loc,), rationale='synthetic')


def sset(pairing, signals):
    p = pid(pairing)
    return SignalSet(pairing_id=p, match_id='m-' + pairing, category='modified', signals=tuple(signals),
                     outcomes=(DetectorOutcome(pairing_id=p, detector='BND', status='complete'),),
                     status='complete')


def scenario():
    sets = [sset('alpha', [sig('BND', 'moderate', 'alpha')]),            # score 27
            sset('beta', [sig('OVF', 'moderate', 'beta')]),              # score 25
            sset('gamma', [sig('ERR', 'weak', 'gamma')]),                # score 5
            sset('delta', [])]
    return sets, rank(sets, RankingConfig())


def names():
    return {pid('beta'): ['Ipv6pReassembleDatagram', 'TcpReceive'], pid('alpha'): ['FUN_14001000'],
            pid('gamma'): ['WriteBufferToStack'], pid('delta'): ['TcpConnect']}


def test_real_cve_reorders_without_changing_base():
    sets, ranking = scenario()
    before = ranking.model_dump()
    result = cve.contextual_rank(ranking, sets, [], [snap()], ['tcpip.sys'], names())
    assert ranking.model_dump() == before  # input untouched
    by = {e.pairing_id: e for e in result.entries}
    beta = by[pid('beta')]
    # CWE-191 aligns with moderate OVF (+10); "tcp" term matches TcpReceive (+12); module +4.
    assert [c.kind for c in beta.contributions] == ['identifier', 'cwe', 'product']
    assert beta.adjustment == 26 and beta.context_score == beta.base_score + 26
    assert beta.context_rank == 1 and beta.base_rank == 2
    alpha = by[pid('alpha')]
    assert alpha.adjustment == 0 and alpha.context_score == alpha.base_score  # BND not aligned with CWE-191
    delta = by[pid('delta')]
    # TcpConnect matches "tcp" (binary support) so the product match may corroborate it.
    assert delta.adjustment == 16
    for e in result.entries:
        orig = next(x for x in ranking.entries if x.pairing_id == e.pairing_id)
        assert (e.base_score, e.base_rank, e.match_id) == (orig.score, orig.rank, orig.match_id)
    assert result.status == 'complete' and result.snapshot_ids == (snap().snapshot_id,)


def test_generic_noise_contributes_zero():
    sets, ranking = scenario()
    noisy = edited(MSRC, lambda d: d.update(
        cveTitle='Windows Kernel Memory Buffer Overflow Stack Write Remote Code Execution Vulnerability',
        cweList=[], tag='Windows Kernel', vectorString=None))
    result = cve.contextual_rank(ranking, sets, [], [snap(nvd=None, msrc=noisy)], ['ntoskrnl.exe'], names())
    assert all(e.adjustment == 0 for e in result.entries)
    assert [e.pairing_id for e in result.entries] == [e.pairing_id for e in ranking.entries]


def test_product_match_alone_is_not_binary_support():
    sets, ranking = scenario()
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cweList=[], cveTitle='Unrelated words')))
    result = cve.contextual_rank(ranking, sets, [], [s], ['tcpip.sys'], {})
    assert all(e.adjustment == 0 for e in result.entries)


def test_no_snapshots_is_unavailable_and_identity_order():
    sets, ranking = scenario()
    result = cve.contextual_rank(ranking, sets, [], [], ['tcpip.sys'], names())
    assert result.status == 'unavailable'
    assert [(e.pairing_id, e.context_rank) for e in result.entries] == [
        (e.pairing_id, e.rank) for e in ranking.entries]


def test_conflicting_cwe_blocks_contribution():
    sets, ranking = scenario()
    msrc = edited(MSRC, lambda d: d.update(cweList=['CWE-787: Out-of-bounds Write']))  # synthetic conflict
    result = cve.contextual_rank(ranking, sets, [], [snap(msrc=msrc)], [], {})
    for e in result.entries:
        assert not any(c.kind == 'cwe' for c in e.contributions)
    by = {e.pairing_id: e for e in result.entries}
    assert by[pid('alpha')].blocked and by[pid('beta')].blocked  # BND↔787, OVF↔191 would align
    assert by[pid('gamma')].blocked == ()


def test_caps_identifier_cwe_and_total():
    sets = [sset('x', [sig('BND', 'moderate', 'x', '1'), sig('SIZE', 'strong', 'x', '2'),
                       sig('OVF', 'moderate', 'x', '3')])]
    ranking = rank(sets, RankingConfig())
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(
        cveTitle='Alphaword Betaword Gammaword Deltaword',
        cweList=['CWE-787', 'CWE-125', 'CWE-190'])))
    trans = [FeatureTransition(transition_id=H, pairing_id=pid('x'), match_id='m-x', feature_id=7, kind='introduced',
                               confidence='moderate', qualifies=True)]
    s = s.model_copy(update={'feature_ids': (7,)})
    result = cve.contextual_rank(ranking, sets, trans, [s], ['tcpip.sys'],
                                 {pid('x'): ['AlphawordBetaword_Gammaword', 'Deltaword']})
    e = result.entries[0]
    kinds = [c.kind for c in e.contributions]
    assert kinds.count('identifier') == 2 and kinds.count('cwe') == 2
    assert 'feature' in kinds and 'product' in kinds
    assert e.adjustment == 30 and e.context_score == min(100, e.base_score + 30)


def test_feature_requires_qualifying_transition():
    sets = [sset('x', [])]
    ranking = rank(sets, RankingConfig())
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cveTitle='none', cweList=[]))).model_copy(
        update={'feature_ids': (7,)})
    t = FeatureTransition(transition_id=H, pairing_id=pid('x'), match_id='m-x', feature_id=7,
                          kind='unknown', confidence='weak', qualifies=False)
    assert cve.contextual_rank(ranking, sets, [t], [s], [], {}).entries[0].adjustment == 0
    t = t.model_copy(update={'qualifies': True})
    assert cve.contextual_rank(ranking, sets, [t], [s], [], {}).entries[0].adjustment == 8


def test_weak_signal_does_not_align_cwe():
    sets = [sset('x', [sig('OVF', 'weak', 'x')])]
    ranking = rank(sets, RankingConfig())
    assert cve.contextual_rank(ranking, sets, [], [snap()], [], {}).entries[0].adjustment == 0


def test_term_cap_marks_partial():
    sets, ranking = scenario()
    words = ' '.join(f'word{chr(97 + i // 26)}{chr(97 + i % 26)}x' for i in range(300))
    s = snap(nvd=None, msrc=edited(MSRC, lambda d: d.update(cveTitle=words)))
    assert len(cve.context_terms([s])) == 300
    assert cve.contextual_rank(ranking, sets, [], [s], [], {}).status == 'partial'


def test_reranking_is_stable_and_input_order_independent():
    sets, ranking = scenario()
    a = cve.contextual_rank(ranking, sets, [], [snap()], ['tcpip.sys'], names())
    b = cve.contextual_rank(ranking, list(reversed(sets)), [], [snap()], ['TCPIP.SYS'], names())
    assert a == b
    keys = [(-e.context_score, -e.base_score, e.pairing_id) for e in a.entries]
    assert keys == sorted(keys) and [e.context_rank for e in a.entries] == list(range(1, len(keys) + 1))


def test_stale_snapshots_reported():
    sets, ranking = scenario()
    later = datetime(2027, 1, 1, tzinfo=UTC)
    r = cve.contextual_rank(ranking, sets, [], [snap()], [], {}, now=later, max_age_days=30)
    assert r.stale_snapshots == (CVE_ID,)


def test_snapshot_round_trips_strictly():
    s = snap()
    assert CveSnapshot.model_validate_json(s.model_dump_json()) == s
