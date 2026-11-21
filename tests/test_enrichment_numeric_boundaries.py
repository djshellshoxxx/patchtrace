"""Issue #105 E3/E4: hostile numeric/time inputs remain typed, with valid boundary controls.

Provider variants below are authored mutations of the existing redacted fixtures.
They establish parser and CLI behavior, not new provider or CVE accuracy evidence.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import ROUND_DOWN, ROUND_HALF_EVEN, Rounded, getcontext, localcontext
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.enrichment import cve, intelligence
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.service import ProjectService

CVE_ID = 'CVE-2024-38063'
WHEN = '2026-10-12T03:46:00Z'
FIXTURES = Path(__file__).parent / 'fixtures' / 'cve'
BODIES = {provider: (FIXTURES / f'{provider}_{CVE_ID}.json').read_bytes() for provider in ('nvd', 'msrc')}
OUTSIDE_UTC = ('9999-12-31T23:59:59-05:00', '0001-01-01T00:00:00+05:00')


def _score_body(provider, number):
    body = json.loads(BODIES[provider])
    metric = (body['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']
              if provider == 'nvd' else body)
    metric['baseScore'] = '__numeric_control__'
    return json.dumps(body).replace('"__numeric_control__"', number).encode('utf-8')


def _snapshot():
    return cve.normalize(CVE_ID, {'nvd': BODIES['nvd']}, WHEN)


@pytest.mark.parametrize('provider', ['nvd', 'msrc'])
@pytest.mark.parametrize('number', ['1e99999999999999999999', '1e-99999999999999999999', '1e1000000'])
def test_unrepresentable_provider_numbers_are_typed_provider_errors(provider, number):
    with pytest.raises(EnrichmentError) as exc:
        cve.normalize(CVE_ID, {provider: _score_body(provider, number)}, WHEN)
    assert exc.value.code == 'PT-ENRICH-PROVIDER'


@pytest.mark.parametrize(('number', 'tenths'), [('0', 0), ('1e1', 100), ('9.8', 98),
                                             ('0e999999', 0), ('0e-999999', 0),
                                             ('-0.0', 0), ('9.80000000', 98), ('10.000000', 100)])
def test_valid_boundary_scores_keep_exact_tenths(number, tenths):
    result = cve.normalize(CVE_ID, {'nvd': _score_body('nvd', number)}, WHEN)
    assert {record.base_score_tenths for record in result.cvss} == {tenths}


@pytest.mark.parametrize('provider', ['nvd', 'msrc'])
@pytest.mark.parametrize('number', ['1e-1000100', '9.80000000000000000000000000000001'])
def test_non_tenth_scores_cannot_round_or_underflow_into_valid_scores(provider, number):
    with pytest.raises(EnrichmentError) as exc:
        cve.normalize(CVE_ID, {provider: _score_body(provider, number)}, WHEN)
    assert exc.value.code == 'PT-ENRICH-PROVIDER'


@pytest.mark.parametrize('provider', ['nvd', 'msrc'])
@pytest.mark.parametrize(('rounding', 'trap_rounded'), [(ROUND_HALF_EVEN, False), (ROUND_DOWN, False),
                                                     (ROUND_DOWN, True)])
def test_valid_tenths_do_not_depend_on_the_callers_precision_or_traps(provider, rounding, trap_rounded):
    with localcontext() as caller:
        caller.prec = 1
        caller.rounding = rounding
        caller.traps[Rounded] = trap_rounded
        caller.clear_flags()
        before = str(caller)
        result = cve.normalize(CVE_ID, {provider: _score_body(provider, '9.80000000')}, WHEN)
        assert {record.base_score_tenths for record in result.cvss} == {98}
        assert getcontext() is caller and str(caller) == before


@pytest.mark.parametrize('number', ['1e99999999999999999999', '0e999999'])
def test_provider_parsing_preserves_the_callers_decimal_context(number):
    with localcontext() as caller:
        caller.prec = 17
        caller.rounding = ROUND_DOWN
        caller.clear_flags()
        before = str(caller)
        if number.startswith('1'):
            with pytest.raises(EnrichmentError):
                cve.normalize(CVE_ID, {'nvd': _score_body('nvd', number)}, WHEN)
        else:
            assert cve.normalize(CVE_ID, {'nvd': _score_body('nvd', number)}, WHEN).cvss[0].base_score_tenths == 0
        assert getcontext() is caller
        assert str(caller) == before


@pytest.mark.parametrize('timestamp', OUTSIDE_UTC)
@pytest.mark.parametrize('operation', ['normalize', 'parse_snapshots', 'is_stale', 'select_latest'])
def test_retrieval_times_outside_utc_range_are_typed_input_errors(timestamp, operation):
    snapshot = _snapshot().model_copy(update={'retrieved_at': timestamp})
    with pytest.raises(EnrichmentError) as exc:
        if operation == 'normalize':
            cve.normalize(CVE_ID, {'nvd': BODIES['nvd']}, timestamp)
        elif operation == 'parse_snapshots':
            cve.parse_snapshots(snapshot.model_dump_json().encode('utf-8'))
        elif operation == 'is_stale':
            cve.is_stale(snapshot, datetime(2026, 10, 12, tzinfo=UTC), 30)
        else:
            cve.select_latest([snapshot])
    assert exc.value.code == 'PT-ENRICH-INPUT'


@pytest.mark.parametrize('timestamp', ['0001-01-01T00:00:00Z', '0001-01-01T05:00:00+05:00',
                                     '9999-12-31T23:59:59Z', '9999-12-31T18:59:59-05:00'])
def test_representable_extreme_dates_remain_usable_without_rewriting_provenance(timestamp):
    snapshot = cve.normalize(CVE_ID, {'nvd': BODIES['nvd']}, timestamp)
    assert snapshot.retrieved_at == timestamp
    assert snapshot.snapshot_id == _snapshot().snapshot_id
    assert cve.parse_snapshots(snapshot.model_dump_json().encode('utf-8')) == [snapshot]
    assert not cve.is_stale(snapshot, datetime.fromisoformat(timestamp), 0)
    assert cve.select_latest([snapshot]) == ((snapshot,), ())


@pytest.mark.parametrize('timestamp', OUTSIDE_UTC)
def test_unrepresentable_freshness_clock_is_a_typed_input_error(timestamp):
    with pytest.raises(EnrichmentError) as exc:
        cve.is_stale(_snapshot(), datetime.fromisoformat(timestamp), 30)
    assert exc.value.code == 'PT-ENRICH-INPUT'


def test_cli_keeps_valid_provider_when_another_has_an_unrepresentable_decimal(tmp_path, monkeypatch, capsys):
    service = ProjectService.sample(tmp_path / 'case')
    project = service.root
    service.close()

    def fetch(*_args, **_kwargs):
        bodies = {'nvd': BODIES['nvd'], 'msrc': _score_body('msrc', '1e99999999999999999999')}
        return {CVE_ID: {p: intelligence.RawResponse(p, CVE_ID, body, 'unused', 'unused', WHEN)
                         for p, body in bodies.items()}}, {}

    monkeypatch.setattr(intelligence, 'fetch_all', fetch)
    result = cli.main(['correlate', str(project), '--cve', CVE_ID, '--fetch', '--providers', 'msrc,nvd',
                       '--consent-providers', 'msrc,nvd', '--json', '--dry-run'])
    output = json.loads(capsys.readouterr().out)
    assert result == 0 and output['status'] == 'partial'
    assert output['result']['snapshot_ids'] == [_snapshot().snapshot_id]
    assert any('msrc' in warning and 'rejected' in warning for warning in output['warnings'])


@pytest.mark.parametrize('timestamp', OUTSIDE_UTC)
def test_cli_refuses_invalid_snapshot_time_before_contextual_ranking(tmp_path, capsys, timestamp):
    service = ProjectService.sample(tmp_path / 'case')
    project = service.root
    service.close()
    snapshot = _snapshot().model_copy(update={'retrieved_at': timestamp})
    source = tmp_path / 'snapshot.json'
    original = snapshot.model_dump_json().encode('utf-8')
    source.write_bytes(original)
    result = cli.main(['correlate', str(project), '--cve', CVE_ID, '--snapshot', str(source),
                       '--json', '--dry-run'])
    output = json.loads(capsys.readouterr().out)
    assert result == 2 and output['status'] == 'failed'
    assert 'PT-ENRICH-INPUT' in output['error']
    assert source.read_bytes() == original
