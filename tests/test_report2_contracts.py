"""SPEC-50 RPT2-2: contract models and the calibration block."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from patchtrace.calibration.artifact import LoadResult
from patchtrace.report2 import calibration_block, contracts

SHA = 'a' * 64


def test_ordinal_block_without_artifact_carries_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path)
    block = calibration_block.build_calibration_block()
    assert block.display_level == 'ordinal'
    assert (block.profile, block.model_id, block.artifact_digest, block.gates) == (None, None, None, None)
    assert block.note == contracts.CALIBRATION_NOTE


def test_caller_request_is_capped_by_display_level_without_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path)
    assert calibration_block.build_calibration_block('numeric').display_level == 'ordinal'
    assert calibration_block.build_calibration_block('bands', profile='G+R').display_level == 'ordinal'


def test_exporter_calls_display_level_itself(monkeypatch):
    calls = []
    monkeypatch.setattr(calibration_block, 'display_level', lambda p, m: calls.append((p, m)) or 'ordinal')
    calibration_block.build_calibration_block('numeric', profile='G')
    assert calls == [('G', None)]


def _models(gates):
    artifact = SimpleNamespace(model_id='m1', digest_sha256=SHA, evidence=SimpleNamespace(gates=gates))
    return {'G+R': LoadResult(artifact, 'ok')}


def test_promoted_level_needs_model_digest_and_gates(monkeypatch):
    monkeypatch.setattr(calibration_block, 'display_level', lambda p, m: 'numeric')
    block = calibration_block.build_calibration_block('numeric', profile='G+R', models=_models({'G0': 'pass'}))
    assert (block.display_level, block.model_id, block.artifact_digest, block.gates) == (
        'numeric', 'm1', SHA, {'G0': 'pass'})
    capped = calibration_block.build_calibration_block('bands', profile='G+R', models=_models({'G0': 'pass'}))
    assert capped.display_level == 'bands'


@pytest.mark.parametrize('models,profile', [(_models({}), 'G+R'), (_models({'G0': 'pass'}), None),
                                            (_models({'G0': 'pass'}), 'other')], ids=['nogates', 'noprofile', 'unknown'])
def test_promotion_without_details_degrades_to_ordinal(monkeypatch, models, profile):
    monkeypatch.setattr(calibration_block, 'display_level', lambda p, m: 'numeric')
    assert calibration_block.build_calibration_block('numeric', profile=profile,
                                                     models=models).display_level == 'ordinal'


def test_bad_request_is_a_value_error():
    with pytest.raises(ValueError):
        calibration_block.build_calibration_block('probability')


@pytest.mark.parametrize('field,value', [('profile', 'G'), ('model_id', 'm'), ('artifact_digest', SHA),
                                         ('gates', {'G0': 'pass'})], ids=['profile', 'model', 'digest', 'gates'])
def test_ordinal_invariant_rejects_any_detail(field, value):
    with pytest.raises(ValidationError, match='ordinal'):
        contracts.Calibration(display_level='ordinal', **{field: value})


def test_promoted_level_without_details_is_rejected():
    with pytest.raises(ValidationError, match='require'):
        contracts.Calibration(display_level='bands')


def test_calibration_note_is_fixed():
    with pytest.raises(ValidationError):
        contracts.Calibration(display_level='ordinal', note='Probability of a vulnerability')


def test_models_are_frozen_strict_and_forbid_extras():
    row = contracts.Channel(engine='bindiff', state='present')
    with pytest.raises(ValidationError):
        row.state = 'absent'
    with pytest.raises(ValidationError):
        contracts.Channel(engine='bindiff', state='present', score=0.9)
    with pytest.raises(ValidationError):
        contracts.Channel(engine='bindiff', state='negative')


def test_no_probability_or_aggregate_field_exists_on_evidence_models():
    forbidden = {'mean', 'average', 'combined_score', 'confidence', 'shown_p', 'probability', 'p', 'score'}
    for model in (contracts.EngineEvidence, contracts.EvidenceRow, contracts.Channel, contracts.Calibration,
                  contracts.UnifiedResult):
        assert not forbidden & set(model.model_fields), model.__name__


def test_unnormalized_text_is_rejected_by_the_contract():
    with pytest.raises(ValidationError, match='normalized'):
        contracts.Lead(lead_id='l1', kind='k', channels=['a'], statement='x\u202ey')
    with pytest.raises(ValidationError, match='normalized'):
        contracts.Lead(lead_id='l1', kind='k', channels=['a'], statement='x\ud800y')
    assert contracts.Lead(lead_id='l1', kind='k', channels=['a'], statement='<U+202E>').statement == '<U+202E>'


def test_ordinal_index_is_bounded_to_the_evidence_cap():
    base = dict(match_id='m', verdict='corroborated', tier='high', channels=[], supporting_engines=[],
                contradicting_engines=[], missing_engines=[])
    assert contracts.EvidenceRow(**base, ordinal_index=83).ordinal_index == 83
    with pytest.raises(ValidationError):
        contracts.EvidenceRow(**base, ordinal_index=84)


@pytest.mark.parametrize('kind,ident', [('cve', 'CVE-2024-1'), ('cve', 'cve-2024-12345'), ('kb', 'KB12'),
                                        ('cwe', 'CWE-x'), ('cve', 'CVE-2024-12345<b>')],
                         ids=['short', 'lower', 'kb', 'cwe', 'markup'])
def test_advisory_ids_pass_a_strict_regex(kind, ident):
    with pytest.raises(ValidationError):
        contracts.Advisory(kind=kind, id=ident, text='t')


def test_advisory_claim_level_is_vendor_claim_and_phrase_ids_are_free():
    advisory = contracts.Advisory(kind='phrase', id='remote code execution', text='t')
    assert advisory.claim_level == 'vendor-claim'
    with pytest.raises(ValidationError):
        contracts.Advisory(kind='cve', id='CVE-2024-12345', text='t', claim_level='observed-in-file')


def test_symbol_servers_only_when_online():
    with pytest.raises(ValidationError, match='online'):
        contracts.Symbols(mode='local', servers=['msdl.example'])
    assert contracts.Symbols(mode='online', servers=['msdl.example']).servers == ['msdl.example']


def test_build_fact_names_are_a_closed_list():
    with pytest.raises(ValidationError):
        contracts.BuildFact(side='older', fact='arbitrary', value='v', source='pe')
    assert contracts.BuildFact(side='older', fact='file_version', value='1', source='pe').claim_level == (
        'observed-in-file')


def _report(**changes):
    base = dict(project_id='p', name='n', revision=1, created='c', sample=True, limitations=[], selection={},
                artifacts=[], analysis_runs=[], matches=[], interpretations=[], change_ranking=None, annotations=[],
                generated_at='g', sections_present=[], stale_sections=[], tool=contracts.Tool(version='0.1.0'),
                orientation=contracts.Orientation(older_sha256=None, newer_sha256=None),
                calibration=contracts.Calibration(display_level='ordinal'),
                redaction=contracts.Redaction(profile='local', paths=True, code=False, notes=True, urls='text'),
                provenance=contracts.Provenance(revision=1), unknowns=[])
    return contracts.Report2(**(base | changes))


def test_sections_present_must_match_the_data():
    lead = contracts.Lead(lead_id='l', kind='k', channels=['a'], statement='s')
    with pytest.raises(ValidationError, match='sections_present'):
        _report(leads=[lead])
    assert _report(leads=[lead], sections_present=['leads']).to_dict()['leads'][0]['lead_id'] == 'l'


def test_absent_sections_are_omitted_but_v1_nulls_stay():
    data = _report().to_dict()
    assert 'engine_evidence' not in data and 'leads' not in data
    assert data['change_ranking'] is None and data['report_version'] == 2 and data['schema_version'] == 1
    assert data['normalization'] == 'report/2 text normalization applied'
