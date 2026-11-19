"""Current stored-tool admission over real stores and an authored fake FLOSS producer.

Synthetic PE inputs are read, never executed. No native-tool qualification.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from test_ui_strings_run import fake_floss, make_project, tool_store

from patchtrace.intelligence.tools import runner
from patchtrace.intelligence.tools.admission import latest_admitted
from patchtrace.intelligence.tools.common import EVIDENCE_KIND, ToolError, ToolRun, evidence_entry_id
from patchtrace.service import ProjectService


def request(service, config):
    return runner.RunRequest(tuple(runner.ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                                   for a in service.project.artifacts),
                             runner.Setup(floss=config), profile='context', engines=('floss',))


@pytest.fixture(scope='module')
def seeds(tmp_path_factory):
    base = tmp_path_factory.mktemp('tool-admission')
    with make_project(base, 'floss-static') as service:
        config = fake_floss(base, service)
        first = runner.run_tools(request(service, config), tool_store(service), threading.Event())
        assert all(not job.run.cache_hit and job.run.raw_sidecar for job in first)
        original = service.root
    fresh = base / 'fresh'
    shutil.copytree(original, fresh)
    with ProjectService.open(original) as service:
        again = runner.run_tools(request(service, config), tool_store(service), threading.Event())
        assert all(job.run.cache_hit and job.run.raw_sidecar is None and job.run.stdout_digest is None
                   for job in again)
    return {'fresh': fresh, 'cache': original}


@pytest.fixture
def case(tmp_path, seeds, request):
    root = tmp_path / 'case'
    shutil.copytree(seeds[getattr(request, 'param', 'cache')], root)
    with ProjectService.open(root) as service:
        store = tool_store(service)
        artifact = next(a for a in service.project.artifacts if a.side == 'newer')
        yield SimpleNamespace(service=service, store=store, db=service.store.connection, artifact=artifact)


def admit(case):
    return latest_admitted(case.store, engine='floss', side='newer', artifact_sha256=case.artifact.sha256)


@pytest.mark.parametrize('case', ['fresh', 'cache'], indirect=True)
def test_real_producer_fresh_and_cache_keep_admitted_original_raw_provenance(case):
    result = admit(case)
    assert result is not None
    assert result.run.input_artifact_hash == result.evidence.artifact_sha256 == case.artifact.sha256
    assert result.evidence_run.run_id == result.evidence.run_id
    assert result.evidence_run.config_digest == result.run.config_digest
    raw = (case.service.root / result.evidence_run.raw_sidecar).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result.evidence_run.stdout_digest
    if result.run.cache_hit:
        assert result.run.raw_sidecar is None and result.run.stdout_digest is None
        assert result.run.run_id != result.evidence_run.run_id
    else:
        assert result.evidence_run is result.run


@pytest.mark.parametrize('row', ['selected-run', 'evidence', 'origin-run'])
@pytest.mark.parametrize(('field', 'value'), [
    ('stale', 1), ('project_id', 'foreign-authored-project'), ('run_id', 'foreign-guard-run'),
    ('raw_sha256', 'f' * 64), ('input_digest', 'e' * 64), ('status', 'failed'), ('id', 'foreign-authored-row'),
])
def test_selected_evidence_and_cache_origin_metadata_refuse_without_mutation(case, row, field, value):
    valid = admit(case)
    identity = {'selected-run': valid.run.run_id, 'evidence': evidence_entry_id(valid.evidence),
                'origin-run': valid.evidence_run.run_id}[row]
    assert field in {'stale', 'project_id', 'run_id', 'raw_sha256', 'input_digest', 'status', 'id'}
    case.db.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, identity))
    before = tuple(case.db.iterdump())
    with pytest.raises(ToolError) as error:
        admit(case)
    assert error.value.code == 'PT-TOOL-STALE'
    assert tuple(case.db.iterdump()) == before


def test_legacy_latest_behavior_remains_separate_from_opt_in_admission(case):
    valid = admit(case)
    case.db.execute('UPDATE enrichment_entries SET stale=1 WHERE id=?', (valid.run.run_id,))
    assert case.store.latest('floss', 'newer') is not None
    with pytest.raises(ToolError):
        admit(case)


@pytest.mark.parametrize('row', ['selected-run', 'evidence'])
def test_blob_body_is_a_typed_read_refusal_even_when_content_digest_matches(case, row):
    valid = admit(case)
    identity = valid.run.run_id if row == 'selected-run' else evidence_entry_id(valid.evidence)
    body = case.db.execute('SELECT body FROM enrichment_entries WHERE id=?', (identity,)).fetchone()[0]
    case.db.execute('UPDATE enrichment_entries SET body=? WHERE id=?',
                    (sqlite3.Binary(body.encode('utf-8')), identity))
    before = tuple(case.db.iterdump())
    with pytest.raises(ToolError) as error:
        admit(case)
    assert error.value.code == 'PT-TOOL-OUTPUT'
    assert tuple(case.db.iterdump()) == before


@pytest.mark.parametrize('row', ['selected-run', 'evidence', 'origin-run'])
def test_original_json_duplicate_keys_refuse_despite_equivalent_parsed_body(case, row):
    valid = admit(case)
    identity = {'selected-run': valid.run.run_id, 'evidence': evidence_entry_id(valid.evidence),
                'origin-run': valid.evidence_run.run_id}[row]
    body = case.db.execute('SELECT body FROM enrichment_entries WHERE id=?', (identity,)).fetchone()[0]
    duplicate = body.rstrip()[:-1] + ',"run_id":' + json.dumps(json.loads(body)['run_id']) + '}'
    assert json.loads(duplicate) == json.loads(body)
    case.db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                    (duplicate, hashlib.sha256(duplicate.encode()).hexdigest(), identity))
    before = tuple(case.db.iterdump())
    with pytest.raises(ToolError) as error:
        admit(case)
    assert error.value.code == 'PT-TOOL-OUTPUT'
    assert tuple(case.db.iterdump()) == before


@pytest.mark.parametrize('row', ['evidence', 'origin-run'])
def test_missing_selected_evidence_or_origin_refuses_without_older_run_fallback(case, row):
    valid = admit(case)
    identity = evidence_entry_id(valid.evidence) if row == 'evidence' else valid.evidence_run.run_id
    case.db.execute('DELETE FROM enrichment_entries WHERE id=?', (identity,))
    before = tuple(case.db.iterdump())
    with pytest.raises(ToolError) as error:
        admit(case)
    assert error.value.code == 'PT-TOOL-STALE'
    assert tuple(case.db.iterdump()) == before


def test_real_cache_selects_matching_side_among_retained_orientation_history(case):
    valid = admit(case)
    assert valid.run.cache_hit and valid.run.raw_sidecar is None
    # Retain coherent opposite-side history for the same artifact/key. Cache
    # keys omit side; an ordinary A/A runner request is not valid input.
    run_body = json.loads(valid.evidence_run.model_dump_json())
    run_body.update(side='older', run_id='authored-opposite-orientation-origin')
    other_run = ToolRun.model_validate_json(json.dumps(run_body))
    body = json.loads(valid.evidence.model_dump_json())
    body['side'] = 'older'
    encoded = json.dumps(body).replace(json.dumps(valid.evidence_run.run_id), json.dumps(other_run.run_id))
    other_evidence = type(valid.evidence).model_validate_json(encoded)
    case.store.publish_run(other_run)
    case.store.publish_evidence(other_evidence)
    assert case.store.enrichment.entries(EVIDENCE_KIND)[0].body['side'] == 'older'
    current = admit(case)
    assert current.run == valid.run
    assert current.evidence == valid.evidence
    assert current.evidence_run == valid.evidence_run


def test_unrelated_side_model_does_not_invalidate_current_side_selection(case):
    valid = admit(case)
    rows = case.db.execute("SELECT id,body FROM enrichment_entries WHERE kind='tool-run'").fetchall()
    identity, body = next((identity, json.loads(text)) for identity, text in rows
                          if json.loads(text)['side'] == 'older')
    body['evidence_count'] = 'not-an-integer'
    text = json.dumps(body)
    with pytest.raises(ValueError):
        ToolRun.model_validate_json(text)
    case.db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                    (text, hashlib.sha256(text.encode()).hexdigest(), identity))
    assert admit(case) == valid
