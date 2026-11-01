"""Retained native recordings, not fresh tool execution: unknown side ownership must abstain."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest
from unified_s0_fixtures import addr_map, func, inputs, loaded, match, rz, rzdiff_set

from patchtrace.calibration.features import extract
from patchtrace.jobs import ProcessResult
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.secondary import rzdiff
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.evidence import assess_reports
from patchtrace.secondary.evidence_view import build_view_model
from patchtrace.secondary.reconcile import Reconciliation, ReconciliationReport, reconcile
from patchtrace.secondary.registry import EngineJob, RawResult, RzDiffAdapter
from patchtrace.secondary.scheduler import ProjectRef, run_engines
from patchtrace.unified import store
from patchtrace.unified.compute import compute_result, is_degrading
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources.secondary import SecondaryAdapter

FIXTURE = Path(__file__).parent / 'fixtures/secondary/rzdiff-0.9.1-native-orientation.json'
RECORDING = json.loads(FIXTURE.read_text())


@pytest.mark.parametrize('attempt', RECORDING['attempts'], ids=lambda row: row['label'])
def test_retained_native_output_never_becomes_side_owned_without_a_witness(attempt):
    process = attempt['process']
    raw = process['stdout'].encode()
    assert hashlib.sha256(raw).hexdigest() == attempt['stdout_sha256']
    cap = Capability(engine='rz-diff', version='0.9.1', path='historical-output-only', supported=True, supports_json=True)
    job = EngineJob(Path('older.bin'), Path('newer.bin'), attempt['input0_sha256'], attempt['input1_sha256'],
                    {}, Path('.'), threading.Event(), 60)
    with pytest.raises(SecondaryError) as rejected:
        RzDiffAdapter().parse(RawResult(process['returncode'], raw, process['stderr'], None,
                                       process.get('reason')), cap, job)
    if raw.strip():
        assert rejected.value.code == 'PT-SECONDARY-ORIENTATION'
        assert rejected.value.kind == 'rz-diff-orientation-unverified'
        assert attempt['stdout_sha256'] in rejected.value.message
    else:
        assert rejected.value.code == 'PT-SECONDARY-INPUT'
        assert 'no output' in rejected.value.message
    assert hashlib.sha256(raw).hexdigest() == attempt['stdout_sha256']
    assert (job.older_sha256, job.newer_sha256) == (attempt['input0_sha256'], attempt['input1_sha256'])


def test_the_same_json_shape_and_bytes_can_have_opposite_side_semantics():
    cases = {row['label']: row for row in RECORDING['attempts']}
    a, b = cases['one-recovered-vs-two'], cases['two-recovered-vs-one']
    assert a['process']['stdout'] == b['process']['stdout']
    assert a['input0_sha256'] == b['input1_sha256'] and a['input1_sha256'] == b['input0_sha256']


@pytest.mark.parametrize('version', ['0.9.1', '00.009.001', '0.9.1+unverified-patch'])
def test_historical_trimmed_fixture_and_unverified_suffixes_cannot_attest_orientation(version):
    raw = (FIXTURE.parent / 'rzdiff-functions.json').read_bytes()
    with pytest.raises(SecondaryError) as rejected:
        rzdiff.parse_output(raw.decode(), version, 'a' * 64, 'b' * 64)
    assert rejected.value.code == 'PT-SECONDARY-ORIENTATION'
    assert hashlib.sha256(raw).hexdigest() in rejected.value.message


def test_affected_probe_is_explicit_and_cannot_reuse_old_scheduler_cache(tmp_path, monkeypatch):
    old, new = tmp_path / 'old.bin', tmp_path / 'new.bin'
    old.write_bytes(b'older bytes')
    new.write_bytes(b'newer bytes')
    old_sha, new_sha = hashlib.sha256(old.read_bytes()).hexdigest(), hashlib.sha256(new.read_bytes()).hexdigest()
    cached = rzdiff_set([rz(0x1000, 0x1080)], older=old_sha, newer=new_sha)
    original = cached.model_dump_json()
    calls = []

    class Cache:
        def find(self, key):
            calls.append(key)
            return cached

    real_probe = rzdiff.probe
    monkeypatch.setattr(rzdiff, 'probe', lambda path, env, cancel: real_probe(
        path, env, cancel, runner=lambda *args, **kwargs: ProcessResult(0, 'rz-diff 0.9.1 @ linux-x86-64\n', None, '')))
    [outcome] = run_engines(ProjectRef(old, new, old_sha, new_sha), ['rz-diff'], registry={
        'rz-diff': RzDiffAdapter('/historical/pinned/rz-diff')}, env={}, cancel=threading.Event(), cache=Cache())
    assert outcome.run.status == 'unsupported' and outcome.match_set is None
    assert outcome.run.engine_version == '0.9.1'
    assert 'orientation' in outcome.error.message.lower()
    assert calls == [] and cached.model_dump_json() == original
    assert (outcome.run.older_sha256, outcome.run.newer_sha256) == (old_sha, new_sha)


def test_stored_affected_sets_retain_provenance_but_emit_no_endpoint_claims(tmp_path):
    old = rzdiff_set([rz(0x1000, 0x1100)])
    primary = match('primary', 'modified', [func('old', 0x1000)], [func('new', 0x1080)], types=['SymbolsHash'])
    data = inputs([primary], secondary=[loaded(old, 'preserved-original-entry')])
    output = SecondaryAdapter().atoms(data, addr_map(), Budget())
    assert output.atoms == () and output.nodes == ()
    assert output.source_refs[0].file_sha256 == old.file_sha256
    assert 'rz-diff-orientation-unverified' in output.limitations
    assert is_degrading('rz-diff-orientation-unverified')
    destination = tmp_path / 'result'
    destination.mkdir()
    manifest = compute_result(data, addr_map(), result_dir=destination, sources=['ghidriff', 'rz-diff'])
    assert manifest.status == 'partial' and 'rz-diff-orientation-unverified' in manifest.limitations
    rows = list(store.read_rows(destination, manifest))
    assert rows and all(atom.source != 'rz-diff' for row in rows for atom in row.atoms)
    assert any(ref.source == 'rz-diff' and ref.file_sha256 == old.file_sha256 for ref in manifest.sources)


@pytest.mark.parametrize('version', ['0.9.0', '0.9.10'])
def test_synthetic_unaffected_version_preserves_existing_parser_and_probe_policy(version):
    # This is a synthetic schema/version-boundary test, not interoperability evidence for these versions.
    text = json.dumps([{'similarity': 0.5, 'type': 'PARTIAL',
                        'original': {'addr': 0x1000, 'name': 'older', 'size': 8},
                        'modified': {'addr': 0x1100, 'name': 'newer', 'size': 8}}])
    value = rzdiff.parse_output(text, version, 'a' * 64, 'b' * 64)
    assert value.matches[0].older_address == 0x1000 and value.matches[0].newer_address == 0x1100
    capability = rzdiff.probe(Path('/synthetic/rz-diff'), {}, runner=lambda *args, **kwargs:
                              ProcessResult(0, f'rz-diff {version}\n', None, ''))
    assert capability.supported and capability.version == version


def _primary():
    return FunctionMatch(id='primary', run_id='run', category='modified',
                         older=[FunctionRecord(artifact_id='old', run_id='run', name='old', address='180001000')],
                         newer=[FunctionRecord(artifact_id='new', run_id='run', name='new', address='180001080')])


def test_retained_report_cannot_supply_matching_vote_calibration_or_actionable_engine_only_links():
    primary = _primary()
    unknown = rzdiff_set([rz(0x1000, 0x1080), rz(0x1200, 0x1280)])
    original = unknown.model_dump_json()
    report = reconcile([primary], unknown)
    assert report.rows[0].status == 'not-comparable' and report.rows[0].secondary == ()
    assert report.secondary_only == ()
    # An old, already reconciled report must be guarded at the direct evidence/calibration boundaries too.
    old = ReconciliationReport('rz-diff', '0.9.1',
                               (Reconciliation(primary.id, 'agreement', 0x180001000, 0x180001080,
                                               (unknown.matches[0],), 'historical agreement'),),
                               (unknown.matches[1],), ())
    [evidence] = assess_reports((old,)).rows
    assert evidence.verdict == 'insufficient' and evidence.supporting_engines == () and evidence.evidence_index is None
    assert extract(primary, [old]).status == 'not-comparable'
    view = build_view_model(project_id='p', run_id='run', revision=1, older_sha256='a' * 64,
                            newer_sha256='b' * 64, matches=[primary], sets=[unknown])
    assert view.engine('rz-diff').state == 'unsupported'
    assert view.engine('rz-diff').file_sha256 == unknown.file_sha256
    assert 'orientation' in view.engine('rz-diff').detail.lower()
    assert view.engine_only == () and view.rows[0].triage_index is None
    assert all(not cell.raw for cell in view.rows[0].cells if cell.engine == 'rz-diff')
    assert unknown.model_dump_json() == original
