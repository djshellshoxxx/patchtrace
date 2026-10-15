"""SPEC-31 wiring, owner side: `make_plan`/`prepare`/`execute`/`publish` find the ProgramIR sidecars placed below the run,
plan the result id from their digests, hand them to the worker and publish an IR-mode result. The project, its two PEs
and the Ghidriff document are the synthetic ones of the S0 tests; the sidecars are hand-assembled x86-64 through the
real ingest and the real placement (tests/unified_wire_support.py). Synthetic: nothing here is live evidence."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from unified_s0_fixtures import make_project
from unified_wire_support import new_functions, old_functions, place, place_pair

from patchtrace.unified import compute, exchange, pipeline, store
from patchtrace.unified.contracts import ProgramIrManifest
from patchtrace.unified.ir.place import list_ir
from patchtrace.unified.ir.reader import IrReader
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def inproc(**kw) -> UnifiedOptions:
    return UnifiedOptions(isolate=False, **kw)


def manifest_of(directory: Path) -> ProgramIrManifest:
    return IrReader.open(directory).manifest


def rows_and_facts(service):
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    facts = {f.row_id: f for f in store.read_facts(loaded.directory, loaded.manifest)}
    rows = {(r.older[0].name if r.older else None, r.newer[0].name if r.newer else None): (r, facts.get(r.row_id))
            for r in store.read_rows(loaded.directory, loaded.manifest)}
    return loaded, rows


# --- finding the sidecars ---------------------------------------------------------------------------------------------------------

def test_without_placed_sidecars_the_plan_is_s0(project):
    plan = pipeline.make_plan(project)
    assert plan.ir is None and plan.mode == 's0' and plan.ir_note is None and plan.ir_digests() is None


def test_sidecars_of_both_sides_make_an_ir_plan_whose_id_covers_their_digests(project, tmp_path):
    s0 = pipeline.make_plan(project)
    older, newer = place_pair(project, scratch=tmp_path)
    plan = pipeline.make_plan(project)
    assert plan.mode == 'ir' and plan.ir_note is None and plan.result_id != s0.result_id
    assert [p.directory for p in plan.ir] == [older, newer]
    assert plan.ir_digests() == (manifest_of(older).content_digest, manifest_of(newer).content_digest)
    assert plan.ir[0].ir_key == manifest_of(older).ir_key and plan.ir[0].functions == 5
    assert (plan.identity.key_inputs.ir_older_digest, plan.identity.key_inputs.ir_newer_digest) == plan.ir_digests()
    assert pipeline.make_plan(project, use_ir=False).result_id == s0.result_id        # `--no-extract` is B-00 exactly
    assert pipeline.make_plan(project, residual=False).result_id != plan.result_id    # backup B-07 is another config


@pytest.mark.parametrize('case', ['one-side', 'foreign-sha', 'other-layout'], ids=['one-side', 'foreign', 'layout'])
def test_sidecars_that_do_not_fit_the_pair_are_not_used(project, tmp_path, case):
    if case == 'one-side':
        place(project, 'older', old_functions(), scratch=tmp_path)
    else:
        place(project, 'older', old_functions(), scratch=tmp_path)
        kw = {'sha': 'a1' * 32} if case == 'foreign-sha' else {'size': 0x3000}
        place(project, 'newer', new_functions(), scratch=tmp_path, **kw)
    plan = pipeline.make_plan(project)
    assert plan.ir is None and plan.mode == 's0' and plan.ir_note is None


def test_sidecars_produced_differently_stay_s0_and_the_report_says_why(project, tmp_path):
    place(project, 'older', old_functions(), scratch=tmp_path, mode='analyze')
    place(project, 'newer', new_functions(), scratch=tmp_path, mode='gzf', options='00' * 32)
    plan = pipeline.make_plan(project)
    assert plan.ir is None and plan.ir_note == pipeline.IR_ASYMMETRIC
    report = pipeline.run_unified(project, inproc())
    assert report.mode == 's0' and pipeline.IR_ASYMMETRIC in report.warnings and 'ir-not-extracted' in report.limitations


def test_the_newest_symmetric_pair_wins_and_a_producer_mismatch_never_pairs(project, tmp_path):
    place_pair(project, scratch=tmp_path, script='11' * 32, created='2026-10-14T10:00:00+00:00')
    newest = place_pair(project, scratch=tmp_path, script='22' * 32, created='2026-10-14T12:00:00+00:00')
    odd_one = place(project, 'newer', new_functions(), scratch=tmp_path, script='33' * 32, mode='gzf',
                    options='aa' * 32, created='2026-10-14T13:00:00+00:00')
    plan = pipeline.make_plan(project)
    assert [p.directory for p in plan.ir] == list(newest) and odd_one not in [p.directory for p in plan.ir]
    assert len(list_ir(project.root, project.project.runs[-1].id)) == 5


def test_a_damaged_directory_is_not_listed_and_never_crashes_a_plan(project, tmp_path):
    older, newer = place_pair(project, scratch=tmp_path)
    (older / 'extra.txt').write_text('x', encoding='utf-8')
    assert [d for d, _m in list_ir(project.root, project.project.runs[-1].id)] == [newer]
    assert pipeline.make_plan(project).ir is None                                # one side left: S0
    (older / 'extra.txt').unlink()
    (newer / 'manifest.json').write_text('{"contract": "program-ir/1"}', encoding='utf-8')
    assert [d for d, _m in list_ir(project.root, project.project.runs[-1].id)] == [older]


# --- running ------------------------------------------------------------------------------------------------------------------------

def test_a_run_with_sidecars_publishes_an_ir_mode_result(project, tmp_path):
    older, newer = place_pair(project, scratch=tmp_path)
    report = pipeline.run_unified(project, inproc())
    assert (report.status, report.result_status, report.mode) == ('ok', 'complete', 'ir')
    assert 'ir-not-extracted' not in report.limitations and not report.warnings
    assert [s.stage for s in report.stages] == ['prepare', 'compute', 'verify', 'publish']
    loaded, rows = rows_and_facts(project)
    assert loaded.state == 'current' and loaded.manifest.result_id == report.result_id
    assert loaded.manifest.ir_older.ir_key == manifest_of(older).ir_key
    assert loaded.manifest.ir_newer.content_digest == manifest_of(newer).content_digest
    assert len(rows) == 6 and report.counts.decisions.matched == 4
    read_item = rows[('read_item', 'read_item')]
    assert {a.source for a in read_item[0].atoms} == {'ghidriff', 'pt-ladder'}                 # both engines, one row
    assert (read_item[1].verdict, read_item[1].second_channel) == ('material', 'C4')           # the IR sees the new call
    assert {rows[(n, n)][1].proof for n in ('format_name', 'keep_same')} == {'UNCH/1'}         # moved, proven equal
    assert rows[('get_version', 'get_version')][1].verdict == 'material'                       # constant + decompiler text
    assert rows[('debug_dump', None)][0].decision == 'older-only'
    assert rows[(None, 'report_invalid_index')][0].decision == 'newer-only'
    runs = pipeline.recent_runs(project, 1)
    assert runs[0].provenance['mode'] == 'ir' and runs[0].result_id == report.result_id


def test_the_real_worker_child_gives_the_same_ir_result_as_the_in_process_run(project, tmp_path):
    place_pair(project, scratch=tmp_path)
    in_process = pipeline.run_unified(project, inproc())
    child = pipeline.run_unified(project, UnifiedOptions(isolate=True, refresh=True, timeout_s=300))
    assert child.mode == 'ir' and child.result_id == in_process.result_id and child.counts == in_process.counts
    assert child.status == 'ok' and 'ir-not-extracted' not in child.limitations


def test_the_second_run_is_cached_and_residual_off_is_a_different_result(project, tmp_path):
    place_pair(project, scratch=tmp_path)
    first = pipeline.run_unified(project, inproc())
    assert pipeline.run_unified(project, inproc()).status == 'cached'
    skipped = pipeline.run_unified(project, inproc(residual=False))
    assert skipped.status == 'ok' and skipped.result_id != first.result_id and skipped.mode == 'ir'
    s0 = pipeline.run_unified(project, inproc(use_ir=False))
    assert s0.mode == 's0' and 'ir-not-extracted' in s0.limitations and s0.result_id not in (first.result_id,
                                                                                         skipped.result_id)


def test_an_s0_result_is_stale_once_sidecars_are_placed(project, tmp_path):
    pipeline.run_unified(project, inproc())
    place_pair(project, scratch=tmp_path)
    loaded = pipeline.load_current(project, pipeline.make_plan(project))
    assert loaded.state == 'stale'


def test_a_tampered_sidecar_fails_the_run_with_a_store_error_and_keeps_the_old_result(project, tmp_path):
    before = pipeline.run_unified(project, inproc(use_ir=False))
    older, _newer = place_pair(project, scratch=tmp_path)
    data = (older / 'ir.sqlite3').read_bytes()
    (older / 'ir.sqlite3').write_bytes(data[:-8] + bytes(8))
    with pytest.raises(UnifiedError) as bad:
        pipeline.run_unified(project, inproc())
    assert bad.value.code == 'PT-UNIFIED-STORE' and bad.value.reason == 'ir-file-hash'
    loaded = pipeline.load_current(project, pipeline.make_plan(project, use_ir=False))
    assert loaded.state == 'current' and loaded.manifest.result_id == before.result_id


# --- the worker request ---------------------------------------------------------------------------------------------------------------

def request_for(project, tmp_path, mutate=None):
    """The request `pipeline.execute` would write for the planned IR run, as a document the test may edit."""
    place_pair(project, scratch=tmp_path)
    request = pipeline.prepare(project, inproc())
    private = tmp_path / 'private'
    private.mkdir()
    path = pipeline._write_request(request, private)
    document = json.loads(path.read_text(encoding='utf-8'))
    if mutate:
        mutate(document)
        path.write_text(json.dumps(document), encoding='utf-8')
    return path, document


def test_the_request_names_both_sidecars_with_their_sections_and_the_residual_switch(project, tmp_path):
    _path, document = request_for(project, tmp_path)
    assert set(document['ir_older']) == {'directory', 'ir_key', 'content_digest', 'sections'}
    assert document['ir_older']['sections'] and document['residual'] is True
    assert Path(document['ir_older']['directory']).parent.name == 'ir'


def test_a_request_with_one_sidecar_only_is_refused(project, tmp_path):
    path, _document = request_for(project, tmp_path, lambda d: d.pop('ir_newer'))
    with pytest.raises(UnifiedError) as bad:
        exchange.read_request(path)
    assert bad.value.reason == 'request-invalid'


@pytest.mark.parametrize('change, code, reason', [
    (lambda d: d['ir_older'].update(ir_key='0' * 64), 'PT-UNIFIED-STALE', 'ir-changed'),
    (lambda d: d['ir_newer'].update(content_digest='0' * 64), 'PT-UNIFIED-STALE', 'ir-changed'),
    (lambda d: d.update(older_sha256='1' * 64), 'PT-UNIFIED-PAIR', 'ir-older-artifact'),
    (lambda d: d['older_layout'].update(size_of_image=0x3000), 'PT-UNIFIED-PAIR', 'ir-older-layout'),
    (lambda d: d['ir_older'].update(directory='relative/path'), 'PT-UNIFIED-INPUT', 'ir-path'),
], ids=['older-key', 'newer-digest', 'wrong-artifact', 'layout', 'relative-path'])
def test_the_worker_refuses_a_sidecar_that_does_not_fit_its_request(project, tmp_path, change, code, reason):
    path, _document = request_for(project, tmp_path, change)
    staged = tmp_path / 'staged'
    staged.mkdir()
    with pytest.raises(UnifiedError) as bad:
        compute.run_request(path, staged)
    assert (bad.value.code, bad.value.reason) == (code, reason)


def test_sidecars_given_in_the_wrong_order_are_an_orientation_error(project, tmp_path):
    def swap(document):
        document['ir_older'], document['ir_newer'] = document['ir_newer'], document['ir_older']
    path, _document = request_for(project, tmp_path, swap)
    staged = tmp_path / 'staged'
    staged.mkdir()
    with pytest.raises(UnifiedError) as bad:
        compute.run_request(path, staged)
    assert (bad.value.code, bad.value.reason) == ('PT-UNIFIED-ORIENTATION', 'ir-reversed')
