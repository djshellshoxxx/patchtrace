"""SPEC-31 S0b pipeline over a real (synthetic) project: plan, prepare, execute, publish, cache, cancel, failures.
The Ghidriff document, the PEs and every engine set are synthetic: nothing here is live evidence. Child processes are
the real `python -m patchtrace unified _worker` in the end-to-end tests and a stub runner everywhere a failure has
to be produced on purpose."""
from __future__ import annotations

import dataclasses
import json
import os
import socket
import stat
import sys
import tempfile
import threading
from pathlib import Path

import pytest
from unified_s0_fixtures import OLD_SHA, bd, bindiff_set, make_project, rz, rzdiff_set

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.jobs import ProcessResult
from patchtrace.sample import synthetic_pe
from patchtrace.secondary.binexport_run import worker_argv, worker_env
from patchtrace.secondary.store import publish_engine_set
from patchtrace.service import ProjectService
from patchtrace.unified import exchange, pipeline, store, worker
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions

GIB = 1024 ** 3


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    yield service
    service.close()


def inproc(**kw) -> UnifiedOptions:
    return UnifiedOptions(isolate=False, **kw)


def sides(service) -> dict[str, str]:
    return {a.side: a.sha256 for a in service.project.artifacts}


def kinds_exist(service) -> bool:
    row = service.store.connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone()
    return row is not None


def kinds(service) -> dict[str, int]:
    """Rows per enrichment kind; a project that never used enrichment has no table and no rows."""
    if not kinds_exist(service):
        return {}
    rows = service.store.connection.execute('SELECT kind, COUNT(*) FROM enrichment_entries GROUP BY kind')
    return dict(rows.fetchall())


def snapshot_sha(service) -> str:
    return service.store.connection.execute('SELECT sha256 FROM current_snapshot WHERE singleton=1').fetchone()[0]


def all_rows(service):
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    return loaded, list(store.read_rows(loaded.directory, loaded.manifest))


def results_dir(service) -> Path:
    run = service.project.runs[-1]
    return service.root / 'runs' / run.id / 'unified' / 'results'


def leftovers(service) -> list[str]:
    parent = results_dir(service)
    return sorted(p.name for p in parent.iterdir() if p.name.startswith('tmp-')) if parent.is_dir() else []


def publish_set(service, match_set):
    project = service.project
    run = project.runs[-1]
    guard = Guard(project.id, run.id, run.raw_sha256, match_set.file_sha256)
    publish_engine_set(EnrichmentStore(service.store), guard, guard, project.revision, match_set)


class StubRunner:
    """Stands in for `jobs.run_process`: records the call, then answers with `behaviour(self, argv, kwargs)`."""

    def __init__(self, behaviour=None):
        self.calls: list[dict] = []
        self.behaviour = behaviour or run_the_worker_here

    def __call__(self, argv, **kwargs):
        self.calls.append({'argv': list(argv), **kwargs})
        return self.behaviour(self, argv, kwargs)


def run_the_worker_here(runner, argv, kwargs):
    """The child's job, done in this process: exactly what `python -m patchtrace unified _worker ...` would do."""
    start = argv.index('unified')
    assert argv[start + 1] == '_worker'
    return ProcessResult(worker.main(argv[start + 2:]), '', None, '')


def answer(result):
    return lambda runner, argv, kwargs: result


def isolated(runner, **kw) -> UnifiedOptions:
    return UnifiedOptions(isolate=True, runner=runner, total_ram_bytes=8 * GIB, **kw)


# --- the main safety property --------------------------------------------------------------------------------------

def test_unified_run_never_mutates_project_snapshot(project):
    """G-U8: the primary record is untouched by a unified run (database snapshot, raw output, artifacts, model)."""
    run = project.project.runs[-1]
    raw = project.root / run.raw_path
    artifacts = [project.root / a.relative_path for a in project.project.artifacts]
    before = (snapshot_sha(project), project.project.model_dump_json(), raw.read_bytes(),
              [p.read_bytes() for p in artifacts], project.project.revision)
    report = pipeline.run_unified(project, inproc())
    again = pipeline.run_unified(project, inproc(refresh=True))
    after = (snapshot_sha(project), project.project.model_dump_json(), raw.read_bytes(),
             [p.read_bytes() for p in artifacts], project.project.revision)
    assert after == before and report.status == 'ok' and again.result_id == report.result_id
    assert set(kinds(project)) == {'unified-result', 'unified-run'}  # nothing but its own two kinds was written
    reopened_snapshot = project.store.load()
    assert reopened_snapshot.model_dump_json() == before[1]


def test_a_run_publishes_a_verified_result_and_records_the_run(project):
    report = pipeline.run_unified(project, inproc())
    assert (report.status, report.result_status, report.mode) == ('ok', 'complete', 's0')
    assert report.counts.total() == 6 and 'ir-not-extracted' in report.limitations
    assert [s.stage for s in report.stages] == ['prepare', 'compute', 'verify', 'publish'] and not report.warnings
    loaded, rows = all_rows(project)
    assert loaded.state == 'current' and loaded.manifest.result_id == report.result_id and len(rows) == 6
    assert loaded.directory == report.directory
    assert loaded.directory.relative_to(project.root).as_posix() == (
        f'runs/{project.project.runs[-1].id}/unified/results/{report.result_id[:16]}')
    runs = pipeline.recent_runs(project)
    assert [r.status for r in runs] == ['ok'] and runs[0].result_id == report.result_id
    assert runs[0].provenance['worker'] == 'in-process' and runs[0].provenance['mode'] == 's0'
    assert leftovers(project) == []


def test_the_expected_pairs_and_verdicts_of_the_synthetic_patch(project):
    pipeline.run_unified(project, inproc())
    _, rows = all_rows(project)
    by_name = {(r.older[0].name if r.older else None, r.newer[0].name if r.newer else None): r for r in rows}
    changed = by_name[('read_item', 'read_item')]
    assert (changed.decision, changed.materiality, changed.change_classes) == ('matched', 'material', ('call-added',))
    assert by_name[('get_version', 'get_version')].materiality == 'review'  # a constant changed
    assert by_name[('format_name', 'format_name')].materiality == 'cosmetic'
    assert by_name[('debug_dump', None)].decision == 'older-only'
    assert by_name[(None, 'report_invalid_index')].decision == 'newer-only'
    unchanged = by_name[(None, None)]  # the pair known only from the raw address table has no names or code
    assert unchanged.decision == 'matched' and unchanged.materiality == 'unknown'


def test_a_second_run_is_served_from_the_store_and_a_refresh_recomputes(project):
    first = pipeline.run_unified(project, inproc())
    cached = pipeline.run_unified(project, inproc())
    assert cached.status == 'cached' and cached.result_id == first.result_id and cached.directory == first.directory
    assert [s.stage for s in cached.stages] == ['prepare', 'cache']
    refreshed = pipeline.run_unified(project, inproc(refresh=True))
    assert refreshed.status == 'ok' and refreshed.result_id == first.result_id
    assert [r.status for r in pipeline.recent_runs(project)] == ['ok', 'cached', 'ok']
    assert kinds(project)['unified-result'] == 1  # one pointer row per result id, whatever was recomputed
    assert leftovers(project) == []


def test_bad_options_are_input_errors_before_anything_is_written(project):
    for kw, reason in (({'sources': ()}, 'bad-sources'), ({'sources': ('nope',)}, 'bad-sources'),
                       ({'timeout_s': 59}, 'timeout-range'), ({'timeout_s': 86_401}, 'timeout-range')):
        with pytest.raises(UnifiedError) as caught:
            pipeline.prepare(project, inproc(**kw))
        assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', reason)
    assert not kinds_exist(project)


def test_a_project_without_a_completed_run_is_an_input_error(tmp_path):
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    service = ProjectService.create(older, newer, 'no run', tmp_path / 'p')
    try:
        with pytest.raises(UnifiedError) as caught:
            pipeline.run_unified(service, inproc())
        assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'no-completed-run')
        assert caught.value.exit_code == 2
        assert pipeline.load_current(service).state == 'none' and pipeline.recent_runs(service) == []
        assert kinds_exist(service) is False  # reading never creates the enrichment tables
    finally:
        service.close()


def test_an_unreadable_artifact_is_an_input_error(project):
    artifact = project.root / project.project.artifacts[0].relative_path
    os.chmod(artifact, stat.S_IWRITE | stat.S_IREAD)
    artifact.write_bytes(b'not the recorded bytes')
    with pytest.raises(UnifiedError) as caught:
        pipeline.make_plan(project)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'artifact-unreadable')


# --- inputs that change the result --------------------------------------------------------------------------------------

def test_stored_engine_sets_enter_the_result_and_the_selection_leaves_them_out(project):
    base = pipeline.run_unified(project, inproc())
    rows = [bd(0x1000, 0x1080, 'function: hash matching'), bd(0x1900, 0x1980, 'function: name hash matching')]
    publish_set(project, bindiff_set(rows, older=sides(project)['older'], newer=sides(project)['newer']))
    with_bindiff = pipeline.run_unified(project, inproc())
    assert with_bindiff.result_id != base.result_id and with_bindiff.status == 'ok'
    loaded, found = all_rows(project)
    assert {s.source for s in loaded.manifest.sources} == {'ghidriff', 'bindiff'}
    read_item = next(r for r in found if r.older and r.older[0].name == 'read_item')
    assert {a.source for a in read_item.atoms} == {'ghidriff', 'bindiff'}
    assert any(r.older and r.older[0].rva == 0x1900 for r in found)  # a pair only the second engine knows
    only_ghidriff = pipeline.run_unified(project, inproc(sources=('ghidriff',)))
    assert only_ghidriff.result_id == base.result_id and only_ghidriff.status == 'cached'


def test_a_set_for_another_pair_is_refused_but_changes_the_identity(project):
    """It makes the result partial, so it must change the id: the store refuses one id with two contents."""
    base = pipeline.run_unified(project, inproc())
    publish_set(project, rzdiff_set([rz(0x1000, 0x1080)], older=OLD_SHA, newer=sides(project)['newer']))
    assert pipeline.make_plan(project).result_id != base.result_id
    report = pipeline.run_unified(project, inproc())
    assert report.result_status == 'partial' and 'rz-diff-pair-mismatch' in report.limitations
    loaded, rows = all_rows(project)
    assert {s.source for s in loaded.manifest.sources} == {'ghidriff', 'rz-diff'}  # looked at, listed, refused
    assert not any(a.source == 'rz-diff' for row in rows for a in row.atoms)
    assert pipeline.recent_runs(project)[0].status == 'partial'


def test_every_unusable_input_has_its_own_result_id_so_the_store_never_sees_drift(project):
    """The same result id with other content is refused by the store (`result-drift`): every input that changes
    the content must change the id, the refused ones and the three kinds of unusable raw output included."""
    ids = [pipeline.run_unified(project, inproc()).result_id]
    publish_set(project, rzdiff_set([rz(0x1000, 0x1080)], older=OLD_SHA, newer=sides(project)['newer']))
    ids.append(pipeline.run_unified(project, inproc()).result_id)  # a refused set
    raw = project.root / project.project.runs[-1].raw_path
    os.chmod(raw, stat.S_IWRITE | stat.S_IREAD)
    original = raw.read_bytes()
    raw.write_bytes(original + b' ')
    report = pipeline.run_unified(project, inproc())
    ids.append(report.result_id)  # a raw file that changed
    assert 'raw-hash-mismatch' in report.limitations
    raw.unlink()
    report = pipeline.run_unified(project, inproc())
    ids.append(report.result_id)  # a raw file that is gone
    assert 'raw-missing' in report.limitations
    assert len(set(ids)) == 4, ids
    assert pipeline.run_unified(project, inproc()).status == 'cached'  # and each of them is stable
    raw.write_bytes(original)  # the original file back: the original raw state, but the refused set stays
    assert pipeline.run_unified(project, inproc()).result_id == ids[1]


def test_a_manual_correction_changes_the_result_and_decides_its_pair(project):
    base = pipeline.run_unified(project, inproc())
    deleted = next(m for m in project.project.matches if m.category == 'removed')
    added = next(m for m in project.project.matches if m.category == 'added')
    project.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified',
                          'the analyst says the removed function became the added one')
    corrected = pipeline.run_unified(project, inproc())
    assert corrected.result_id != base.result_id
    loaded, rows = all_rows(project)
    manual = next(r for r in rows if r.older and r.older[0].name == 'debug_dump')
    assert manual.decision == 'matched' and manual.newer[0].name == 'report_invalid_index'
    assert [(s.component, s.tier) for s in manual.support] == [('K0', 'M')]
    assert {s.source for s in loaded.manifest.sources} == {'ghidriff', 'manual'}


@pytest.mark.parametrize('damage, status', [('missing', 'raw-missing'), ('changed', 'raw-hash-mismatch')])
def test_unusable_raw_output_gives_a_partial_result_with_another_identity(project, damage, status):
    base = pipeline.make_plan(project)
    raw = project.root / project.project.runs[-1].raw_path
    os.chmod(raw, stat.S_IWRITE | stat.S_IREAD)
    if damage == 'missing':
        raw.unlink()
    else:
        raw.write_bytes(raw.read_bytes() + b' ')
    report = pipeline.run_unified(project, inproc())
    assert report.result_status == 'partial' and status in report.limitations
    assert report.result_id != base.result_id and report.counts.total() > 0
    assert pipeline.recent_runs(project)[0].status == 'partial'


# --- executing: the worker is a child through C3's recipe ---------------------------------------------------------------

def test_worker_spawn_reuses_c3_argv_environment_and_memory_cap(project):
    runner = StubRunner()
    report = pipeline.run_unified(project, isolated(runner))
    assert report.status == 'ok' and len(runner.calls) == 1
    call = runner.calls[0]
    argv = call['argv']
    head = worker_argv()
    assert argv[:len(head)] == head and argv[len(head):len(head) + 2] == ['unified', '_worker']
    assert argv[len(head) + 2] == '--request' and argv[len(head) + 4] == '--result-dir' and len(argv) == len(head) + 6
    assert Path(argv[len(head) + 3]).name == 'request.json' and Path(argv[len(head) + 5]).name.startswith('tmp-')
    expected_env = {k: v for k, v in worker_env().items() if k != 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'}
    assert call['env'] == expected_env and 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION' not in call['env']
    assert call['memory_limit_bytes'] == DEFAULT_LIMITS.worker_memory_cap(8 * GIB) == 4 * GIB
    assert call['separate_streams'] is True and call['timeout_seconds'] == DEFAULT_LIMITS.l34_worker_timeout_s
    assert call['stderr_limit'] == DEFAULT_LIMITS.l31_stderr_tail_bytes and callable(call['check_output'])


@pytest.mark.parametrize('ram, cap', [(None, 4 * GIB), (2 * GIB, GIB), (6 * GIB, 3 * GIB), (64 * GIB, 4 * GIB)],
                         ids=['unknown', '2g', '6g', '64g'])
def test_the_worker_memory_cap_is_half_the_ram_up_to_four_gib(project, ram, cap):
    runner = StubRunner()
    request = dataclasses.replace(pipeline.prepare(project, UnifiedOptions(isolate=True, timeout_s=120)),
                                  total_ram_bytes=ram)
    pipeline.publish(project, request, pipeline.execute(request, runner=runner))
    assert runner.calls[0]['memory_limit_bytes'] == cap and runner.calls[0]['timeout_seconds'] == 120


def test_children_get_absolute_argv_and_a_private_cwd(project):
    runner = StubRunner()
    before = {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')}
    pipeline.run_unified(project, isolated(runner))
    call = runner.calls[0]
    argv = call['argv']
    request_path, staged = Path(argv[argv.index('--request') + 1]), Path(argv[argv.index('--result-dir') + 1])
    assert Path(argv[0]).is_absolute() and request_path.is_absolute() and staged.is_absolute()
    assert staged.parent.is_relative_to(project.root)  # staged beside the final directory: the rename is atomic
    cwd = Path(call['cwd'])
    assert cwd.is_absolute() and cwd.name.startswith('pt-unified-') and request_path.parent == cwd
    assert not cwd.is_relative_to(project.root) and cwd != Path.cwd()
    assert {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')} == before  # removed after the run
    assert not cwd.exists()


def test_the_child_inputs_are_private_files_listed_with_their_hashes(project):
    seen = {}

    def inspect(runner, argv, kwargs):
        private = Path(kwargs['cwd'])
        seen['names'] = sorted(p.name for p in private.iterdir())
        seen['request'] = json.loads((private / 'request.json').read_text(encoding='utf-8'))
        return run_the_worker_here(runner, argv, kwargs)
    pipeline.run_unified(project, isolated(StubRunner(inspect)))
    assert seen['names'] == ['matches.jsonl', 'request.json']
    request = seen['request']
    assert request['contract'] == 'unified-worker-request/1' and request['raw_status'] == 'ok'
    assert Path(request['raw_path']).is_relative_to(project.root)  # the one input read in place, re-hashed by the worker
    assert len(request['snapshot']['sha256']) == 64 and request['snapshot_lines'] == len(project.project.matches) == 5
    assert request['sources'] == ['bindiff', 'ghidriff', 'manual', 'rz-diff']


def test_progress_comes_from_the_childs_progress_file(project):
    events = []

    def write_progress(runner, argv, kwargs):
        private = Path(kwargs['cwd'])
        check = kwargs['check_output']
        assert check() is None  # nothing yet: indeterminate, never an error
        progress = private / 'progress.json'
        progress.write_text('{"stage": "facts", "done": 2, "total": 3}', encoding='utf-8')
        assert check() is None and check() is None  # the same state twice is reported once
        progress.write_text('not json', encoding='utf-8')
        assert check() is None
        progress.write_text(' ' * (DEFAULT_LIMITS.l37_progress_bytes + 1), encoding='utf-8')
        assert check() is None
        progress.unlink()
        return run_the_worker_here(runner, argv, kwargs)
    pipeline.run_unified(project, isolated(StubRunner(write_progress)), emit=events.append)
    assert [(e.stage, e.done, e.total) for e in events] == [('facts', 2, 3)]


def test_a_real_child_process_produces_the_same_result_as_the_same_code_in_process(project):
    request = pipeline.prepare(project, UnifiedOptions(isolate=True))
    child = pipeline.execute(request)
    here = pipeline.execute(dataclasses.replace(request, isolate=False))
    try:
        assert child.error is None and here.error is None and child.report.result_id == here.report.result_id
        for name in ('rows.jsonl.gz', 'facts.jsonl.gz'):
            assert (child.staged / name).read_bytes() == (here.staged / name).read_bytes()
        assert child.report.raw_status == 'ok' and child.stderr_tail == ''
    finally:
        pipeline._discard(child.staged)
        pipeline._discard(here.staged)
    report = pipeline.run_unified(project, UnifiedOptions(isolate=True, refresh=True))
    assert report.status == 'ok' and report.result_id == child.report.result_id
    assert pipeline.recent_runs(project)[0].provenance['worker'] == 'child'


def test_execute_needs_no_database_and_runs_on_any_thread(project):
    request = pipeline.prepare(project, inproc())
    box = {}
    thread = threading.Thread(target=lambda: box.setdefault('output', pipeline.execute(request)))
    thread.start()
    thread.join()
    output = box['output']
    assert output.error is None and output.staged.is_dir()
    assert pipeline.publish(project, request, output).status == 'ok'


def test_publishing_off_the_owner_thread_is_refused_and_cleans_up(project):
    request = pipeline.prepare(project, inproc())
    output = pipeline.execute(request)
    box = {}

    def attempt():
        try:
            pipeline.publish(project, request, output)
        except Exception as error:  # noqa: BLE001 - the test inspects whatever came out
            box['error'] = error
    thread = threading.Thread(target=attempt)
    thread.start()
    thread.join()
    assert isinstance(box['error'], UnifiedError) and box['error'].reason == 'wrong-thread'
    assert not output.staged.exists() and kinds(project) == {}


def test_the_request_is_immutable(project):
    request = pipeline.prepare(project, inproc())
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.timeout_s = 1  # type: ignore[misc]
    assert isinstance(request.snapshot, tuple) and isinstance(request.plan.secondary, tuple)
    assert isinstance(request.plan.manual, tuple) and request.plan.result_id == pipeline.make_plan(project).result_id


# --- failures never replace the current result ------------------------------------------------------------------------

def report_document(**kw) -> bytes:
    return exchange.WorkerReport(**kw).model_dump_json().encode()


def error_document(runner, argv, kwargs):
    (Path(kwargs['cwd']) / 'report.json').write_bytes(report_document(ok=False, error_code='PT-UNIFIED-INPUT',
                                                                      reason='snapshot-hash-mismatch'))
    return ProcessResult(3, '', None, '')


FAILURES = {
    'cancelled': (answer(ProcessResult(-1, '', 'cancelled')), 'cancelled', 'PT-UNIFIED-CANCEL', 'cancelled'),
    'timeout': (answer(ProcessResult(-1, '', 'timeout')), 'timeout', 'PT-UNIFIED-TIMEOUT', 'worker-deadline'),
    'exit-22': (answer(ProcessResult(22, '', None, '')), 'failed', 'PT-UNIFIED-LIMIT', 'worker-oom'),
    'oom-text': (answer(ProcessResult(1, '', None, 'MemoryError')), 'failed', 'PT-UNIFIED-LIMIT', 'worker-oom'),
    'job-limit': (answer(ProcessResult(1, '', None, '', 4 * GIB)), 'failed', 'PT-UNIFIED-LIMIT', 'worker-oom'),
    'crash': (answer(ProcessResult(1, '', None, 'Traceback (most recent call last)')), 'failed',
              'PT-UNIFIED-INTERNAL', 'worker-exit-1'),
    'signal': (answer(ProcessResult(-9, '', None, '')), 'failed', 'PT-UNIFIED-INTERNAL', 'worker-signal-9'),
    'silent': (answer(ProcessResult(0, '', None, '')), 'failed', 'PT-UNIFIED-INTERNAL', 'worker-no-report'),
    'error-document': (error_document, 'failed', 'PT-UNIFIED-INPUT', 'snapshot-hash-mismatch'),
}


@pytest.mark.parametrize('name', sorted(FAILURES))
def test_worker_failures_are_classified_recorded_and_publish_nothing(project, name):
    behaviour, status, code, reason = FAILURES[name]
    previous = pipeline.run_unified(project, inproc())
    kept = {p.name: p.read_bytes() for p in previous.directory.iterdir()}
    with pytest.raises(UnifiedError) as caught:
        pipeline.run_unified(project, isolated(StubRunner(behaviour), refresh=True))
    assert (caught.value.code, caught.value.reason) == (code, reason)
    newest = pipeline.recent_runs(project)[0]
    assert (newest.status, newest.error_code, newest.result_id) == (status, code, None)
    assert newest.stages and newest.stages[0].stage == 'prepare'
    loaded = pipeline.load_current(project, pipeline.make_plan(project))
    assert loaded.state == 'current' and loaded.manifest.result_id == previous.result_id
    assert {p.name: p.read_bytes() for p in previous.directory.iterdir()} == kept
    assert leftovers(project) == [] and kinds(project)['unified-result'] == 1


def test_a_failed_attempt_keeps_a_sanitised_stderr_tail(project):
    hostile = 'x' * 70_000 + ' boom \x1b[31mred\x1b[0m \u202e\r\nsecond line\x00 '  # the TAIL is what is kept
    with pytest.raises(UnifiedError):
        pipeline.run_unified(project, isolated(StubRunner(answer(ProcessResult(1, '', None, hostile)))))
    tail = pipeline.recent_runs(project)[0].stderr_tail
    assert 'boom' in tail and 'second line' in tail and len(tail.encode()) <= DEFAULT_LIMITS.l31_stderr_tail_bytes
    assert not set(tail) & set('\x1b\u202e\r\x00')


def test_a_runner_that_cannot_start_the_child_is_an_internal_error(project):
    def refuse(runner, argv, kwargs):
        raise OSError('no such file: C:\\secret')
    with pytest.raises(UnifiedError) as caught:
        pipeline.run_unified(project, isolated(StubRunner(refuse)))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INTERNAL', 'worker-spawn-failed')
    assert 'secret' not in str(caught.value) and pipeline.recent_runs(project)[0].status == 'failed'


def test_cancel_keeps_previous_result(project):
    """A cancelled run (the user, or the deadline) never replaces what is current, even when the inputs moved on."""
    first = pipeline.run_unified(project, inproc())
    cancel = threading.Event()

    def cancelling(runner, argv, kwargs):
        cancel.set()
        return ProcessResult(-1, '', 'cancelled')
    deleted = next(m for m in project.project.matches if m.category == 'removed')
    added = next(m for m in project.project.matches if m.category == 'added')
    project.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified', 'inputs moved on')
    with pytest.raises(UnifiedError) as caught:
        pipeline.run_unified(project, isolated(StubRunner(cancelling)), cancel=cancel)
    assert caught.value.code == 'PT-UNIFIED-CANCEL' and caught.value.exit_code == 5
    loaded = pipeline.load_current(project, pipeline.make_plan(project))
    assert loaded.state == 'stale' and loaded.manifest.result_id == first.result_id  # old result: shown, flagged
    assert loaded.directory == first.directory and pipeline.recent_runs(project)[0].status == 'cancelled'
    assert leftovers(project) == []


def test_a_cancel_that_is_already_set_does_nothing_at_all(project):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(UnifiedError) as caught:
        pipeline.run_unified(project, inproc(), cancel=cancel)
    assert caught.value.code == 'PT-UNIFIED-CANCEL'
    output = pipeline.execute(pipeline.prepare(project, inproc()), cancel)
    assert output.error is not None and output.staged is None
    assert kinds(project) == {} and leftovers(project) == []


def tamper_rows(staged: Path) -> None:
    path = staged / 'rows.jsonl.gz'
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))


GARBAGE_GZIP = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff' + b'\xff' * 64  # a gzip header, then an invalid deflate block


def garbage_rows(staged: Path) -> None:
    (staged / 'rows.jsonl.gz').write_bytes(GARBAGE_GZIP)


def add_file(staged: Path) -> None:
    (staged / 'extra.txt').write_text('x', encoding='utf-8')


def drop_manifest(staged: Path) -> None:
    (staged / store.MANIFEST).unlink()


def other_id(staged: Path) -> None:
    manifest = json.loads((staged / store.MANIFEST).read_text(encoding='utf-8'))
    manifest['result_id'] = '0' * 64
    (staged / store.MANIFEST).write_text(json.dumps(manifest), encoding='utf-8')


@pytest.mark.parametrize('damage, reasons', [
    (tamper_rows, {'part-hash-mismatch', 'part-unreadable'}), (garbage_rows, {'part-unreadable'}),
    (add_file, {'unexpected-files'}), (drop_manifest, {'manifest-missing'}), (other_id, {'result-id-mismatch'})],
    ids=['rows', 'garbage', 'extra', 'manifest', 'id'])
def test_worker_output_is_validated_before_publish(project, damage, reasons):
    request = pipeline.prepare(project, inproc())
    output = pipeline.execute(request)
    damage(output.staged)
    with pytest.raises(UnifiedError) as caught:
        pipeline.publish(project, request, output)
    assert caught.value.code == 'PT-UNIFIED-STORE' and caught.value.reason in reasons
    assert not output.staged.exists() and kinds(project) == {'unified-run': 1}
    assert pipeline.recent_runs(project)[0].status == 'failed'
    assert not results_dir(project).exists() or list(results_dir(project).iterdir()) == []


def test_a_damaged_deflate_stream_is_a_typed_error_everywhere_and_a_rerun_repairs_it(project):
    """`zlib.error` is not an OSError: S0a's reader lets it through, so the owner side maps it (and says so)."""
    first = pipeline.run_unified(project, inproc())
    rows = first.directory / 'rows.jsonl.gz'
    os.chmod(rows, stat.S_IWRITE | stat.S_IREAD)
    rows.write_bytes(GARBAGE_GZIP)
    plan = pipeline.make_plan(project)
    loaded = pipeline.load_current(project, plan)
    assert loaded.state == 'invalid' and loaded.reason == 'part-unreadable'
    readable = store.LoadedResult('current', None, directory=first.directory,
                                  manifest=store.read_manifest(first.directory)[0])
    with pytest.raises(UnifiedError) as caught:
        list(pipeline.read_rows(readable))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-STORE', 'part-unreadable')
    assert len(list(pipeline.read_facts(readable))) == 4  # the other part is intact and still readable
    again = pipeline.run_unified(project, inproc())  # a damaged stored result is a cache miss, not a crash
    assert again.status == 'ok' and again.result_id == first.result_id
    repaired = pipeline.load_current(project, pipeline.make_plan(project))
    assert repaired.state == 'current' and len(list(pipeline.read_rows(repaired))) == 6
    assert leftovers(project) == []


def test_a_report_for_other_inputs_is_refused(project):
    request = pipeline.prepare(project, inproc())
    output = pipeline.execute(request)
    wrong = dataclasses.replace(output, report=output.report.model_copy(update={'result_id': '1' * 64}))
    with pytest.raises(UnifiedError) as caught:
        pipeline.publish(project, request, wrong)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-STORE', 'result-id-mismatch')
    assert not output.staged.exists()


def test_the_identity_is_rechecked_against_what_the_worker_saw(project):
    """The owner hashed the raw file before the run; the worker saw something else (changed in between)."""
    request = pipeline.prepare(project, inproc())
    raw = project.root / project.project.runs[-1].raw_path
    os.chmod(raw, stat.S_IWRITE | stat.S_IREAD)
    raw.write_bytes(raw.read_bytes() + b' ')  # after the owner's check, before the worker's
    output = pipeline.execute(request)
    assert output.report.raw_status == 'hash-mismatch'
    report = pipeline.publish(project, request, output)
    assert report.result_status == 'partial' and report.result_id != request.plan.result_id  # the id that was seen
    assert pipeline.recent_runs(project)[0].result_id == report.result_id


def test_a_project_that_moved_on_during_the_run_stores_the_result_as_stale(project):
    request = pipeline.prepare(project, inproc())
    output = pipeline.execute(request)
    deleted = next(m for m in project.project.matches if m.category == 'removed')
    added = next(m for m in project.project.matches if m.category == 'added')
    project.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified', 'moved during the run')
    report = pipeline.publish(project, request, output)  # same run, same raw output: the guard still holds
    assert report.status == 'ok'
    loaded = pipeline.load_current(project, pipeline.make_plan(project))
    assert loaded.state == 'stale' and loaded.manifest.result_id == report.result_id  # but no longer this project's


# --- hygiene --------------------------------------------------------------------------------------------------------

_WATCH = {'on': False, 'events': []}


def _audit(event, args):
    if _WATCH['on'] and event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind', 'socket.gethostbyname'):
        _WATCH['events'].append(event)


sys.addaudithook(_audit)


def test_no_network_during_unified_run(project):
    """G-U8: no socket is opened by a full run (the audit hook is armed only for the duration of this test)."""
    _WATCH['events'].clear()
    _WATCH['on'] = True
    try:
        pipeline.run_unified(project, inproc())
        pipeline.run_unified(project, isolated(StubRunner(), refresh=True))
    finally:
        _WATCH['on'] = False
    assert _WATCH['events'] == []
    assert hasattr(socket, 'socket')  # the guard above really watched the module the code could have used


def test_runs_leave_no_stray_files_behind(project):
    before = {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')}
    pipeline.run_unified(project, inproc())
    for behaviour in (answer(ProcessResult(22, '', None, '')), error_document):
        with pytest.raises(UnifiedError):
            pipeline.run_unified(project, isolated(StubRunner(behaviour), refresh=True))
    assert {p.name for p in Path(tempfile.gettempdir()).glob('pt-unified-*')} == before
    root = results_dir(project)
    assert [p.name for p in root.iterdir()] == [pipeline.make_plan(project).result_id[:16]]
    assert sorted(p.name for p in root.iterdir().__next__().iterdir()) == [
        'facts.jsonl.gz', 'manifest.json', 'rows.jsonl.gz']
    assert not list(project.root.rglob('*.part'))
