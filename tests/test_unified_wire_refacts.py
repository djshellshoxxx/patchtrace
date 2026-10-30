"""SPEC-31 S3b wiring (05 s2.8, 01 s5): after the facts, the pairs worth a decompile are decompiled on both sides over the
retained programs (the owner spawns the extractor, never the capped worker), the worker judges those rows again with
the C text as the second channel, and the owner publishes the result. The extractor is a fake interpreter that answers
the real `decompile` request of the real runner; the project, the sidecars and the C text are synthetic. Nothing here
is live Ghidra evidence (the live end-to-end run of the extractor is docs/qa.md [S3b:decompile])."""
from __future__ import annotations

import dataclasses
import json
import threading

import pytest
from unified_s0_fixtures import addr_map, make_project, rich_inputs
from unified_wire_support import fake_backend, keep_same_text, place_gzfs, place_pair

from patchtrace.unified import exchange, pipeline, store
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.limits import Budget, UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.sources.ghidriff import GhidriffAdapter
from patchtrace.unified.sources.manual import ManualAdapter
from patchtrace.unified.sources.secondary import SecondaryAdapter

KEEP_SAME = {'older': 0x1300, 'newer': 0x1380}
SHOWN = {'older': keep_same_text('0x77'), 'newer': keep_same_text('0x78')}


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    place_pair(service, scratch=tmp_path, keep_same=0x78)          # a constant-only edit in a pair Ghidriff never read
    yield service
    service.close()


def options(tmp_path, *, texts=None, isolate=False, **kw) -> UnifiedOptions:
    backend = None if texts is None else fake_backend(tmp_path, {s: {KEEP_SAME[s]: t} for s, t in texts.items()})
    return UnifiedOptions(isolate=isolate, backend=backend, **kw)


def keep_same(service):
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    facts = {f.row_id: f for f in store.read_facts(loaded.directory, loaded.manifest)}
    row = next(r for r in store.read_rows(loaded.directory, loaded.manifest)
               if r.older and r.older[0].name == 'keep_same')
    return loaded.manifest, row, facts[row.row_id]


def stage(report, name):
    return next((s for s in report.stages if s.stage == name), None)


# --- the inverse of `to_match` --------------------------------------------------------------------------------------------

def test_a_stored_row_is_the_decided_row_it_came_from_for_every_kind_of_row():
    """Contested, one-sided, candidate, manual and plain rows: `decided_from_match(to_match(d)) == d`."""
    data = rich_inputs()
    addr = addr_map()
    outputs = [GhidriffAdapter().atoms(data, addr, Budget()), SecondaryAdapter().atoms(data, addr, Budget()),
               ManualAdapter().atoms(data, addr, Budget())]
    nodes = arbiter.merge_nodes(o.nodes for o in outputs)
    decided = arbiter.decide([a for o in outputs for a in o.atoms], [g for o in outputs for g in o.groups], nodes)
    assert {d.decision for d in decided} >= {'matched', 'contested', 'candidate', 'older-only', 'newer-only'}
    assert any(d.mapped for d in decided) and any(d.pair is None for d in decided)
    for d in decided:
        row = arbiter.to_match(d, nodes, data.older_sha256, data.newer_sha256)
        assert arbiter.decided_from_match(row) == d, d.decision
        assert arbiter.node_info(row) == {key: nodes[key] for key in arbiter.node_info(row)}


# --- the file that carries the C text to the worker -----------------------------------------------------------------------

def test_the_refacts_file_round_trips_and_refuses_what_it_should(tmp_path):
    path = tmp_path / 'refacts.json'
    described = exchange.write_refacts(path, pairs=[(0x1300, 0x1380), (0x1300, 0x1380)],
                                       texts={'older': {0x1300: 'a'}, 'newer': {0x1380: 'b'}})
    loaded = exchange.read_refacts(path, expected_sha256=described.sha256)
    assert loaded.pairs == ((0x1300, 0x1380),) and loaded.texts('older') == {0x1300: 'a'}
    assert loaded.texts('newer') == {0x1380: 'b'} and described.size == path.stat().st_size
    bad = {'wrong contract': {'contract': 'x/1'}, 'unknown key': {'extra': 1}, 'float': {'pairs': [[1.5, 2]]},
           'too many pairs': {'pairs': [[i, i] for i in range(65)]}, 'negative rva': {'older': [[-1, 'a']]}}
    for name, patch in bad.items():
        path.write_text(json.dumps(json.loads(described and path.read_text(encoding='utf-8') or '{}') | patch),
                        encoding='utf-8')
        with pytest.raises(UnifiedError) as error:
            exchange.read_refacts(path)
        assert error.value.reason == 'refacts-invalid', name
        exchange.write_refacts(path, pairs=[], texts={})
    with pytest.raises(UnifiedError) as changed:
        exchange.read_refacts(path, expected_sha256='0' * 64)
    assert changed.value.reason == 'refacts-invalid'


# --- the stage through the pipeline ---------------------------------------------------------------------------------------

def test_without_a_backend_the_pair_stays_in_review_and_the_report_says_why(project, tmp_path):
    report = pipeline.run_unified(project, options(tmp_path))
    manifest, _row, facts = keep_same(project)
    assert facts.verdict == 'review' and {d.cls for d in facts.deltas} == {'constant'}
    assert (stage(report, 'decompile').status, stage(report, 'decompile').reason) == ('skipped', 'no-backend')
    assert 'decompile-skipped:no-backend' in report.limitations and report.status == 'ok'
    assert 'decompile-skipped:no-backend' in manifest.limitations


def test_no_gzf_means_skipped_with_that_reason(project, tmp_path):
    report = pipeline.run_unified(project, options(tmp_path, texts=SHOWN))
    assert stage(report, 'decompile').reason == 'no-gzf' and 'decompile-skipped:no-gzf' in report.limitations


def test_the_decompiled_text_makes_the_constant_only_edit_material_through_the_second_channel(project, tmp_path):
    place_gzfs(project)
    report = pipeline.run_unified(project, options(tmp_path, texts=SHOWN))
    manifest, _row, facts = keep_same(project)
    assert (facts.verdict, facts.second_channel) == ('material', 'C6') and dict(facts.channels)['C6'] == 'differs'
    assert stage(report, 'decompile').status == 'ok' and not [x for x in report.limitations if 'decompile' in x]
    assert [s.stage for s in report.stages] == ['prepare', 'compute', 'decompile', 'verify', 'publish']
    assert report.counts.materiality.material == manifest.counts.materiality.material == 3      # + read_item, get_version
    assert report.counts.materiality.review == 0
    loaded = pipeline.load_current(project, pipeline.make_plan(project))
    assert store.verify_result_dir(loaded.directory).result_id == report.result_id


def test_the_result_id_does_not_depend_on_the_decompile_and_a_refresh_upgrades_the_rows(project, tmp_path):
    """The text is a second channel computed from the retained programs: the same inputs, the same id; the refresh
    that decompiled replaces the directory of that id (`upgrade`), a plain publish of other content is still refused."""
    place_gzfs(project)
    without = pipeline.run_unified(project, options(tmp_path))
    assert keep_same(project)[2].verdict == 'review'
    with_text = pipeline.run_unified(project, options(tmp_path, texts=SHOWN, refresh=True))
    assert with_text.result_id == without.result_id and with_text.counts != without.counts
    assert keep_same(project)[2].verdict == 'material'
    with pytest.raises(UnifiedError) as drift:
        pipeline.run_unified(project, options(tmp_path, decompile=False, refresh=True))
    assert drift.value.reason == 'result-drift'


def test_a_text_that_does_not_show_the_edit_promotes_nothing(project, tmp_path):
    place_gzfs(project)
    same = {'older': keep_same_text('0x77'), 'newer': keep_same_text('0x77')}
    pipeline.run_unified(project, options(tmp_path, texts=same))
    _manifest, _row, facts = keep_same(project)
    assert (facts.verdict, facts.second_channel) == ('review', None) and dict(facts.channels)['C6'] == 'equal'


@pytest.mark.parametrize('failure', ['no-backend', 'no-gzf', 'partial', 'failed', 'part-failed'])
def test_an_incomplete_decompile_refresh_preserves_the_committed_result(project, tmp_path, monkeypatch, failure):
    place_gzfs(project)
    first = pipeline.run_unified(project, options(tmp_path, texts=SHOWN))
    committed = {p.name: p.read_bytes() for p in first.directory.iterdir()}
    assert keep_same(project)[2].verdict == 'material'
    refresh = options(tmp_path, texts=SHOWN, refresh=True)
    if failure == 'no-backend':
        refresh = options(tmp_path, refresh=True)
    elif failure == 'no-gzf':
        for path in (project.root / 'runs' / project.project.runs[-1].id / 'unified' / 'gzf').iterdir():
            path.unlink()
    elif failure == 'partial':
        refresh = options(tmp_path, texts={'older': SHOWN['older']}, refresh=True)
    elif failure == 'part-failed':
        monkeypatch.setattr(pipeline, '_store_decomp', lambda *args: ('decompile-part-skipped:part-too-large',))
    else:
        def fail_decompile(*args, **kwargs):
            raise UnifiedError('PT-UNIFIED-UNSUPPORTED', 'decompiler unavailable', reason='decompiler-unavailable')
        monkeypatch.setattr(pipeline, 'decompile_side', fail_decompile)
    with pytest.raises(UnifiedError) as error:
        pipeline.run_unified(project, refresh)
    assert error.value.reason == 'result-drift'
    assert keep_same(project)[2].verdict == 'material'
    assert {p.name: p.read_bytes() for p in first.directory.iterdir()} == committed


def test_a_function_the_decompiler_failed_on_leaves_the_pair_in_review_and_is_counted(project, tmp_path):
    place_gzfs(project)
    report = pipeline.run_unified(project, options(tmp_path, texts={'older': SHOWN['older']}))   # nothing for newer
    _manifest, _row, facts = keep_same(project)
    assert facts.verdict == 'review' and 'decompile-failed:1' in report.limitations
    assert stage(report, 'decompile').status == 'partial'


def test_a_retained_program_that_changed_since_the_run_recorded_it_is_never_decompiled(project, tmp_path):
    place_gzfs(project)
    request = pipeline.prepare(project, options(tmp_path, texts=SHOWN))
    changed = dataclasses.replace(request, gzf_recorded={'older': '0' * 64})
    output = pipeline.execute(changed)
    assert output.report is not None and output.notes == ('decompile-skipped:gzf-changed',)
    assert (output.stages[0].status, output.stages[0].reason) == ('skipped', 'gzf-changed')
    pipeline._discard(output.staged)


def test_disabling_the_decompile_is_silent_and_final(project, tmp_path):
    place_gzfs(project)
    report = pipeline.run_unified(project, options(tmp_path, texts=SHOWN, decompile=False))
    _manifest, _row, facts = keep_same(project)
    assert facts.verdict == 'review' and stage(report, 'decompile') is None
    assert not [x for x in report.limitations if 'decompile' in x]


def test_the_real_worker_child_gives_the_same_result_for_both_phases(project, tmp_path):
    place_gzfs(project)
    in_process = pipeline.run_unified(project, options(tmp_path, texts=SHOWN))
    child = pipeline.run_unified(project, options(tmp_path, texts=SHOWN, isolate=True, refresh=True, timeout_s=300))
    assert child.result_id == in_process.result_id and child.counts == in_process.counts
    assert stage(child, 'decompile').status == 'ok'
    assert keep_same(project)[2].verdict == 'material'


def test_a_cancel_during_the_decompile_ends_the_run_and_leaves_no_staged_directory(project, tmp_path):
    place_gzfs(project)
    cancel = threading.Event()
    slow = UnifiedOptions(isolate=False, backend=fake_backend(tmp_path, {s: {KEEP_SAME[s]: t}
                                                                         for s, t in SHOWN.items()}, slow=30.0))

    def watch(event):
        if event.stage == 'compute' or event.stage == 'write':
            threading.Timer(0.5, cancel.set).start()
    with pytest.raises(UnifiedError) as error:
        pipeline.run_unified(project, slow, cancel=cancel, emit=watch)
    assert error.value.code == 'PT-UNIFIED-CANCEL'
    results = project.root / 'runs' / project.project.runs[-1].id / 'unified' / 'results'
    assert not results.exists() or not [p for p in results.iterdir() if p.name.startswith('tmp-')]


def test_phase_one_picks_exactly_the_review_pair_with_a_constant_delta(project, tmp_path):
    output = pipeline.execute(pipeline.prepare(project, options(tmp_path, decompile=False)))
    assert output.report.refacts == ((0x1300, 0x1380),)
    manifest = store.verify_result_dir(output.staged)
    facts = {f.row_id: f for f in store.read_facts(output.staged, manifest)}
    chosen = [r for r in store.read_rows(output.staged, manifest)
              if r.older and r.newer and (r.older[0].rva, r.newer[0].rva) in output.report.refacts]
    assert len(chosen) == 1 and facts[chosen[0].row_id].verdict == 'review'
    pipeline._discard(output.staged)


def test_a_refacts_request_without_programir_is_refused_by_the_schema(project, tmp_path):
    request = pipeline.prepare(project, options(tmp_path, decompile=False))
    private = tmp_path / 'private'
    private.mkdir()
    base = json.loads(pipeline._write_request(request, private).read_text(encoding='utf-8'))
    described = exchange.write_refacts(private / 'refacts.json', pairs=[], texts={})
    for key in ('ir_older', 'ir_newer'):
        base.pop(key, None)
    base['refacts'] = described.model_dump()
    with pytest.raises(ValueError):
        exchange.WorkerRequest.model_validate(base)
