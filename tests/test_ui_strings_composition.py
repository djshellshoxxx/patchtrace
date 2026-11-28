# ruff: noqa: F811
"""Explicit stored-source and anchor composition; authored records/bytes, no tools executed."""
from __future__ import annotations

import hashlib
import threading
from types import SimpleNamespace

import pytest
from qt_support import join_gui_threads  # noqa: F401
from test_intel_tools_snapshot import entry, publish_tool
from test_strings_composition import request_for, service  # noqa: F401
from test_ui_strings_panel import SAMPLE, key, settle, start, status

from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.intelligence.tools import snapshot
from patchtrace.intelligence.tools.common import EVIDENCE_KIND, RUN_KIND, cache_key, config_digest
from patchtrace.strings import cli, compose
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.qt_panel import scan_builtin


class StoredProject:
    def __init__(self, service):
        self.service = service

    def key(self):
        return request_for(self.service).key

    def artifact_paths(self):
        request = request_for(self.service)
        return request.older, request.newer, request.older_sha256, request.newer_sha256

    def project(self):
        return self.service.project

    def busy(self):
        return False


def controller_for(qtbot, service, *, loader=scan_builtin):
    return start(qtbot, loader=loader, project=StoredProject(service), scan=False)[0]


def choose(controller, choice):
    source = controller.panel.source
    index = source.findData(choice)
    assert index >= 0
    source.setCurrentIndex(index)


def expected(service, source='auto', anchors=None):
    return cli.compute(SimpleNamespace(source=source, anchors=anchors, min_length=4), service, threading.Event())


def test_choices_are_explicit_and_builtin_never_captures_tools(qtbot, service, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError('built-in selection must not capture stored tools')
    monkeypatch.setattr(snapshot, 'capture_tool_sources', forbidden)
    controller = controller_for(qtbot, service)
    assert controller.loaded is None and not controller.tasks.busy()
    assert {controller.panel.source.itemData(i) for i in range(controller.panel.source.count())} == {
        'auto', 'floss', 'builtin'}
    choose(controller, 'builtin')
    assert controller.loaded is None and not controller.tasks.busy()
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == expected(service, 'builtin').delta


@pytest.mark.parametrize('stored,choice', [((), 'auto'), (('older',), 'auto'),
    (('older', 'newer'), 'auto'), (('older', 'newer'), 'floss'), (('older', 'newer'), 'builtin')],
    ids=['none', 'mixed', 'both', 'explicit', 'builtin'])
def test_dock_selection_matches_cli_for_each_side(qtbot, service, stored, choice):
    for side in stored:
        publish_tool(service, side, label=f'{side} authored stored string')
    wanted = expected(service, choice)
    controller = controller_for(qtbot, service)
    choose(controller, choice)
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == wanted.delta
    if stored and choice != 'builtin':
        assert any('FLOSS' in row.source for row in controller.loaded.rows)


def test_explicit_missing_source_keeps_rows_and_does_not_scan(qtbot, service, monkeypatch):
    controller = controller_for(qtbot, service)
    choose(controller, 'builtin')
    controller.scan()
    settle(qtbot, controller)
    before = controller.loaded
    publish_tool(service, 'older')
    choose(controller, 'floss')

    def forbidden(*_args, **_kwargs):
        raise AssertionError('missing source must refuse before artifact inspection')
    monkeypatch.setattr('patchtrace.strings.pairing.inspect_image', forbidden)
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded is before and controller.view.kind == 'error'
    assert 'no stored FLOSS evidence for the newer artifact' in status(controller)


@pytest.mark.parametrize('kind', [RUN_KIND, EVIDENCE_KIND], ids=['run', 'evidence'])
@pytest.mark.parametrize('field,value', [('stale', 1), ('project_id', 'foreign-project')], ids=['stale', 'foreign'])
def test_refused_side_keeps_valid_other_side(qtbot, service, kind, field, value):
    publish_tool(service, 'older', label='older stored string')
    publish_tool(service, 'newer', label='newer stored string')
    row = entry(service, kind)
    service.store.connection.execute(f'UPDATE enrichment_entries SET {field}=? WHERE id=?', (value, row.id))
    wanted = expected(service)
    assert wanted.sources == {'older': 'floss', 'newer': 'builtin-scan'}
    controller = controller_for(qtbot, service)
    choose(controller, 'auto')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == wanted.delta


def test_cache_hit_retains_original_raw_and_executable_basis(qtbot, service):
    runs = []
    for side in ('older', 'newer'):
        store, run, _evidence = publish_tool(service, side, label=f'{side} retained string')
        runs.append(run)
    before = expected(service, 'floss')
    for run in runs:
        store.publish_run(run.model_copy(update={'run_id': f'cached-{run.side}', 'cache_hit': True,
                                                 'raw_sidecar': None, 'stdout_digest': None}))
    controller = controller_for(qtbot, service)
    choose(controller, 'floss')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == before.delta
    after = expected(service, 'floss')
    for side in ('older', 'newer'):
        part = after.tables[side].basis.parts[0]
        original = next(run for run in runs if run.side == side)
        assert part.run_id == original.run_id and part.raw_sha256 == original.stdout_digest
        assert part.executable_sha256 == original.manifest.executable_sha256


def test_capture_owner_and_worker_deep_snapshot(qtbot, service, monkeypatch):
    publish_tool(service, 'older')
    publish_tool(service, 'newer')
    owner, captures, workers = threading.get_ident(), [], []
    original = snapshot.capture_tool_sources

    def capture(*args, **kwargs):
        captures.append(threading.get_ident())
        assert captures[-1] == owner
        return original(*args, **kwargs)

    def load(request, token, report):
        workers.append(threading.get_ident())
        assert workers[-1] != owner and isinstance(request.tool_sources, snapshot.ToolSources)
        assert request.project is not service.project and request.project.artifacts is not service.project.artifacts
        return scan_builtin(request, token, report)

    monkeypatch.setattr(snapshot, 'capture_tool_sources', capture)
    controller = controller_for(qtbot, service, loader=load)
    controller.scan()
    settle(qtbot, controller)
    assert captures == [owner] and len(workers) == 1 and controller.loaded is not None


@pytest.mark.parametrize('damage', ['row-budget', 'body-digest'])
def test_global_capture_failure_preserves_rows_and_builtin_bypass(qtbot, service, monkeypatch, damage):
    publish_tool(service, 'older')
    publish_tool(service, 'newer')
    controller = controller_for(qtbot, service)
    controller.scan()
    settle(qtbot, controller)
    accepted = controller.loaded
    if damage == 'row-budget':
        monkeypatch.setattr(snapshot, 'SNAPSHOT_ROWS', 1)
    else:
        row = entry(service, RUN_KIND)
        service.store.connection.execute('UPDATE enrichment_entries SET body_sha256=? WHERE id=?',
                                         ('f' * 64, row.id))
    with monkeypatch.context() as limited:
        def forbidden(*_args, **_kwargs):
            raise AssertionError('global capture failure must refuse before artifact inspection')
        limited.setattr('patchtrace.strings.pairing.inspect_image', forbidden)
        with pytest.raises(StringsError) as failure:
            expected(service)
        assert failure.value.code == 'PT-STR-SOURCE'
        controller.scan()
        settle(qtbot, controller)
    assert controller.loaded is accepted and controller.view.kind == 'error'
    assert 'PT-STR-SOURCE' in status(controller)
    choose(controller, 'builtin')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == expected(service, 'builtin').delta


def test_produced_empty_remains_a_floss_source(qtbot, service):
    for side in ('older', 'newer'):
        publish_tool(service, side, empty=True)
    wanted = expected(service, 'floss')
    assert wanted.sources == {'older': 'floss', 'newer': 'floss'}
    assert all(table.basis.rows_kept == 0 for table in wanted.tables.values())
    controller = controller_for(qtbot, service)
    choose(controller, 'floss')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == wanted.delta and controller.view.kind == 'ready'
    assert not controller.loaded.rows


def test_truncated_stored_source_keeps_indeterminate_rows(qtbot, service):
    for side in ('older', 'newer'):
        store, _run, evidence = publish_tool(service, side, label=f'{side} retained string')
    store.publish_evidence(evidence.model_copy(update={
        'truncated': True, 'truncated_types': ('static',), 'counts': {'strings_total': 3, 'total_static': 3}}))
    wanted = expected(service, 'floss')
    assert wanted.tables['newer'].basis.stages['static'].state == 'truncated'
    assert wanted.delta.changes and all(change.status == 'indeterminate' for change in wanted.delta.changes)
    controller = controller_for(qtbot, service)
    choose(controller, 'floss')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == wanted.delta
    assert controller.loaded.partial == (('newer', '1'),) and controller.view.kind == 'partial'
    assert '1 rows retained' in status(controller)


@pytest.mark.parametrize('mismatch', ['executable', 'consent'])
def test_incompatible_stored_emulation_keeps_static_comparison(qtbot, service, mismatch):
    for side in ('older', 'newer'):
        store, run, evidence = publish_tool(service, side, label=f'{side} retained static string')
        manifest = run.manifest.model_copy(update={'executable_sha256':
            ('b' if side == 'newer' and mismatch == 'executable' else 'a') * 64})
        options = {'emulation_consent_sha256':
            ('c' if side == 'newer' and mismatch == 'consent' else 'b') * 64}
        digest, cache = config_digest(manifest, options), cache_key(run.input_artifact_hash, manifest, options)
        run_id = f'comparison-{side}'  # different configuration is a new immutable producing run
        static = evidence.strings[0].model_copy(update={'source_run_id': run_id,
            'source_location': evidence.strings[0].source_location.model_copy(update={'tool_run_id': run_id})})
        value = f'{side} retained stack string'
        stack = static.model_copy(update={'type': 'stack', 'extraction_method': 'floss-stack',
            'display_value': value, 'value_hash': hashlib.sha256(value.encode()).hexdigest(), 'length': len(value)})
        store.publish_run(run.model_copy(update={'run_id': run_id, 'manifest': manifest, 'options': options,
            'config_digest': digest, 'cache_key': cache, 'evidence_count': 2}))
        store.publish_evidence(evidence.model_copy(update={'run_id': run_id,
            'config_digest': digest, 'cache_key': cache,
            'analysis': {'types': 'static,stack'}, 'strings': (static, stack)}))
    wanted = expected(service, 'floss')
    assert wanted.delta.comparable
    assert wanted.delta.harmonized.types == ('static',)
    assert wanted.delta.counts['not-compared-rows'] == 2
    assert wanted.delta.changes and all(change.status in ('only-older', 'only-newer')
                                       for change in wanted.delta.changes)
    assert {kind for change in wanted.delta.changes for observed in (change.older, change.newer)
            if observed for kind in observed.types} == {'static'}
    assert any(f'the {"FLOSS executable" if mismatch == "executable" else "emulation consent"} differs' in note
               for note in wanted.delta.basis_notes)
    controller = controller_for(qtbot, service)
    choose(controller, 'floss')
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded.delta == wanted.delta


def anchor_file(tmp_path):
    anchor = Anchor(anchor_id=hashlib.sha256(b'ui-anchor').hexdigest(), kind='string', value='exceeds length',
                    source='csaf-title', quality='explicit', label='authored hint')
    path = tmp_path / 'anchors.json'
    path.write_text(AnchorSet(cve='CVE-2026-0001', anchors=(anchor,)).model_dump_json(), encoding='utf-8')
    return path


def test_anchor_choice_reads_on_worker_and_can_be_cleared(qtbot, service, tmp_path, monkeypatch):
    path = anchor_file(tmp_path)
    wanted = expected(service, anchors=path)
    controller = controller_for(qtbot, service)
    controller.anchor_dialog = lambda _parent: str(path)
    owner, reads, original = threading.get_ident(), [], compose.load_anchors

    def observed(path):
        reads.append(threading.get_ident())
        return original(path)
    monkeypatch.setattr(compose, 'load_anchors', observed)
    controller.choose_anchors()
    assert controller.anchors_path == path and not reads and not controller.tasks.busy()
    assert controller.panel.anchors_label.full_text() == path.name
    controller.scan()
    settle(qtbot, controller)
    assert reads and owner not in reads and controller.loaded.delta == wanted.delta
    accepted = controller.loaded
    controller.clear_anchors()
    assert controller.anchors_path is None and controller.loaded is accepted
    assert controller.stale and not controller.tasks.busy()
    assert not controller.panel.buttons['clear_anchors'].isEnabled()


def test_bad_anchor_keeps_accepted_results(qtbot, service, tmp_path):
    controller = controller_for(qtbot, service)
    controller.scan()
    settle(qtbot, controller)
    accepted = controller.loaded
    path = tmp_path / 'invalid.json'
    path.write_text('{"cve":"CVE-2026-0001","cve":"CVE-2026-0002"}', encoding='utf-8')
    controller.anchor_dialog = lambda _parent: str(path)
    controller.choose_anchors()
    controller.scan()
    settle(qtbot, controller)
    assert controller.loaded is accepted and controller.view.kind == 'error'
    assert 'PT-STR-INPUT' in status(controller)


def test_cancelled_anchor_chooser_leaves_inputs_and_rows_unchanged(qtbot, tmp_path):
    controller, *_ = start(qtbot)
    path = anchor_file(tmp_path)
    controller.anchor_dialog = lambda _parent: str(path)
    controller.choose_anchors()
    controller.scan()
    settle(qtbot, controller)
    accepted, generation = controller.loaded, controller.generation
    controller.anchor_dialog = lambda _parent: ''
    controller.choose_anchors()
    assert controller.anchors_path == path and controller.loaded is accepted and not controller.stale
    assert controller.generation == generation and not controller.tasks.busy()


@pytest.mark.parametrize('change', ['project', 'shutdown'])
def test_anchor_chooser_discards_result_after_owner_changes(qtbot, tmp_path, change):
    controller, _, _, project = start(qtbot)
    path = anchor_file(tmp_path)

    def dialog(_parent):
        if change == 'project':
            project.current = key(project='different-project')
            controller.project_changed(project.current)
        else:
            controller.shutdown()
        return str(path)

    controller.anchor_dialog = dialog
    controller.choose_anchors()
    assert controller.anchors_path is None and not controller.tasks.busy()


@pytest.mark.parametrize('change', ['source', 'anchors'])
def test_repeated_project_notification_does_not_clear_changed_input(qtbot, tmp_path, change):
    controller, *_ = start(qtbot)
    if change == 'source':
        choose(controller, 'builtin')
    else:
        controller.anchor_dialog = lambda _parent: str(anchor_file(tmp_path))
        controller.choose_anchors()
    controller.project_changed(controller.key)
    assert controller.stale and controller.view.kind == 'stale'
    assert controller.loaded is SAMPLE and not controller.tasks.busy()


@pytest.mark.parametrize('change', ['source', 'anchors', 'revision'])
def test_running_result_is_refused_after_context_change(qtbot, tmp_path, change):
    entered, release = threading.Event(), threading.Event()

    def delayed(*_args):
        entered.set()
        assert release.wait(3)
        return SAMPLE
    controller, _, _, project = start(qtbot, loader=delayed, scan=False)
    controller.scan()
    try:
        qtbot.waitUntil(entered.is_set)
        if change == 'source':
            choose(controller, 'builtin')
        elif change == 'anchors':
            controller.anchor_dialog = lambda _parent: str(anchor_file(tmp_path))
            controller.choose_anchors()
        else:
            project.current = key(revision=2)
        release.set()
        settle(qtbot, controller)
        assert controller.loaded is None and controller.progress is None
        if change == 'revision':
            assert controller.stale and controller.view.kind == 'stale'
    finally:
        release.set()


def test_project_switch_clears_explicit_anchor_choice(qtbot, tmp_path):
    controller, *_ = start(qtbot, scan=False)
    path = anchor_file(tmp_path)
    controller.anchor_dialog = lambda _parent: str(path)
    controller.choose_anchors()
    controller.project_changed(key(project='different-project'))
    assert controller.anchors_path is None and not controller.tasks.busy()
    assert not controller.panel.buttons['clear_anchors'].isEnabled()


def test_revision_changed_during_capture_never_starts_worker(qtbot, service, monkeypatch):
    def forbidden(*_args):
        raise AssertionError('revision changed before worker launch')
    controller = controller_for(qtbot, service, loader=forbidden)
    before = controller.port.key
    current = before()

    def capture(*_args, **_kwargs):
        controller.port.key = lambda: current._replace(revision=current.revision + 1)
        return snapshot.ToolSources(captured_engines=('floss',))
    monkeypatch.setattr(snapshot, 'capture_tool_sources', capture)
    controller.scan()
    assert controller.loaded is None and not controller.tasks.busy() and controller.stale
