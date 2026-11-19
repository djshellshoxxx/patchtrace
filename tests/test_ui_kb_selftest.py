"""Authored F8 integration through the real event loop; no native or live-source evidence."""
from __future__ import annotations

import hashlib
import importlib
import os
import socket
import subprocess
import threading

import pytest
from PySide6.QtCore import QThread, QTimer

ENVIRONMENT = ('LOCALAPPDATA', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME')
CHILD = 'KB-Δ-調査'


def modules():
    return (importlib.import_module('patchtrace.gui.qt.kb_selftest'),
            importlib.import_module('patchtrace.gui.qt.selftest_loop'))


@pytest.fixture
def offline(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError('Synthetic self-test crossed a network or process boundary')
    for owner, name in ((socket.socket, 'connect'), (socket.socket, 'connect_ex'),
                        (socket, 'create_connection'), (socket, 'getaddrinfo'),
                        (subprocess, 'Popen'), (os, 'system')):
        monkeypatch.setattr(owner, name, refused)


def test_real_packaged_journey_retains_exact_source_and_stale_project(qtbot, qapp, tmp_path, offline):
    from patchtrace.gui.qt.tasks import CancelToken, live_task_threads
    from patchtrace.kbcorrelation.cli_leads import read_snapshot
    from patchtrace.kbcorrelation.panel_qt import load_report
    from patchtrace.service import ProjectService

    journey, _ = modules()
    before = {key: os.environ.get(key) for key in ENVIRONMENT}
    result = journey.run_journey(qapp, tmp_path)
    assert result['contract'] == 'patchtrace-kb-selftest/1'
    assert result['synthetic'] is True and result['matches'] == 4
    assert result['candidate_leads'] >= 4 and result['stale_after_reopen'] is True
    assert {'missing-coverage', 'kb-cve-search', 'ambiguous-scope', 'preview-cancel',
            'create-adopt', 'source-snapshot', 'stale-reopen'} <= set(result['coverage'])
    assert {key: os.environ.get(key) for key in ENVIRONMENT} == before
    assert not live_task_threads()
    root = tmp_path / CHILD
    workspace = root / 'app-data' / 'PatchTrace' / 'kb'
    with ProjectService.open(root / 'comparison-ε') as service:
        assert len(service.project.matches) == 4
        report = load_report(workspace, read_snapshot(service), CancelToken())
        assert 'advisory-revision' in report.stale_reasons
        sources = list((service.root / 'kb' / 'sources').glob('*.json.gz'))
        assert len(sources) == 1
        assert sources[0].name == result['source_sha256'] + '.json.gz'
        assert hashlib.sha256(journey._snapshot_bytes(sources[0])).hexdigest() == result['source_sha256']
    assert (root / 'comparison-report.json').is_file()
    assert (root / 'advisory-context.json').is_file()


def test_one_real_loop_delivers_timers_and_refuses_nested_or_wrong_thread(qapp, tmp_path):
    journey, loop = modules()
    delivered, errors = [], []
    before = qapp.quitOnLastWindowClosed()

    def steps():
        assert QThread.currentThread().loopLevel() == 1
        with pytest.raises(RuntimeError, match='before its event loop'):
            journey.run_journey(qapp, tmp_path / 'nested')
        QTimer.singleShot(0, lambda: delivered.append(True))
        yield loop.Wait(lambda: bool(delivered), 'normal timer delivery')
        return {'done': True}

    assert loop.run_steps(qapp, steps()) == {'done': True}
    assert qapp.quitOnLastWindowClosed() == before
    assert not (tmp_path / 'nested').exists()

    def off_thread():
        try:
            journey.run_journey(qapp, tmp_path / 'wrong-thread')
        except RuntimeError as error:
            errors.append(str(error))

    thread = threading.Thread(target=off_thread)
    thread.start()
    thread.join(2)
    assert not thread.is_alive() and len(errors) == 1
    assert 'GUI thread' in errors[0] and not (tmp_path / 'wrong-thread').exists()


@pytest.mark.parametrize('timeout', [False, True], ids=['step-error', 'wait-timeout'])
@pytest.mark.parametrize('cleanup_error', [False, True], ids=['normal-close', 'close-error'])
def test_failure_cancels_worker_releases_project_and_restores_environment(
        qtbot, qapp, tmp_path, monkeypatch, offline, timeout, cleanup_error):
    from patchtrace.gui.qt.tasks import live_task_threads
    from patchtrace.service import ProjectService

    journey, loop = modules()
    before = qapp.quitOnLastWindowClosed()
    qapp.setQuitOnLastWindowClosed(not before)
    expected_policy = qapp.quitOnLastWindowClosed()
    for key in ENVIRONMENT:
        monkeypatch.setenv(key, str(tmp_path / ('original-' + key)))
    environment = {key: os.environ.get(key) for key in ENVIRONMENT}
    started, stopped = threading.Event(), threading.Event()

    def worker(cancel, _report):
        started.set()
        try:
            cancel.wait(3)
        finally:
            stopped.set()

    def fail_candidate(window):
        window.panels.tasks.submit('selftest-failure-control', worker)
        yield loop.Wait(started.is_set, 'failure worker startup', timeout=1)
        if timeout:
            yield loop.Wait(lambda: False, 'forced wait', timeout=0.02)
        raise RuntimeError('forced step error')

    monkeypatch.setattr(journey, '_candidate', fail_candidate)
    if cleanup_error:
        close = journey.MainWindow.close

        def close_then_fail(window):
            close(window)
            raise ValueError('private cleanup detail must not enter the public note')

        monkeypatch.setattr(journey.MainWindow, 'close', close_then_fail)
    try:
        with pytest.raises(RuntimeError, match='timed out' if timeout else 'forced step') as failure:
            journey.run_journey(qapp, tmp_path)
        assert {key: os.environ.get(key) for key in ENVIRONMENT} == environment
        assert qapp.quitOnLastWindowClosed() == expected_policy
        assert stopped.is_set() and not live_task_threads()
        if cleanup_error:
            assert any('ValueError' in note for note in failure.value.__notes__)
            assert not any('private cleanup detail' in note for note in failure.value.__notes__)
        with ProjectService.open(tmp_path / CHILD / 'comparison-ε') as reopened:
            assert reopened.project.matches
    finally:
        qapp.setQuitOnLastWindowClosed(before)


def test_premature_application_exit_fails_and_closes_generator(qapp):
    _, loop = modules()
    cleaned = []
    before = qapp.quitOnLastWindowClosed()

    def steps():
        try:
            QTimer.singleShot(0, qapp.quit)
            yield loop.Wait(lambda: False, 'never completed')
        finally:
            cleaned.append(True)

    with pytest.raises(RuntimeError, match='exited before completion'):
        loop.run_steps(qapp, steps())
    assert cleaned == [True] and qapp.quitOnLastWindowClosed() == before


def test_early_quit_with_active_project_cancels_owned_tasks(qtbot, qapp, tmp_path, monkeypatch, offline):
    from patchtrace.gui.qt.tasks import live_task_threads
    from patchtrace.service import ProjectService

    journey, loop = modules()
    stopped = threading.Event()

    def worker(cancel, _report):
        cancel.wait(3)
        stopped.set()

    def leave_early(window):
        window.panels.tasks.submit('selftest-early-quit', worker)
        QTimer.singleShot(0, qapp.quit)
        yield loop.Wait(lambda: False, 'pending while app quits')

    monkeypatch.setattr(journey, '_candidate', leave_early)
    with pytest.raises(RuntimeError, match='exited before completion'):
        journey.run_journey(qapp, tmp_path)
    assert stopped.is_set() and not live_task_threads()
    with ProjectService.open(tmp_path / CHILD / 'comparison-ε') as service:
        assert service.project.matches


def test_changed_child_cleanup_preserves_the_original_failure(qapp, tmp_path, monkeypatch):
    journey, _ = modules()

    def replace_then_fail(owned):
        owned.path.rename(owned.path.with_name('retained-original'))
        owned.path.mkdir()
        (owned.path / 'foreign.txt').write_bytes(b'foreign replacement')
        raise ValueError('original step failure')
        yield

    monkeypatch.setattr(journey, '_journey_steps', replace_then_fail)
    with pytest.raises(ValueError, match='original step failure') as failure:
        journey.run_journey(qapp, tmp_path)
    assert any('RuntimeError' in note for note in failure.value.__notes__)
    assert (tmp_path / CHILD / 'foreign.txt').read_bytes() == b'foreign replacement'
    assert (tmp_path / 'retained-original').is_dir()


def test_global_deadline_also_bounds_steps_that_keep_becoming_ready(qapp):
    _, loop = modules()
    cleaned = []

    def steps():
        try:
            while True:
                yield loop.Wait(lambda: True, 'already ready')
        finally:
            cleaned.append(True)

    with pytest.raises(RuntimeError, match='overall deadline'):
        loop.run_steps(qapp, steps(), timeout=0.02)
    assert cleaned == [True]


def test_existing_unicode_child_is_never_reused_or_removed(qapp, tmp_path, offline):
    journey, _ = modules()
    child = tmp_path / CHILD
    child.mkdir()
    foreign = child / 'foreign.txt'
    foreign.write_bytes(b'not a self-test workspace')
    before = (child.stat().st_ino, foreign.read_bytes(), tuple(tmp_path.iterdir()))
    with pytest.raises(RuntimeError, match='owned|exists|collision'):
        journey.run_journey(qapp, tmp_path)
    assert (child.stat().st_ino, foreign.read_bytes(), tuple(tmp_path.iterdir())) == before


@pytest.mark.parametrize('replace_child', [False, True], ids=['parent', 'child'])
def test_temporary_cleanup_retains_observed_foreign_replacement(tmp_path, replace_child):
    _, loop = modules()
    with pytest.raises(RuntimeError, match='changed|replaced|ownership'):
        with loop.temporary_workspace(directory=tmp_path) as workspace:
            workspace.claim()
            target = workspace.path if replace_child else workspace.root
            retained = target.with_name(target.name + '-retained')
            target.rename(retained)
            target.mkdir()
            foreign = target / 'foreign.txt'
            foreign.write_bytes(b'preserve replacement')
    assert retained.is_dir() and foreign.read_bytes() == b'preserve replacement'


def test_temporary_workspace_cleans_only_its_owned_tree_after_failure(tmp_path):
    _, loop = modules()
    sibling = tmp_path / 'existing.txt'
    sibling.write_bytes(b'preserve sibling')
    with pytest.raises(ValueError, match='forced failure'):
        with loop.temporary_workspace(directory=tmp_path) as workspace:
            workspace.claim()
            artifact = workspace.path / 'read-only.bin'
            artifact.write_bytes(b'authored')
            artifact.chmod(0o400)
            root = workspace.root
            raise ValueError('forced failure')
    assert not root.exists() and sibling.read_bytes() == b'preserve sibling'


def test_worker_that_exceeds_join_budget_prevents_temporary_cleanup(qtbot, qapp, tmp_path, monkeypatch, offline):
    journey, loop = modules()
    started, release = threading.Event(), threading.Event()
    runners = []

    def worker(_cancel, _report):
        started.set()
        release.wait(3)

    def fail_with_pending_work(window):
        runner = window.panels.tasks
        shutdown = runner.shutdown
        runners.append(shutdown)
        monkeypatch.setattr(runner, 'shutdown', lambda: shutdown(timeout=0.01))
        runner.submit('selftest-uncooperative-control', worker)
        yield loop.Wait(started.is_set, 'worker startup')
        raise RuntimeError('controlled pending work failure')

    monkeypatch.setattr(journey, '_candidate', fail_with_pending_work)
    try:
        with pytest.raises(RuntimeError, match='controlled pending work failure') as failure:
            with loop.temporary_workspace(directory=tmp_path) as workspace:
                root = workspace.root
                journey.run_journey(qapp, workspace)
        assert root.is_dir() and workspace.retain
        assert any('cleanup' in note and 'RuntimeError' in note for note in failure.value.__notes__)
    finally:
        release.set()
        for shutdown in runners:
            assert shutdown(timeout=2) == []


def test_inventory_and_investigation_registry_what_texts_are_distinct(qapp, tmp_path):
    from patchtrace.kbcorrelation.inventory_qt import register_inventory_tips
    from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
    from patchtrace.tooltips import REGISTRY

    register_inventory_tips()
    dialog = InvestigationDialog(workspace=tmp_path)
    try:
        assert REGISTRY['kb.inventory.browse_workspace'].what != REGISTRY['kb.investigation.browse_workspace'].what
    finally:
        dialog.reject()
