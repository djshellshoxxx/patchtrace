"""Constructed offline F8 journey for source and frozen desktop self-tests.

The advisory, PE bytes and imported comparison are synthetic controls, never native
analysis or live-provider evidence. The same desktop controllers and persisted
contracts used by the product are exercised without importing anything from tests.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, QThread, QTimer
from PySide6.QtWidgets import QLineEdit, QPushButton

from ...enrichment.pipeline import publish, run
from ...enrichment.storage import EnrichmentStore
from ...kbcorrelation.store import WorkspaceStore, default_workspace
from ...kbcorrelation.wiring import build_service
from ...sample import sample_diff, synthetic_pe
from ...service import ProjectService
from ...ui import MainWindow

MARKER = 'offline-investigation: synthetic F8 journey passed'
CVE = 'CVE-2099-20001'


def _require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError('KB frozen journey: ' + message)


@dataclass(frozen=True)
class _Wait:
    ready: Callable[[], bool]
    description: str
    timeout: float = 15


class _JourneyRunner(QObject):
    """One continuation per timer turn; worker signals and deferred deletion use the normal Qt event loop."""

    def __init__(self, app, steps):
        super().__init__()
        self.app, self.steps = app, steps
        self.wait: _Wait | None = None
        self.deadline = 0.0
        self.result = None
        self.error: BaseException | None = None
        self.done = False
        self.timer = QTimer(self)
        self.timer.setInterval(2)
        self.timer.timeout.connect(self.advance)

    def finish(self, error: BaseException | None = None) -> None:
        self.error = error
        try:
            self.steps.close()
        except BaseException as cleanup:
            if self.error is None:
                self.error = cleanup
            else:
                self.error.add_note(f'Journey cleanup also failed: {cleanup!r}')
        self.done = True

    def advance(self) -> None:
        if self.done:
            self.timer.stop()
            self.app.exit(1 if self.error else 0)
            return
        try:
            if self.wait is not None and not self.wait.ready():
                if time.monotonic() >= self.deadline:
                    raise RuntimeError('KB frozen journey timed out: ' + self.wait.description)
                return
            self.wait = next(self.steps)
            if self.wait is not None:
                self.deadline = time.monotonic() + self.wait.timeout
        except StopIteration as completed:
            self.result = completed.value
            self.finish()
        except BaseException as error:
            # Exceptions must leave the Qt callback through the caller, never get printed and swallowed by Qt.
            self.finish(error)


def _run_steps(app, steps: Generator) -> dict:
    if QThread.currentThread() != app.thread() or app.thread().loopLevel() != 0:
        raise RuntimeError('Desktop self-test requires the GUI thread before its event loop starts')
    runner = _JourneyRunner(app, steps)
    quit_on_close = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    try:
        runner.timer.start()
        app.exec()
        if not runner.done:
            runner.finish(RuntimeError('Desktop self-test event loop exited before completion'))
        if runner.error is not None:
            raise runner.error
        return runner.result
    finally:
        runner.timer.stop()
        if not runner.done:
            runner.finish(sys.exception())
        app.setQuitOnLastWindowClosed(quit_on_close)
        runner.deleteLater()


def _close_owned(objects, failure: BaseException | None) -> None:
    cleanup_errors = []
    for obj, method in objects:
        if obj is not None:
            try:
                getattr(obj, method)()
            except BaseException as error:
                cleanup_errors.append(error)
    if cleanup_errors:
        if failure is not None and not isinstance(failure, GeneratorExit):
            for error in cleanup_errors:
                failure.add_note(f'Journey cleanup also failed: {error!r}')
        else:
            raise cleanup_errors[0]


def _advisory(*, revision: int = 0) -> dict:
    today = datetime.now(UTC)
    month = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')[today.month - 1]
    release = f'{today.year}-{month}'
    return {
        'dialect': 'cvrf-json/0', 'synthetic': True,
        'document': {'release_id': release, 'tracking_id': f'PT-SYNTHETIC-{release}',
                     'current_release_date': f'{today:%Y-%m-%d}T00:0{revision}:00Z',
                     'publisher': 'PatchTrace synthetic self-test, not Microsoft',
                     'title': 'Constructed offline self-test'},
        'product_tree': [
            {'product_id': 'PT-AMD64', 'name': 'Example OS 24H2 x64',
             'architecture': 'amd64', 'family': 'windows-client'},
            {'product_id': 'PT-ARM64', 'name': 'Example OS 24H2 ARM64',
             'architecture': 'arm64', 'family': 'windows-client'}],
        'vulnerabilities': [{'cve': CVE, 'title': 'SYNTHETIC item reader bounds check',
                             'cwe': {'id': 'CWE-125', 'name': 'Out-of-bounds Read'},
                             'product_statuses': {'Fixed': ['PT-AMD64', 'PT-ARM64']},
                             'remediations': [{'description': '5099001', 'type': 2,
                                               'product_ids': ['PT-AMD64', 'PT-ARM64'],
                                               'fixed_build': '10.0.26100.9001'}]}],
    }


def _press(dialog, name: str):
    _require(dialog.buttons[name].isEnabled(), f'{name} is unexpectedly disabled')
    dialog.buttons[name].click()
    yield _Wait(lambda: dialog._pending is None, name)


def _candidate(window):
    window.panels.show_panel('kb')
    controller = window.panels.controller('kb')
    _require(controller is not None, 'KB candidate controller could not be constructed')
    controller.project_changed(controller.port.key())
    yield _Wait(lambda: not controller.tasks.busy(), 'candidate view')
    _require(controller.model is not None, 'KB candidate view did not load: '
             + controller.panel.state_view.status_label().full_text())
    return controller


def _rank(window) -> None:
    service = window.service
    result = run(service.project)
    _require(result.ranking is not None, 'synthetic comparison did not produce a ranking')
    publish(EnrichmentStore(service.store), service.project, result)
    window.refresh()


def _snapshot_bytes(path: Path) -> bytes:
    envelope = json.loads(gzip.decompress(path.read_bytes()))
    _require(envelope['contract'] == 'kbcorrelation/1' and envelope['encoding'] == 'base64',
             'source snapshot envelope is invalid')
    raw = base64.b64decode(envelope['bytes'], validate=True)
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == envelope['source']['sha256'] and path.name == f'{digest}.json.gz',
             'source snapshot identity does not match its bytes')
    return raw


def _journey_steps(root: Path):
    root = Path(root) / 'KB-Δ-調査'
    root.mkdir(parents=True)
    saved = os.environ.get('LOCALAPPDATA')
    os.environ['LOCALAPPDATA'] = str(root / 'app-data')
    window = dialog = None
    failure: BaseException | None = None
    try:
        workspace = default_workspace()
        source = root / 'synthetic-advisory.json'
        raw = json.dumps(_advisory(), ensure_ascii=False).encode('utf-8')
        source.write_bytes(raw)
        inputs = []
        for side, variant in (('older', 0), ('newer', 1)):
            folder = root / side
            folder.mkdir()
            path = folder / 'exampledrv.sys'
            path.write_bytes(synthetic_pe(variant))
            inputs.append(path)
        destination = root / 'comparison-ε'
        settings = QSettings(str(root / 'settings.ini'), QSettings.Format.IniFormat)
        window = MainWindow(settings=settings)
        window.show()
        yield None
        dialog = window.investigation_dialog()
        _require(not dialog.buttons['create'].isEnabled(), 'unpreviewed project creation was enabled')
        for widget in [*dialog.findChildren(QLineEdit), *dialog.findChildren(QPushButton),
                       dialog.scope, dialog.same_component]:
            _require(widget.accessibleName() and widget.toolTip(), 'an investigation control lacks a name or tooltip')
        dialog.fields['lead'].setText(CVE)
        yield from _press(dialog, 'search')
        _require(dialog.scope.count() == 1 and not dialog.buttons['create'].isEnabled(),
                 'missing advisory coverage unexpectedly enabled a comparison')
        dialog.fields['source'].setText(str(source))
        yield from _press(dialog, 'import')
        with WorkspaceStore(workspace, create=False) as store:
            sources = store.sources()
            _require(len(sources) == 1 and sources[0].sha256 == hashlib.sha256(raw).hexdigest(),
                     'source provenance was not persisted')
        dialog.fields['lead'].setText(CVE)
        yield from _press(dialog, 'search')
        _require(dialog.scope.count() == 3 and dialog.scope.currentData() is None,
                 'ambiguous products were implicitly selected or omitted')
        index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(index)
        yield _Wait(lambda: dialog._pending is None, 'explicit product selection')
        for key, value in (('older', inputs[0]), ('newer', inputs[1]), ('destination', destination),
                           ('name', 'SYNTHETIC offline KB journey')):
            dialog.fields[key].setText(str(value))
        yield from _press(dialog, 'preview')
        _require(dialog._preview is not None and 'Older SHA-256:' in dialog.details.toPlainText(),
                 'verified local pair preview is absent')
        yield from _press(dialog, 'create')
        _require(window.service is not None and window.service.root == destination.resolve(),
                 'created project was not adopted by the desktop')
        dialog.reject()
        dialog = None
        snapshots = list((destination / 'kb' / 'sources').glob('*.gz'))
        _require(len(snapshots) == 1 and _snapshot_bytes(snapshots[0]) == raw,
                 'content-addressed advisory snapshot differs from the imported bytes')
        comparison = root / 'synthetic.ghidriff.json'
        comparison.write_text(json.dumps(sample_diff(window.service.project)), encoding='utf-8')
        window.service.import_diff(comparison)
        _rank(window)
        _require(window.navigator.count() == 4, 'imported fixture matches did not reach the desktop navigator')
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'ready' and controller.model.lead_count >= 4,
                 'ranked candidate view is missing its real persisted leads')
        _require(any(g.group == CVE for g in controller.model.report.groups), 'advisory group is missing')
        _require(all(chip.state != 'supports' for group in controller.model.report.groups
                     for lead in group.leads for chip in lead.chips if chip.channel == 'applicability'),
                 'constructed advisory association became proof of binary applicability')
        report_path = root / 'comparison-report.json'
        window.service.export_report('json', report_path)
        exported = json.loads(report_path.read_text(encoding='utf-8'))
        _require(bool(exported), 'project report is empty')
        project_id = window.service.project.id
        original_count = len(window.service.project.runs)
        window.close()
        yield None
        window = None
        kb = build_service(workspace)
        kb_export = kb.export(str(destination), str(root / 'advisory-context.json'), overwrite=False)
        _require(kb_export.exit == 0 and kb_export.result['written'], 'stored advisory export failed')
        window = MainWindow(service=ProjectService.open(destination), settings=settings)
        window.show()
        yield None
        _require(window.project.id == project_id and len(window.project.runs) == original_count,
                 'reopen lost project identity or analysis history')
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'ready', 'candidate state was lost after reopen')
        # Replacing the advisory must retain old evidence while disabling stale navigation.
        source.write_text(json.dumps(_advisory(revision=1)), encoding='utf-8')
        dialog = window.investigation_dialog()
        dialog.fields['source'].setText(str(source))
        yield from _press(dialog, 'import')
        dialog.reject()
        dialog = None
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'stale'
                 and 'advisory-revision' in controller.model.report.stale_reasons,
                 'advisory replacement did not mark the candidate view stale')
        _require(not controller.model.navigation_enabled, 'stale evidence navigation remained enabled')
        window.close()
        yield None
        window = MainWindow(service=ProjectService.open(destination), settings=settings)
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'stale' and not controller.model.navigation_enabled,
                 'stale state did not survive close and reopen')
        _require(_snapshot_bytes(snapshots[0]) == raw, 'replacement discarded the attached source')
        return {'contract': 'patchtrace-kb-selftest/1', 'synthetic': True,
                'source_sha256': hashlib.sha256(raw).hexdigest(), 'matches': 4,
                'candidate_leads': controller.model.lead_count, 'stale_after_reopen': True,
                'coverage': ['missing-coverage', 'offline-import', 'ambiguous-scope', 'pair-preview', 'create-adopt',
                             'fixture-analysis-import', 'candidate-panel', 'project-and-context-export',
                             'unicode-paths', 'tooltips', 'source-snapshot', 'reopen', 'stale-reopen']}
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            _close_owned(((dialog, 'reject'), (window, 'close')), failure)
        finally:
            if saved is None:
                os.environ.pop('LOCALAPPDATA', None)
            else:
                os.environ['LOCALAPPDATA'] = saved


def run_journey(app, root: Path) -> dict:
    """Run the full F8 control before the application loop starts; no repository-test dependency."""
    return _run_steps(app, _journey_steps(root))


def _selftest_steps(root: Path):
    service = ProjectService.sample(root / 'sample')
    settings = QSettings(str(root / 'settings.ini'), QSettings.Format.IniFormat)
    window = None
    failure: BaseException | None = None
    try:
        window = MainWindow(service=service, settings=settings)
        window.show()
        yield None
        _require(window.navigator.count() and 'SYNTHETIC SAMPLE' in window.project_label.text(),
                 'desktop sample matches did not display')
        problems = window.panels.self_check()
        _require(not problems, 'panel self-check failed: ' + '; '.join(problems))
    except BaseException as error:
        failure = error
        raise
    finally:
        _close_owned(((window if window is not None else service, 'close'),), failure)
    yield None
    return (yield from _journey_steps(root))


def run_selftest(app, root: Path) -> dict:
    """The sample desktop check and F8 journey share one normal application event loop."""
    return _run_steps(app, _selftest_steps(root))
