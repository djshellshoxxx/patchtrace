"""Package-authored offline F8 control through current desktop and persisted contracts.

The advisory, PE bytes and imported comparison are synthetic. This is neither native
analysis nor live-provider evidence and has no dependency on repository test fixtures.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QLineEdit, QPushButton

from ...enrichment.pipeline import publish, run
from ...enrichment.storage import EnrichmentStore
from ...kbcorrelation.sources.cvrf import load_json
from ...kbcorrelation.store import WorkspaceStore, default_workspace
from ...kbcorrelation.wiring import build_service
from ...sample import sample_diff, synthetic_pe
from ...service import ProjectService
from ...ui import MainWindow
from .selftest_loop import Wait, Workspace, run_steps

MARKER = 'offline-investigation: synthetic F8 journey passed'
CVE, KB = 'CVE-2099-20001', 'KB5099001'
ENVIRONMENT = ('LOCALAPPDATA', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME')


def _require(condition: object, message: str) -> None:
    if not condition:
        raise RuntimeError('Desktop self-test KB journey: ' + message)


def _close_owned(window, dialog, service, workspace, failure=None) -> None:
    errors = []
    tasks = window.panels.tasks if window is not None else None
    service = window.service if window is not None and window.service is not None else service
    for obj, method in ((dialog, 'reject'), (tasks, 'shutdown'), (window, 'close'), (service, 'close')):
        if obj is not None:
            try:
                result = getattr(obj, method)()
                if method == 'shutdown' and result:
                    raise RuntimeError('Desktop self-test workers did not stop')
                if method == 'close' and result is False:
                    raise RuntimeError('Desktop self-test window did not close')
            except BaseException as error:
                errors.append(error)
    if errors:
        workspace.retain = True
        if failure is not None and not isinstance(failure, GeneratorExit):
            for error in errors:
                failure.add_note(f'Desktop self-test cleanup also failed: {type(error).__name__}')
        else:
            raise errors[0]


def _advisory(today: datetime, *, revision: int = 0) -> dict:
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
    yield Wait(lambda: dialog._pending is None, name)


def _candidate(window):
    window.panels.show_panel('kb')
    controller = window.panels.controller('kb')
    _require(controller is not None, 'KB candidate controller could not be constructed')
    controller.project_changed(controller.port.key())
    yield Wait(lambda: not controller.tasks.busy(), 'candidate view')
    _require(controller.model is not None, 'KB candidate view did not load')
    return controller


def _rank(window) -> None:
    service = window.service
    result = run(service.project)
    _require(result.ranking is not None, 'synthetic comparison did not produce a ranking')
    publish(EnrichmentStore(service.store), service.project, result)
    window.refresh()


def _snapshot_bytes(path: Path) -> bytes:
    _require(path.stat().st_size <= 64 * 1024, 'synthetic source copy exceeds its fixture budget')
    with gzip.open(path, 'rb') as source:
        body = source.read(64 * 1024 + 1)
    _require(len(body) <= 64 * 1024, 'synthetic source envelope exceeds its fixture budget')
    envelope = load_json(body)
    _require(envelope['contract'] == 'kbcorrelation/1' and envelope['encoding'] == 'base64',
             'source snapshot envelope is invalid')
    raw = base64.b64decode(envelope['bytes'], validate=True)
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == envelope['source']['sha256'] and path.name == f'{digest}.json.gz',
             'source snapshot identity does not match its bytes')
    return raw


def _journey_steps(owned: Workspace):
    root, workspace = owned.path, default_workspace()
    window = dialog = service = None
    failure = None
    try:
        today = datetime.now(UTC)
        source = root / 'synthetic-advisory.json'
        raw = json.dumps(_advisory(today), ensure_ascii=False).encode('utf-8')
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
        dialog.fields['lead'].setText(KB)
        yield from _press(dialog, 'search')
        _require(dialog.scope.count() == 1 and not dialog.buttons['create'].isEnabled(),
                 'missing advisory coverage unexpectedly enabled a comparison')
        dialog.fields['source'].setText(str(source))
        yield from _press(dialog, 'import')
        with WorkspaceStore(workspace, create=False) as store:
            sources = store.sources()
            _require(len(sources) == 1 and sources[0].sha256 == hashlib.sha256(raw).hexdigest(),
                     'source provenance was not persisted')
        for lead in (KB, CVE):
            dialog.fields['lead'].setText(lead)
            yield from _press(dialog, 'search')
            _require(dialog.scope.count() == 3 and dialog.scope.currentData() is None,
                     'ambiguous products were implicitly selected or omitted')
        index = next(i for i in range(1, dialog.scope.count()) if 'amd64' in dialog.scope.itemText(i))
        dialog.scope.setCurrentIndex(index)
        yield Wait(lambda: dialog._pending is None, 'explicit product selection')
        for key, value in (('older', inputs[0]), ('newer', inputs[1]), ('destination', destination),
                           ('name', 'SYNTHETIC offline KB journey')):
            dialog.fields[key].setText(str(value))
        _require(dialog.buttons['preview'].isEnabled(), 'preview is unexpectedly disabled')
        dialog.buttons['preview'].click()
        dialog.cancel_operation()
        yield Wait(lambda: not dialog.tasks.busy(), 'cancelled preview worker')
        _require(dialog._preview is None and not dialog.buttons['create'].isEnabled(),
                 'cancelled preview enabled project creation')
        yield from _press(dialog, 'preview')
        _require(dialog._preview is not None and 'Older SHA-256:' in dialog.details.toPlainText(),
                 'verified local pair preview is absent')
        pair = dialog._preview[1].data['pair']
        _require(all(pair[f'{side}_sha256'] == hashlib.sha256(synthetic_pe(variant)).hexdigest()
                     for side, variant in (('older', 0), ('newer', 1))), 'preview changed the ordered input hashes')
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
                 'ranked candidate view is missing its persisted leads')
        _require(any(g.group == CVE for g in controller.model.report.groups), 'advisory group is missing')
        _require(all(chip.state != 'supports' for group in controller.model.report.groups
                     for lead in group.leads for chip in lead.chips if chip.channel == 'applicability'),
                 'constructed advisory association became proof of binary applicability')
        report_path = root / 'comparison-report.json'
        window.service.export_report('json', report_path)
        _require(bool(load_json(report_path.read_bytes())), 'project report is empty')
        project_id = window.service.project.id
        original_runs = tuple(run.id for run in window.service.project.runs)
        _close_owned(window, None, None, owned)
        window = None
        yield None
        kb_export = build_service(workspace).export(str(destination), str(root / 'advisory-context.json'), overwrite=False)
        _require(kb_export.exit == 0 and kb_export.result['written'], 'stored advisory export failed')
        service = ProjectService.open(destination)
        window = MainWindow(service=service, settings=settings)
        window.show()
        yield None
        _require(window.project.id == project_id and tuple(run.id for run in window.project.runs) == original_runs,
                 'reopen lost project identity or analysis history')
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'ready', 'candidate state was lost after reopen')
        source.write_text(json.dumps(_advisory(today, revision=1)), encoding='utf-8')
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
        _close_owned(window, None, service, owned)
        window = service = None
        yield None
        service = ProjectService.open(destination)
        window = MainWindow(service=service, settings=settings)
        window.show()
        yield None
        controller = yield from _candidate(window)
        _require(controller.model.report.state == 'stale' and not controller.model.navigation_enabled,
                 'stale state did not survive close and reopen')
        _require(_snapshot_bytes(snapshots[0]) == raw, 'replacement discarded the attached source')
        return {'contract': 'patchtrace-kb-selftest/1', 'synthetic': True,
                'source_sha256': hashlib.sha256(raw).hexdigest(), 'matches': 4,
                'candidate_leads': controller.model.lead_count, 'stale_after_reopen': True,
                'coverage': ['missing-coverage', 'offline-import', 'kb-cve-search', 'ambiguous-scope', 'pair-preview',
                             'preview-cancel', 'create-adopt', 'fixture-analysis-import', 'candidate-panel',
                             'project-and-context-export', 'unicode-paths', 'tooltips', 'source-snapshot',
                             'reopen', 'stale-reopen']}
    except BaseException as error:
        failure = error
        raise
    finally:
        _close_owned(window, dialog, service, owned, failure)


def _sample_steps(owned: Workspace):
    service = window = None
    failure = None
    try:
        service = ProjectService.sample(owned.path / 'sample')
        settings = QSettings(str(owned.path / 'sample-settings.ini'), QSettings.Format.IniFormat)
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
        _close_owned(window, None, service, owned, failure)
    yield None


def _session_steps(root: Path | Workspace, *, sample: bool):
    owned = root if isinstance(root, Workspace) else Workspace(root)
    path = owned.claim()
    saved = {key: os.environ.get(key) for key in ENVIRONMENT}
    failure = None
    try:
        for key, name in zip(ENVIRONMENT, ('app-data', 'app-data', 'app-state', 'app-cache'), strict=True):
            os.environ[key] = str(path / name)
        if sample:
            yield from _sample_steps(owned)
        return (yield from _journey_steps(owned))
    except BaseException as error:
        failure = error
        raise
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        # Resource cleanup failures already annotate the original error. Do not replace it with an identity error.
        if not owned.retain:
            try:
                owned.check()
            except BaseException as cleanup:
                owned.retain = True
                if failure is None or isinstance(failure, GeneratorExit):
                    raise
                failure.add_note(f'Desktop self-test cleanup also failed: {type(cleanup).__name__}; files retained')


def run_journey(app, root: Path | Workspace) -> dict:
    """Retain authored artifacts beneath an exclusive child of the supplied parent for inspection."""
    return run_steps(app, _session_steps(root, sample=False))


def run_selftest(app, root: Path | Workspace) -> dict:
    """The existing sample and synthetic F8 journey share one normal application event loop."""
    return run_steps(app, _session_steps(root, sample=True))
