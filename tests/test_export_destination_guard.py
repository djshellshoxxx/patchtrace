
import pytest

from patchtrace.reports import ExportError
from patchtrace.service import ProjectService


def test_export_cannot_replace_open_project_database(tmp_path):
    root = tmp_path / 'case'
    service = ProjectService.sample(root)
    database = root / 'project.sqlite3'
    before = database.read_bytes()
    inventory = set(root.rglob('*'))
    try:
        with pytest.raises(ExportError, match='PT-EXPORT'):
            service.export_report('md', database)
        assert database.read_bytes() == before
        assert set(root.rglob('*')) == inventory
    finally:
        service.close()
    reopened = ProjectService.open(root)
    reopened.close()


@pytest.mark.parametrize('kind', ['parent-alias', 'hardlink', 'hardlink-db', 'final-symlink', 'raw-in-exports', 'sidecar'])
def test_export_refuses_project_evidence_aliases_without_side_effects(tmp_path, kind):
    import os
    import shutil

    service = ProjectService.sample(tmp_path / 'case')
    root = service.root
    protected = root / service.project.artifacts[0].relative_path
    if kind == 'hardlink-db':
        protected = root / 'project.sqlite3'
    destination = tmp_path / 'outside.md'
    if kind == 'parent-alias':
        alias = tmp_path / 'alias'
        alias.symlink_to(root, target_is_directory=True)
        destination = alias / 'project.sqlite3'
    elif kind in {'hardlink', 'hardlink-db'}:
        os.link(protected, destination)
    elif kind == 'final-symlink':
        destination.symlink_to(protected)
    elif kind == 'sidecar':
        destination = root / 'runs' / 'not-created' / 'report.md'
    else:
        destination = root / 'exports' / 'owned.bin'
        destination.parent.mkdir()
        shutil.copy2(protected, destination)
        import hashlib

        service.project.runs[0].raw_path = 'exports/owned.bin'
        service.project.runs[0].raw_sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
        service.save()
    before = protected.read_bytes()
    inventory = set(root.rglob('*'))
    try:
        with pytest.raises(ExportError, match='PT-EXPORT'):
            service.export_report('md', destination)
        assert protected.read_bytes() == before
        assert set(root.rglob('*')) == inventory
    finally:
        service.close()


@pytest.mark.parametrize('external', [True, False])
def test_reports_and_previous_backups_remain_supported(tmp_path, external):
    service = ProjectService.sample(tmp_path / 'case')
    destination = (tmp_path if external else service.root / 'exports') / 'report.md'
    try:
        service.export_report('md', destination)
        previous = destination.read_bytes()
        service.export_report('md', destination, include_code=True)
        assert destination.read_bytes() != previous
        backups = list(destination.parent.glob('report.previous-*.md'))
        assert len(backups) == 1 and backups[0].read_bytes() == previous
    finally:
        service.close()


def test_main_window_routes_export_through_service(tmp_path, qtbot, monkeypatch):
    from PySide6.QtWidgets import QDialog

    from patchtrace.ui import ExportDialog, MainWindow

    service = ProjectService.sample(tmp_path / 'case')
    window = MainWindow(service=service)
    qtbot.addWidget(window)
    destination = service.root / 'project.sqlite3'
    before = destination.read_bytes()

    def accept(dialog):
        dialog.destination.setText(str(destination))
        return QDialog.DialogCode.Accepted

    errors = []
    monkeypatch.setattr(ExportDialog, 'exec', accept)
    monkeypatch.setattr(window, 'show_error', errors.append)
    window.export_report()
    assert errors and 'PT-EXPORT' in str(errors[0])
    assert destination.read_bytes() == before
    window.close()


def test_existing_report_export_never_walks_project_tree(tmp_path, monkeypatch):
    from pathlib import Path

    service = ProjectService.sample(tmp_path / 'case')
    destination = service.root / 'exports/report.md'
    service.export_report('md', destination)

    def forbidden(*args, **kwargs):
        raise AssertionError('export must not recursively enumerate project files')

    monkeypatch.setattr(Path, 'rglob', forbidden)
    try:
        service.export_report('md', destination, include_code=True)
    finally:
        service.close()


@pytest.mark.parametrize('status', ['queued', 'running'])
def test_export_uses_committed_snapshot_without_recovering_live_runs(tmp_path, status):
    import json

    from patchtrace.models import AnalysisRun

    service = ProjectService.sample(tmp_path / 'case')
    service.project.name = 'Committed name'
    live_run = AnalysisRun(status=status)
    service.project.runs.append(live_run)
    service.save()
    service.project.name = 'Unsaved name'
    destination = tmp_path / 'report.json'
    before = (service.root / 'project.sqlite3').read_bytes()
    history = service.store.history()
    try:
        service.export_report('json', destination)
        text = destination.read_text()
        assert 'Committed name' in text and 'Unsaved name' not in text
        exported = next(run for run in json.loads(text)['analysis_runs'] if run['id'] == live_run.id)
        assert exported['status'] == status
        with pytest.raises(ExportError):
            service.export_report('md', service.root / 'project.sqlite3')
        assert (service.root / 'project.sqlite3').read_bytes() == before
        assert service.project.name == 'Unsaved name'
        assert service.project.runs[-1].status == status
        assert service.store.load(recover_interrupted=False).runs[-1].status == status
        assert service.store.history() == history
    finally:
        service.close()
    reopened = ProjectService.open(tmp_path / 'case')
    try:
        assert reopened.project.runs[-1].status == 'failed'
    finally:
        reopened.close()
