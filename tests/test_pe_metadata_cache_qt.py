"""SPEC-51: the existing inspection worker computes facts; only the owner stores them."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from pe_meta_builder import meta_pe
from PySide6.QtCore import QObject, Signal

from patchtrace import artifact_inspection, ui_inspection
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pe_overview.cache import KIND
from patchtrace.pe_overview.metadata import PeMetadata
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow
from patchtrace.ui_inspection import FilesController, SigningTab


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'old.exe', tmp_path / 'new.exe'
    older.write_bytes(meta_pe('1.0.0.0')[0])
    newer.write_bytes(meta_pe('1.0.1.0', 'requireAdministrator')[0])
    service = ProjectService.create(older, newer, 'metadata worker', tmp_path / 'case')
    yield service
    service.close()


class Owner(QObject):
    """Exercise MainWindow's production lifecycle slots without unrelated dock startup."""
    inspection_status = Signal(str)

    def __init__(self, service):
        super().__init__()
        self.service, self.project = service, service.project
        self._inspection = self._inspection_key = self._inspection_thread = self._inspection_error = None
        self._inspection_threads = []
        self._raw_sides = {}
        self.raw_alignment = SimpleNamespace(invalidate=lambda: None)
        self.logs = SimpleNamespace(appendPlainText=lambda text: None)

    _project_inspection_key = MainWindow._project_inspection_key
    _current_inspection = MainWindow._current_inspection
    start_inspection = MainWindow.start_inspection
    _inspection_ready = MainWindow._inspection_ready
    _inspection_failed = MainWindow._inspection_failed
    _clear_inspection = MainWindow._clear_inspection
    _reap_inspection_threads = MainWindow._reap_inspection_threads
    _stop_inspection = MainWindow._stop_inspection

    def _raw_mode(self):
        return False


def test_metadata_parse_is_worker_owned_and_storage_is_gui_owned(qtbot, service, monkeypatch):
    owner_id = threading.get_ident()
    parsed, read, written = [], [], []
    real_parse, real_entry, real_publish = (artifact_inspection.inspect_metadata,
                                          EnrichmentStore.entry, EnrichmentStore.publish)

    def parse(*args, **kwargs):
        parsed.append(threading.get_ident())
        return real_parse(*args, **kwargs)

    def entry(*args, **kwargs):
        read.append(threading.get_ident())
        return real_entry(*args, **kwargs)

    def publish(*args, **kwargs):
        written.append(threading.get_ident())
        return real_publish(*args, **kwargs)

    monkeypatch.setattr(artifact_inspection, 'inspect_metadata', parse)
    monkeypatch.setattr(EnrichmentStore, 'entry', entry)
    monkeypatch.setattr(EnrichmentStore, 'publish', publish)
    owner = Owner(service)
    try:
        owner.start_inspection()
        qtbot.waitUntil(lambda: owner._inspection is not None, timeout=20000)
        assert len(parsed) == 2 and all(ident != owner_id for ident in parsed)
        assert read and written and set(read + written) == {owner_id}
        assert len(EnrichmentStore(service.store).entries(KIND)) == 2
    finally:
        owner._stop_inspection()


def test_files_tab_uses_existing_worker_result_without_second_reader(qtbot, service, monkeypatch):
    monkeypatch.setattr(ui_inspection, 'MetadataThread',
                        lambda *args, **kwargs: pytest.fail('Files tab started a second metadata reader'))
    owner = Owner(service)
    context = SimpleNamespace(project=SimpleNamespace(window=owner, project=lambda: service.project))
    controller = FilesController(context)
    qtbot.addWidget(controller.widget())
    try:
        controller.refresh()
        qtbot.waitUntil(lambda: controller.signing.model.rowCount() > 0, timeout=20000)
        values = {row.values[0]: row.values for row in controller.signing.model.rows}
        assert values['File version (fixed)'][1:3] == ('1.0.0.0', '1.0.1.0')
        assert controller._signing_thread is None
        assert owner._inspection.sides['older'].metadata is not None
    finally:
        controller.shutdown()
        owner._stop_inspection()


def test_second_inspection_reuses_cache_on_the_existing_worker(qtbot, service, monkeypatch):
    owner = Owner(service)
    try:
        owner.start_inspection()
        qtbot.waitUntil(lambda: owner._inspection is not None, timeout=20000)
        original = owner._inspection.sides['older'].metadata
        owner._stop_inspection()
        monkeypatch.setattr(artifact_inspection, 'inspect_metadata',
                            lambda *args, **kwargs: pytest.fail('metadata cache was not used'))
        owner.start_inspection()
        qtbot.waitUntil(lambda: owner._inspection is not None, timeout=20000)
        assert owner._inspection.sides['older'].metadata == original
    finally:
        owner._stop_inspection()


def test_missing_metadata_is_unavailable_not_absent_version(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result({'older': None, 'newer': PeMetadata('ok')})
    assert 'PT-PE-INPUT' in tab.status.full_text()
    assert tab.status.full_text() != ui_inspection.sv.EMPTY


def test_partial_metadata_remains_visible_without_inventing_a_limit_cause(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result({'older': PeMetadata('partial'), 'newer': PeMetadata('ok')})
    assert tab.status.full_text() == ui_inspection.sv.PARTIAL
    assert tab.model.rowCount() > 0


def test_closing_project_clears_previous_signing_facts(qtbot, service):
    owner = Owner(service)
    port = SimpleNamespace(window=owner, project=lambda: service.project)
    controller = FilesController(SimpleNamespace(project=port))
    qtbot.addWidget(controller.widget())
    try:
        controller.refresh()
        qtbot.waitUntil(lambda: controller.signing.model.rowCount() > 0, timeout=20000)
        assert controller.signing.tree_model.rowCount() > 0
        port.project = lambda: None
        controller.refresh(retry=False)
        assert controller.signing.model.rowCount() == 0
        assert controller.signing.tree_model.rowCount() == 0
        assert controller.signing.manifest.toPlainText() == ''
        assert controller.signing.status.full_text() == ui_inspection.IDLE_STATUS
    finally:
        controller.shutdown()
        owner._stop_inspection()
