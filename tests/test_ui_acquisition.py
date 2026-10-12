"""SPEC-08 §5 desktop acquisition dialog with a fake opener behind the real Transport."""
from __future__ import annotations

import gzip
import hashlib
import json
import threading

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog

from patchtrace.acquisition import transport as tr
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import AcquisitionDialog, MainWindow

OLDER, NEWER = synthetic_pe(0), synthetic_pe(1)
SHA_O, SHA_N = hashlib.sha256(OLDER).hexdigest(), hashlib.sha256(NEWER).hexdigest()
META = 'https://winbindex.m417z.com/data/by_filename_compressed/demo.sys.json.gz'
EVIL = '<b>bold</b><img src=x>'


class Resp:
    def __init__(self, status, body=b'', headers=None):
        self.status, self.headers, self._body = status, headers or {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


def record():
    doc = {}
    for i, data in enumerate((OLDER, NEWER)):
        sha = hashlib.sha256(data).hexdigest()
        doc[sha] = {'fileInfo': {'sha256': sha, 'size': len(data), 'machineType': 34404,
                                 'timestamp': 0x100 + i, 'virtualSize': 0x4000,
                                 'version': EVIL if i == 0 else '10.0.2'},
                    'windowsVersions': {'11-24H2': {f'KB50{i}': {'updateInfo': {
                        'releaseDate': f'2026-0{i + 1}-14'}}}}}
    doc['a' * 64] = {'fileInfo': {'sha256': 'a' * 64, 'size': 10, 'machineType': 332, 'timestamp': 1,
                                  'virtualSize': 0x1000, 'version': 'x86'}}
    doc['b' * 64] = {'fileInfo': {'sha256': 'b' * 64, 'size': 10, 'machineType': 34404, 'timestamp': 1,
                                  'version': 'pkg-only'}}
    return gzip.compress(json.dumps(doc).encode(), mtime=0)


class Server:
    def __init__(self, msdl_status=None, gate=None):
        self.calls, self.msdl_status, self.gate = [], msdl_status, gate

    def __call__(self, method, url, headers, timeout):
        self.calls.append((method, url))
        if url.startswith('https://winbindex.m417z.com/'):
            return Resp(200, record())
        if url.startswith('https://msdl.microsoft.com/'):
            if self.gate is not None:
                self.gate.wait(5)
            if self.msdl_status:
                return Resp(self.msdl_status)
            return Resp(302, headers={'Location': 'https://s.blob.core.windows.net/b?sig=X&u=' + url})
        return Resp(200, OLDER if '00000100' in url else NEWER)


def make(qtbot, server, consents=None):
    dialog = AcquisitionDialog(transport_factory=lambda cancel: tr.Transport(
        opener=server, cancel=cancel, sleep=lambda s, c: None))
    asked = [] if consents is None else consents
    dialog.confirm = lambda title, text: asked.append(text) or True
    qtbot.addWidget(dialog)
    return dialog, asked


def search(qtbot, dialog):
    dialog.name.setText('demo.sys')
    dialog.search_button.click()
    qtbot.waitUntil(lambda: dialog.worker is None and dialog.table.rowCount() > 0, timeout=5000)


def row_of(dialog, sha):
    return next(i for i, c in enumerate(dialog.candidates) if c.sha256 == sha)


def pick(dialog, sha, side):
    dialog.table.selectRow(row_of(dialog, sha))
    getattr(dialog, f'{side}_button').click()


def test_no_network_before_consent_and_declined_consent(qtbot):
    server = Server()
    dialog, _ = make(qtbot, server)
    dialog.name.setText('demo.sys')
    seen = []
    dialog.confirm = lambda title, text: seen.append(text) or False
    dialog.search_button.click()
    assert dialog.worker is None and server.calls == []
    assert 'winbindex.m417z.com' in seen[0] and META in seen[0]
    dialog.name.setText('Bad<NAME>.sys')
    dialog.search_button.click()
    assert 'PT-ACQ-INPUT' in dialog.status.text() and server.calls == []


def test_table_shows_all_rows_but_only_eligible_selectable(qtbot):
    dialog, asked = make(qtbot, Server())
    search(qtbot, dialog)
    assert META in asked[0]
    assert dialog.table.rowCount() == 4
    texts = {dialog.table.item(r, 0).text(): r for r in range(4)}
    x86, pkg = texts['x86'], texts['pkg-only']
    assert 'not x64' in dialog.table.item(x86, 3).text()
    assert dialog.table.item(pkg, 3).text() == 'update-package only'
    for r in (x86, pkg):
        assert not dialog.table.item(r, 0).flags() & Qt.ItemFlag.ItemIsSelectable
    newer = row_of(dialog, SHA_N)
    assert dialog.table.item(newer, 1).text() == 'KB501'
    assert dialog.table.item(newer, 2).text() == '2026-02-14'
    assert dialog.table.item(newer, 3).text() == 'direct download'
    dialog.table.setCurrentCell(x86, 0)
    dialog.pick('older')
    assert dialog.older is None


def test_injected_name_is_plain_text_including_tooltips(qtbot):
    dialog, _ = make(qtbot, Server())
    search(qtbot, dialog)
    item = dialog.table.item(row_of(dialog, SHA_O), 0)
    assert item.text() == EVIL
    assert EVIL not in item.toolTip() and '&lt;b&gt;bold&lt;/b&gt;' in item.toolTip()
    pick(dialog, SHA_O, 'older')
    assert dialog.older_label.textFormat() == Qt.TextFormat.PlainText
    assert dialog.older_label.text().startswith(EVIL)
    assert EVIL not in dialog.older_label.toolTip()


def test_explicit_selection_and_swap(qtbot):
    dialog, _ = make(qtbot, Server())
    search(qtbot, dialog)
    assert dialog.older is None and dialog.newer is None
    assert not dialog.download_button.isEnabled()
    pick(dialog, SHA_N, 'older')
    pick(dialog, SHA_O, 'newer')
    assert (dialog.older.sha256, dialog.newer.sha256) == (SHA_N, SHA_O)
    dialog.swap_button.click()
    assert (dialog.older.sha256, dialog.newer.sha256) == (SHA_O, SHA_N)
    assert dialog.download_button.isEnabled()


def ready(qtbot, dialog, tmp_path):
    search(qtbot, dialog)
    pick(dialog, SHA_O, 'older')
    pick(dialog, SHA_N, 'newer')
    dialog.root.setText(str(tmp_path / 'proj'))


def test_success_creates_project_via_promote_and_window_opens_it(qtbot, tmp_path):
    server = Server()
    dialog, asked = make(qtbot, server)
    ready(qtbot, dialog, tmp_path)
    calls_before = len(server.calls)
    dialog.download_button.click()
    text = asked[-1]
    assert 'msdl.microsoft.com' in text and '.blob.core.windows.net' in text
    assert 'https://msdl.microsoft.com/download/symbols/demo.sys/000001004000/demo.sys' in text
    qtbot.waitUntil(lambda: dialog.worker is None and dialog.service is not None, timeout=10000)
    assert len(server.calls) > calls_before
    assert dialog.result() == QDialog.DialogCode.Accepted
    service = dialog.service
    assert [a.sha256 for a in service.project.artifacts] == [SHA_O, SHA_N]
    assert any(a.text.startswith('acquisition/1 provenance: ') for a in service.project.annotations)
    assert 'sig=' not in json.dumps([a.text for a in service.project.annotations])
    service.close()


def test_main_window_menu_adopts_dialog_service(qtbot, tmp_path, monkeypatch):
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    window = MainWindow(None, settings)
    qtbot.addWidget(window)
    titles = [a.text() for a in window.menuBar().actions()[0].menu().actions()]
    assert 'Download from Microsoft symbol server…' in titles
    created = ProjectService.sample(tmp_path / 'sample')

    class Fake:
        service = created

        def exec(self):
            return QDialog.DialogCode.Accepted
    monkeypatch.setattr(window, 'acquisition_dialog', lambda: Fake())
    window.acquire_action.trigger()
    assert window.service is created


def test_404_is_normal_not_on_symbol_server(qtbot, tmp_path):
    dialog, _ = make(qtbot, Server(msdl_status=404))
    ready(qtbot, dialog, tmp_path)
    dialog.download_button.click()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    assert dialog.status.text().startswith('Not on symbol server')
    assert 'Error' not in dialog.status.text()
    assert dialog.service is None and not (tmp_path / 'proj').exists()


def test_cancel_during_download_creates_nothing(qtbot, tmp_path):
    gate = threading.Event()
    server = Server(gate=gate)
    dialog, _ = make(qtbot, server)
    ready(qtbot, dialog, tmp_path)
    dialog.download_button.click()
    qtbot.waitUntil(lambda: any('msdl' in u for _, u in server.calls), timeout=5000)
    assert dialog.cancel_button.isEnabled()
    dialog.cancel_button.click()
    gate.set()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    assert 'PT-ACQ-CANCEL' in dialog.status.text()
    assert dialog.service is None and not (tmp_path / 'proj').exists()


def test_errors_show_pt_code(qtbot, tmp_path):
    dialog, _ = make(qtbot, Server(msdl_status=403))
    ready(qtbot, dialog, tmp_path)
    dialog.download_button.click()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    assert dialog.status.text().startswith('Error · PT-ACQ-PROVIDER')


def test_download_consent_declined_makes_no_msdl_call(qtbot, tmp_path):
    server = Server()
    dialog, _ = make(qtbot, server)
    ready(qtbot, dialog, tmp_path)
    dialog.confirm = lambda title, text: False
    dialog.download_button.click()
    assert dialog.worker is None
    assert not any('msdl' in u for _, u in server.calls)
