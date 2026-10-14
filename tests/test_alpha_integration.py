"""Integration tests: project inspection orchestration, raw view composition and desktop wiring."""
from __future__ import annotations

import hashlib
import os

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QApplication

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.models import Artifact
from patchtrace.pe_overview import inspect_pe
from patchtrace.raw_view import build_side, differing_lines, entry_scope, parse_entry_rva
from patchtrace.representations import Representation
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def store(root, side, data):
    digest = hashlib.sha256(data).hexdigest()
    (root / 'artifacts').mkdir(exist_ok=True)
    (root / 'artifacts' / f'{digest}.bin').write_bytes(data)
    return Artifact(side=side, name=f'{side}.dll', sha256=digest, size=len(data),
                    relative_path=f'artifacts/{digest}.bin')


# ---- orchestration -----------------------------------------------------------------------------

def test_inspects_both_sides_and_compares(tmp_path):
    older = store(tmp_path, 'older', build_pe(PeSpec(timestamp=1)))
    newer = store(tmp_path, 'newer', build_pe(PeSpec(timestamp=2, overlay=b'tail' * 8)))
    result = inspect_project_artifacts('p', [newer, older], tmp_path)
    try:
        assert result.sides['older'].overview.status == 'ok'
        assert result.sides['newer'].overview is not None
        assert result.comparisons and any(row.status == 'changed' for row in result.comparisons)
        assert result.reader('older').read(0, 2) == b'MZ'
    finally:
        result.close()
    assert result.readers == {}


def test_one_side_tampered_does_not_hide_other(tmp_path):
    older = store(tmp_path, 'older', build_pe())
    newer = store(tmp_path, 'newer', build_pe(PeSpec(timestamp=9)))
    (tmp_path / newer.relative_path).write_bytes(b'MZ' + b'\x00' * (newer.size - 2))
    result = inspect_project_artifacts('p', [older, newer], tmp_path)
    try:
        assert result.sides['newer'].error_code == 'hash_mismatch'
        assert result.reader('newer') is None
        assert result.sides['older'].overview is not None
        assert result.comparisons == ()
    finally:
        result.close()


def test_missing_side_is_a_contract_error(tmp_path):
    older = store(tmp_path, 'older', build_pe())
    with pytest.raises(ValueError, match='newer'):
        inspect_project_artifacts('p', [older], tmp_path)


def test_cancelled_before_start(tmp_path):
    older = store(tmp_path, 'older', build_pe())
    newer = store(tmp_path, 'newer', build_pe(PeSpec(timestamp=5)))
    result = inspect_project_artifacts('p', [older, newer], tmp_path, cancel=lambda: True)
    assert result.cancelled and result.readers == {}


# ---- raw view composition ----------------------------------------------------------------------

@pytest.mark.parametrize('address,base,expected', [
    ('140001000', 0x140000000, 0x1000), ('0x140001010', 0x140000000, 0x1010),
    ('1000', 0x140000000, None), ('zz', 0x140000000, None), (None, 0x140000000, None),
    ('140001000', None, None), ('1' * 17, 0, None)])
def test_parse_entry_rva(address, base, expected):
    assert parse_entry_rva(address, base) == expected


def open_pe(tmp_path, spec):
    path = tmp_path / 'x.bin'
    path.write_bytes(build_pe(spec))
    reader = VerifiedArtifactReader.open_path(path)
    return reader, inspect_pe(reader)


def test_entry_scope_maps_through_sections_and_never_claims_extent(tmp_path):
    reader, overview = open_pe(tmp_path, PeSpec(image_base=0x140000000,
                                                sections=[SectionSpec(data=b'\xcc' * 0x300)]))
    with reader:
        text = overview.sections[0]
        address = f'{0x140000000 + text.virtual_address + 0x10:x}'
        scope, message = entry_scope(overview, reader.size, address)
        assert message == '' and scope is not None
        assert scope.segments[0].file_offset == text.raw_offset + 0x10
        assert 'function extent not determined' in scope.label
        side = build_side('older', reader, overview, address, 'entry', Representation.HEX, 0)
        assert side.rendered is not None and 'cc cc' in side.rendered.text


def test_entry_scope_virtual_only_is_unavailable(tmp_path):
    spec = PeSpec(image_base=0x140000000,
                  sections=[SectionSpec(data=b'\x90' * 16, virtual_size=0x4000)])
    reader, overview = open_pe(tmp_path, spec)
    with reader:
        text = overview.sections[0]
        address = f'{0x140000000 + text.virtual_address + 0x3000:x}'
        scope, message = entry_scope(overview, reader.size, address)
        assert scope is None and 'No range is guessed' in message


def test_differing_lines_hex_and_base64(tmp_path):
    a, b = tmp_path / 'a.bin', tmp_path / 'b.bin'
    data = bytearray(64)
    a.write_bytes(bytes(data))
    data[40] = 1
    b.write_bytes(bytes(data))
    with VerifiedArtifactReader.open_path(a) as ra, VerifiedArtifactReader.open_path(b) as rb:
        old = build_side('older', ra, None, None, 'whole', Representation.HEX, 0)
        new = build_side('newer', rb, None, None, 'whole', Representation.HEX, 0)
        assert differing_lines(old, new, Representation.HEX) == (2,)
        old64 = build_side('older', ra, None, None, 'whole', Representation.BASE64, 0)
        new64 = build_side('newer', rb, None, None, 'whole', Representation.BASE64, 0)
        assert differing_lines(old64, new64, Representation.BASE64) == ()
        assert build_side('older', None, None, None, 'whole', Representation.HEX, 0).rendered is None
        missing = build_side('older', ra, None, '1', 'entry', Representation.HEX, 0)
        assert missing.rendered is None and 'unavailable' in missing.message


# ---- desktop wiring ----------------------------------------------------------------------------

@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    win = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(win)
    paired = {m.id for m in service.project.matches if m.older and m.newer}
    for row in range(win.navigator.count()):
        win.navigator.setCurrentRow(row)
        if win.current_match() and win.current_match().id in paired:
            break
    assert win.current_match().older and win.current_match().newer
    yield win
    win._stop_inspection()


def test_file_overview_shows_parsed_pe_comparison(window, qtbot):
    window.show_file_overview()
    qtbot.waitUntil(lambda: window._current_inspection() is not None, timeout=10000)
    table = window._preflight_pe_table
    assert table.rowCount() > 3
    fields = [table.item(i, 0).text() for i in range(table.rowCount())]
    assert any('entry' in f.lower() or 'machine' in f.lower() for f in fields)
    assert 'complete' in window._preflight_status.text()
    window._preflight_dialog.close()


def test_hex_mode_shows_verified_bytes_and_highlights_differences(window, qtbot):
    window.mode.setCurrentIndex(3)
    assert window.raw_scope.isVisibleTo(window) and window.raw_page.isVisibleTo(window)
    qtbot.waitUntil(lambda: window._raw_sides.get('older') is not None, timeout=10000)
    older = window.views['older'].toPlainText()
    assert older.startswith('00000000') and '4d 5a' in older
    # The two synthetic sample PEs differ in their embedded variant label.
    assert window.views['older'].extraSelections()
    assert 'original on-disk bytes' in window.match_label.text()
    window.navigate_hunk(1)
    assert 'no text hunks' in window.statusBar().currentMessage()


def select_match_with_older_address(window, address):
    for row in range(window.navigator.count()):
        window.navigator.setCurrentRow(row)
        match = window.current_match()
        if match and match.older and match.newer and match.older[0].address == address:
            return True
    return False


def test_entry_scope_maps_or_reports_unavailable_for_sample_functions(window, qtbot):
    window.mode.setCurrentIndex(3)
    qtbot.waitUntil(lambda: window._raw_sides.get('older') is not None, timeout=10000)
    window.raw_scope.setCurrentIndex(1)
    # Sample .text: RVA 0x1000, 64 bytes virtual, file offset 0x200, image base 0x180000000.
    if select_match_with_older_address(window, '180001000'):
        assert window.views['older'].toPlainText().startswith('00000200  b8')
        assert 'function extent not determined' in window.match_label.toolTip()
    assert select_match_with_older_address(window, '180001600')
    assert 'unavailable' in window.views['older'].toPlainText().lower()


def test_binary_base64_goto_and_copy(window, qtbot):
    window.mode.setCurrentIndex(4)
    qtbot.waitUntil(lambda: window._raw_sides.get('older') is not None, timeout=10000)
    assert window.views['older'].toPlainText().startswith('00000000')
    window.mode.setCurrentIndex(5)
    assert window.views['older'].toPlainText().startswith('TVo')  # base64 of b'MZ'
    window.raw_goto.setText('0x200')
    window.raw_goto_offset()
    assert window.raw_page.value() == 1
    window.raw_goto.setText('0xffffffff')
    window.raw_goto_offset()
    assert 'outside' in window.statusBar().currentMessage()
    window.copy_code('older')
    copied = QApplication.clipboard().text()
    assert 'Artifact SHA-256' in copied and window.project.id in copied


def test_text_modes_still_work_after_raw(window, qtbot):
    window.mode.setCurrentIndex(3)
    qtbot.waitUntil(lambda: window._raw_sides.get('older') is not None, timeout=10000)
    window.mode.setCurrentIndex(0)
    assert not window.raw_scope.isVisibleTo(window)
    assert 'return' in window.views['older'].toPlainText()


# ---- Authenticode surfacing --------------------------------------------------------------------

def test_trust_probe_runs_only_on_verified_pe_and_failures_are_reported(tmp_path):
    from patchtrace.pe_overview.authenticode import TrustResult
    older = store(tmp_path, 'older', build_pe())
    newer = store(tmp_path, 'newer', build_pe(PeSpec(timestamp=7)))
    (tmp_path / newer.relative_path).write_bytes(b'MZ' + b'\x00' * (newer.size - 2))
    calls = []

    def fake(path):
        calls.append(path.name)
        return TrustResult('trusted_no_revocation_check', 0, 'fake')
    result = inspect_project_artifacts('p', [older, newer], tmp_path, verify_trust=fake)
    result.close()
    assert calls == [f'{older.sha256}.bin']
    assert result.sides['older'].trust.status == 'trusted_no_revocation_check'
    assert result.sides['newer'].trust is None

    def broken(path):
        raise OSError('boom')
    older2 = store(tmp_path, 'newer', build_pe(PeSpec(timestamp=8)))
    result = inspect_project_artifacts('p', [older, older2], tmp_path, verify_trust=broken)
    result.close()
    assert result.sides['older'].trust.status == 'unavailable'


def test_trust_labels_never_claim_full_validity():
    from patchtrace.pe_overview.authenticode import STATUSES
    from patchtrace.ui_inspection import TRUST_LABELS
    assert set(TRUST_LABELS) == set(STATUSES)
    assert 'revocation NOT checked' in TRUST_LABELS['trusted_no_revocation_check']
    assert not any(label.lower().startswith('valid') for label in TRUST_LABELS.values())


def test_overview_table_has_authenticode_row(window, qtbot):
    window.show_file_overview()
    qtbot.waitUntil(lambda: window._current_inspection() is not None, timeout=10000)
    table = window._preflight_pe_table
    fields = [table.item(i, 0).text() for i in range(table.rowCount())]
    assert 'Authenticode (embedded, offline)' in fields
    window._preflight_dialog.close()
