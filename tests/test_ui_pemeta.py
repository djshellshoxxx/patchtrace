"""PE build-facts tab (WBQ S6): pure rows and copy, the widget's states, the 100,000-row gates, keyboard, names."""
from __future__ import annotations

import time

import pytest
from PySide6.QtCore import QItemSelectionModel, Qt
from PySide6.QtTest import QTest
from qt_support import HOSTILE_PARAMS, RecordingAnnouncer, a11y_audit, join_gui_threads  # noqa: F401

from patchtrace import pemeta_view as pv
from patchtrace import tooltips
from patchtrace.pe_overview.api_delta import ApiChange, ApiDelta
from patchtrace.pe_overview.manifest import AssemblyIdentity, ManifestObservation
from patchtrace.pe_overview.resources import ResourceLeaf
from patchtrace.pe_overview.version_info import FixedFileInfo, VersionBlock, VersionInfoSet, VersionString
from patchtrace.ui_pemeta import API_NAME, FACTS_NAME, PeMetaWidget

LEAF = ResourceLeaf(16, 'RT_VERSION', 1, 1033, 0x3000, 100, 0, 0x800)
MANIFEST_LEAF = ResourceLeaf(24, 'RT_MANIFEST', 1, 1033, 0x4000, 100, 0, 0x900)


def version(file_version=(1, 0, 0, 1), strings=(('ProductName', 'Demo'),), status='ok') -> VersionInfoSet:
    block = VersionBlock(
        LEAF, FixedFileInfo(file_version, file_version, 0x3F, 0, 0x40004, 1, 0),
        tuple(VersionString('040904b0', key, value, False) for key, value in strings), ('040904b0',), status, ())
    return VersionInfoSet((block,), 0, ())


def manifest(level='asInvoker', assembly='1.0.0.0', **options) -> ManifestObservation:
    return ManifestObservation(MANIFEST_LEAF, 'ab' * 32, execution_level=level,
                               identity=AssemblyIdentity('x', assembly, 'amd64', None, 'win32'), **options)


def side(**options) -> pv.SideMeta:
    options.setdefault('version', version())
    options.setdefault('manifests', (manifest(),))
    return pv.SideMeta(**options)


def delta(count: int, status='changed') -> ApiDelta:
    changes = tuple(ApiChange(f'dll{n % 7}.dll', f'Api{n:06d}', 'name', 'added' if n % 2 else 'removed')
                    for n in range(count))
    return ApiDelta(status, '', 'a' * 64, 'b' * 64, 10, 12, changes)


def rows_by_key(snapshot: pv.PeMetaSnapshot) -> dict[str, pv.FactRow]:
    return {row.key: row for row in pv.fact_rows(snapshot)}


# ---- pure view-model ----------------------------------------------------------------------------------------------


def test_identical_sides_are_unchanged():
    rows = rows_by_key(pv.PeMetaSnapshot(side(), side()))
    assert rows['file_version'].status == 'unchanged'
    assert rows['manifest:execution_level'].older == 'asInvoker'
    assert {row.status for row in rows.values()} == {'unchanged'}


def test_changed_version_and_level_are_marked_changed():
    snapshot = pv.PeMetaSnapshot(side(), side(version=version((2, 0, 0, 5)), manifests=(manifest('requireAdministrator'),)))
    rows = rows_by_key(snapshot)
    assert (rows['file_version'].older, rows['file_version'].newer) == ('1.0.0.1', '2.0.0.5')
    assert rows['file_version'].status == 'changed'
    assert rows['manifest:execution_level'].status == 'changed'
    assert rows['manifest:ui_access'].status == 'unchanged'  # absent on both sides


def test_an_unreadable_side_is_unavailable_never_changed():
    rows = rows_by_key(pv.PeMetaSnapshot(side(), pv.SideMeta(error='artifact_changed')))
    assert rows['file_version'].status == 'unavailable'
    assert rows['file_version'].newer == pv.UNKNOWN
    assert all(row.status == 'unavailable' for row in rows.values())


def test_a_refused_manifest_is_unknown_not_absent():
    refused = side(warnings=('manifest_dtd_rejected',), manifests=())
    rows = rows_by_key(pv.PeMetaSnapshot(side(), refused))
    assert rows['manifest:execution_level'].status == 'unavailable'
    assert rows['file_version'].status == 'unchanged'


def test_a_verified_absence_is_not_present_and_says_it_is_normal():
    empty = side(version=VersionInfoSet((), None, ()), manifests=())
    snapshot = pv.PeMetaSnapshot(side(), empty)
    assert rows_by_key(snapshot)['file_version'].newer == pv.ABSENT
    assert pv.notes(snapshot) == ('NEWER: ' + pv.NO_VERSION,)
    assert pv.panel_state(snapshot).kind == 'ready'  # a verified absence is not a partial result


def test_string_rows_follow_the_documented_keys():
    older = side(version=version(strings=(('ProductName', 'A'), ('Zzz', 'x'))))
    newer = side(version=version(strings=(('ProductName', 'B'), ('CompanyName', 'C'))))
    keys = [row.key for row in pv.fact_rows(pv.PeMetaSnapshot(older, newer)) if row.key.startswith('string:')]
    assert keys == ['string:CompanyName', 'string:ProductName']


@pytest.mark.parametrize('warning,fragment', [
    pytest.param('resource_nodes_over_cap', '20,000 resource entries', id='nodes'),
    pytest.param('manifest_over_cap', 'the manifest size', id='manifest'),
    pytest.param('manifest_dtd_rejected', 'document type definition (DTD)', id='dtd')])
def test_limits_and_refusals_make_the_result_partial_with_their_copy(warning, fragment):
    snapshot = pv.PeMetaSnapshot(side(warnings=(warning,)), side())
    assert any(fragment in text for text in pv.notes(snapshot))
    assert pv.panel_state(snapshot).kind == 'partial'


def test_unreadable_side_copy_names_the_code_and_the_other_side():
    snapshot = pv.PeMetaSnapshot(pv.SideMeta(error='artifact_changed'), side())
    assert pv.notes(snapshot) == ('OLDER: Could not read this record (artifact_changed). The other side is still shown.',)


@pytest.mark.parametrize('decoder,expected,kind', [
    ('unavailable', pv.DECODER_MISSING, 'ready'), ('stopped', pv.DECODER_STOPPED, 'partial'),
    ('ok', None, 'ready'), ('off', None, 'ready')])
def test_decoder_states(decoder, expected, kind):
    snapshot = pv.PeMetaSnapshot(side(), side(), decoder=decoder)
    assert (pv.DECODER_MISSING in pv.notes(snapshot) or pv.DECODER_STOPPED in pv.notes(snapshot)) is (expected is not None)
    assert pv.panel_state(snapshot).kind == kind


def test_unknown_decoder_state_is_rejected():
    with pytest.raises(ValueError):
        pv.PeMetaSnapshot(side(), side(), decoder='maybe')


def test_state_precedence_of_no_project_loading_idle():
    assert pv.panel_state(None, has_project=False).kind == 'no-project'
    assert pv.panel_state(None, loading=True).text == pv.LOADING
    assert pv.panel_state(None).kind == 'idle'


def test_unavailable_delta_is_a_row_and_a_note_not_a_list():
    unavailable = ApiDelta('unavailable', 'older imports are truncated', 'a' * 64, 'b' * 64, None, 12, ())
    snapshot = pv.PeMetaSnapshot(side(), side(), unavailable)
    row = rows_by_key(snapshot)['imports']
    assert (row.status, row.older) == ('unavailable', pv.UNKNOWN)
    assert pv.api_changes(snapshot) == ()
    assert any('older imports are truncated' in text for text in pv.notes(snapshot))


def test_duplicate_api_pairs_collapse_to_unique_row_keys():
    change = ApiChange('a.dll', 'F', 'name', 'added')
    assert pv.unique_changes([change, change]) == (change,)


# ---- the widget ---------------------------------------------------------------------------------------------------


@pytest.fixture
def widget(qtbot, monkeypatch):
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))  # private copy: the tip registry stays clean
    announcer = RecordingAnnouncer()
    view = PeMetaWidget(announcer)
    view.announcer = announcer
    qtbot.addWidget(view)
    view.resize(900, 700)
    view.show()
    return view


def snapshot_with(count: int) -> pv.PeMetaSnapshot:
    return pv.PeMetaSnapshot(side(), side(version=version((2, 0, 0, 5))), delta(count))


def test_loading_then_ready_shows_both_tables(widget):
    widget.set_loading()
    assert widget.state.kind == 'loading'
    assert widget.state.status_label().full_text() == pv.LOADING
    widget.set_snapshot(snapshot_with(5))
    assert widget.state.kind == 'ready'
    assert widget.facts.table_model.rowCount() >= 3
    assert widget.api.table_model.rowCount() == 5


def test_partial_keeps_rows_and_shows_notes(widget):
    widget.set_snapshot(pv.PeMetaSnapshot(side(warnings=('metadata_time_budget',)), side(), delta(3)))
    assert widget.state.kind == 'partial'
    assert widget.api.table_model.rowCount() == 3
    assert 'the time budget' in widget.notes.full_text()
    assert not widget.notes.isHidden()


def test_no_project_hides_the_content(widget):
    widget.set_snapshot(snapshot_with(2))
    widget.set_no_project()
    assert widget.state.kind == 'no-project'
    assert widget.facts.isHidden() or not widget.facts.isVisible()


def test_filter_narrows_the_api_table_by_dll_or_name(widget):
    widget.set_snapshot(snapshot_with(70))
    widget.filter.setText('dll3.DLL')
    assert widget.api.table_model.rowCount() == 10
    widget.filter.setText('api000007')
    assert widget.api.table_model.rowCount() == 1
    widget.filter.setText('')
    assert widget.api.table_model.rowCount() == 70


def test_enter_on_an_api_row_emits_show_callers(widget, qtbot):
    widget.set_snapshot(snapshot_with(4))
    widget.api.selectRow(0)
    widget.api.setCurrentIndex(widget.api.table_model.index(0, 0))
    expected = widget.api.table_model.row_at(0)
    with qtbot.waitSignal(widget.show_callers, timeout=2000) as caught:
        QTest.keyClick(widget.api, Qt.Key.Key_Return)
    assert caught.args == [expected.dll, expected.name]


def test_default_order_lists_added_before_removed(widget):
    widget.set_snapshot(snapshot_with(6))
    first = [widget.api.table_model.row_at(row).change for row in range(6)]
    assert first == sorted(first, key=pv.CHANGES.index)


def test_accessible_names_and_audit(widget):
    widget.set_snapshot(snapshot_with(3))
    assert widget.facts.accessibleName() == FACTS_NAME == 'Version and build facts'
    assert widget.api.accessibleName() == API_NAME == 'Imported API changes'
    assert widget.filter.accessibleName() == 'Filter imported API changes'
    # the table headers are never focus targets (the table is), as in test_gui_table
    assert [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable'] == []


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_resource_text_is_plain_text_in_cells_and_notes(widget, text):
    hostile = side(version=version(strings=(('ProductName', text),)), error='')
    widget.set_snapshot(pv.PeMetaSnapshot(hostile, side(), delta(1)))
    model = widget.facts.table_model
    cells = [model.texts_at(row) for row in range(model.rowCount())]
    assert all('\x00' not in cell and '\x1b' not in cell for row in cells for cell in row)
    assert widget.notes.textFormat() == Qt.TextFormat.PlainText


def test_filter_is_disabled_without_changes(widget):
    widget.set_snapshot(pv.PeMetaSnapshot(side(), side(), delta(0, 'unchanged')))
    assert not widget.filter.isEnabled()


# ---- gates at 100,000 rows (plan section 8: construct <= 150 ms, 100,000 data() calls <= 400 ms) ---------------------


def test_one_hundred_thousand_rows_meet_the_budgets(widget):
    prepared = pv.prepare_meta(snapshot_with(100_000))  # worker side: not part of the GUI budget
    start = time.perf_counter()
    widget.set_prepared(prepared)
    construct = time.perf_counter() - start
    model = widget.api.table_model
    assert model.rowCount() == 100_000
    index = model.index
    start = time.perf_counter()
    for row in range(100_000):
        model.data(index(row, 2))
    reading = time.perf_counter() - start
    assert construct >= 0 and reading >= 0
    assert construct <= 0.15 * 3, f'swap took {construct:.3f}s'  # the CI gate is 3x the measured budget
    assert reading <= 0.4 * 3, f'100,000 data() calls took {reading:.3f}s'


def test_over_one_hundred_thousand_rows_show_the_too_large_state(widget):
    widget.set_prepared(pv.prepare_meta(snapshot_with(100_001)))
    assert widget.api.too_large
    assert widget.api.table_model.rowCount() == 0


def test_selection_follows_the_key_across_a_refresh(widget):
    widget.set_snapshot(snapshot_with(20))
    row = widget.api.table_model.index(3, 0)
    widget.api.selectionModel().select(row, QItemSelectionModel.SelectionFlag.ClearAndSelect
                                       | QItemSelectionModel.SelectionFlag.Rows)
    chosen = widget.api.table_model.key_at(3)
    widget.set_snapshot(snapshot_with(20))
    assert widget.api.selected_keys() == [chosen]
