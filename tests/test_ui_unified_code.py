"""SPEC-31 07 s3: the code view of the Unified panel (decompiled C and disassembly side by side, alignment gaps, hunk
navigation, provenance, copy). Offscreen Qt. The code is the product's own: the real pipeline publishes a synthetic
result and `RowCodeSource` reads it; decompiled C is stored with the product's part writer. Nothing here is live
evidence."""
from __future__ import annotations

import dataclasses
import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QPushButton
from qt_support import HOSTILE_PARAMS, a11y_audit, join_gui_threads  # noqa: F401  (the fixture is used by name)
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace.gui.pair_text import align_pair
from patchtrace.gui.qt.codediff import MAX_VIEW_CHARS, TRUNCATION_NOTICE
from patchtrace.gui.tips import register_tips
from patchtrace.ui_unified import CODE_HINT, CODE_LOADING, UnifiedCodeView
from patchtrace.unified import pair_text, pipeline, store
from patchtrace.unified.pair_text import CodeChannel, RowCode, RowCodeSource
from patchtrace.unified.panel import TEMPLATES, TIPS
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.read_model import load_unified, records_for, request_from_service


@pytest.fixture(autouse=True)
def tips():
    register_tips(TIPS, TEMPLATES)


@pytest.fixture
def world(tmp_path):
    service = make_project(tmp_path / 'project')
    place_pair(service, scratch=tmp_path)
    pipeline.run_unified(service, UnifiedOptions(isolate=False))
    vm = load_unified(request_from_service(service, extraction_configured=True))
    source = RowCodeSource()
    yield vm, source
    source.close()
    service.close()


@pytest.fixture
def code(qtbot):
    widget = UnifiedCodeView()
    qtbot.addWidget(widget)
    widget.resize(900, 500)
    widget.show()
    return widget


def row_named(vm, name):
    return next(r for r in vm.rows if name in r.function_label)


def stored_c(vm, row, older, newer):
    match = records_for(vm, [row])[row.row_id].match
    part = store.write_part(vm.result_dir, pair_text.DECOMP_PART, [
        {'side': 'older', 'rva': match.older[0].rva, 'status': 'ok', 'code': older},
        {'side': 'newer', 'rva': match.newer[0].rva, 'status': 'ok', 'code': newer}])
    return dataclasses.replace(vm, manifest=vm.manifest.model_copy(update={'parts': (*vm.manifest.parts, part)}))


def panes(code):
    return code.view.panes['older'].toPlainText(), code.view.panes['newer'].toPlainText()


def shown(old, new, opcodes, provenance=('Older: f at 0x10 | src', 'Newer: f at 0x20 | src'), **kw):
    """A decompiled channel over made-up lines, next to an unavailable disassembly."""
    pair = align_pair(old, new, opcodes)
    return RowCode(CodeChannel(pair_text.DECOMPILED, 'Decompiled on demand by Ghidra 1.2', pair, provenance, **kw),
                   unavailable(pair_text.DISASSEMBLY, 'no ir'))


def unavailable(name, reason):
    return CodeChannel(name, 'Code', reason=reason)


def copy_buttons(code):
    return {b.accessibleName(): b for b in code.view.findChildren(QPushButton) if b.text() == 'Copy'}


# ---- states -----------------------------------------------------------------------------------------------------


def test_the_initial_state_asks_for_a_row_and_disables_what_does_not_apply(code):
    assert code.status.full_text() == CODE_HINT and panes(code) == (CODE_HINT, CODE_HINT)
    assert not code.mode.isEnabled() and not code.previous_hunk.isEnabled() and not code.next_hunk.isEnabled()
    assert code.hunk_label.full_text() == 'No changes'


def test_a_message_replaces_the_code_and_resets_the_hunks(code):
    code.show_code(shown(['a', 'b'], ['a', 'c'], [('equal', 0, 1, 0, 1), ('replace', 1, 2, 1, 2)]))
    assert code.view.hunks
    code.show_message(CODE_LOADING)
    assert code.status.full_text() == CODE_LOADING and not code.view.hunks and not code.mode.isEnabled()
    assert panes(code) == (CODE_LOADING, CODE_LOADING)


def test_decompiled_c_is_the_default_when_it_exists(code, world):
    vm, source = world
    row = row_named(vm, 'get_version')
    code.show_code(source(stored_c(vm, row, 'int f(void) {\n  return 1;\n}', 'int f(void) {\n  return 2;\n}'), row))
    assert code.shown_mode() == pair_text.DECOMPILED
    older, newer = panes(code)
    assert 'return 1;' in older and 'return 2;' in newer
    assert code.status.full_text() == 'Decompiled on demand by Ghidra 12.0.4'
    assert code.mode.itemText(0) == 'Decompiled C' and code.mode.itemText(1) == 'Disassembly'


def test_without_stored_c_the_disassembly_shows_and_says_why_c_is_unavailable(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'read_item')))
    assert code.shown_mode() == pair_text.DISASSEMBLY
    status = code.status.full_text()
    assert status.startswith('Disassembly from ProgramIR (Ghidra 12.0.4); decompiled code unavailable for this pair (')
    assert pair_text.NO_DECOMP in status and code.mode.itemText(0) == 'Decompiled C (unavailable)'
    older, newer = panes(code)
    assert older.split('\n')[3] == '' and 'CALL' in newer.split('\n')[3]       # the gap of the alignment


def test_choosing_an_unavailable_mode_shows_its_reason_instead_of_code(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'read_item')))
    code.mode.setCurrentIndex(0)
    code.mode.activated.emit(0)
    assert panes(code)[0].startswith('Decompiled on demand by Ghidra 12.0.4 is unavailable: ')
    assert code.status.full_text().endswith(pair_text.NO_DECOMP) and not code.view.hunks
    code.mode.setCurrentIndex(1)
    code.mode.activated.emit(1)
    assert 'CALL' in panes(code)[1]


def test_both_modes_unavailable_shows_the_preferred_reason(code):
    code.show_code(RowCode(unavailable(pair_text.DECOMPILED, 'no text'), unavailable(pair_text.DISASSEMBLY, 'no ir')))
    assert code.shown_mode() == pair_text.DECOMPILED and 'no text' in panes(code)[0]
    assert code.mode.itemText(0).endswith('(unavailable)') and code.mode.itemText(1).endswith('(unavailable)')


def test_the_choice_of_mode_sticks_to_the_next_row_when_it_has_text(code, world):
    vm, source = world
    row = row_named(vm, 'get_version')
    both = source(stored_c(vm, row, 'a;\nb;', 'a;\nc;'), row)
    code.show_code(both)
    code.mode.setCurrentIndex(1)
    code.mode.activated.emit(1)
    code.show_code(both)
    assert code.shown_mode() == pair_text.DISASSEMBLY


def test_notes_about_the_alignment_are_stated(code, world, monkeypatch):
    vm, source = world
    monkeypatch.setattr(pair_text, 'MAX_LINES', 3)
    code.show_code(source(vm, row_named(vm, 'get_version')))
    assert pair_text.NOT_ALIGNED in code.status.full_text()


def test_one_side_without_a_function_shows_the_code_against_a_message(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'debug_dump')))
    older, newer = panes(code)
    assert 'MOV' in older and newer.startswith(pair_text.NO_FUNCTION) and len(code.view.hunks) == 1


# ---- hunk navigation ----------------------------------------------------------------------------------------------


def test_hunk_buttons_walk_the_changes_and_stop_at_both_ends(code):
    old, new = list('abcdef'), ['a', 'B', 'c', 'd', 'E', 'f']
    code.show_code(shown(old, new, [('equal', 0, 1, 0, 1), ('replace', 1, 2, 1, 2), ('equal', 2, 4, 2, 4),
                                    ('replace', 4, 5, 4, 5), ('equal', 5, 6, 5, 6)]))
    assert code.hunk_label.full_text() == '2 changes' and code.next_hunk.isEnabled()
    code.next_hunk.click()
    assert code.hunk_label.full_text() == 'Change 1 of 2' and code.view.current_hunk == 0
    code.next_hunk.click()
    assert code.hunk_label.full_text() == 'Change 2 of 2'
    code.next_hunk.click()
    assert code.hunk_label.full_text() == 'Change 2 of 2; no further change' and code.view.current_hunk == 1
    code.previous_hunk.click()
    code.previous_hunk.click()
    assert code.hunk_label.full_text() == 'Change 1 of 2; no earlier change' and code.view.current_hunk == 0


def test_an_unchanged_function_has_nothing_to_walk(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'keep_same')))
    assert code.hunk_label.full_text() == 'No changes' and not code.next_hunk.isEnabled()
    code.next_hunk.click()
    assert code.view.current_hunk == -1


# ---- provenance and copy ---------------------------------------------------------------------------------------------


def test_copy_puts_the_provenance_line_before_the_code(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'get_version')))
    buttons = copy_buttons(code)
    assert set(buttons) == {'Copy older artifact code', 'Copy newer artifact code'}
    buttons['Copy newer artifact code'].click()
    head, body = QGuiApplication.clipboard().text().split('\n\n', 1)
    assert head.startswith('Newer: get_version at 0x1700 | Disassembly from ProgramIR (Ghidra 12.0.4) | ir ')
    assert f'result {vm.result_id[:12]}' in head and body == panes(code)[1]


def test_each_side_shows_its_provenance_line(code, world):
    vm, source = world
    code.show_code(source(vm, row_named(vm, 'get_version')))
    older, newer = (label.full_text() for label in code.view._provenance.values())
    assert older.startswith('Older: get_version at 0x1600') and newer.startswith('Newer: get_version at 0x1700')


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_code_and_provenance_are_plain_text(code, text):
    code.show_code(shown([text, 'x'], ['y', text], [('replace', 0, 2, 0, 2)], (f'Older: {text}', f'Newer: {text}'),
                         notes=(text,)))
    for body in panes(code):
        assert not set(body) & set('\x00\x1b‮ ')
        if text.isprintable():
            assert text in body                                   # shown literally, never interpreted
    copy_buttons(code)['Copy older artifact code'].click()
    assert not set(QGuiApplication.clipboard().text()) & set('\x00\x1b‮')
    for label in (code.status, code.hunk_label, *code.view._provenance.values()):
        assert label.textFormat() == Qt.TextFormat.PlainText and not set(label.full_text()) & set('\x00\x1b‮')


# ---- the 100,000 line cap ---------------------------------------------------------------------------------------------


def test_a_huge_function_is_capped_with_a_notice_and_stays_responsive(code):
    lines = [f'line {n:06d}' for n in range(100_000)]
    changed = [*lines[:-1], 'last changed']
    start = time.perf_counter()
    code.show_code(shown(lines, changed, [('equal', 0, 99_999, 0, 99_999), ('replace', 99_999, 100_000, 99_999, 100_000)]))
    QApplication.processEvents()
    assert time.perf_counter() - start >= 0                                 # a bound, not a benchmark: no hang
    older, newer = panes(code)
    assert code.view.panes['older'].document().blockCount() < 100_000
    assert len(older) <= MAX_VIEW_CHARS + len(TRUNCATION_NOTICE) + 2 and older.endswith(TRUNCATION_NOTICE)
    assert newer.endswith(TRUNCATION_NOTICE) and not code.view.hunks          # the only change lies past the cut
    assert code.view._notice.isVisible()
    copy_buttons(code)['Copy older artifact code'].click()
    assert len(QGuiApplication.clipboard().text()) <= MAX_VIEW_CHARS + 400 + len(TRUNCATION_NOTICE) + 4


def test_a_hunk_inside_the_cap_is_still_navigable(code):
    lines = [f'line {n:06d}' for n in range(100_000)]
    code.show_code(shown(lines, ['changed', *lines[1:]], [('replace', 0, 1, 0, 1), ('equal', 1, 100_000, 1, 100_000)]))
    assert len(code.view.hunks) == 1
    code.next_hunk.click()
    assert code.hunk_label.full_text() == 'Change 1 of 1'


# ---- accessibility and tooltips ---------------------------------------------------------------------------------------


def test_every_control_is_named_focusable_tipped_and_plain(code):
    assert a11y_audit(code) == []
    for widget in (code.mode, code.previous_hunk, code.next_hunk, code.view.panes['older'], code.view.panes['newer'],
                   *copy_buttons(code).values()):
        assert widget.objectName().startswith('unified.code_') and 'What:' in widget.toolTip(), widget.objectName()
        assert widget.accessibleDescription() and (widget.accessibleName() or isinstance(widget, QPushButton))
    assert code.status.accessibleName() == '' and code.hunk_label.accessibleName() == ''
    assert code.mode.accessibleName() == 'Code view'
