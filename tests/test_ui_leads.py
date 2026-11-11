# ruff: noqa: F811
"""PIL-C2 Leads dock: every state, hostile text, names and keys, anchors, actions and threads (offscreen Qt).

Docs: docs/specs/program-e/PIL-integration-plan.md s8 "GUI", "States", "Offscreen tests". The controller is driven through fake
panel ports that record what it did; the tests that need the project database use the sample project."""
from __future__ import annotations

import dataclasses
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from leads_support import (
    HOSTILE,
    FakeProject,
    lead_of,
    make_context,
    no_collect,
    no_matches,
    no_publish,
    no_rank,
    real_assessment,
    sample_assessment,
    stored_of,
)
from pilot_localize_support import CVE_A, CVE_B
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication
from qt_support import (  # noqa: F401
    a11y_audit,
    assert_lazy_model,
    join_gui_threads,
    main_window,
    settings,
    top_level_windows,
)

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.qt.table import VirtualTableModel
from patchtrace.gui.table_spec import prepare_table
from patchtrace.panel_manifest import MANIFEST
from patchtrace.pilot import contracts as c
from patchtrace.pilot import read_model as rm
from patchtrace.pilot import review, store
from patchtrace.pilot.limits import PilotError
from patchtrace.pilot.panel import PANEL
from patchtrace.service import ProjectService
from patchtrace.ui_leads import LEAD_COLUMNS, LEAD_SPEC, LeadsController, Stored


@pytest.fixture(scope='module')
def assessment():
    return sample_assessment()


def audit(widget) -> list[str]:
    """The shared audit, minus the table header focus that every Qt table view has (as the shared table test does)."""
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and controller.progress is None, timeout=5000)
    QApplication.processEvents()


def start(qtbot, assessment, *, state='current', changed=(), project=None, loader=None, resolver=no_matches,
          collector=no_collect, ranker=no_rank, publisher=no_publish, ask=None, show=True):
    project = project or FakeProject()
    ctx, nav, shell = make_context(project)
    stored = stored_of(assessment, state, changed)
    controller = LeadsController(ctx, loader=loader or (lambda _s, _p: stored), collector=collector, ranker=ranker,
                                 publisher=publisher, resolver=resolver, ask=ask)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1100, 700)
    if show:
        controller.panel.show()
    controller.project_changed(project.key())
    settle(qtbot, controller)
    return controller, nav, shell, project


def texts(controller) -> tuple[str, str]:
    return controller.panel.headline.full_text(), controller.panel.banners.full_text()


def row_names(controller) -> list[str]:
    model = controller.panel.table.table_model
    return [model.texts_at(i)[1] for i in range(model.rowCount())]


def visible(controller, name: str) -> bool:
    return controller.panel.buttons[name].isVisibleTo(controller.panel)


# ---- states ------------------------------------------------------------------------------------------------------

def test_l0_without_a_project_says_to_open_one(qtbot):
    controller, *_ = start(qtbot, None, project=FakeProject(open=False))
    assert texts(controller)[0] == 'Open a project to see leads.'
    assert not controller.panel.content.isVisibleTo(controller.panel)


def test_l1_without_a_comparison_result_says_to_run_the_analysis(qtbot):
    controller, *_ = start(qtbot, None, project=FakeProject(run_id=None))
    assert texts(controller)[0] == ('No comparison result yet. Run the analysis first; leads are computed from stored '
                                    'results only.')
    assert not visible(controller, 'prepare')  # nothing to prepare them from


def test_l1b_with_a_run_but_no_leads_offers_to_prepare_them(qtbot):
    controller, *_ = start(qtbot, None)
    assert texts(controller)[0].startswith('No leads have been prepared for this comparison yet.')
    assert visible(controller, 'prepare') and controller.panel.buttons['prepare'].isEnabled()


def test_l2_shows_progress_with_cancel_until_the_first_table(qtbot):
    gate, started = threading.Event(), threading.Event()

    def slow(_collected, _token, report):
        report('ranking', 1, 3)
        started.set()
        gate.wait(5)
        return None
    controller, *_ = start(qtbot, None, ranker=slow)
    try:
        controller.panel.buttons['prepare'].click()
        assert texts(controller)[0] == 'Preparing leads: collecting evidence 0/3'
        qtbot.waitUntil(started.is_set, timeout=5000)
        qtbot.waitUntil(lambda: texts(controller)[0] == 'Preparing leads: ranking 1/3', timeout=5000)
        assert visible(controller, 'cancel') and not controller.panel.content.isVisibleTo(controller.panel)
    finally:
        gate.set()
    settle(qtbot, controller)


def test_l3_is_the_table_and_the_detail_for_the_first_cve(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    assert controller.panel.content.isVisibleTo(controller.panel)
    assert controller.cve == CVE_A and controller.panel.table.table_model.rowCount() == 4
    assert row_names(controller)[0].startswith('read_item')
    assert controller.panel.context.currentData() == CVE_A


def test_l4_banner_names_channels_without_hiding_the_table(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    banner = texts(controller)[1]
    assert banner.startswith('Some evidence was not available: ') and 'Capa (not run)' in banner
    assert controller.panel.content.isVisibleTo(controller.panel) and controller.presentation.state == 'L4'


def test_l5_names_the_code_and_keeps_the_earlier_leads_then_retry_recovers(qtbot, assessment):
    answers = [stored_of(assessment), PilotError('PT-PILOT-STORAGE', 'The project could not be read'), stored_of(assessment)]

    def loader(_service, _project):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    controller, _nav, shell, _project = start(qtbot, assessment, loader=loader)
    controller.reload()
    settle(qtbot, controller)
    assert controller.presentation.state == 'L5'
    assert texts(controller)[1].startswith('Leads could not be prepared: PT-PILOT-STORAGE: The project could not be read. '
                                           'The stored comparison and earlier leads are unchanged.')
    assert controller.panel.table.table_model.rowCount() == 4  # the earlier table stays
    assert visible(controller, 'retry') and visible(controller, 'copy_details')
    controller.panel.buttons['copy_details'].click()
    assert shell.copied[-1] == 'PT-PILOT-STORAGE: The project could not be read'
    assert shell.announced[-1][1] is True  # an error is announced assertively
    controller.panel.buttons['retry'].click()
    settle(qtbot, controller)
    assert controller.presentation.state != 'L5'


def test_l5_without_any_table_replaces_the_content(qtbot):
    def failing(_s, _p):
        raise PilotError('PT-PILOT-INTEGRITY', 'It does not verify')
    controller, *_ = start(qtbot, None, loader=failing)
    assert controller.presentation.state == 'L5' and not controller.panel.content.isVisibleTo(controller.panel)


def test_l6_names_the_changed_input_and_refresh_reloads(qtbot, assessment):
    controller, *_ = start(qtbot, assessment, state='stale', changed=('raw_sha256',))
    assert texts(controller)[1].splitlines()[0] == ('These leads are out of date: the Ghidriff output. They are shown for '
                                                    'reference only.')
    assert controller.presentation.state == 'L6' and visible(controller, 'refresh')


def test_l7_says_that_no_advisory_is_loaded(qtbot, assessment):
    controller, *_ = start(qtbot, assessment.model_copy(update={'cves': ()}))
    assert rm.L7 in texts(controller)[1] and controller.panel.context.currentText() == rm.NO_ADVISORY


def test_l8_says_to_narrow_the_filter(qtbot, assessment, monkeypatch):
    monkeypatch.setattr('patchtrace.gui.table_spec.MAX_ROWS', 2)
    controller, *_ = start(qtbot, assessment)
    assert 'Too many rows to display (4). Narrow the filter.' in texts(controller)[1]
    assert controller.panel.table.too_large and controller.panel.table.table_model.rowCount() == 0


@pytest.mark.parametrize('cve, gate, fragment', [
    (CVE_B, 'unverified', 'could not be tied to these builds'),
    (CVE_B, 'conflict', 'conflicts with itself or with the build order'),
    (CVE_B, 'not-applicable', 'No leads are produced for it'),
], ids=['unverified', 'conflict', 'not-applicable'])
def test_gate_banners_follow_the_chosen_context(qtbot, cve, gate, fragment):
    controller, *_ = start(qtbot, sample_assessment(gate_b=gate))
    controller.panel.context.setCurrentIndex(controller.panel.context.findData(cve))
    settle(qtbot, controller)
    assert fragment in texts(controller)[1]
    assert (controller.panel.table.table_model.rowCount() == 0) is (gate == 'not-applicable')


def test_the_window_text_names_how_many_cves_are_fixed(qtbot, assessment):
    window = c.Confounding(state='yes', cves=(CVE_A, CVE_B))
    both = assessment.model_copy(update={'cves': tuple(x.model_copy(update={'confounding': window})
                                                        for x in assessment.cves)})
    controller, *_ = start(qtbot, both)
    assert 'The advisory lists 2 CVEs fixed in this build.' in texts(controller)[1]


# ---- the table, the filters and the detail --------------------------------------------------------------------------

def test_context_combo_lists_kev_first_and_code_only_last(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    combo = controller.panel.context
    assert [combo.itemData(i) for i in range(combo.count())] == [CVE_A, CVE_B, '']
    assert combo.itemText(0).startswith(f'{CVE_A}  KEV, 3 fit, 1 review')


def test_class_filter_and_search_narrow_the_rows(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    controller.panel.filter.setCurrentIndex(controller.panel.filter.findData('review'))
    settle(qtbot, controller)
    assert len(row_names(controller)) == 1
    controller.panel.filter.setCurrentIndex(0)
    settle(qtbot, controller)
    controller.panel.search.setText('get_version')
    assert len(row_names(controller)) == 1 and row_names(controller)[0].startswith('get_version')
    controller.panel.search.setText('0x2000c0')  # an address finds the function too
    assert len(row_names(controller)) == 1
    controller.panel.search.setText('')
    assert len(row_names(controller)) == 4


def test_the_selected_lead_fills_the_detail_and_the_evidence(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    detail = controller.panel.detail.toPlainText()
    assert detail.startswith('Summary') and detail.rstrip().endswith(rm.FOOTER)
    assert controller.panel.observations.table_model.rowCount() > 0
    assert controller.panel.buttons['copy'].isEnabled() and controller.panel.buttons['pin'].isEnabled()


def test_hostile_text_is_shown_as_text_everywhere(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    model = controller.panel.table.table_model
    row = next(i for i in range(model.rowCount()) if HOSTILE.split()[0] in model.texts_at(i)[1])
    index = model.index(row, 1)
    assert model.data(index, Qt.ItemDataRole.DisplayRole).startswith('<b>x</b>&amp;{0}%s')
    controller.select_key(model.key_at(row))
    assert '<b>x</b>' in controller.panel.detail.toPlainText()
    assert controller.panel.detail.document().toPlainText() == controller.panel.detail.toPlainText()
    assert not controller.panel.detail.document().toHtml().count('<b>x</b>')  # escaped, not markup
    assert audit(controller.panel) == []


def test_a_hostile_note_is_a_labelled_statement_not_a_finding(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    lead = lead_of(assessment, 'read_item', CVE_A)
    note = c.ReviewEvent.model_construct(candidate_key=lead.candidate_key, cve=CVE_A, action='note',
                                         text='<script>1</script>\x00\u202etext', created_utc='2099-01-02T00:00:00Z')
    controller.stored = Stored(controller.stored.loaded, {(lead.candidate_key, CVE_A): review.LeadReview(
        statements=(note,))})
    controller._build(assessment, controller.stored.reviews)
    settle(qtbot, controller)
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    detail = controller.panel.detail.toPlainText()
    assert 'Analyst statement' in detail and '<script>1</script>' in detail and '\u202e' not in detail and '\x00' not in detail


# ---- names, tooltips, windows ------------------------------------------------------------------------------------

def test_the_accessible_names_are_exactly_the_specified_ones(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    panel = controller.panel
    assert panel.table.accessibleName() == 'Ranked leads table'
    assert panel.context.accessibleName() == 'Advisory context for leads'
    assert panel.filter.accessibleName() == 'Filter leads by class'
    assert panel.search.accessibleName() == 'Search leads by function name or address'
    assert panel.detail.accessibleName() == 'Why this function: details of the selected lead'
    controller.select_key(panel.table.table_model.key_at(0))
    assert {k: b.accessibleName() for k, b in panel.buttons.items() if k in ('goto', 'copy', 'pin', 'dismiss', 'note')} == {
        'goto': 'Go to selected lead in the code panes', 'copy': 'Copy explanation of selected lead',
        'pin': 'Pin selected lead', 'dismiss': 'Dismiss selected lead', 'note': 'Add analyst note'}


def test_the_whole_panel_passes_the_accessibility_audit_in_every_state(qtbot, assessment):
    for state in (None, assessment):
        controller, *_ = start(qtbot, state)
        assert audit(controller.panel) == []
    assert all(chip.accessibleName().startswith('Channel: ') for chip in controller.panel.chips.values())


def test_every_interactive_control_has_a_tooltip_with_the_four_lines(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    panel = controller.panel
    for widget in (panel.context, panel.filter, panel.search, panel.dismissed, panel.detail, panel.table,
                   *(panel.buttons[k] for k in ('prepare', 'refresh', 'copy', 'pin', 'dismiss', 'note'))):
        tip = widget.toolTip()
        assert 'What:' in tip and 'Why:' in tip and 'Effect:' in tip, widget.objectName()
    assert 'Select a lead first.' in panel.buttons['goto'].toolTip()  # the reason, until a lead is chosen
    controller.select_key(panel.table.table_model.key_at(0))
    assert 'not tied to a row' in panel.buttons['goto'].toolTip()
    assert 'Source:' in panel.table.toolTip() and '<b>' not in panel.table.toolTip().replace('<br>', '')


def test_status_is_announced_not_only_shown(qtbot, assessment):
    _controller, _nav, shell, _project = start(qtbot, assessment)
    assert any(text.startswith('Some evidence was not available') for text, _assertive in shell.announced)


def test_the_dock_opens_no_window_of_its_own(qtbot, assessment):
    before = top_level_windows()
    controller, *_ = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    controller.panel.buttons['copy'].click()
    assert [w for w in top_level_windows() if w not in before and w is not controller.panel] == []


def test_f6_cycles_the_panes(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    panel = controller.panel
    panel.table.setFocus()
    qtbot.keyClick(panel.table, Qt.Key.Key_F6)
    assert panel.detail.hasFocus() or panel.detail.isAncestorOf(QApplication.focusWidget())
    qtbot.keyClick(panel.detail, Qt.Key.Key_F6)
    assert panel.observations.hasFocus()


# ---- the panel declaration ----------------------------------------------------------------------------------------

def test_the_panel_declaration_matches_its_manifest_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'leads'])
    assert loaded.specs['leads'] is PANEL and not loaded.errors and not loaded.forbidden
    assert (PANEL.area, PANEL.shortcut, PANEL.title) == ('left', 'Ctrl+Shift+L', 'Leads')
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'leads'] == []


def test_loading_the_declaration_imports_no_qt_and_no_feature():
    code = ('import sys, patchtrace.pilot.panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_the_panel_is_hidden_until_asked_for_and_never_steals_focus():
    assert PANEL.default_visible is False and PANEL.eager is False


def test_tooltips_and_texts_pass_the_claims_sweep():
    for tip_id, entry in PANEL.tips.items():
        assert PANEL.claims.violations(' '.join((entry.what, entry.why, entry.effect, entry.source))) == (), tip_id


# ---- performance --------------------------------------------------------------------------------------------------

def lead_rows(count: int):
    model = rm.LeadsModel(sample_assessment())
    base = model.rows(CVE_A)[0]
    return tuple(dataclasses.replace(base, key=f'k{i}') for i in range(count))


def test_data_is_called_for_what_is_visible_only(qtbot):
    source = lead_rows(100_000)
    prepared = {size: prepare_table(LEAD_SPEC, LEAD_COLUMNS, source[:size]) for size in (10_000, 100_000)}

    def factory(size: int) -> VirtualTableModel:
        model = VirtualTableModel()
        model.set_prepared(prepared[size])
        return model
    calls = assert_lazy_model(factory, sizes=(10_000, 100_000))
    assert max(calls.values()) < 20 * len(LEAD_COLUMNS) * 8


# ---- anchors -----------------------------------------------------------------------------------------------------

def test_a_cve_anchor_selects_its_context(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    result = controller.show_anchor(AnchorRef('cve', CVE_B))
    settle(qtbot, controller)
    assert result.status == 'shown' and controller.panel.context.currentData() == CVE_B and controller.cve == CVE_B


def test_an_unknown_cve_anchor_is_not_found_and_changes_nothing(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2000-0001')).status == 'not-found'
    assert controller.panel.context.currentData() == CVE_A


def test_a_match_anchor_selects_the_lead_tied_to_that_row(qtbot, assessment):
    lead = lead_of(assessment, 'copy_block', CVE_A)
    controller, *_ = start(qtbot, assessment, resolver=lambda _r, _s, _t: {lead.candidate_key: 'match-7'})
    assert controller.show_anchor(AnchorRef('match', 'match-7')).status == 'shown'
    assert controller.panel.table.current_key() == f'{CVE_A}|{lead.candidate_key}'
    assert controller.show_anchor(AnchorRef('match', 'match-9')).status == 'not-found'


def test_anchors_the_panel_does_not_open_are_blocked_with_a_reason(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    result = controller.show_anchor(AnchorRef('string', 'abc'))
    assert result.status == 'blocked' and 'string' in result.message


def test_anchors_declared_in_and_out_are_real_kinds_and_handled(qtbot):
    from patchtrace.gui.anchors import ANCHOR_KINDS
    assert PANEL.anchors_in <= set(ANCHOR_KINDS) and PANEL.anchors_out <= set(ANCHOR_KINDS)
    assert {'cve', 'match'} == PANEL.anchors_in


def test_evidence_with_an_anchor_but_no_location_emits_that_anchor(qtbot, assessment):
    controller, nav, *_ = start(qtbot, assessment)
    lead = lead_of(assessment, 'read_item', CVE_A)
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    pool = controller.model.pool
    adv = next(o for o in pool.values() if o.channel == 'advisory')
    tagged = adv.model_copy(update={'anchor_ids': ('advisory_phrase:out-of-bounds read',), 'nav': None})
    pool[adv.obs_id] = tagged
    controller._open_anchor(next(o for o in controller.model.observations(controller.current_row())
                                 if o.obs_id == adv.obs_id))
    assert [(a.kind, a.key) for a in nav.anchors] == [('advisory_phrase', 'out-of-bounds read')]


def test_evidence_with_nothing_to_open_says_so_and_navigates_nowhere(qtbot, assessment):
    controller, nav, shell, _p = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    plain = controller.model.observations(controller.current_row())[0]
    controller._open_anchor(dataclasses.replace(plain, obs_id='0' * 64))
    assert nav.anchors == [] and shell.announced[-1][0] == 'This evidence has no location to open.'


# ---- go to the code ----------------------------------------------------------------------------------------------

def test_go_to_function_selects_the_comparison_row_of_the_lead(qtbot, assessment):
    lead = lead_of(assessment, 'read_item', CVE_A)
    controller, nav, *_ = start(qtbot, assessment, resolver=lambda _r, _s, _t: {lead.candidate_key: 'match-1'})
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    assert controller.panel.buttons['goto'].isEnabled()
    controller.panel.buttons['goto'].click()
    assert nav.selected == ['match-1']
    qtbot.keyClick(controller.panel.table, Qt.Key.Key_Return)
    assert nav.selected == ['match-1', 'match-1']


def test_go_to_function_is_disabled_with_its_reason_when_no_row_is_known(qtbot, assessment):
    controller, nav, shell, _p = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    button = controller.panel.buttons['goto']
    assert not button.isEnabled() and 'not tied to a row of the comparison' in button.toolTip()
    qtbot.keyClick(controller.panel.table, Qt.Key.Key_Return)
    assert nav.selected == [] and 'not tied to a row' in shell.announced[-1][0]


def test_observation_with_a_location_reveals_its_lines_only_when_the_function_is_unambiguous(qtbot, assessment):
    lead = lead_of(assessment, 'read_item', CVE_A)
    function = SimpleNamespace(id='fn-new')
    project = FakeProject()
    project.matches.append(SimpleNamespace(id='match-1', older=[function], newer=[function]))
    controller, nav, *_ = start(qtbot, assessment, project=project,
                                resolver=lambda _r, _s, _t: {lead.candidate_key: 'match-1'})
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    located = next(o for o in controller.model.observations(controller.current_row()) if o.nav is not None)
    controller._observation_activated(located.obs_id)
    assert nav.revealed == [('fn-new', located.nav.start_line, located.nav.end_line)]
    project.matches[0].newer.append(SimpleNamespace(id='fn-other'))  # ambiguous now: only the row is shown
    controller._observation_activated(located.obs_id)
    assert nav.revealed[1:] == [] and nav.selected == ['match-1']


# ---- keys ---------------------------------------------------------------------------------------------------------

def test_ctrl_c_copies_the_explanation_not_the_row(qtbot, assessment):
    controller, _nav, shell, _p = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    controller.panel.table.setFocus()
    qtbot.keyClick(controller.panel.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert shell.copied and shell.copied[-1].startswith('Summary') and shell.copied[-1].endswith(rm.FOOTER)


def test_space_moves_focus_to_the_detail(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    controller.panel.table.setFocus()
    qtbot.keyClick(controller.panel.table, Qt.Key.Key_Space)
    assert controller.panel.detail.hasFocus()


def test_navigation_keys_move_the_current_lead(qtbot, assessment):
    controller, *_ = start(qtbot, assessment)
    table = controller.panel.table
    controller.select_key(table.table_model.key_at(0))
    table.setFocus()
    for key, expected in ((Qt.Key.Key_Down, 1), (Qt.Key.Key_End, 3), (Qt.Key.Key_Home, 0)):
        qtbot.keyClick(table, key)
        assert table.currentIndex().row() == expected
    event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier)
    assert event.key() == Qt.Key.Key_Down


# ---- review events (the project database) -------------------------------------------------------------------------

@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as opened:
        yield opened


def put(service):
    assessment, config = real_assessment(service)
    enrichment = EnrichmentStore(service.store)
    store.publish(enrichment, assessment, config, current=store.current_guard(service.project, assessment.result_id))
    return assessment


def real_start(qtbot, service, **kw):
    project = FakeProject(service, run_id=service.project.runs[-1].id)
    from patchtrace.ui_leads import load_stored
    return start(qtbot, None, project=project, loader=kw.pop('loader', None) or load_stored, **kw)


def events(service) -> list[tuple[str, str]]:
    return [(e.action, e.text) for e in review.read(EnrichmentStore(service.store)).events]


def test_the_stored_result_of_a_real_project_is_listed(qtbot, service):
    put(service)
    controller, *_ = real_start(qtbot, service)
    assert controller.stored.loaded.state == 'current' and row_names(controller)[0].startswith('read_item')


def test_pin_dismiss_restore_and_note_append_events_and_never_change_the_class(qtbot, service):
    put(service)
    answers = iter(['looks like a false trail', 'my statement'])
    controller, *_ = real_start(qtbot, service, ask=lambda _t, _l: next(answers))
    key = controller.panel.table.table_model.key_at(0)
    controller.select_key(key)
    controller.panel.buttons['pin'].click()
    settle(qtbot, controller)
    assert events(service) == [('pin', '')] and controller.current_row().pinned
    assert controller.panel.buttons['pin'].accessibleName() == 'Unpin selected lead'
    controller.panel.buttons['dismiss'].click()
    settle(qtbot, controller)
    assert events(service)[-1] == ('dismiss', 'looks like a false trail')
    assert row_names(controller) == []  # hidden, not deleted
    controller.panel.dismissed.setChecked(True)
    settle(qtbot, controller)
    assert len(row_names(controller)) == 1
    controller.select_key(key)
    assert controller.panel.buttons['dismiss'].text() == 'Restore'
    controller.panel.buttons['dismiss'].click()
    settle(qtbot, controller)
    controller.panel.buttons['note'].click()
    settle(qtbot, controller)
    assert [a for a, _t in events(service)] == ['pin', 'dismiss', 'restore', 'note']
    assert 'Analyst statement' in controller.panel.detail.toPlainText()
    assert controller.current_row().lead.lead_class == 'fit'


def test_cancelling_a_prompt_stores_nothing(qtbot, service):
    put(service)
    controller, *_ = real_start(qtbot, service, ask=lambda _t, _l: None)
    controller.select_key(controller.panel.table.table_model.key_at(0))
    controller.panel.buttons['dismiss'].click()
    controller.panel.buttons['note'].click()
    assert events(service) == []


def test_a_changed_project_marks_the_stored_result_as_out_of_date(qtbot, service):
    put(service)
    controller, *_ = real_start(qtbot, service)
    stale = dataclasses.replace(controller.stored.loaded, state='stale', changed=('newer_sha256',))
    controller.stored = Stored(stale, controller.stored.reviews)
    controller._render()
    assert controller.presentation.state == 'L6'


# ---- threads ------------------------------------------------------------------------------------------------------

def test_leads_publish_runs_on_the_gui_thread(qtbot, assessment):
    seen: list[int] = []
    controller, *_ = start(qtbot, None)
    original = controller._built

    def spy(result):
        seen.append(threading.get_ident())
        original(result)
    controller._built = spy
    controller.loader = lambda _s, _p: stored_of(assessment)
    controller.reload()
    settle(qtbot, controller)
    assert seen == [threading.get_ident()]


def test_project_switch_during_compute_drops_the_result(qtbot, assessment):
    gate, started = threading.Event(), threading.Event()
    built: list[object] = []

    def slow(_collected, _token, _report):
        started.set()
        gate.wait(5)
        return None
    controller, _nav, _shell, project = start(qtbot, None, ranker=slow)
    controller.loader = lambda _s, _p: built.append(1) or stored_of(assessment)
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(started.is_set, timeout=5000)
    project.is_open = False
    controller.project_changed(None)  # the project is closed while the work runs
    gate.set()
    settle(qtbot, controller)
    assert built == [] and controller.model is None and controller.presentation.state == 'L0'


def test_close_while_computing_cancels_and_waits(qtbot):
    started, tokens = threading.Event(), []

    def waits(_collected, token, _report):
        tokens.append(token)
        started.set()
        token.wait(5)
        return None
    controller, *_ = start(qtbot, None, ranker=waits)
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.shutdown()
    qtbot.waitUntil(lambda: tokens[0].is_set(), timeout=5000)
    controller.tasks.shutdown()
    assert not controller.tasks.busy()


def test_a_failed_worker_shows_the_exception_class_only(qtbot):
    def boom(_collected, _token, _report):
        raise RuntimeError('C:\\secret\\path token=abc')
    controller, *_ = start(qtbot, None, ranker=boom)
    controller.tasks._reraise = False
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(lambda: controller.error is not None, timeout=5000)
    assert controller.error == ('PT-GUI-TASK', 'RuntimeError stopped the work')
    assert 'secret' not in ' '.join(texts(controller))


def test_a_worker_refusal_is_shown_with_its_code(qtbot):
    def refuses(_collected, _token, _report):
        raise PilotError('PT-PILOT-LIMIT', 'The candidate universe exceeds the limit')

    def cannot_collect(_service, _token):
        raise PilotError('PT-PILOT-NOTFOUND', 'No comparison result yet.')
    controller, *_ = start(qtbot, None, ranker=refuses)
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(lambda: controller.presentation.state == 'L5', timeout=5000)
    assert 'PT-PILOT-LIMIT: The candidate universe exceeds the limit.' in texts(controller)[0]
    controller, *_ = start(qtbot, None, collector=cannot_collect)
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(lambda: controller.presentation.state == 'L5', timeout=5000)
    assert 'PT-PILOT-NOTFOUND: No comparison result yet.' in texts(controller)[0]


def test_prepare_then_reload_shows_the_new_result(qtbot, assessment):
    results = [stored_of(None), stored_of(assessment)]
    controller, *_ = start(qtbot, None, loader=lambda _s, _p: results.pop(0) if len(results) > 1 else results[0])
    assert controller.presentation.state == 'L1b'
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(lambda: controller.model is not None, timeout=5000)
    settle(qtbot, controller)
    assert controller.panel.table.table_model.rowCount() == 4
    assert controller.panel.content.isVisibleTo(controller.panel)


def test_the_match_lookup_runs_off_the_gui_thread(qtbot, assessment):
    ran: list[int] = []

    def lookup(_root, _snapshot, _token):
        ran.append(threading.get_ident())
        return {}
    start(qtbot, assessment, resolver=lookup)
    assert ran and ran[0] != threading.get_ident()


# ---- the panel host and the real main window ------------------------------------------------------------------------

def test_the_host_builds_the_dock_on_the_left_with_its_name_and_shortcut(qtbot, settings):
    from host_support import make_host
    window, host = make_host(qtbot, settings, PANEL)
    before = top_level_windows()
    panel = host.show_panel('leads')
    controller = host.controller('leads')
    assert panel is not None and isinstance(controller, LeadsController)
    assert panel.dock.accessibleName() == 'Leads panel' and panel.dock.objectName() == 'leads.dock'
    assert window.dockWidgetArea(panel.dock) == Qt.DockWidgetArea.LeftDockWidgetArea
    assert host.toggle_action('leads').shortcut().toString() == 'Ctrl+Shift+L'
    assert controller.presentation.state == 'L0' and top_level_windows() == before
    assert not panel.dock.hasFocus()  # showing the dock does not steal focus


def test_main_window_hosts_the_leads_dock_over_the_sample_project(qtbot, main_window):
    panel = main_window.panels.show_panel('leads')
    controller = main_window.panels.controller('leads')
    assert panel is not None and controller is not None
    qtbot.waitUntil(lambda: controller.presentation.state in ('L1', 'L1b'), timeout=5000)
    assert controller.presentation.state == 'L1b'  # the sample has a completed run and no stored leads yet
    assessment, config = real_assessment(main_window.service)
    enrichment = EnrichmentStore(main_window.service.store)
    store.publish(enrichment, assessment, config,
                  current=store.current_guard(main_window.service.project, assessment.result_id))
    controller.reload()
    settle(qtbot, controller)
    assert row_names(controller)[0].startswith('read_item') and audit(controller.panel) == []
    controller.select_key(controller.panel.table.table_model.key_at(0))
    controller.panel.buttons['pin'].click()
    settle(qtbot, controller)
    assert [a for a, _t in events(main_window.service)] == ['pin'] and controller.current_row().pinned



# ---- the three phases and the resolver against a real project ----------------------------------------------------------

def test_collect_rank_publish_store_a_result_that_the_dock_then_lists(qtbot, service):
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.ui_leads import collect_inputs, load_stored, publish_result, rank_inputs
    steps: list[str] = []
    collected = collect_inputs(service, CancelToken())
    assessment = rank_inputs(collected, CancelToken(), lambda stage, *_a: steps.append(stage))
    publish_result(service, assessment, None)
    loaded = load_stored(service, service.project).loaded
    assert steps == ['ranking'] and loaded.state == 'current' and loaded.assessment.result_id == assessment.result_id


def test_prepare_leads_runs_end_to_end_through_the_dock(qtbot, service):
    project = FakeProject(service, run_id=service.project.runs[-1].id)
    from patchtrace.ui_leads import collect_inputs, load_stored, publish_result, rank_inputs
    controller, *_ = start(qtbot, None, project=project, loader=load_stored, collector=collect_inputs,
                           ranker=rank_inputs, publisher=publish_result)
    assert controller.presentation.state == 'L1b'
    controller.panel.buttons['prepare'].click()
    qtbot.waitUntil(lambda: controller.stored is not None and controller.stored.loaded.state == 'current', timeout=90000)
    settle(qtbot, controller)
    assert controller.error is None and controller.presentation.state in ('L3', 'L4', 'L7')


def test_a_cancelled_collection_reports_cancel_in_words(qtbot, service):
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.ui_leads import collect_inputs
    token = CancelToken()
    token.set()
    with pytest.raises(PilotError) as raised:
        collect_inputs(service, token)
    assert raised.value.code == 'PT-PILOT-CANCEL'


def test_resolve_matches_never_guesses_a_row(qtbot, service):
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.ui_leads import Snapshot, resolve_matches, snapshot_of
    found = resolve_matches(service.root, snapshot_of(service.project), CancelToken())
    assert isinstance(found, dict) and all(len(k) == 64 for k in found)
    assert resolve_matches(service.root, Snapshot((), (), None), CancelToken()) == {}
