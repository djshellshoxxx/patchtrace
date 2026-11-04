"""WB3-S7c Strings dock source choice (offscreen Qt): Auto, Built-in scan or stored FLOSS results, compared by
`strings.compose` exactly as `patchtrace strings delta --source auto` does.

Synthetic PE pairs only (bytes, never executed). Stored FLOSS evidence comes from a FAKE FLOSS executable that
prints committed output (`test_ui_strings_run.fake_floss`); no target and no real tool runs."""
from __future__ import annotations

import dataclasses
import json
import sqlite3
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from qt_support import a11y_audit, join_gui_threads  # noqa: F401
from strings_pe import synergy_pair
from test_strings_compose import API, imports_pair
from test_strings_copy import assert_no_banned
from test_ui_strings_panel import FakeNav, FakeShell, settle, status, table_texts
from test_ui_strings_run import fake_floss, make_project, tool_store

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.registry import PanelContext
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.persistence import ProjectStore
from patchtrace.service import ProjectService
from patchtrace.strings import copy
from patchtrace.strings.panel import PANEL
from patchtrace.strings.qt_panel import StringsController, load_strings
from patchtrace.strings.run_service import make_request, run_strings
from patchtrace.strings.sources import FlossEvidenceSource
from patchtrace.strings.tooltip_entries import PANEL_ONLY

SOURCE_COLUMN = 7


class ServicePort:
    """The dock's view of a real open project, as `gui.qt.host` gives it to a panel."""

    def __init__(self, service: ProjectService) -> None:
        self.service = service

    def _sides(self):
        return {a.side: a for a in self.service.project.artifacts}

    def key(self) -> ProjectKey:
        sides, project = self._sides(), self.service.project
        return ProjectKey(str(self.service.root), project.id, project.revision, None, sides['older'].sha256,
                          sides['newer'].sha256)

    def busy(self) -> bool:
        return False

    def project(self):
        return self.service.project

    def artifact_paths(self):
        sides, root = self._sides(), Path(self.service.root)
        return (root / sides['older'].relative_path, root / sides['newer'].relative_path, sides['older'].sha256,
                sides['newer'].sha256)


def start(qtbot, service, *, choice: str | None = None, loader=None) -> StringsController:
    ctx = PanelContext(PANEL, ServicePort(service), SimpleNamespace(), FakeNav(), FakeShell())
    controller = StringsController(ctx, **({'loader': loader} if loader else {}))
    qtbot.addWidget(controller.widget())
    controller.widget().resize(1100, 600)
    controller.widget().show()
    controller.project_changed(ctx.project.key())
    if choice is not None:
        choose(controller, choice)
    return controller


def choose(controller, choice: str) -> None:
    combo = controller.panel.source
    index = combo.findData(choice)
    assert index >= 0, choice
    combo.setCurrentIndex(index)


def scan(qtbot, controller) -> None:
    controller.scan()
    settle(qtbot, controller)


def store_floss(tmp_path, service, *sides: str) -> None:
    """FLOSS evidence of the fake tool for `sides`, stored as `intel-tools run --engines floss` stores it."""
    out = run_strings(make_request(service, floss=fake_floss(tmp_path, service)), threading.Event())
    assert out.state == 'ready'
    store = tool_store(service)
    for job in out.jobs:
        if job.run.side in sides:
            store.publish_run(job.run)
            store.publish_evidence(job.evidence)


def fields(change) -> tuple:
    return change['id'], change['status'], tuple(change['cues']), change['review_tier'], tuple(change['reasons'])


def cli_changes(capsys, root: Path) -> list[tuple]:
    code = cli.main(['strings', 'delta', str(root), '--source', 'auto', '--json'])
    out = capsys.readouterr().out
    assert code == 0, out[:300]
    return [fields(c) for c in json.loads(out)['result']['changes']]


def dock_changes(controller) -> list[tuple]:
    return [fields(c.model_dump(mode='json')) for c in controller.loaded.delta.changes]


def source_cells(controller) -> dict[str, str]:
    return {texts[1]: texts[SOURCE_COLUMN] for texts in table_texts(controller)}


def synthetic(tmp_path, older: bytes, newer: bytes) -> Path:
    paths = {}
    for side, data in (('older', older), ('newer', newer)):
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(data)
    service = ProjectService.create(paths['older'], paths['newer'], 'strings', tmp_path / 'case')
    root = service.root
    service.close()
    return root


# ---- parity with the CLI -----------------------------------------------------------------------------------------

@pytest.mark.parametrize('pair', ['synergy', 'imports'])
def test_dock_changes_equal_the_cli_delta(qtbot, capsys, tmp_path, pair):
    built = synergy_pair()
    root = synthetic(tmp_path, *(imports_pair() if pair == 'imports' else (built.older, built.newer)))
    expected = cli_changes(capsys, root)
    service = ProjectService.open(root)
    try:
        controller = start(qtbot, service)
        scan(qtbot, controller)
        assert controller.view.kind == 'ready' and dock_changes(controller) == expected
    finally:
        service.close()
    if pair == 'imports':
        api = next(c for c in controller.loaded.delta.changes if c.display == API)
        assert 'api-name' in api.cues  # the cue that needs the build's import table


def test_auto_with_stored_floss_on_both_sides_shows_floss_and_matches_the_cli(qtbot, capsys, tmp_path):
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        controller = start(qtbot, service)
        scan(qtbot, controller)
        assert controller.view.kind == 'ready' and table_texts(controller)
        assert set(source_cells(controller).values()) == {copy.SOURCE_LABELS['floss']}
        got = dock_changes(controller)
    finally:
        service.close()
    assert got == cli_changes(capsys, service.root)


def test_a_mixed_pair_is_harmonized_and_names_each_side(qtbot, tmp_path):
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'newer')
        controller = start(qtbot, service)
        scan(qtbot, controller)
        delta = controller.loaded.delta
        assert delta.comparable and any('different sources' in n for n in delta.basis_notes)
        by_status = {row.status: row.source for row in controller.loaded.rows}
        assert by_status['only-newer'] == copy.SOURCE_LABELS['floss']
        assert by_status['only-older'] == copy.SOURCE_LABELS['builtin-scan']
    finally:
        service.close()


def test_builtin_choice_ignores_stored_floss(qtbot, tmp_path):
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        controller = start(qtbot, service, choice='builtin')
        scan(qtbot, controller)
        assert set(source_cells(controller).values()) == {copy.SOURCE_LABELS['builtin-scan']}
    finally:
        service.close()


# ---- FLOSS chosen without stored results -------------------------------------------------------------------------

def test_floss_without_stored_results_says_so_runs_nothing_and_keeps_earlier_results(qtbot, tmp_path):
    calls = []

    def loader(request, token, report):
        calls.append(request)
        return load_strings(request, token, report)
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'newer')
        controller = start(qtbot, service, loader=loader)
        scan(qtbot, controller)
        earlier, rows = controller.loaded, table_texts(controller)
        assert len(calls) == 1 and rows
        choose(controller, 'floss')
        scan(qtbot, controller)
        assert len(calls) == 1 and controller.loaded is earlier and table_texts(controller) == rows
        assert status(controller) == copy.STATES['floss-not-stored'].format(side='older')
        assert controller.panel.table.isVisibleTo(controller.widget())
        choose(controller, 'auto')
        scan(qtbot, controller)
        assert len(calls) == 2 and controller.view.kind == 'ready'
    finally:
        service.close()


# ---- the request crosses threads without a store ----------------------------------------------------------------

FORBIDDEN = (ToolStore, EnrichmentStore, ProjectStore, ProjectService, sqlite3.Connection, sqlite3.Cursor)


def reachable(value, seen: set[int] | None = None, depth: int = 0):
    """Every object reachable from `value` through fields, attributes and containers (bounded)."""
    seen = set() if seen is None else seen
    if id(value) in seen or depth > 12 or isinstance(value, (str, bytes, int, float, bool, type(None), Path)):
        return
    seen.add(id(value))
    yield value
    if isinstance(value, dict):
        children = [*value.keys(), *value.values()]
    elif isinstance(value, (list, tuple, set, frozenset)):
        children = list(value)
    elif dataclasses.is_dataclass(value):
        children = [getattr(value, f.name) for f in dataclasses.fields(value)]
    else:
        children = list(getattr(value, '__dict__', {}).values())
        children += [getattr(value, s, None) for s in getattr(type(value), '__slots__', ())]
    for child in children:
        yield from reachable(child, seen, depth + 1)


def test_the_request_carries_paths_and_floss_sources_but_no_store(qtbot, tmp_path):
    seen = []

    def loader(request, token, report):
        seen.append(request)
        return load_strings(request, token, report)
    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        controller = start(qtbot, service, loader=loader)
        scan(qtbot, controller)
    finally:
        service.close()
    request = seen[0]
    assert isinstance(request.older_floss, FlossEvidenceSource) and isinstance(request.newer_floss,
                                                                              FlossEvidenceSource)
    assert [type(v).__name__ for v in reachable(request) if isinstance(v, FORBIDDEN)] == []
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.older_floss = None


# ---- the control -------------------------------------------------------------------------------------------------

def test_the_source_combo_is_named_tipped_and_defaults_to_auto(qtbot, tmp_path):
    service = make_project(tmp_path, 'floss-static')
    try:
        controller = start(qtbot, service)
        combo = controller.panel.source
        assert combo.currentData() == 'auto'
        assert combo.objectName() == 'strings.source' and combo.accessibleName() == 'Source'
        assert [combo.itemData(i) for i in range(combo.count())] == ['auto', 'builtin', 'floss']
        assert [combo.itemText(i) for i in range(combo.count())] == list(copy.SOURCE_CHOICES.values())
        assert combo.toolTip() and combo.accessibleDescription()
        assert [p for p in a11y_audit(controller.widget()) if p != 'QHeaderView#?: not keyboard focusable'] == []
    finally:
        service.close()


def test_the_new_wording_passes_the_banned_word_sweep():
    texts = [*copy.SOURCE_LABELS.values(), *copy.SOURCE_CHOICES.values(), copy.STATES['floss-not-stored'],
             *copy.TEACH['strings.state.floss-not-stored'], *(part for e in PANEL_ONLY.values() for part in e)]
    for text in texts:
        assert_no_banned(text)
    assert set(PANEL_ONLY) == {'strings.source'}
