"""E1-WB1-S8b: the stored tool, advisory and CVE groups reach production search (CLI and dock) over REAL stores.

Tool rows come from FAKE capa/FLOSS executables that print committed real output captured on SYNTHETIC PE pairs, and
the advisory is the committed synthetic CSAF fixture: not live evidence. No target runs; nothing uses the network."""
from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

from intel_tools_support import fake_engine, golden
from qt_support import join_gui_threads  # noqa: F401  (autouse fixture)
from search_synergy_builders import attention, extra_specs, make_project
from test_capa_cli import stored_project
from test_intel_tools_cli import clean_env  # noqa: F401  (autouse fixture)
from test_intel_tools_pe import PAIRS

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.persistence import ProjectStore
from patchtrace.search import cli as search_cli
from patchtrace.search import wiring
from patchtrace.search.sources.tools import ENGINES, SIDES
from patchtrace.service import ProjectService

ADVISORY = Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'
NEW_ONLY = 'PatchTrace synthetic: index %u exceeds length %u'  # in the newer FLOSS golden only
TOOL_GROUPS = {f'tool:{engine}:{side}' for engine in ENGINES for side in SIDES}
STORES = (sqlite3.Connection, ProjectStore, ProjectService, EnrichmentStore, ToolStore, AdvisoryStore)


def search(capsys, root, cache, *argv):
    capsys.readouterr()
    code = cli.main(['search', str(root), '--cache-dir', str(cache), '--json', *argv])
    return code, json.loads(capsys.readouterr().out)


def evidence(doc) -> list[dict]:
    return [e for hit in doc['result']['hits'] for e in hit['evidence']]


def floss_project(tmp_path) -> Path:
    """Both FLOSS runs stored through `intel-tools run` (the fake_floss pattern of test_ui_strings_run)."""
    files = {}
    for side, data in zip(SIDES, PAIRS['floss-static'](), strict=True):
        files[side] = tmp_path / f'{side}.exe'
        files[side].write_bytes(data)
    service = ProjectService.create(files['older'], files['newer'], 'strings', tmp_path / 'case')
    outputs = {a.sha256: golden(f'floss/floss-static-{a.side}.static.json').decode() for a in service.project.artifacts}
    root = service.root
    service.close()
    body = ('import hashlib, sys\nsha = hashlib.sha256(open(ARGS[-1], "rb").read()).hexdigest()\n'
            f'sys.stdout.write({outputs!r}[sha])\n')
    exe = fake_engine(tmp_path / 'bin', 'floss', run_body=body)
    assert cli.main(['intel-tools', 'run', str(root), '--profile', 'context', '--engines', 'floss', '--floss',
                     str(exe), '--floss-accept-untested', '--json']) == 0
    return root


def rewrite_older_run(root: Path, engine: str) -> None:
    """Rewrite the stored older run in place with another configuration digest: the pair is no longer comparable."""
    service = ProjectService.open(root)
    try:
        store = ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)
        older = next(run for run in store.runs(engine) if run.side == 'older')
        store.publish_run(older.model_copy(update={'config_digest': 'f' * 64}))
    finally:
        service.close()


# ------------------------------------------------------------------------------------------------- CLI

def test_a_stored_capa_rule_is_found_in_its_tool_group(tmp_path, capsys):
    root = stored_project(tmp_path)
    code, doc = search(capsys, root, tmp_path / 'cache', '--query', 'write file', '--rebuild')
    found = [e for e in evidence(doc) if e['group'] == 'tool:capa:newer']
    assert code == 0 and [e['title'] for e in found] == ['write file on Windows']
    assert found[0]['kind'] == 'capability' and str(tmp_path) not in json.dumps(doc)


def test_status_lists_every_tool_group_and_the_advisory_groups(tmp_path, capsys):
    root = stored_project(tmp_path)
    code, doc = search(capsys, root, tmp_path / 'cache', '--status')
    rows = {row['group']: row for row in doc['result']['coverage']}
    assert code == 0 and TOOL_GROUPS | {'adv', 'cve'} <= set(rows)
    for side in SIDES:
        assert rows[f'tool:floss:{side}']['status'] == 'unavailable'
        assert rows[f'tool:floss:{side}']['reason'] == (f'No FLOSS run has produced results for the {side} build. '
                                                        'Run FLOSS to add them.')
        assert rows[f'tool:capa:{side}']['status'] == 'missing'  # stored and buildable, only not indexed yet


def test_an_imported_advisory_is_found_by_its_cve(tmp_path, capsys):
    root = stored_project(tmp_path, analysed=False)
    assert cli.main(['intelligence', 'import', str(root), str(ADVISORY), '--cve', 'CVE-2099-10001']) == 0
    code, doc = search(capsys, root, tmp_path / 'cache', '--query', 'CVE-2099-10001')
    assert code == 0 and ('adv', 'advisory') in {(e['group'], e['kind']) for e in evidence(doc)}


def test_a_newer_only_floss_string_is_absent_in_older_only_while_the_runs_are_comparable(tmp_path, capsys):
    root = floss_project(tmp_path)
    query = ('--query', 'index exceeds length', '--kind', 'string')

    def presence() -> tuple[str, str]:
        code, doc = search(capsys, root, tmp_path / 'cache', *query)
        assert code == 0
        hit = next(h for h in doc['result']['hits']
                   if any(e['group'] == 'tool:floss:newer' and e['title'] == NEW_ONLY for e in h['evidence']))
        return hit['presence']['older'], hit['presence']['newer']

    assert presence() == ('absent', 'present')
    rewrite_older_run(root, 'floss')
    assert presence()[0] == 'unknown'


def test_injected_specs_keep_their_path_and_read_no_store(tmp_path, monkeypatch):
    def refuse(*_args):
        raise AssertionError('the production sources were read although specs were injected')
    monkeypatch.setattr(wiring, 'snapshot_sources', refuse)
    service, out = make_project(tmp_path / 'project'), io.StringIO()
    code = search_cli.main(['P', '--status', '--json', '--cache-dir', str(tmp_path / 'cache')],
                           opener=lambda _path: (service, attention), extra_specs=extra_specs, stdout=out,
                           stderr=io.StringIO())
    assert code == 0 and 'tool:floss:newer' in out.getvalue()


# ---------------------------------------------------------------------------------------------- snapshot

def test_unreadable_rows_make_only_their_group_unavailable(tmp_path, monkeypatch):
    root = stored_project(tmp_path, analysed=False)
    real = ToolStore.latest

    def latest(self, engine, side):
        if (engine, side) == ('capa', 'older'):
            raise OSError('sidecar unreadable')
        return real(self, engine, side)

    def advisories(_self):
        raise IntelError('PT-INTEL-STORAGE', 'database is locked')

    monkeypatch.setattr(ToolStore, 'latest', latest)
    monkeypatch.setattr(AdvisoryStore, 'advisories', advisories)
    service = ProjectService.open(root)
    try:
        guard = Guard(service.project.id, 'cve', '0' * 64, 'cve')
        EnrichmentStore(service.store).publish('cve-snapshot', guard, guard, service.project.revision, 'complete',
                                               {'cve_id': 'not a snapshot'}, 'cve-snapshot:bad')
        snapshot = wiring.snapshot_sources(service)
    finally:
        service.close()
    specs = {spec.group: spec for spec in snapshot.extra_specs(None)}
    assert set(specs) == TOOL_GROUPS | {'adv', 'cve'}
    assert (specs['cve'].status, specs['cve'].reason) == ('unavailable', wiring.CVE_UNREADABLE.format(count=1))
    assert specs['tool:capa:older'].status == 'unavailable' and 'OSError' in specs['tool:capa:older'].reason
    assert specs['adv'].status == 'unavailable' and 'PT-INTEL-STORAGE' in specs['adv'].reason
    assert specs['tool:capa:newer'].buildable and not snapshot.comparable('capa')


def test_a_service_without_a_store_reports_every_group_unavailable(tmp_path):
    snapshot = wiring.snapshot_sources(SimpleNamespace(project=SimpleNamespace(id='p', revision=1), root=tmp_path))
    specs = snapshot.extra_specs(None)
    assert {s.group for s in specs} == TOOL_GROUPS | {'adv', 'cve'} and {s.status for s in specs} == {'unavailable'}
    assert snapshot.key is None and not snapshot.comparable('floss')


def test_a_snapshot_is_reused_until_a_stored_row_changes(tmp_path):
    root = stored_project(tmp_path, analysed=False)
    service = ProjectService.open(root)
    try:
        first = wiring.snapshot_sources(service)
        assert wiring.snapshot_sources(service, first) is first
    finally:
        service.close()
    rewrite_older_run(root, 'capa')
    service = ProjectService.open(root)
    try:
        second = wiring.snapshot_sources(service, first)
    finally:
        service.close()
    assert second is not first and first.comparable('capa') and not second.comparable('capa')


# -------------------------------------------------------------------------------------------------- dock

def reachable(value, found: dict[int, object]) -> dict[int, object]:
    """Every object reachable from `value` through dataclass fields, containers and instance attributes."""
    if id(value) in found or isinstance(value, (str, bytes, int, float, Path, type(None))):
        return found
    found[id(value)] = value
    if isinstance(value, dict):
        items = [*value.keys(), *value.values()]
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    elif hasattr(value, '__dataclass_fields__'):
        items = [getattr(value, name) for name in value.__dataclass_fields__]
    else:
        items = list(getattr(value, '__dict__', {}).values())
    for item in items:
        reachable(item, found)
    return found


def test_the_dock_loads_evidence_once_and_hands_workers_no_store(tmp_path, qtbot, monkeypatch):
    from leads_support import FakeNav, FakeProject, FakeShell
    from PySide6.QtWidgets import QApplication

    from patchtrace.gui.qt.tasks import TaskRunner
    from patchtrace.gui.registry import PanelContext
    from patchtrace.search import qt_panel
    from patchtrace.search.panel import PANEL

    root = stored_project(tmp_path)
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'appdata'))  # the dock's default cache root, outside the project
    loads, workers = [], []
    real = ToolStore.latest
    monkeypatch.setattr(ToolStore, 'latest', lambda self, engine, side: loads.append(engine) or real(self, engine, side))

    def recorded(call):
        def wrapper(service, *rest):
            workers.append(service)
            return call(service, *rest)
        return wrapper

    service = ProjectService.open(root)
    project = FakeProject(service)
    controller = PANEL.factory(PanelContext(PANEL, project, SimpleNamespace(), FakeNav(),
                                            FakeShell(TaskRunner(reraise=True))))
    try:
        assert controller.sources is wiring.snapshot_sources
        controller.searcher = recorded(qt_panel.default_search)
        controller.builder = recorded(qt_panel.default_build)
        controller.coverage = recorded(qt_panel.default_coverage)
        qtbot.addWidget(controller.panel)

        def settle():
            qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=20000)
            QApplication.processEvents()

        controller.project_changed(project.key())
        settle()
        controller.build()
        settle()
        for text in ('write file', 'write file on'):
            controller.panel.query.setText(text)
            controller.submit()
            settle()
        groups = {e.group for hit in controller.result.hits for e in hit.evidence}
    finally:
        controller.shutdown()
        service.close()
    assert 'tool:capa:newer' in groups
    assert len(loads) == len(ENGINES) * len(SIDES)  # one evidence load for the project, not one per keystroke
    assert len(workers) >= 4 and all(isinstance(w, wiring.BoundService) for w in workers)
    leaked = [type(v).__name__ for w in workers for v in reachable(w, {}).values() if isinstance(v, STORES)]
    assert leaked == []
