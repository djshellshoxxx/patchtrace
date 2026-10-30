"""WB3 s8: strings run orchestration through a FAKE FLOSS executable (committed real output on SYNTHETIC PE pairs)
and the built-in scan. Proves consent recording, cancel, stale and project-switch handling; not tool behaviour."""
from __future__ import annotations

import os
import threading

import pytest
from intel_tools_support import fake_engine, golden
from test_intel_tools_pe import PAIRS

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.intelligence.tools import floss
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.service import ProjectService
from patchtrace.strings.run_service import is_stale, make_request, run_strings
from patchtrace.ui_strings_run import StringsRunController

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')


def make_project(tmp_path, pair: str) -> ProjectService:
    paths = {}
    for side, data in zip(('older', 'newer'), PAIRS[pair](), strict=True):
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(data)
    return ProjectService.create(paths['older'], paths['newer'], 'strings', tmp_path / 'case')


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path, 'floss-static')
    yield service
    service.close()


@pytest.fixture
def decode_project(tmp_path):
    service = make_project(tmp_path, 'floss-decode')
    yield service
    service.close()


def request(service, **kw):
    return make_request(service, **kw)


def tool_store(service) -> ToolStore:
    return ToolStore(EnrichmentStore(service.store), service.root, service.project.id, service.project.revision)


def controller_for(tasks, service, got, **kw) -> StringsRunController:
    return StringsRunController(tasks, got.append, lambda: (service.project.id, service.project.revision),
                                lambda: tool_store(service), **kw)


def fake_floss(tmp_path, service, *, extra: str = '', **config):
    pair, mode = ('floss-decode', 'deobfuscate') if config.get('deobfuscate') else ('floss-static', 'static')
    outputs = {a.sha256: golden(f'floss/{pair}-{a.side}.{mode}.json').decode() for a in service.project.artifacts}
    body = ('import hashlib, sys, time\n' + extra + 'sha = hashlib.sha256(open(ARGS[-1], "rb").read()).hexdigest()\n'
            f'sys.stdout.write({outputs!r}[sha])\n')
    return floss.FlossConfig(fake_engine(tmp_path / 'bin', 'floss', run_body=body), accept_untested=True, **config)


def test_builtin_scan_labels_rows_as_builtin_and_never_as_floss(project):
    out = run_strings(request(project), threading.Event())
    assert out.state == 'ready' and [s.side for s in out.sides] == ['newer', 'older']
    assert {s.source for s in out.sides} == {'builtin-scan'}
    assert all(len(s.table) > 0 and s.consent_sha256 is None for s in out.sides)


def test_floss_run_builds_tables_from_the_stored_evidence(tmp_path, project):
    out = run_strings(request(project, floss=fake_floss(tmp_path, project)), threading.Event())
    assert out.state == 'ready' and {s.source for s in out.sides} == {'floss'}
    assert all(s.run_id and len(s.table) > 0 and s.table.basis.parts[0].source == 'floss' for s in out.sides)


def test_emulation_without_consent_fails_and_with_consent_records_the_hash(tmp_path, decode_project):
    project = decode_project
    refused = run_strings(request(project, floss=fake_floss(tmp_path, project, deobfuscate=True)), threading.Event())
    assert (refused.state, refused.code) == ('failed', 'PT-TOOL-CONSENT')
    config = fake_floss(tmp_path, project, deobfuscate=True, consent_sha256=floss.EMULATION_CONSENT_SHA256)
    out = run_strings(request(project, floss=config), threading.Event())
    assert out.state == 'ready'
    assert {s.consent_sha256 for s in out.sides} == {floss.EMULATION_CONSENT_SHA256}
    assert {s.table.basis.parts[0].consent_sha256 for s in out.sides} == {floss.EMULATION_CONSENT_SHA256}


def test_a_failing_tool_is_a_typed_failure_with_a_bounded_message(tmp_path, project):
    config = fake_floss(tmp_path, project, extra='sys.stderr.write("x" * 5000)\nsys.exit(3)\n')
    out = run_strings(request(project, floss=config), threading.Event())
    assert out.state == 'failed' and out.code.startswith('PT-') and len(out.message) <= 300 and not out.sides


def test_staleness_compares_project_id_and_revision(project):
    req = request(project)
    assert not is_stale(req, project.project.id, project.project.revision)
    assert is_stale(req, project.project.id, project.project.revision + 1) and is_stale(req, 'other', req.revision)


def test_pre_cancelled_run_reports_cancelled(tmp_path, project):
    cancel = threading.Event()
    cancel.set()
    out = run_strings(request(project, floss=fake_floss(tmp_path, project)), cancel)
    assert out.state == 'cancelled' and not out.sides


@pytest.fixture
def tasks():
    made = TaskRunner(reraise=True)
    yield made
    assert made.shutdown(timeout=10) == []


def test_controller_persists_runs_and_delivers_one_outcome_on_the_gui_thread(qtbot, tasks, tmp_path, decode_project):
    project = decode_project
    got, threads = [], []
    controller = StringsRunController(
        tasks, lambda o: (got.append(o), threads.append(threading.current_thread())),
        lambda: (project.project.id, project.project.revision), lambda: tool_store(project))
    config = fake_floss(tmp_path, project, deobfuscate=True, consent_sha256=floss.EMULATION_CONSENT_SHA256)
    assert controller.start(request(project, floss=config)) and not controller.start(request(project))
    qtbot.waitUntil(lambda: bool(got), timeout=20000)
    assert got[0].state == 'ready' and threads == [threading.main_thread()] and not controller.running
    stored = tool_store(project).runs('floss')
    assert {r.side for r in stored} == {'older', 'newer'}
    assert {r.options.get('emulation_consent_sha256') for r in stored} == {floss.EMULATION_CONSENT_SHA256}


def test_controller_reports_stale_and_stores_nothing_when_the_project_moved_on(qtbot, tasks, tmp_path, project):
    got = []
    controller = StringsRunController(tasks, got.append, lambda: (project.project.id, project.project.revision + 1),
                                      lambda: tool_store(project))
    controller.start(request(project, floss=fake_floss(tmp_path, project)))
    qtbot.waitUntil(lambda: bool(got), timeout=20000)
    assert (got[0].state, got[0].code) == ('stale', 'PT-STR-STALE') and not tool_store(project).runs('floss')


def test_cancel_reports_cancelled_at_once_and_drops_the_late_result(qtbot, tasks, tmp_path, project):
    got = []
    controller = controller_for(tasks, project, got)
    controller.start(request(project, floss=fake_floss(tmp_path, project, extra='time.sleep(60)\n')))
    qtbot.waitUntil(lambda: tasks.busy('strings.run'), timeout=5000)
    controller.cancel()
    assert [o.state for o in got] == ['cancelled'] and not controller.running
    qtbot.waitUntil(lambda: not tasks.busy(), timeout=30000)
    assert len(got) == 1 and not tool_store(project).runs('floss')


def test_project_switch_drops_the_result_silently(qtbot, tasks, project):
    got = []
    controller = controller_for(tasks, project, got)
    controller.start(request(project))
    controller.project_changed()
    qtbot.waitUntil(lambda: not tasks.busy(), timeout=20000)
    qtbot.wait(50)
    assert got == [] and not controller.running
    assert controller.start(request(project))   # a new run on the new project starts normally
    qtbot.waitUntil(lambda: len(got) == 1, timeout=20000)
