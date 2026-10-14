"""C6 pure evidence panel service (spec §4, §6): requests, staleness, duplicates, runs."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest
from test_evidence_view import NEW, OLD, RUN, standard_matches, standard_sets

from patchtrace.enrichment.storage import EnrichmentStore, Entry, Guard
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.evidence_panel_service import (
    Cancelled,
    EvidenceRequest,
    RunRequest,
    build_request,
    capability_view,
    detect_stale,
    execute_run,
    load_evidence,
    outcome_view,
    persist_outcome,
    probe_engines,
    run_cache,
)
from patchtrace.secondary.evidence_view import STALE_PAIR, STALE_REVISION, STALE_RUN
from patchtrace.secondary.registry import RzDiffAdapter
from patchtrace.secondary.store import current_sets
from patchtrace.service import ProjectService


def entry(match_set, created='2026-10-14T00:00:00', run_id=RUN, ident=None, stale=False):
    return Entry(ident or f'{match_set.engine}-{created}', 'secondary-matches', Guard('p1', run_id, 'r' * 64, 'x'),
                 3, 'complete', stale, created, {})


def request(sets=None, **kw):
    sets = standard_sets() if sets is None else sets
    rows = tuple((entry(s), s) for s in sets)
    base = dict(project_id='p1', run_id=RUN, revision=3, older_sha256=OLD, newer_sha256=NEW,
                matches=tuple(standard_matches()), sets=rows)
    base.update(kw)
    return EvidenceRequest(**base)


def test_load_evidence_builds_ready_model():
    vm = load_evidence(request())
    assert vm.state == 'ready' and len(vm.rows) == 4 and vm.ghidriff_run_id == RUN


def test_duplicate_sets_do_not_crash_and_warn():
    first, second = standard_sets()[0], standard_sets()[0]
    rows = ((entry(first, '2026-10-14T00:00:01', ident='new'), first),
            (entry(second, '2026-10-13T00:00:00', ident='old'), second))
    vm = load_evidence(request(sets=()).__class__(**{**request().__dict__, 'sets': rows}))
    assert vm.state == 'ready'
    assert 'Multiple stored sets for bindiff; showing the newest.' in vm.warnings


def test_inconsistent_assessment_is_failed_model(monkeypatch):
    from patchtrace.secondary import evidence_view

    def boom(reports):
        raise ValueError('secondary reports must describe the same Ghidriff match set')
    monkeypatch.setattr(evidence_view, 'assess_reports', boom)
    vm = load_evidence(request())
    assert vm.state == 'failed' and 'same Ghidriff match set' in vm.error


def test_unexpected_exception_is_failed_model_with_class_name_only(monkeypatch):
    from patchtrace.secondary import evidence_view

    def boom(*a, **k):
        raise RuntimeError('secret-token')
    monkeypatch.setattr(evidence_view, 'reconcile', boom)
    vm = load_evidence(request())
    assert vm.state == 'failed' and 'RuntimeError' in vm.error and 'secret' not in vm.error


def test_cancel_raises():
    with pytest.raises(Cancelled):
        load_evidence(request(), lambda: True)


def test_stale_reasons_each():
    vm = load_evidence(request())
    assert detect_stale(vm, 3, RUN, (OLD, NEW)) is None
    assert detect_stale(vm, 3, RUN, ('e' * 64, NEW)) == STALE_PAIR
    assert detect_stale(vm, 3, 'run-2', (OLD, NEW)) == STALE_RUN
    assert detect_stale(vm, 4, RUN, (OLD, NEW)) == STALE_REVISION
    other_run = request(sets=())
    rows = tuple((entry(s, run_id='old-run'), s) for s in standard_sets())
    stale = load_evidence(EvidenceRequest(**{**other_run.__dict__, 'sets': rows}))
    assert stale.state == 'stale' and stale.stale_reason == STALE_RUN


def test_run_request_validates_ranges(tmp_path):
    base = dict(project_id='p', revision=0, generation=1, engines=('rz-diff',), max_parallel=1, timeout_s=1800,
                older_path=tmp_path, newer_path=tmp_path, older_sha256=OLD, newer_sha256=NEW)
    RunRequest(**base)
    for bad in ({'max_parallel': 3}, {'timeout_s': 59}, {'engines': ()}):
        with pytest.raises(ValueError):
            RunRequest(**{**base, **bad})


def test_capability_and_outcome_views():
    cap = Capability(engine='rz-diff', supported=False, version='0.8', path='', supports_json=False,
                     reason='PT-SECONDARY-UNSUPPORTED: rz-diff 0.8 < 0.9.0')
    view = capability_view(cap)
    assert view.status == 'unsupported' and view.message == 'rz-diff 0.8 < 0.9.0'
    assert capability_view(cap.model_copy(update={'supported': True})) is None


class FakeRz(RzDiffAdapter):
    def __init__(self, code):
        super().__init__()
        self.code = code

    def probe(self, job_env, cancel):
        return Capability(engine='rz-diff', supported=True, version='0.9.1', path=sys.executable,
                          supports_json=True)

    def argv(self, cap, job):
        return (sys.executable, '-c', self.code)


GOOD = ('import json,sys; sys.stderr.write("<b>warn</b>\\n"); print(json.dumps([{"similarity": 0.5, '
        '"type": "PARTIAL", "original": {"addr": 16, "name": "f", "size": 1}, '
        '"modified": {"addr": 32, "name": "g", "size": 1}}]))')


def run_request(tmp_path, engines=('rz-diff',)):
    return RunRequest('p', 0, 1, engines, 1, 60, tmp_path / 'o', tmp_path / 'n', OLD, NEW, RUN)


def test_execute_run_success_and_failure_isolated(tmp_path):
    registry = {'rz-diff': FakeRz(GOOD), 'bindiff': FakeRz('import sys; sys.exit(3)')}
    registry['bindiff'].id = 'bindiff'
    events = []
    outcomes = execute_run(run_request(tmp_path, ('rz-diff', 'bindiff')), threading.Event(),
                           on_event=events.append, registry=registry, env={})
    views = [outcome_view(o) for o in outcomes]
    assert views[0].status == 'ok' and views[0].match_set is not None
    assert views[1].status == 'failed' and views[1].error_code == 'PT-SECONDARY-RUN'
    assert {e.phase for e in events} == {'started', 'finished'}


def test_execute_run_cancelled_before_start(tmp_path):
    cancel = threading.Event()
    cancel.set()
    [outcome] = execute_run(run_request(tmp_path), cancel, registry={'rz-diff': FakeRz(GOOD)}, env={})
    view = outcome_view(outcome)
    assert view.status == 'cancelled' and view.match_set is None


def test_probe_engines_isolates_raising_probe():
    class Raising(RzDiffAdapter):
        def probe(self, env, cancel):
            raise SecondaryError('PT-SECONDARY-RUN', 'x')
    found = probe_engines(threading.Event(), registry={'rz-diff': Raising()}, env={})
    assert not found['rz-diff'].supported and not found['bindiff'].supported


def test_build_request_and_persist_on_service(tmp_path):
    service = ProjectService.sample(tmp_path / 's')
    try:
        req = build_request(service, generation=5)
        assert req.generation == 5 and req.sets == () and req.run_id is not None
        assert load_evidence(req).state == 'no-engines'
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        rr = RunRequest(service.project.id, service.project.revision, 5, ('rz-diff',), 1, 60, Path('o'), Path('n'),
                        sides['older'], sides['newer'], req.run_id)
        outcomes = execute_run(RunRequest(**{**rr.__dict__, 'older_sha256': sides['older']}), threading.Event(),
                               registry={'rz-diff': FakeRz(GOOD)}, env={})
        view = outcome_view(outcomes[0])
        assert view.status == 'ok'
        assert persist_outcome(service, rr, view) is None
        assert [m.engine for _, m in current_sets(EnrichmentStore(service.store))] == ['rz-diff']
        assert run_cache(service, sides['older'], sides['newer'])
        loaded = load_evidence(build_request(service))
        assert loaded.state in ('ready', 'partial') and loaded.engine('rz-diff').state == 'ready'
        moved = RunRequest(**{**rr.__dict__, 'run_id': 'other'})
        assert persist_outcome(service, moved, view) == STALE_RUN
        wrong = RunRequest(**{**rr.__dict__, 'project_id': 'other'})
        assert persist_outcome(service, wrong, view) is not None
    finally:
        service.close()


def test_stderr_tail_is_sanitized_and_bounded(tmp_path):
    code = 'import sys; [sys.stderr.write("line\\u202e%d\\x1b\\n" % i) for i in range(5000)]; sys.exit(2)'
    [outcome] = execute_run(run_request(tmp_path), threading.Event(), registry={'rz-diff': FakeRz(code)}, env={})
    view = outcome_view(outcome)
    lines = view.stderr_tail.splitlines()
    assert len(lines) <= 200 and '‮' not in view.stderr_tail and '\x1b' not in view.stderr_tail
