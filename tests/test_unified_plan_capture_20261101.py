"""Captured plans have no placeholder identity; complete immutable manual inputs alone permit cache reuse."""
from __future__ import annotations

import dataclasses
import threading

import pytest
from unified_s0_fixtures import make_project

from patchtrace.unified import keys, pipeline
from patchtrace.unified.compute import plan_identity
from patchtrace.unified.limits import Budget, BudgetExhausted, UnifiedError


@pytest.fixture
def project(tmp_path):
    service = make_project(tmp_path / 'project')
    removed = next(m for m in service.project.matches if m.category == 'removed')
    added = next(m for m in service.project.matches if m.category == 'added')
    service.correct_match(removed.id, [removed.older[0].id], [added.newer[0].id], 'modified', 'synthetic correction')
    yield service
    service.close()


def watch_hash(monkeypatch):
    calls = []
    original = keys.source_content_digest

    def hashing(source, snapshot, **kwargs):
        if source == 'manual':
            calls.append(snapshot)
        return original(source, snapshot, **kwargs)

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    return calls


def test_capture_has_no_identity_and_repeated_resolve_reuses_only_completed_manual_digest(project, monkeypatch):
    calls = watch_hash(monkeypatch)
    capture = pipeline.capture_plan(project)
    assert calls == [] and capture.identity is None
    with pytest.raises(UnifiedError, match='plan-unresolved'):
        _ = capture.result_id
    first = pipeline.resolve_plan(capture)
    second = pipeline.resolve_plan(pipeline.capture_plan(project), previous=first)
    assert first.identity == second.identity and len(calls) == 1
    assert first.inputs()._manual_digest == first.identity.manual_digest
    assert first.inputs(raw_status='missing')._manual_digest == first.identity.manual_digest
    observed = plan_identity(first.inputs(raw_status='missing'), first.addr(), first.sources)
    assert observed.result_id != first.result_id and observed.manual_digest == first.identity.manual_digest
    assert first.inputs(matches=())._manual_digest is None
    assert dataclasses.replace(first).inputs()._manual_digest is None


@pytest.mark.parametrize('field,value', [('name', 'changed name'), ('code', 'return 57;'), ('address', '180001401')])
def test_changed_manual_content_never_reuses_previous_digest(project, monkeypatch, field, value):
    calls = watch_hash(monkeypatch)
    capture = pipeline.capture_plan(project)
    first = pipeline.resolve_plan(capture)
    [manual] = capture.manual
    altered = manual.model_copy(update={'older': (manual.older[0].model_copy(update={field: value}),)})
    changed = pipeline.resolve_plan(dataclasses.replace(capture, manual=(altered,)), previous=first)
    assert len(calls) == 2 and changed.result_id != first.result_id
    assert changed.identity.manual_digest != first.identity.manual_digest


def test_prior_selection_without_manual_cannot_seed_empty_digest_for_manual_evidence(project, monkeypatch):
    calls = watch_hash(monkeypatch)
    previous = pipeline.make_plan(project, sources=('ghidriff',))
    # The corrections are a key input whatever the sources (follow-up p9: correct_match reshapes the non-manual
    # matches too), so even a plan without the manual source holds the real digest, computed once; it can never seed
    # an empty one.
    digest = previous._identity_inputs._manual_digest
    assert digest not in (None, keys.manual_digest([])) and len(calls) == 1
    resolved = pipeline.resolve_plan(pipeline.capture_plan(project), previous=previous)
    assert len(calls) == 1 and resolved.identity.manual_digest == digest
    assert any(ref.source == 'manual' for ref in resolved.identity.source_refs)


def test_cancelled_resolution_publishes_no_identity_or_digest_cache(project, monkeypatch):
    capture = pipeline.capture_plan(project)
    cancel = threading.Event()
    original = keys.source_content_digest

    def hashing(*args, **kwargs):
        cancel.set()
        return original(*args, **kwargs)

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    with pytest.raises(BudgetExhausted) as rejected:
        pipeline.resolve_plan(capture, budget=Budget(cancel=cancel))
    assert rejected.value.code == 'PT-UNIFIED-CANCEL'
    assert capture.identity is None and capture._identity_inputs is None


def test_resolve_request_observes_the_original_capture_deadline(project):
    captured = pipeline.capture_request(project)
    expired = dataclasses.replace(captured, started_monotonic=-captured.timeout_s)
    with pytest.raises(BudgetExhausted) as rejected:
        pipeline.resolve_request(expired)
    assert rejected.value.code == 'PT-UNIFIED-TIMEOUT'
    assert captured.plan.identity is None and captured.plan._identity_inputs is None


def test_synchronous_run_cancels_before_identity_is_completed_or_a_run_is_published(project, monkeypatch):
    cancel = threading.Event()
    completed = []
    original = keys.source_content_digest

    def hashing(*args, **kwargs):
        cancel.set()
        digest = original(*args, **kwargs)
        completed.append(digest)
        return digest

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    with pytest.raises(BudgetExhausted) as rejected:
        pipeline.run_unified(project, pipeline.UnifiedOptions(isolate=False), cancel=cancel)
    assert rejected.value.code == 'PT-UNIFIED-CANCEL'
    assert completed == [] and pipeline.recent_runs(project) == []
