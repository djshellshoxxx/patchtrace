"""Candidate-pair request admission must reject non-text component names before index IO."""
from __future__ import annotations

import threading
from dataclasses import replace

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kb_candidate_journey_20261105 import candidate_request, seed, selected_request

from patchtrace.kbcorrelation import investigation_service, wiring
from patchtrace.kbcorrelation.investigation_service import (
    CurrentProjectInputs,
    InvestigationRequest,
    execute_request,
)
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


class _LooksLikeComponent:
    def strip(self):
        return "examplenet.sys"


class _OverridingComponent(str):
    def strip(self):
        return b"examplenet.sys"


@pytest.mark.parametrize("operation", ["candidate_pairs", "candidate_preview"])
@pytest.mark.parametrize(
    "component",
    [None, 42, b"examplenet.sys", _LooksLikeComponent(), _OverridingComponent("examplenet.sys")],
    ids=["null", "number", "bytes", "strip-capable-object", "overriding-str-subclass"],
)
def test_candidates_refuse_non_text_component_without_index_read(tmp_path, monkeypatch, component, operation):
    run, selected = seed(tmp_path)
    request = replace(candidate_request(selected), operation=operation, component_name=component)

    def unexpected_index_read(*args, **kwargs):
        raise AssertionError("bad request must never inspect the file index")

    monkeypatch.setattr(wiring.WorkspaceFileIndex, "available", unexpected_index_read)
    monkeypatch.setattr(wiring.WorkspaceFileIndex, "rows", unexpected_index_read)
    result = run(request, threading.Event())

    assert not result.success and result.error_code == "PT-KBC-INPUT"
    assert "examplenet.sys" not in result.text
    assert result.project_path is None


@pytest.mark.parametrize("operation", ["candidate_pairs", "candidate_preview"])
@pytest.mark.parametrize("with_snapshot", [False, True], ids=["no-current-inputs", "captured-current-inputs"])
def test_invalid_component_precedes_current_input_reads_and_service(tmp_path, monkeypatch, operation, with_snapshot):
    snapshot = None
    if with_snapshot:
        previous = ProjectService.sample(tmp_path / "previous")
        try:
            artifacts = {artifact.side: artifact for artifact in previous.project.artifacts}
            snapshot = CurrentProjectInputs(
                previous.project.id, previous.project.revision, previous.root,
                artifacts["older"].model_dump_json(), artifacts["newer"].model_dump_json(),
            )
        finally:
            previous.close()
    workspace = tmp_path / "unopened-workspace"
    request = InvestigationRequest(operation, workspace, component_name=None, current_inputs=snapshot)

    def unexpected_current_read(*args, **kwargs):
        raise AssertionError("invalid component must be refused before current-input verification")

    def unexpected_service(*args, **kwargs):
        raise AssertionError("invalid component must be refused before workspace service construction")

    monkeypatch.setattr(investigation_service, "_verified_current", unexpected_current_read)
    result = execute_request(request, threading.Event(), service_factory=unexpected_service)

    assert not result.success and result.error_code == "PT-KBC-INPUT"
    assert result.text == "The component basename must be text."
    assert result.project_path is None
    assert not workspace.exists()


@pytest.mark.parametrize("operation", ["candidate_pairs", "candidate_preview"])
@pytest.mark.parametrize(
    "mode, code, text",
    [
        ("cancelled", "PT-KBC-CANCEL", "The local operation was cancelled before its next commit."),
        ("product", "PT-KBC-INPUT", "Product-only mode uses a fresh local pair without KB/CVE or download requests."),
        ("binary", "PT-KBC-INPUT", "Saved-index pairing requires an explicit advisory product."),
    ],
)
def test_candidate_admission_preserves_cancellation_and_start_mode_precedence(tmp_path, operation, mode, code, text):
    request = InvestigationRequest(
        operation, tmp_path / "unopened-workspace", component_name=None,
        product_start=mode == "product", manual_pair_start=mode == "binary",
    )
    cancel = threading.Event()
    if mode == "cancelled":
        cancel.set()
    result = execute_request(request, cancel, service_factory=lambda root: object())
    assert not result.success and result.error_code == code
    assert result.text == text
    assert not request.workspace.exists()


def test_candidates_preserve_trimmed_plain_component_name(tmp_path):
    run, selected = seed(tmp_path)
    request = replace(candidate_request(selected), component_name="  examplenet.sys  ")
    result = run(request, threading.Event())
    assert result.success and result.data["component_name"] == "examplenet.sys"
    preview = run(selected_request(request, result), threading.Event())
    assert preview.success and preview.project_path is None
    assert preview.data["pair"]["pair_id"] == result.data["pairs"][0]["pair_id"]
