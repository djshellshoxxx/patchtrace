"""Candidate-pair request admission must reject non-text component names before index IO."""
from __future__ import annotations

import threading
from dataclasses import replace

import pytest
from test_kb_candidate_journey_20261105 import candidate_request, seed

from patchtrace.kbcorrelation import wiring


class _LooksLikeComponent:
    def strip(self):
        return "examplenet.sys"


class _OverridingComponent(str):
    def strip(self):
        return b"examplenet.sys"


@pytest.mark.parametrize(
    "component",
    [None, 42, b"examplenet.sys", _LooksLikeComponent(), _OverridingComponent("examplenet.sys")],
    ids=["null", "number", "bytes", "strip-capable-object", "overriding-str-subclass"],
)
def test_candidate_pairs_refuses_non_text_component_without_index_read(tmp_path, monkeypatch, component):
    run, selected = seed(tmp_path)
    request = replace(candidate_request(selected), component_name=component)

    def unexpected_index_read(*args, **kwargs):
        raise AssertionError("bad request must never inspect the file index")

    monkeypatch.setattr(wiring.WorkspaceFileIndex, "rows", unexpected_index_read)
    result = run(request, threading.Event())

    assert not result.success and result.error_code == "PT-KBC-INPUT"
    assert "examplenet.sys" not in result.text
    assert result.project_path is None


def test_candidate_pairs_preserves_trimmed_plain_component_name(tmp_path):
    run, selected = seed(tmp_path)
    request = replace(candidate_request(selected), component_name="  examplenet.sys  ")
    result = run(request, threading.Event())
    assert result.success and result.data["component_name"] == "examplenet.sys"
