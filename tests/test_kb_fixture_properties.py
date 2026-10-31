"""Property test for the current CVRF parser's semantic edge order invariance."""
from __future__ import annotations

import copy

import kbc_helpers as helpers
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from kbc_k1_support import import_doc, no_sockets, projection  # noqa: F401 - pytest fixture registration

pytestmark = pytest.mark.usefixtures("no_sockets")


@given(
    vulnerabilities=st.permutations((0, 1, 2)),
    products=st.permutations((0, 1, 2, 3)),
)
@settings(max_examples=24, deadline=None)
def test_cvrf_array_reordering_preserves_semantic_edges(vulnerabilities, products) -> None:
    """Array ordering may move source pointers but must not change the semantic edge projection."""
    baseline = helpers.baseline_cvrf()
    expected = projection(import_doc(copy.deepcopy(baseline)).edges)
    changed = copy.deepcopy(baseline)
    changed["vulnerabilities"] = [changed["vulnerabilities"][index] for index in vulnerabilities]
    changed["product_tree"] = [changed["product_tree"][index] for index in products]
    actual = projection(import_doc(changed).edges)
    assert actual == expected
