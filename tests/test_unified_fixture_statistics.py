"""UNVERIFIED: paired-bootstrap diagnostics not executed. Pure deterministic statistical checks."""
from __future__ import annotations

import pytest
from unified_support.statistics import paired_difference, zero_event_cases


def test_pairing_preserves_covariance_and_reproducible_intervals() -> None:
    # Each lineage has a different base rate but both engines make exactly the same errors there.
    counts = {f"L{i}": (float(i), 30.0, float(i), 30.0) for i in range(30)}
    first = paired_difference(counts, seed="paired-equal")
    second = paired_difference(dict(reversed(list(counts.items()))), seed="paired-equal")
    assert first == second
    assert first["point"] == first["lo"] == first["hi"] == 0.0
    assert first["groups"] == 30 and first["anti_conservative"] is False


def test_zero_denominators_and_thin_lineages_cannot_decide() -> None:
    empty = paired_difference({}, seed="empty")
    assert empty["point"] is None and empty["undefined"] == 2000
    undefined = paired_difference({"one": (0.0, 0.0, 0.0, 0.0)}, seed="undefined")
    assert undefined["lo"] is None and undefined["hi"] is None
    assert paired_difference({"one": (1.0, 1.0, 0.0, 1.0)}, seed="thin")["anti_conservative"] is True


def test_independent_zero_event_planning_is_not_a_clustered_power_claim() -> None:
    assert zero_event_cases(0.001) == 2995
    assert zero_event_cases(0.01) == 299
    assert zero_event_cases(0.05) == 59
    for rate in (0, 1, -0.1):
        with pytest.raises(ValueError):
            zero_event_cases(rate)


def test_invalid_paired_count_vectors_are_rejected() -> None:
    for counts in ((1.0,), (-1.0, 1.0, 0.0, 1.0), (2.0, 1.0, 0.0, 1.0)):
        with pytest.raises(ValueError):
            paired_difference({"one": counts}, seed="invalid")
