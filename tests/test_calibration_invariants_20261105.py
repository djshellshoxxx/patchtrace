"""Deterministic hand-computed metric invariants; no fitted model or live binary evidence."""
from __future__ import annotations

import itertools
import sys
from fractions import Fraction
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.calibration import metrics as M  # noqa: E402


@pytest.mark.parametrize('weights', [(1.0, 1.0, 1.0, 1.0), (1.0, 3.0, 2.0, 2.0)])
def test_equal_mass_ece_keeps_constant_score_ties_in_one_label_free_bin(weights):
    probabilities = [0.5] * 4
    labels = [1, 1, 0, 0]
    for order in itertools.permutations(range(4)):
        value = M.ece_equal_mass([probabilities[i] for i in order], [labels[i] for i in order],
                                 [weights[i] for i in order], bins=2)
        assert value == pytest.approx(0.0)


def test_equal_mass_tied_metrics_match_integer_weight_replication_and_permutations():
    probabilities = [0.2, 0.5, 0.5, 0.9]
    labels = [0, 1, 0, 1]
    weights = [2, 1, 2, 1]
    # Three whole tie bins: weighted absolute residuals .4, .5 and .1 over total weight 6.
    expected = 1 / 6
    for order in itertools.permutations(range(4)):
        assert M.ece_equal_mass([probabilities[i] for i in order], [labels[i] for i in order],
                                [weights[i] for i in order], bins=3) == pytest.approx(expected)
    replicated = [(p, y) for p, y, w in zip(probabilities, labels, weights, strict=True) for _ in range(w)]
    assert M.ece_equal_mass([p for p, _ in replicated], [y for _, y in replicated],
                            [1] * len(replicated), bins=3) == pytest.approx(expected)


def _pairwise_auc(probabilities, labels, weights):
    """Independent exact rational oracle: weighted correct pairwise ordering, half credit for ties."""
    positives = [i for i, label in enumerate(labels) if label]
    negatives = [i for i, label in enumerate(labels) if not label]
    denominator = sum(Fraction(weights[i]) * Fraction(weights[j]) for i in positives for j in negatives)
    if not denominator:
        return None
    numerator = sum(Fraction(weights[i]) * Fraction(weights[j])
                    * (1 if probabilities[i] > probabilities[j] else
                       Fraction(1, 2) if probabilities[i] == probabilities[j] else 0)
                    for i in positives for j in negatives)
    return float(numerator / denominator)


@pytest.mark.parametrize('probabilities', [[0.9, 0.1], [0.1, 0.9], [0.5, 0.5]])
def test_weighted_auc_does_not_erase_small_class_mass(probabilities):
    labels, weights = [1, 0], [1e16, 1.0]
    assert M.auc(probabilities, labels, weights) == pytest.approx(_pairwise_auc(probabilities, labels, weights))


def test_weighted_auc_matches_pairwise_oracle_with_mixed_ties_and_imbalanced_weights():
    probabilities = [0.9, 0.5, 0.5, 0.1]
    labels, weights = [1, 1, 0, 0], [1e16, 3, 2, 1]
    expected = _pairwise_auc(probabilities, labels, weights)
    for order in itertools.permutations(range(4)):
        assert M.auc([probabilities[i] for i in order], [labels[i] for i in order],
                     [weights[i] for i in order]) == pytest.approx(expected)


@pytest.mark.parametrize('labels', [[0, 0], [1, 1]])
def test_weighted_auc_still_reports_undefined_without_both_classes(labels):
    assert M.auc([0.1, 0.9], labels, [1e16, 1.0]) is None
