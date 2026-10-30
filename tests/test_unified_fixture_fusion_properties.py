"""Fusion mutation-killing properties (05 s1): preserve conflicts, missing is no vote,
shared-origin counts once, native scores never decide. UNVERIFIED: not executed.

Each assertion is chosen to fail a specific plausible mutation: drop against-atoms, treat a one-sided
observation as disagreement, count sources instead of components/classes, or average native ratios.
"""
from __future__ import annotations

from collections.abc import Sequence

from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter


def atom(source: str, step: str, tier: str, cls: str, older: int | None, newer: int | None,
         native: tuple[tuple[str, str], ...] = ()) -> Atom:
    return Atom(source=source, step=step, tier=tier, cls=cls, older_rva=older, newer_rva=newer,
                cardinality="1:1", native=native)


def decide(atoms: Sequence[Atom]) -> list:
    return arbiter.decide(list(atoms), [], {})


def shape(rows: Sequence) -> list:
    return [(r.older, r.newer, r.decision, r.support, r.contest, r.hints) for r in rows]


@settings(max_examples=32, derandomize=True, deadline=None)
@given(st.integers(min_value=0, max_value=255))
def test_conflicting_weak_proposal_survives_in_the_against_atoms(offset: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    strong = atom("ghidriff", "SymbolsHash", "A", "E-NAME", old, new)
    weak = atom("rz-diff", "levenshtein-bytes", "W", "E-BODY", old, new + 8)
    rows = decide([weak, strong])
    selected = next(r for r in rows if old in r.older)
    assert selected.decision == "contested" and selected.contest.strength == "weak"
    assert weak in [selected.atoms[i] for i in selected.contest.against]
    assert shape(rows) == shape(decide([strong, weak]))


@settings(max_examples=24, derandomize=True, deadline=None)
@given(st.integers(min_value=0, max_value=255))
def test_missing_and_one_sided_observation_do_not_demote_tier_a(offset: int) -> None:
    old, new = 0x1000 + offset * 16, 0x10000 + offset * 16
    strong = atom("ghidriff", "SymbolsHash", "A", "E-NAME", old, new)
    observation = atom("rz-diff", "levenshtein-bytes", "W", "E-BODY", old, None)
    [before] = decide([strong])
    [after] = decide([observation, strong])
    assert before.decision == after.decision == "matched"
    assert before.support == after.support and after.contest is None
    assert observation in after.atoms


@settings(max_examples=24, derandomize=True, deadline=None)
@given(st.integers(min_value=1, max_value=8))
def test_many_shared_origin_atoms_cannot_become_corroboration(copies: int) -> None:
    common = [
        atom("ghidriff", "StringsRefsHasher", "B", "E-DATA", 0x1000, 0x2000),
        atom("bindiff", "prime signature matching", "B", "E-BODY", 0x1000, 0x2000),
    ]
    [row] = decide(common * copies)
    assert row.decision == "tentative"
    assert len(row.support) == 1 and row.support[0].component == "K1"


@settings(max_examples=24, derandomize=True, deadline=None)
@given(st.sampled_from(("0", "0.001", "0.5", "0.999", "1", "nan", "<b>1</b>")),
       st.sampled_from(("0", "0.001", "0.5", "0.999", "1")))
def test_score_changes_never_change_decision_support_or_contest(first: str, second: str) -> None:
    atoms = [
        atom("ghidriff", "StringsRefsHasher", "B", "E-DATA", 0x1000, 0x2000),
        atom("pt-bytes", "P08-mnemonic-seq", "B", "E-BODY", 0x1000, 0x2000),
        atom("rz-diff", "levenshtein-bytes", "W", "E-BODY", 0x1000, 0x2100),
    ]
    changed = [a.model_copy(update={"native": (("similarity", first), ("confidence", second))}) for a in atoms]
    assert shape(decide(atoms)) == shape(decide(changed))
    row = next(r for r in decide(changed) if 0x1000 in r.older)
    assert row.decision == "contested"
    assert "uncontested:matched" in row.hints


def test_different_components_still_need_different_evidence_classes() -> None:
    same = [
        atom("ghidriff", "ExactMnemonicsFunctionHasher", "B", "E-BODY", 0x1000, 0x2000),
        atom("pt-bytes", "P08-mnemonic-seq", "B", "E-BODY", 0x1000, 0x2000),
    ]
    [row] = decide(same)
    assert row.decision == "tentative"
    different = [same[0].model_copy(update={"step": "StringsRefsHasher", "cls": "E-DATA"}), same[1]]
    [row] = decide(different)
    assert row.decision == "matched"
