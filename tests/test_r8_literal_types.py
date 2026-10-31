"""R8-LIT-01: type-relevant C literals must not collapse into a benign pseudo-code proof.

These tests cover the canonicalizer and deterministic channel inputs. They do NOT
claim real Ghidra/Ghidriff decompiler output or end-to-end native G-U2 accuracy.
See docs/research/deep-uncertainty-r8/01-typed-literal-counterexamples.md.
"""
from __future__ import annotations

import pytest
from unified_s0_fixtures import NEW_SHA, OLD_SHA, addr_map

from patchtrace.unified.facts import pseudo
from patchtrace.unified.facts.channels import PairMap
from patchtrace.unified.limits import DEFAULT_LIMITS


@pytest.mark.parametrize(
    ("left_kind", "left", "right_kind", "right"),
    [
        ("dec", "2147483648", "dec", "2147483648U"),
        ("dec", "2147483648", "hex", "0x80000000"),
        ("float", "0.1", "float", "0.1f"),
        ("float", "0.1", "float", "0.1F"),
        ("dec", "16", "dec", "16L"),
        ("hex", "0xFFFFFFFF", "hex", "0xFFFFFFFFu"),
        ("dec", "2147483648L", "hex", "0x80000000L"),
    ],
)
def test_r8_type_relevant_spelling_is_not_erased(left_kind, left, right_kind, right):
    """The original canon/1 converted both tokens to the same value-only key."""
    assert pseudo._number(left_kind, left) != pseudo._number(right_kind, right)


def test_r8_octal_values_are_parsed_with_their_actual_base():
    assert pseudo._number("dec", "010") == pseudo._number("dec", "8")
    assert pseudo._number("dec", "0129") != pseudo._number("dec", "129")


def test_r8_same_type_suffix_variants_and_small_hex_decimal_values_remain_equal():
    assert pseudo._number("dec", "16uL") == pseudo._number("dec", "16Lu")
    assert pseudo._number("float", "0.1f") == pseudo._number("float", "0.1F")
    assert pseudo._number("hex", "0x100") == pseudo._number("dec", "256")
    assert pseudo._number("dec", "2147483647") == pseudo._number("hex", "0x7FFFFFFF")


@pytest.mark.parametrize(
    ("older_expression", "newer_expression"),
    [
        ("2147483648", "2147483648U"),
        ("2147483648", "0x80000000"),
        ("0.1f", "0.1"),
        ("010e1", "8e1"),
        ("010E+1f", "8E+1f"),
    ],
)
def test_r8_c6_tokens_and_c5_literal_sets_retain_type_relevant_edits(
    older_expression, newer_expression
):
    def canon(expression):
        source = f"int compare(int x) {{ return x < {expression}; }}"
        return pseudo.canonicalize(
            source,
            "older",
            PairMap.from_pairs(OLD_SHA, NEW_SHA, ()),
            addr_map(),
            "va",
            DEFAULT_LIMITS,
        )

    old, new = canon(older_expression), canon(newer_expression)
    assert old.tokens != new.tokens
    assert old.numbers != new.numbers


def test_r8_small_equivalent_integer_spellings_remain_compatible():
    def canon(expression):
        return pseudo.canonicalize(
            f"int compare(int x) {{ return x < {expression}; }}",
            "older",
            PairMap.from_pairs(OLD_SHA, NEW_SHA, ()),
            addr_map(),
            "va",
            DEFAULT_LIMITS,
        )

    assert canon("0x100").tokens == canon("256").tokens
    assert canon("010").tokens == canon("8").tokens


def test_r8_unparseable_numeric_text_cannot_collide_by_truncated_prefix():
    """Python's bounded int parser rejects huge numerals; fallback must retain whole-text identity."""
    a, b = "9" * 5000 + "1", "9" * 5000 + "2"
    assert a[:40] == b[:40] and a != b
    assert pseudo._number("dec", a) != pseudo._number("dec", b)
    # Invalid octal literals also take the conservative unknown-text path.
    a, b = "0" + "7" * 50 + "8", "0" + "7" * 50 + "9"
    assert pseudo._number("dec", a) != pseudo._number("dec", b)


def test_reconciled_semantic_versions_each_invalidate_cached_results():
    from dataclasses import replace

    from patchtrace.unified.compute import compute_config_digest
    from patchtrace.unified.registry import REGISTRY

    current = compute_config_digest(REGISTRY)
    old_canon = replace(REGISTRY, channel_versions=tuple(
        (name, 1 if name == 'canon' else version) for name, version in REGISTRY.channel_versions))
    old_proof = replace(REGISTRY, proof_versions=tuple(
        (name, 1 if name == 'COS-PSEUDO/1' else version) for name, version in REGISTRY.proof_versions))
    assert len({current, compute_config_digest(old_canon), compute_config_digest(old_proof)}) == 3
