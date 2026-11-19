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


@pytest.mark.parametrize(('old', 'new'), [('16', '16L'), ('2147483648L', '0x80000000L'), ('256U', '512U')])
def test_typed_literal_changes_reach_facts_without_crashing_or_erasing_type(old, new):
    from test_unified_facts import context, decided, judged, pair_match

    row = decided(0x1000, 0x1080)
    m = pair_match(f'int f(int a) {{ return a < {old}; }}', f'int f(int a) {{ return a < {new}; }}')
    facts = judged(context([m], [row]), row).facts
    assert facts.verdict == 'review'
    deltas = [d for d in facts.deltas if d.cls == 'constant']
    assert len(deltas) == 1 and deltas[0].old != deltas[0].new


def test_suffixed_value_changes_still_anchor_the_same_machine_constant_delta(tmp_path):
    from test_unified_anchors import CMP_NEW, CMP_OLD, verdict_of

    old = 'int f(int a) { if (a > 0x100U) { return 1; } return 0; }'
    new = 'int f(int a) { if (a > 0x200U) { return 1; } return 0; }'
    facts = verdict_of(tmp_path, CMP_OLD, CMP_NEW, old, new)
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')


def test_type_only_literal_swaps_do_not_anchor_an_unrelated_machine_value_change(tmp_path):
    from test_unified_anchors import CMP_NEW, CMP_OLD, verdict_of

    old = 'int f(int a) { if (a > 0x100U) { return 0x200; } return 0; }'
    new = 'int f(int a) { if (a > 0x100) { return 0x200U; } return 0; }'
    facts = verdict_of(tmp_path, CMP_OLD, CMP_NEW, old, new)
    assert (facts.verdict, facts.second_channel) == ('review', None)


def test_type_only_literal_swaps_do_not_anchor_an_unrelated_struct_offset(tmp_path):
    from test_unified_anchors import verdict_of

    old_ins = [('load_m', 'EAX', 'RBX', 0x10), ('ret',)]
    new_ins = [('load_m', 'EAX', 'RBX', 0x20), ('ret',)]
    old = 'int f(long p) { return *(int *)(p + 0x10) + 0x20U; }'
    new = 'int f(long p) { return *(int *)(p + 0x10U) + 0x20; }'
    facts = verdict_of(tmp_path, old_ins, new_ins, old, new)
    assert (facts.verdict, facts.second_channel) == ('review', None)
