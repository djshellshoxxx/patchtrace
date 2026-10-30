"""Research-only R7 sliced P-code-shaped facts: synthetic tests, not native Ghidra proof."""
import pytest

from tools.research.r7.slicer import Op, Scope, SliceCancelled, slice_ops

SCOPE = Scope(artifact_sha256="a" * 64, function_rva=0x1000, ir_digest="b" * 64)


def op(uid, rva, opcode, inputs=(), output=None, controls=()):
    return Op(uid=uid, rva=rva, opcode=opcode, inputs=tuple(inputs), output=output,
              controls=tuple(controls))


def graph():
    return [
        op("a", 0x1000, "COPY", ["param:length"], "u:length"),
        op("b", 0x1002, "INT_LESS", ["u:length", "const:64"], "u:ok"),
        op("c", 0x1004, "CBRANCH", ["u:ok"]),
        op("d", 0x1006, "STORE", ["param:buffer", "u:length"], controls=["c"]),
        op("other", 0x1008, "COPY", ["param:log"], "u:log"),
    ]


def test_backward_follows_transitive_defs_and_explicit_control_edges():
    report = slice_ops(graph(), "d", SCOPE)
    assert [site[0] for site in report.sites] == ["a", "b", "c", "d"]
    assert report.scope == SCOPE
    assert report.unknowns == ("memory-alias:d",)
    assert report.boundaries == ("param:buffer", "param:length")
    assert report.status == "incomplete"


def test_unrelated_comparison_does_not_enter_slice():
    ops = [op("guard", 0x1010, "INT_LESS", ["param:other", "const:10"], "u:guard"),
           op("write", 0x1012, "STORE", ["param:buffer", "param:length"])]
    report = slice_ops(ops, "write", SCOPE)
    assert [site[0] for site in report.sites] == ["write"]


def test_forward_follows_output_uses_and_control_dependents():
    report = slice_ops(graph(), "b", SCOPE, direction="forward")
    assert [site[0] for site in report.sites] == ["b", "c", "d"]
    assert "memory-alias:d" in report.unknowns


def test_pure_arithmetic_slice_is_only_complete_within_supplied_graph():
    ops = [op("x", 0x1000, "COPY", ["param:x"], "u:x"),
           op("y", 0x1002, "INT_ADD", ["u:x", "const:1"], "u:y")]
    r = slice_ops(ops, "y", SCOPE)
    assert r.status == "bounded-within-supplied-graph"
    assert r.unknowns == ()
    assert r.boundaries == ("param:x",)


def test_missing_definition_is_exposed_and_never_assumed_constant():
    r = slice_ops([op("x", 0x1000, "INT_ADD", ["u:missing", "const:1"], "u:x")], "x", SCOPE)
    assert r.unknowns == ("missing-def:u:missing",)


def test_ambiguous_non_ssa_definition_does_not_choose_a_source():
    ops = [op("a", 0x1000, "COPY", ["const:1"], "u:x"),
           op("b", 0x1002, "COPY", ["const:2"], "u:x"),
           op("c", 0x1004, "INT_ADD", ["u:x", "const:3"], "u:y")]
    r = slice_ops(ops, "c", SCOPE)
    assert [site[0] for site in r.sites] == ["c"]
    assert r.unknowns == ("multiple-defs:u:x",)


def test_unknown_control_reference_reported_not_silently_skipped():
    r = slice_ops([op("x", 0x1000, "COPY", controls=["unlisted"])], "x", SCOPE)
    assert r.unknowns == ("missing-control:unlisted",)


def test_indirect_call_and_memory_are_explicit_unknowns():
    ops = [op("a", 0x1000, "LOAD", ["param:ptr"], "u:p"),
           op("b", 0x1002, "CALLIND", ["u:p"])]
    r = slice_ops(ops, "b", SCOPE)
    assert set(r.unknowns) == {"call-effects:b", "indirect-target:b", "memory-alias:a"}


def test_node_cap_has_frontier_and_no_completeness_claim():
    r = slice_ops(graph(), "d", SCOPE, max_nodes=2)
    assert r.truncated
    assert "node-cap" in r.unknowns
    assert r.frontier
    assert len(r.sites) == 2


def test_depth_cap_keeps_limit_visible():
    r = slice_ops(graph(), "d", SCOPE, max_depth=0)
    assert r.truncated
    assert "depth-cap:d" in r.unknowns
    assert len(r.sites) == 1


def test_cycles_terminate_and_are_deterministic():
    ops = [op("x", 0x1000, "COPY", ["u:y"], "u:x"),
           op("y", 0x1002, "COPY", ["u:x"], "u:y")]
    first = slice_ops(ops, "x", SCOPE)
    second = slice_ops(list(reversed(ops)), "x", SCOPE)
    assert first == second
    assert len(first.sites) == 2


def test_duplicate_uid_fails_closed():
    with pytest.raises(ValueError, match="duplicate"):
        slice_ops([op("x", 1, "COPY"), op("x", 2, "COPY")], "x", SCOPE)


@pytest.mark.parametrize("scope", [
    lambda: Scope("invalid", 0),
    lambda: Scope("a" * 64, -1),
    lambda: Scope("a" * 64, True),
    lambda: Scope("a" * 64, 0, "F" * 64),
])
def test_bad_provenance_is_refused(scope):
    with pytest.raises(ValueError):
        scope()


@pytest.mark.parametrize("bad", [
    lambda: op("x", -1, "COPY"),
    lambda: op("x", True, "COPY"),
    lambda: op("x", 1, "call++"),
    lambda: op("x", 1, "COPY", inputs=["\x00naughty"]),
    lambda: op("x", 1, "COPY", inputs=["u:" + "a" * 200]),
])
def test_bad_operation_is_refused(bad):
    with pytest.raises(ValueError):
        bad()


def test_hard_input_and_limit_caps():
    with pytest.raises(ValueError, match="max_nodes"):
        slice_ops(graph(), "d", SCOPE, max_nodes=0)
    with pytest.raises(ValueError, match="max_depth"):
        slice_ops(graph(), "d", SCOPE, max_depth=-1)
    with pytest.raises(ValueError, match="too many"):
        slice_ops([op(str(i), i, "COPY") for i in range(4097)], "0", SCOPE)


def test_cancel_is_checked_before_work():
    with pytest.raises(SliceCancelled):
        slice_ops(graph(), "d", SCOPE, cancelled=lambda: True)


def test_missing_seed_is_refused():
    with pytest.raises(ValueError, match="seed"):
        slice_ops(graph(), "not-there", SCOPE)


def test_direction_is_checked():
    with pytest.raises(ValueError, match="direction"):
        slice_ops(graph(), "a", SCOPE, direction="sideways")


def test_iterable_input_limit_stops_consumption_before_unbounded_generator():
    def long_generator():
        for i in range(4098):
            if i > 4096:
                raise AssertionError("read beyond maximum allowed input")
            yield op(f"n{i}", i, "COPY")
    with pytest.raises(ValueError, match="too many"):
        slice_ops(long_generator(), "n0", SCOPE)


def test_indirect_decompiler_effect_and_unknown_opcode_are_declared():
    ops = [op("a", 0x1000, "MAGIC", ["param:x"], "u:x"),
           op("b", 0x1002, "INDIRECT", ["u:x"], "u:y")]
    r = slice_ops(ops, "b", SCOPE)
    assert {"unknown-op:MAGIC:a", "indirect-effect:b"} <= set(r.unknowns)


def test_known_but_unmodelled_pcode_effect_abstains():
    r = slice_ops([op('x', 0x1000, 'UNIMPLEMENTED', ['param:x'], 'u:x')], 'x', SCOPE)
    assert 'opaque-effect:x' in r.unknowns
    assert r.status == 'incomplete'
