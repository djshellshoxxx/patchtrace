"""SPEC-10b §10.2 (C3-6): hypothesis property tests and boundary cases. Synthetic only: not live-compat evidence.

(a) random valid messages are accepted; (b) single generic mutations give their exact reason; (c) arbitrary and
mutated bytes never raise anything but SecondaryError, within a time bound; (d) pre-scan counts equal parsed
table sizes; (e) lowering caps never turns a reject into an accept.
"""
from __future__ import annotations

import time

import pytest
from binexport_builder import SHA, raw, valid
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from patchtrace.secondary.binexport_check import check_message
from patchtrace.secondary.binexport_limits import DEFAULT_COUNTS, BinExportLimits, Budget
from patchtrace.secondary.binexport_pipeline import inspect_binexport, inspect_bytes
from patchtrace.secondary.binexport_prescan import KNOWN, prescan
from patchtrace.secondary.binexport_proto import load_binexport2_class
from patchtrace.secondary.contracts import SecondaryError

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
TINY = BinExportLimits(max_file_bytes=1 << 20, max_record_bytes=1 << 18, max_string_bytes=4096,
                       max_string_total=1 << 18, max_counts={k: min(v, 50_000) for k, v in DEFAULT_COUNTS.items()},
                       wall_seconds=5)


@st.composite
def messages(draw):
    """A random structurally valid BinExport2 (bounded sizes) built only from legal indexes."""
    m = load_binexport2_class()()
    meta = m.meta_information
    meta.executable_id = SHA
    meta.executable_name = draw(st.text(min_size=1, max_size=20).filter(lambda s: '\x00' not in s))
    meta.architecture_name = draw(st.sampled_from(['x86-64', 'x86-32', 'AARCH64-64', 'ARM-32']))
    if draw(st.booleans()):
        meta.timestamp = draw(st.integers(1, 2_000_000_000))
    for s in draw(st.lists(st.text(max_size=30), min_size=1, max_size=6)):
        m.string_table.append(s)
    for name in draw(st.lists(st.sampled_from(['mov', 'call', 'jmp', 'ret']), min_size=1, max_size=4)):
        m.mnemonic.add().name = name
    for _ in range(draw(st.integers(0, 6))):  # operand trees: each expression's parent precedes it in the operand
        size = draw(st.integers(1, 4))
        first = len(m.expression)
        ids = []
        for k in range(size):
            e = m.expression.add(type=draw(st.integers(1, 7)))
            if k:
                e.parent_index = first + draw(st.integers(0, k - 1))
            ids.append(first + k)
        m.operand.add().expression_index.extend(ids)
    n_ins = draw(st.integers(1, 30))
    for _ in range(n_ins):
        ops = draw(st.lists(st.integers(0, len(m.operand) - 1), max_size=3)) if len(m.operand) else []
        ins = m.instruction.add(mnemonic_index=draw(st.integers(0, len(m.mnemonic) - 1)), operand_index=ops)
        if draw(st.booleans()):
            ins.ClearField('mnemonic_index')  # default 0 is effective and valid
    cuts = sorted(set(draw(st.lists(st.integers(1, n_ins - 1), max_size=6)))) if n_ins > 1 else []
    bounds = [0, *cuts, n_ins]
    for b, e in zip(bounds, bounds[1:], strict=False):
        r = m.basic_block.add().instruction_index.add(begin_index=b)
        if e != b + 1 or draw(st.booleans()):
            r.end_index = e
    n_bb = len(m.basic_block)
    gcuts = sorted(set(draw(st.lists(st.integers(1, n_bb - 1), max_size=3)))) if n_bb > 1 else []
    groups = [list(range(a, b)) for a, b in zip([0, *gcuts], [*gcuts, n_bb], strict=False)]
    addresses = sorted(draw(st.sets(st.integers(0, 2**64 - 1), min_size=len(groups), max_size=len(groups))))
    for g, addr in zip(groups, addresses, strict=True):
        fg = m.flow_graph.add(entry_basic_block_index=g[0])
        fg.basic_block_index.extend(g)
        for _ in range(draw(st.integers(0, 3))):
            fg.edge.add(source_basic_block_index=draw(st.sampled_from(g)), target_basic_block_index=draw(st.sampled_from(g)))
        m.call_graph.vertex.add(address=addr, type=draw(st.integers(0, 4)))
    nv = len(m.call_graph.vertex)
    for _ in range(draw(st.integers(0, 4))):
        m.call_graph.edge.add(source_vertex_index=draw(st.integers(0, nv - 1)),
                              target_vertex_index=draw(st.integers(0, nv - 1)))
    with_ops = [i for i, ins in enumerate(m.instruction) if len(ins.operand_index)]
    for _ in range(draw(st.integers(0, 3)) if with_ops else 0):
        i = draw(st.sampled_from(with_ops))
        op = draw(st.integers(0, len(m.instruction[i].operand_index) - 1))
        ex = draw(st.integers(0, len(m.operand[m.instruction[i].operand_index[op]].expression_index) - 1))
        target = draw(st.sampled_from([m.string_reference, m.expression_substitution]))
        target.add(instruction_index=i, instruction_operand_index=op, operand_expression_index=ex,
                   string_table_index=draw(st.integers(0, len(m.string_table) - 1)))
    for _ in range(draw(st.integers(0, 2))):
        m.comment.add(string_table_index=draw(st.integers(0, len(m.string_table) - 1)))
        m.data_reference.add(instruction_index=draw(st.integers(0, n_ins - 1)), address=draw(st.integers(0, 2**64 - 1)))
    for _ in range(draw(st.integers(0, 2))):
        size = draw(st.integers(0, 2**32))
        m.section.add(address=draw(st.integers(0, 2**64 - 1 - size)), size=size)
    return m


@FAST
@given(messages())
def test_random_valid_messages_accepted_and_wire_agrees(m):
    data = raw(m)
    stats = prescan(memoryview(data), BinExportLimits(), Budget())
    msg, report, _ = inspect_bytes(data, BinExportLimits(), Budget())
    for number, name in KNOWN.items():
        if number not in (1, 8):
            assert stats.counts.get(number, 0) == len(getattr(msg, name))  # (d)
    assert report.vertex_addresses == tuple(v.address for v in m.call_graph.vertex)
    assert list(report.vertex_addresses) == sorted(set(report.vertex_addresses))


def _dup_vertex(m):
    assume(len(m.call_graph.vertex) >= 2)
    m.call_graph.vertex[-1].address = m.call_graph.vertex[-2].address


def _self_parent(m):
    assume(len(m.expression) >= 1)
    m.expression[-1].parent_index = len(m.expression) - 1


def _range_past_end(m):
    m.basic_block[-1].instruction_index[0].end_index = len(m.instruction) + 1


def _drop_name(m):
    m.meta_information.executable_name = ''


def _edge_outside(m):
    assume(len(m.flow_graph) >= 2)
    m.flow_graph[0].edge.add(source_basic_block_index=m.flow_graph[0].basic_block_index[0],
                             target_basic_block_index=m.flow_graph[1].basic_block_index[0])


def _mnemonic_oob(m):
    m.instruction[0].mnemonic_index = len(m.mnemonic)


GENERIC = {'vertex_unsorted_or_duplicate': _dup_vertex, 'self_parent': _self_parent, 'range_invalid': _range_past_end,
           'meta_field_empty': _drop_name, 'edge_endpoint_not_in_graph': _edge_outside,
           'index_oob:instruction.mnemonic': _mnemonic_oob}


@FAST
@given(messages(), st.sampled_from(sorted(GENERIC)))
def test_single_generic_mutation_gives_its_reason(m, reason):
    GENERIC[reason](m)
    with pytest.raises(SecondaryError) as info:
        check_message(load_binexport2_class().FromString(raw(m)), BinExportLimits(), Budget())
    assert info.value.reason == reason


def _never_crash(data: bytes) -> None:
    started = time.monotonic()
    try:
        inspect_bytes(data, TINY, Budget.for_seconds(5))
    except SecondaryError as exc:
        assert exc.code.startswith('PT-SECONDARY-') and exc.reason and len(exc.message) <= 200
    assert time.monotonic() - started < 5


@settings(deadline=None, max_examples=2000, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_crash(data):
    _never_crash(data)


SEED = raw(valid(functions=3))


@settings(deadline=None, max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.tuples(st.integers(0, len(SEED) - 1), st.integers(0, 255)), min_size=1, max_size=8),
       st.integers(0, len(SEED)), st.integers(0, len(SEED)), st.binary(max_size=64))
def test_flipped_truncated_spliced_valid_files_never_crash(flips, cut, splice_at, insert):
    data = bytearray(SEED)
    for pos, value in flips:
        data[pos] = value
    _never_crash(bytes(data))
    _never_crash(SEED[:cut])
    _never_crash(SEED[:splice_at] + insert + SEED[splice_at:])


CAP_NAMES = ('max_record_bytes', 'max_string_bytes', 'max_expr_depth', 'max_operands_per_instr',
             'max_exprs_per_operand', 'max_ranges_per_block', 'coverage_factor')


@FAST
@given(messages(), st.sampled_from(CAP_NAMES), st.integers(1, 8), st.sampled_from(sorted(DEFAULT_COUNTS)),
       st.integers(0, 40))
def test_lowering_caps_never_turns_reject_into_accept(m, cap, value, table, count):
    data = raw(m)
    high = BinExportLimits(**{cap: value * 4}, max_counts={table: count * 4})
    low = BinExportLimits(**{cap: value}, max_counts={table: count})

    def accepted(limits):
        try:
            inspect_bytes(data, limits, Budget())
            return True
        except SecondaryError:
            return False
    assert not (accepted(low) and not accepted(high))


# --- boundary cases (§10.2) ---

def _reason(data: bytes, limits=TINY):
    with pytest.raises(SecondaryError) as info:
        inspect_bytes(data, limits, Budget())
    return info.value.reason


def test_boundaries_small_inputs():
    assert _reason(b'') == 'meta_missing'
    assert _reason(b'\x0a') == 'wire_truncated'
    assert _reason(b'\x0a\x03\x12\x01x') == 'callgraph_missing'
    assert _reason(b'\x0a\x00\x42\x00') == 'meta_field_empty'  # empty meta strings
    assert _reason(b'\x0a\x00\x42\x02\x0a\x00') == 'meta_field_empty'


def test_boundaries_packed_and_negative_and_uint64():
    m = valid()
    m.call_graph.vertex[-1].address = 2**64 - 1
    check_message(load_binexport2_class().FromString(raw(m)), BinExportLimits(), Budget())
    base = valid()
    del base.operand[:]
    del base.string_reference[:]
    base.comment[0].ClearField('instruction_operand_index')  # plain instruction comment, no operand
    base.comment[0].ClearField('operand_expression_index')
    for ins in base.instruction:
        del ins.operand_index[:]
    data = raw(base)
    unpacked = b'\x1a\x04\x08\x00\x08\x01'  # operand{expression_index: 0, expression_index: 1}
    packed = b'\x1a\x04\x0a\x02\x00\x01'    # same values, packed encoding
    a = load_binexport2_class().FromString(data + unpacked)
    b = load_binexport2_class().FromString(data + packed)
    assert list(a.operand[0].expression_index) == list(b.operand[0].expression_index) == [0, 1]
    for blob in (unpacked, packed):
        inspect_bytes(data + blob, BinExportLimits(), Budget())
    negative = b'\x1a\x0b\x08' + b'\xff' * 9 + b'\x01'  # expression_index -1 as a 10-byte varint
    assert _reason(data + negative, BinExportLimits()) == 'index_oob:operand.expression'


def test_boundaries_strings():
    m = valid()
    m.string_table.append('nul\x00inside is fine for string_table')
    inspect_bytes(raw(m), BinExportLimits(), Budget())
    surrogate = raw(valid()) + b'\x4a\x03\xed\xa0\x80'  # UTF-8-encoded lone surrogate
    assert _reason(surrogate, BinExportLimits()) == 'utf8_invalid'
    big = valid()
    big.string_table.append('s' * (5 << 20))
    assert _reason(raw(big), BinExportLimits()) == 'string_too_long'
    assert _reason(raw(big), BinExportLimits(max_record_bytes=1 << 20)) == 'record_too_large'


def test_boundary_empty_message_through_snapshot(tmp_path):
    p = tmp_path / 'x'
    p.write_bytes(b'\x00')
    with pytest.raises(SecondaryError) as info:
        inspect_binexport(p, tmp_path / 's', artifact_sha256=SHA, role='older', limits=TINY, budget=Budget())
    assert info.value.reason == 'wire_malformed'
