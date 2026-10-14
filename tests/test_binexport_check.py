"""SPEC-10b §6.5 (C3-3): structural checker - one test per taxonomy reason, real upb messages and duck types."""
from __future__ import annotations

import threading
from types import SimpleNamespace as N

import pytest
from binexport_builder import MUTATIONS, SHA, mutated, raw, valid

from patchtrace.secondary.binexport_check import check_message
from patchtrace.secondary.binexport_limits import BinExportLimits, Budget
from patchtrace.secondary.binexport_pipeline import inspect_bytes
from patchtrace.secondary.binexport_proto import load_binexport2_class
from patchtrace.secondary.contracts import SecondaryError

TIGHT = BinExportLimits(coverage_slack=0)


def failure(msg, limits=TIGHT) -> SecondaryError:
    with pytest.raises(SecondaryError) as info:
        check_message(msg, limits, Budget())
    assert len(info.value.message) <= 200
    return info.value


def test_valid_message_report():
    report = check_message(valid(functions=3), TIGHT, Budget())
    assert report.vertex_addresses == (0x140001000, 0x140001100, 0x140001200)
    assert report.vertex_types == (0, 0, 0)
    assert report.counts['vertex'] == 3 and report.counts['flow_edge'] == 3 and report.counts['call_edge'] == 2
    assert report.warnings == ()


@pytest.mark.parametrize('key', sorted(MUTATIONS))
def test_single_mutation_gives_exact_reason(key):
    """Mutation oracle (§10.2 b): exactly one mutation, exactly the named reason, on the parsed message."""
    expected = key.split('#')[0]
    msg = load_binexport2_class().FromString(raw(mutated(key)))
    error = failure(msg)
    assert error.reason == expected, (error.reason, error.message)
    assert error.code == ('PT-SECONDARY-LIMIT' if expected.startswith('count_cap') else 'PT-SECONDARY-INPUT')


def test_same_mutations_through_wire_pipeline():
    for key in MUTATIONS:
        with pytest.raises(SecondaryError) as info:
            inspect_bytes(raw(mutated(key)), TIGHT, Budget())
        assert info.value.reason == key.split('#')[0]


def test_invalid_utf8_string_reads_back_as_bytes_and_is_rejected():
    """U4 measured: upb accepts invalid UTF-8 in proto2 strings and returns bytes for them."""
    data = raw(valid()) + b'\x4a\x02\xff\xfe'  # extra string_table entry b'\xff\xfe'
    msg = load_binexport2_class().FromString(data)
    assert isinstance(msg.string_table[-1], bytes)
    assert failure(msg).reason == 'utf8_invalid'
    meta = raw(valid()) + b'\x0a\x04\x0a\x02\xff\xfe'  # merged meta: executable_name = b'\xff\xfe'
    assert failure(load_binexport2_class().FromString(meta)).reason == 'utf8_invalid'


def test_unknown_enum_reads_back_as_default():
    """Measured: an unknown proto2 enum value becomes an unknown field; the vertex type reads as NORMAL."""
    m = valid()
    vertex = b'\x08\x05\x10\x09'  # address 5, type 9
    data = raw(m) + b'\x42' + bytes([len(vertex) + 2]) + b'\x0a' + bytes([len(vertex)]) + vertex
    parsed = load_binexport2_class().FromString(data)  # merged: appends a 3rd vertex at address 5 -> disorder
    assert parsed.call_graph.vertex[-1].type == 0 and not parsed.call_graph.vertex[-1].HasField('type')


def test_meta_rules():
    m = valid()
    m.meta_information.executable_id = ''
    check_message(m, TIGHT, Budget())  # empty id is an identity question (binexport_identity), not structure
    m.meta_information.architecture_name = 'x\x00'
    assert failure(m).reason == 'meta_field_invalid'
    m = valid()
    m.meta_information.executable_name = 'n' * 4097
    assert failure(m).reason == 'meta_field_invalid'
    m = valid()
    m.ClearField('meta_information')
    assert failure(m).reason == 'meta_missing'
    m = valid()
    m.ClearField('call_graph')
    assert failure(m).reason == 'callgraph_missing'


@pytest.mark.parametrize('ts, warns', [(None, True), (0, True), (-5, True), (4_000_000_000, True), (1, False)])
def test_timestamp_warning_never_rejects(ts, warns):
    m = valid()
    if ts is None:
        m.meta_information.ClearField('timestamp')
    else:
        m.meta_information.timestamp = ts
    report = check_message(m, TIGHT, Budget(), now=1_760_000_000)
    assert ('timestamp_implausible' in report.warnings) is warns


def test_tier2_warnings():
    m = valid()
    m.flow_graph[0].basic_block_index.append(0)
    m.operand[1].expression_index.append(0)  # two roots in one operand
    m.md_index[0].address = 7
    report = check_message(m, TIGHT, Budget())
    assert set(report.warnings) == {'flow_graph_duplicate_blocks', 'operand_tree_shape', 'md_index_address_not_vertex'}


def test_count_caps_and_arity():
    assert failure(valid(functions=3), BinExportLimits(max_counts={'vertex': 2})).reason == 'count_cap:vertex'
    assert failure(valid(functions=3), BinExportLimits(max_counts={'call_edge': 1})).reason == 'count_cap:call_edge'
    assert failure(valid(functions=3), BinExportLimits(max_counts={'flow_edge': 2})).reason == 'count_cap:flow_edge'
    assert failure(valid(), BinExportLimits(max_counts={'section': 0})).reason == 'count_cap:section'
    m = valid()
    m.instruction[0].operand_index.extend([0] * 15)
    assert failure(m).reason == 'operand_arity'
    m = valid()
    m.operand[0].expression_index.extend([1] * 63)
    assert failure(m).reason == 'operand_arity'
    m = valid()
    m.instruction[0].call_target.extend(range(1025))
    assert failure(m).reason == 'call_target_arity'
    m = valid()
    m.basic_block[0].instruction_index.add(begin_index=0)
    assert failure(m, BinExportLimits(max_ranges_per_block=1)).reason == 'block_ranges_excess'


def test_string_total_and_depth_boundary():
    m = valid()
    m.string_table.extend(['y' * 1000] * 3)
    assert failure(m, BinExportLimits(max_string_total=2000)).reason == 'string_total_bytes'
    m = valid()
    first = len(m.expression)
    for k in range(64):  # exactly max depth: accepted
        e = m.expression.add(type=4)
        if k:
            e.parent_index = first + k - 1
    check_message(m, TIGHT, Budget())
    m.expression.add(type=4, parent_index=len(m.expression) - 1)
    assert failure(m).reason == 'expression_depth'


def test_long_cycle_and_out_of_range_parent():
    m = valid()
    base = len(m.expression)
    for k in range(5):
        m.expression.add(type=4, parent_index=base + (k + 1) % 5)
    assert failure(m).reason == 'expression_cycle'
    m = valid()
    m.expression[1].parent_index = -1
    assert failure(m).reason == 'index_oob:expression.parent'


def test_flow_graph_amplification_and_reference_defaults():
    m = valid()
    for _ in range(20):
        m.flow_graph[0].basic_block_index.extend([0, 1])
    assert failure(m).reason == 'coverage_amplification'
    m = valid()
    m.string_reference[0].ClearField('instruction_operand_index')  # default 0 is effective: operand 0 -> 2 exprs
    m.string_reference[0].operand_expression_index = 1
    check_message(m, TIGHT, Budget())
    m.string_reference[0].ClearField('instruction_index')
    assert failure(m).reason == 'reference_incomplete'
    m = valid()
    m.address_comment.add(instruction_index=0)  # address_comment needs no string index
    check_message(m, TIGHT, Budget())
    m.address_comment[0].instruction_operand_index = 5
    assert failure(m).reason == 'index_oob:address_comment.operand'


def test_instruction_comment_on_operandless_instruction():
    """Proto: Comment operand/expression indexes are operand-level markup; absent on a `ret` is legitimate."""
    m = valid()
    ret = m.instruction.add(mnemonic_index=1)
    m.basic_block[-1].instruction_index[0].end_index = len(m.instruction)
    m.comment.add(instruction_index=len(m.instruction) - 1, string_table_index=1, type=1)
    check_message(m, TIGHT, Budget())
    m.comment[-1].instruction_operand_index = 0  # explicit pointer to an operand that does not exist
    assert failure(m).reason == 'index_oob:comment.operand'
    m = valid()
    m.string_reference.add(instruction_index=len(m.instruction) - 1, string_table_index=0)  # strict: needs operand
    check_message(m, TIGHT, Budget())  # last instruction has an operand (default 0 resolves)
    m.instruction.add(mnemonic_index=1)
    m.basic_block[-1].instruction_index[0].end_index = len(m.instruction)
    m.string_reference.add(instruction_index=len(m.instruction) - 1, string_table_index=0)
    assert failure(m).reason == 'index_oob:string_reference.operand'
    assert ret.mnemonic_index == 1


def test_vertex_name_nul_rejected():
    m = valid()
    m.call_graph.vertex[0].demangled_name = 'f\x00g'
    assert failure(m).reason == 'name_invalid'


def test_section_boundary():
    m = valid()
    m.section[0].address, m.section[0].size = 2**64 - 0x1000, 0x1000  # ends exactly at 2**64: allowed
    check_message(m, TIGHT, Budget())


def test_budget_cancellation_inside_checker():
    cancel = threading.Event()
    cancel.set()
    m = valid(functions=9000)
    with pytest.raises(SecondaryError) as info:
        check_message(m, TIGHT, Budget(None, cancel))
    assert (info.value.code, info.value.reason) == ('PT-SECONDARY-CANCEL', 'cancelled')


def test_duck_typed_minimal_message():
    msg = N(meta_information=N(executable_id=SHA, executable_name='n', architecture_name='x86-64'),
            call_graph=N(vertex=[N(address=1, library_index=None, module_index=None)], edge=[]),
            string_table=[])
    report = check_message(msg, TIGHT, Budget(), now=0)
    assert report.vertex_addresses == (1,) and 'timestamp_implausible' in report.warnings
    msg.call_graph.vertex[0].type = 9
    assert failure(msg).reason == 'vertex_type_invalid'
    msg.call_graph.vertex[0].type = 0
    msg.string_table = ['\ud800']  # lone surrogate (possible only for duck types / pure Python)
    assert failure(msg).reason == 'utf8_invalid'
