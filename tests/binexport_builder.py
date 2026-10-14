"""Synthetic BinExport2 messages built with the runtime class (SPEC-10b §10.1). Not live-compat evidence.

`valid(sha)` is a small but complete message touching every table; `MUTATIONS` maps a §7 reason slug to a
single mutation of that valid message. `tools/gen_binexport_fixtures.py` writes committed goldens from here.
"""
from __future__ import annotations

from patchtrace.secondary.binexport_proto import load_binexport2_class

SHA = 'a' * 64
NEWER = 'b' * 64


def cls():
    return load_binexport2_class()


def valid(sha: str = SHA, *, base: int = 0x140001000, timestamp: int = 1_760_000_000, functions: int = 2):
    m = cls()()
    meta = m.meta_information
    meta.executable_id, meta.executable_name, meta.architecture_name = sha, 'synthetic.sys', 'x86-64'
    meta.timestamp = timestamp
    m.mnemonic.add().name = 'mov'
    m.mnemonic.add().name = 'call'
    m.string_table.append('hello')
    m.string_table.append('comment text')
    # expressions: operand 0 = [reg] tree (deref root -> register), operand 1 = immediate
    m.expression.add(type=7, symbol='[')                       # 0 DEREFERENCE root
    m.expression.add(type=5, symbol='rax', parent_index=0)     # 1 REGISTER child
    m.expression.add(type=2, immediate=0x10)                    # 2 IMMEDIATE root
    m.operand.add().expression_index.extend([0, 1])
    m.operand.add().expression_index.extend([2])
    for f in range(functions):
        addr = base + 0x100 * f
        i0 = len(m.instruction)
        m.instruction.add(address=addr, mnemonic_index=0, operand_index=[0, 1], raw_bytes=b'\x48\x8b\x00')
        m.instruction.add(address=addr + 3, mnemonic_index=1, operand_index=[1], comment_index=[0])
        b0 = len(m.basic_block)
        m.basic_block.add().instruction_index.add(begin_index=i0)            # end absent -> begin + 1
        m.basic_block.add().instruction_index.add(begin_index=i0 + 1, end_index=i0 + 2)
        g = m.flow_graph.add(entry_basic_block_index=b0)
        g.basic_block_index.extend([b0, b0 + 1])
        g.edge.add(source_basic_block_index=b0, target_basic_block_index=b0 + 1, type=3)
        m.call_graph.vertex.add(address=addr, type=0, mangled_name=f'f{f}')
    for f in range(functions - 1):
        m.call_graph.edge.add(source_vertex_index=f, target_vertex_index=f + 1)
    m.comment.add(instruction_index=1, instruction_operand_index=0, operand_expression_index=0, string_table_index=1,
                  type=0)
    m.string_reference.add(instruction_index=0, instruction_operand_index=1, operand_expression_index=0,
                           string_table_index=0)
    m.data_reference.add(instruction_index=0, address=base + 0x5000)
    m.section.add(address=base, size=0x1000, flag_r=True, flag_x=True)
    m.library.add(name='ntoskrnl.exe', is_static=False)
    m.module.add(name='mod')
    m.md_index.add(address=base, md_index=1.5)
    return m


def raw(msg) -> bytes:
    return msg.SerializeToString()


def _vertex(m, i):
    return m.call_graph.vertex[i]


def _m_dup_vertex(m):
    _vertex(m, 1).address = _vertex(m, 0).address


def _m_swap(m):
    a, b = _vertex(m, 0).address, _vertex(m, 1).address
    _vertex(m, 0).address, _vertex(m, 1).address = b, a


def _m_self_parent(m):
    m.expression[1].parent_index = 1


def _m_cycle(m):
    m.expression[0].parent_index = 1


def _m_drop_entry(m):
    m.flow_graph[0].ClearField('entry_basic_block_index')


def _m_edge_non_member(m):
    m.flow_graph[0].edge[0].target_basic_block_index = 2  # exists, but belongs to the other graph


def _m_range_end(m):
    m.basic_block[0].instruction_index[0].end_index = len(m.instruction) + 1


def _m_overlap(m):
    for _ in range(4):
        m.basic_block[0].instruction_index.add(begin_index=0, end_index=len(m.instruction))


def _m_meta_name(m):
    m.meta_information.executable_name = ''


def _m_call_edge(m):
    m.call_graph.edge[0].ClearField('target_vertex_index')


def _m_operand_oob(m):
    m.operand[0].expression_index.append(len(m.expression))


def _m_operand_neg(m):
    m.operand[0].expression_index.append(-1)


def _m_instr_operand(m):
    m.instruction[0].operand_index.append(len(m.operand))


def _m_mnemonic(m):
    m.ClearField('mnemonic')


def _m_block_empty(m):
    m.basic_block[0].ClearField('instruction_index')


def _m_ref_operand(m):
    m.string_reference[0].instruction_operand_index = 2  # instruction 0 has two operands


def _m_ref_expression(m):
    m.string_reference[0].operand_expression_index = 1  # operand 1 has one expression


def _m_ref_string(m):
    m.string_reference[0].ClearField('string_table_index')


def _m_section(m):
    m.section[0].address = 2**64 - 1


def _m_md_nan(m):
    m.md_index[0].md_index = float('nan')


def _m_md_count(m):
    for _ in range(len(m.call_graph.vertex)):
        m.md_index.add(address=1, md_index=0.0)


def _m_library(m):
    _vertex(m, 0).library_index = 5


def _m_flow_edge_incomplete(m):
    m.flow_graph[0].edge[0].ClearField('source_basic_block_index')


def _m_comment_string(m):
    m.comment[0].string_table_index = 99


def _m_data_ref(m):
    m.data_reference[0].instruction_index = 99


def _m_depth(m):
    first = len(m.expression)
    for k in range(70):
        e = m.expression.add(type=4)
        if k:
            e.parent_index = first + k - 1


def _m_long_string(m):
    m.string_table.append('x' * (64 * 1024 + 1))


def _m_no_vertices(m):
    m.call_graph.ClearField('vertex')
    m.call_graph.ClearField('edge')
    m.ClearField('md_index')


MUTATIONS = {
    'vertex_unsorted_or_duplicate': _m_dup_vertex,
    'vertex_unsorted_or_duplicate#swap': _m_swap,
    'self_parent': _m_self_parent,
    'expression_cycle': _m_cycle,
    'expression_depth': _m_depth,
    'entry_not_in_graph': _m_drop_entry,
    'edge_endpoint_not_in_graph': _m_edge_non_member,
    'flow_edge_incomplete': _m_flow_edge_incomplete,
    'range_invalid': _m_range_end,
    'coverage_amplification': _m_overlap,
    'meta_field_empty': _m_meta_name,
    'call_edge_incomplete': _m_call_edge,
    'index_oob:operand.expression': _m_operand_oob,
    'index_oob:operand.expression#neg': _m_operand_neg,
    'index_oob:instruction.operand': _m_instr_operand,
    'index_oob:instruction.mnemonic': _m_mnemonic,
    'index_oob:vertex.library': _m_library,
    'index_oob:string_reference.operand': _m_ref_operand,
    'index_oob:string_reference.expression': _m_ref_expression,
    'index_oob:comment.string_table': _m_comment_string,
    'index_oob:data_reference.instruction': _m_data_ref,
    'reference_incomplete': _m_ref_string,
    'block_empty': _m_block_empty,
    'section_wraps': _m_section,
    'md_index_invalid': _m_md_nan,
    'count_cap:md_index': _m_md_count,
    'string_too_long': _m_long_string,
    'callgraph_empty': _m_no_vertices,
}


def mutated(key: str, sha: str = SHA):
    m = valid(sha)
    MUTATIONS[key](m)
    return m
