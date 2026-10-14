"""Structural validator over a parsed BinExport2 message (SPEC-10b §6.5).

Duck-typed: works on the upb message class and on `SimpleNamespace` trees (absent optional = None, absent
repeated table = missing attribute). Every pass is iterative and calls `budget.tick`; the first violation raises
a SecondaryError whose text contains labels and numbers only, never strings from the file. Warnings (tier 2)
never change validity.

Measured (upb 7.36.2, proto2): an invalid-UTF-8 `string` field parses and reads back as `bytes`, so any
non-`str` value is reported as `utf8_invalid`; an unknown enum value reads back as the default with
`HasField` false (it becomes an unknown field), so `vertex_type_invalid` is only reachable for duck-typed input.
"""
from __future__ import annotations

import math
import time
from array import array
from collections.abc import Mapping
from dataclasses import dataclass

from .binexport_limits import BinExportLimits, Budget, err

TABLES = ('expression', 'operand', 'mnemonic', 'instruction', 'basic_block', 'flow_graph', 'string_table',
          'comment', 'library', 'module', 'section', 'string_reference', 'expression_substitution',
          'address_comment', 'data_reference', 'md_index')
META_FIELDS = ('executable_id', 'executable_name', 'architecture_name')
REQUIRED_META = ('executable_name', 'architecture_name')  # executable_id policy lives in binexport_identity
FUTURE_SLACK_SECONDS = 2 * 86400


@dataclass(frozen=True, slots=True)
class CheckReport:
    vertex_addresses: tuple[int, ...]
    vertex_types: tuple[int, ...]
    counts: Mapping[str, int]
    warnings: tuple[str, ...]


def _input(reason: str, message: str):
    return err('PT-SECONDARY-INPUT', reason, message)


def _has(message, field: str) -> bool:
    has = getattr(message, 'HasField', None)
    if has is not None:
        return has(field)
    return getattr(message, field, None) is not None


def _opt(message, field: str, default):
    return getattr(message, field) if _has(message, field) else default


def _first_bad(values, n: int):
    for v in values:
        if not 0 <= v < n:
            return v
    return None


def _idx(values, n: int, label: str) -> None:
    """`values` empty or all in [0, n); min/max run at C speed on repeated scalar containers."""
    if values and (min(values) < 0 or max(values) >= n):
        raise _input(f'index_oob:{label}', f'{label} index {_first_bad(values, n)} out of bounds ({n})')


def _one(value: int, n: int, label: str) -> None:
    if not 0 <= value < n:
        raise _input(f'index_oob:{label}', f'{label} index {value} out of bounds ({n})')


def _text_bytes(value, label: str, limit: int, *, reason: str = 'string_too_long') -> int:
    if not isinstance(value, str):  # upb returns bytes for invalid UTF-8 in proto2 string fields
        raise _input('utf8_invalid', f'{label} is not valid UTF-8')
    if len(value) * 4 <= limit:
        try:
            value.encode('utf-8')
        except UnicodeEncodeError:
            raise _input('utf8_invalid', f'{label} is not valid UTF-8') from None
        return len(value) if value.isascii() else len(value.encode('utf-8'))
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        raise _input('utf8_invalid', f'{label} is not valid UTF-8') from None
    if size > limit:
        raise _input(reason, f'{label} exceeds {limit} bytes')
    return size


def _count_cap(n: int, name: str, limits: BinExportLimits) -> None:
    cap = limits.cap(name)
    if n > cap:
        raise err('PT-SECONDARY-LIMIT', f'count_cap:{name}', f'BinExport {name} count exceeds {cap}')


def check_message(msg, limits: BinExportLimits | None = None, budget: Budget | None = None,
                  *, now: float | None = None) -> CheckReport:
    L = limits or BinExportLimits()
    B = budget or Budget()
    tick = B.tick
    warnings: list[str] = []

    def warn(slug: str) -> None:
        if slug not in warnings:
            warnings.append(slug)

    tables = {t: getattr(msg, t, ()) for t in TABLES}
    n = {t: len(v) for t, v in tables.items()}
    for name in TABLES:
        _count_cap(n[name], name, L)

    # --- meta ---
    if not _has(msg, 'meta_information'):
        raise _input('meta_missing', 'BinExport meta_information missing')
    meta = msg.meta_information
    for field in META_FIELDS:
        value = getattr(meta, field, '')
        if value is None:
            value = ''
        size = _text_bytes(value, f'meta_information.{field}', L.max_meta_bytes, reason='meta_field_invalid')
        if '\x00' in value:
            raise _input('meta_field_invalid', f'meta_information.{field} contains NUL')
        if size == 0 and field in REQUIRED_META:
            raise _input('meta_field_empty', f'meta_information.{field} is empty')
    ts = _opt(meta, 'timestamp', None)
    wall = time.time() if now is None else now
    if ts is None or ts <= 0 or ts > wall + FUTURE_SLACK_SECONDS:
        warn('timestamp_implausible')

    # --- call graph: vertices strictly increasing (duplicates and disorder rejected) ---
    if not _has(msg, 'call_graph'):
        raise _input('callgraph_missing', 'BinExport call_graph missing')
    cg = msg.call_graph
    vertices = getattr(cg, 'vertex', ())
    nv = len(vertices)
    if nv == 0:
        raise _input('callgraph_empty', 'BinExport call_graph has no vertices')
    _count_cap(nv, 'vertex', L)
    if n['md_index'] > nv:
        raise err('PT-SECONDARY-LIMIT', 'count_cap:md_index', 'BinExport md_index count exceeds vertex count')
    n_lib, n_mod, max_name = n['library'], n['module'], L.max_string_bytes
    prev = -1
    addrs: list[int] = []
    types: list[int] = []
    for v in vertices:
        a = v.address if _has(v, 'address') else 0
        if a <= prev:
            raise _input('vertex_unsorted_or_duplicate',
                         'call_graph vertices are not sorted strictly by address (duplicate or disorder)')
        t = getattr(v, 'type', 0) or 0
        if t not in (0, 1, 2, 3, 4):
            raise _input('vertex_type_invalid', f'call_graph vertex type {int(t)} is invalid')
        if _has(v, 'library_index'):
            _one(v.library_index, n_lib, 'vertex.library')
        if _has(v, 'module_index'):
            _one(v.module_index, n_mod, 'vertex.module')
        for field in ('mangled_name', 'demangled_name'):
            name = getattr(v, field, None)
            if name:
                _text_bytes(name, f'vertex.{field}', max_name)
                if '\x00' in name:
                    raise _input('meta_field_invalid', f'vertex.{field} contains NUL')
        prev = a
        addrs.append(a)
        types.append(int(t))
        tick()
    call_edges = getattr(cg, 'edge', ())
    _count_cap(len(call_edges), 'call_edge', L)
    for e in call_edges:  # absent endpoint would alias vertex 0 through the proto default
        if not (_has(e, 'source_vertex_index') and _has(e, 'target_vertex_index')):
            raise _input('call_edge_incomplete', 'call_graph.edge lacks an endpoint')
        _one(e.source_vertex_index, nv, 'call_graph.edge')
        _one(e.target_vertex_index, nv, 'call_graph.edge')
        tick()

    # --- string table ---
    total = 0
    for s in tables['string_table']:
        total += _text_bytes(s, 'string_table entry', max_name)
        if total > L.max_string_total:
            raise _input('string_total_bytes', f'string_table exceeds {L.max_string_total} bytes')
        tick()

    # --- expressions: parent bounds, self-parent, cycles, depth (iterative, memoised, O(n)) ---
    exprs = tables['expression']
    ne = n['expression']
    parent = array('i', [-1]) * ne
    for i, e in enumerate(exprs):
        if _has(e, 'parent_index'):
            p = e.parent_index
            _one(p, ne, 'expression.parent')
            if p == i:
                raise _input('self_parent', f'expression {i} is its own parent')
            parent[i] = p
        tick()
    depth = array('i', [0]) * ne  # 0 unknown, -1 on current path, k >= 1 depth
    max_depth = L.max_expr_depth
    for i in range(ne):
        if depth[i]:
            continue
        path: list[int] = []
        j = i
        while j != -1 and depth[j] <= 0:
            if depth[j] == -1:
                raise _input('expression_cycle', f'expression parent chain from {i} is cyclic')
            depth[j] = -1
            path.append(j)
            if len(path) > max_depth:
                raise _input('expression_depth', f'expression tree deeper than {max_depth}')
            j = parent[j]
        base = 0 if j == -1 else depth[j]
        for k in reversed(path):
            base += 1
            depth[k] = base
        if base > max_depth:
            raise _input('expression_depth', f'expression tree deeper than {max_depth}')
        tick(len(path) or 1)
    del depth

    # --- operands ---
    max_ex = L.max_exprs_per_operand
    for o in tables['operand']:
        ex = o.expression_index
        if len(ex) > max_ex:
            raise _input('operand_arity', f'operand has more than {max_ex} expressions')
        _idx(ex, ne, 'operand.expression')
        if ex:  # tier 2: Ghidra emits flat operands, so shape is advisory only
            members = set(ex)
            roots = 0
            for k in ex:
                p = parent[k]
                if p == -1:
                    roots += 1
                elif p not in members:
                    roots = -1
                    break
            if roots != 1:
                warn('operand_tree_shape')
        tick()
    del parent

    # --- mnemonics / instructions (mnemonic_index default 0 is effective) ---
    n_ins, n_mn, n_op, n_cm = n['instruction'], n['mnemonic'], n['operand'], n['comment']
    max_ops, max_ct = L.max_operands_per_instr, L.max_call_targets
    for ins in tables['instruction']:
        _one(_opt(ins, 'mnemonic_index', 0), n_mn, 'instruction.mnemonic')
        ops = getattr(ins, 'operand_index', ())
        if len(ops) > max_ops:
            raise _input('operand_arity', f'instruction has more than {max_ops} operands')
        _idx(ops, n_op, 'instruction.operand')
        _idx(getattr(ins, 'comment_index', ()), n_cm, 'instruction.comment')
        if len(getattr(ins, 'call_target', ())) > max_ct:
            raise _input('call_target_arity', f'instruction has more than {max_ct} call targets')
        tick()

    # --- basic blocks: ranges + amplification (checked per block) ---
    cover = 0
    cover_cap = L.coverage_factor * n_ins + L.coverage_slack
    max_ranges = L.max_ranges_per_block
    for b in tables['basic_block']:
        rs = b.instruction_index
        if not rs:
            raise _input('block_empty', 'basic_block has no instruction range')
        if len(rs) > max_ranges:
            raise _input('block_ranges_excess', f'basic_block has more than {max_ranges} ranges')
        for r in rs:
            begin = _opt(r, 'begin_index', 0)
            end = _opt(r, 'end_index', begin + 1)
            if not 0 <= begin < end <= n_ins:
                raise _input('range_invalid', f'basic_block instruction range {begin}..{end} invalid ({n_ins})')
            cover += end - begin
        if cover > cover_cap:
            raise _input('coverage_amplification', 'basic_block ranges cover too many instructions')
        tick(len(rs))

    # --- flow graphs: membership, entry, edges, amplification ---
    n_bb = n['basic_block']
    members_total = flow_edges = 0
    member_cap = L.coverage_factor * n_bb + nv
    flow_cap = L.cap('flow_edge')
    for g in tables['flow_graph']:
        bl = g.basic_block_index
        members_total += len(bl)
        if members_total > member_cap:
            raise _input('coverage_amplification', 'flow_graph block lists repeat too many blocks')
        _idx(bl, n_bb, 'flow_graph.basic_block')
        members = set(bl)
        if len(members) != len(bl):
            warn('flow_graph_duplicate_blocks')
        if not _has(g, 'entry_basic_block_index') or g.entry_basic_block_index not in members:
            raise _input('entry_not_in_graph', 'flow_graph entry block is not in its block list')
        edges = getattr(g, 'edge', ())
        flow_edges += len(edges)
        if flow_edges > flow_cap:
            raise err('PT-SECONDARY-LIMIT', 'count_cap:flow_edge', f'BinExport flow_edge count exceeds {flow_cap}')
        for e in edges:
            if not (_has(e, 'source_basic_block_index') and _has(e, 'target_basic_block_index')):
                raise _input('flow_edge_incomplete', 'flow_graph.edge lacks an endpoint')
            s, t = e.source_basic_block_index, e.target_basic_block_index
            if s not in members or t not in members:
                _one(s, n_bb, 'flow_graph.edge')
                _one(t, n_bb, 'flow_graph.edge')
                raise _input('edge_endpoint_not_in_graph', 'flow_graph.edge endpoint is not a member block')
        tick(len(bl) + len(edges) or 1)

    # --- references: per-instruction local operand/expression indexes (defaults 0 are effective) ---
    instructions, operands, n_str = tables['instruction'], tables['operand'], n['string_table']

    def local(ref, label: str) -> None:
        i = ref.instruction_index
        _one(i, n_ins, f'{label}.instruction')
        ops = getattr(instructions[i], 'operand_index', ())
        op = _opt(ref, 'instruction_operand_index', 0)
        _one(op, len(ops), f'{label}.operand')
        ex = _opt(ref, 'operand_expression_index', 0)
        _one(ex, len(operands[ops[op]].expression_index), f'{label}.expression')

    for label, refs, need_string in (('string_reference', tables['string_reference'], True),
                                     ('expression_substitution', tables['expression_substitution'], True),
                                     ('address_comment', tables['address_comment'], False)):
        for ref in refs:
            if not _has(ref, 'instruction_index'):
                raise _input('reference_incomplete', f'{label} lacks instruction_index')
            local(ref, label)
            if _has(ref, 'string_table_index'):
                _one(ref.string_table_index, n_str, f'{label}.string_table')
            elif need_string:
                raise _input('reference_incomplete', f'{label} lacks string_table_index')
            tick()
    for c in tables['comment']:
        if _has(c, 'instruction_index'):
            local(c, 'comment')
        if not _has(c, 'string_table_index'):
            raise _input('reference_incomplete', 'comment lacks string_table_index')
        _one(c.string_table_index, n_str, 'comment.string_table')
        tick()
    for d in tables['data_reference']:
        if _has(d, 'instruction_index'):
            _one(d.instruction_index, n_ins, 'data_reference.instruction')
        tick()

    # --- sections / md_index ---
    for s in tables['section']:
        if _opt(s, 'address', 0) + _opt(s, 'size', 0) > 2**64:
            raise _input('section_wraps', 'section address + size wraps past 2**64')
        tick()
    if n['md_index']:
        vset = set(addrs)
        for m in tables['md_index']:
            value = _opt(m, 'md_index', 0.0)
            if not isinstance(value, float | int) or not math.isfinite(value):
                raise _input('md_index_invalid', 'md_index value is not finite')
            if _opt(m, 'address', None) not in vset:
                warn('md_index_address_not_vertex')
            tick()
    counts = dict(n)
    counts.update(vertex=nv, call_edge=len(call_edges), flow_edge=flow_edges)
    return CheckReport(tuple(addrs), tuple(types), counts, tuple(warnings))
