"""`.BinExport` validator (SPEC-10 §2) behind optional protobuf bindings.

`.BinExport` has no magic number, so only a full parse plus structural checks tells a
genuine file from a lookalike. Bindings are not shipped in this version; generate them
from binexport2.proto pinned at google/binexport@2bff7af (Apache-2.0, add its notice):

    protoc --python_out=src/patchtrace/secondary binexport2.proto
    mv src/patchtrace/secondary/binexport2_pb2.py src/patchtrace/secondary/_binexport2_pb2.py

and add the matching `protobuf` runtime. Until then `validate_binexport` reports
`unsupported`. The structural checks run over any object exposing the proto2 field
names, which is how they are tested without the runtime.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .contracts import SecondaryError, check_pair

MAX_SIZE = 512 * 1024 * 1024


@dataclass(frozen=True)
class BinExportResult:
    status: str  # 'valid' or 'unsupported'
    reason: str | None
    executable_id: str | None = None
    executable_name: str | None = None
    architecture_name: str | None = None
    function_addresses: tuple[int, ...] = ()


def _fail(message: str) -> SecondaryError:
    return SecondaryError('PT-SECONDARY-INPUT', message)


def _has(message, field: str) -> bool:
    if hasattr(message, 'HasField'):
        return message.HasField(field)
    return getattr(message, field, None) is not None


def _bound(values: Iterable[int], size: int, label: str) -> None:
    for value in values:
        if not 0 <= value < size:
            raise _fail(f'{label} index {value} out of bounds ({size})')


def _optional(message, field: str) -> list[int]:
    return [getattr(message, field)] if _has(message, field) else []


def check_message(msg) -> BinExportResult:
    """Structural validation of a parsed BinExport2 message; raises SecondaryError."""
    if not _has(msg, 'meta_information'):
        raise _fail('meta_information missing')
    meta = msg.meta_information
    for field in ('executable_id', 'executable_name', 'architecture_name'):
        if not getattr(meta, field, ''):
            raise _fail(f'meta_information.{field} is empty')
    if not _has(msg, 'call_graph') or not msg.call_graph.vertex:
        raise _fail('call_graph has no vertices')
    vertices = msg.call_graph.vertex
    addresses = [v.address for v in vertices]
    if any(b < a for a, b in zip(addresses, addresses[1:], strict=False)):
        raise _fail('call_graph vertices are not sorted by address')
    counts = {name: len(getattr(msg, name)) for name in (
        'expression', 'operand', 'mnemonic', 'instruction', 'basic_block', 'flow_graph', 'string_table',
        'library', 'module', 'comment')}
    for e in msg.expression:
        _bound(_optional(e, 'parent_index'), counts['expression'], 'expression.parent')
    for o in msg.operand:
        _bound(o.expression_index, counts['expression'], 'operand.expression')
    for i in msg.instruction:
        _bound(_optional(i, 'mnemonic_index'), counts['mnemonic'], 'instruction.mnemonic')
        _bound(i.operand_index, counts['operand'], 'instruction.operand')
        _bound(i.comment_index, counts['comment'], 'instruction.comment')
    for block in msg.basic_block:
        for r in block.instruction_index:
            begin = r.begin_index
            end = r.end_index if _has(r, 'end_index') else begin + 1
            if not 0 <= begin < end <= counts['instruction']:
                raise _fail(f'basic_block instruction range {begin}..{end} out of bounds')
    for graph in msg.flow_graph:
        _bound(graph.basic_block_index, counts['basic_block'], 'flow_graph.basic_block')
        if not _has(graph, 'entry_basic_block_index') or \
                graph.entry_basic_block_index not in set(graph.basic_block_index):
            raise _fail('flow_graph entry block is not in its block list')
        for edge in graph.edge:
            _bound(_optional(edge, 'source_basic_block_index') + _optional(edge, 'target_basic_block_index'),
                   counts['basic_block'], 'flow_graph.edge')
    for v in vertices:
        _bound(_optional(v, 'library_index'), counts['library'], 'vertex.library')
        _bound(_optional(v, 'module_index'), counts['module'], 'vertex.module')
    for edge in msg.call_graph.edge:
        _bound(_optional(edge, 'source_vertex_index') + _optional(edge, 'target_vertex_index'),
               len(vertices), 'call_graph.edge')
    for ref in list(msg.string_reference) + list(msg.expression_substitution):
        _bound(_optional(ref, 'instruction_index'), counts['instruction'], 'reference.instruction')
        _bound(_optional(ref, 'string_table_index'), counts['string_table'], 'reference.string_table')
    for ref in msg.data_reference:
        _bound(_optional(ref, 'instruction_index'), counts['instruction'], 'data_reference.instruction')
    for c in msg.comment:
        _bound(_optional(c, 'instruction_index'), counts['instruction'], 'comment.instruction')
        _bound(_optional(c, 'string_table_index'), counts['string_table'], 'comment.string_table')
    return BinExportResult('valid', None, meta.executable_id, meta.executable_name, meta.architecture_name,
                           tuple(addresses))


def check_executable(result: BinExportResult, artifact_sha256: str) -> None:
    """The Ghidra exporter writes the program SHA-256 as executable_id; anything else is a wrong pair."""
    if (result.executable_id or '').strip().lower() != artifact_sha256:
        raise SecondaryError('PT-SECONDARY-PAIR', 'BinExport executable_id does not match the artifact SHA-256')


def check_pair_exports(older: BinExportResult, newer: BinExportResult, older_sha256: str,
                       newer_sha256: str) -> None:
    check_pair(older.executable_id or '', newer.executable_id or '', older_sha256, newer_sha256)


def _bindings():
    try:
        from . import _binexport2_pb2  # type: ignore[attr-defined]
    except ImportError:
        return None
    return _binexport2_pb2


def validate_binexport(path: Path, artifact_sha256: str, bindings=None) -> BinExportResult:
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise _fail(f'cannot read BinExport file: {exc.strerror}') from None
    if size > MAX_SIZE:
        raise SecondaryError('PT-SECONDARY-LIMIT', 'BinExport file exceeds 512 MiB')
    module = bindings or _bindings()
    if module is None:
        return BinExportResult('unsupported', 'protobuf bindings not installed')
    data = path.read_bytes()
    message = module.BinExport2()
    try:
        message.ParseFromString(data)
    except Exception:  # protobuf raises DecodeError, whose import path differs by runtime.
        raise _fail('not a parseable BinExport2 message') from None
    result = check_message(message)
    check_executable(result, artifact_sha256)
    return result


def unmatched_addresses(function_addresses: Iterable[int], matched: Iterable[int | None]) -> tuple[int, ...]:
    """BinDiff stores only matches; unmatched functions are call-graph vertices it never mentions."""
    seen = {a for a in matched if a is not None}
    return tuple(sorted({a for a in function_addresses} - seen))

