"""SPEC-10b §2 (C3-1): checked-in descriptor set, private pool, upb-only runtime, pinned protobuf."""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import re
from pathlib import Path

import pytest

from patchtrace.secondary import binexport_descriptor as D
from patchtrace.secondary import binexport_proto as P

ROOT = Path(__file__).resolve().parents[1]

# (message path, field number) -> (name, label, type) from descriptor.proto enums; label 1 optional, 3 repeated;
# type 4 uint64, 3 int64, 5 int32, 8 bool, 9 string, 12 bytes, 14 enum, 11 message, 1 double.
GOLDEN_FIELDS = {
    ('BinExport2', 1): ('meta_information', 1, 11),
    ('BinExport2', 2): ('expression', 3, 11),
    ('BinExport2', 3): ('operand', 3, 11),
    ('BinExport2', 4): ('mnemonic', 3, 11),
    ('BinExport2', 5): ('instruction', 3, 11),
    ('BinExport2', 6): ('basic_block', 3, 11),
    ('BinExport2', 7): ('flow_graph', 3, 11),
    ('BinExport2', 8): ('call_graph', 1, 11),
    ('BinExport2', 9): ('string_table', 3, 9),
    ('BinExport2', 10): ('address_comment', 3, 11),
    ('BinExport2', 11): ('string_reference', 3, 11),
    ('BinExport2', 12): ('expression_substitution', 3, 11),
    ('BinExport2', 13): ('section', 3, 11),
    ('BinExport2', 14): ('library', 3, 11),
    ('BinExport2', 15): ('data_reference', 3, 11),
    ('BinExport2', 16): ('module', 3, 11),
    ('BinExport2', 17): ('comment', 3, 11),
    ('BinExport2', 93992622): ('md_index', 3, 11),
    ('BinExport2.BasicBlock', 1): ('instruction_index', 3, 11),
    ('BinExport2.BasicBlock.IndexRange', 1): ('begin_index', 1, 5),
    ('BinExport2.BasicBlock.IndexRange', 2): ('end_index', 1, 5),
    ('BinExport2.CallGraph', 1): ('vertex', 3, 11),
    ('BinExport2.CallGraph', 2): ('edge', 3, 11),
    ('BinExport2.CallGraph.Edge', 1): ('source_vertex_index', 1, 5),
    ('BinExport2.CallGraph.Edge', 2): ('target_vertex_index', 1, 5),
    ('BinExport2.CallGraph.Vertex', 1): ('address', 1, 4),
    ('BinExport2.CallGraph.Vertex', 2): ('type', 1, 14),
    ('BinExport2.CallGraph.Vertex', 3): ('mangled_name', 1, 9),
    ('BinExport2.CallGraph.Vertex', 4): ('demangled_name', 1, 9),
    ('BinExport2.CallGraph.Vertex', 5): ('library_index', 1, 5),
    ('BinExport2.CallGraph.Vertex', 6): ('module_index', 1, 5),
    ('BinExport2.Comment', 1): ('instruction_index', 1, 5),
    ('BinExport2.Comment', 2): ('instruction_operand_index', 1, 5),
    ('BinExport2.Comment', 3): ('operand_expression_index', 1, 5),
    ('BinExport2.Comment', 4): ('string_table_index', 1, 5),
    ('BinExport2.Comment', 5): ('repeatable', 1, 8),
    ('BinExport2.Comment', 6): ('type', 1, 14),
    ('BinExport2.DataReference', 1): ('instruction_index', 1, 5),
    ('BinExport2.DataReference', 2): ('address', 1, 4),
    ('BinExport2.Expression', 1): ('type', 1, 14),
    ('BinExport2.Expression', 2): ('symbol', 1, 9),
    ('BinExport2.Expression', 3): ('immediate', 1, 4),
    ('BinExport2.Expression', 4): ('parent_index', 1, 5),
    ('BinExport2.Expression', 5): ('is_relocation', 1, 8),
    ('BinExport2.FlowGraph', 1): ('basic_block_index', 3, 5),
    ('BinExport2.FlowGraph', 2): ('edge', 3, 11),
    ('BinExport2.FlowGraph', 3): ('entry_basic_block_index', 1, 5),
    ('BinExport2.FlowGraph.Edge', 1): ('source_basic_block_index', 1, 5),
    ('BinExport2.FlowGraph.Edge', 2): ('target_basic_block_index', 1, 5),
    ('BinExport2.FlowGraph.Edge', 3): ('type', 1, 14),
    ('BinExport2.FlowGraph.Edge', 4): ('is_back_edge', 1, 8),
    ('BinExport2.Instruction', 1): ('address', 1, 4),
    ('BinExport2.Instruction', 2): ('call_target', 3, 4),
    ('BinExport2.Instruction', 3): ('mnemonic_index', 1, 5),
    ('BinExport2.Instruction', 4): ('operand_index', 3, 5),
    ('BinExport2.Instruction', 5): ('raw_bytes', 1, 12),
    ('BinExport2.Instruction', 6): ('comment_index', 3, 5),
    ('BinExport2.Library', 1): ('is_static', 1, 8),
    ('BinExport2.Library', 2): ('load_address', 1, 4),
    ('BinExport2.Library', 3): ('name', 1, 9),
    ('BinExport2.MDIndex', 1): ('address', 1, 4),
    ('BinExport2.MDIndex', 2): ('md_index', 1, 1),
    ('BinExport2.Meta', 1): ('executable_name', 1, 9),
    ('BinExport2.Meta', 2): ('executable_id', 1, 9),
    ('BinExport2.Meta', 3): ('architecture_name', 1, 9),
    ('BinExport2.Meta', 4): ('timestamp', 1, 3),
    ('BinExport2.Mnemonic', 1): ('name', 1, 9),
    ('BinExport2.Module', 1): ('name', 1, 9),
    ('BinExport2.Operand', 1): ('expression_index', 3, 5),
    ('BinExport2.Reference', 1): ('instruction_index', 1, 5),
    ('BinExport2.Reference', 2): ('instruction_operand_index', 1, 5),
    ('BinExport2.Reference', 3): ('operand_expression_index', 1, 5),
    ('BinExport2.Reference', 4): ('string_table_index', 1, 5),
    ('BinExport2.Section', 1): ('address', 1, 4),
    ('BinExport2.Section', 2): ('size', 1, 4),
    ('BinExport2.Section', 3): ('flag_r', 1, 8),
    ('BinExport2.Section', 4): ('flag_w', 1, 8),
    ('BinExport2.Section', 5): ('flag_x', 1, 8),
}


@pytest.fixture(autouse=True)
def _fresh_cache():
    P.reset_cache()
    yield
    P.reset_cache()


def _fields():
    from google.protobuf import descriptor_pb2
    files = descriptor_pb2.FileDescriptorSet.FromString(P.descriptor_bytes())
    out = {}

    def walk(d, path):
        for f in d.field:
            out[(path, f.number)] = (f.name, f.label, f.type)
        for n in d.nested_type:
            walk(n, f'{path}.{n.name}')
    assert [f.name for f in files.file] == ['binexport2.proto'] and not files.file[0].package
    walk(files.file[0].message_type[0], 'BinExport2')
    return out, files.file[0]


def test_descriptor_constants_and_golden_field_table():
    assert D.PROTO_SHA256 == 'e8e4943de00b37038b614bbd0515cb188caf3e4a2e20c6566544e791f93647d8'
    assert D.PROTO_COMMIT == '2bff7af27af206354b2a90a9de566dc6bbae3e1b'
    data = base64.b64decode(D.DESCRIPTOR_SET_B64)
    assert len(data) == 4144 and hashlib.sha256(data).hexdigest() == D.DESCRIPTOR_SET_SHA256
    fields, proto = _fields()
    assert fields == GOLDEN_FIELDS
    top = {n: name for (path, n), (name, _, _) in fields.items() if path == 'BinExport2'}
    assert top[93992622] == 'md_index' and len(top) == 18
    ranges = [(r.start, r.end) for r in proto.message_type[0].extension_range]
    assert ranges == [(100000000, 536870912)]  # `extensions 100000000 to max`


def test_notice_copy_of_proto_matches_pin():
    notice = ROOT / 'third_party' / 'notices' / 'binexport-2bff7af'
    assert hashlib.sha256((notice / 'binexport2.proto').read_bytes()).hexdigest() == D.PROTO_SHA256
    assert 'Apache License' in (notice / 'LICENSE').read_text(encoding='utf-8')
    assert D.PROTO_COMMIT in (notice / 'PROVENANCE.txt').read_text(encoding='utf-8')
    bsd = (ROOT / 'third_party' / 'notices' / 'protobuf-7.36.2' / 'LICENSE').read_text(encoding='utf-8')
    assert 'Redistribution and use in source and binary forms' in bsd


def test_runtime_is_pinned_upb():
    from google.protobuf.internal import api_implementation
    assert api_implementation.Type() == 'upb'
    pin = re.search(r'"protobuf==([0-9.]+)"', (ROOT / 'pyproject.toml').read_text(encoding='utf-8')).group(1)
    assert importlib.metadata.version('protobuf') == pin == '.'.join(map(str, P.PINNED_PROTOBUF))
    assert P.runtime_info()['implementation'] == 'upb'


def test_class_is_private_and_memoised():
    from google.protobuf import descriptor_pool
    cls = P.load_binexport2_class()
    assert P.load_binexport2_class() is cls
    with pytest.raises(KeyError):
        descriptor_pool.Default().FindMessageTypeByName('BinExport2')
    m = cls()
    m.meta_information.executable_id = 'x'
    assert cls.FromString(m.SerializeToString()).meta_information.executable_id == 'x'


def test_pure_python_runtime_refused(monkeypatch):
    from google.protobuf.internal import api_implementation
    monkeypatch.setattr(api_implementation, 'Type', lambda: 'python')
    with pytest.raises(P.ProtoUnavailable) as info:
        P.load_binexport2_class()
    assert info.value.reason == 'protobuf_not_upb'


def test_old_runtime_refused(monkeypatch):
    import google.protobuf
    monkeypatch.setattr(google.protobuf, '__version__', '7.36.1')
    with pytest.raises(P.ProtoUnavailable) as info:
        P.load_binexport2_class()
    assert info.value.reason == 'protobuf_too_old'
    assert P._version_tuple('7.36.2rc1') == (7, 36, 2) and P._version_tuple('8.0.0') > P.PINNED_PROTOBUF


def test_missing_runtime_and_descriptor_tamper(monkeypatch):
    import builtins
    real = builtins.__import__

    def deny(name, *a, **k):
        if name.startswith('google.protobuf'):
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, '__import__', deny)
    with pytest.raises(P.ProtoUnavailable) as info:
        P.load_binexport2_class()
    assert info.value.reason == 'protobuf_missing'
    monkeypatch.setattr(builtins, '__import__', real)
    P.reset_cache()
    monkeypatch.setattr(D, 'DESCRIPTOR_SET_SHA256', '0' * 64)
    with pytest.raises(P.ProtoUnavailable) as info:
        P.load_binexport2_class()
    assert info.value.reason == 'descriptor_mismatch'


def test_generator_render_round_trips():
    import importlib.util
    spec = importlib.util.spec_from_file_location('gen', ROOT / 'tools' / 'gen_binexport_descriptor.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    data = base64.b64decode(D.DESCRIPTOR_SET_B64)
    namespace: dict = {}
    exec(gen.render(data, D.GENERATOR), namespace)  # noqa: S102 - our own generated constants
    assert namespace['DESCRIPTOR_SET_B64'] == D.DESCRIPTOR_SET_B64
    assert (ROOT / 'src/patchtrace/secondary/binexport_descriptor.py').read_text(encoding='utf-8') == \
        gen.render(data, D.GENERATOR)
