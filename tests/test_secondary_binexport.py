"""SPEC-10 §2: `.BinExport` structural checks over duck-typed messages (no protobuf runtime needed)."""
from __future__ import annotations

from types import SimpleNamespace as N

import pytest

from patchtrace.secondary import binexport
from patchtrace.secondary.binexport import (
    check_executable,
    check_message,
    check_pair_exports,
    unmatched_addresses,
    validate_binexport,
)
from patchtrace.secondary.contracts import SecondaryError

SHA = 'a' * 64


def message(**over):
    base = dict(
        meta_information=N(executable_id=SHA, executable_name='afd.sys', architecture_name='x86-64'),
        expression=[N(parent_index=None), N(parent_index=0)],
        operand=[N(expression_index=[0, 1])],
        mnemonic=[N(name='mov')],
        instruction=[N(mnemonic_index=0, operand_index=[0], comment_index=[]),
                     N(mnemonic_index=0, operand_index=[], comment_index=[])],
        basic_block=[N(instruction_index=[N(begin_index=0, end_index=2)]),
                     N(instruction_index=[N(begin_index=1, end_index=None)])],
        flow_graph=[N(basic_block_index=[0, 1], entry_basic_block_index=0,
                      edge=[N(source_basic_block_index=0, target_basic_block_index=1)])],
        call_graph=N(vertex=[N(address=0x1000, library_index=None, module_index=None),
                             N(address=0x2000, library_index=None, module_index=None)],
                     edge=[N(source_vertex_index=0, target_vertex_index=1)]),
        string_table=['s'], string_reference=[], expression_substitution=[], data_reference=[],
        library=[], module=[], comment=[],
    )
    base.update(over)
    return N(**base)


def test_valid_message():
    result = check_message(message())
    assert result.status == 'valid'
    assert result.function_addresses == (0x1000, 0x2000)
    check_executable(result, SHA)


@pytest.mark.parametrize('over, needle', [
    ({'meta_information': None}, 'meta_information missing'),
    ({'meta_information': N(executable_id='', executable_name='x', architecture_name='y')}, 'executable_id'),
    ({'call_graph': N(vertex=[], edge=[])}, 'no vertices'),
    ({'call_graph': N(vertex=[N(address=2, library_index=None, module_index=None),
                              N(address=1, library_index=None, module_index=None)], edge=[])}, 'sorted'),
    ({'operand': [N(expression_index=[5])]}, 'operand.expression'),
    ({'instruction': [N(mnemonic_index=3, operand_index=[], comment_index=[])]}, 'instruction.mnemonic'),
    ({'basic_block': [N(instruction_index=[N(begin_index=0, end_index=9)])]}, 'range'),
    ({'flow_graph': [N(basic_block_index=[0], entry_basic_block_index=1, edge=[])]}, 'entry block'),
    ({'flow_graph': [N(basic_block_index=[7], entry_basic_block_index=7, edge=[])]}, 'flow_graph.basic_block'),
    ({'expression': [N(parent_index=4)]}, 'expression.parent'),
    ({'comment': [N(instruction_index=0, string_table_index=3)]}, 'comment.string_table'),
    ({'data_reference': [N(instruction_index=10)]}, 'data_reference'),
])
def test_out_of_range_and_missing_fields(over, needle):
    with pytest.raises(SecondaryError, match=needle):
        check_message(message(**over))


def test_call_graph_edge_out_of_bounds():
    msg = message()
    msg.call_graph.edge = [N(source_vertex_index=0, target_vertex_index=2)]
    with pytest.raises(SecondaryError, match='call_graph.edge'):
        check_message(msg)


def test_executable_id_must_match_artifact_and_orientation():
    result = check_message(message())
    with pytest.raises(SecondaryError) as info:
        check_executable(result, 'b' * 64)
    assert info.value.code == 'PT-SECONDARY-PAIR'
    newer = check_message(message(meta_information=N(executable_id='b' * 64, executable_name='n',
                                                     architecture_name='x86-64')))
    check_pair_exports(result, newer, SHA, 'b' * 64)
    with pytest.raises(SecondaryError) as info:
        check_pair_exports(newer, result, SHA, 'b' * 64)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'


def test_missing_bindings_report_unsupported(tmp_path, monkeypatch):
    monkeypatch.setattr(binexport, '_bindings', lambda: None)
    path = tmp_path / 'x.BinExport'
    path.write_bytes(b'\x0a\x00')
    result = validate_binexport(path, SHA)
    assert (result.status, result.reason) == ('unsupported', 'protobuf bindings not installed')


def test_real_bindings_absent_in_this_build(tmp_path):
    path = tmp_path / 'x.BinExport'
    path.write_bytes(b'')
    assert validate_binexport(path, SHA).status == 'unsupported'


def test_injected_bindings_parse_failure_and_success(tmp_path):
    path = tmp_path / 'x.BinExport'
    path.write_bytes(b'junk')

    class Bad:
        def ParseFromString(self, data):  # noqa: N802 - protobuf API name
            raise ValueError('DecodeError')

    with pytest.raises(SecondaryError, match='parseable'):
        validate_binexport(path, SHA, bindings=N(BinExport2=Bad))
    good = message()
    good.ParseFromString = lambda data: None
    assert validate_binexport(path, SHA, bindings=N(BinExport2=lambda: good)).status == 'valid'


def test_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(binexport, 'MAX_SIZE', 3)
    path = tmp_path / 'x.BinExport'
    path.write_bytes(b'1234')
    with pytest.raises(SecondaryError, match='512 MiB'):
        validate_binexport(path, SHA)


def test_unmatched_derived_from_call_graph():
    assert unmatched_addresses([0x10, 0x20, 0x30], [0x20, None]) == (0x10, 0x30)
