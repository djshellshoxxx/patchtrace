"""DIE slice D1: diec adapter hardening (DIE-integration-plan s6, s7). The fixtures nested-overlay, empty-result and
vocabulary are hand-authored from the upstream JSON writer (`ScanItemModel::_toJSON`); they are NOT captured from a
real diec run until gate G-L1 replaces them. No tool runs here."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchtrace.intelligence.tools import delta, diec, process
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools' / 'diec'
VOCABULARY = json.loads((FIXTURES / 'vocabulary.json').read_text(encoding='utf-8'))
TYPE_NAMES = [leaf['string'].split(': ')[0] for leaf in VOCABULARY['detects'][0]['values']]
MIB = 1024 * 1024
GIB = 1024 * MIB


def parse(raw: bytes | str | dict | list, side: str = 'older'):
    if isinstance(raw, dict | list):
        raw = json.dumps(raw)
    if isinstance(raw, str):
        raw = raw.encode('utf-8')
    return diec.parse(raw, diec.ParseContext('r', side, 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec']))


def parse_fixture(name: str):
    return parse((FIXTURES / f'{name}.json').read_bytes())


def leaf(type_: str, name: str = 'N', string: str = '', version: str = ''):
    return {'info': '', 'name': name, 'string': string or f'{type_}: {name}', 'type': type_, 'version': version}


def header(values: list, filetype: str = 'PE64', offset: str = '0', parent: str = 'Header'):
    return {'filetype': filetype, 'info': '', 'offset': offset, 'parentfilepart': parent, 'size': '1', 'values': values}


def nest(depth: int) -> dict:
    node = header([leaf('packer', 'UPX')], 'LEAF')
    for level in range(depth - 1):
        node = header([node], f'F{level}')
    return {'detects': [node]}


def test_nested_file_part_nodes_flatten_with_path():
    evidence = parse_fixture('nested-overlay')
    by_name = {e.detector_rule: e for e in evidence.environment}
    assert set(by_name) == {'MinGW', 'ZIP', 'UPX'}
    assert by_name['MinGW'].part_path == 'PE64@0'
    assert by_name['ZIP'].part_path == 'PE64@0/ZIP@8192'
    assert by_name['UPX'].part_path == 'PE64@0/ZIP@8192/PE32@16384'
    assert by_name['UPX'].filetype == 'PE32'
    assert by_name['UPX'].category == 'packer'
    assert evidence.counts['environment_total'] == 3
    assert 'PE32' in evidence.analysis['filetypes']


def test_nesting_depth_is_capped_at_eight():
    assert parse(nest(8)).environment[0].detector_rule == 'UPX'
    with pytest.raises(ToolError) as caught:
        parse(nest(9))
    assert caught.value.code == 'PT-TOOL-OUTPUT'


def test_empty_result_document_is_none_found():
    evidence = parse_fixture('empty-result')
    assert evidence.environment == ()
    assert evidence.analysis['result'] == 'none-found'
    assert evidence.truncated is False
    assert evidence.counts == {'environment': 0, 'environment_total': 0}


@pytest.mark.parametrize('document', [
    {'info': '', 'name': '', 'string': 'Other', 'type': '', 'version': ''},
    {'info': '', 'name': '', 'string': 'Result'},
    {'detects': [], 'string': 'Result'},
    {'detects': [header([], 'PE64')], 'extra': 1},
    [],
    {'detects': [{'filetype': 'PE64'}]},
], ids=['wrong-string', 'leaf-missing-keys', 'mixed-root', 'extra-key', 'array-root', 'missing-header-keys'])
def test_any_other_shape_stays_tool_output_error(document):
    with pytest.raises(ToolError) as caught:
        parse(document)
    assert caught.value.code == 'PT-TOOL-OUTPUT'


@pytest.mark.parametrize(('type_', 'heuristic', 'certainty'), [
    ('~compiler', True, 'heuristic'), ('!protection', True, 'heuristic'), ('~!packer', True, 'heuristic'),
    ('compiler', False, 'signature')], ids=['tilde', 'bang', 'both', 'plain'])
def test_aggressive_heuristic_markers_are_heuristic(type_, heuristic, certainty):
    item = parse({'detects': [header([leaf(type_)])]}).environment[0]
    assert item.heuristic is heuristic
    assert item.certainty == certainty
    assert item.raw_type == type_.lstrip('~!')


def test_a_heur_display_string_is_heuristic():
    item = parse({'detects': [header([leaf('protection', string='(A-Heur)Protection: Generic')])]}).environment[0]
    assert item.heuristic is True
    assert item.certainty == 'heuristic'


def test_vocabulary_fixture_has_57_names():
    assert len(TYPE_NAMES) == 57
    assert len(set(TYPE_NAMES)) == 57


@pytest.mark.parametrize('index', range(57), ids=[f't{i:02d}' for i in range(57)])
def test_every_upstream_record_type_has_a_category(index):
    raw_type = TYPE_NAMES[index].lower()
    item = {e.detector_rule: e for e in parse_fixture('vocabulary').environment}[f'N{index:02d}']
    assert item.raw_type == raw_type
    assert item.category == diec.TYPE_CATEGORY[raw_type]
    if raw_type == 'unknown':
        assert item.certainty == 'unknown'
    classes = (diec.PACKED_TYPES, diec.PROTECTED_TYPES, diec.INSTALLER_TYPES, diec.NEUTRAL_TYPES)
    assert sum(raw_type in group for group in classes) == 1, 'a type is in exactly one warning set or neutral'


def test_type_table_is_total_and_closed():
    assert set(diec.TYPE_CATEGORY) == {name.lower() for name in TYPE_NAMES}
    assert diec.PACKED_TYPES == {'packer', 'compressor', '.net compressor', 'cryptor', 'crypter'}
    assert diec.PROTECTED_TYPES == {'protector', 'protection', 'obfuscator', '.net obfuscator'}


@pytest.mark.parametrize(('raw_type', 'category'), [
    ('compressor', 'packer'), ('.net compressor', 'packer'), ('crypter', 'cryptor'), ('obfuscator', 'protector'),
    ('.net obfuscator', 'protector'), ('protection', 'protector'), ('installer data', 'installer'),
    ('sfx data', 'sfx'), ('language', 'language'), ('operation system', 'os'), ('archive', 'archive'),
    ('sign tool', 'signtool'), ('pe tool', 'petool'), ('virtual machine', 'other'), ('stub', 'other')],
    ids=['compressor', 'netcomp', 'crypter', 'obfuscator', 'netobf', 'protection', 'instdata', 'sfxdata', 'lang',
         'os', 'archive', 'sign', 'petool', 'vm', 'stub'])
def test_card_category_mapping(raw_type, category):
    assert diec.TYPE_CATEGORY[raw_type] == category


def test_unknown_type_name_is_other_and_raw_type_is_kept():
    item = parse({'detects': [header([leaf('Brand New Kind', 'X')])]}).environment[0]
    assert item.category == 'other'
    assert item.raw_type == 'brand new kind'


def test_vocabulary_drift_is_reported():
    evidence = parse({'detects': [header([leaf('brand new kind', 'X'), leaf('packer', 'UPX')])]})
    assert evidence.analysis['vocabulary_drift'] == 1
    assert 'vocabulary_drift' not in parse_fixture('vocabulary').analysis


def test_raw_type_is_bounded_and_plain_text():
    item = parse({'detects': [header([leaf('x‮' + 'y' * 500, 'X')])]}).environment[0]
    assert len(item.raw_type) <= 64
    assert '‮' not in item.raw_type


def test_existing_goldens_keep_their_categories():
    item = parse((FIXTURES / 'diec-toolchain-newer.json').read_bytes()).environment[0]
    assert (item.category, item.raw_type, item.part_path) == ('compiler', 'compiler', 'PE64@0')


def evidence_for(*types: str, side: str = 'older'):
    return parse({'detects': [header([leaf(t, f'{t} name') for t in types])]}, side)


@pytest.mark.parametrize(('raw_type', 'code'), [
    ('packer', 'packed'), ('compressor', 'packed'), ('.net compressor', 'packed'), ('crypter', 'packed'),
    ('cryptor', 'packed'), ('protector', 'protected'), ('protection', 'protected'), ('obfuscator', 'protected'),
    ('.net obfuscator', 'protected'), ('installer', 'installer'), ('installer data', 'installer'),
    ('sfx', 'installer'), ('sfx data', 'installer')],
    ids=['packer', 'compressor', 'netcomp', 'crypter', 'cryptor', 'protector', 'protection', 'obfuscator',
         'netobf', 'installer', 'instdata', 'sfx', 'sfxdata'])
def test_quality_flags_use_the_shared_type_sets(raw_type, code):
    flags = delta.quality_flags((evidence_for(raw_type), evidence_for('compiler', side='newer')))
    assert code in {f.code for f in flags}
    other = {'packed', 'protected', 'installer'} - {code}
    assert not other & {f.code for f in flags}


@pytest.mark.parametrize('raw_type', ['virtual machine', 'dongle protection', 'joiner', 'stub', 'loader', 'tool'],
                         ids=['vm', 'dongle', 'joiner', 'stub', 'loader', 'tool'])
def test_neutral_types_raise_no_warning_flag(raw_type):
    flags = delta.quality_flags((evidence_for(raw_type), evidence_for('compiler', side='newer')))
    assert not {'packed', 'protected', 'installer'} & {f.code for f in flags}


def test_installer_flag_does_not_claim_packed():
    flags = delta.quality_flags((evidence_for('installer'), evidence_for('compiler', side='newer')))
    assert 'packed' not in {f.code for f in flags}


def test_memory_cap_is_min_of_4_gib_and_half_of_ram():
    assert diec.memory_cap(16 * GIB) == 4 * GIB
    assert diec.memory_cap(6 * GIB) == 3 * GIB
    assert diec.memory_cap(None) == 4 * GIB
    assert diec.memory_cap(0) == 4 * GIB


def test_config_effective_memory_limit_reads_ram_through_process(monkeypatch):
    monkeypatch.setattr(process, 'total_ram_bytes', lambda: 2 * GIB)
    assert diec.DiecConfig(None).effective_memory_limit() == GIB
    assert diec.DiecConfig(None, memory_limit_bytes=300 * MIB).effective_memory_limit() == 300 * MIB


def test_config_memory_limit_below_minimum_is_rejected():
    with pytest.raises(ToolError) as caught:
        diec.DiecConfig(None, memory_limit_bytes=MIB).effective_memory_limit()
    assert caught.value.code == 'PT-TOOL-INPUT'


def test_total_ram_is_a_positive_int_or_none():
    value = process.total_ram_bytes()
    assert value is None or (isinstance(value, int) and value > 0)
