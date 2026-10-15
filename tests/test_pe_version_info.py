"""VS_VERSIONINFO reader: blocks, ordering, contradictions, hostile structure, hostile text and parity."""
from __future__ import annotations

import json
import struct
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_rsrc_builder import (
    LANG_EN_US,
    RT_ICON,
    RT_VERSION,
    Data,
    Name,
    fixed_file_info,
    mutate,
    node,
    open_pe,
    real_launchers,
    rsrc_pe,
    standard_strings,
    string_node,
    string_table,
    tree,
    utf16z,
    version_blob,
)

from patchtrace.intelligence.csaf.identity import read_version_info
from patchtrace.pe_overview.resources import DEFAULT_RESOURCE_LIMITS, ResourceLimits, parse_resources
from patchtrace.pe_overview.version_info import (
    FixedFileInfo,
    VersionString,
    parse_version_info,
    version_text,
)

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
BUDGET_S = 0.25


def read(tmp_path, root, limits=DEFAULT_RESOURCE_LIMITS):
    data, _info = rsrc_pe(root)
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size, limits)
        return parse_version_info(pe.ctx, pe.smap, inventory, limits), pe.codes()


def one(tmp_path, blob, limits=DEFAULT_RESOURCE_LIMITS):
    info, codes = read(tmp_path, tree({RT_VERSION: {1: {LANG_EN_US: blob}}}), limits)
    (block,) = info.blocks
    return block, codes


def values(block):
    return {s.key: s.value for s in block.strings}


def locate(blob: bytes, key: str) -> int:
    """File offset of the node whose key is `key` (the 6 byte header precedes the key)."""
    return blob.index(utf16z(key)) - 6


# -- well-formed blocks -------------------------------------------------------------------------------------


def test_fixed_info_strings_and_translations_decode(tmp_path):
    blob = version_blob((10, 0, 19041, 1), (10, 0, 19041, 2), strings=standard_strings('10.0.19041.1'),
                        translations=[(0x409, 0x4B0), (0x407, 0x4B0)], mask=0x3F, flags=0x2, file_os=0x40004,
                        file_type=2, subtype=7)
    block, codes = one(tmp_path, blob)
    assert codes == set() and block.status == 'ok' and block.warnings == ()
    assert block.fixed == FixedFileInfo((10, 0, 19041, 1), (10, 0, 19041, 2), 0x3F, 0x2, 0x40004, 2, 7)
    assert block.strings[0] == VersionString('040904B0', 'CompanyName', 'Example Corp', False)
    assert [s.key for s in block.strings] == ['CompanyName', 'FileDescription', 'FileVersion', 'InternalName',
                                              'OriginalFilename', 'ProductName', 'ProductVersion']
    assert block.translations == ('040904B0', '040704B0')
    assert (block.leaf.type_id, block.leaf.name, block.leaf.lang) == (RT_VERSION, 1, LANG_EN_US)


def test_table_keys_are_normalised_and_languages_kept_apart(tmp_path):
    blob = version_blob(strings={'040904b0': {'FileVersion': '1.0.0.1'}, '040704B0': {'FileVersion': '1.0.0.1'}})
    block, _codes = one(tmp_path, blob)
    assert [(s.lang_codepage, s.key) for s in block.strings] == [('040904B0', 'FileVersion'),
                                                                 ('040704B0', 'FileVersion')]


def test_missing_fixed_info_still_reads_strings(tmp_path):
    block, codes = one(tmp_path, version_blob(fixed=False, strings=standard_strings()))
    assert block.fixed is None and values(block)['FileVersion'] == '1.0.0.1'
    assert block.status == 'ok' and codes == set()


def test_version_without_string_or_var_tables(tmp_path):
    block, _codes = one(tmp_path, version_blob(strings=None, translations=None))
    assert block.fixed.file_version == (1, 0, 0, 1) and block.strings == () and block.translations == ()


def test_duplicate_keys_are_kept_in_file_order(tmp_path):
    table = node('040904B0', children=[string_node('Comments', 'one'), string_node('Comments', 'two')])
    blob = node('VS_VERSION_INFO', fixed_file_info(), wtype=0, children=[node('StringFileInfo', children=[table])])
    block, _codes = one(tmp_path, blob)
    assert [(s.key, s.value) for s in block.strings] == [('Comments', 'one'), ('Comments', 'two')]


def test_trailing_padding_after_the_root_is_ignored(tmp_path):
    block, codes = one(tmp_path, version_blob(strings=standard_strings()) + bytes(40))
    assert block.status == 'ok' and codes == set()


def test_absent_version_resource_gives_an_empty_set(tmp_path):
    info, codes = read(tmp_path, tree({RT_ICON: {1: {0: b'x'}}}))
    assert (info.blocks, info.primary_index, info.contradictions) == ((), None, ()) and codes == set()


def test_version_text_formats_a_quad():
    assert version_text((10, 0, 19041, 1)) == '10.0.19041.1'


# -- several blocks ---------------------------------------------------------------------------------------------


def test_primary_block_is_the_lowest_name_then_language(tmp_path):
    def blob_for(name, lang):
        return version_blob((name, 0, 0, lang & 0xFF))
    root = tree({RT_VERSION: {2: {0x409: blob_for(2, 0x409)},
                              1: {0x409: blob_for(1, 0x409), 0x407: blob_for(1, 0x407)}}})
    info, _codes = read(tmp_path, root)
    assert [(b.leaf.name, b.leaf.lang) for b in info.blocks] == [(1, 0x407), (1, 0x409), (2, 0x409)]
    assert info.primary_index == 0 and info.blocks[0].fixed.file_version == (1, 0, 0, 7)


def test_named_version_resources_sort_after_numeric_ones(tmp_path):
    root = tree({RT_VERSION: {Name('ALPHA'): {0: version_blob((9, 0, 0, 0))}, 5: {0: version_blob((5, 0, 0, 0))}}})
    info, _codes = read(tmp_path, root)
    assert [b.leaf.name for b in info.blocks] == [5, 'ALPHA']
    assert info.blocks[info.primary_index].fixed.file_version == (5, 0, 0, 0)


def test_blocks_that_agree_have_no_contradictions(tmp_path):
    blob = version_blob(strings=standard_strings())
    info, _codes = read(tmp_path, tree({RT_VERSION: {1: {0x409: blob, 0x407: blob}}}))
    assert len(info.blocks) == 2 and info.contradictions == ()


def test_disagreeing_blocks_are_all_kept_and_the_disagreement_listed(tmp_path):
    old = version_blob((1, 0, 0, 1), (1, 0, 0, 1), strings=standard_strings('1.0.0.1'))
    new = version_blob((2, 0, 0, 1), (2, 0, 0, 1), strings=standard_strings('2.0.0.1'))
    info, _codes = read(tmp_path, tree({RT_VERSION: {1: {0x407: old, 0x409: new}}}))
    assert len(info.blocks) == 2
    assert info.contradictions == ('fixed_disagree:file_version', 'fixed_disagree:product_version',
                                   'string_disagree:FileVersion', 'string_disagree:ProductVersion')


@pytest.mark.parametrize('fixed,text,flagged', [
    ((10, 0, 19041, 1), '10.0.19041.1 (WinBuild.160101.0800)', False),
    ((1, 0, 0, 1), '1, 0, 0, 1', False),
    ((1, 0, 0, 0), '1', False),
    ((2, 5, 1, 0), '2.5.1 beta', False),
    ((2, 0, 0, 0), 'v2', False),
    ((1, 0, 0, 1), '1.0', True),
    ((1, 2, 3, 4), '1.2.3.5', True),
    ((0, 0, 0, 0), '1.0.0.0', True),
], ids=['build-lab-suffix', 'comma-separated', 'one-part', 'trailing-words', 'not-comparable', 'padded-mismatch',
        'last-part-differs', 'zero-fixed'])
def test_file_version_string_is_compared_with_the_fixed_version(tmp_path, fixed, text, flagged):
    strings = {'040904B0': {'FileVersion': text}}
    info, _codes = read(tmp_path, tree({RT_VERSION: {1: {0: version_blob(fixed, strings=strings)}}}))
    assert info.contradictions == (('fixed_vs_string:FileVersion',) if flagged else ())


# -- hostile text ---------------------------------------------------------------------------------------------


def test_values_keep_unicode_and_lose_controls_and_bidi_controls(tmp_path):
    text = 'café \U0001f600 a‮b\x07c⁦d\ud800e\n'
    block, _codes = one(tmp_path, version_blob(strings={'040904B0': {'Comments': text}}))
    assert values(block)['Comments'] == 'café \U0001f600 abcd�e'


def test_hostile_keys_are_cleaned_too(tmp_path):
    block, _codes = one(tmp_path, version_blob(strings={'040904B0': {'Com‮ments\x07': 'x'}}))
    assert [s.key for s in block.strings] == ['Comments']


def test_long_values_and_keys_are_cut_and_flagged(tmp_path):
    strings = {'040904B0': {'Comments': 'v' * 3000, 'K' * 400: 'short'}}
    block, _codes = one(tmp_path, version_blob(strings=strings))
    long_value, long_key = block.strings
    assert len(long_value.value) == 1024 and long_value.truncated is True
    assert len(long_key.key) == 256 and long_key.truncated is True and long_key.value == 'short'


def test_only_the_first_keys_of_a_table_are_read(tmp_path):
    strings = {'040904B0': {f'Key{i:03d}': str(i) for i in range(100)}}
    block, codes = one(tmp_path, version_blob(strings=strings))
    assert len(block.strings) == 64 and 'version_over_cap' in codes and block.status == 'partial'
    assert 'version_over_cap' in block.warnings


# -- hostile structure --------------------------------------------------------------------------------------------


def child_blob(extra: bytes) -> bytes:
    table = string_table('040904B0', {'FileVersion': '1.0.0.1'})
    return node('VS_VERSION_INFO', fixed_file_info(), wtype=0, children=[node('StringFileInfo', children=[table]), extra])


def patched(blob: bytes, key: str, fmt: str, value: int, delta: int = 0) -> bytes:
    out = bytearray(blob)
    struct.pack_into(fmt, out, locate(blob, key) + delta, value)
    return bytes(out)


GOOD = version_blob(strings=standard_strings())
SHORT_VALUE_LENGTH = patched(GOOD, 'VS_VERSION_INFO', '<H', 20, delta=2)

HOSTILE = {
    'root-key-wrong': (version_blob(root_key='VS_VERSION_INFX', strings=standard_strings()), 'malformed',
                       'version_key_mismatch'),
    'zero-length-child': (child_blob(bytes(12)), 'partial', 'version_block_malformed'),
    'child-below-header': (child_blob(struct.pack('<HHH', 3, 0, 1) + bytes(6)), 'partial', 'version_block_malformed'),
    'child-longer-than-parent': (patched(GOOD, 'StringFileInfo', '<H', 0xFFF0), 'partial', 'version_block_malformed'),
    'root-longer-than-data': (GOOD[:-20], 'partial', 'version_block_malformed'),
    'fixed-length-short': (SHORT_VALUE_LENGTH, 'malformed', 'version_block_malformed'),
    'fixed-signature-wrong': (version_blob(strings=standard_strings(), signature=0xDEADBEEF), 'partial',
                              'version_block_malformed'),
    'table-key-not-hex': (version_blob(strings={'ZZZZZZZZ': {'FileVersion': '1.0.0.1'}}), 'partial',
                          'version_key_mismatch'),
    'root-key-unterminated': (node('VS_VERSION_INFO'.encode('utf-16-le'), b'', wtype=0), 'malformed',
                              'version_block_malformed'),
    'fixed-beyond-root-length': (patched(GOOD, 'VS_VERSION_INFO', '<H', 50), 'malformed', 'version_block_malformed'),
    'cut-inside-fixed-info': (GOOD[:60], 'malformed', 'version_block_malformed'),
}


@pytest.mark.parametrize('name', list(HOSTILE))
def test_hostile_structure_is_reported_and_never_raises(tmp_path, name):
    blob, status, code = HOSTILE[name]
    began = time.perf_counter()
    block, codes = one(tmp_path, blob)
    assert time.perf_counter() - began <= BUDGET_S
    assert block.status == status and code in block.warnings and code in codes
    if status == 'malformed':
        assert block.fixed is None and block.strings == ()


def test_a_wrong_fixed_signature_gives_no_fixed_info_but_keeps_the_strings(tmp_path):
    block, _codes = one(tmp_path, HOSTILE['fixed-signature-wrong'][0])
    assert block.fixed is None and values(block)['FileVersion'] == '1.0.0.1'


def test_a_lying_child_length_keeps_what_was_read_before_it(tmp_path):
    block, _codes = one(tmp_path, HOSTILE['zero-length-child'][0])
    assert values(block) == {'FileVersion': '1.0.0.1'} and block.fixed is not None


def test_odd_unterminated_and_surrogate_values_are_decoded_leniently(tmp_path):
    table = node('040904B0', children=[
        node('Odd', utf16z('abc') + b'\x41', value_length=5),
        node('Unterminated', 'xyz'.encode('utf-16-le'), value_length=3),
        string_node('Lone', 'a\ud800b'),
        node('Empty', b'', value_length=0)])
    blob = node('VS_VERSION_INFO', fixed_file_info(), wtype=0, children=[node('StringFileInfo', children=[table])])
    block, _codes = one(tmp_path, blob)
    assert values(block) == {'Odd': 'abc', 'Unterminated': 'xyz', 'Lone': 'a�b', 'Empty': ''}


def test_a_string_key_without_a_terminator_does_not_disturb_its_siblings(tmp_path):
    glued = node('FileVersion'.encode('utf-16-le'), utf16z('1.0'), value_length=4)
    table = node('040904B0', children=[glued, string_node('ProductName', 'P')])
    blob = node('VS_VERSION_INFO', fixed_file_info(), wtype=0, children=[node('StringFileInfo', children=[table])])
    block, _codes = one(tmp_path, blob)
    assert values(block)['ProductName'] == 'P' and block.fixed is not None


def test_leaf_data_outside_the_image_is_unreadable_not_empty(tmp_path):
    root = tree({RT_VERSION: {1: {0: Data(b'', rva=0xFFFF0000, size=200)}}})
    info, codes = read(tmp_path, root)
    (block,) = info.blocks
    assert block.status == 'unreadable' and block.fixed is None and 'version_block_malformed' in codes


def test_an_empty_leaf_is_malformed(tmp_path):
    block, _codes = one(tmp_path, b'')
    assert block.status == 'malformed' and block.fixed is None


# -- limits ---------------------------------------------------------------------------------------------------


def test_a_leaf_over_the_byte_cap_is_read_up_to_the_cap(tmp_path):
    block, codes = one(tmp_path, version_blob(strings=standard_strings()) + bytes(100_000))
    assert 'version_over_cap' in codes and block.status == 'partial'
    assert block.fixed.file_version == (1, 0, 0, 1) and len(block.strings) == 7


def test_a_structure_cut_by_the_byte_cap_keeps_the_parsed_prefix(tmp_path):
    block, codes = one(tmp_path, GOOD, ResourceLimits(max_version_bytes=120))
    assert block.fixed is not None and 'version_over_cap' in codes and block.status == 'partial'


def test_declared_size_far_beyond_the_file_is_clipped_to_the_cap(tmp_path):
    root = tree({RT_VERSION: {1: {0: Data(GOOD, size=0xFFFFFFF0)}}})
    (block,) = read(tmp_path, root)[0].blocks
    assert block.fixed is not None and values(block)['FileVersion'] == '1.0.0.1'


def test_only_sixteen_blocks_are_read(tmp_path):
    root = tree({RT_VERSION: {1: {lang: GOOD for lang in range(1, 21)}}})
    info, codes = read(tmp_path, root)
    assert len(info.blocks) == 16 and 'version_over_cap' in codes
    assert [b.leaf.lang for b in info.blocks] == list(range(1, 17))


# -- parity ---------------------------------------------------------------------------------------------------------


def parity_trees():
    good = version_blob((10, 0, 19041, 1), (10, 0, 19041, 2), strings=standard_strings('10.0.19041.1'))
    other = version_blob((3, 1, 4, 1), (3, 1, 4, 1))
    return {
        'single': tree({RT_VERSION: {1: {LANG_EN_US: good}}}),
        'lowest-name-wins': tree({RT_VERSION: {7: {LANG_EN_US: other}, 3: {LANG_EN_US: good}}}),
        'lowest-language-wins': tree({RT_VERSION: {1: {0x409: other, 0x407: good}}}),
        'named-entry-ignored': tree({RT_VERSION: {Name('FIRST'): {0: other}, 2: {0: good}}}),
        'no-fixed-info': tree({RT_VERSION: {1: {0: version_blob(fixed=False, strings=standard_strings())}}}),
        'wrong-root-key': tree({RT_VERSION: {1: {0: version_blob(root_key='VS_VERSION_INFX')}}}),
        'bad-signature': tree({RT_VERSION: {1: {0: version_blob(signature=0x1234)}}}),
        'no-version': tree({RT_ICON: {1: {0: b'x'}}}),
    }


@pytest.mark.parametrize('case', list(parity_trees()))
def test_primary_block_agrees_with_the_csaf_identity_reader(tmp_path, case):
    data, _info = rsrc_pe(parity_trees()[case])
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        info = parse_version_info(pe.ctx, pe.smap, inventory)
        csaf = read_version_info(pe.reader, pe.overview)
    fixed = info.blocks[info.primary_index].fixed if info.primary_index is not None else None
    mine = (version_text(fixed.file_version), version_text(fixed.product_version)) if fixed else (None, None)
    assert mine == (csaf.file_version, csaf.product_version)


def assert_block_matches_pefile(pefile, tmp_path, data):
    """The single version block of `data` equals pefile's reading (tables compared by upper-cased key)."""
    pe = pefile.PE(data=data)
    fixed = pe.VS_FIXEDFILEINFO[0]
    expected_tables = {table.LangID.decode().upper(): {k.decode(): v.decode() for k, v in table.entries.items()}
                       for info in pe.FileInfo[0] if info.Key == b'StringFileInfo' for table in info.StringTable}
    with open_pe(tmp_path, data) as opened:
        inventory = parse_resources(opened.ctx, opened.smap, opened.resource.rva, opened.resource.size)
        (block,) = parse_version_info(opened.ctx, opened.smap, inventory).blocks
    ours = block.fixed
    assert [fixed.FileVersionMS, fixed.FileVersionLS, fixed.ProductVersionMS, fixed.ProductVersionLS] == [
        ours.file_version[0] << 16 | ours.file_version[1], ours.file_version[2] << 16 | ours.file_version[3],
        ours.product_version[0] << 16 | ours.product_version[1], ours.product_version[2] << 16 | ours.product_version[3]]
    assert (fixed.FileFlagsMask, fixed.FileFlags, fixed.FileOS, fixed.FileType, fixed.FileSubtype) == (
        ours.flags_mask, ours.flags, ours.os, ours.type, ours.subtype)
    mine: dict[str, dict[str, str]] = {}
    for item in block.strings:
        mine.setdefault(item.lang_codepage, {})[item.key] = item.value
    assert mine == expected_tables
    return block


def test_agrees_with_pefile_on_builder_versions(tmp_path):
    pefile = pytest.importorskip('pefile')
    strings = {'040904B0': {'CompanyName': 'Example Corp', 'FileVersion': '10.0.19041.1'},
               '040704B0': {'CompanyName': 'Beispiel GmbH', 'FileVersion': '10.0.19041.1'}}
    blob = version_blob((10, 0, 19041, 1), (10, 0, 19041, 2), strings=strings, flags=0x2, file_os=0x40004)
    data, _info = rsrc_pe(tree({RT_VERSION: {1: {LANG_EN_US: blob}}}))
    block = assert_block_matches_pefile(pefile, tmp_path, data)
    assert block.fixed.file_version == (10, 0, 19041, 1) and block.fixed.product_version == (10, 0, 19041, 2)


def test_agrees_with_pefile_on_real_windows_launchers(tmp_path):
    pefile = pytest.importorskip('pefile')
    versioned = [path for path in real_launchers() if hasattr(pefile.PE(path, fast_load=False), 'VS_FIXEDFILEINFO')]
    if not versioned:
        pytest.skip('this pip carries no distlib launcher executables with a version resource')
    for launcher in versioned:
        block = assert_block_matches_pefile(pefile, tmp_path, launcher.read_bytes())
        assert block.status == 'ok' and block.strings, launcher.name


# -- never raises -------------------------------------------------------------------------------------------------


def test_mutated_version_blobs_never_raise_and_stay_bounded(tmp_path):
    blob = version_blob((10, 0, 19041, 1), strings=standard_strings())
    for seed in range(120):
        mutated = mutate(blob, seed, flips=1 + seed % 10)
        began = time.perf_counter()
        block, _codes = one(tmp_path, mutated)
        assert time.perf_counter() - began <= BUDGET_S * 4
        assert block.status in ('ok', 'partial', 'malformed')
        json.dumps(asdict(block))


@FAST
@given(st.binary(min_size=0, max_size=400))
def test_arbitrary_version_bytes_never_raise(blob):
    data, _info = rsrc_pe(tree({RT_VERSION: {1: {0: Data(blob)}}}))
    with tempfile.TemporaryDirectory() as folder, open_pe(Path(folder), data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        info = parse_version_info(pe.ctx, pe.smap, inventory)
        assert len(info.blocks) == 1
