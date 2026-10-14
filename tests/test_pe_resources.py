"""Resource tree reader: well-formed trees, hostile trees, limits, cancellation and parity with pefile."""
from __future__ import annotations

import json
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_builder import PeSpec, SectionSpec
from pe_rsrc_builder import (
    HIGH,
    LANG_EN_US,
    RT_ICON,
    RT_MANIFEST,
    RT_RCDATA,
    RT_VERSION,
    Data,
    Dir,
    Name,
    Raw,
    leaf_file_offset,
    mutate,
    open_pe,
    real_launchers,
    rsrc_pe,
    tree,
    version_blob,
)

from patchtrace.artifact_bytes import ArtifactBytesError
from patchtrace.pe_overview import Limits
from patchtrace.pe_overview._common import Cancelled, Ctx
from patchtrace.pe_overview.resources import (
    DEFAULT_RESOURCE_LIMITS,
    ResourceLimits,
    leaves_of_type,
    parse_resources,
    read_leaf,
    sanitize_text,
)

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
PE_STUB = b'MZ' + bytes(100)
BUDGET_S = 0.25


def walk(tmp_path, data, limits=DEFAULT_RESOURCE_LIMITS):
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size, limits)
        return inventory, pe.codes()


def timed(tmp_path, data, limits=DEFAULT_RESOURCE_LIMITS, runs=3):
    """Best of a few runs of the walk alone (file open and header parse excluded), to ignore transient load."""
    best = float('inf')
    with open_pe(tmp_path, data) as pe:
        for _ in range(runs):
            ctx = Ctx(pe.reader, None, Limits())
            start = time.perf_counter()
            inventory = parse_resources(ctx, pe.smap, pe.resource.rva, pe.resource.size, limits)
            best = min(best, time.perf_counter() - start)
        return inventory, {w.code for w in ctx.warnings}, best


def sample_tree() -> Dir:
    return tree({
        RT_ICON: {1: {LANG_EN_US: b'icon-bytes'}, 2: {LANG_EN_US: b'second icon', 0x407: b'german icon'}},
        RT_RCDATA: {Name('PAYLOAD'): {0: Data(PE_STUB, codepage=1252)}},
        RT_VERSION: {1: {LANG_EN_US: version_blob()}},
        RT_MANIFEST: {1: {LANG_EN_US: b'<assembly/>'}},
        300: {5: {LANG_EN_US: b'unknown type'}},
        Name('CUSTOM'): {7: {0: b'zz'}},
    })


def keys(inventory):
    return [(leaf.type_id, leaf.type_label, leaf.name, leaf.lang, leaf.size, leaf.codepage)
            for leaf in inventory.leaves]


# -- well-formed trees --------------------------------------------------------------------------------------


def test_leaves_carry_type_name_language_size_and_codepage(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    inventory, codes = walk(tmp_path, data)
    assert codes == set() and inventory.truncated is False
    assert keys(inventory) == [
        (RT_ICON, 'RT_ICON', 1, LANG_EN_US, 10, 0),
        (RT_ICON, 'RT_ICON', 2, 0x407, 11, 0),
        (RT_ICON, 'RT_ICON', 2, LANG_EN_US, 11, 0),
        (RT_RCDATA, 'RT_RCDATA', 'PAYLOAD', 0, len(PE_STUB), 1252),
        (RT_VERSION, 'RT_VERSION', 1, LANG_EN_US, len(version_blob()), 0),
        (RT_MANIFEST, 'RT_MANIFEST', 1, LANG_EN_US, 11, 0),
        (300, '#300', 5, LANG_EN_US, 12, 0),
        (None, 'name:CUSTOM', 7, 0, 2, 0),
    ]


def test_leaf_offsets_point_at_the_declared_bytes(tmp_path):
    data, info = rsrc_pe(sample_tree())
    inventory, _codes = walk(tmp_path, data)
    for leaf in inventory.leaves:
        assert leaf.offset == leaf_file_offset(info, leaf.rva)
    icon = leaves_of_type(inventory, RT_ICON)[0]
    assert data[icon.offset:icon.offset + icon.size] == b'icon-bytes'


def test_by_type_counts_and_declared_bytes(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    inventory, _codes = walk(tmp_path, data)
    assert inventory.by_type == (
        ('RT_ICON', 3, 10 + 11 + 11), ('RT_RCDATA', 1, len(PE_STUB)), ('RT_VERSION', 1, len(version_blob())),
        ('RT_MANIFEST', 1, 11), ('#300', 1, 12), ('name:CUSTOM', 1, 2))


def test_leaves_of_type_selects_numeric_types_only(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    inventory, _codes = walk(tmp_path, data)
    assert [leaf.name for leaf in leaves_of_type(inventory, RT_ICON)] == [1, 2, 2]
    assert leaves_of_type(inventory, 999) == ()


def test_embedded_pe_is_sniffed_in_opaque_types_only(tmp_path):
    root = tree({
        RT_RCDATA: {1: {0: Data(PE_STUB)}, 2: {0: Data(b'MZ')}, 3: {0: Data(b'PK' + bytes(100))}},
        RT_ICON: {1: {0: Data(PE_STUB)}},
        Name('BIN'): {1: {0: Data(PE_STUB)}},
    })
    data, _info = rsrc_pe(root)
    inventory, _codes = walk(tmp_path, data)
    assert [(leaf.type_label, leaf.name) for leaf in inventory.embedded_pe] == [('RT_RCDATA', 1), ('name:BIN', 1)]


def test_shallow_and_four_level_trees_are_accepted(tmp_path):
    data, _info = rsrc_pe(tree({RT_RCDATA: {1: Data(b'x')}, RT_VERSION: {1: {LANG_EN_US: {7: Data(b'y')}}}}))
    inventory, codes = walk(tmp_path, data)
    assert codes == set()
    assert [(leaf.type_id, leaf.name, leaf.lang) for leaf in inventory.leaves] == [
        (RT_RCDATA, 1, None), (RT_VERSION, 1, LANG_EN_US)]


def test_depth_beyond_the_cap_is_reported_not_followed(tmp_path):
    data, _info = rsrc_pe(tree({RT_VERSION: {1: {LANG_EN_US: {7: {8: Data(b'deep')}}}}, RT_ICON: {1: {0: b'ok'}}}))
    inventory, codes = walk(tmp_path, data)
    assert 'resource_depth_over_cap' in codes and inventory.truncated is True
    assert [leaf.type_id for leaf in inventory.leaves] == [RT_ICON]


def test_duplicate_ids_keep_every_leaf(tmp_path):
    lang = Dir([(LANG_EN_US, Data(b'first')), (LANG_EN_US, Data(b'second'))], keep_order=True)
    data, _info = rsrc_pe(Dir([(RT_VERSION, Dir([(1, lang)]))]))
    inventory, _codes = walk(tmp_path, data)
    assert [leaf.size for leaf in inventory.leaves] == [5, 6]


def reversed_copy(directory: Dir) -> Dir:
    entries = [(key, reversed_copy(target) if isinstance(target, Dir) else target)
               for key, target in reversed(directory.entries)]
    return Dir(entries, keep_order=True)


def test_leaf_order_does_not_depend_on_entry_order_in_the_file(tmp_path):
    ordered, _info = rsrc_pe(sample_tree())
    reversed_pe, _info = rsrc_pe(reversed_copy(sample_tree()))
    a, _codes = walk(tmp_path, ordered)
    b, _codes = walk(tmp_path, reversed_pe)
    assert keys(a) == keys(b) and len(keys(a)) == 8


def test_packed_style_layout_with_virtual_only_section(tmp_path):
    spec = PeSpec(sections=[SectionSpec('UPX0', b'', raw_size=0, virtual_size=0x20000), SectionSpec('UPX1')])
    data, info = rsrc_pe(sample_tree(), spec=spec)
    inventory, codes = walk(tmp_path, data)
    assert codes == set() and len(inventory.leaves) == 8
    assert info['rsrc_rva'] == 0x1000 + 0x20000 + 0x1000


def test_result_is_deterministic_and_json_serializable(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    first, _codes = walk(tmp_path, data)
    second, _codes = walk(tmp_path, data)
    assert first == second
    json.dumps(asdict(first))


def test_default_limits_match_the_card():
    lim = DEFAULT_RESOURCE_LIMITS
    assert (lim.max_nodes, lim.max_depth, lim.max_dir_entries, lim.max_name_chars) == (20_000, 4, 4_096, 256)
    assert (lim.max_version_bytes, lim.max_manifest_bytes, lim.max_hash_bytes) == (65_536, 2_097_152, 16_777_216)
    assert (lim.max_rich_entries, lim.max_exports, lim.time_budget_s) == (256, 20_000, 2.0)


# -- structure the file does not back ---------------------------------------------------------------------------


def test_directory_outside_the_image_is_unreadable(tmp_path):
    data, _info = rsrc_pe(sample_tree(), declared_rva=0x90000)
    inventory, codes = walk(tmp_path, data)
    assert inventory is None and 'resource_dir_unreadable' in codes


def test_declared_size_beyond_the_section_is_clipped_to_the_backed_bytes(tmp_path):
    data, _info = rsrc_pe(sample_tree(), declared_size=0xFFFFFF00)
    inventory, codes = walk(tmp_path, data)
    assert len(inventory.leaves) == 8 and codes == set()


def test_structures_beyond_the_declared_size_are_not_followed(tmp_path):
    _blob, info = rsrc_pe(sample_tree())
    data, _info = rsrc_pe(sample_tree(), declared_size=info['rsrc_size'] // 2)
    inventory, codes = walk(tmp_path, data)
    assert len(inventory.leaves) < 8 and 'resource_dir_unreadable' in codes and inventory.truncated is True


def test_declared_size_smaller_than_a_header_is_unreadable(tmp_path):
    data, _info = rsrc_pe(sample_tree(), declared_size=8)
    inventory, codes = walk(tmp_path, data)
    assert inventory is None and 'resource_dir_unreadable' in codes


def test_leaf_data_outside_the_image_keeps_its_declaration(tmp_path):
    data, _info = rsrc_pe(tree({RT_RCDATA: {1: {0: Data(b'', rva=0xFFFF0000, size=8)}}}))
    inventory, codes = walk(tmp_path, data)
    (leaf,) = inventory.leaves
    assert (leaf.rva, leaf.size, leaf.offset) == (0xFFFF0000, 8, None)
    assert codes == set()


@pytest.mark.parametrize('target', [
    Raw(0x7FFFFF00, directory=True), Raw(0x7FFFFF00), Raw(0x7FFFFFF8, directory=True)],
    ids=['dir-far', 'data-far', 'dir-at-31-bit-edge'])
def test_wild_entry_offsets_are_reported_not_followed(tmp_path, target):
    root = Dir([(RT_ICON, Dir([(1, Dir([(LANG_EN_US, Data(b'good'))]))])), (RT_RCDATA, target)])
    data, _info = rsrc_pe(root)
    inventory, codes = walk(tmp_path, data)
    assert [leaf.type_id for leaf in inventory.leaves][:1] == [RT_ICON]
    assert inventory.truncated is True or 'resource_dir_unreadable' in codes


def test_name_offset_outside_the_window_becomes_a_placeholder(tmp_path):
    entry_key = HIGH | 0x7FFF0000
    root = Dir([(RT_ICON, Dir([(entry_key, Data(b'x'))]))])
    data, _info = rsrc_pe(root)
    inventory, codes = walk(tmp_path, data)
    (leaf,) = inventory.leaves
    assert leaf.name == '<unreadable name @ 0x7fff0000>'
    assert 'resource_dir_unreadable' in codes


def test_declared_counts_larger_than_the_directory_are_clipped(tmp_path):
    inner = Dir([(1, Data(b'a')), (2, Data(b'b')), (3, Data(b'c'))], ids=60_000)
    data, _info = rsrc_pe(Dir([(RT_RCDATA, inner)]))
    inventory, codes = walk(tmp_path, data)
    assert {1, 2, 3} <= {leaf.name for leaf in inventory.leaves}
    assert inventory.truncated is True and codes & {'resource_dir_unreadable', 'resource_nodes_over_cap'}


def test_unreadable_data_entry_drops_the_leaf_and_marks_truncation(tmp_path):
    root = Dir([(RT_RCDATA, Dir([(1, Raw(0x7FFFF000)), (2, Data(b'fine'))]))])
    data, _info = rsrc_pe(root)
    inventory, codes = walk(tmp_path, data)
    assert [leaf.name for leaf in inventory.leaves] == [2]
    assert inventory.truncated is True and 'resource_dir_unreadable' in codes


# -- hostile trees ----------------------------------------------------------------------------------------------


def test_cycles_are_walked_once(tmp_path):
    loop = Dir()
    root = Dir([(RT_RCDATA, loop)])
    loop.entries = [(1, loop), (2, root), (3, Dir([(LANG_EN_US, Data(b'fine'))]))]
    data, _info = rsrc_pe(root)
    inventory, codes, elapsed = timed(tmp_path, data)
    assert [(leaf.name, leaf.lang) for leaf in inventory.leaves] == [(3, LANG_EN_US)]
    assert 'resource_cycle_skipped' in codes and inventory.truncated is True
    assert elapsed <= BUDGET_S


def test_shared_subtree_is_reported_and_not_walked_twice(tmp_path):
    shared = Dir([(LANG_EN_US, Data(b'shared'))])
    root = Dir([(RT_VERSION, Dir([(1, shared), (2, shared)]))])
    data, _info = rsrc_pe(root)
    inventory, codes = walk(tmp_path, data)
    assert [(leaf.name, leaf.lang) for leaf in inventory.leaves] == [(1, LANG_EN_US)]
    assert 'resource_cycle_skipped' in codes and inventory.truncated is True


def test_exponential_dag_costs_linear_time(tmp_path):
    layer = [Dir([(1, Data(b'x'))]), Dir([(1, Data(b'y'))])]
    for _ in range(30):
        layer = [Dir([(1, layer[0]), (2, layer[1])]) for _ in range(2)]
    data, _info = rsrc_pe(Dir([(1, layer[0]), (2, layer[1])]))
    inventory, codes, elapsed = timed(tmp_path, data, ResourceLimits(max_depth=64))
    assert len(inventory.leaves) == 2 and 'resource_cycle_skipped' in codes
    assert elapsed <= BUDGET_S


def test_fan_at_the_entry_cap_is_read_in_time(tmp_path):
    fan = Dir([(i, Data(b'x')) for i in range(1, 4097)])
    data, _info = rsrc_pe(Dir([(RT_RCDATA, fan)]))
    inventory, codes, elapsed = timed(tmp_path, data)
    assert len(inventory.leaves) == 4096 and codes == set() and inventory.truncated is False
    assert elapsed <= BUDGET_S


def test_fan_over_the_entry_cap_is_cut_and_reported(tmp_path):
    fan = Dir([(i, Data(b'x')) for i in range(1, 80)])
    data, _info = rsrc_pe(Dir([(RT_RCDATA, fan)]))
    inventory, codes = walk(tmp_path, data, ResourceLimits(max_dir_entries=50))
    assert len(inventory.leaves) == 50 and 'resource_nodes_over_cap' in codes and inventory.truncated is True


def test_fan_of_named_entries_sharing_one_huge_name(tmp_path):
    huge = 'N' * 65_535
    fan = Dir([(huge, Data(b'x')) for _ in range(4096)])
    data, _info = rsrc_pe(Dir([(RT_RCDATA, fan)]))
    inventory, codes, elapsed = timed(tmp_path, data)
    assert len(inventory.leaves) == 4096
    assert all(isinstance(leaf.name, str) and len(leaf.name) <= 256 for leaf in inventory.leaves)
    assert 'resource_name_truncated' in codes
    assert elapsed <= BUDGET_S


def test_length_field_larger_than_the_written_name_is_bounded(tmp_path):
    root = Dir([(RT_ICON, Dir([(Name('short', length=0xFFFF), Data(b'x'))]))])
    data, _info = rsrc_pe(root)
    inventory, codes, elapsed = timed(tmp_path, data)
    (leaf,) = inventory.leaves
    assert len(leaf.name) <= 256 and 'resource_name_truncated' in codes
    assert elapsed <= BUDGET_S


def test_giant_declared_size_is_kept_and_reads_are_clipped_to_the_file(tmp_path):
    root = tree({RT_RCDATA: {1: {0: Data(b'abc', size=0xFFFFFFF0)}}})
    data, info = rsrc_pe(root)
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        (leaf,) = inventory.leaves
        assert leaf.size == 0xFFFFFFF0 and inventory.by_type == (('RT_RCDATA', 1, 0xFFFFFFF0),)
        start = time.perf_counter()
        body = read_leaf(pe.ctx, pe.smap, leaf, 1 << 20)
        assert time.perf_counter() - start <= BUDGET_S
        backed_end = info['rsrc_rva'] + info['rsrc_size']
        assert len(body) == backed_end - leaf.rva and body.startswith(b'abc')


def test_read_leaf_honours_the_byte_cap_and_unbacked_leaves(tmp_path):
    payload = bytes(range(256)) * 8
    root = tree({RT_RCDATA: {1: {0: payload}, 2: {0: Data(b'', rva=0xFFFF0000, size=64)}, 3: {0: b''}}})
    data, _info = rsrc_pe(root)
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        first, second, third = inventory.leaves
        assert read_leaf(pe.ctx, pe.smap, first, 100) == payload[:100]
        assert read_leaf(pe.ctx, pe.smap, first, 1 << 20) == payload
        assert read_leaf(pe.ctx, pe.smap, second, 1 << 20) == b''
        assert read_leaf(pe.ctx, pe.smap, third, 1 << 20) == b''


def test_node_limit_stops_the_walk(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    inventory, codes = walk(tmp_path, data, ResourceLimits(max_nodes=15))
    assert 'resource_nodes_over_cap' in codes and inventory.truncated is True
    assert 0 < len(inventory.leaves) < 8


def test_node_limit_boundary_is_exact(tmp_path):
    data, _info = rsrc_pe(tree({RT_RCDATA: {1: b'payload'}}))  # three nodes: root, type directory, data entry
    exact, codes = walk(tmp_path, data, ResourceLimits(max_nodes=3))
    assert len(exact.leaves) == 1 and codes == set() and exact.truncated is False
    short, codes = walk(tmp_path, data, ResourceLimits(max_nodes=2))
    assert short.leaves == () and 'resource_nodes_over_cap' in codes


def test_name_reads_never_exceed_the_name_cap(tmp_path):
    root = Dir([(RT_ICON, Dir([(Name('N' * 65_535), Data(b'x'))]))])
    data, _info = rsrc_pe(root)
    with open_pe(tmp_path, data) as pe:
        lengths = []
        original = pe.reader.read
        pe.reader.read = lambda offset, length, **kw: lengths.append(length) or original(offset, length, **kw)
        parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
    assert lengths and max(lengths) <= 2 + 2 * DEFAULT_RESOURCE_LIMITS.max_name_chars


def test_numeric_ids_use_the_low_sixteen_bits_like_the_loader(tmp_path):
    data, _info = rsrc_pe(Dir([(0x10000 | RT_VERSION, Dir([(0x20001, Dir([(0x30409, Data(b'x'))]))]))]))
    inventory, _codes = walk(tmp_path, data)
    (leaf,) = inventory.leaves
    assert (leaf.type_id, leaf.name, leaf.lang) == (RT_VERSION, 1, LANG_EN_US)


def test_leaf_data_is_located_up_to_the_last_backed_byte_only(tmp_path):
    def edge_tree(end):
        return tree({RT_RCDATA: {1: {0: Data(b'x' * 8)}, 2: {0: Data(b'', rva=end - 1, size=1)},
                                 3: {0: Data(b'', rva=end, size=1)}}})
    _probe, info = rsrc_pe(edge_tree(1))  # the layout does not depend on the overridden RVAs
    end = info['rsrc_rva'] + info['rsrc_size']
    data, _info = rsrc_pe(edge_tree(end))
    inventory, _codes = walk(tmp_path, data)
    offsets = {leaf.name: leaf.offset for leaf in inventory.leaves}
    assert offsets[2] == leaf_file_offset(info, end - 1) and offsets[3] is None


def test_time_budget_stops_the_walk(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    inventory, codes = walk(tmp_path, data, ResourceLimits(time_budget_s=0.0))
    assert 'metadata_time_budget' in codes and inventory.truncated is True and inventory.leaves == ()


def test_cancel_is_polled_for_every_directory(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    polls = []
    with open_pe(tmp_path, data, cancel=lambda: polls.append(1) or False) as pe:
        parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
    directories = 14  # sample_tree: the root, six type directories and seven name directories
    assert len(polls) >= directories
    with open_pe(tmp_path, data, cancel=lambda: True) as pe, pytest.raises(Cancelled):
        parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)


def test_reader_errors_propagate(tmp_path):
    data, _info = rsrc_pe(sample_tree())
    with open_pe(tmp_path, data) as pe:
        pe.reader.close()
        with pytest.raises(ArtifactBytesError) as exc:
            parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
    assert exc.value.code == 'closed'


# -- hostile text -----------------------------------------------------------------------------------------------


def test_names_are_decoded_leniently_and_cleaned(tmp_path):
    hostile = 'A‮B\x07C\ud800D⁦E\x85F\x00G'
    data, _info = rsrc_pe(Dir([(RT_RCDATA, Dir([(Name(hostile), Data(b'x'))]))]))
    inventory, _codes = walk(tmp_path, data)
    (leaf,) = inventory.leaves
    assert leaf.name == 'ABC�DEFG'


@pytest.mark.parametrize('raw,clean', [
    ('plain', 'plain'), ('a\tb\nc', 'abc'), ('a‮b‬c', 'abc'), ('x‎y‏z؜', 'xyz'),
    (' a ', 'a'), ('café \U0001f600', 'café \U0001f600'), ('a\x7fb\x9fc', 'abc')],
    ids=['plain', 'ascii-controls', 'bidi-embeddings', 'bidi-marks', 'line-separators', 'unicode-kept', 'del-and-c1'])
def test_sanitize_text_drops_controls_and_bidi_controls(raw, clean):
    assert sanitize_text(raw) == clean


# -- never raises -----------------------------------------------------------------------------------------------


def test_mutated_trees_never_raise_and_stay_bounded(tmp_path):
    base, info = rsrc_pe(sample_tree())
    start, end = info['rsrc_off'], info['rsrc_off'] + info['rsrc_size']
    for seed in range(80):
        mutated = mutate(base, seed, flips=1 + seed % 24, start=start, end=end)
        with open_pe(tmp_path, mutated) as pe:
            if pe.resource is None:
                continue
            began = time.perf_counter()
            inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
            assert time.perf_counter() - began <= BUDGET_S * 4
            if inventory is not None:
                json.dumps(asdict(inventory))


@FAST
@given(st.binary(min_size=0, max_size=700))
def test_arbitrary_resource_bytes_never_raise(blob):
    data, _info = rsrc_pe(blob or b'\0')
    with tempfile.TemporaryDirectory() as folder, open_pe(Path(folder), data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        assert inventory is None or isinstance(inventory.leaves, tuple)


# -- oracle -----------------------------------------------------------------------------------------------------


def pefile_leaves(pe) -> set[tuple]:
    def label(entry):
        return entry.name.decode() if entry.name else entry.id

    found = set()
    for kind in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in kind.directory.entries:
            for lang in name.directory.entries:
                leaf = lang.data.struct
                found.add((label(kind), label(name), lang.id, leaf.OffsetToData, leaf.Size, leaf.CodePage))
    return found


def own_leaves(inventory) -> set[tuple]:
    return {(leaf.type_id if leaf.type_id is not None else leaf.type_label.removeprefix('name:'), leaf.name, leaf.lang,
             leaf.rva, leaf.size, leaf.codepage) for leaf in inventory.leaves}


def test_agrees_with_pefile_on_builder_trees(tmp_path):
    pefile = pytest.importorskip('pefile')
    data, _info = rsrc_pe(sample_tree())
    inventory, _codes = walk(tmp_path, data)
    assert own_leaves(inventory) == pefile_leaves(pefile.PE(data=data)) and len(inventory.leaves) == 8


def test_agrees_with_pefile_on_real_windows_launchers(tmp_path):
    pefile = pytest.importorskip('pefile')
    launchers = real_launchers()
    if not launchers:
        pytest.skip('this pip carries no distlib launcher executables')
    for launcher in launchers:
        data = launcher.read_bytes()
        inventory, codes = walk(tmp_path, data)
        assert own_leaves(inventory) == pefile_leaves(pefile.PE(data=data)), launcher.name
        assert codes == set() and inventory.truncated is False and inventory.leaves, launcher.name
