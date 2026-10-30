"""SPEC-31 07 s3 code panes: the code text of a unified row, read from what the result stores. The project, the
hand-assembled functions and the sidecars are the synthetic ones of the wiring tests; the real pipeline publishes the
result, so the view model, the sidecar directories and the rows are the product's own. Decompiled C is stored by the
test with the product's own part writer (`store.write_part`), the way a decompiling run would."""
from __future__ import annotations

import dataclasses
import gzip
import subprocess
import sys
from types import SimpleNamespace

import pytest
from hypothesis import given
from hypothesis import strategies as st
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace.unified import pair_text, pipeline, store
from patchtrace.unified.contracts import SideRef
from patchtrace.unified.pair_text import DECOMPILED, DISASSEMBLY, RowCodeSource
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.read_model import load_unified, records_for, request_from_service


@pytest.fixture
def world(tmp_path):
    service = make_project(tmp_path / 'project')
    place_pair(service, scratch=tmp_path)
    pipeline.run_unified(service, UnifiedOptions(isolate=False))
    vm = load_unified(request_from_service(service, extraction_configured=True))
    source = RowCodeSource()
    yield vm, source
    source.close()
    service.close()


def row_named(vm, name):
    return next(r for r in vm.rows if name in r.function_label)


def with_decomp(vm, records):
    """The view model of a result that carries a `decomp.jsonl.gz` part with these `(side, rva, status, code)`."""
    part = store.write_part(vm.result_dir, pair_text.DECOMP_PART,
                            [{'side': s, 'rva': r, 'status': st_, 'code': c} for s, r, st_, c in records])
    manifest = vm.manifest.model_copy(update={'parts': (*vm.manifest.parts, part)})
    return dataclasses.replace(vm, manifest=manifest)


def rvas(vm, row):
    match = records_for(vm, [row])[row.row_id].match
    return match.older[0].rva, match.newer[0].rva


def rows_of(text):
    return text.split('\n')


# ---- disassembly with alignment gaps from the stored IR ------------------------------------------------------------


def test_the_module_has_no_qt():
    code = 'import sys, patchtrace.unified.pair_text; sys.exit(any(n.split(".")[0] == "PySide6" for n in sys.modules))'
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_a_changed_pair_aligns_the_stored_instructions_and_marks_only_the_changed_rows(world):
    vm, source = world
    channel = source(vm, row_named(vm, 'read_item')).disassembly
    pair = channel.pair
    older, newer = rows_of(pair.older), rows_of(pair.newer)
    assert len(older) == len(newer) == 7                      # one aligned row per line, gaps padded
    assert [(h.start, h.length, h.operation) for h in pair.hunks] == [(2, 2, 'replace')]
    assert older[3] == '' and 'CALL' in newer[3]               # the inserted call is a gap on the older side
    assert 'MOV' in older[0] and older[0][:8] == '00001000' and newer[0][:8] == '00001080'
    assert len(pair.older_map) == 6 and len(pair.newer_map) == 7 and 3 not in pair.older_map
    assert channel.label == 'Disassembly from ProgramIR (Ghidra 12.0.4)' and channel.reason == ''


def test_an_identical_function_has_no_hunk(world):
    vm, source = world
    pair = source(vm, row_named(vm, 'keep_same')).disassembly.pair
    assert pair.hunks == () and len(rows_of(pair.older)) == 6


def test_one_changed_instruction_is_one_single_row_hunk(world):
    vm, source = world
    pair = source(vm, row_named(vm, 'get_version')).disassembly.pair
    assert [(h.start, h.length) for h in pair.hunks] == [(0, 1)]
    assert 'MOV EAX,0x1' in rows_of(pair.older)[0] and 'MOV EAX,0x2' in rows_of(pair.newer)[0]


def test_a_one_sided_row_shows_its_code_against_an_honest_message(world):
    vm, source = world
    only_old = source(vm, row_named(vm, 'debug_dump')).disassembly
    assert only_old.pair.newer.startswith(pair_text.NO_FUNCTION) and 'MOV' in only_old.pair.older
    assert [(h.operation, h.length) for h in only_old.pair.hunks] == [('delete', 6)]
    assert only_old.pair.newer_map == () and only_old.provenance[1].startswith('Newer: no function')
    only_new = source(vm, row_named(vm, 'report_invalid_index')).disassembly
    assert only_new.pair.older.startswith(pair_text.NO_FUNCTION) and [h.operation for h in only_new.pair.hunks] == ['insert']


def test_each_side_has_a_provenance_line_with_function_source_and_digests(world):
    vm, source = world
    old, new = source(vm, row_named(vm, 'get_version')).disassembly.provenance
    assert old.startswith('Older: get_version at 0x1600 | Disassembly from ProgramIR (Ghidra 12.0.4) | ir ')
    assert new.startswith('Newer: get_version at 0x1700 |')
    for line, digest in ((old, vm.manifest.older_sha256), (new, vm.manifest.newer_sha256)):
        assert f'artifact {digest[:12]}' in line and f'result {vm.result_id[:12]}' in line and len(line) <= 400


def test_without_a_placed_programir_disassembly_is_unavailable_with_the_reason(world):
    vm, source = world
    bare = dataclasses.replace(vm, manifest=vm.manifest.model_copy(update={'ir_older': None, 'ir_newer': None}))
    channel = source(bare, bare.rows[0]).disassembly
    assert channel.pair is None and channel.reason == pair_text.NO_IR
    gone = source(dataclasses.replace(vm, result_dir=None), vm.rows[0])
    assert gone.disassembly.reason == gone.decompiled.reason == pair_text.NO_RESULT


def test_text_missing_from_the_ir_is_unavailable_never_invented(world, monkeypatch):
    vm, source = world
    monkeypatch.setattr(pair_text.IrReader, 'texts', lambda self, fid: [])
    channel = source(vm, row_named(vm, 'get_version')).disassembly
    assert channel.pair is None and channel.reason == pair_text.NOT_STORED


def test_a_function_missing_from_the_ir_is_named_as_such(world, monkeypatch):
    vm, source = world
    row = row_named(vm, 'get_version')
    ref = SideRef(rva=0x7777, kind='function')
    record = SimpleNamespace(match=SimpleNamespace(older=(ref,), newer=(ref,)))
    monkeypatch.setattr(pair_text, 'records_for', lambda _vm, _rows: {row.row_id: record})
    channel = source(vm, row).disassembly
    assert channel.pair is None and channel.reason == pair_text.NOT_IN_IR


def test_a_long_function_is_cut_and_the_pair_is_not_aligned(world, monkeypatch):
    vm, source = world
    monkeypatch.setattr(pair_text, 'MAX_LINES', 3)
    channel = source(vm, row_named(vm, 'get_version')).disassembly
    older = rows_of(channel.pair.older)
    assert older[-1].startswith('... ') and len(older) == 4
    assert channel.notes == (pair_text.NOT_ALIGNED,) and [h.length for h in channel.pair.hunks] == [4]


def test_readers_are_cached_per_ir_key_and_closed(world):
    vm, source = world
    source(vm, row_named(vm, 'get_version'))
    source(vm, row_named(vm, 'keep_same'))
    assert len(source._readers) == 2
    source.close()
    assert not source._readers and not source._decomp


# ---- decompiled C from the stored part ------------------------------------------------------------------------------


def c_records(vm, row, older, newer, status=('ok', 'ok')):
    o, n = rvas(vm, row)
    return [('older', o, status[0], older), ('newer', n, status[1], newer)]


def test_a_result_without_decompiled_text_says_so_and_never_fabricates(world):
    vm, source = world
    channel = source(vm, row_named(vm, 'get_version')).decompiled
    assert channel.pair is None and channel.reason == pair_text.NO_DECOMP and channel.label.startswith(
        'Decompiled on demand by Ghidra 12.0.4')


def test_stored_c_text_is_aligned_side_by_side_with_gaps(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    older = 'int f(int a) {\n  int b = a + 1;\n\n  return b;\n}'
    newer = 'int f(int a) {\n  int b = a + 1;\n  if (a > 9) {\n    return 0;\n  }\n\n  return b;\n}'
    stored = with_decomp(vm, c_records(vm, row, older, newer))
    channel = source(stored, row).decompiled
    pair = channel.pair
    assert len(rows_of(pair.older)) == len(rows_of(pair.newer)) == 8
    assert [(h.start, h.length, h.operation) for h in pair.hunks] == [(2, 3, 'insert')]
    assert rows_of(pair.older)[2:5] == ['', '', ''] and 'return 0;' in rows_of(pair.newer)[3]
    assert pair.older_map == (0, 1, 5, 6, 7) and pair.newer_map == tuple(range(8))
    assert channel.label == 'Decompiled on demand by Ghidra 12.0.4' and source(stored, row).channel(DECOMPILED) == channel
    assert source(stored, row).channel(DISASSEMBLY).channel == DISASSEMBLY
    assert channel.provenance[0].startswith('Older: get_version at 0x1600 | Decompiled on demand by Ghidra 12.0.4')


def test_empty_lines_do_not_shift_the_alignment(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, c_records(vm, row, 'a\n\n\nb\n\n', 'a\n\n\nc\n\n'))
    pair = source(stored, row).decompiled.pair
    assert [(h.start, h.length) for h in pair.hunks] == [(3, 1)] and len(rows_of(pair.older)) == 5


@pytest.mark.parametrize(('status', 'reason'), [
    (('timeout', 'ok'), pair_text.DECOMP_STATUS['timeout']),
    (('ok', 'failed'), pair_text.DECOMP_STATUS['failed'])], ids=['timeout', 'failed'])
def test_a_failed_side_is_named_and_the_other_side_still_shows(world, status, reason):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, c_records(vm, row, None if status[0] != 'ok' else 'int x;', None if status[1] != 'ok'
                                       else 'int y;', status))
    pair = source(stored, row).decompiled.pair
    shown = pair.older if status[0] == 'ok' else pair.newer
    other = pair.newer if status[0] == 'ok' else pair.older
    assert shown.startswith('int') and other.startswith(reason)


def test_both_sides_failed_is_unavailable_with_both_reasons(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, c_records(vm, row, None, None, ('timeout', 'failed')))
    channel = source(stored, row).decompiled
    assert channel.pair is None and pair_text.DECOMP_STATUS['timeout'] in channel.reason
    assert pair_text.DECOMP_STATUS['failed'] in channel.reason


def test_a_function_the_decompile_skipped_is_named(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, [('older', 0x7777, 'ok', 'int x;')])
    assert source(stored, row).decompiled.reason == pair_text.DECOMP_MISSING


def test_a_one_sided_row_shows_its_c_against_no_function(world):
    vm, source = world
    row = row_named(vm, 'debug_dump')
    older_rva = rvas_side(vm, row)
    stored = with_decomp(vm, [('older', older_rva, 'ok', 'void g(void) {\n}')])
    pair = source(stored, row).decompiled.pair
    assert pair.older.startswith('void g') and pair.newer.startswith(pair_text.NO_FUNCTION)


def rvas_side(vm, row):
    return records_for(vm, [row])[row.row_id].match.older[0].rva


def test_a_part_that_disagrees_with_its_manifest_is_not_shown(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, c_records(vm, row, 'int a;', 'int b;'))
    part = next(p for p in stored.manifest.parts if p.name == pair_text.DECOMP_PART)
    forged = stored.manifest.model_copy(update={'parts': tuple(
        part.model_copy(update={'sha256': '0' * 64}) if p is part else p for p in stored.manifest.parts)})
    channel = source(dataclasses.replace(stored, manifest=forged), row).decompiled
    assert channel.pair is None and channel.reason == pair_text.DECOMP_UNREADABLE


@pytest.mark.parametrize('line', [b'not json\n', b'{"side":"older"}\n', b'{"side":"sideways","rva":1,"status":"ok","code":"x"}\n',
                                  b'{"side":"older","rva":1,"status":"ok","code":null}\n',
                                  b'{"side":"older","rva":1,"status":"failed","code":"x"}\n'],
                         ids=['text', 'keys', 'side', 'null-code', 'code-on-failure'])
def test_a_malformed_decompile_line_makes_the_part_unreadable(world, line):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, [('older', 1, 'ok', 'x')])
    (stored.result_dir / pair_text.DECOMP_PART).write_bytes(gzip.compress(line))
    assert source(stored, row).decompiled.reason == pair_text.DECOMP_UNREADABLE


HOSTILE_C = ['<b>pwn</b>\n{0} %s', '\x1b[31mred\x00‮rev', 'l1 l2\rl3', '&lt;script&gt;']


@pytest.mark.parametrize('text', HOSTILE_C, ids=['markup', 'controls', 'separators', 'entities'])
def test_hostile_c_text_is_data_and_keeps_the_row_count_consistent(world, text):
    vm, source = world
    row = row_named(vm, 'get_version')
    stored = with_decomp(vm, c_records(vm, row, text, 'int x;'))
    pair = source(stored, row).decompiled.pair
    assert len(rows_of(pair.older)) == len(rows_of(pair.newer))
    assert len(pair.older_map) == len(text.splitlines())


# ---- pure alignment helpers -----------------------------------------------------------------------------------------


@given(st.lists(st.tuples(st.integers(0, 40), st.integers(0, 40)), unique_by=lambda p: p[0], max_size=25))
def test_the_chain_is_increasing_and_never_longer_than_the_input(pairs):
    pairs = sorted(pairs)
    chain = pair_text.increasing_chain(pairs)
    assert set(chain) <= set(pairs) and len(chain) <= len(pairs)
    assert all(a[0] < b[0] and a[1] < b[1] for a, b in zip(chain, chain[1:], strict=False))


def test_the_chain_drops_a_block_that_moved_against_the_address_order():
    assert pair_text.increasing_chain([(0, 0), (1, 5), (2, 1), (3, 2)]) == [(0, 0), (2, 1), (3, 2)]
    assert pair_text.increasing_chain([]) == []


def test_opcodes_cover_both_sides_exactly_once():
    old, new = ['a', 'b', 'x', 'c'], ['a', 'b', 'y', 'z', 'c']
    ops = pair_text.ir_opcodes(old, new, [(0, 0), (1, 1), (3, 4)])
    assert ops == [('equal', 0, 1, 0, 1), ('equal', 1, 2, 1, 2), ('replace', 2, 3, 2, 4), ('equal', 3, 4, 4, 5)]
    assert pair_text.ir_opcodes(['a'], [], []) == [('delete', 0, 1, 0, 0)]
    assert pair_text.ir_opcodes([], ['a'], []) == [('insert', 0, 0, 0, 1)]

def test_code_source_cache_reloads_after_same_result_id_gains_a_decompile_part(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    assert source(vm, row).decompiled.reason == pair_text.NO_DECOMP
    changed = with_decomp(vm, c_records(vm, row, 'int x = 3;', 'int x = 4;'))
    rendered = source(changed, row).decompiled
    assert rendered.pair is not None
    assert 'int x = 3;' in str(rendered.pair.older)
    assert 'int x = 4;' in str(rendered.pair.newer)


def test_code_source_cache_reloads_when_verified_c_part_digest_changes(world):
    vm, source = world
    row = row_named(vm, 'get_version')
    first = with_decomp(vm, c_records(vm, row, 'int first = 1;', 'int first = 2;'))
    assert 'int first = 1;' in str(source(first, row).decompiled.pair.older)
    second = with_decomp(vm, c_records(vm, row, 'int second = 1;', 'int second = 2;'))
    pane = source(second, row).decompiled.pair
    assert 'int second = 1;' in str(pane.older) and 'int first = 1;' not in str(pane.older)
