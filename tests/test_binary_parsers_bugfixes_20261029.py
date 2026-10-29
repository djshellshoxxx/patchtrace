"""Regression tests for issue #105 BUG-STR-1, BUG-STR-4, BUG-PE-1 and BUG-PE-2. Offline; synthetic inputs only."""
from __future__ import annotations

import hashlib
import random
import re
import struct
import time

import pytest
from pe_builder import RDATA, PeSpec, SectionSpec, build_pe_ex
from strings_pe import builtin_table

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.tables import PeTables
from patchtrace.strings.links import SideFunctions, link_strings
from patchtrace.strings.scan import scan_bytes
from patchtrace.strings.sources import SourceRow


def inspect(tmp_path, data: bytes):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader)


def test_str1_a_duplicated_string_does_not_crash_prefix_linking():
    text = 'A long message that is quite long indeed for prefix'
    sha = hashlib.sha256(text.encode()).digest()
    rows = [SourceRow(sha, text, len(text), 'static', 'ASCII', off, 0x1000 + off, None, None, None, None,
                      'verified-bytes') for off in (0, 100)]
    table = builtin_table('older', 'a' * 64, rows)
    record = FunctionRecord(id='f1', artifact_id='a', run_id='r', name='main', address='0x1000',
                            address_space='relative',
                            code='void main(){ puts("A long message that is quite long..." '
                                 '/* TRUNCATED STRING LITERAL */); }')
    functions = SideFunctions.from_matches([FunctionMatch(id='m1', run_id='r', older=[record],
                                                          category='modified')], 'older', 0, None)
    result = link_strings({'older': table}, pairing=FunctionPairing.empty(), functions={'older': functions},
                          ghidra_group='g')
    links = [link for found in result.links.values() for link in found]
    assert links and {link.join for link in links} == {'contains'}   # equal rows share one key


def _oracle(data: bytes, min_length: int) -> list[tuple[int, bytes]]:
    """Every maximal printable ASCII run of at least min_length (the strings definition the scanner implements)."""
    return [(m.start(), m.group()) for m in re.finditer(rb'[\x20-\x7e\t]{%d,}' % min_length, data)]


@pytest.mark.parametrize('min_length', [4, 31, 33, 100])
def test_str4_scan_results_are_unchanged_by_the_run_start_lookbehind(min_length):
    rng = random.Random(min_length)
    pieces = [bytes(rng.choice(b'abcdefgh \t') for _ in range(rng.randrange(1, 3 * min_length))) + b'\0'
              for _ in range(400)]
    data = b''.join(pieces)
    rows = [(row.offset, row.value) for row in scan_bytes(data, min_length=min_length).rows if row.encoding == 'ASCII']
    assert rows == [(offset, raw.decode('ascii')) for offset, raw in _oracle(data, min_length)]


def test_str4_long_minimum_is_linear_on_runs_just_below_it():
    min_length = 4096
    data = (b'A\0' * (min_length - 1) + b'\xff\xff') * 128     # 1 MiB of UTF-16LE near-misses
    started = time.perf_counter()
    assert scan_bytes(data, min_length=min_length).rows == ()
    assert time.perf_counter() - started < 3.0           # about 6.5 s per MiB on main, about 0.03 s after the fix


def test_pe1_a_directory_over_the_single_read_cap_is_read_in_pieces(tmp_path):
    size = 17 * 1024 * 1024
    big = SectionSpec('.pdata', b'\0' * size, RDATA)
    data, _ = build_pe_ex(PeSpec(sections=[SectionSpec(), big], extra_directories={3: (0x2000, size)}))
    path = tmp_path / 'big.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        functions = PeTables.open(reader).runtime_functions()     # raised ArtifactBytesError on main
    assert len(functions) == 0                            # an all-zero table holds no entries


def test_pe2_name_rva_zero_is_not_read_as_the_dos_header(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'KERNEL32.dll': ['CreateFileW']}))
    data = bytearray(data)
    struct.pack_into('<I', data, info['import_desc_off'] + 12, 0)
    overview = inspect(tmp_path, bytes(data))
    assert [dll.name for dll in overview.imports.dlls] != ['MZ']
    assert 'import_rva_out_of_file' in [w.code for w in overview.warnings]

    data, info = build_pe_ex(PeSpec(exports=('lib.dll', ['a', 'b'])))
    data = bytearray(data)
    names_rva = struct.unpack_from('<I', data, info['export_dir_off'] + 32)[0]
    section = next(s for s in info['sections'] if s[0] == '.idata')
    struct.pack_into('<I', data, section[3] + (names_rva - section[1]), 0)
    assert 'MZ' not in inspect(tmp_path, bytes(data)).exports.names


def _one_row_blob(display: str) -> bytes:
    row = SourceRow(hashlib.sha256(display.encode()).digest(), display, len(display), 'static', 'ASCII', 0, None,
                    None, None, None, None, 'verified-bytes')
    return builtin_table('older', 'a' * 64, [row]).to_bytes()


def test_str3_a_string_table_with_invalid_utf8_fails_typed():
    from patchtrace.strings.contracts import StringsError
    from patchtrace.strings.table import StringTable
    blob = bytearray(_one_row_blob('ABCDEFGH'))
    blob[blob.index(b'ABCDEFGH')] = 0xff
    with pytest.raises(StringsError, match='invalid string pool'):
        StringTable.from_bytes(bytes(blob))


def test_str3_a_string_table_display_over_the_limit_is_refused():
    from patchtrace.strings.contracts import StringsError
    from patchtrace.strings.limits import DISPLAY_CHARS
    from patchtrace.strings.table import StringTable
    with pytest.raises(StringsError, match='display text too long'):
        StringTable.from_bytes(_one_row_blob('%' + '0' * DISPLAY_CHARS))


def test_str3_the_format_cue_is_linear_and_still_matches_real_formats():
    from patchtrace.strings import cues
    started = time.perf_counter()
    assert cues._FORMAT.search('%' + '0' * 20000) is None
    assert time.perf_counter() - started < 1.0              # about 12 s on main
    for text in ('%d', '%05d', '%010.3f', '%-8s', '%*d', '%I64u', '%#x', '%+.2e'):
        assert cues._FORMAT.search(text), text


def test_code1_comment_state_covers_rows_past_the_document_cap():
    from patchtrace.codetext import MAX_DOCUMENT_CHARS, CodeTextModel
    rows = ['/* a comment that is never closed'] + ['int x = 1;'] * (MAX_DOCUMENT_CHARS // 10 + 1000)
    model = CodeTextModel(rows, rows, 'c', paired=[])
    last = len(rows) - 1
    assert last in model._comment_rows('older')
    assert {span.style_key.role for span in model.spans('older', last, rows[last])} == {'comment'}
