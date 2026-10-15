"""WB3-S3: PatchTrace basic string scan. Gate: byte-identical to the recorded FLOSS 3.1.1 static goldens (SYNTHETIC
PE pairs); chunked scanning equals one whole-buffer regex pass; cancellation; limits."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools import floss
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS
from patchtrace.intelligence.tools.normalize import PeMap
from patchtrace.intelligence.tools.process import ArtifactCopy
from patchtrace.strings import scan
from patchtrace.strings.sources import STATIC_SEMANTICS_ID, FlossEvidenceSource, StringSource

FLOSS_DIR = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools' / 'floss'
CLASS = b'[\x20-\x7e\t]'


def oracle(data: bytes, n: int = 4) -> list[tuple[str, str, int]]:
    """FLOSS 3.1.1 `extract_ascii_unicode_strings` written as two whole-buffer regexes."""
    ascii_hits = [(m.group().decode('ascii'), 'ASCII', m.start()) for m in re.finditer(CLASS + b'{%d,}' % n, data)]
    wide = [(m.group().decode('utf-16-le'), 'UTF-16LE', m.start())
            for m in re.finditer(b'(?:' + CLASS + b'\x00){%d,}' % n, data)]
    return ascii_hits + wide


def triples(result: scan.ScanResult) -> list[tuple[str, str, int]]:
    return [tuple(row) for row in result.rows]


def sides(pair: str) -> dict[str, bytes]:
    return dict(zip(('older', 'newer'), PAIRS[pair](), strict=True))


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['older', 'newer'])
def test_scan_matches_floss_goldens(side):
    golden = json.loads((FLOSS_DIR / f'floss-static-{side}.static.json').read_text(encoding='utf-8'))
    expected = [(s['string'], s['encoding'], s['offset']) for s in golden['strings']['static_strings']]
    assert triples(scan.scan_bytes(sides('floss-static')[side])) == expected
    assert golden['metadata']['min_length'] == scan.DEFAULT_MIN_LENGTH


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['older', 'newer'])
def test_scan_matches_the_decode_goldens(side):
    golden = json.loads((FLOSS_DIR / f'floss-decode-{side}.static.json').read_text(encoding='utf-8'))
    expected = [(s['string'], s['encoding'], s['offset']) for s in golden['strings']['static_strings']]
    assert triples(scan.scan_bytes(sides('floss-decode')[side])) == expected


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['older', 'newer'])
def test_source_rows_equal_the_floss_adapter_rows(tmp_path, side):
    data = sides('floss-static')[side]
    path = tmp_path / 'a.bin'
    path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    copy = ArtifactCopy(path, sha, hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), len(data))
    reader = VerifiedArtifactReader.open_path(path, sha)
    try:
        pe = PeMap.from_reader(reader)
        ctx = floss.ParseContext('r', side, copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], False)
        evidence = floss.parse((FLOSS_DIR / f'floss-static-{side}.static.json').read_bytes(), ctx)
        theirs = FlossEvidenceSource(evidence).load()
        mine = scan.BuiltinScanSource(path, artifact_sha256=sha, side=side,
                                      offset_to_rva=lambda off: pe.offset_to_rva(off)[0]).load()
    finally:
        reader.close()
    assert isinstance(scan.BuiltinScanSource(path, artifact_sha256=sha, side=side), StringSource)
    fields = [(r.value_sha256, r.display, r.length, r.type, r.encoding, r.offset, r.rva, r.secret_kind)
              for r in mine.rows]
    assert fields == [(r.value_sha256, r.display, r.length, r.type, r.encoding, r.offset, r.rva, r.secret_kind)
                      for r in theirs.rows]
    assert mine.part.source == 'builtin-scan' and mine.part.semantics_id == theirs.part.semantics_id
    assert mine.stages['static'].state == 'complete'
    assert {mine.stages[t].state for t in ('stack', 'tight', 'decoded')} == {'not-run'}


def test_label_and_semantics_are_not_floss():
    assert scan.SOURCE_LABEL == 'PatchTrace basic string scan' and 'floss' not in scan.SOURCE_LABEL.lower()
    assert scan.SEMANTICS_ID == STATIC_SEMANTICS_ID == 'ascii+utf16le-ascii/v1'


@pytest.mark.parametrize(('data', 'expected'), [
    (b'', []),
    (b'abc', []),
    (b'abcd', [('abcd', 'ASCII', 0)]),
    (b'\x00abcd\x00efgh', [('abcd', 'ASCII', 1), ('efgh', 'ASCII', 6)]),
    (b'ab\ncd\r\nwxyz', [('wxyz', 'ASCII', 7)]),                       # CR and LF end a string
    (b'tab\tin\tside', [('tab\tin\tside', 'ASCII', 0)]),                 # TAB belongs to the class
    (b'abc\x7fdefg', [('defg', 'ASCII', 4)]),                            # DEL does not
    (b'\xc3\xa9\xc3\xa9test', [('test', 'ASCII', 4)]),                  # UTF-8 multibyte is not covered
    ('wide'.encode('utf-16-le'), [('wide', 'UTF-16LE', 0)]),
    (b'x' + 'wide'.encode('utf-16-le'), [('wide', 'UTF-16LE', 1)]),      # odd alignment is found
    ('wéide'.encode('utf-16-le'), []),                              # non-ASCII wide text is not covered
    (b'abcd\x00\x00' + 'wide'.encode('utf-16-le'), [('abcd', 'ASCII', 0), ('wide', 'UTF-16LE', 6)]),
], ids=['empty', 'short', 'exact', 'nul', 'crlf', 'tab', 'del', 'utf8', 'wide', 'wide-odd', 'wide-nonascii',
        'mixed'])
def test_known_answers(data, expected):
    assert triples(scan.scan_bytes(data)) == expected == oracle(data)


def test_min_length_is_a_parameter_and_validated():
    assert triples(scan.scan_bytes(b'ab\x00abc\x00abcdef', min_length=3)) == [('abc', 'ASCII', 3),
                                                                            ('abcdef', 'ASCII', 7)]
    for bad in (0, 4097):
        with pytest.raises(scan.ScanError) as info:
            scan.scan_bytes(b'x', min_length=bad)
        assert info.value.code == 'PT-STR-INPUT'


def test_run_across_chunk_boundaries_is_one_string():
    data = b'\x00' + b'A' * 10 + b'\x00' + 'wide string'.encode('utf-16-le') + b'\x00'
    for size in range(1, len(data) + 2):
        assert triples(scan.scan_bytes(data, chunk_bytes=size)) == oracle(data), size


@given(data=st.binary(max_size=400), size=st.integers(min_value=1, max_value=64),
       n=st.integers(min_value=1, max_value=12))
@settings(max_examples=300, deadline=None)
def test_random_chunking_equals_the_whole_buffer_regex(data, size, n):
    assert triples(scan.scan_bytes(data, chunk_bytes=size, min_length=n)) == oracle(data, n)


@given(parts=st.lists(st.one_of(st.binary(max_size=12), st.text(alphabet='abc \t%', max_size=12).map(
    lambda t: t.encode('utf-16-le')), st.text(alphabet='abc \t%', max_size=12).map(str.encode)), max_size=30),
       size=st.integers(min_value=1, max_value=40), n=st.integers(min_value=1, max_value=12))
@settings(max_examples=300, deadline=None)
def test_text_rich_inputs_equal_the_oracle(parts, size, n):
    data = b''.join(parts)
    assert triples(scan.scan_bytes(data, chunk_bytes=size, min_length=n)) == oracle(data, n)


def test_scan_path_reads_a_file_in_chunks(tmp_path):
    data = (b'\x00' * 100 + b'needle value' + b'\x00' * 100 + 'wide needle'.encode('utf-16-le')) * 3
    path = tmp_path / 'f.bin'
    path.write_bytes(data)
    result = scan.scan_path(path, chunk_bytes=37)
    assert triples(result) == oracle(data) and result.bytes_scanned == len(data)
    assert result.totals == {'ASCII': 3, 'UTF-16LE': 3} and not result.truncated


def test_cancel_stops_between_chunks():
    calls: list[int] = []

    def cancel() -> bool:
        calls.append(1)
        return len(calls) > 2
    with pytest.raises(scan.ScanError) as info:
        scan.scan_bytes(b'abcdefgh' * 100, chunk_bytes=10, cancel=cancel)
    assert info.value.code == 'PT-STR-CANCEL' and len(calls) == 3


def test_row_cap_keeps_exact_totals_and_records_the_cut():
    data = b''.join(b'string%03d\x00' % i for i in range(50)) + 'wide one'.encode('utf-16-le')
    result = scan.scan_bytes(data, max_rows=10)
    assert result.totals == {'ASCII': 50, 'UTF-16LE': 1}
    assert [r.encoding for r in result.rows].count('ASCII') == 10 and result.truncated_encodings == ('ASCII',)
    assert result.rows[0].offset == 0 and result.rows[9].value == 'string009'   # first by position
    assert result.rows[-1].encoding == 'UTF-16LE'                               # a flood does not starve wide


def test_source_reports_truncation_as_a_stage(tmp_path):
    path = tmp_path / 'f.bin'
    path.write_bytes(b''.join(b'string%03d\x00' % i for i in range(30)))
    result = scan.BuiltinScanSource(path, artifact_sha256='a' * 64, side='older', max_rows=5).load()
    assert len(result.rows) == 5 and result.rows_seen == 30
    assert result.stages['static'].state == 'truncated'


def test_a_single_huge_run_is_split_and_counted():
    data = b'A' * 1000
    result = scan.scan_bytes(data, max_run=300, chunk_bytes=64)
    assert [len(r.value) for r in result.rows] == [300, 300, 300, 100] and result.split_runs == 3
    assert triples(scan.scan_bytes(data, max_run=300, chunk_bytes=999)) == triples(result)


def test_hostile_values_are_escaped_in_source_rows(tmp_path):
    path = tmp_path / 'f.bin'
    path.write_bytes(b'\x00\x1b[31mred\x00' + 'a‮b'.encode('utf-16-le') + b'\x00\x00')
    rows = scan.BuiltinScanSource(path, artifact_sha256='a' * 64, side='older').load().rows
    assert all(r.display.isprintable() for r in rows)
