"""Tests for raw byte representations (SPEC-26 requirement B)."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

import pytest

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.representations import (
    MAX_PAGE_SIZE,
    UNMAPPED_REASON,
    Representation,
    base64_exact,
    byte_diff_mask,
    file_range,
    format_base64,
    format_binary,
    format_hex,
    function_rva,
    page_count,
    read_page,
    render_page,
    whole_file,
)


@dataclass
class FR:
    file_offset: int
    length: int


class FakeMap:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def rva_to_file_ranges(self, rva, length):
        self.calls.append((rva, length))
        return self.result


class CountingReader:
    def __init__(self, inner):
        self.inner = inner
        self.reads = []

    @property
    def size(self):
        return self.inner.size

    @property
    def sha256(self):
        return self.inner.sha256

    def read(self, offset, length, *, clip=True):
        self.reads.append((offset, length))
        return self.inner.read(offset, length, clip=clip)


@pytest.fixture
def make_reader(tmp_path):
    readers = []

    def make(data: bytes):
        path = tmp_path / f'f{len(readers)}.bin'
        path.write_bytes(data)
        reader = VerifiedArtifactReader.open_path(path)
        readers.append(reader)
        return reader

    yield make
    for r in readers:
        r.close()


# -- formatters ----------------------------------------------------------
def test_hex_golden_layout_with_nulls_and_high_bit():
    data = b'Hello world\n\x00\xff\x80A'
    assert format_hex(data, 0) == (
        '00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 0a 00 ff 80 41  |Hello world....A|')


def test_hex_partial_line_and_base_offset_alignment():
    out = format_hex(bytes(range(0x41, 0x41 + 20)), 0x400).split('\n')
    assert out[0] == '00000400  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|'
    assert out[1].startswith('00000410  51 52 53 54 ') and out[1].endswith('  |QRST|')
    assert out[0].index('|') == out[1].index('|')


def test_hex_no_ascii_and_wide_gutter():
    assert format_hex(b'\x00', 0x1_0000_0000, ascii=False) == '100000000  00' + ' ' * 46
    assert format_hex(b'', 0) == ''


def test_ascii_gutter_only_printable():
    out = format_hex(bytes([0x1f, 0x20, 0x7e, 0x7f, 0x00, 0xff]), 0)
    assert out.endswith('|. ~...|')


def test_binary_golden():
    data = bytes([0x4D, 0x00, 0xFF, 0x80, 0x01, 0x7F, 0xAA, 0x55, 0x0F])
    assert format_binary(data, 0x10) == (
        '00000010  01001101 00000000 11111111 10000000 00000001 01111111 10101010 01010101\n'
        '00000018  00001111')


@pytest.mark.parametrize('n', [0, 1, 2, 3, 4, 5, 57, 58])
def test_base64_matches_stdlib(n):
    data = bytes(range(250, 250 + n)) if n < 6 else bytes((i * 7) % 256 for i in range(n))
    assert base64_exact(data) == base64.b64encode(data).decode()
    assert format_base64(data).replace('\n', '') == base64.b64encode(data).decode()


def test_base64_padding_and_wrap_vs_exact():
    assert base64_exact(b'a') == 'YQ=='
    assert base64_exact(b'ab') == 'YWI='
    assert base64_exact(b'abc') == 'YWJj'
    data = bytes(range(256)) * 2
    exact = base64_exact(data)
    wrapped = format_base64(data)
    assert '\n' not in exact
    assert all(len(line) <= 76 for line in wrapped.split('\n'))
    assert len(wrapped.split('\n')[0]) == 76
    assert wrapped.replace('\n', '') == exact
    assert base64.b64decode(exact) == data


def test_formatter_argument_validation():
    with pytest.raises(ValueError):
        format_hex(b'a', -1)
    with pytest.raises(ValueError):
        format_hex(b'a', True)
    with pytest.raises(ValueError):
        format_binary(b'a', 0, per_line=0)
    with pytest.raises(TypeError):
        format_hex('text', 0)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        format_base64(b'a', wrap=0)


# -- scopes ----------------------------------------------------------------
def test_whole_file_scope():
    s = whole_file(10)
    assert (s.kind, s.total_length, s.label, s.available) == ('whole_file', 10, 'Whole file', True)
    assert whole_file(0).segments == ()


def test_file_range_clipping_and_labels():
    s = file_range(0x600, 0x400, 0x400)
    assert s.clipped and s.total_length == 0x200
    assert 'File range 0x400..0x600' in s.label and 'clipped' in s.label
    ok = file_range(0x1000, 0x400, 0x400)
    assert not ok.clipped and ok.label == 'File range 0x400..0x800'
    eof = file_range(5, 5, 3)
    assert eof.total_length == 0 and eof.segments == ()


@pytest.mark.parametrize('args', [
    (10, 11, 1), (10, -1, 1), (10, 0, -1), (10, True, 1), (10, 0, True), (10, 1.0, 1), (10, 0, 1.5),
    (10, '1', 1), (10, 0, 1 << 63), (1 << 63, 0, 1),
])
def test_file_range_rejects_bad_input(args):
    with pytest.raises(ValueError):
        file_range(*args)


def test_offset_past_eof_message():
    with pytest.raises(ValueError, match='past end of file'):
        file_range(10, 11, 1)


def test_function_rva_contiguous():
    m = FakeMap((FR(0x400, 0x80),))
    s = function_rva(m, 0x1000, 0x80)
    assert s.available and s.label == 'Function RVA 0x1000 (+0x80)' and s.rva == 0x1000
    assert [(x.file_offset, x.length) for x in s.segments] == [(0x400, 0x80)]
    assert m.calls == [(0x1000, 0x80)]


def test_function_rva_two_segments_keep_offsets():
    s = function_rva(FakeMap((FR(0x400, 0x10), FR(0x2000, 0x20))), 0x1000, 0x30)
    assert s.total_length == 0x30
    assert [x.file_offset for x in s.segments] == [0x400, 0x2000]


@pytest.mark.parametrize('result', [
    None, (), (FR(0, 4),), (FR(-1, 8),), (FR(0, 0), FR(0, 8)), (FR(True, 8),),
])
def test_function_rva_unavailable(result):
    s = function_rva(FakeMap(result), 0x1000, 8)
    assert not s.available and s.unavailable_reason == UNMAPPED_REASON
    assert s.segments == () and s.total_length == 0
    assert page_count(s, 16) == 0
    with pytest.raises(ValueError, match='unmapped'):
        read_page(None, s, 0)  # type: ignore[arg-type]


def test_function_rva_over_max_length_never_queries_map():
    m = FakeMap((FR(0, 4),))
    s = function_rva(m, 0, 2 * 1024 * 1024)
    assert not s.available and 'cap' in s.unavailable_reason and m.calls == []
    assert function_rva(FakeMap((FR(0, 40),)), 0, 40, max_length=40).available
    assert not function_rva(FakeMap((FR(0, 41),)), 0, 41, max_length=40).available


def test_function_rva_argument_validation():
    with pytest.raises(ValueError):
        function_rva(FakeMap(None), -1, 4)
    with pytest.raises(ValueError):
        function_rva(FakeMap(None), 0, 0)
    with pytest.raises(ValueError):
        function_rva(FakeMap(None), 0, 4.0)  # type: ignore[arg-type]


# -- paging ---------------------------------------------------------------
def test_page_size_validation(make_reader):
    s = whole_file(100)
    for bad in (0, 8, 24, 65552, -16, 16.0, True, '16'):
        with pytest.raises(ValueError):
            page_count(s, bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            read_page(make_reader(b'x' * 100), s, 0, bad)  # type: ignore[arg-type]
    assert page_count(s, 16) == 7 and page_count(s, 65536) == 1


def test_whole_file_paging_with_partial_last_page(make_reader):
    data = bytes((i * 31) % 256 for i in range(100))
    reader = make_reader(data)
    scope = whole_file(100)
    assert page_count(scope, 32) == 4 == page_count(scope, 32)
    got = b''
    for i in range(4):
        page = read_page(reader, scope, i, 32)
        assert page.logical_start == i * 32 and page.page_count == 4
        assert page.chunks[0][0] == i * 32
        assert page.sha256 == hashlib.sha256(page.data).hexdigest()
        got += page.data
    assert got == data
    last = read_page(reader, scope, 3, 32)
    assert last.byte_count == 4 and last.sha256 == hashlib.sha256(data[96:]).hexdigest()


def test_empty_file_has_zero_pages(make_reader):
    reader = make_reader(b'')
    scope = whole_file(0)
    assert page_count(scope, 16) == 0
    with pytest.raises(IndexError):
        read_page(reader, scope, 0)


def test_page_index_errors(make_reader):
    reader = make_reader(b'a' * 40)
    scope = whole_file(40)
    for bad in (-1, 3):
        with pytest.raises(IndexError):
            read_page(reader, scope, bad, 16)
    with pytest.raises(TypeError):
        read_page(reader, scope, 1.0, 16)  # type: ignore[arg-type]


def test_file_range_paging_reads_only_range(make_reader):
    data = bytes(range(256)) * 4
    reader = CountingReader(make_reader(data))
    page = read_page(reader, file_range(len(data), 0x100, 0x30), 0, 16)
    assert page.data == data[0x100:0x110]
    assert reader.reads == [(0x100, 16)]


def test_function_pages_span_segments_with_true_offsets(make_reader):
    data = bytes(range(256)) * 2
    reader = make_reader(data)
    scope = function_rva(FakeMap((FR(0x10, 0x18), FR(0x100, 0x18))), 0x1000, 0x30)
    p0 = read_page(reader, scope, 0, 32)
    assert p0.chunks == ((0x10, data[0x10:0x28]), (0x100, data[0x100:0x108]))
    assert p0.byte_count == 32 and p0.data == data[0x10:0x28] + data[0x100:0x108]
    p1 = read_page(reader, scope, 1, 32)
    assert p1.chunks == ((0x108, data[0x108:0x118]),)
    assert p1.logical_start == 32 and p1.byte_count == 16


def test_function_scope_past_eof_surfaces_reader_error(make_reader):
    reader = make_reader(b'a' * 64)
    scope = function_rva(FakeMap((FR(60, 8),)), 0x1000, 8)
    with pytest.raises(ArtifactBytesError) as exc:
        read_page(reader, scope, 0)
    assert exc.value.code == 'range_invalid'


def test_large_sparse_file_last_page_reads_only_that_page(tmp_path):
    size = 5 * 1024 * 1024 + 123
    path = tmp_path / 'big.bin'
    with path.open('wb') as fh:
        fh.truncate(size)
        fh.seek(size - 4)
        fh.write(b'\xde\xad\xbe\xef')
    with VerifiedArtifactReader.open_path(path) as inner:
        reader = CountingReader(inner)
        scope = whole_file(reader.size)
        count = page_count(scope, 4096)
        assert count == -(-size // 4096)
        page = read_page(reader, scope, count - 1, 4096)
        assert reader.reads == [((count - 1) * 4096, size - (count - 1) * 4096)]
        assert page.data.endswith(b'\xde\xad\xbe\xef') and page.byte_count == 4096 - (count * 4096 - size)
        text = render_page(page, Representation.HEX).text
        assert 'de  ad be ef' in text.splitlines()[-1]


def test_changed_file_surfaces_artifact_bytes_error(tmp_path):
    path = tmp_path / 'c.bin'
    path.write_bytes(b'a' * 64)
    with VerifiedArtifactReader.open_path(path) as reader:
        scope = whole_file(64)
        assert read_page(reader, scope, 0, 16).byte_count == 16
        with path.open('ab') as fh:
            fh.write(b'more')
        with pytest.raises(ArtifactBytesError) as exc:
            read_page(reader, scope, 1, 16)
        assert exc.value.code in {'artifact_changed', 'size_mismatch'}


def test_scope_size_mismatch_with_reader(make_reader):
    reader = make_reader(b'a' * 64)
    with pytest.raises(ArtifactBytesError) as exc:
        read_page(reader, whole_file(32), 0)
    assert exc.value.code == 'size_mismatch'


# -- rendering --------------------------------------------------------------
def test_render_hex_caption_and_copy(make_reader):
    data = b'MZ\x90\x00' + bytes(range(60))
    reader = make_reader(data)
    page = read_page(reader, whole_file(len(data)), 0, 32)
    out = render_page(page, Representation.HEX)
    assert out.text == format_hex(data[:32], 0)
    assert out.byte_count == 32
    for needle in ('Whole file', 'Hex', '0x0..0x20', '32 bytes', 'page 1/2', page.sha256,
                   'original on-disk bytes (not transformed)'):
        assert needle in out.caption
    head, _, body = out.copy_text.partition('\n')
    assert head.startswith('#') and page.sha256 in head and body == out.text


def test_render_binary_and_enum_value(make_reader):
    reader = make_reader(b'\x01\x02')
    page = read_page(reader, whole_file(2), 0)
    assert render_page(page, Representation('binary')).text == '00000000  00000001 00000010'
    assert Representation.BASE64.value == 'base64'
    with pytest.raises(ValueError):
        render_page(page, 'octal')  # type: ignore[arg-type]


def test_render_base64_exact_bytes_in_logical_order(make_reader):
    data = bytes(range(256))
    reader = make_reader(data)
    scope = function_rva(FakeMap((FR(0x80, 4), FR(0x10, 3))), 0, 7)
    page = read_page(reader, scope, 0)
    out = render_page(page, Representation.BASE64)
    expected = data[0x80:0x84] + data[0x10:0x13]
    assert out.text.replace('\n', '') == base64.b64encode(expected).decode()
    assert 'logical order' in out.caption and 'original on-disk bytes' in out.caption
    assert '0x80..0x84, 0x10..0x13' in out.caption
    assert '--' not in out.text


def test_render_non_contiguous_hex_has_segment_headers(make_reader):
    data = bytes(range(256))
    reader = make_reader(data)
    scope = function_rva(FakeMap((FR(0x10, 4), FR(0x80, 4))), 0, 8)
    out = render_page(read_page(reader, scope, 0), Representation.HEX)
    lines = out.text.split('\n')
    assert lines[0].startswith('-- segment 1/2: file offset 0x10..0x14')
    assert lines[1].startswith('00000010  10 11 12 13')
    assert lines[2].startswith('-- segment 2/2: file offset 0x80..0x84')
    assert lines[3].startswith('00000080  80 81 82 83')
    assert 'Function RVA 0x0 (+0x8)' in out.caption


def test_render_empty_page_set_caption():
    from patchtrace.representations import PageBytes
    page = PageBytes(0, 0, whole_file(0), (), 0, 0, hashlib.sha256(b'').hexdigest())
    out = render_page(page, Representation.HEX)
    assert out.text == '' and 'page 1/1' in out.caption


def test_render_cap_and_max_page_bounds(make_reader):
    data = b'\xaa' * MAX_PAGE_SIZE
    reader = make_reader(data)
    page = read_page(reader, whole_file(len(data)), 0, MAX_PAGE_SIZE)
    assert render_page(page, Representation.BINARY).byte_count == MAX_PAGE_SIZE
    from dataclasses import replace
    with pytest.raises(ValueError, match='render cap'):
        render_page(replace(page, chunks=((0, data + b'x'),), byte_count=MAX_PAGE_SIZE + 1),
                    Representation.HEX)


# -- compare ------------------------------------------------------------------
def test_byte_diff_mask():
    assert byte_diff_mask(b'abc', b'abc') == ()
    assert byte_diff_mask(b'abc', b'aXc') == (1,)
    assert byte_diff_mask(b'ab', b'abcd') == (2, 3)
    assert byte_diff_mask(b'abcd', b'a') == (1, 2, 3)
    assert byte_diff_mask(b'', b'') == ()
    assert byte_diff_mask(b'\x00', b'\xff') == (0,)


def test_byte_diff_mask_capped_at_page_size():
    assert byte_diff_mask(b'a' * MAX_PAGE_SIZE, b'a' * MAX_PAGE_SIZE) == ()
    with pytest.raises(ValueError):
        byte_diff_mask(b'a' * (MAX_PAGE_SIZE + 1), b'')
