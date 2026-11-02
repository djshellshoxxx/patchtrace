"""Original-byte and physical-coordinate invariants of the paired presentation seam."""
from __future__ import annotations

import hashlib
import re

import pytest

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.raw_alignment_view import GAP, WindowRequest, build_alignment_view
from patchtrace.representations import Representation, format_binary, format_hex


@pytest.fixture
def readers(tmp_path):
    opened = []

    def make(older, newer):
        pair = []
        for side, data in (('older', older), ('newer', newer)):
            path = tmp_path / f'{side}-{len(opened)}'
            path.write_bytes(data)
            reader = VerifiedArtifactReader.open_path(path, hashlib.sha256(data).hexdigest())
            opened.append(reader)
            pair.append(reader)
        return pair

    yield make
    for reader in opened:
        reader.close()


@pytest.mark.parametrize('representation', [Representation.HEX, Representation.BINARY])
@pytest.mark.parametrize('reverse', [False, True])
def test_independent_physical_gutters_gaps_spans_and_exact_copy(readers, representation, reverse):
    data = bytes(range(1, 161))
    old, new = data, b'\xfe\xff' + data
    if reverse:
        old, new = new, old
    pair = readers(b'a' * 35 + old, b'b' * 71 + new)
    result = build_alignment_view(WindowRequest(*pair, 35, 71, 128, representation))
    spans = result.alignment.spans
    assert b''.join(span.older for span in spans) == old[:128]
    assert b''.join(span.newer for span in spans) == new[:128]
    assert spans[0].kind == ('delete' if reverse else 'insert')
    assert GAP in result.newer_text if reverse else GAP in result.older_text
    fmt = format_hex if representation is Representation.HEX else format_binary
    for side, data, offset in (('older', old, 35), ('newer', new, 71)):
        copy = getattr(result, side).copy_text
        assert copy.split('\n', 1)[1] == fmt(data[:128], offset)
        assert GAP not in copy
        assert hashlib.sha256(data[:128]).hexdigest() in copy
        shown = getattr(result, side + '_text').splitlines()
        byte_lines = [line for line in shown if re.match(r'^[0-9a-f]{8,}  ', line)]
        assert int(byte_lines[0].split()[0], 16) == offset
    assert len(result.spans) == len(spans)
    for row in result.spans:
        assert result.older_text.splitlines()[row.line] == f'[{row.label}]'
        assert result.newer_text.splitlines()[row.line] == f'[{row.label}]'


def test_ambiguity_and_unresolved_are_visible_without_losing_bytes(readers):
    old, new = b'x' + b'a' * 64, b'y' + b'a' * 64
    result = build_alignment_view(WindowRequest(*readers(old, new), 0, 0, 80, Representation.HEX))
    assert result.alignment.status == 'ambiguous'
    assert result.alignment.reason in result.summary
    assert 'unresolved' in result.older_text
    assert 'EOF (window clipped)' in result.summary
    assert result.older.copy_text.split('\n', 1)[1] == format_hex(old, 0)


@pytest.mark.parametrize('old,new', [(b'', b'abc'), (b'abc', b''), (b'', b'')])
def test_eof_does_not_claim_alignment_or_invent_bytes(readers, old, new):
    result = build_alignment_view(WindowRequest(*readers(old, new), 0, 0, 16, Representation.HEX))
    assert result.alignment is None and result.spans == ()
    assert 'unavailable' in result.summary and 'EOF' in result.summary
    assert result.older.byte_count == len(old) and result.newer.byte_count == len(new)
    assert result.older.copy_text.split('\n', 1)[1] == format_hex(old, 0)
    assert result.newer.copy_text.split('\n', 1)[1] == format_hex(new, 0)


@pytest.mark.parametrize('size', [0, 15, 17, 4097, 8192, True, 16.0])
def test_window_bounds(readers, size):
    with pytest.raises(ValueError, match='multiple of 16'):
        build_alignment_view(WindowRequest(*readers(b'a' * 32, b'b' * 32), 0, 0, size, Representation.HEX))


def test_unavailable_offsets_base64_changed_handle_and_cancellation(readers):
    pair = readers(b'a' * 32, b'b' * 32)
    with pytest.raises(ValueError, match='past end'):
        build_alignment_view(WindowRequest(*pair, 33, 0, 16, Representation.HEX))
    with pytest.raises(ValueError, match='Hex and Binary'):
        build_alignment_view(WindowRequest(*pair, 0, 0, 16, Representation.BASE64))
    with pytest.raises(ArtifactBytesError, match='cancelled'):
        build_alignment_view(WindowRequest(*pair, 0, 0, 16, Representation.HEX), lambda: True)
    pair[0].close()
    with pytest.raises(ArtifactBytesError, match='closed'):
        build_alignment_view(WindowRequest(*pair, 0, 0, 16, Representation.HEX))


def test_large_physical_offsets_are_retained():
    class SparseReader:
        size = 2**33 + 500
        sha256 = '0' * 64

        def read(self, offset, length, *, clip=False):
            assert not clip
            return bytes(range(length))

    result = build_alignment_view(WindowRequest(SparseReader(), SparseReader(), 2**33 + 11, 2**33 + 71,
                                                16, Representation.HEX))
    assert '20000000b  ' in result.older_text
    assert '200000047  ' in result.newer_text


@pytest.mark.parametrize('size', [16, 4096])
def test_exact_read_bounds_and_eof_clip_are_preserved(size):
    class Reader:
        def __init__(self, length):
            self.size = length
            self.calls = []

        def read(self, offset, length, *, clip=False):
            self.calls.append((offset, length, clip))
            return b'\xaa' * length

    older, newer = Reader(8192), Reader(3)
    result = build_alignment_view(WindowRequest(older, newer, 10, 1, size, Representation.HEX))
    assert older.calls == [(10, size, False)]
    assert newer.calls == [(1, 2, False)]
    assert result.older.byte_count == size and result.newer.byte_count == 2


def test_changed_verified_handle_is_not_presented(tmp_path):
    path = tmp_path / 'artifact'
    path.write_bytes(b'a' * 32)
    with VerifiedArtifactReader.open_path(path) as reader:
        path.write_bytes(b'b' * 64)
        with pytest.raises(ArtifactBytesError, match='artifact_changed'):
            build_alignment_view(WindowRequest(reader, reader, 0, 0, 16, Representation.HEX))
