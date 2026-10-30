"""Independent integration regressions for bounded joins and exact PE byte preservation."""
from __future__ import annotations

from pe_builder import DATA, PeSpec, SectionSpec, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import tables
from patchtrace.strings.links import _join_row, _previous_longer


def test_containing_duplicate_string_rows_require_linear_digest_work():
    class CountedRow:
        reads = 0

        @property
        def value_sha256(self):
            self.reads += 1
            return b'a' * 32

    count = 2000
    row = CountedRow()
    located = [(0x1000, 64, row)] * count
    starts = [0x1000] * count
    ends = [0x1040] * count
    assert _join_row(0x1020, located, starts, ends, _previous_longer(ends)) == (row, 'contains')
    assert row.reads <= 2 * count  # operation bound, independent of machine speed or scheduler load


def test_pe_chunked_reads_preserve_nonzero_bytes_after_first_chunk(tmp_path, monkeypatch):
    payload = bytes(range(1, 128)) * 8
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec('.data', payload, DATA)]))
    path = tmp_path / 'bytes.bin'
    path.write_bytes(data)
    rva = info['sections'][0][1]
    with VerifiedArtifactReader.open_path(path) as reader:
        pe = tables.PeTables.open(reader)
        monkeypatch.setattr(tables, 'MAX_READ_BYTES', 64)
        assert pe.read_rva(rva, len(payload)) == payload
        assert pe.read_backed(rva, len(payload)) == payload
