"""PE overview fixes from random audit 1: a per-file entropy budget and a header-only image layout for the callers
that need ImageBase and SizeOfImage only (RA-1, size-budgeted equivalents of the 34 s recipe), and a positive-zero
entropy for constant data (RA-9)."""
from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, headers, inspect_pe
from patchtrace.unified.addressing import layout_from_reader


def run(tmp_path: Path, data: bytes, **kw):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader, **kw)


def codes(ov) -> set[str]:
    return {w.code for w in ov.warnings}


def noise(n: int, seed: bytes = b'seed') -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + struct.pack('<I', counter)).digest()
        counter += 1
    return bytes(out[:n])


def overlapping_sections(count: int, region: int) -> bytes:
    """`count` section headers that all claim the same `region` raw bytes: one range, measured `count` times."""
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec(f'.s{i}', b'\x90' * 16) for i in range(count)],
                                    overlay=noise(region)))
    patched = bytearray(data)
    for i in range(count):
        struct.pack_into('<II', patched, info['section_table_off'] + 40 * i + 16, region, info['overlay_off'])
    return bytes(patched)


class CountingReader:
    """Duck-typed reader (`inspect_pe` uses `size`, `sha256` and `read`) that counts the bytes asked of it."""

    def __init__(self, inner):
        self.inner, self.requested = inner, 0

    size = property(lambda self: self.inner.size)
    sha256 = property(lambda self: self.inner.sha256)

    def read(self, offset, length, **kw):
        self.requested += length
        return self.inner.read(offset, length, **kw)


# -- entropy budget -----------------------------------------------------------------------------------------------

def test_entropy_budget_bounds_overlapping_sections(tmp_path):
    """RA-1: 96 sections over one 8 MiB range took 34 s; a file measures at most four entropy caps in all."""
    cap = 4096
    ov = run(tmp_path, overlapping_sections(40, cap), limits=Limits(entropy_cap=cap))
    assert [s.entropy_bytes for s in ov.sections] == [cap] * 4 + [0] * 36
    assert [s.sampled for s in ov.sections] == [False] * 4 + [True] * 36
    assert all(s.entropy is not None for s in ov.sections[:4]) and all(s.entropy is None for s in ov.sections[4:])
    assert codes(ov) == {'entropy_budget_exhausted'} and ov.status == 'partial'


def test_entropy_budget_cuts_the_range_that_crosses_it(tmp_path):
    sizes = [1024, 1024, 1024, 512, 1024, 512]  # 3584 of the 4096 budget spent before the fifth section
    spec = PeSpec(sections=[SectionSpec(f'.s{i}', noise(n, bytes([i]))) for i, n in enumerate(sizes)])
    ov = run(tmp_path, build_pe(spec), limits=Limits(entropy_cap=1024))
    assert [s.entropy_bytes for s in ov.sections] == [1024, 1024, 1024, 512, 512, 0]
    assert [s.sampled for s in ov.sections] == [False, False, False, False, True, True]
    assert ov.sections[4].entropy is not None and ov.sections[5].entropy is None
    assert codes(ov) == {'entropy_budget_exhausted'}


def test_entropy_within_the_budget_is_unchanged(tmp_path):
    spec = PeSpec(sections=[SectionSpec(f'.s{i}', noise(1024, bytes([i]))) for i in range(4)])
    ov = run(tmp_path, build_pe(spec), limits=Limits(entropy_cap=1024))  # exactly four caps
    assert ov.status == 'ok' and ov.warnings == ()
    assert all(s.entropy is not None and s.entropy_bytes == 1024 and not s.sampled for s in ov.sections)


def test_the_overlay_draws_on_the_same_entropy_budget(tmp_path):
    spec = PeSpec(sections=[SectionSpec(f'.s{i}', noise(1024, bytes([i]))) for i in range(4)], overlay=noise(512))
    ov = run(tmp_path, build_pe(spec), limits=Limits(entropy_cap=1024))
    assert (ov.overlay.size, ov.overlay.entropy, ov.overlay.sampled) == (512, None, True)
    assert codes(ov) == {'entropy_budget_exhausted'}


def test_constant_data_has_a_positive_zero_entropy(tmp_path):
    """RA-9: `-sum(p log p)` of one symbol is -0.0, which printed as `-0.00` and serialized as `-0.0`."""
    ov = run(tmp_path, build_pe(PeSpec(sections=[SectionSpec('.text', b'\x90' * 4096)])))
    assert ov.sections[0].entropy == 0.0 and math.copysign(1.0, ov.sections[0].entropy) == 1.0
    assert '-0.0' not in json.dumps(ov.to_dict())


# -- header-only image layout -------------------------------------------------------------------------------------

def test_image_layout_reads_only_the_headers(tmp_path):
    path = tmp_path / 'hostile.bin'
    path.write_bytes(overlapping_sections(96, 1 << 16))  # a full inspection asks for 6 MiB of entropy reads here
    with VerifiedArtifactReader.open_path(path) as reader:
        counting = CountingReader(reader)
        layout = headers.read_image_layout(counting)
        full = inspect_pe(reader, limits=Limits(entropy_cap=0))
    assert layout == (full.image_base, full.size_of_image) and layout[0] == 0x140000000
    assert counting.requested <= 4096


def zero_size_of_image() -> bytes:
    data, info = build_pe_ex(PeSpec())
    patched = bytearray(data)
    struct.pack_into('<I', patched, info['opt_off'] + 56, 0)
    return bytes(patched)


@pytest.mark.parametrize('make', [
    lambda: b'', lambda: b'\x7fELF' + bytes(200), lambda: build_pe()[:0xC0], zero_size_of_image],
    ids=['empty', 'not-pe', 'cut-before-size-of-image', 'zero-size-of-image'])
def test_image_layout_is_none_without_a_readable_image_header(tmp_path, make):
    path = tmp_path / 'x.bin'
    path.write_bytes(make())
    with VerifiedArtifactReader.open_path(path) as reader:
        assert headers.read_image_layout(reader) is None


def test_the_unified_layout_reads_the_headers_and_nothing_else(tmp_path):
    """`layout_from_reader` needs ImageBase and SizeOfImage only, so the sections must cost no entropy reads."""
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec('.text', bytes(range(256)) * 512)]))
    path = tmp_path / 'a.dll'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        counting = CountingReader(reader)
        layout = layout_from_reader(counting)
    assert (layout.image_base, layout.size_of_image) == (0x140000000, info['size_of_image'])
    assert counting.requested <= 4096 < len(data)  # the 128 KiB section was not read
