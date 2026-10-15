from __future__ import annotations

import pytest

from patchtrace.pe_overview.models import SectionInfo
from patchtrace.strings import regions as r

CODE = 0x60000020
RDATA = 0x40000040
DATA = 0xC0000040
DISCARD = 0x02000040


def sec(name, va, size, flags):
    return SectionInfo(name=name, virtual_address=va, virtual_size=size, raw_offset=va, raw_size=size,
                       characteristics=flags, flags=(), entropy=None, entropy_bytes=0, sampled=False)


SECTIONS = (sec('.text', 0x1000, 0x1000, CODE), sec('.rdata', 0x2000, 0x1000, RDATA),
            sec('.data', 0x3000, 0x1000, DATA), sec('.rsrc', 0x4000, 0x1000, RDATA),
            sec('.reloc', 0x5000, 0x1000, DISCARD), sec('.weird', 0x6000, 0x1000, 0))

GOLDEN = [
    (0x0, r.REGION_HEADERS), (0x3ff, r.REGION_HEADERS), (0x400, r.REGION_UNMAPPED),
    (0x1000, r.REGION_CODE), (0x1fff, r.REGION_CODE), (0x2000, r.REGION_RDATA),
    (0x3000, r.REGION_DATA), (0x4000, r.REGION_RESOURCE), (0x5000, r.REGION_RELOC),
    (0x6000, r.REGION_OTHER), (0x7000, r.REGION_UNMAPPED), (0xFFFFFFFF, r.REGION_UNMAPPED),
    (-1, r.REGION_UNMAPPED), (0x1_0000_0000, r.REGION_UNMAPPED),
]


@pytest.mark.parametrize('rva,expected', GOLDEN, ids=[f'r{i}' for i in range(len(GOLDEN))])
def test_region_for_rva(rva, expected):
    assert r.region_for_rva(rva, SECTIONS, 0x400) == expected


def test_overlapping_sections_are_ambiguous():
    overlap = (sec('.a', 0x1000, 0x1000, CODE), sec('.b', 0x1800, 0x1000, DATA))
    assert r.region_for_rva(0x1900, overlap) == r.REGION_OTHER
    assert r.region_for_rva(0x1100, overlap) == r.REGION_CODE


def test_no_sections_or_headers_is_unmapped():
    assert r.region_for_rva(0x10, None) == r.REGION_UNMAPPED
    assert r.region_for_rva(0x10, (), 0) == r.REGION_UNMAPPED


def test_zero_virtual_size_falls_back_to_raw_size():
    s = SectionInfo('.text', 0x1000, 0, 0x400, 0x200, CODE, (), None, 0, False)
    assert r.region_for_rva(0x1100, (s,)) == r.REGION_CODE
    assert r.region_for_rva(0x1200, (s,)) == r.REGION_UNMAPPED


def test_bool_rva_is_rejected():
    assert r.region_for_rva(True, SECTIONS, 0x400) == r.REGION_UNMAPPED


def test_regions_constant_covers_every_result():
    assert {e for _, e in GOLDEN} <= set(r.REGIONS)
