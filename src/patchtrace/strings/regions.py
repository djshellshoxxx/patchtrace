"""Where a string sits in the image: a coarse, deterministic region label from the PE section table."""
from __future__ import annotations

from collections.abc import Sequence

from patchtrace.pe_overview.models import SectionInfo

REGION_HEADERS = 'headers'
REGION_CODE = 'code'
REGION_RDATA = 'rdata'
REGION_DATA = 'data'
REGION_RESOURCE = 'resource'
REGION_RELOC = 'reloc'
REGION_OTHER = 'other'
REGION_UNMAPPED = 'unmapped'
REGIONS = (REGION_HEADERS, REGION_CODE, REGION_RDATA, REGION_DATA, REGION_RESOURCE, REGION_RELOC,
           REGION_OTHER, REGION_UNMAPPED)

_SCN_CNT_CODE = 0x00000020
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000
_U32 = 0x1_0000_0000


def section_region(section: SectionInfo) -> str:
    """Name first (the loader treats .rsrc and .reloc specially), then the characteristics bits."""
    name = section.name.lower()
    if name == '.rsrc':
        return REGION_RESOURCE
    if name == '.reloc':
        return REGION_RELOC
    flags = section.characteristics
    if flags & (_SCN_CNT_CODE | _SCN_MEM_EXECUTE):
        return REGION_CODE
    if flags & _SCN_MEM_WRITE:
        return REGION_DATA
    if flags & _SCN_MEM_READ:
        return REGION_RDATA
    return REGION_OTHER


def region_for_rva(rva: int, sections: Sequence[SectionInfo] | None, size_of_headers: int | None = None) -> str:
    """Region of `rva`. Overlapping sections are ambiguous and give `other`; no section gives `unmapped`."""
    if isinstance(rva, bool) or not isinstance(rva, int) or not 0 <= rva < _U32:
        return REGION_UNMAPPED
    covering = [s for s in sections or ()
                if s.virtual_address <= rva < s.virtual_address + (s.virtual_size or s.raw_size)]
    if len(covering) > 1:
        return REGION_OTHER
    if covering:
        return section_region(covering[0])
    if size_of_headers and rva < size_of_headers:
        return REGION_HEADERS
    return REGION_UNMAPPED
