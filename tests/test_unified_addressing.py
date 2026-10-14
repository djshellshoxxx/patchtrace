"""SPEC-31 addressing (06 s1, D-17): per-set VA/RVA detection reusing C3's rule, external keys, bounds."""
from __future__ import annotations

import pytest

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.sample import synthetic_pe
from patchtrace.secondary import binexport_identity
from patchtrace.unified import addressing
from patchtrace.unified.addressing import AddressMap, is_external_key, layout_from_reader, parse_va_text
from patchtrace.unified.limits import UnifiedError

BASE = 0x180000000
LAYOUT = binexport_identity.PeLayout(image_base=BASE, size_of_image=0x2000)
OTHER = binexport_identity.PeLayout(image_base=0x140000000, size_of_image=0x3000)


def test_detect_address_basis_is_reused_not_reimplemented():
    assert addressing.detect_address_basis is binexport_identity.detect_address_basis
    assert addressing.PeLayout is binexport_identity.PeLayout


def test_address_basis_auto_va_rva_mixed():
    amap = AddressMap(LAYOUT, LAYOUT)
    assert amap.set_basis([BASE + 0x1000, BASE + 0x1100], [BASE + 0x1080]) == 'va'
    assert amap.set_basis([0x1000, 0x1100], [0x1080]) == 'rva'
    assert amap.set_basis([0x1000], [BASE + 0x1080]) == 'not-comparable'  # one side VA, the other RVA
    assert amap.set_basis([BASE + 0x1000, 0x1100], [BASE + 0x1080]) == 'not-comparable'  # mixed inside one side
    assert amap.set_basis([BASE + 0x5000], [BASE + 0x1080]) == 'not-comparable'  # outside the image
    assert amap.set_basis([], [BASE + 0x1080]) == 'va'  # a side without addresses does not decide
    assert amap.set_basis([], []) == 'va'


def test_set_basis_sorts_its_input_because_c3_reads_first_and_last():
    amap = AddressMap(LAYOUT, LAYOUT)
    assert amap.set_basis([BASE + 0x1100, BASE + 0x1000, BASE + 0x1800], [BASE + 0x1080]) == 'va'
    assert amap.set_basis({0x1800, 0x1000, 0x1100}, iter([0x1080])) == 'rva'


def test_each_side_uses_its_own_layout():
    amap = AddressMap(LAYOUT, OTHER)
    assert amap.set_basis([BASE + 0x1000], [0x140000000 + 0x2000]) == 'va'
    assert amap.set_basis([BASE + 0x1000], [BASE + 0x1000]) == 'not-comparable'  # newer layout rejects it


def test_to_rva_respects_the_image_bounds():
    amap = AddressMap(LAYOUT, OTHER)
    assert amap.to_rva('older', BASE, 'va') == 0 and amap.to_rva('older', BASE + 0x1FFF, 'va') == 0x1FFF
    assert amap.to_rva('older', BASE + 0x2000, 'va') is None and amap.to_rva('older', BASE - 1, 'va') is None
    assert amap.to_rva('newer', 0x2FFF, 'rva') == 0x2FFF and amap.to_rva('newer', 0x3000, 'rva') is None
    assert amap.to_rva('newer', 0x140000000 + 0x2000, 'va') == 0x2000


@pytest.mark.parametrize('text, expected', [
    ('EXTERNAL:00000012', True), ('EXTERNAL:ab', True), (' EXTERNAL:1F ', True), ('EXTERNAL:', False),
    ('external:12', False), ('180001000', False), ('EXTERNAL:12:34', False), (None, False), (12, False)])
def test_external_keys_are_recognised_exactly(text, expected):
    assert is_external_key(text) is expected


def test_parse_va_text_accepts_hex_with_or_without_prefix_and_refuses_the_rest():
    assert parse_va_text('180001000') == 0x180001000 and parse_va_text('0X180001000') == 0x180001000
    assert parse_va_text('zz') is None and parse_va_text('') is None and parse_va_text(None) is None
    assert parse_va_text('EXTERNAL:00000012') is None


def test_layout_from_reader_reads_the_pe_headers_of_verified_bytes(tmp_path):
    path = tmp_path / 'a.dll'
    path.write_bytes(synthetic_pe(0))
    reader = VerifiedArtifactReader.open_path(path)
    try:
        layout = layout_from_reader(reader)
    finally:
        reader.close()
    assert (layout.image_base, layout.size_of_image) == (BASE, 0x2000)


def test_layout_from_reader_refuses_a_file_without_a_pe_layout(tmp_path):
    path = tmp_path / 'junk.bin'
    path.write_bytes(b'not a pe image at all')
    reader = VerifiedArtifactReader.open_path(path)
    try:
        with pytest.raises(UnifiedError) as info:
            layout_from_reader(reader)
    finally:
        reader.close()
    assert info.value.code == 'PT-UNIFIED-INPUT' and info.value.reason == 'pe-layout-unavailable'
