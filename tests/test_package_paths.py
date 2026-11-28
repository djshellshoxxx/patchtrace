"""Logical archive names never authorize a filesystem path. Authored bytes only."""
from __future__ import annotations

import importlib

import pytest

from patchtrace.acquisition.contracts import AcquisitionError


def paths():
    return importlib.import_module('patchtrace.acquisition.package_paths')


@pytest.mark.parametrize('raw', [
    b'', b'/root.dll', b'\\root.dll', b'\\\\server\\share\\file.dll', b'C:relative.dll',
    b'C:\\file.dll', b'../file.dll', b'a/../file.dll', b'a/./file.dll', b'a//file.dll',
    b'a\\\\file.dll', b'a/', b'file.dll:stream', b'file.dll.', b'file.dll ', b' file.dll',
    b'CON', b'CON.dll', b'con .dll', b'PRN.dll', b'AUX', b'NUL', b'COM1.sys', b'LPT9.dll',
    b'CONIN$', b'CONOUT$', b'CLOCK$', b'a?b.dll', b'a*b.dll', b'a|b.dll', b'a<b.dll',
    b'a>b.dll', b'a"b.dll', b'a\x00.dll', b'a\x1b.dll', b'a\x7f.dll', b'\xff.dll',
    ('COM\u00b9.dll').encode(), ('LPT\u00b2.sys').encode(), ('a\u202eb.dll').encode(),
    ('a\u200db.dll').encode(), ('a\ue000b.dll').encode(), ('a\u2028b.dll').encode(),
    ('a\u0085b.dll').encode(), b'a' * 256 + b'.dll', b'a/' * 64 + b'x', b'a' * 1025,
    b'\xed\xa0\x80.dll',
])
def test_hostile_names_refuse_without_echoing_archive_bytes(raw):
    with pytest.raises(AcquisitionError) as error:
        paths().decode_member_name(raw, utf8=True)
    assert error.value.code in {'PT-ACQ-INPUT', 'PT-ACQ-LIMIT'}
    assert '\x1b' not in str(error.value) and '\u202e' not in str(error.value)


def test_safe_names_keep_raw_identity_and_logical_separators():
    name = paths().decode_member_name(b'folder\\Sample.DLL', utf8=False)
    assert name.path == 'folder/Sample.DLL'
    assert name.raw_hex == b'folder\\Sample.DLL'.hex()
    assert name.collision_key == 'folder/sample.dll'
    assert name.basename == 'Sample.DLL'


def test_utf8_requires_the_flag_and_preserves_original_unicode_spelling():
    raw = 'folder/cafe\u0301.dll'.encode('utf-8')
    with pytest.raises(AcquisitionError):
        paths().decode_member_name(raw, utf8=False)
    name = paths().decode_member_name(raw, utf8=True)
    assert name.path == 'folder/cafe\u0301.dll'
    assert name.collision_key == 'folder/caf\u00e9.dll'


@pytest.mark.parametrize('first,second', [
    (b'File.dll', b'file.DLL'), (b'a\\b.dll', b'a/b.dll'),
    ('caf\u00e9.dll'.encode(), 'cafe\u0301.dll'.encode()),
    ('Stra\u00dfe.dll'.encode(), b'STRASSE.dll'),
    (b'a', b'a/b.dll'), (b'a/b.dll', b'a'),
])
def test_name_set_refuses_aliases_and_both_prefix_collision_orders(first, second):
    registry = paths().NameRegistry()
    registry.add(first, utf8=True)
    with pytest.raises(AcquisitionError):
        registry.add(second, utf8=True)
    assert registry.count == 1


def test_name_registry_bounds_distinct_entries_and_preserves_previous_names():
    registry = paths().NameRegistry(max_entries=2)
    registry.add(b'a/file.dll', utf8=False)
    registry.add(b'b/file.dll', utf8=False)
    with pytest.raises(AcquisitionError) as error:
        registry.add(b'c/file.dll', utf8=False)
    assert error.value.code == 'PT-ACQ-LIMIT' and registry.count == 2


@pytest.mark.parametrize('raw,flag,limit', [('x.dll', False, 1024), (bytearray(b'x'), False, 1024),
                                          (b'x.dll', 1, 1024), (b'x.dll', False, True),
                                          (b'x.dll', False, 1025)])
def test_name_boundary_never_coerces_types_or_raises_ceilings(raw, flag, limit):
    with pytest.raises(AcquisitionError):
        paths().decode_member_name(raw, utf8=flag, max_bytes=limit)
