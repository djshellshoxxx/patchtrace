"""PE build facts: Rich header (against pefile as oracle), header fields, debug types, LoadConfig, CLR, limits."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pefile
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_build_fixtures import E_LFANEW, MSVC_RICH, RICH_AT, BuildSpec, build_with_facts, rich_bytes

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.build_facts import collect_build_facts, runtime_families
from patchtrace.pe_overview.rich_header import MAX_ENTRIES, RichEntry, parse_rich_header, rich_signature

NO_HEALTH = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def facts_of(tmp_path: Path, data: bytes, **kw):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return collect_build_facts(reader, inspect_pe(reader), **kw)


def region(data: bytes) -> bytes:
    return data[:struct.unpack_from('<I', data, 0x3C)[0]]


# -- Rich header ---------------------------------------------------------------------------------

def test_rich_matches_pefile_and_checksum_ok():
    data = build_with_facts(BuildSpec(rich=MSVC_RICH))
    rich = parse_rich_header(region(data))
    oracle = pefile.PE(data=data, fast_load=True)
    parsed = oracle.parse_rich_header()
    flat = [w for e in rich.entries for w in ((e.product_id << 16) | e.build, e.count)]
    assert flat == parsed['values'] and rich.key == parsed['checksum']
    assert rich.checksum_ok is True and rich.offset == RICH_AT and not rich.truncated
    assert rich.entries[0] == RichEntry(0x105, 33134, 12)


def test_rich_signature_ignores_counts_and_order():
    twin = [(p, b, c + 7) for p, b, c in reversed(MSVC_RICH)]
    a = parse_rich_header(region(build_with_facts(BuildSpec(rich=MSVC_RICH))))
    b = parse_rich_header(region(build_with_facts(BuildSpec(rich=twin))))
    assert a.signature == b.signature != parse_rich_header(
        region(build_with_facts(BuildSpec(rich=[(0x105, 36248, 12)])))).signature


def test_rich_checksum_failure_is_flagged_not_dropped():
    rich = parse_rich_header(region(build_with_facts(BuildSpec(rich=MSVC_RICH, rich_key=0x1234ABCD))))
    assert rich.checksum_ok is False and len(rich.entries) == len(MSVC_RICH)


def test_rich_checksum_detects_dos_header_tamper():
    data = bytearray(build_with_facts(BuildSpec(rich=MSVC_RICH)))
    data[0x10] ^= 0xFF
    assert parse_rich_header(region(bytes(data))).checksum_ok is False


def test_rich_absent_is_none():
    assert parse_rich_header(region(build_with_facts())) is None


def test_rich_entry_cap_marks_truncated_and_drops_checksum():
    many = [(0x100 + i % 50, 30000 + i, 1) for i in range(MAX_ENTRIES + 5)]
    rich = parse_rich_header(region(_big_rich_pe(many)))
    assert rich.truncated and len(rich.entries) == MAX_ENTRIES and rich.checksum_ok is None


def _big_rich_pe(entries) -> bytes:
    dos = bytearray(RICH_AT)
    dos[:2] = b'MZ'
    blob = rich_bytes(bytes(dos), entries)
    out = bytearray(dos + blob)
    out += b'\0' * ((-len(out)) % 8)
    struct.pack_into('<I', out, 0x3C, len(out))
    return bytes(out)


@pytest.mark.parametrize('mutate', [
    lambda d: d[:RICH_AT + 20], lambda d: d[:RICH_AT + 4], lambda d: d.replace(b'DanS', b'XXXX')[:200],
    lambda d: d.replace(b'Rich', b'Rixh'), lambda d: b'Rich' + d[4:], lambda d: d[:RICH_AT + 26] + b'Rich\0\0\0\0',
], ids=['cut-mid', 'cut-early', 'no-dans', 'no-rich', 'rich-at-zero', 'odd-words'])
def test_rich_malformed_never_raises(mutate):
    data = build_with_facts(BuildSpec(rich=MSVC_RICH))
    result = parse_rich_header(mutate(region(data)))
    assert result is None or isinstance(result.entries, tuple)


def test_rich_odd_word_count_is_none():
    dos = bytes(RICH_AT)
    key = 0x11223344
    blob = struct.pack('<4I', 0x536E6144 ^ key, key, key, key) + struct.pack('<I', 5 ^ key) + b'Rich' + struct.pack('<I', key)
    assert parse_rich_header(dos + blob) is None


@given(st.binary(max_size=2048))
@NO_HEALTH
def test_rich_random_bytes_never_raise(blob):
    parse_rich_header(blob)


@given(st.lists(st.tuples(st.integers(1, 0xFFFF), st.integers(0, 0xFFFF), st.integers(1, 1000)),
                min_size=1, max_size=40))
@NO_HEALTH
def test_rich_equals_pefile_on_generated_headers(entries):
    data = build_with_facts(BuildSpec(rich=entries))
    rich = parse_rich_header(region(data))
    parsed = pefile.PE(data=data, fast_load=True).parse_rich_header()
    assert [w for e in rich.entries for w in ((e.product_id << 16) | e.build, e.count)] == parsed['values']
    assert rich.checksum_ok is True


def test_signature_is_sha256_of_sorted_unique_pairs():
    expected = hashlib.sha256(struct.pack('<HHHH', 1, 2, 3, 4)).hexdigest()
    assert rich_signature((RichEntry(3, 4, 9), RichEntry(1, 2, 1), RichEntry(1, 2, 5))) == expected


# -- header fields -------------------------------------------------------------------------------

@pytest.mark.parametrize('plus', [True, False], ids=['pe32plus', 'pe32'])
def test_header_version_fields_match_pefile(tmp_path, plus):
    spec = BuildSpec(pe32plus=plus, linker=(2, 38), os_version=(10, 0), image_version=(1, 2), subsystem_version=(6, 1))
    data = build_with_facts(spec)
    facts = facts_of(tmp_path, data)
    oracle = pefile.PE(data=data, fast_load=True).OPTIONAL_HEADER
    assert facts.linker_field == (oracle.MajorLinkerVersion, oracle.MinorLinkerVersion) == (2, 38)
    assert facts.os_field == (oracle.MajorOperatingSystemVersion, oracle.MinorOperatingSystemVersion) == (10, 0)
    assert facts.image_field == (oracle.MajorImageVersion, oracle.MinorImageVersion)
    assert facts.subsystem_field == (oracle.MajorSubsystemVersion, oracle.MinorSubsystemVersion) == (6, 1)
    assert facts.facts_version == 'pe-build-facts/1' and facts.subsystem == 'WINDOWS_CUI'


def test_lld_style_header_has_no_rich_and_linker_14_0(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(linker=(14, 0))))
    assert facts.linker_field == (14, 0) and facts.rich is None and facts.anomalies == ()


def test_rich_reported_in_facts_with_anomaly_on_bad_checksum(tmp_path):
    good = facts_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)))
    bad = facts_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH, rich_key=7)))
    assert good.rich.checksum_ok is True and 'rich-checksum-failed' not in good.anomalies
    assert 'rich-checksum-failed' in bad.anomalies and bad.rich is not None


def test_pefile_crosscheck_agrees_on_clean_header(tmp_path):
    assert 'rich-pefile-mismatch' not in facts_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH))).anomalies


# -- debug, LoadConfig, CLR, runtimes ------------------------------------------------------------

def test_debug_entry_types_and_repro(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(debug_types=(2, 13, 16, 20))))
    assert facts.debug_entry_types == (2, 13, 16, 20) and facts.repro is True
    plain = facts_of(tmp_path, build_with_facts(BuildSpec(debug_types=(2,))))
    assert plain.debug_entry_types == (2,) and plain.repro is False
    assert facts_of(tmp_path, build_with_facts()).debug_entry_types == ()


def test_debug_entries_over_cap_are_truncated(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(debug_types=tuple([2] * 17))))
    assert len(facts.debug_entry_types) == 16 and 'debug-entries-truncated' in facts.anomalies


@pytest.mark.parametrize('plus', [True, False], ids=['pe32plus', 'pe32'])
def test_load_config_guard_flags_and_cookie(tmp_path, plus):
    flags = 0x100 | 0x400 | 0x800000
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(pe32plus=plus, load_config=(0x4000, flags))))
    assert facts.guard_flags == ('CF_INSTRUMENTED', 'CF_FUNCTION_TABLE_PRESENT', 'XFG_ENABLED')
    assert facts.security_cookie_set is True
    empty = facts_of(tmp_path, build_with_facts(BuildSpec(pe32plus=plus, load_config=(0, 0))))
    assert empty.guard_flags == () and empty.security_cookie_set is False


def test_load_config_size_field_bounds_the_fields(tmp_path):
    short = facts_of(tmp_path, build_with_facts(BuildSpec(load_config=(5, 0x100), load_config_size=0x40)))
    assert short.guard_flags is None and short.security_cookie_set is None
    assert facts_of(tmp_path, build_with_facts()).guard_flags is None


def test_clr_header_basics(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(clr_flags=0x1 | 0x8)))
    clr = facts.clr
    assert (clr.header_size, clr.runtime_major, clr.runtime_minor) == (72, 2, 5)
    assert clr.flags == ('ILONLY', 'STRONGNAMESIGNED') and clr.il_only and not clr.has_native_header
    assert clr.metadata_version == 'v4.0.30319'
    mixed = facts_of(tmp_path, build_with_facts(BuildSpec(clr_flags=0, clr_native_header=True)))
    assert mixed.clr.has_native_header and not mixed.clr.il_only
    assert facts_of(tmp_path, build_with_facts()).clr is None


def test_clr_metadata_version_is_bounded_and_cleaned(tmp_path):
    version = b'v\x01' + b'A' * 200
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(clr_flags=1, clr_version=version)))
    assert facts.clr.metadata_version == 'v?' + 'A' * 62


@pytest.mark.parametrize(('dlls', 'expected'), [
    (['VCRUNTIME140.dll', 'MSVCP140_1.dll'], ('msvc-crt-14',)),
    (['api-ms-win-crt-runtime-l1-1-0.dll', 'ucrtbase.dll'], ('ucrt',)),
    (['msvcrt.dll', 'MSVCR100.dll'], ('msvcrt-legacy',)),
    (['libgcc_s_seh-1.dll', 'libstdc++-6.dll', 'libwinpthread-1.dll'], ('mingw',)),
    (['KERNEL32.dll', 'evil-msvcp140.dll'], ()),
    (['msvcr100.dll', 'vcruntime140.dll', 'ucrtbase.dll', 'libgcc_s_dw2-1.dll'],
     ('mingw', 'msvc-crt-14', 'msvcrt-legacy', 'ucrt')),
], ids=['msvc14', 'ucrt', 'legacy', 'mingw', 'no-claim', 'several'])
def test_runtime_families_closed_table(dlls, expected):
    assert runtime_families(dlls) == expected


def test_runtime_families_from_imports(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(imports={'KERNEL32.dll': ['Sleep'], 'VCRUNTIME140.dll': ['memcpy']})))
    assert facts.runtime_families == ('msvc-crt-14',)


def test_overlay_and_entropy_summary(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(overlay=b'TAIL' * 64)))
    assert facts.overlay_size == 256 and facts.overlay_entropy is not None
    assert facts.entropy_exec_max is not None and facts.sampled is False


# -- hostile input, cancel ---------------------------------------------------------------------

def test_non_pe_yields_empty_facts(tmp_path):
    facts = facts_of(tmp_path, b'hello world' * 20)
    assert facts.linker_field is None and facts.rich is None and facts.clr is None and facts.debug_entry_types == ()


def test_cancel_returns_partial_facts_with_anomaly(tmp_path):
    facts = facts_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)), cancel=lambda: True)
    assert 'cancelled' in facts.anomalies and facts.rich is None


@given(st.binary(max_size=1500), st.integers(0, 3))
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_random_and_mutated_bytes_never_raise(tmp_path_factory, noise, which):
    base = build_with_facts(BuildSpec(rich=MSVC_RICH, debug_types=(2, 16), load_config=(1, 0x100), clr_flags=1))
    blobs = [noise, base[:len(noise) + 64], base[:E_LFANEW] + noise + base[E_LFANEW + len(noise):],
             base[:0x200] + noise]
    facts_of(tmp_path_factory.mktemp('h'), blobs[which])
