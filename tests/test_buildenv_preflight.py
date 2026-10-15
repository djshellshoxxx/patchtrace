"""Pre-flight warnings: severity rules, shared type sets, one-sided packing, hostile text (DIE plan s6, s7)."""
from __future__ import annotations

import hashlib

import pytest
from pe_build_fixtures import BuildSpec, build_with_facts
from pe_builder import CODE, PeSpec, SectionSpec, build_pe
from test_buildenv_support import detects, fingerprint_of, pair_fingerprints

from patchtrace.buildenv import preflight
from patchtrace.buildenv.copy import TEACH
from patchtrace.buildenv.delta import compute_delta
from patchtrace.intelligence.tools import diec

CLEAN = build_with_facts(BuildSpec(rich=None))
NOISE = b''.join(hashlib.sha256(bytes([i])).digest() for i in range(64))
UPX_LAYOUT = build_pe(PeSpec(sections=[SectionSpec('UPX0', b'', CODE, virtual_size=0x4000, raw_size=0),
                                       SectionSpec('UPX1', NOISE, CODE)]))
UPX_NAME_ONLY = build_pe(PeSpec(sections=[SectionSpec('UPX0', b'\x90' * 64, CODE), SectionSpec('UPX1', b'\x90' * 64, CODE)]))


def warnings_for(tmp_path, older_pe=CLEAN, newer_pe=CLEAN, older_die=None, newer_die=None):
    older = fingerprint_of(tmp_path, older_pe, 'older', older_die)
    newer = fingerprint_of(tmp_path, newer_pe, 'newer', newer_die)
    return {(w.code, w.side): w for w in compute_delta(older, newer).preflight}


@pytest.mark.parametrize('kind,code', [('packer', 'packed'), ('compressor', 'packed'), ('.net compressor', 'packed'),
                                       ('cryptor', 'packed'), ('crypter', 'packed'), ('protector', 'protected'),
                                       ('protection', 'protected'), ('obfuscator', 'protected'),
                                       ('.net obfuscator', 'protected'), ('installer', 'installer'),
                                       ('sfx data', 'installer')],
                         ids=['packer', 'compressor', 'net-comp', 'cryptor', 'crypter', 'protector', 'protection',
                              'obfuscator', 'net-obf', 'installer', 'sfx'])
def test_signature_types_map_to_warnings(tmp_path, kind, code):
    found = warnings_for(tmp_path, newer_die=detects((kind, 'Sample Tool', '1.0')))
    warning = found[(code, 'newer')]
    assert warning.severity == ('notice' if code == 'installer' else 'caution')
    assert 'Sample Tool 1.0' in warning.summary


@pytest.mark.parametrize('kind', ['virtual machine', 'dongle protection', 'joiner', 'stub', 'loader'])
def test_neutral_types_are_listed_but_raise_nothing(tmp_path, kind):
    older = fingerprint_of(tmp_path, CLEAN, 'older', detects((kind, 'Sample', '1')))
    assert any(f.key == 'protector' for f in older.facts)
    assert not {'packed', 'protected'} & {code for code, _ in warnings_for(tmp_path, older_die=detects((kind, 'S', '1')))}


def test_shared_type_sets_are_the_adapters(tmp_path):
    assert preflight.PACKED_TYPES is diec.PACKED_TYPES and preflight.PROTECTED_TYPES is diec.PROTECTED_TYPES


def test_one_sided_packing_warns_once(tmp_path):
    packed = detects(('packer', 'UPX', '3.96'))
    one = warnings_for(tmp_path, newer_die=packed, older_die=detects(('compiler', 'GCC', '10')))
    assert ('packed-one-side', 'newer') in one and ('packed', 'newer') in one
    both = warnings_for(tmp_path, older_die=packed, newer_die=packed)
    assert not any(code == 'packed-one-side' for code, _ in both)


def test_medium_layout_hint_is_a_caution_and_a_name_hint_only_a_notice(tmp_path):
    medium = warnings_for(tmp_path, newer_pe=UPX_LAYOUT)[('packed', 'newer')]
    assert medium.severity == 'caution' and 'may be packed (hint: UPX)' in medium.summary
    low = warnings_for(tmp_path, newer_pe=UPX_NAME_ONLY)[('packed', 'newer')]
    assert low.severity == 'notice' and low.summary.startswith('[i] Notice:')


def test_heuristics_never_raise_caution(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain', heuristics=True)
    found = compute_delta(older, newer).preflight
    weak = next(w for w in found if w.code == 'heuristic-only')
    assert weak.severity == 'notice' and weak.side == 'newer'
    assert not any(w.severity == 'caution' for w in found)


@pytest.mark.parametrize('flags,native,severity', [(1, False, 'caution'), (0, True, 'notice'), (0x10, False, 'notice')],
                         ids=['il-only', 'mixed', 'plain-managed'])
def test_managed_severity(tmp_path, flags, native, severity):
    data = build_with_facts(BuildSpec(clr_flags=flags, clr_native_header=native))
    warning = warnings_for(tmp_path, newer_pe=data)[('managed', 'newer')]
    assert warning.severity == severity and warning.teach_id == 'build.managed'


@pytest.mark.parametrize('size,expected', [(preflight.OVERLAY_LARGE - 1, False), (preflight.OVERLAY_LARGE, True)],
                         ids=['below', 'at-threshold'])
def test_large_overlay_threshold(tmp_path, size, expected):
    data = build_with_facts(BuildSpec(rich=None, overlay=b'\0' * size))
    found = warnings_for(tmp_path, newer_pe=data)
    assert (('overlay-large', 'newer') in found) is expected


def test_tool_unavailable_when_diec_did_not_run(tmp_path):
    assert ('tool-unavailable', 'both') in warnings_for(tmp_path)
    assert ('tool-unavailable', 'both') not in warnings_for(tmp_path, older_die=detects(), newer_die=detects())


def test_cautions_sort_before_notices_and_teach_ids_exist(tmp_path):
    older = fingerprint_of(tmp_path, build_with_facts(BuildSpec(overlay=b'\0' * preflight.OVERLAY_LARGE)), 'older',
                           detects(('compiler', 'GCC', '10')))
    newer = fingerprint_of(tmp_path, CLEAN, 'newer', detects(('packer', 'UPX', '3.96')))
    found = compute_delta(older, newer).preflight
    severities = [w.severity for w in found]
    assert severities == sorted(severities, key=lambda s: s != 'caution')
    assert all(w.teach_id in TEACH for w in found if w.teach_id)


def test_hostile_detection_strings_plain_text(tmp_path):
    hostile = detects(('packer', '<b>UPX</b>‮\x07 ' + 'A' * 300, '1 '))
    warning = warnings_for(tmp_path, newer_die=hostile)[('packed', 'newer')]
    assert len(warning.summary) <= 160 and '‮' not in warning.summary and '\x07' not in warning.summary
    assert '<b>' in warning.summary  # plain text: markup is shown, never interpreted
    older = fingerprint_of(tmp_path, CLEAN, 'older', hostile)
    assert all(len(f.value) <= 200 and '‮' not in f.value for f in older.facts)


def test_large_evidence_set_is_capped(tmp_path):
    items = [('compiler', f'Tool{i}', str(i)) for i in range(200)]
    fp = fingerprint_of(tmp_path, CLEAN, 'older', detects(*items))
    assert len(fp.facts) == 128 and 'facts-truncated' in fp.anomalies


def test_unknown_type_names_raise_a_vocabulary_anomaly(tmp_path):
    fp = fingerprint_of(tmp_path, CLEAN, 'older', detects(('brand new type', 'X', '1')))
    assert 'vocabulary-drift' in fp.anomalies
