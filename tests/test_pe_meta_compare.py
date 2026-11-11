"""Version, manifest and signature comparison (SPEC-51 D2-5): the synergy fixture, the closed label set, the cache
key and the persistence round trip over a fake sidecar."""
from __future__ import annotations

import json
import re
from contextlib import contextmanager
from dataclasses import replace

import pytest
from pe_meta_builder import flip, meta_pe, single_signature

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview.cache import KIND, OVERVIEW_VERSION, cache_key, load_or_compute
from patchtrace.pe_overview.compare import compare_metadata
from patchtrace.pe_overview.labels import CATALOG_LABELS, EMBEDDED_LABELS, catalog_label, embedded_label
from patchtrace.pe_overview.metadata import inspect_metadata


@contextmanager
def opened(tmp_path, data, name='sample.bin'):
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        yield reader, inspect_pe(reader)


def metadata(tmp_path, data, name='sample.bin', cancel=None):
    with opened(tmp_path, data, name) as (reader, overview):
        return inspect_metadata(reader, overview, cancel)


def rows(older, newer):
    return {r.field: r for r in compare_metadata(older, newer)}


def test_metadata_reads_version_manifest_and_signature(tmp_path):
    data, _info = meta_pe('1.0.0.0', 'asInvoker')
    meta = metadata(tmp_path, data)
    assert meta.status == 'ok'
    assert meta.version.blocks[0].fixed.file_version == (1, 0, 0, 0)
    assert meta.manifests[0].execution_level == 'asInvoker'
    assert [(s.structure, s.digest_match) for s in meta.signatures] == [('ok', True)]


def test_metadata_of_a_plain_pe_is_empty_not_an_error(tmp_path):
    from pe_builder import build_pe
    meta = metadata(tmp_path, build_pe())
    assert (meta.status, meta.version, meta.manifests, meta.signatures) == ('ok', None, (), ())


def test_metadata_of_a_non_pe(tmp_path):
    assert metadata(tmp_path, b'hello world ' * 20).status == 'not_pe'


def test_metadata_cancel_is_reported(tmp_path):
    data, _info = meta_pe()
    assert metadata(tmp_path, data, cancel=lambda: True).status == 'cancelled'


def test_metadata_to_dict_is_json(tmp_path):
    data, _info = meta_pe()
    text = json.dumps(metadata(tmp_path, data).to_dict(), sort_keys=True)
    assert 'PT Test Publisher' in text and 'PT Test Corp' in text


def test_synergy_privilege_and_signature_delta(tmp_path):
    older = metadata(tmp_path, meta_pe('1.0.0.0', 'asInvoker')[0], 'a.bin')
    newer = metadata(tmp_path, meta_pe('1.0.1.0', 'requireAdministrator', signed=False, sections_extra=b'\xCC')[0],
                     'b.bin')
    found = rows(older, newer)
    assert (found['File version (fixed)'].older, found['File version (fixed)'].newer) == ('1.0.0.0', '1.0.1.0')
    assert found['File version (fixed)'].status == 'changed'
    exec_row = found['Requested execution level']
    assert (exec_row.older, exec_row.newer, exec_row.status) == ('asInvoker', 'requireAdministrator', 'changed')
    assert exec_row.reason == 'privilege request changed'
    assert (found['Signature (embedded)'].older, found['Signature (embedded)'].newer) == (
        'Signature present, digest matches file; trust not evaluated on this platform', 'Not signed')
    assert found['Signature (embedded)'].reason == 'signature removed'
    assert (found['Signature digest vs file'].older, found['Signature digest vs file'].newer) == (
        'matches', 'not applicable')
    lead = found['Combined lead (not a verdict)']
    assert lead.reason == 'newer build requests administrator rights and is not signed (a lead, not a verdict)'
    assert lead.status == 'changed'


def test_each_channel_alone_is_a_neutral_field_diff(tmp_path):
    older = metadata(tmp_path, meta_pe('1.0.0.0', 'asInvoker', signed=False)[0], 'a.bin')
    newer = metadata(tmp_path, meta_pe('1.0.0.0', 'requireAdministrator', signed=False)[0], 'b.bin')
    found = rows(older, newer)
    assert 'Combined lead (not a verdict)' not in found
    assert found['Requested execution level'].status == 'changed'


def test_changed_rows_come_first_and_order_is_stable(tmp_path):
    older = metadata(tmp_path, meta_pe('1.0.0.0')[0], 'a.bin')
    newer = metadata(tmp_path, meta_pe('1.0.1.0', company='Other Corp')[0], 'b.bin')
    result = compare_metadata(older, newer)
    statuses = [r.status for r in result]
    assert statuses == sorted(statuses, key=lambda s: s != 'changed')
    assert result == compare_metadata(older, newer)
    changed = [r.field for r in result if r.status == 'changed']
    assert 'CompanyName' in changed and 'FileVersion string' in changed


def test_tampered_section_reports_digest_mismatch(tmp_path):
    data, info = meta_pe('1.0.0.0')
    tampered = flip(data, info['sections'][0][3] + 3)
    newer = metadata(tmp_path, tampered, 'b.bin')
    older = metadata(tmp_path, data, 'a.bin')
    found = rows(older, newer)
    assert found['Signature (embedded)'].newer == 'Signature present, digest does NOT match file'
    assert found['Signature digest vs file'].newer == 'does NOT match'
    for text in (found['Signature (embedded)'].newer, found['Signature digest vs file'].newer):
        assert not re.search(r'\b(valid|verified|trusted|safe)\b', text.replace('does NOT match', ''), re.I)


def test_unavailable_side(tmp_path):
    older = metadata(tmp_path, meta_pe()[0])
    result = compare_metadata(older, None)
    assert [r.status for r in result] == ['unavailable']
    assert 'newer' in result[0].reason


def test_unsigned_vs_unsigned_is_unchanged(tmp_path):
    a = metadata(tmp_path, meta_pe(signed=False)[0], 'a.bin')
    b = metadata(tmp_path, meta_pe(signed=False)[0], 'b.bin')
    found = rows(a, b)
    assert found['Signature (embedded)'].status == 'unchanged'
    assert all(r.status == 'unchanged' for r in found.values())


def test_signer_change_is_reported(tmp_path):
    a, _ = single_signature('sha256', subject='Old Publisher')
    b, _ = single_signature('sha256', subject='New Publisher', issuer='Other Root')
    found = rows(metadata(tmp_path, a, 'a.bin'), metadata(tmp_path, b, 'b.bin'))
    assert (found['Signer subject'].older, found['Signer subject'].newer) == ('Old Publisher', 'New Publisher')
    assert found['Signer subject'].reason == 'signer changed'
    assert found['Signer issuer'].status == 'changed'


def test_digest_algorithm_downgrade_is_labelled(tmp_path):
    a, _ = single_signature('sha256')
    b, _ = single_signature('sha1')
    found = rows(metadata(tmp_path, a, 'a.bin'), metadata(tmp_path, b, 'b.bin'))
    assert found['Signature digest algorithm'].reason == 'digest algorithm weaker'


# --- labels ---------------------------------------------------------------------------------------------------------

def test_label_set_is_closed(tmp_path):
    seen = set()
    good, info = single_signature('sha256')
    cases = {
        'none': (),
        'good': metadata(tmp_path, good, 'g.bin').signatures,
        'bad': metadata(tmp_path, flip(good, info['sections'][0][3]), 'b.bin').signatures,
        'unreadable': metadata(tmp_path, flip(good, info['cert_off'] + 6), 'u.bin').signatures,
    }
    for sigs in cases.values():
        for status in (None, 'unavailable', 'unsigned', 'untrusted', 'invalid', 'unknown', 'trusted_no_revocation_check'):
            seen.add(embedded_label(sigs, status))
    assert seen <= set(EMBEDDED_LABELS)
    assert {'Not signed', 'Signature present, structure unreadable', 'Signature present, digest does NOT match file',
            'Signature present, digest matches file; trust not evaluated on this platform'} <= seen
    for label in (*EMBEDDED_LABELS, *CATALOG_LABELS):
        assert not re.search(r'\b(valid|verified publisher|safe)\b', label, re.I)
    assert {catalog_label(s) for s in ('present_trusted_no_revocation_check', 'present_untrusted', 'absent',
                                       'not_checked', 'unavailable')} <= set(CATALOG_LABELS)


def test_windows_trust_text_is_only_used_when_the_digest_matches(tmp_path):
    good, info = single_signature('sha256')
    ok = metadata(tmp_path, good, 'g.bin').signatures
    bad = metadata(tmp_path, flip(good, info['sections'][0][3]), 'b.bin').signatures
    assert embedded_label(ok, 'trusted_no_revocation_check') == (
        'embedded signature chains to a trusted root (revocation NOT checked)')
    assert embedded_label(bad, 'trusted_no_revocation_check') == 'Signature present, digest does NOT match file'


def test_catalog_labels():
    assert catalog_label('absent') == 'No catalog signature found'
    assert catalog_label('present_trusted_no_revocation_check') == 'Catalog signature present (no revocation check)'
    assert catalog_label('not_checked') == 'Not checked'


# --- cache key and persistence -------------------------------------------------------------------------------------

class FakePort:
    def __init__(self):
        self.rows: dict[tuple[str, str], dict] = {}
        self.puts = 0

    def get(self, kind, key):
        return self.rows.get((kind, key))

    def put(self, kind, key, payload):
        self.puts += 1
        self.rows[(kind, key)] = payload


def test_cache_key_covers_every_input():
    base = cache_key('a' * 64, Limits(), 'offline', 'portable')
    assert re.fullmatch(r'[0-9a-f]{64}', base)
    assert base == cache_key('a' * 64, Limits(), 'offline', 'portable')
    for other in (cache_key('b' * 64, Limits(), 'offline', 'portable'),
                  cache_key('a' * 64, replace(Limits(), max_der_nodes=1), 'offline', 'portable'),
                  cache_key('a' * 64, Limits(), 'cache', 'portable'),
                  cache_key('a' * 64, Limits(), 'offline', 'win32:22631')):
        assert other != base
    assert OVERVIEW_VERSION == 2 and KIND == 'pe-metadata'


def test_load_or_compute_hits_the_sidecar_once(tmp_path):
    data, _info = meta_pe()
    port = FakePort()
    calls = []

    def compute():
        calls.append(1)
        return metadata(tmp_path, data).to_dict()
    key = cache_key('a' * 64, Limits(), 'offline', 'portable')
    first = load_or_compute(port, key, compute, {'trust_mode': 'offline'})
    second = load_or_compute(port, key, compute, {'trust_mode': 'offline'})
    assert first == second and len(calls) == 1 and port.puts == 1
    stored = port.rows[(KIND, key)]
    assert stored['overview_version'] == 2 and stored['consent'] == {'trust_mode': 'offline'}


def test_a_portable_result_is_not_reused_as_a_windows_result(tmp_path):
    port = FakePort()
    portable = cache_key('a' * 64, Limits(), 'offline', 'portable')
    windows = cache_key('a' * 64, Limits(), 'offline', 'win32:22631')
    load_or_compute(port, portable, lambda: {'x': 1}, {})
    assert port.get(KIND, windows) is None


def test_a_damaged_sidecar_row_is_recomputed():
    port = FakePort()
    key = cache_key('a' * 64, Limits(), 'offline', 'portable')
    port.put(KIND, key, {'overview_version': 1, 'result': {'old': True}, 'consent': {}})
    assert load_or_compute(port, key, lambda: {'new': True}, {}) == {'new': True}


@pytest.mark.parametrize('mode', ['offline', 'cache', 'online'])
def test_trust_modes_have_distinct_keys(mode):
    keys = {cache_key('a' * 64, Limits(), m, 'portable') for m in ('offline', 'cache', 'online')}
    assert len(keys) == 3 and cache_key('a' * 64, Limits(), mode, 'portable') in keys
