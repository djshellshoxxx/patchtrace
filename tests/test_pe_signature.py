"""Embedded Authenticode structure and digest (SPEC-51 D2-3): known-answer digests computed independently with
hashlib, tamper and excluded-region tests, dual signatures, timestamps as claims, hostile PKCS#7 and caps."""
from __future__ import annotations

import json
import random
import socket
from contextlib import contextmanager
from dataclasses import asdict, replace

import pytest
from pe_builder import build_pe_ex
from pe_meta_builder import (
    COUNTERSIG,
    NESTED_SIG,
    RFC3161_ATTR,
    attribute,
    authenticode_blob,
    base_spec,
    certificate,
    counter_signature,
    dual_signature,
    flip,
    reference_digest,
    set_entry_type,
    signed_pe,
    single_signature,
    tst_token,
)

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview.signature import verify_embedded

DEFAULT = Limits()


@contextmanager
def opened(tmp_path, data, limits=DEFAULT):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        yield reader, inspect_pe(reader, limits=limits)


def verify(tmp_path, data, *, limits=DEFAULT, cancel=None):
    with opened(tmp_path, data, limits) as (reader, overview):
        return verify_embedded(reader, overview, cancel, limits)


def test_unsigned_pe_has_no_signatures(tmp_path):
    assert verify(tmp_path, build_pe_ex(base_spec())[0]) == ()


def test_not_pe_has_no_signatures(tmp_path):
    assert verify(tmp_path, b'not a pe file at all' * 10) == ()


def test_single_sha256_signature_identity_and_digest(tmp_path):
    data, info = single_signature('sha256', org='PT Org')
    (sig,) = verify(tmp_path, data)
    expected = reference_digest(data, info, 'sha256').hex()
    assert (sig.index, sig.nested_depth, sig.structure) == (0, 0, 'ok')
    assert (sig.digest_algorithm, sig.weak_digest) == ('sha256', False)
    assert sig.digest_claimed_hex == sig.digest_computed_hex == expected
    assert sig.digest_match is True
    (signer,) = sig.signers
    assert (signer.subject_cn, signer.issuer_cn, signer.serial_hex) == ('PT Test Publisher', 'PT Test Root', '1092')
    assert signer.subject_dn == 'O=PT Org, CN=PT Test Publisher'
    assert signer.issuer_dn == 'O=PT Org, CN=PT Test Root'
    assert (signer.not_before, signer.not_after) == ('2020-01-01T00:00:00Z', '2030-01-01T00:00:00Z')
    assert (signer.eku_code_signing, signer.digest_alg, signer.signer_cert_found) == (True, 'sha256', True)
    assert signer.signature_alg_oid == '1.2.840.113549.1.1.1'
    assert len(sig.certificates) == 1 and sig.certificates[0].subject_cn == 'PT Test Publisher'
    assert (sig.signature_math, sig.chain, sig.revocation) == ('not_evaluated', 'not_evaluated', 'not_checked')
    assert sig.warnings == () and sig.timestamps == ()


@pytest.mark.parametrize('alg', ['sha1', 'sha256', 'sha384', 'sha512', 'md5'])
def test_known_answer_digest_per_algorithm(tmp_path, alg):
    from pe_meta_builder import three_range_digest
    data, info = single_signature(alg)
    (sig,) = verify(tmp_path, data)
    assert sig.digest_algorithm == alg
    assert sig.digest_computed_hex == reference_digest(data, info, alg).hex()
    assert sig.digest_computed_hex == three_range_digest(data, info, alg).hex()  # two formulations agree
    assert sig.digest_match is True
    assert sig.weak_digest is (alg in ('sha1', 'md5'))


@pytest.mark.parametrize('where', ['checksum', 'cert_signature_value'])
def test_flips_in_excluded_regions_keep_the_match(tmp_path, where):
    data, info = single_signature('sha256')
    if where == 'checksum':
        data = flip(data, info['checksum_off'])
    else:
        data = flip(data, data.rindex(b'\xBB' * 16))
    (sig,) = verify(tmp_path, data)
    assert sig.digest_match is True


@pytest.mark.parametrize('where', ['header_timestamp', 'section_byte', 'second_section', 'overlay', 'overlay_padding'])
def test_flips_elsewhere_break_the_match(tmp_path, where):
    data, info = single_signature('sha256')
    offset = {
        'header_timestamp': info['e_lfanew'] + 8,
        'section_byte': info['sections'][0][3] + 5,
        'second_section': info['sections'][1][3] + 9,
        'overlay': info['overlay_off'] + 2,
        'overlay_padding': info['cert_off'] - 1,
    }[where]
    (sig,) = verify(tmp_path, flip(data, offset))
    assert sig.digest_match is False
    assert sig.digest_claimed_hex != sig.digest_computed_hex
    assert 'signature_digest_mismatch' in sig.warnings


def test_tampered_section_reports_digest_mismatch(tmp_path):
    data, info = single_signature('sha256')
    sig = verify(tmp_path, flip(data, info['sections'][0][3] + 1))[0]
    assert (sig.structure, sig.digest_match) == ('ok', False)
    assert sig.signers[0].subject_cn == 'PT Test Publisher'  # identity is still reported, never as a verdict


def test_dual_signature_is_flattened_with_nested_depth(tmp_path):
    data, info = dual_signature()
    sigs = verify(tmp_path, data)
    assert [(s.index, s.nested_depth, s.digest_algorithm) for s in sigs] == [(0, 0, 'sha1'), (0, 1, 'sha256')]
    assert [s.digest_match for s in sigs] == [True, True]
    assert sigs[0].digest_computed_hex == reference_digest(data, info, 'sha1').hex()
    assert sigs[1].digest_computed_hex == reference_digest(data, info, 'sha256').hex()
    assert sigs[0].signers[0].subject_cn == 'PT Test Publisher'
    assert sigs[1].signers[0].subject_cn == 'PT Nested Publisher'
    assert sigs[0].weak_digest and not sigs[1].weak_digest


def test_dual_signature_tamper_breaks_both(tmp_path):
    data, info = dual_signature()
    sigs = verify(tmp_path, flip(data, info['sections'][1][3]))
    assert [s.digest_match for s in sigs] == [False, False]


def test_two_win_certificate_entries(tmp_path):
    def make(digests):
        return [authenticode_blob('sha256', digests['sha256'], subject='First', serial=1),
                authenticode_blob('sha256', digests['sha256'], subject='Second', serial=2)]
    data, _info = signed_pe(make, count=2)
    sigs = verify(tmp_path, data)
    assert [(s.index, s.signers[0].subject_cn, s.digest_match) for s in sigs] == [
        (0, 'First', True), (1, 'Second', True)]


def test_nested_cap_warns_and_flattens_at_most_the_cap(tmp_path):
    def make(digests):
        nested = [attribute(NESTED_SIG, authenticode_blob('sha256', digests['sha256'], subject=f'N{i}', serial=10 + i))
                  for i in range(6)]
        return [authenticode_blob('sha256', digests['sha256'], unauth=tuple(nested))]
    data, _info = signed_pe(make)
    sigs = verify(tmp_path, data)
    assert [s.nested_depth for s in sigs] == [0, 1, 1, 1, 1]
    assert 'signature_nested_over_cap' in sigs[0].warnings


def test_unsupported_certificate_type(tmp_path):
    data, info = single_signature('sha256')
    (sig,) = verify(tmp_path, set_entry_type(data, info, 3))
    assert (sig.structure, sig.digest_match, sig.signers, sig.digest_algorithm) == (
        'unsupported_type', None, (), 'unknown')
    assert 'signature_unsupported_type' in sig.warnings


@pytest.mark.parametrize('payload', [b'\x30\x80\x00\x00', b'\xff' * 40, b'\x30\x03\x02\x01\x01', b'',
                                     b'\x30\x00', bytes([0x30, 0x06, 0x06, 0x01, 0x2a, 0x05, 0x00, 0x00])],
                         ids=['indefinite', 'noise', 'tiny', 'empty', 'empty-seq', 'wrong-oid'])
def test_malformed_pkcs7_is_a_warning_not_an_exception(tmp_path, payload):
    data = build_pe_ex(replace(base_spec(), cert_payloads=[payload]))[0]
    (sig,) = verify(tmp_path, data)
    assert sig.structure == 'malformed'
    assert sig.digest_match is None and sig.signers == ()
    assert any(w.startswith('signature_der_') for w in sig.warnings)


def test_oversized_signature_reports_the_cap(tmp_path):
    big = authenticode_blob('sha256', b'\0' * 32, extra_certs=tuple(
        certificate(f'filler {i}', 'x', i, org='y' * 300) for i in range(60)))
    data = build_pe_ex(replace(base_spec(), cert_payloads=[big]))[0]
    (sig,) = verify(tmp_path, data, limits=Limits(max_der_bytes=4096))
    assert sig.structure == 'malformed' and 'signature_der_over_cap' in sig.warnings


def test_certificate_cap(tmp_path):
    def make(digests):
        return [authenticode_blob('sha256', digests['sha256'], extra_certs=tuple(
            certificate(f'extra {i}', 'PT Test Root', 1000 + i) for i in range(70)))]
    data, _info = signed_pe(make)
    (sig,) = verify(tmp_path, data)
    assert len(sig.certificates) == 64
    assert 'signature_certs_over_cap' in sig.warnings
    assert sig.signers[0].signer_cert_found is True


def test_signer_without_certificate(tmp_path):
    data, _info = single_signature('sha256', signer_cert=False)
    (sig,) = verify(tmp_path, data)
    (signer,) = sig.signers
    assert signer.signer_cert_found is False
    assert (signer.issuer_cn, signer.subject_cn, signer.serial_hex) == ('PT Test Root', None, '1092')
    assert sig.certificates == ()


def test_hostile_names_are_cleaned(tmp_path):
    evil = 'Evil‮ Corp\x1b[31m'
    data, _info = single_signature('sha256', subject=evil)
    (sig,) = verify(tmp_path, data)
    cn = sig.signers[0].subject_cn
    assert '‮' not in cn and '\x1b' not in cn and cn.startswith('Evil? Corp')


def test_unknown_digest_algorithm(tmp_path):
    def make(digests):
        blob = authenticode_blob('sha256', digests['sha256'])
        return [blob.replace(bytes.fromhex('0609608648016503040201'), bytes.fromhex('0609608648016503040299'))]
    data, _info = signed_pe(make)
    sigs = verify(tmp_path, data)
    assert sigs[0].digest_algorithm == 'unknown'
    assert sigs[0].digest_match is None and sigs[0].digest_computed_hex is None
    assert 'signature_digest_unsupported' in sigs[0].warnings


def test_large_file_skips_the_digest(tmp_path):
    data, _info = single_signature('sha256')
    (sig,) = verify(tmp_path, data, limits=Limits(checksum_max_file=len(data) - 1))
    assert sig.digest_computed_hex is None and sig.digest_match is None
    assert sig.digest_claimed_hex is not None
    assert 'digest_skipped_large' in sig.warnings


def test_digest_reads_are_chunked_and_cancel_is_polled(tmp_path):
    spec = base_spec(overlay=b'\xAB' * 5000)
    data, _info = signed_pe(lambda d: [authenticode_blob('sha256', d['sha256'])], spec)
    polls = []

    def cancel():
        polls.append(1)
        return False
    (sig,) = verify(tmp_path, data, limits=Limits(chunk=512), cancel=cancel)
    assert sig.digest_match is True
    assert len(polls) >= 10


def test_cancel_returns_without_a_verdict(tmp_path):
    data, _info = single_signature('sha256')
    sigs = verify(tmp_path, data, cancel=lambda: True)
    assert all(s.digest_match is not True for s in sigs)


def test_rfc3161_timestamp_is_a_claim(tmp_path):
    def make(digests):
        return [authenticode_blob('sha256', digests['sha256'], unauth=(
            attribute(RFC3161_ATTR, tst_token('20240301102030')),))]
    data, _info = signed_pe(make)
    (sig,) = verify(tmp_path, data)
    (stamp,) = sig.timestamps
    assert (stamp.kind, stamp.claimed_time_utc, stamp.token_structure_ok) == ('rfc3161', '2024-03-01T10:20:30Z', True)
    assert stamp.note == 'Claimed by the signature container; its signature and chain were not verified.'


def test_ms_countersignature_timestamp_is_a_claim(tmp_path):
    def make(digests):
        return [authenticode_blob('sha256', digests['sha256'], unauth=(
            attribute(COUNTERSIG, counter_signature('20230615080910')),))]
    data, _info = signed_pe(make)
    (sig,) = verify(tmp_path, data)
    (stamp,) = sig.timestamps
    assert (stamp.kind, stamp.claimed_time_utc, stamp.token_structure_ok) == (
        'ms_countersignature', '2023-06-15T08:09:10Z', True)


def test_broken_timestamp_token_is_flagged_not_fatal(tmp_path):
    def make(digests):
        return [authenticode_blob('sha256', digests['sha256'], unauth=(attribute(RFC3161_ATTR, b'\x30\x00'),))]
    data, _info = signed_pe(make)
    (sig,) = verify(tmp_path, data)
    assert sig.structure == 'ok' and sig.digest_match is True
    assert [(t.kind, t.token_structure_ok, t.claimed_time_utc) for t in sig.timestamps] == [('rfc3161', False, None)]


def test_claimed_digest_comes_from_the_signed_content(tmp_path):
    forged, _ = signed_pe(lambda d: [authenticode_blob('sha256', b'\x11' * 32)])
    (sig,) = verify(tmp_path, forged)
    assert sig.digest_claimed_hex == '11' * 32 and sig.digest_match is False


def test_result_is_deterministic_json(tmp_path):
    data, _info = dual_signature()
    first = json.dumps([asdict(s) for s in verify(tmp_path, data)], sort_keys=True)
    second = json.dumps([asdict(s) for s in verify(tmp_path, data)], sort_keys=True)
    assert first == second and 'valid' not in first.lower().replace('invalid', '')


def test_no_network_and_no_execution(tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError('network used')
    monkeypatch.setattr(socket, 'socket', refuse)
    data, _info = single_signature('sha256')
    assert verify(tmp_path, data)[0].digest_match is True


def test_mutated_signature_bytes_never_raise(tmp_path):
    data, info = dual_signature()
    rng = random.Random(51)
    start, end = info['cert_off'], info['cert_off'] + info['cert_len']
    for _ in range(150):
        mutated = bytearray(data)
        for _ in range(rng.randint(1, 6)):
            mutated[rng.randrange(start, end)] = rng.randrange(256)
        for sig in verify(tmp_path, bytes(mutated)):
            assert sig.structure in ('ok', 'malformed', 'unsupported_type')
            assert sig.signature_math == 'not_evaluated'


def test_digest_survives_pe32(tmp_path):
    spec = replace(base_spec(), pe32plus=False)
    data, info = signed_pe(lambda d: [authenticode_blob('sha256', d['sha256'])], spec)
    (sig,) = verify(tmp_path, data)
    assert sig.digest_computed_hex == reference_digest(data, info, 'sha256').hex() and sig.digest_match is True
