"""RSA PKCS#1 v1.5 check with pow() (SPEC-51 D2-6): openssl known answers, tamper, bounds, and the end-to-end label
"signature math ok, chain not evaluated" that never becomes a trust claim."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager

import pytest
from pe_meta_builder import flip, signed_pe
from pe_rsa_builder import (
    OPENSSL_SIGNATURES,
    RSA_E,
    RSA_MESSAGE,
    RSA_N,
    rsa_authenticode_blob,
    rsa_sign,
)

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.der import parse
from patchtrace.pe_overview.labels import MATCH, MATH_FAILED, MATH_OK, WINDOWS_TRUSTED, embedded_label
from patchtrace.pe_overview.rsa_verify import public_key_from_spki, verify_pkcs1_v15
from patchtrace.pe_overview.signature import verify_embedded


def digest_of(alg, data=RSA_MESSAGE):
    return hashlib.new(alg, data).digest()


@pytest.mark.parametrize('alg', ['sha1', 'sha256', 'sha512'])
def test_openssl_known_answers_verify(alg):
    signature = bytes.fromhex(OPENSSL_SIGNATURES[alg])
    assert verify_pkcs1_v15(RSA_N, RSA_E, digest_of(alg), alg, signature) is True
    assert rsa_sign(alg, RSA_MESSAGE) == signature  # the independent test signer agrees with openssl


@pytest.mark.parametrize('alg', ['sha1', 'sha256', 'sha512'])
def test_tampering_fails(alg):
    signature = bytes.fromhex(OPENSSL_SIGNATURES[alg])
    assert verify_pkcs1_v15(RSA_N, RSA_E, digest_of(alg, RSA_MESSAGE + b'!'), alg, signature) is False
    flipped = bytes([signature[0] ^ 1]) + signature[1:]
    assert verify_pkcs1_v15(RSA_N, RSA_E, digest_of(alg), alg, flipped) is False
    assert verify_pkcs1_v15(RSA_N, RSA_E, digest_of(alg), 'sha1' if alg != 'sha1' else 'sha256', signature) is False


@pytest.mark.parametrize('n,e,sig', [
    (RSA_N, RSA_E, b'\x01' * 10),                       # wrong length
    (RSA_N, RSA_E, (RSA_N + 1).to_bytes(128, 'big')),   # signature not below the modulus
    (RSA_N, 1, bytes.fromhex(OPENSSL_SIGNATURES['sha256'])),
    (RSA_N, 0, bytes.fromhex(OPENSSL_SIGNATURES['sha256'])),
    (RSA_N, 2**80 + 1, bytes.fromhex(OPENSSL_SIGNATURES['sha256'])),   # absurd exponent: refused, not computed
    (3, 3, b'\x02'),                                    # modulus too small for the encoding
    (1 << 9000, 65537, b'\x01' * 1126),                 # modulus over the bit cap
    (RSA_N + 1, RSA_E, bytes.fromhex(OPENSSL_SIGNATURES['sha256'])),   # even modulus
], ids=['short', 'too-big', 'e1', 'e0', 'e-huge', 'tiny-n', 'huge-n', 'even-n'])
def test_bounds_and_nonsense_are_refused(n, e, sig):
    assert verify_pkcs1_v15(n, e, digest_of('sha256'), 'sha256', sig) is False


def test_unknown_algorithm_is_refused():
    assert verify_pkcs1_v15(RSA_N, RSA_E, b'\0' * 16, 'md4', b'\0' * 128) is False


def test_public_key_is_read_from_a_certificate():
    from pe_rsa_builder import rsa_certificate
    cert = parse(rsa_certificate('s', 'i', 1))
    spki = cert.children[0].children[6]
    assert public_key_from_spki(spki) == (RSA_N, RSA_E)


def test_public_key_of_a_non_rsa_or_broken_key_is_none():
    from pe_meta_builder import alg_id, bit_string, seq
    assert public_key_from_spki(parse(seq(alg_id('1.2.840.10045.2.1'), bit_string(b'\x04' * 20)))) is None
    assert public_key_from_spki(parse(seq(alg_id('1.2.840.113549.1.1.1'), bit_string(b'\x00' * 8)))) is None


# --- end to end ---------------------------------------------------------------------------------------------------

@contextmanager
def opened(tmp_path, data):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        yield reader, inspect_pe(reader)


def signatures(tmp_path, tamper=None, alg='sha256', flip_section=False):
    data, info = signed_pe(lambda d: [rsa_authenticode_blob(alg, d[alg], tamper=tamper)], algs=(alg,))
    if flip_section:
        data = flip(data, info['sections'][0][3] + 1)
    with opened(tmp_path, data) as (reader, overview):
        return verify_embedded(reader, overview)


@pytest.mark.parametrize('alg', ['sha1', 'sha256', 'sha512'])
def test_real_rsa_signature_reports_math_ok_chain_not_evaluated(tmp_path, alg):
    (sig,) = signatures(tmp_path, alg=alg)
    assert sig.signature_math == 'ok_chain_not_evaluated'
    assert sig.chain == 'not_evaluated' and sig.revocation == 'not_checked' and sig.digest_match is True
    assert embedded_label((sig,)) == MATH_OK
    assert embedded_label((sig,), 'trusted_no_revocation_check') == WINDOWS_TRUSTED


@pytest.mark.parametrize('tamper', ['signature', 'attributes'])
def test_tampered_container_fails_the_math(tmp_path, tamper):
    (sig,) = signatures(tmp_path, tamper=tamper)
    assert sig.signature_math == 'failed'
    assert embedded_label((sig,)) == MATH_FAILED


def test_math_can_be_ok_while_the_file_digest_does_not_match(tmp_path):
    (sig,) = signatures(tmp_path, flip_section=True)
    assert sig.signature_math == 'ok_chain_not_evaluated' and sig.digest_match is False
    assert embedded_label((sig,)) == 'Signature present, digest does NOT match file'


def test_signatures_without_a_usable_key_stay_not_evaluated(tmp_path):
    from pe_meta_builder import single_signature
    data, _info = single_signature('sha256')
    with opened(tmp_path, data) as (reader, overview):
        (sig,) = verify_embedded(reader, overview)
    assert sig.signature_math == 'not_evaluated' and embedded_label((sig,)) == MATCH


def test_labels_never_say_valid_or_trusted():
    import re
    for text in (MATH_OK, MATH_FAILED):
        assert not re.search(r'\b(valid|verified publisher|safe|trusted)\b', text, re.I)
