"""Real RSA PKCS#1 v1.5 material for tests: a throwaway 1024-bit key (never used for anything else), signatures that
`openssl dgst -sign` produced over RSA_MESSAGE as known answers, an independent signer written from RFC 8017
section 9.2, and an Authenticode container signed with it."""
from __future__ import annotations

import hashlib

from pe_meta_builder import (
    ALG_OIDS,
    RSA_ENCRYPTION,
    SPC_INDIRECT,
    alg_id,
    attribute,
    bit_string,
    content_info_signed,
    explicit,
    implicit_set,
    integer,
    name,
    octets,
    oid,
    seq,
    set_,
    signed_data,
    spc_indirect,
    utc_time,
)

RSA_N = int('eccc19f6184a628781a320e71dd6e760a66cab05f0d6dc6895149edc3b843b957cdad74990a8441b022734ca9feb808c98e2a5d9'
            'eb6813d1387a427650c5e3d453e8e65dc805e40df827eae286b335b40dccc482170d619fb252c2492c1b49edfcca16b85c659861'
            'e66b225208e03938f9c047260aca40812dd6d0c949c52149', 16)
RSA_E = 65537
RSA_D = int('a1843e190c4c8094692a79e0eb0b90daede9a565f1f6bc74616ba54817188503dc1bf148ee70b7b3ac6e4da6001ac49e2212468a'
            '33f5d3be9bc558dc171043eb5a3a8b1321e0181f0eea5d9441ecf594d6eaa53f2ca070d96dd2aed0132c1446a81aecd682a4d0dc'
            '6783af130a4415519b5f10677b6a518090fcccb6a6991601', 16)
RSA_MESSAGE = b'PatchTrace RSA known answer'
OPENSSL_SIGNATURES = {
    'sha1': 'be309f855b398dca7417ebd7071abfaa869ddc91b4ba6616b9d9a4f2a3627febc930793e488134ae38719f87aa50740c40e4e2e22'
            '8746b0d9414c9f4be641b70a7477b1b73ca357ded852ab055a709755e612413156683ba2fb4bd24b1416e6b0809eedbe7b5c4946'
            '0932efee9f82e66acf97c11db5a2298c30625deab3ea157',
    'sha256': '87bd567dacd7154ed56d6e0206c3fe884e53dbe1eee446f7d94f90c99997d3b46ed65a107e0a4074be63ad83063ffa54e880c80f'
              '4ceb32f42441968a7f44ce1e1fdd2665c20eef173c0887e543c3a30d14fca4ce686e699617e29825ae56ccdfb643a12c1c3d5cf3'
              '33d69469f2ff38c076d9d06e374d9415d6a4316b8bd303a8',
    'sha512': '2ced3e3cc7bc4c51841fed277745754f3580ff2eddd28a8d74c97ecc7e388383fd4d649efca9b244002ee12ebc03348243251bd5'
              'a61e4f8f280be9741ac3ed10d2eb8bfa37d856e6fcf09853fe908a5247088b5c4c3203d10407b27cbb951a32efb5d67fbaa887e4'
              '5954e8565629622a5d6748909aac3f10a99eac54f05a1a02',
}
_PREFIX = {'sha1': '3021300906052b0e03021a05000414', 'sha256': '3031300d060960864801650304020105000420',
           'sha512': '3051300d060960864801650304020305000440'}
MESSAGE_DIGEST_ATTR = '1.2.840.113549.1.9.4'
CONTENT_TYPE_ATTR = '1.2.840.113549.1.9.3'


def rsa_sign(alg: str, data: bytes) -> bytes:
    """EMSA-PKCS1-v1_5 encoding and the private exponent."""
    info = bytes.fromhex(_PREFIX[alg]) + hashlib.new(alg, data).digest()
    size = (RSA_N.bit_length() + 7) // 8
    encoded = b'\x00\x01' + b'\xff' * (size - len(info) - 3) + b'\x00' + info
    return pow(int.from_bytes(encoded, 'big'), RSA_D, RSA_N).to_bytes(size, 'big')


def content_of(der: bytes) -> bytes:
    """The content octets of one DER element: what PKCS#7 hashes for the messageDigest attribute."""
    size = der[1]
    return der[2 if size < 0x80 else 2 + (size & 0x7F):]


def rsa_certificate(subject: str, issuer: str, serial: int) -> bytes:
    from pe_meta_builder import OID_CODE_SIGNING, OID_EKU_EXT, SHA256_RSA
    key = seq(integer(RSA_N), integer(RSA_E))
    tbs = seq(explicit(0, integer(2)), integer(serial), alg_id(SHA256_RSA), name(issuer),
              seq(utc_time('20200101000000'), utc_time('20300101000000')), name(subject),
              seq(alg_id(RSA_ENCRYPTION), bit_string(key)),
              explicit(3, seq(seq(oid(OID_EKU_EXT), octets(seq(oid(OID_CODE_SIGNING)))))))
    return seq(tbs, alg_id(SHA256_RSA), bit_string(b'\xAA' * 16))


def rsa_authenticode_blob(alg: str, file_digest: bytes, *, tamper: str | None = None) -> bytes:
    """A SignedData whose signer signature is real RSA over the authenticated attributes. `tamper` is
    'signature' (one bit of the signature), 'attributes' (messageDigest attribute changed after signing) or None."""
    content = spc_indirect(alg, file_digest)
    md = hashlib.new(alg, content_of(content)).digest()
    attrs = (attribute(CONTENT_TYPE_ATTR, oid(SPC_INDIRECT)), attribute(MESSAGE_DIGEST_ATTR, octets(md)))
    signature = rsa_sign(alg, set_(*attrs))
    if tamper == 'signature':
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    if tamper == 'attributes':
        attrs = (attrs[0], attribute(MESSAGE_DIGEST_ATTR, octets(b'\x00' * len(md))))
    signer = seq(integer(1), seq(name('PT Test Root'), integer(4242)), alg_id(ALG_OIDS[alg]),
                 implicit_set(0, *attrs), alg_id(RSA_ENCRYPTION), octets(signature))
    cert = rsa_certificate('PT RSA Publisher', 'PT Test Root', 4242)
    return content_info_signed(signed_data(alg, content, (cert,), (signer,)))
