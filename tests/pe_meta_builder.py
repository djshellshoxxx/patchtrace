"""Synthetic Authenticode material for tests: a DER writer, X.509 and PKCS#7 builders, signed PE images and an
independent Authenticode digest reference. Bytes only: nothing is executed, no Microsoft bytes, no real keys (every
signature value is a constant filler; the readers under test make no signature-math claim).

The digest reference below deliberately shares no code with `pe_overview.signature`: it slices the image with plain
offsets taken from the builder's layout info, so a wrong range in the reader cannot cancel out in the test.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import replace

from pe_builder import PeSpec, SectionSpec, build_pe_ex

SPC_INDIRECT = '1.3.6.1.4.1.311.2.1.4'
SPC_PE_IMAGE = '1.3.6.1.4.1.311.2.1.15'
SIGNED_DATA = '1.2.840.113549.1.7.2'
NESTED_SIG = '1.3.6.1.4.1.311.2.4.1'
RFC3161_ATTR = '1.3.6.1.4.1.311.3.3.1'
COUNTERSIG = '1.2.840.113549.1.9.6'
SIGNING_TIME = '1.2.840.113549.1.9.5'
TST_INFO = '1.2.840.113549.1.9.16.1.4'
ALG_OIDS = {'sha1': '1.3.14.3.2.26', 'sha256': '2.16.840.1.101.3.4.2.1', 'sha384': '2.16.840.1.101.3.4.2.2',
            'sha512': '2.16.840.1.101.3.4.2.3', 'md5': '1.2.840.113549.2.5'}
RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
SHA256_RSA = '1.2.840.113549.1.1.11'
OID_CN = '2.5.4.3'
OID_ORG = '2.5.4.10'
OID_EKU_EXT = '2.5.29.37'
OID_CODE_SIGNING = '1.3.6.1.5.5.7.3.3'


# --- DER writer -------------------------------------------------------------------------------------------------

def length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b''.join(parts))


def set_(*parts: bytes) -> bytes:
    return tlv(0x31, b''.join(parts))


def explicit(number: int, *parts: bytes) -> bytes:
    return tlv(0xA0 | number, b''.join(parts))


def implicit_set(number: int, *parts: bytes) -> bytes:
    return tlv(0xA0 | number, b''.join(parts))


def integer(value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return tlv(0x02, value.to_bytes(size, 'big', signed=True))


def octets(data: bytes) -> bytes:
    return tlv(0x04, data)


def null() -> bytes:
    return b'\x05\x00'


def utf8(text: str) -> bytes:
    return tlv(0x0C, text.encode('utf-8'))


def bit_string(data: bytes) -> bytes:
    return tlv(0x03, b'\x00' + data)


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split('.')]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return tlv(0x06, bytes(body))


def utc_time(stamp: str) -> bytes:
    """`stamp` is 'YYYYMMDDHHMMSS'; years before 2050 use UTCTime, later ones GeneralizedTime (RFC 5280)."""
    if int(stamp[:4]) < 2050:
        return tlv(0x17, (stamp[2:] + 'Z').encode())
    return tlv(0x18, (stamp + 'Z').encode())


def gen_time(stamp: str) -> bytes:
    return tlv(0x18, (stamp + 'Z').encode())


def alg_id(dotted: str, params: bytes = b'\x05\x00') -> bytes:
    return seq(oid(dotted), params)


def name(common: str, org: str | None = None) -> bytes:
    rdns = [set_(seq(oid(OID_CN), utf8(common)))]
    if org:
        rdns.insert(0, set_(seq(oid(OID_ORG), utf8(org))))
    return seq(*rdns)


# --- X.509 / PKCS#7 ---------------------------------------------------------------------------------------------

def certificate(subject: str, issuer: str, serial: int, not_before: str = '20200101000000',
                not_after: str = '20300101000000', *, code_signing: bool = True, org: str | None = None) -> bytes:
    extensions = b''
    if code_signing:
        eku = seq(oid(OID_EKU_EXT), octets(seq(oid(OID_CODE_SIGNING))))
        extensions = explicit(3, seq(eku))
    tbs = seq(explicit(0, integer(2)), integer(serial), alg_id(SHA256_RSA), name(issuer, org),
              seq(utc_time(not_before), utc_time(not_after)), name(subject, org),
              seq(alg_id(RSA_ENCRYPTION), bit_string(b'\x00' * 8)), extensions)
    return seq(tbs, alg_id(SHA256_RSA), bit_string(b'\xAA' * 16))


def attribute(dotted: str, *values: bytes) -> bytes:
    return seq(oid(dotted), set_(*values))


def signer_info(issuer: str, serial: int, digest_alg: str, *, auth_attrs: tuple[bytes, ...] = (),
                unauth_attrs: tuple[bytes, ...] = (), org: str | None = None) -> bytes:
    parts = [integer(1), seq(name(issuer, org), integer(serial)), alg_id(ALG_OIDS[digest_alg])]
    if auth_attrs:
        parts.append(implicit_set(0, *auth_attrs))
    parts += [alg_id(RSA_ENCRYPTION), octets(b'\xBB' * 16)]
    if unauth_attrs:
        parts.append(implicit_set(1, *unauth_attrs))
    return seq(*parts)


def spc_indirect(digest_alg: str, digest: bytes) -> bytes:
    data = seq(oid(SPC_PE_IMAGE), seq(tlv(0x03, b'\x00')))
    return seq(data, seq(alg_id(ALG_OIDS[digest_alg]), octets(digest)))


def content_info_signed(signed_data: bytes) -> bytes:
    return seq(oid(SIGNED_DATA), explicit(0, signed_data))


def signed_data(digest_alg: str, content: bytes | None, certs: tuple[bytes, ...], signers: tuple[bytes, ...],
                *, content_type: str = SPC_INDIRECT) -> bytes:
    inner = [oid(content_type)]
    if content is not None:
        inner.append(explicit(0, content))
    parts = [integer(1), set_(alg_id(ALG_OIDS[digest_alg])), seq(*inner)]
    if certs:
        parts.append(implicit_set(0, *certs))
    parts.append(set_(*signers))
    return seq(*parts)


def tst_token(claimed: str, *, sha: str = 'sha256') -> bytes:
    """An RFC 3161 timestamp token (ContentInfo of SignedData whose content is a TSTInfo)."""
    info = seq(integer(1), oid('1.2.3.4'), seq(alg_id(ALG_OIDS[sha]), octets(b'\x00' * 32)), integer(7),
               gen_time(claimed))
    tsa = certificate('PT Test TSA', 'PT Test Root', 900)
    signer = signer_info('PT Test Root', 900, sha)
    sd = signed_data(sha, octets(info), (tsa,), (signer,), content_type=TST_INFO)
    return content_info_signed(sd)


def counter_signature(signing_time: str) -> bytes:
    return signer_info('PT Test TSA', 901, 'sha1', auth_attrs=(attribute(SIGNING_TIME, utc_time(signing_time)),))


def authenticode_blob(digest_alg: str, digest: bytes, *, subject: str = 'PT Test Publisher',
                      issuer: str = 'PT Test Root', serial: int = 4242, not_before: str = '20200101000000',
                      not_after: str = '20300101000000', unauth: tuple[bytes, ...] = (), org: str | None = None,
                      signer_cert: bool = True, extra_certs: tuple[bytes, ...] = ()) -> bytes:
    certs = list(extra_certs)
    if signer_cert:
        certs.insert(0, certificate(subject, issuer, serial, not_before, not_after, org=org))
    signer = signer_info(issuer, serial, digest_alg, unauth_attrs=unauth, org=org)
    return content_info_signed(signed_data(digest_alg, spc_indirect(digest_alg, digest), tuple(certs), (signer,)))


# --- signed PE images ---------------------------------------------------------------------------------------------

def reference_digest(data: bytes, info: dict, alg: str) -> bytes:
    """The Authenticode PE digest by plain slicing: header bytes minus CheckSum and the Security directory entry,
    then each section's raw bytes in file-offset order, then the trailing bytes before the certificate table."""
    h = hashlib.new(alg)
    checksum, entry = info['checksum_off'], info['dir_off'] + 4 * 8
    soh = info['size_of_headers']
    h.update(data[:checksum])
    h.update(data[checksum + 4:entry])
    h.update(data[entry + 8:soh])
    summed = soh
    for _name, _rva, _vsize, off, rsize in sorted(info['sections'], key=lambda s: s[3]):
        if rsize:
            h.update(data[off:off + rsize])
            summed += rsize
    h.update(data[summed:len(data) - info['cert_len']])
    return h.digest()


def three_range_digest(data: bytes, info: dict, alg: str) -> bytes:
    """Cross-check formulation: the whole file minus the three excluded ranges (valid while the sections are
    contiguous and the certificate table is last, as in every fixture of this module)."""
    omit = sorted([(info['checksum_off'], 4), (info['dir_off'] + 32, 8), (info['cert_off'], info['cert_len'])])
    h, pos = hashlib.new(alg), 0
    for start, size in omit:
        h.update(data[pos:start])
        pos = start + size
    h.update(data[pos:])
    return h.digest()


def base_spec(**kw) -> PeSpec:
    sections = [SectionSpec('.text', bytes(range(256)) * 3), SectionSpec('.data', b'DATA' * 200, 0xC0000040)]
    return PeSpec(sections=sections, overlay=kw.pop('overlay', b'OVERLAY-BYTES'), **kw)


def signed_pe(make_blobs, spec: PeSpec | None = None, algs: tuple[str, ...] = ('sha256',),
              count: int = 1) -> tuple[bytes, dict]:
    """Build an image, hash it, and embed `count` WIN_CERTIFICATE entries produced by
    `make_blobs(digests)` (digest bytes by algorithm name). The digest does not depend on the certificate table, so
    one placeholder pass fixes the layout."""
    spec = spec or base_spec()
    placeholder, info = build_pe_ex(replace(spec, cert_payloads=[b'\0' * 16] * count))
    digests = {alg: reference_digest(placeholder, info, alg) for alg in algs}
    payloads = make_blobs(digests)
    data, info = build_pe_ex(replace(spec, cert_payloads=list(payloads)))
    return data, info


def single_signature(alg: str = 'sha256', **blob_kw):
    def make(digests):
        return [authenticode_blob(alg, digests[alg], **blob_kw)]
    return signed_pe(make, algs=(alg,))


def dual_signature():
    """SHA-1 outer signature carrying a SHA-256 nested signature (unauthenticated attribute 1.3.6.1.4.1.311.2.4.1)."""
    def make(digests):
        nested = authenticode_blob('sha256', digests['sha256'], subject='PT Nested Publisher', serial=77)
        return [authenticode_blob('sha1', digests['sha1'], unauth=(attribute(NESTED_SIG, nested),))]
    return signed_pe(make, algs=('sha1', 'sha256'))


def set_entry_type(data: bytes, info: dict, cert_type: int) -> bytes:
    out = bytearray(data)
    struct.pack_into('<H', out, info['cert_off'] + 6, cert_type)
    return bytes(out)
