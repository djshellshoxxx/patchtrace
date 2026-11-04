"""Embedded Authenticode structure and digest without trust (SPEC-51 D2-3). Stdlib only, no Qt, no network.

Reads each `WIN_CERTIFICATE` (PKCS#7 `SignedData` carrying `SpcIndirectDataContent`) of the security directory,
reports the signature's claimed file digest, signer and certificate identity, validity windows, timestamp CLAIMS and
nested signatures, and recomputes the PE Authenticode digest from the verified reader. It makes no statement about
the signature math, the certificate chain or revocation: those fields say `not_evaluated` / `not_checked`. A digest
match means the file bytes equal what the container claims, never that anyone should trust the container.

Authenticode digest (checked against signify 0.7.1, MIT, `signed_file/pe.py`, and recorded in the spec status line):
the file minus the optional-header CheckSum, the Security data-directory entry and the certificate table, hashed as
headers up to SizeOfHeaders, then every section's raw bytes in PointerToRawData order, then the bytes between the
last section and the certificate table. Container OIDs follow the same source and RFC 2315 / RFC 3161.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from patchtrace.artifact_bytes import VerifiedArtifactReader

from ._common import Cancelled, Ctx
from .der import (
    INVALID,
    OCTET_STRING,
    SEQUENCE,
    SET,
    DerError,
    DerLimits,
    Node,
    decode_int,
    decode_oid,
    decode_text,
    decode_time,
    parse,
)
from .models import (
    CertificateSummary,
    Limits,
    PeOverview,
    SignatureInfo,
    SignerInfo,
    TimestampClaim,
)

SIGNED_DATA = '1.2.840.113549.1.7.2'
SPC_INDIRECT = '1.3.6.1.4.1.311.2.1.4'
NESTED_SIGNATURE = '1.3.6.1.4.1.311.2.4.1'
RFC3161_TIMESTAMP = '1.3.6.1.4.1.311.3.3.1'
COUNTERSIGNATURE = '1.2.840.113549.1.9.6'
SIGNING_TIME = '1.2.840.113549.1.9.5'
EXTENDED_KEY_USAGE = '2.5.29.37'
CODE_SIGNING = '1.3.6.1.5.5.7.3.3'
WIN_CERT_REVISION = 0x0200
WIN_CERT_PKCS_SIGNED_DATA = 0x0002
ALGORITHMS = {
    '1.3.14.3.2.26': 'sha1', '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512', '1.2.840.113549.2.5': 'md5',
}
DEFAULT_LIMITS = Limits()
WEAK = frozenset({'sha1', 'md5'})
_NAME_KEYS = {'2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST'}
_COMMON_NAME = '2.5.4.3'
_MAX_DN = 512
_MAX_TIMESTAMPS = 8


@dataclass(slots=True)
class _Parsed:
    """A signature while it is read; frozen into `SignatureInfo` once the digests are known."""

    index: int
    depth: int
    structure: str = 'ok'
    algorithm: str = 'unknown'
    claimed: str | None = None
    signers: list[SignerInfo] = field(default_factory=list)
    certificates: list[CertificateSummary] = field(default_factory=list)
    timestamps: list[TimestampClaim] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def warn(self, code: str) -> None:
        if code not in self.warnings:
            self.warnings.append(code)


def verify_embedded(reader: VerifiedArtifactReader, overview: PeOverview,
                    cancel: Callable[[], bool] | None = None, limits: Limits = DEFAULT_LIMITS) -> tuple[SignatureInfo, ...]:
    """Every embedded signature of `reader`, nested ones flattened after their parent. Never raises for file
    content; on cancellation the signatures read so far are returned without a digest verdict."""
    table = overview.certificates
    if table is None or not table.present or not table.entries:
        return ()
    ctx = Ctx(reader, cancel, limits)
    parsed: list[_Parsed] = []
    try:
        for index, entry in enumerate(table.entries):
            ctx.check()
            parsed.extend(_read_entry(ctx, index, entry))
        digests = _digests(ctx, overview, {p.algorithm for p in parsed if p.structure == 'ok'}, parsed)
    except Cancelled:
        return tuple(_freeze(p, {}) for p in parsed)
    return tuple(_freeze(p, digests) for p in parsed)


def _read_entry(ctx: Ctx, index: int, entry) -> list[_Parsed]:
    top = _Parsed(index, 0)
    if entry.cert_type != WIN_CERT_PKCS_SIGNED_DATA or entry.revision != WIN_CERT_REVISION:
        top.structure = 'unsupported_type'
        top.warn('signature_unsupported_type')
        return [top]
    size = entry.length - 8
    if size > ctx.limits.max_der_bytes:
        top.structure = 'malformed'
        top.warn('signature_der_over_cap')
        return [top]
    blob = ctx.read(entry.offset + 8, size)
    out = [top]
    try:
        root = parse(blob, DerLimits(ctx.limits.max_der_bytes, ctx.limits.max_der_depth, ctx.limits.max_der_nodes))
        _signature(ctx, root, top, out)
    except DerError as exc:
        top.structure = 'malformed'
        top.warn(exc.code)
    return out


def _signed_data(node: Node) -> Node:
    """The `SignedData` SEQUENCE inside a ContentInfo."""
    kids = node.children
    if not node.is_universal(SEQUENCE) or len(kids) < 2 or decode_oid(kids[0]) != SIGNED_DATA \
            or not kids[1].is_context(0) or len(kids[1].children) != 1 or not kids[1].children[0].is_universal(SEQUENCE):
        raise DerError(INVALID, 'not a PKCS#7 SignedData')
    return kids[1].children[0]


def _signature(ctx: Ctx, content_info: Node, sig: _Parsed, out: list[_Parsed]) -> None:
    kids = _signed_data(content_info).children
    if len(kids) < 4 or not kids[2].is_universal(SEQUENCE) or not kids[-1].is_universal(SET):
        raise DerError(INVALID, 'SignedData has an unexpected shape')
    sig.algorithm, sig.claimed = _indirect_digest(kids[2])
    if sig.algorithm == 'unknown':
        sig.warn('signature_digest_unsupported')
    found: list[_Cert] = []
    for node in kids[3:-1]:
        if node.is_context(0):
            sig.certificates, found = _certificates(ctx, node, sig)
    signers = kids[-1].children
    if len(signers) > ctx.limits.max_signers:
        sig.warn('signature_der_over_cap')
    for signer in signers[:ctx.limits.max_signers]:
        _signer(ctx, signer, sig, found, out)


def _indirect_digest(content: Node) -> tuple[str, str]:
    """(algorithm name, claimed digest hex) of a SpcIndirectDataContent, or raise."""
    kids = content.children
    if len(kids) < 2 or decode_oid(kids[0]) != SPC_INDIRECT or not kids[1].is_context(0) or not kids[1].children:
        raise DerError(INVALID, 'content is not SpcIndirectDataContent')
    spc = kids[1].children[0]
    if not spc.is_universal(SEQUENCE) or len(spc.children) < 2 or not spc.children[1].is_universal(SEQUENCE):
        raise DerError(INVALID, 'SpcIndirectDataContent has no DigestInfo')
    info = spc.children[1].children
    if len(info) < 2 or not info[0].children or not info[1].is_universal(OCTET_STRING):
        raise DerError(INVALID, 'DigestInfo has an unexpected shape')
    return ALGORITHMS.get(decode_oid(info[0].children[0]) or '', 'unknown'), info[1].content.hex()


@dataclass(frozen=True, slots=True)
class _Cert:
    summary: CertificateSummary
    issuer: bytes
    serial: int | None


def _certificates(ctx: Ctx, node: Node, sig: _Parsed) -> tuple[list[CertificateSummary], list[_Cert]]:
    found: list[_Cert] = []
    for child in node.children:
        if len(found) >= ctx.limits.max_signature_certs:
            sig.warn('signature_certs_over_cap')
            break
        cert = _certificate(child)
        if cert is not None:
            found.append(cert)
    return [c.summary for c in found], found


def _name(node: Node) -> tuple[str, str | None]:
    """(display DN, first common name) of an X.501 Name; hostile characters are replaced."""
    parts: list[str] = []
    common = None
    for rdn in node.children:
        for pair in rdn.children:
            if len(pair.children) != 2:
                continue
            key = decode_oid(pair.children[0]) or '?'
            text = decode_text(pair.children[1])
            parts.append(f'{_NAME_KEYS.get(key, key)}={text}')
            if key == _COMMON_NAME and common is None:
                common = text
    return ', '.join(parts)[:_MAX_DN], common


def _certificate(node: Node) -> _Cert | None:
    """Identity fields of an X.509 certificate, or None when its shape is unexpected."""
    if not node.is_universal(SEQUENCE) or not node.children or not node.children[0].is_universal(SEQUENCE):
        return None
    items = node.children[0].children
    base = 1 if items and items[0].is_context(0) else 0
    if len(items) < base + 6 or not items[base + 3].is_universal(SEQUENCE) or len(items[base + 3].children) != 2:
        return None
    serial_node = items[base]
    serial = decode_int(serial_node)
    issuer_dn, issuer_cn = _name(items[base + 2])
    subject_dn, subject_cn = _name(items[base + 4])
    valid = items[base + 3].children
    summary = CertificateSummary(
        subject_cn, subject_dn, issuer_cn, issuer_dn, _serial_hex(serial_node), decode_time(valid[0]),
        decode_time(valid[1]), _code_signing(items[base + 6:]))
    return _Cert(summary, items[base + 2].raw, serial)


def _serial_hex(node: Node) -> str:
    raw = node.content.lstrip(b'\0') or b'\0'
    return raw.hex()


def _code_signing(extensions: list[Node]) -> bool | None:
    """Whether the extended key usage lists code signing; None when the certificate has no such extension."""
    for container in extensions:
        if not container.is_context(3) or not container.children:
            continue
        for ext in container.children[0].children:
            if len(ext.children) >= 2 and decode_oid(ext.children[0]) == EXTENDED_KEY_USAGE:
                try:
                    usages = parse(ext.children[-1].content, DerLimits(4096, 4, 64)).children
                except DerError:
                    return None
                return any(decode_oid(u) == CODE_SIGNING for u in usages)
    return None


def _signer(ctx: Ctx, node: Node, sig: _Parsed, certs: list[_Cert], out: list[_Parsed]) -> None:
    kids = node.children
    if len(kids) < 5 or not kids[1].is_universal(SEQUENCE) or len(kids[1].children) != 2 \
            or not kids[2].children:
        sig.warn('signature_der_invalid')
        return
    issuer, serial_node = kids[1].children
    serial = decode_int(serial_node)
    position = 3
    if kids[position].is_context(0):
        position += 1
    if position >= len(kids) or not kids[position].children:
        sig.warn('signature_der_invalid')
        return
    sig_oid = decode_oid(kids[position].children[0])
    unauth = next((k for k in kids[position + 1:] if k.is_context(1)), None)
    digest_alg = ALGORITHMS.get(decode_oid(kids[2].children[0]) or '', 'unknown')
    match = next((c for c in certs if c.issuer == issuer.raw and c.serial == serial), None)
    issuer_dn, issuer_cn = _name(issuer)
    if match is not None:
        s = match.summary
        sig.signers.append(SignerInfo(s.issuer_cn, s.issuer_dn, s.serial_hex, s.subject_cn, s.subject_dn,
                                      s.not_before, s.not_after, s.eku_code_signing, digest_alg, sig_oid, True))
    else:
        sig.signers.append(SignerInfo(issuer_cn, issuer_dn, _serial_hex(serial_node), None, None, None, None, None,
                                      digest_alg, sig_oid, False))
    if unauth is not None:
        _unauthenticated(ctx, unauth, sig, out)


def _unauthenticated(ctx: Ctx, attrs: Node, sig: _Parsed, out: list[_Parsed]) -> None:
    for attr in attrs.children:
        if len(attr.children) != 2:
            continue
        kind = decode_oid(attr.children[0])
        for value in attr.children[1].children:
            if kind == COUNTERSIGNATURE:
                _add_timestamp(sig, TimestampClaim('ms_countersignature', *_countersignature_time(value)))
            elif kind == RFC3161_TIMESTAMP:
                _add_timestamp(sig, TimestampClaim('rfc3161', *_tst_time(value)))
            elif kind == NESTED_SIGNATURE:
                _nested(ctx, value, sig, out)


def _add_timestamp(sig: _Parsed, claim: TimestampClaim) -> None:
    if len(sig.timestamps) < _MAX_TIMESTAMPS:
        sig.timestamps.append(claim)


def _countersignature_time(signer: Node) -> tuple[str | None, bool]:
    """Signing time claimed by a countersignature SignerInfo (the `signingTime` authenticated attribute)."""
    for part in signer.children:
        if part.is_context(0):
            for attr in part.children:
                if len(attr.children) == 2 and decode_oid(attr.children[0]) == SIGNING_TIME and attr.children[1].children:
                    stamp = decode_time(attr.children[1].children[0])
                    return stamp, stamp is not None
    return None, False


def _tst_time(token: Node) -> tuple[str | None, bool]:
    """`genTime` of the TSTInfo inside an RFC 3161 token (ContentInfo of SignedData whose content is a TSTInfo)."""
    try:
        content = _signed_data(token).children[2]
        octets = content.children[1].children[0]
        if not octets.is_universal(OCTET_STRING):
            return None, False
        info = parse(octets.content, DerLimits(4096, 4, 256))
        stamp = decode_time(info.children[4])
    except (DerError, IndexError):
        return None, False
    return stamp, stamp is not None


def _nested(ctx: Ctx, node: Node, parent: _Parsed, out: list[_Parsed]) -> None:
    if sum(1 for p in out if p.index == parent.index and p.depth > 0) >= ctx.limits.max_nested_signatures:
        parent.warn('signature_nested_over_cap')
        return
    child = _Parsed(parent.index, parent.depth + 1)
    out.append(child)
    try:
        _signature(ctx, node, child, out)
    except DerError as exc:
        child.structure = 'malformed'
        child.warn(exc.code)


# --- digest -------------------------------------------------------------------------------------------------------

def _ranges(ctx: Ctx, overview: PeOverview) -> list[tuple[int, int]] | None:
    """File ranges that make up the Authenticode digest, or None when the headers cannot say."""
    table = overview.certificates
    if table is None or overview.size_of_headers is None or overview.sections is None \
            or overview.optional_magic not in ('PE32', 'PE32+'):
        return None
    pointer = ctx.read(0x3C, 4)
    if len(pointer) < 4:
        return None
    optional = struct.unpack('<I', pointer)[0] + 24
    checksum = optional + 64
    entry = optional + (144 if overview.optional_magic == 'PE32+' else 128)
    headers = overview.size_of_headers
    ranges = [(0, min(checksum, headers)), (checksum + 4, min(entry, headers)), (entry + 8, headers)]
    summed = headers
    for section in sorted(overview.sections, key=lambda s: s.raw_offset):
        if section.raw_size:
            ranges.append((section.raw_offset, section.raw_offset + section.raw_size))
            summed += section.raw_size
    tail_end = overview.size - table.size
    if tail_end > summed:
        ranges.append((summed, tail_end))
    return [(a, min(b, overview.size)) for a, b in ranges if a < min(b, overview.size)]


def _digests(ctx: Ctx, overview: PeOverview, algorithms: set[str], parsed: list[_Parsed]) -> dict[str, str]:
    """{algorithm: digest hex} in one pass over the file; empty (with a warning on each signature) when skipped."""
    algorithms = {a for a in algorithms if a in ALGORITHMS.values()}
    if not algorithms:
        return {}
    if overview.size > ctx.limits.checksum_max_file:
        _note(parsed, algorithms, 'digest_skipped_large')
        return {}
    ranges = _ranges(ctx, overview)
    if ranges is None:
        _note(parsed, algorithms, 'signature_digest_unsupported')
        return {}
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    for start, end in ranges:
        position = start
        while position < end:
            ctx.check()
            block = ctx.read(position, min(ctx.limits.chunk, end - position))
            if not block:
                _note(parsed, algorithms, 'signature_digest_unsupported')
                return {}
            for hasher in hashers.values():
                hasher.update(block)
            position += len(block)
    return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}


def _note(parsed: list[_Parsed], algorithms: set[str], code: str) -> None:
    for item in parsed:
        if item.structure == 'ok' and item.algorithm in algorithms:
            item.warn(code)


def _freeze(item: _Parsed, digests: dict[str, str]) -> SignatureInfo:
    computed = digests.get(item.algorithm) if item.structure == 'ok' else None
    match = None if computed is None or item.claimed is None else computed == item.claimed
    warnings = list(item.warnings)
    if match is False:
        warnings.append('signature_digest_mismatch')
    return SignatureInfo(
        item.index, item.depth, item.structure, item.algorithm, item.claimed, computed, match,
        item.algorithm in WEAK, tuple(item.signers), tuple(item.certificates), tuple(item.timestamps),
        warnings=tuple(warnings))


__all__ = ['verify_embedded']
