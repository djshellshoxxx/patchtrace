"""RSA PKCS#1 v1.5 signature check with `pow()` (SPEC-51 D2-6). Stdlib only, no key store, no chain.

Answers one narrow question: does this signature value verify against this public key for this hash? It says nothing
about who owns the key or whether any certificate may be trusted, so callers label a success "signature math ok,
chain not evaluated". Encoding per RFC 8017 section 9.2 (EMSA-PKCS1-v1_5) and 8.2.2 (RSASSA-PKCS1-v1_5-VERIFY); the
comparison is of the whole encoded message, so a padding or DigestInfo forgery cannot pass on a partial match.
Keys outside 512..8192 bits or with an exponent over 64 bits are refused, which bounds the work on hostile input.
"""
from __future__ import annotations

import hashlib
import hmac

from .der import BIT_STRING, SEQUENCE, DerError, DerLimits, Node, decode_int, decode_oid, parse

RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
MIN_MODULUS_BITS = 512
MAX_MODULUS_BITS = 8192
MAX_EXPONENT_BITS = 64
# DER DigestInfo prefixes (RFC 8017 section 9.2 note 1).
_PREFIX = {
    'md5': '3020300c06082a864886f70d020505000410',
    'sha1': '3021300906052b0e03021a05000414',
    'sha256': '3031300d060960864801650304020105000420',
    'sha384': '3041300d060960864801650304020205000430',
    'sha512': '3051300d060960864801650304020305000440',
}


def verify_pkcs1_v15(modulus: int, exponent: int, message_hash: bytes, algorithm: str, signature: bytes) -> bool:
    prefix = _PREFIX.get(algorithm)
    if prefix is None or len(message_hash) != hashlib.new(algorithm).digest_size:
        return False
    if not MIN_MODULUS_BITS <= modulus.bit_length() <= MAX_MODULUS_BITS:
        return False
    if exponent < 3 or exponent.bit_length() > MAX_EXPONENT_BITS:
        return False
    size = (modulus.bit_length() + 7) // 8
    value = int.from_bytes(signature, 'big')
    if len(signature) != size or value >= modulus:
        return False
    info = bytes.fromhex(prefix) + message_hash
    if size < len(info) + 11:
        return False
    expected = b'\x00\x01' + b'\xff' * (size - len(info) - 3) + b'\x00' + info
    return hmac.compare_digest(pow(value, exponent, modulus).to_bytes(size, 'big'), expected)


def public_key_from_spki(spki: Node) -> tuple[int, int] | None:
    """(modulus, exponent) of a SubjectPublicKeyInfo holding an RSA key, else None."""
    if not spki.is_universal(SEQUENCE) or len(spki.children) != 2:
        return None
    algorithm, bits = spki.children
    if not algorithm.children or decode_oid(algorithm.children[0]) != RSA_ENCRYPTION \
            or not bits.is_universal(BIT_STRING) or len(bits.content) < 2 or bits.content[0] != 0:
        return None
    try:
        key = parse(bits.content[1:], DerLimits(4096, 4, 16))
    except DerError:
        return None
    if not key.is_universal(SEQUENCE) or len(key.children) != 2:
        return None
    modulus, exponent = decode_int(key.children[0]), decode_int(key.children[1])
    if modulus is None or exponent is None or modulus <= 0 or exponent <= 0:
        return None
    return modulus, exponent
