#!/usr/bin/env python3
"""Monero address validation for the site build (standard library only).

A Monero address is ``base58(prefix | public spend key | public view key [| payment id] | checksum)``
where the checksum is the first four bytes of **Keccak-256** (the original Keccak padding, *not* NIST
SHA3-256, so ``hashlib.sha3_256`` gives a different value) of everything before it. Monero's base58 is not
Bitcoin's: the input is cut into 8-byte blocks and every block is encoded on its own into 11 characters
(a shorter last block uses a fixed shorter width), so a standard address is exactly 95 characters.

Supported forms (mainnet by default, because this is a public donation address):

* standard   prefix 18, 95 characters, starts with ``4``
* subaddress prefix 42, 95 characters, starts with ``8``
* integrated prefix 19, 106 characters (carries an 8-byte payment id), starts with ``4``

The check is the same structural check a wallet performs when it parses an address: length, base58
alphabet and per-block range, network/kind prefix and the 32-bit checksum. It deliberately does **not**
test that the two 32-byte keys are valid Ed25519 points: a mistyped address fails the checksum with
probability 1 - 2**-32, and a false rejection of the owner's real address would be far costlier than
accepting a pathological one.

CLI: ``python tools/site/xmr_address.py ADDRESS`` prints the kind and network or the reason it is invalid.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

__all__ = ['AddressError', 'MoneroAddress', 'keccak256', 'base58_encode', 'base58_decode', 'encode_address',
           'decode_address', 'monero_uri']


class AddressError(ValueError):
    """The text is not a valid Monero address (message is safe to show the site owner)."""


# ---- Keccak-256 -------------------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# Rotation offsets r[x][y] of the rho step (lane index = x + 5 * y).
_ROTATIONS = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_RATE_256 = 136  # bytes: (1600 - 2 * 256) / 8


def _rol(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & _MASK64 if count else value


def _keccak_f1600(lanes: list[int]) -> None:
    for constant in _ROUND_CONSTANTS:
        column = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        for x in range(5):
            delta = column[(x - 1) % 5] ^ _rol(column[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                lanes[x + y] ^= delta
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(lanes[x + 5 * y], _ROTATIONS[x][y])
        for y in range(0, 25, 5):
            row = moved[y:y + 5]
            for x in range(5):
                lanes[x + y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5])
        lanes[0] ^= constant


def _sponge(data: bytes, suffix: int, rate: int = _RATE_256, length: int = 32) -> bytes:
    padded = bytearray(data)
    padded.append(suffix)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    lanes = [0] * 25
    for offset in range(0, len(padded), rate):
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(padded[offset + 8 * i:offset + 8 * i + 8], 'little')
        _keccak_f1600(lanes)
    return b''.join(lane.to_bytes(8, 'little') for lane in lanes)[:length]


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (domain suffix 0x01). NIST SHA3-256 uses 0x06 and is NOT interchangeable."""
    return _sponge(bytes(data), 0x01)


# ---- Monero base58 ----------------------------------------------------------------------------------

_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_INDEX = {char: index for index, char in enumerate(_ALPHABET)}
_ENCODED_BLOCK_SIZES = (0, 2, 3, 5, 6, 7, 9, 10, 11)  # characters used for a block of 0..8 bytes
_FULL_BLOCK, _FULL_ENCODED = 8, 11


def _encode_block(block: bytes) -> str:
    number = int.from_bytes(block, 'big')
    characters = []
    for _ in range(_ENCODED_BLOCK_SIZES[len(block)]):
        number, remainder = divmod(number, 58)
        characters.append(_ALPHABET[remainder])
    return ''.join(reversed(characters))


def base58_encode(data: bytes) -> str:
    full, rest = divmod(len(data), _FULL_BLOCK)
    parts = [_encode_block(data[i * _FULL_BLOCK:(i + 1) * _FULL_BLOCK]) for i in range(full)]
    if rest:
        parts.append(_encode_block(data[full * _FULL_BLOCK:]))
    return ''.join(parts)


def _decode_block(text: str) -> bytes:
    try:
        size = _ENCODED_BLOCK_SIZES.index(len(text))
    except ValueError:  # pragma: no cover - callers pass only valid widths
        raise AddressError('invalid base58 block width') from None
    number = 0
    for char in text:
        digit = _INDEX.get(char)
        if digit is None:
            raise AddressError(f'character {char!r} is not in the Monero base58 alphabet')
        number = number * 58 + digit
    if number >= 1 << (8 * size):
        raise AddressError('a base58 block is out of range (mistyped or corrupted address)')
    return number.to_bytes(size, 'big')


def base58_decode(text: str) -> bytes:
    full, rest = divmod(len(text), _FULL_ENCODED)
    if rest not in _ENCODED_BLOCK_SIZES:
        raise AddressError('length is not a valid Monero base58 length')
    chunks = [_decode_block(text[i * _FULL_ENCODED:(i + 1) * _FULL_ENCODED]) for i in range(full)]
    if rest:
        chunks.append(_decode_block(text[full * _FULL_ENCODED:]))
    return b''.join(chunks)


# ---- addresses --------------------------------------------------------------------------------------

_PREFIXES = {  # network -> kind -> one-byte varint
    'mainnet': {'standard': 18, 'integrated': 19, 'subaddress': 42},
    'testnet': {'standard': 53, 'integrated': 54, 'subaddress': 63},
    'stagenet': {'standard': 24, 'integrated': 25, 'subaddress': 36},
}
_BY_PREFIX = {prefix: (network, kind) for network, kinds in _PREFIXES.items() for kind, prefix in kinds.items()}
_KEY_BYTES, _PAYMENT_ID_BYTES, _CHECKSUM_BYTES = 32, 8, 4
_LENGTHS = {  # characters in the text form
    'standard': len(base58_encode(bytes(1 + 2 * _KEY_BYTES + _CHECKSUM_BYTES))),
    'subaddress': len(base58_encode(bytes(1 + 2 * _KEY_BYTES + _CHECKSUM_BYTES))),
    'integrated': len(base58_encode(bytes(1 + 2 * _KEY_BYTES + _PAYMENT_ID_BYTES + _CHECKSUM_BYTES))),
}


@dataclass(frozen=True)
class MoneroAddress:
    address: str
    kind: str  # 'standard' | 'subaddress' | 'integrated'
    network: str  # 'mainnet' | 'testnet' | 'stagenet'
    spend_key: bytes
    view_key: bytes
    payment_id: bytes | None = None


def encode_address(kind: str, network: str, spend_key: bytes, view_key: bytes,
                   payment_id: bytes | None = None) -> str:
    """Build an address from raw parts (used by tests to make synthetic addresses)."""
    try:
        prefix = _PREFIXES[network][kind]
    except KeyError:
        raise AddressError(f'unknown network/kind {network!r}/{kind!r}') from None
    if len(spend_key) != _KEY_BYTES or len(view_key) != _KEY_BYTES:
        raise AddressError('public keys must be 32 bytes')
    if (kind == 'integrated') != (payment_id is not None):
        raise AddressError('exactly the integrated form carries a payment id')
    if payment_id is not None and len(payment_id) != _PAYMENT_ID_BYTES:
        raise AddressError('payment id must be 8 bytes')
    body = bytes([prefix]) + spend_key + view_key + (payment_id or b'')
    return base58_encode(body + keccak256(body)[:_CHECKSUM_BYTES])


def decode_address(text: str, *, networks: tuple[str, ...] = ('mainnet',)) -> MoneroAddress:
    """Validate ``text`` and return its parts; raises :class:`AddressError` with a plain reason."""
    if not isinstance(text, str) or not text:
        raise AddressError('the address is empty')
    if text != text.strip() or any(char.isspace() for char in text):
        raise AddressError('the address contains whitespace; paste the bare address only')
    if text.lower().startswith('monero:'):
        raise AddressError('paste the bare address, not a monero: URI')
    if len(text) not in (_LENGTHS['standard'], _LENGTHS['integrated']):
        raise AddressError(f'a Monero address has {_LENGTHS["standard"]} (standard or subaddress) or '
                           f'{_LENGTHS["integrated"]} (integrated) characters, this one has {len(text)}')
    raw = base58_decode(text)
    body, checksum = raw[:-_CHECKSUM_BYTES], raw[-_CHECKSUM_BYTES:]
    if keccak256(body)[:_CHECKSUM_BYTES] != checksum:
        raise AddressError('the checksum does not match: the address has a typing error or is not Monero')
    network_kind = _BY_PREFIX.get(body[0])
    if network_kind is None:
        raise AddressError(f'unknown address prefix {body[0]}')
    network, kind = network_kind
    if network not in networks:
        raise AddressError(f'this is a {network} address; the site accepts {"/".join(networks)} only')
    expected = 1 + 2 * _KEY_BYTES + (_PAYMENT_ID_BYTES if kind == 'integrated' else 0)
    if len(body) != expected:
        raise AddressError('the address length does not fit its prefix')
    spend = body[1:1 + _KEY_BYTES]
    view = body[1 + _KEY_BYTES:1 + 2 * _KEY_BYTES]
    payment_id = body[1 + 2 * _KEY_BYTES:] or None
    return MoneroAddress(text, kind, network, spend, view, payment_id)


def monero_uri(address: str) -> str:
    """``monero:<address>`` after validation (the form wallets and QR scanners open)."""
    return 'monero:' + decode_address(address).address


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print('usage: xmr_address.py ADDRESS', file=sys.stderr)
        return 2
    try:
        found = decode_address(args[0].strip(), networks=tuple(_PREFIXES))
    except AddressError as error:
        print(f'INVALID: {error}')
        return 1
    print(f'valid {found.network} {found.kind} address')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
