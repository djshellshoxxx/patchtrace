"""Monero address validator for the site build (tools/site/xmr_address.py, stdlib only).

Every address here is SYNTHETIC: random public-key bytes from a seeded generator, never a real wallet."""
from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.site import xmr_address as xmr  # noqa: E402

KEYS = random.Random(20261014)
SPEND, VIEW, PAYMENT_ID = KEYS.randbytes(32), KEYS.randbytes(32), KEYS.randbytes(8)
STANDARD = xmr.encode_address('standard', 'mainnet', SPEND, VIEW)
SUBADDRESS = xmr.encode_address('subaddress', 'mainnet', SPEND, VIEW)
INTEGRATED = xmr.encode_address('integrated', 'mainnet', SPEND, VIEW, PAYMENT_ID)
TESTNET = xmr.encode_address('standard', 'testnet', SPEND, VIEW)


# ---- Keccak-256 -------------------------------------------------------------------------------------

@pytest.mark.parametrize(('message', 'digest'), [
    (b'', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
    (b'abc', '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'),
    (b'The quick brown fox jumps over the lazy dog',
     '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'),
], ids=['empty', 'abc', 'fox'])
def test_keccak256_known_answers(message, digest):
    assert xmr.keccak256(message).hex() == digest


@pytest.mark.parametrize('size', [0, 1, 55, 135, 136, 137, 271, 272, 273, 1000], ids=str)
def test_permutation_and_sponge_match_nist_sha3_when_only_the_padding_differs(size):
    """Keccak-256 and SHA3-256 share the permutation, rate and sponge; only the domain byte differs
    (0x01 vs 0x06). So the SHA3 suffix must reproduce hashlib exactly, across block boundaries."""
    data = random.Random(size).randbytes(size)
    assert xmr._sponge(data, 0x06) == hashlib.sha3_256(data).digest()


def test_keccak256_is_not_sha3_256():
    assert xmr.keccak256(b'abc') != hashlib.sha3_256(b'abc').digest()


# ---- base58 -----------------------------------------------------------------------------------------

@pytest.mark.parametrize('size', range(0, 41), ids=str)
def test_base58_block_round_trip(size):
    data = random.Random(1000 + size).randbytes(size)
    text = xmr.base58_encode(data)
    full, rest = divmod(size, 8)
    assert len(text) == full * 11 + (0, 2, 3, 5, 6, 7, 9, 10, 11)[rest]
    assert xmr.base58_decode(text) == data


def test_base58_extremes_round_trip():
    for data in (b'\x00' * 8, b'\xff' * 8, b'\x00' * 69, b'\xff' * 69):
        assert xmr.base58_decode(xmr.base58_encode(data)) == data


@pytest.mark.parametrize('bad', ['0', 'O', 'I', 'l'], ids=['zero', 'cap-o', 'cap-i', 'low-l'])
def test_base58_rejects_characters_outside_the_alphabet(bad):
    with pytest.raises(xmr.AddressError, match='alphabet'):
        xmr.base58_decode(bad + '1' * 10)


def test_base58_rejects_out_of_range_block_and_impossible_length():
    with pytest.raises(xmr.AddressError, match='out of range'):
        xmr.base58_decode('zzzzzzzzzzz')  # 11 characters above 2**64
    for length in (1, 4, 8):  # no byte count encodes to these widths
        with pytest.raises(xmr.AddressError, match='length'):
            xmr.base58_decode('1' * length)


# ---- addresses --------------------------------------------------------------------------------------

def test_synthetic_forms_have_the_documented_shape():
    assert (len(STANDARD), STANDARD[0]) == (95, '4')
    assert (len(SUBADDRESS), SUBADDRESS[0]) == (95, '8')
    assert (len(INTEGRATED), INTEGRATED[0]) == (106, '4')


@pytest.mark.parametrize(('text', 'kind', 'payment'), [
    (STANDARD, 'standard', None), (SUBADDRESS, 'subaddress', None), (INTEGRATED, 'integrated', PAYMENT_ID),
], ids=['standard', 'subaddr', 'integrated'])
def test_decode_returns_kind_keys_and_payment_id(text, kind, payment):
    found = xmr.decode_address(text)
    assert (found.kind, found.network, found.payment_id) == (kind, 'mainnet', payment)
    assert (found.spend_key, found.view_key, found.address) == (SPEND, VIEW, text)


def test_network_is_enforced_by_default_and_selectable():
    with pytest.raises(xmr.AddressError, match='testnet'):
        xmr.decode_address(TESTNET)
    assert xmr.decode_address(TESTNET, networks=('testnet',)).network == 'testnet'


@pytest.mark.parametrize('position', [0, 1, 40, 80, 93, 94], ids=str)
def test_any_single_character_error_is_rejected(position):
    text = STANDARD
    replacement = 'B' if text[position] != 'B' else 'C'
    with pytest.raises(xmr.AddressError):
        xmr.decode_address(text[:position] + replacement + text[position + 1:])


def test_checksum_failure_names_the_reason():
    # Swap two neighbouring characters inside a block: still decodable, checksum must catch it.
    chars = list(STANDARD)
    chars[20], chars[21] = chars[21], chars[20]
    text = ''.join(chars)
    assert text != STANDARD
    with pytest.raises(xmr.AddressError, match='checksum'):
        xmr.decode_address(text)


@pytest.mark.parametrize('bad', [
    '', ' ' + STANDARD, STANDARD + '\n', STANDARD[:50] + ' ' + STANDARD[50:], STANDARD[:-1], STANDARD + '1',
    'monero:' + STANDARD,
], ids=['empty', 'lead-space', 'newline', 'inner-space', 'short', 'long', 'uri'])
def test_malformed_text_is_rejected(bad):
    with pytest.raises(xmr.AddressError):
        xmr.decode_address(bad)


def test_non_string_is_rejected():
    with pytest.raises(xmr.AddressError):
        xmr.decode_address(None)  # type: ignore[arg-type]


def test_unknown_prefix_with_valid_checksum_is_rejected():
    body = bytes([99]) + SPEND + VIEW
    text = xmr.base58_encode(body + xmr.keccak256(body)[:4])
    with pytest.raises(xmr.AddressError, match='prefix'):
        xmr.decode_address(text)


def test_encode_rejects_inconsistent_parts():
    with pytest.raises(xmr.AddressError):
        xmr.encode_address('standard', 'mainnet', SPEND[:31], VIEW)
    with pytest.raises(xmr.AddressError):
        xmr.encode_address('standard', 'mainnet', SPEND, VIEW, PAYMENT_ID)
    with pytest.raises(xmr.AddressError):
        xmr.encode_address('integrated', 'mainnet', SPEND, VIEW)
    with pytest.raises(xmr.AddressError):
        xmr.encode_address('wallet', 'mainnet', SPEND, VIEW)


def test_monero_uri_is_scheme_plus_validated_address():
    assert xmr.monero_uri(STANDARD) == 'monero:' + STANDARD
    with pytest.raises(xmr.AddressError):
        xmr.monero_uri(STANDARD[:-1])


def test_cli_reports_validity(capsys):
    assert xmr.main([STANDARD]) == 0
    assert 'valid mainnet standard' in capsys.readouterr().out
    assert xmr.main([TESTNET]) == 0
    assert xmr.main([STANDARD[:-1]]) == 1
    assert 'INVALID' in capsys.readouterr().out
    assert xmr.main([]) == 2
