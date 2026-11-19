"""Strict bounded decoding of persisted offline PE metadata (SPEC-51 D2-5).

The public parser records remain frozen dataclasses. JSON round-trip equality adds
closed-field validation to Pydantic's strict dataclass decoding; no defaults, type
coercions, unknown fields, chain claims or hostile text enter through a cache hit.
"""
from __future__ import annotations

import json
import re
from functools import cache

from pydantic import TypeAdapter

from ..hostile_text import is_hostile
from .metadata import PeMetadata
from .models import TIMESTAMP_NOTE, SignatureInfo
from .signature import RSA_SIGNATURES

MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_CACHE_NODES = 250_000
MAX_CACHE_DEPTH = 32
MAX_CACHE_STRING = 8192
_DIGEST_WIDTHS = {'md5': 32, 'sha1': 40, 'sha256': 64, 'sha384': 96, 'sha512': 128}


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _bounded(value: object) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_CACHE_NODES or depth > MAX_CACHE_DEPTH:
            raise ValueError('PE metadata cache exceeds structural limits')
        if isinstance(item, dict):
            if any(type(key) is not str for key in item):
                raise ValueError('PE metadata cache has a non-string field')
            if count + len(pending) + len(item) > MAX_CACHE_NODES:
                raise ValueError('PE metadata cache exceeds its node limit')
            pending.extend((part, depth + 1) for part in item.values())
        elif isinstance(item, (list, tuple)):
            if count + len(pending) + len(item) > MAX_CACHE_NODES:
                raise ValueError('PE metadata cache exceeds its node limit')
            pending.extend((part, depth + 1) for part in item)
        elif type(item) is str:
            if len(item) > MAX_CACHE_STRING or any(is_hostile(char) for char in item):
                raise ValueError('PE metadata cache has unsafe text')
        elif type(item) is int:
            if not 0 <= item < 1 << 64:
                raise ValueError('PE metadata cache has an out-of-range integer')
        elif item is not None and type(item) is not bool:
            raise ValueError('PE metadata cache has an unsupported value')


@cache
def _adapter() -> TypeAdapter:
    return TypeAdapter(PeMetadata)


def _signature_proof_fields(sig: SignatureInfo) -> None:
    claimed, computed = sig.digest_claimed_hex, sig.digest_computed_hex
    if claimed is not None and re.fullmatch(r'(?:[0-9a-f]{2})*', claimed) is None:
        raise ValueError('PE metadata cache claimed digest is not byte hexadecimal')
    if computed is not None and (len(computed) != _DIGEST_WIDTHS.get(sig.digest_algorithm)
                                 or re.fullmatch(r'[0-9a-f]+', computed) is None):
        raise ValueError('PE metadata cache computed digest has an invalid width or encoding')
    if sig.signature_math != 'ok_chain_not_evaluated':
        return
    if not sig.signers:
        raise ValueError('PE metadata cache signature math has no signers')
    for signer in sig.signers:
        if (not signer.signer_cert_found or signer.digest_alg not in _DIGEST_WIDTHS
                or signer.signature_alg_oid not in RSA_SIGNATURES):
            raise ValueError('PE metadata cache signature math lacks supported signer inputs')
        if not any((cert.serial_hex, cert.issuer_dn, cert.subject_dn, cert.subject_cn,
                    cert.not_before, cert.not_after, cert.eku_code_signing) ==
                   (signer.serial_hex, signer.issuer_dn, signer.subject_dn, signer.subject_cn,
                    signer.not_before, signer.not_after, signer.eku_code_signing)
                   for cert in sig.certificates):
            raise ValueError('PE metadata cache signature math has no matching certificate')


def decode_metadata(value: object) -> PeMetadata:
    """Decode complete offline facts; malformed or incomplete rows are cache misses."""
    _bounded(value)
    text = canonical(value)
    if len(text.encode('utf-8')) > MAX_CACHE_BYTES:
        raise ValueError('PE metadata cache exceeds its byte limit')
    result = _adapter().validate_json(text, strict=True)
    if canonical(result.to_dict()) != text or result.status != 'ok' or result.warnings:
        raise ValueError('PE metadata cache shape or status is invalid')
    if result.version is not None:
        primary = result.version.primary_index
        if primary is not None and not 0 <= primary < len(result.version.blocks):
            raise ValueError('PE metadata cache primary version is invalid')
        if any(block.status not in ('ok', 'partial', 'malformed', 'unreadable')
               for block in result.version.blocks):
            raise ValueError('PE metadata cache version status is invalid')
    for sig in result.signatures:
        _signature_proof_fields(sig)
        if (sig.chain != 'not_evaluated' or sig.revocation != 'not_checked'
                or sig.signature_math not in ('not_evaluated', 'failed', 'ok_chain_not_evaluated')
                or sig.structure not in ('ok', 'malformed', 'unsupported_type')
                or sig.digest_algorithm not in ('sha1', 'sha256', 'sha384', 'sha512', 'md5', 'unknown')):
            raise ValueError('PE metadata cache contains unsupported signature claims')
        match = (None if sig.digest_claimed_hex is None or sig.digest_computed_hex is None
                 else sig.digest_claimed_hex == sig.digest_computed_hex)
        if sig.digest_match is not match or sig.weak_digest != (sig.digest_algorithm in ('sha1', 'md5')):
            raise ValueError('PE metadata cache digest facts are inconsistent')
        if any(claim.note != TIMESTAMP_NOTE or claim.kind not in ('rfc3161', 'ms_countersignature')
               for claim in sig.timestamps):
            raise ValueError('PE metadata cache timestamp claims are invalid')
    return result
