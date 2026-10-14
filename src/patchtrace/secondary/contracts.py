"""Strict secondary-engine records (SPEC-10 §3, SPEC-11 §4). Pure: no Qt, process or network I/O."""
from __future__ import annotations

import math
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer, model_validator

from ..enrichment.identity import domain_id

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Address = Annotated[int, Field(ge=0, le=2**64 - 1)]
Milli = Annotated[int, Field(ge=0, le=1000)]
Engine = Literal['bindiff', 'rz-diff']
FLAG_NAMES = ('G', 'I', 'O', 'J', 'E', 'L', 'C')
KIND = 'secondary-matches'
ErrorCode = Literal['PT-SECONDARY-INPUT', 'PT-SECONDARY-PAIR', 'PT-SECONDARY-ORIENTATION',
                    'PT-SECONDARY-UNSUPPORTED', 'PT-SECONDARY-RUN', 'PT-SECONDARY-CANCEL',
                    'PT-SECONDARY-LIMIT', 'PT-SECONDARY-TIMEOUT', 'PT-SECONDARY-FORMAT',
                    'PT-SECONDARY-CACHE']
MAX_ALTERNATIVES_PER_ANCHOR = 8
MAX_ALTERNATIVES = 50_000

RZDIFF_LIMITATIONS = (
    'rz-diff similarity is raw-byte Levenshtein: not semantic, sensitive to relocations and address shifts.',
    'rz-diff provides no per-match confidence and no symbol names; functions are mapped by address only.',
    'Agreement with Ghidriff is not independent proof or a calibrated probability.',
)
BINDIFF_LIMITATIONS = (
    'BinDiff similarity/confidence are BinDiff heuristics, not calibrated probabilities.',
    'Agreement with Ghidriff is not independent proof or a calibrated probability.',
)


class SecondaryError(Exception):
    def __init__(self, code: ErrorCode, message: str, *, reason: str | None = None):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
        self.reason = reason  # optional machine slug (SPEC-10b §7); additive, None for older callers


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class SecondaryMatch(_Strict):
    engine: Engine
    engine_version: str = Field(min_length=1)
    older_address: Address | None
    newer_address: Address | None
    older_name: str | None
    newer_name: str | None
    similarity_milli: Milli
    similarity_text: str = Field(min_length=1)
    confidence_milli: Milli | None
    confidence_text: str | None
    flags: tuple[str, ...]
    algorithm: str = Field(min_length=1)
    match_type: str | None = None

    @model_validator(mode='after')
    def consistent(self):
        if self.older_address is None and self.newer_address is None:
            raise ValueError('secondary match needs at least one address')
        if (self.confidence_milli is None) != (self.confidence_text is None):
            raise ValueError('confidence value and text must both be present or absent')
        if not set(self.flags) <= set(FLAG_NAMES) or len(set(self.flags)) != len(self.flags):
            raise ValueError('unknown or duplicate flag')
        if self.engine == 'bindiff' and (self.older_address is None or self.newer_address is None
                                         or self.confidence_milli is None):
            raise ValueError('BinDiff rows are always two-sided with confidence')
        if self.engine == 'rz-diff' and (self.confidence_milli is not None or self.flags
                                         or self.algorithm != 'levenshtein-bytes'):
            raise ValueError('rz-diff records carry no confidence or flags')
        return self


class AlternativeMatch(_Strict):
    """A further candidate an engine proposed for one anchor; never merged across engines or re-scored."""
    anchor_side: Literal['older', 'newer']
    anchor_address: Address
    candidate: SecondaryMatch
    source: Literal['rz-diff', 'bindiff', 'ghidriff-baseline']
    rank: int = Field(ge=1)


class SecondaryMatchSet(_Strict):
    contract: Literal['secondary/1', 'secondary/2'] = 'secondary/1'
    engine: Engine
    engine_version: str = Field(min_length=1)
    older_sha256: Sha256
    newer_sha256: Sha256
    file_sha256: Sha256  # SHA-256 of the imported .BinDiff file or of rz-diff stdout bytes.
    image_base_subtracted: Literal['yes', 'no', 'unknown'] = 'unknown'
    matches: tuple[SecondaryMatch, ...]
    limitations: tuple[str, ...] = ()
    # secondary/2 only; omitted from serialised output when default so secondary/1 JSON is unchanged.
    alternatives: tuple[AlternativeMatch, ...] = ()
    run_id: str | None = None

    @model_serializer(mode='wrap')
    def _omit_defaults(self, handler):
        data = handler(self)
        for key in ('alternatives', 'run_id'):
            if not data.get(key):
                data.pop(key, None)
        return data

    @model_validator(mode='after')
    def same_engine(self):
        if any(m.engine != self.engine or m.engine_version != self.engine_version for m in self.matches):
            raise ValueError('match engine differs from set engine')
        if self.contract == 'secondary/1' and (self.alternatives or self.run_id is not None):
            raise ValueError('alternatives and run_id require contract secondary/2')
        if len(self.alternatives) > MAX_ALTERNATIVES:
            raise ValueError('PT-SECONDARY-LIMIT: too many alternative matches')
        per_anchor: dict[tuple[str, int], int] = {}
        for alt in self.alternatives:
            key = (alt.anchor_side, alt.anchor_address)
            per_anchor[key] = per_anchor.get(key, 0) + 1
            if per_anchor[key] > MAX_ALTERNATIVES_PER_ANCHOR:
                raise ValueError('PT-SECONDARY-LIMIT: too many alternatives for one anchor')
        return self

    @property
    def entry_id(self) -> str:
        if self.contract == 'secondary/2':
            return domain_id('secondary', 2, {'engine': self.engine, 'older': self.older_sha256,
                                              'newer': self.newer_sha256})
        return domain_id('secondary', 1, {'engine': self.engine, 'file_sha256': self.file_sha256,
                                          'older': self.older_sha256, 'newer': self.newer_sha256})


class Capability(_Strict):
    engine: Literal['bindiff', 'rz-diff', 'ghidriff-baseline']
    supported: bool
    version: str | None
    path: str
    supports_json: bool
    reason: str | None = None


def to_milli(value: object, label: str) -> tuple[int, str]:
    """Upstream double → (integer milli, upstream text). Rejects bools, NaN and out-of-range."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SecondaryError('PT-SECONDARY-INPUT', f'{label} is not a number')
    try:
        number = float(value)
    except OverflowError:
        raise SecondaryError('PT-SECONDARY-INPUT', f'{label} is outside 0..1') from None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise SecondaryError('PT-SECONDARY-INPUT', f'{label} {value!r} is outside 0..1')
    return round(number * 1000), repr(value)


def flag_names(mask: int) -> tuple[str, ...]:
    if isinstance(mask, bool) or not isinstance(mask, int) or not 0 <= mask < 1 << len(FLAG_NAMES):
        raise SecondaryError('PT-SECONDARY-INPUT', f'unknown BinDiff flag bits {mask!r}')
    return tuple(name for bit, name in enumerate(FLAG_NAMES) if mask & (1 << bit))


def check_pair(found_older: str, found_newer: str, older_sha256: str, newer_sha256: str) -> None:
    found = (found_older.strip().lower(), found_newer.strip().lower())
    if found == (newer_sha256, older_sha256) and older_sha256 != newer_sha256:
        raise SecondaryError('PT-SECONDARY-ORIENTATION', 'file hashes are reversed relative to older/newer')
    if found != (older_sha256, newer_sha256):
        raise SecondaryError('PT-SECONDARY-PAIR', 'file hashes do not match the project artifact pair')
