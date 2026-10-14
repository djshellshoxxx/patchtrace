"""`validation-ledger/1`: which channel/facet was tested on what (LBL integration plan 7.5). Package data, strict.

A missing, malformed, tampered or expired file never raises: it degrades to "everything unvalidated" with
reason `PT-CALIB-LEDGER ...`. Pure: no Qt, network, numpy or pickle.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from .artifact import ArtifactError, Sha256, _Strict, digest, strict_json
from .scope import ScopeId

CONTRACT = 'validation-ledger/1'
MAX_LEDGER_BYTES = 64 * 1024
MAX_ENTRIES = 64
LEDGER_PATH = Path(__file__).with_name('ledger') / 'validation-ledger.json'
Channel = Literal['ghidriff', 'rz-diff', 'bindiff', 'unified', 'attention', 'capa', 'floss', 'diec', 'yara-x']
Facet = Literal['pairing', 'materiality', 'lead-list', 'capability-delta', 'string-delta', 'environment-flag',
                'rule-match']
LedgerState = Literal['unvalidated', 'synthetic-validated', 'windows-validated']
Tier = Literal['synthetic', 'tier-r', 'tier-w']


class LedgerEntry(_Strict):
    channel: Channel
    facet: Facet
    state: LedgerState
    evidence_tiers: tuple[Tier, ...] = ()
    report_sha256: Sha256 | None = None
    prereg_sha256: Sha256 | None = None
    corpus_id: str = Field(default='', max_length=120)
    n_lineages: int = Field(default=0, ge=0)
    n_pairs: int = Field(default=0, ge=0)
    tool_versions: dict[str, str] = Field(default_factory=dict, max_length=16)
    scope_ids: tuple[ScopeId, ...] = ()
    measured_on: str | None = None
    expires: str | None = None

    @model_validator(mode='after')
    def _invariants(self):
        if self.state == 'synthetic-validated' and not ('tier-r' in self.evidence_tiers and self.report_sha256):
            raise ValueError('synthetic-validated needs tier-r evidence and a report sha256')
        if self.state == 'windows-validated':
            if 'tier-w' not in self.evidence_tiers or not self.report_sha256:
                raise ValueError('windows-validated needs tier-w evidence and a report sha256')
            if 'no-windows-system-binaries' in self.scope_ids:
                raise ValueError('windows-validated contradicts scope no-windows-system-binaries')
        if self.state != 'unvalidated':
            if self.measured_on is None or self.expires is None:
                raise ValueError('validated entries need measured_on and expires')
            m, e = dt.date.fromisoformat(self.measured_on), dt.date.fromisoformat(self.expires)
            if e < m or (e - m).days > 366:
                raise ValueError('entry expiry must be within 12 months of measurement')
        return self


class ValidationLedger(_Strict):
    contract: Literal['validation-ledger/1']
    entries: tuple[LedgerEntry, ...] = Field(max_length=MAX_ENTRIES)
    created: str
    expires: str
    digest_sha256: Sha256


@dataclass(frozen=True)
class LedgerResult:
    entries: tuple[LedgerEntry, ...]
    reason: str  # 'ok', 'missing', 'expired' or 'PT-CALIB-LEDGER: ...'

    def state(self, channel: str, facet: str, today: dt.date | None = None) -> LedgerState:
        """Current state of one channel/facet; an expired entry reads as unvalidated."""
        day = today or dt.date.today()
        for e in self.entries:
            if e.channel == channel and e.facet == facet:
                if e.state != 'unvalidated' and day > dt.date.fromisoformat(e.expires or '1970-01-01'):
                    return 'unvalidated'
                return e.state
        return 'unvalidated'


def parse_ledger(data: bytes, *, today: dt.date | None = None) -> ValidationLedger:
    if len(data) > MAX_LEDGER_BYTES:
        raise ArtifactError('ledger exceeds 64 KiB')
    try:
        document = strict_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ArtifactError(f'not strict JSON: {exc}') from None
    if not isinstance(document, dict):
        raise ArtifactError('ledger must be a JSON object')
    try:
        ledger = ValidationLedger.model_validate_json(data)
    except ValidationError as exc:
        raise ArtifactError(f'schema: {exc.error_count()} validation error(s)') from None
    if digest(document) != ledger.digest_sha256:
        raise ArtifactError('digest mismatch')
    try:
        created, expires = dt.date.fromisoformat(ledger.created), dt.date.fromisoformat(ledger.expires)
    except ValueError:
        raise ArtifactError('bad date') from None
    if expires < created or (expires - created).days > 366:
        raise ArtifactError('expiry must be within 12 months of creation')
    if (today or dt.date.today()) > expires:
        raise ArtifactError('expired')
    keys = [(e.channel, e.facet) for e in ledger.entries]
    if len(set(keys)) != len(keys):
        raise ArtifactError('duplicate channel/facet entry')
    return ledger


def load_ledger(data: bytes | None, *, today: dt.date | None = None) -> LedgerResult:
    """Never raises; any problem means every channel is `unvalidated`."""
    if data is None:
        return LedgerResult((), 'missing')
    try:
        return LedgerResult(parse_ledger(data, today=today).entries, 'ok')
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        return LedgerResult((), 'expired' if text == 'expired' else f'PT-CALIB-LEDGER: {text}')


def load_bundled_ledger(path: Path | None = None, *, today: dt.date | None = None) -> LedgerResult:
    target = path or LEDGER_PATH
    try:
        with open(target, 'rb') as handle:
            data = handle.read(MAX_LEDGER_BYTES + 1)
    except FileNotFoundError:
        return LedgerResult((), 'missing')
    except OSError as exc:
        return LedgerResult((), f'PT-CALIB-LEDGER: unreadable ({type(exc).__name__})')
    return load_ledger(data, today=today)
