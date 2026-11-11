"""Strict Diaphora records (SPEC-DA-01 "Persisted records"). Pure: no Qt, process or network I/O."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

KIND = 'diaphora-matches'
CONTRACT = 'diaphora/1'
MANIFEST_CONTRACT = 'diaphora-diff/1'
CATEGORIES = ('best', 'partial', 'unreliable', 'multimatch')
UNMATCHED_SIDES = ('primary', 'secondary')

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Ea = Annotated[int, Field(ge=0, le=2**64 - 1)]
Milli = Annotated[int, Field(ge=0, le=1000)]
Text = Annotated[str, Field(max_length=4096)]
AddressStatus = Literal['verified-rva', 'external-ea-only', 'ambiguous']
Trust = Literal['manifest-bound', 'user-attested']
ErrorCode = Literal['PT-DIAPHORA-INPUT', 'PT-DIAPHORA-DB', 'PT-DIAPHORA-LIMIT', 'PT-DIAPHORA-PAIR',
                    'PT-DIAPHORA-ORIENTATION', 'PT-DIAPHORA-PROVENANCE', 'PT-DIAPHORA-CANCEL',
                    'PT-DIAPHORA-STORAGE']

BASE_LIMITATIONS = (
    'Diaphora ratio is a Diaphora-specific heuristic similarity, not a BinDiff confidence or a probability.',
    'Pseudocode, microcode and graph evidence from Diaphora is often correlated with Ghidriff; agreement is not '
    'independent proof.',
    'Imported rows were produced outside PatchTrace; only the file and pair hashes are verified here.',
)


class DiaphoraError(Exception):
    """Carries a stable `PT-DIAPHORA-*` code; the message already starts with it."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class DiaphoraMatch(_Strict):
    index: int = Field(ge=0)                      # row position in the source `results` table (rowid order)
    category: Literal['best', 'partial', 'unreliable', 'multimatch']
    older_ea_text: Text
    newer_ea_text: Text
    older_ea: Ea
    newer_ea: Ea
    older_rva: Ea | None
    newer_rva: Ea | None
    older_name: Text
    newer_name: Text
    ratio_text: Text                              # the source text, always preserved
    ratio_milli: Milli | None                     # None: missing/unusable, never zero
    ratio_transform: Literal['direct', 'capped-bonus', 'unavailable']
    older_nodes: int | None = Field(ge=0)
    newer_nodes: int | None = Field(ge=0)
    heuristic: Text
    address_status: AddressStatus

    @model_validator(mode='after')
    def consistent(self):
        if (self.ratio_milli is None) != (self.ratio_transform == 'unavailable'):
            raise ValueError('ratio value and transform disagree')
        if self.address_status == 'verified-rva' and (self.older_rva is None or self.newer_rva is None):
            raise ValueError('verified-rva needs both RVAs')
        return self


class DiaphoraUnmatched(_Strict):
    index: int = Field(ge=0)
    source_side: Literal['primary', 'secondary']
    side: Literal['older', 'newer']               # after orientation binding (primary is older)
    ea_text: Text
    ea: Ea
    rva: Ea | None
    name: Text
    address_status: AddressStatus


class DiaphoraMatchSet(_Strict):
    contract: Literal['diaphora/1'] = 'diaphora/1'
    engine: Literal['diaphora'] = 'diaphora'
    engine_version: Text                          # config.version of the result database
    older_sha256: Sha256
    newer_sha256: Sha256
    result_sha256: Sha256
    orientation: Literal['older->newer'] = 'older->newer'
    trust: Trust
    matches: tuple[DiaphoraMatch, ...]
    unmatched: tuple[DiaphoraUnmatched, ...]
    duplicate_rows: int = Field(ge=0, default=0)
    limitations: tuple[str, ...] = BASE_LIMITATIONS

    @property
    def entry_id(self) -> str:
        from ..enrichment.identity import domain_id
        return domain_id('diaphora', 1, {'older': self.older_sha256, 'newer': self.newer_sha256,
                                         'result': self.result_sha256})


class DiaphoraDiffManifest(_Strict):
    """Sidecar a user (or a later PatchTrace runner) writes next to the result; binds it to the exact pair."""
    contract: Literal['diaphora-diff/1']
    orientation: Literal['older->newer']
    older_binary_sha256: Sha256
    newer_binary_sha256: Sha256
    result_sha256: Sha256
    diaphora_version: Text = ''
