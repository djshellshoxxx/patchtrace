"""Strict acquisition/1 records (SPEC-08 §3). Pure: no Qt, network or I/O.

A matching SHA-256 proves identity with the Winbindex record, not vendor authenticity;
Authenticode verification is out of scope for acquisition/1 and is labelled as such.
"""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..enrichment.identity import domain_id

CONTRACT = 'acquisition/1'
AUTHENTICITY_NOTE = ('SHA-256 matches the Winbindex record (identity only); '
                     'Authenticode signature verification is out of scope for acquisition/1')
X64_MACHINE = 34404
UINT32_MAX = 4_294_967_295
PE_EXTENSIONS = frozenset({'exe', 'dll', 'sys', 'efi', 'drv', 'ocx', 'cpl', 'scr'})
SYMBOL_SERVER = 'https://msdl.microsoft.com/download/symbols'
_NAME = re.compile(r'[a-z0-9._-]{1,128}')
_DEVICE_NAMES = frozenset({'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)),
                          *(f'lpt{i}' for i in range(1, 10))})
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Format = Literal['pe', 'pa30', 'pa31', 'unknown']
ErrorCode = Literal['PT-ACQ-INPUT', 'PT-ACQ-CONFIG', 'PT-ACQ-LIMIT', 'PT-ACQ-CANCEL', 'PT-ACQ-NETWORK',
                    'PT-ACQ-PROVIDER', 'PT-ACQ-NOTFOUND', 'PT-ACQ-VERIFY', 'PT-ACQ-UNSUPPORTED']


class AcquisitionError(Exception):
    """Typed failure with a user-safe message. PT-ACQ-NOTFOUND is a normal outcome, not a fault."""

    def __init__(self, code: ErrorCode, message: str, *, recoverable: bool = False):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message
        self.recoverable = recoverable


def validate_file_name(value: object) -> str:
    # fullmatch: `$` would admit a trailing newline into a URL path segment.
    if type(value) is not str or not _NAME.fullmatch(value) or value in {'.', '..'}:
        raise AcquisitionError('PT-ACQ-INPUT', 'file name must be a lowercase basename of [a-z0-9._-]')
    stem = value.split('.', 1)[0]
    if not stem or stem in _DEVICE_NAMES:  # Windows resolves `con.dll` to the console device
        raise AcquisitionError('PT-ACQ-INPUT', 'file name is empty or reserved by Windows')
    if value.rsplit('.', 1)[-1] not in PE_EXTENSIONS or '.' not in value:
        raise AcquisitionError('PT-ACQ-INPUT', f'file extension must be one of {sorted(PE_EXTENSIONS)}')
    return value


def symbol_server_url(file_name: str, timestamp: int, size_of_image: int) -> str:
    # %08X timestamp + %x SizeOfImage, exactly as Winbindex derives it (server is case-insensitive).
    if not 0 <= timestamp <= UINT32_MAX or not 0 < size_of_image <= UINT32_MAX:
        raise AcquisitionError('PT-ACQ-INPUT', 'timestamp/SizeOfImage out of range')
    name = validate_file_name(file_name)
    return f'{SYMBOL_SERVER}/{name}/{timestamp:08X}{size_of_image:x}/{name}'


def acquisition_id(file_name: str, sha256: str) -> str:
    return domain_id('acquisition', 1, {'file_name': file_name, 'sha256': sha256})


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class AcquisitionQuery(Record):
    file_name: str
    dataset: Literal['x64'] = 'x64'

    @field_validator('file_name')
    @classmethod
    def _name(cls, value):
        try:
            return validate_file_name(value)
        except AcquisitionError as exc:
            raise ValueError(exc.message) from None


class KbRef(Record):
    kb: str = Field(min_length=1, max_length=64)
    release_date: str | None = None
    release_version: str | None = None


class BuildCandidate(Record):
    file_name: str
    sha256: Sha256
    size: int = Field(ge=1, le=UINT32_MAX)
    machine_type: int = Field(ge=0, le=0xFFFF)
    timestamp: int = Field(ge=0, le=UINT32_MAX)
    virtual_size: int | None = Field(default=None, ge=1, le=UINT32_MAX)
    last_section_va: int | None = Field(default=None, ge=0, le=UINT32_MAX)
    last_section_raw: int | None = Field(default=None, ge=0, le=UINT32_MAX)
    version: str | None = None
    windows_versions: tuple[str, ...] = ()
    kbs: tuple[KbRef, ...] = ()
    download: Literal['direct', 'candidates', 'unavailable']
    source: str = Field(pattern=r'^winbindex@\d{4}-\d{2}-\d{2}$')
    record_sha256: Sha256

    @model_validator(mode='after')
    def _consistent(self):
        if list(self.windows_versions) != sorted(set(self.windows_versions)):
            raise ValueError('windows_versions must be sorted and unique')
        expected = ('direct' if self.virtual_size is not None else
                    'candidates' if self.last_section_va is not None and self.last_section_raw is not None
                    else 'unavailable')
        if self.download != expected:
            raise ValueError('download classification does not match the record fields')
        return self

    @property
    def x64(self) -> bool:
        return self.machine_type == X64_MACHINE


class PlannedDownload(Record):
    side: Literal['older', 'newer']
    file_name: str
    sha256: Sha256
    size: int = Field(ge=1, le=UINT32_MAX)
    url: str
    record_sha256: Sha256


class DownloadPlan(Record):
    """Exactly two downloads, older then newer, chosen explicitly by the analyst."""
    contract: Literal['acquisition/1'] = CONTRACT
    downloads: tuple[PlannedDownload, PlannedDownload]

    @model_validator(mode='after')
    def _ordered(self):
        older, newer = self.downloads
        if (older.side, newer.side) != ('older', 'newer'):
            raise ValueError('plan must list the older then the newer download')
        if older.sha256 == newer.sha256:
            raise ValueError('older and newer builds must differ')
        if older.file_name != newer.file_name:
            raise ValueError('both builds must be the same file')
        for item in self.downloads:
            prefix = f'{SYMBOL_SERVER}/{item.file_name}/'
            if not item.url.startswith(prefix) or not item.url.endswith('/' + item.file_name):
                raise ValueError('download URL is not a symbol-server URL for this file')
        return self


class Provenance(Record):
    source_url: str
    # Host only: the signed blob URL is short-lived and carries a SAS token, so it is never kept.
    redirect_host: str | None
    retrieved_at: str
    winbindex_record_sha256: Sha256


class AcquiredArtifact(Record):
    contract: Literal['acquisition/1'] = CONTRACT
    acquisition_id: Sha256
    side: Literal['older', 'newer']
    file_name: str
    path: str
    sha256: Sha256
    size: int = Field(ge=1)
    format: Format
    machine: int | None = None
    provenance: Provenance
    authenticity: str = AUTHENTICITY_NOTE
