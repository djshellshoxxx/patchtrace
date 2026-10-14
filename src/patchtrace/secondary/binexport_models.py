"""Strict JSON records crossing the BinExport worker boundary (SPEC-10b §4). Pure pydantic, no I/O."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .contracts import Address, Sha256, _Strict

Role = Literal['older', 'newer']
VertexType = Annotated[int, Field(ge=0, le=4)]  # NORMAL, LIBRARY, IMPORTED, THUNK, INVALID
Slug = Annotated[str, Field(pattern=r'^[a-z0-9_:.]{1,80}$')]


class BinExportSummary(_Strict):
    """Names/strings from the file are deliberately absent except the three bounded meta fields (T6)."""
    contract: Literal['binexport-summary/1'] = 'binexport-summary/1'
    file_sha256: Sha256
    file_size: int = Field(ge=1)
    executable_id: str = Field(max_length=4096)
    executable_name: str = Field(min_length=1, max_length=4096)
    architecture_name: str = Field(min_length=1, max_length=4096)
    timestamp: int | None
    id_binding: Literal['sha256', 'md5', 'empty', 'other']
    role: Role
    address_basis: Literal['va', 'rva', 'unknown']
    counts: dict[str, Annotated[int, Field(ge=0)]]
    function_addresses: tuple[Address, ...] = Field(min_length=1)
    vertex_types: tuple[VertexType, ...]
    warnings: tuple[Slug, ...]
    protobuf_version: str = Field(min_length=1, max_length=40)
    descriptor_proto_sha256: Sha256

    @model_validator(mode='after')
    def consistent(self):
        a = self.function_addresses
        if any(x >= y for x, y in zip(a, a[1:], strict=False)):
            raise ValueError('function_addresses must be strictly increasing')
        if len(self.vertex_types) != len(a):
            raise ValueError('vertex_types must parallel function_addresses')
        if any('\x00' in s for s in (self.executable_id, self.executable_name, self.architecture_name)):
            raise ValueError('meta fields must not contain NUL')
        return self


class PeLayoutModel(_Strict):
    image_base: Address
    size_of_image: Annotated[int, Field(ge=0, le=2**32 - 1)]
    machine: str | None = Field(default=None, max_length=64)


class WorkerRequest(_Strict):
    contract: Literal['binexport-worker-request/1'] = 'binexport-worker-request/1'
    src: str = Field(min_length=1)
    snapshot: str = Field(min_length=1)
    result: str = Field(min_length=1)
    artifact_sha256: Sha256
    role: Role
    limits: dict
    pe_layout: PeLayoutModel | None = None
    accept_unbound: bool = False


class WorkerError(_Strict):
    code: str = Field(pattern=r'^PT-SECONDARY-[A-Z]+$')
    message: str = Field(max_length=400)
    reason: Slug | None


class WorkerResult(_Strict):
    contract: Literal['binexport-worker-result/1'] = 'binexport-worker-result/1'
    kind: Literal['ok', 'error']
    summary: BinExportSummary | None = None
    error: WorkerError | None = None

    @model_validator(mode='after')
    def one_of(self):
        if (self.kind == 'ok') != (self.summary is not None) or (self.kind == 'error') != (self.error is not None):
            raise ValueError('worker result must carry exactly the summary or the error')
        return self
