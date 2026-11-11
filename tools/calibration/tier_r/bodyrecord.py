"""Per-lineage masked-body records (`tier-r-bodies/1`): the input of the corpus vendoring scan (LBL-remaining 4.3).

One document per lineage holds the sorted, de-duplicated `masked_sha256` of its function bodies (tier_r/bodyhash.py). Writing
to an existing record unions the hashes, so every pair of a lineage can contribute. Additive contract: nothing else reads it.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Literal

from pydantic import ValidationError, field_validator, model_validator

from ..common import digest
from .contracts import MAX_LABEL_BYTES, ContractError, Ident, Sha256, _Strict, _strict_doc, dump_json

CONTRACT = 'tier-r-bodies/1'
SUFFIX = '.bodies.json'


class BodyRecord(_Strict):
    contract: Literal['tier-r-bodies/1']
    lineage: Ident
    masked_sha256: tuple[Sha256, ...]
    digest_sha256: Sha256

    @field_validator('masked_sha256')
    @classmethod
    def sorted_unique(cls, value):
        if list(value) != sorted(set(value)):
            raise ValueError('masked_sha256 must be sorted and unique')
        return value

    @model_validator(mode='after')
    def non_empty(self):
        if not self.masked_sha256:
            raise ValueError('a record needs at least one body hash')
        return self


def make_record(lineage: str, hashes: Iterable[str]) -> dict:
    doc = {'contract': CONTRACT, 'lineage': lineage, 'masked_sha256': sorted(set(hashes)), 'digest_sha256': '0' * 64}
    try:
        BodyRecord.model_validate_json(dump_json(doc))
    except ValidationError as exc:
        raise ContractError(f'body record invalid: {exc}') from None
    doc['digest_sha256'] = digest(doc)
    return doc


def from_hashed(lineage: str, hashed: Mapping[int, tuple[str, str]]) -> dict:
    """Record from `bodyhash.hash_functions` output ((raw, masked) per rva)."""
    return make_record(lineage, (masked for _raw, masked in hashed.values()))


def load_record(data: bytes) -> BodyRecord:
    raw = _strict_doc(data, MAX_LABEL_BYTES)
    try:
        rec = BodyRecord.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'body record invalid: {exc}') from None
    if digest({**raw, 'digest_sha256': '0' * 64}) != rec.digest_sha256:
        raise ContractError(f'body record digest mismatch for {rec.lineage} (edited after generation)')
    return rec


def write_record(folder: Path, lineage: str, hashes: Iterable[str]) -> Path:
    """Write `<folder>/<lineage>.bodies.json`, unioning with an existing record of the same lineage."""
    path = folder / f'{lineage}{SUFFIX}'
    merged = set(hashes)
    if path.exists():
        merged |= set(load_record(path.read_bytes()).masked_sha256)
    doc = make_record(lineage, merged)
    folder.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dump_json(doc))
    return path


def load_folder(folder: Path) -> dict[str, tuple[str, ...]]:
    """{lineage: hashes} in lineage order; a file named for another lineage is a contract error."""
    out: dict[str, tuple[str, ...]] = {}
    for path in sorted(folder.glob(f'*{SUFFIX}')):
        rec = load_record(path.read_bytes())
        if path.name != f'{rec.lineage}{SUFFIX}':
            raise ContractError(f'{path.name}: file name does not match lineage {rec.lineage}')
        out[rec.lineage] = rec.masked_sha256
    return out
