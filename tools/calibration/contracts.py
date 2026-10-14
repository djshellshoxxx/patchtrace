"""Dev-side contracts: `calibration-corpus/1` manifest, `calibration-labels/1` records, `calibration-report/1`.

Strict JSON (duplicate keys / NaN rejected) then pydantic strict, extra=forbid. The model artifact contract
ships in `patchtrace.calibration.artifact`.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .common import strict_json

Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Ident = Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')]
Role = Literal['dev', 'locked-test', 'shift-test']
SUBTYPES = tuple(f'N{i}' for i in range(1, 13))
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


class ContractError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class WinbindexIdentity(_Strict):
    timestamp: int = Field(ge=0, le=2**32 - 1)
    virtual_size: int = Field(ge=0, le=2**32 - 1)
    version: str | None = None
    kb: tuple[str, ...] = ()


class Pdb(_Strict):
    guid_age: str | None = None
    name: str | None = None
    used_for: Literal['labels-only', 'none']


class Source(_Strict):
    git: str = Field(min_length=1)
    commit: str = Field(pattern=r'^[0-9a-f]{7,64}$')
    license: str = Field(min_length=1)


class Recipe(_Strict):
    toolchain_digest: Sha256
    argv: tuple[str, ...] = Field(min_length=1)
    opt: str
    strip: bool
    env_digest: Sha256


class Binary(_Strict):
    id: Ident
    tier: Literal['W', 'R']
    file_name: str = Field(min_length=1, max_length=255, pattern=r'^[^/\\:]+$')
    arch: Literal['x64', 'x86', 'arm64', 'other']
    sha256: Sha256
    size: int | None = Field(default=None, ge=0)
    winbindex: WinbindexIdentity | None = None
    pdb: Pdb | None = None
    toolchain: str = 'unknown'
    source: Source | None = None
    recipe: Recipe | None = None
    redistribution: str

    @model_validator(mode='after')
    def tiers(self):
        if self.tier == 'W' and (self.winbindex is None or self.redistribution != 'none' or self.source):
            raise ValueError('Tier W needs a Winbindex identity, redistribution "none" and no source')
        if self.tier == 'R' and (self.source is None or self.recipe is None):
            raise ValueError('Tier R needs source pins and a build recipe')
        return self


class Pair(_Strict):
    id: Ident
    older: Ident
    newer: Ident
    kind: Literal['adjacent-patch', 'cross-version', 'unrelated-control']
    lineage: Ident
    family_tags: tuple[str, ...] = ()
    role: Role | None = None


class Lineage(_Strict):
    id: Ident
    members: tuple[Ident, ...] = Field(min_length=1)
    cluster_rule: str
    cluster_evidence_sha256: Sha256
    family: str = 'unknown'


class Split(_Strict):
    salt: str = Field(min_length=1)
    method: str
    shift_test_lineages: tuple[Ident, ...] = ()
    overlap_threshold: float = Field(default=0.15, gt=0, le=1)


class CorpusManifest(_Strict):
    contract: Literal['calibration-corpus/1']
    corpus_id: Ident
    created: str
    tool_git: str
    binaries: tuple[Binary, ...]
    pairs: tuple[Pair, ...]
    lineages: tuple[Lineage, ...]
    split: Split

    @model_validator(mode='after')
    def references(self):
        ids = [b.id for b in self.binaries]
        if len(set(ids)) != len(ids) or len({p.id for p in self.pairs}) != len(self.pairs):
            raise ValueError('duplicate binary or pair id')
        members = [m for lin in self.lineages for m in lin.members]
        if sorted(members) != sorted(ids):
            raise ValueError('every binary must belong to exactly one lineage')
        owner = {m: lin.id for lin in self.lineages for m in lin.members}
        for p in self.pairs:
            if p.older not in owner or p.newer not in owner:
                raise ValueError(f'pair {p.id} references an unknown binary')
            if p.kind != 'unrelated-control' and not owner[p.older] == owner[p.newer] == p.lineage:
                raise ValueError(f'pair {p.id} lineage does not contain both binaries')
        return self


class Side(_Strict):
    rva: int = Field(ge=0, le=2**64 - 1)
    size: int = Field(ge=0)
    body_sha256: Sha256


class Sampling(_Strict):
    stratum: Literal['natural', 'adversarial']
    stage: str
    p_incl: float = Field(gt=0, le=1)


class LabelRecord(_Strict):
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    older: Side
    newer: Side
    A: Literal['same', 'different', 'no-counterpart', 'indeterminate']
    subtype: Literal['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9', 'N10', 'N11', 'N12'] | None
    B: None = None
    C: None = None
    D: None = None
    source: Literal['human', 'symbol-derived', 'synthetic-exact']
    annotators: tuple[str, ...]
    adjudicated: bool
    guideline: str
    sampling: Sampling
    notes: str = Field(default='', max_length=2000)

    @property
    def y(self) -> int | None:
        return {'same': 1, 'different': 0, 'no-counterpart': 0}.get(self.A)


class GateResult(_Strict):
    status: Literal['pass', 'fail', 'insufficient-data']
    reasons: tuple[str, ...]


class CalibrationReport(_Strict):
    contract: Literal['calibration-report/1']
    claim: str
    prereg_sha256: str | None
    corpus_manifest_sha256: str | None
    label_set_sha256: str | None
    tool_git: str
    python_version: str
    dataset: dict[str, Any]
    per_profile: dict[str, Any]
    gates: dict[Literal['G0', 'G1', 'G2', 'G3'], GateResult]
    blind_spots: tuple[str, ...]
    amendments: tuple[str, ...]
    report_sha256: Sha256


def _strict(data: bytes, limit: int):
    if len(data) > limit:
        raise ContractError('document too large')
    try:
        return strict_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ContractError(f'not strict JSON: {exc}') from None


def load_manifest(data: bytes) -> CorpusManifest:
    _strict(data, MAX_MANIFEST_BYTES)
    try:
        return CorpusManifest.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'manifest invalid: {exc}') from None


def load_labels(data: bytes) -> tuple[LabelRecord, ...]:
    """JSONL; every line strict; duplicate (pair, match_id) rejected."""
    out, seen = [], set()
    for number, line in enumerate(data.splitlines(), 1):
        if not line.strip():
            continue
        _strict(line, 1024 * 1024)
        try:
            rec = LabelRecord.model_validate_json(line)
        except ValidationError as exc:
            raise ContractError(f'label line {number} invalid: {exc}') from None
        key = (rec.pair, rec.match_id)
        if key in seen:
            raise ContractError(f'label line {number} duplicates {key}')
        seen.add(key)
        out.append(rec)
    return tuple(out)
