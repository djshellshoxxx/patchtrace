"""Strict `build-environment/1` contracts (DIE plan s7). Pure: no Qt, no I/O.

Records forbid extra fields, coerce nothing and are frozen; changes are additive only. A build fact is a labelled
observation (`certainty`) with its source, never a verdict: header fields are forgeable and a missing source is
unknown, not a negative vote. Deltas are always recomputed from two fingerprints and never stored.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..enrichment.identity import domain_id

CONTRACT = 'build-environment/1'
FACTS_VERSION = 'pe-build-facts/1'
FINGERPRINT_VERSION = 'buildenv/1'
MAP_VERSION = 'noise-map/1'
MAX_FACTS = 128
MAX_CHANGES = 128
MAX_ANOMALIES = 16

Side = Literal['older', 'newer']
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Slug = Annotated[str, Field(pattern=r'^[a-z0-9][a-z0-9-]{0,39}$')]
Version = tuple[Annotated[int, Field(ge=0, le=65535)], Annotated[int, Field(ge=0, le=65535)]]
FactKey = Literal['compiler', 'compiler_version', 'linker', 'linker_field', 'linker_rich', 'build_tool',
                  'runtime_family', 'language', 'target_os', 'subsystem', 'os_version_field',
                  'subsystem_version_field', 'image_version_field', 'rich_signature', 'packer', 'protector',
                  'installer', 'obfuscator', 'managed', 'gs_cookie', 'cfg', 'aslr', 'repro', 'debug_entry_types',
                  'entropy_exec', 'overlay']
FactSource = Literal['pe-header', 'rich-header', 'debug-directory', 'load-config', 'imports', 'clr-header',
                     'sections', 'diec']
Certainty = Literal['exact-field', 'derived', 'signature', 'heuristic', 'unknown']
ChangeKind = Literal['added', 'removed', 'changed', 'unchanged', 'one-sided-unknown']
ChangeType = Literal['toolchain', 'option', 'descriptive']
Strength = Literal['strong', 'weak']
WarningCode = Literal['packed', 'protected', 'managed', 'installer', 'overlay-large', 'packed-one-side',
                      'toolchain-differs', 'tool-unavailable', 'heuristic-only', 'stale-evidence',
                      'sources-disagree']
Severity = Literal['notice', 'caution']
ToolchainVerdict = Literal['same', 'differs', 'unknown']
DieStatus = Literal['ok', 'none-found', 'failed', 'timeout', 'cancelled', 'unsupported', 'absent', 'not-run']
ErrorCode = Literal['PT-BUILD-INPUT', 'PT-BUILD-LIMIT', 'PT-BUILD-STALE', 'PT-BUILD-MISMATCH', 'PT-BUILD-STORE']
Effect = Literal['tag', 'order']
Text = Annotated[str, Field(max_length=200)]


class BuildEnvError(Exception):
    """Typed, user-safe failure (`message` never contains raw tool output or local paths)."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class RichEntry(_Strict):
    product_id: int = Field(ge=0, le=0xFFFF)
    build: int = Field(ge=0, le=0xFFFF)
    count: int = Field(ge=0, le=0xFFFFFFFF)


class RichFacts(_Strict):
    offset: int = Field(ge=0)
    key: int = Field(ge=0, le=0xFFFFFFFF)
    checksum_ok: bool | None
    entries: tuple[RichEntry, ...] = Field(max_length=1024)
    truncated: bool
    signature: Sha256


class ClrFacts(_Strict):
    header_size: int = Field(ge=0)
    runtime_major: int = Field(ge=0)
    runtime_minor: int = Field(ge=0)
    flags: tuple[Annotated[str, Field(max_length=32)], ...] = Field(max_length=16)
    il_only: bool
    has_native_header: bool
    metadata_version: str | None = Field(max_length=64)


class PeBuildFacts(_Strict):
    """Header-level facts of one PE (mirror of `pe_overview.build_facts.PeBuildFacts`, which stays stdlib)."""
    facts_version: Literal['pe-build-facts/1'] = FACTS_VERSION
    linker_field: Version | None
    os_field: Version | None
    image_field: Version | None
    subsystem_field: Version | None
    subsystem: str | None = Field(max_length=32)
    dll_characteristics: tuple[Annotated[str, Field(max_length=32)], ...] = Field(max_length=32)
    guard_flags: tuple[Annotated[str, Field(max_length=48)], ...] | None = Field(max_length=32)
    security_cookie_set: bool | None
    debug_entry_types: tuple[int, ...] = Field(max_length=16)
    repro: bool
    rich: RichFacts | None
    clr: ClrFacts | None
    runtime_families: tuple[Annotated[str, Field(max_length=32)], ...] = Field(max_length=8)
    entropy_exec_max: float | None = Field(ge=0, le=8)
    overlay_size: int = Field(ge=0)
    overlay_entropy: float | None = Field(ge=0, le=8)
    sampled: bool
    anomalies: tuple[Slug, ...] = Field(max_length=MAX_ANOMALIES)


class BuildFact(_Strict):
    key: FactKey
    value: Text
    version: str = Field(default='', max_length=120)
    source: FactSource
    certainty: Certainty
    ref: str = Field(default='', max_length=64)
    raw: tuple[tuple[Annotated[str, Field(max_length=32)], Annotated[str, Field(max_length=120)]], ...] = \
        Field(default=(), max_length=4)

    def label(self) -> str:
        return f'{self.value} {self.version}'.strip()

    def raw_value(self, name: str) -> str | None:
        return next((value for key, value in self.raw if key == name), None)


class DieSummary(_Strict):
    """What the stored `diec` run says about itself; the evidence rows are only read."""
    status: DieStatus
    run_id: str = Field(max_length=128)
    tool_version: str | None = Field(max_length=64)
    db_label: str | None = Field(max_length=64)
    db_sha256: Sha256 | None
    argv_version: str | None = Field(max_length=32)
    heuristics: bool
    cache_key: Sha256 | None

    def produced(self) -> bool:
        return self.status in ('ok', 'none-found')

    def identity(self) -> tuple:
        return (self.tool_version, self.db_sha256, self.argv_version, self.heuristics)


class BuiltFrom(_Strict):
    pe_facts_version: str = Field(max_length=32)
    die_cache_key: Sha256 | None
    fingerprint_version: Literal['buildenv/1'] = FINGERPRINT_VERSION


class BuildFingerprint(_Strict):
    contract: Literal['build-environment/1'] = CONTRACT
    artifact_sha256: Sha256
    side: Side
    pe: PeBuildFacts | None
    die: DieSummary | None
    facts: tuple[BuildFact, ...] = Field(max_length=MAX_FACTS)
    anomalies: tuple[Slug, ...] = Field(max_length=MAX_ANOMALIES)
    built_from: BuiltFrom

    @model_validator(mode='after')
    def _consistent(self):
        if any(f.source == 'diec' for f in self.facts) and not (self.die and self.die.produced()):
            raise ValueError('diec facts need a produced diec run')
        if self.built_from.die_cache_key != (self.die.cache_key if self.die and self.die.produced() else None):
            raise ValueError('built_from names the diec cache key of the produced run')
        return self

    def entry_id(self) -> str:
        """Enrichment entry id of the stored row (DIE plan s7, Persistence)."""
        return domain_id('build-env', 1, {'artifact_sha256': self.artifact_sha256,
                                          'pe_facts_version': self.built_from.pe_facts_version,
                                          'die_cache_key': self.built_from.die_cache_key})


class BuildChange(_Strict):
    key: FactKey
    older: str | None = Field(max_length=200)
    newer: str | None = Field(max_length=200)
    change: ChangeKind
    kind: ChangeType
    strength: Strength
    basis: tuple[FactSource, ...] = Field(max_length=4)

    @model_validator(mode='after')
    def _consistent(self):
        if self.change == 'unchanged' and self.older != self.newer:
            raise ValueError('an unchanged fact has equal values')
        if self.change == 'added' and (self.older is not None or self.newer is None):
            raise ValueError('an added fact exists on the newer side only')
        if self.change == 'removed' and (self.newer is not None or self.older is None):
            raise ValueError('a removed fact exists on the older side only')
        return self


class PreflightWarning(_Strict):
    code: WarningCode
    side: Literal['older', 'newer', 'both']
    severity: Severity
    summary: str = Field(max_length=160)
    detail: str = Field(max_length=400)
    basis: tuple[FactSource, ...] = Field(max_length=4)
    teach_id: str | None = Field(max_length=40)


class NoiseReason(_Strict):
    code: Literal['toolchain-differs']
    classes: tuple[Annotated[str, Field(max_length=24)], ...] = Field(max_length=12)
    effect: Effect
    why: str = Field(max_length=200)


class BuildEnvDelta(_Strict):
    contract: Literal['build-environment/1'] = CONTRACT
    delta_id: Sha256
    older_sha256: Sha256
    newer_sha256: Sha256
    orientation: Literal['older->newer'] = 'older->newer'
    comparable: bool
    reasons: tuple[Slug, ...] = Field(max_length=12)
    toolchain: ToolchainVerdict
    toolchain_corroborated: bool
    options_changed: tuple[FactKey, ...] = Field(max_length=8)
    changes: tuple[BuildChange, ...] = Field(max_length=MAX_CHANGES)
    preflight: tuple[PreflightWarning, ...] = Field(max_length=16)
    noise: tuple[NoiseReason, ...] = Field(max_length=4)
    map_version: Literal['noise-map/1'] = MAP_VERSION
    limits_hit: tuple[Slug, ...] = Field(max_length=8)
    counts: dict[Annotated[str, Field(max_length=32)], Annotated[int, Field(ge=0)]] = Field(max_length=16)

    @model_validator(mode='after')
    def _consistent(self):
        if self.toolchain != 'unknown' and not self.comparable:
            raise ValueError('a toolchain verdict needs comparable inputs')
        if self.toolchain_corroborated and self.toolchain != 'differs':
            raise ValueError('only a difference is corroborated')
        if self.noise and self.toolchain != 'differs':
            raise ValueError('noise attribution needs a toolchain difference')
        return self


class BuildFactAnchor(_Strict):
    """A per-side build fact offered to other tracks as an anchor (never as a vote)."""
    anchor_id: Sha256
    key: FactKey
    value: Text
    side: Side
    artifact_sha256: Sha256
    source: FactSource
    certainty: Certainty


class TeachHook(_Strict):
    id: str = Field(max_length=40)
    meaning: str = Field(max_length=200)
    next_steps: tuple[Annotated[str, Field(max_length=200)], ...] = Field(max_length=4)
