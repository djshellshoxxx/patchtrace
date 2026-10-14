"""Strict `tool-evidence/1` records and shared helpers for the capa / FLOSS / diec adapters (SPEC-29 tools T2).

Pure: no Qt, no process, file or network I/O. Every record forbids extra fields, coerces nothing and is frozen, so
evidence cannot be altered after it was validated. Tool output is hostile: `load_json_strict` bounds and validates
it before any model sees it, and `display_text` is the only way a tool string becomes displayable text.

'none found' (`ToolRun.status == 'none-found'`) is a successful run with zero evidence items and is kept apart
from `absent`, `unsupported`, `failed`, `timeout` and `cancelled`: a missing or broken tool is unknown, never a
negative vote.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ...enrichment.identity import canonical_json, domain_id

CONTRACT = 'tool-evidence/1'
RUN_KIND = 'tool-run'
EVIDENCE_KIND = 'tool-evidence'
GUARD_RUN_ID = 'intel-tools'
ENGINES: tuple[str, ...] = ('capa', 'floss', 'diec')
LICENSES = {'capa': 'Apache-2.0', 'floss': 'Apache-2.0', 'diec': 'MIT'}
PROFILES: dict[str, tuple[str, ...]] = {'basic': ('capa',), 'context': ('capa', 'floss'),
                                        'full': ('capa', 'floss', 'diec')}
DISPLAY_LIMIT = 256
ERROR_LIMIT = 500
STDERR_EXCERPT = 4 * 1024
MAX_ANOMALIES = 64
MAX_ADDRESS = 2**64 - 1

Engine = Literal['capa', 'floss', 'diec']
Side = Literal['older', 'newer']
Profile = Literal['basic', 'context', 'full']
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Address = Annotated[int, Field(ge=0, le=MAX_ADDRESS)]
RunStatus = Literal['ok', 'none-found', 'failed', 'timeout', 'cancelled', 'unsupported', 'absent']
ErrorCode = Literal['PT-TOOL-ABSENT', 'PT-TOOL-UNSUPPORTED', 'PT-TOOL-INPUT', 'PT-TOOL-ARTIFACT', 'PT-TOOL-OUTPUT',
                    'PT-TOOL-LIMIT', 'PT-TOOL-RUN', 'PT-TOOL-TIMEOUT', 'PT-TOOL-CANCEL', 'PT-TOOL-ADDRESS',
                    'PT-TOOL-STALE', 'PT-TOOL-MISMATCH', 'PT-TOOL-STORE', 'PT-TOOL-CONSENT']
Attribution = Literal['function-start', 'basic-block-in-function', 'decoding-routine', 'stack-frame', 'none']
LOCALIZED: frozenset[str] = frozenset({'function-start', 'basic-block-in-function', 'decoding-routine',
                                       'stack-frame'})
CapaScope = Literal['file', 'function', 'basic block', 'instruction']
StringType = Literal['static', 'stack', 'tight', 'decoded', 'language']
EnvCategory = Literal['compiler', 'linker', 'tool', 'packer', 'protector', 'cryptor', 'installer', 'sfx', 'library',
                      'format', 'overlay', 'other', 'unknown']
_FUNCTION_ID = re.compile(r'^rva:0x[0-9a-f]{1,16}$')
_SHORT = Annotated[str, Field(max_length=256)]


class ToolError(Exception):
    """Typed, user-safe failure (`message` never contains raw tool output or local paths)."""

    def __init__(self, code: ErrorCode, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ToolLimits:
    stdout_bytes: int
    stderr_bytes: int = 256 * 1024
    json_depth: int = 96
    max_rule_matches: int = 20_000
    max_feature_locations: int = 64
    max_strings: int = 200_000
    max_environment: int = 512


DEFAULT_LIMITS = {'capa': ToolLimits(64 * 1024 * 1024), 'floss': ToolLimits(64 * 1024 * 1024),
                  'diec': ToolLimits(1024 * 1024)}


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class ToolManifest(_Strict):
    """What the probe verified about one configured tool (T2)."""
    contract: Literal['tool-evidence/1'] = CONTRACT
    engine: Engine
    version: str | None = Field(default=None, max_length=64)
    version_text: str | None = Field(default=None, max_length=120)
    cli_path: str = Field(default='', max_length=4096)
    executable_sha256: Sha256 | None = None
    capabilities: tuple[Annotated[str, Field(max_length=64)], ...] = Field(default=(), max_length=32)
    license: str = Field(max_length=32)
    rules_sha256: Sha256 | None = None
    rules_source: Literal['directory', 'embedded', 'none'] = 'none'
    signatures_sha256: Sha256 | None = None
    backend: str | None = Field(default=None, max_length=32)
    backend_version: str | None = Field(default=None, max_length=64)
    untested_version: bool = False
    supported: bool
    reason: str | None = Field(default=None, max_length=ERROR_LIMIT)
    # Additive (TA-6): 'pinned' = the executable digest equals a release listed in `pins.PINNED_EXECUTABLES`.
    pin_status: Literal['pinned', 'unpinned'] = 'unpinned'

    @model_validator(mode='after')
    def _consistent(self):
        if self.rules_source == 'directory' and self.rules_sha256 is None:
            raise ValueError('a rule or signature database directory needs its digest')
        if self.supported and (not self.version or not self.executable_sha256):
            raise ValueError('a supported tool has a probed version and executable digest')
        return self

    def rules_identity(self) -> str | None:
        if self.rules_sha256:
            return self.rules_sha256
        if self.rules_source == 'embedded' and self.executable_sha256:
            return f'embedded:{self.executable_sha256}'
        return None

    def identity(self) -> dict:
        """Everything about the tool that determines its output, without local paths."""
        return {'engine': self.engine, 'version': self.version, 'executable_sha256': self.executable_sha256,
                'rules': self.rules_identity(), 'signatures': self.signatures_sha256, 'backend': self.backend,
                'backend_version': self.backend_version}


class ToolRun(_Strict):
    """One attempt for one engine and one side; written once, never updated."""
    contract: Literal['tool-evidence/1'] = CONTRACT
    run_id: str = Field(min_length=1, max_length=128)
    engine: Engine
    side: Side
    input_artifact_hash: Sha256
    config_digest: Sha256
    cache_key: Sha256
    started_at: str = Field(max_length=64)
    elapsed: int = Field(ge=0)  # milliseconds
    status: RunStatus
    error: str | None = Field(default=None, max_length=ERROR_LIMIT)
    error_code: ErrorCode | None = None
    returncode: int | None = None
    stderr_digest: Sha256 | None = None
    stdout_digest: Sha256 | None = None
    stderr_excerpt: str = Field(default='', max_length=STDERR_EXCERPT)
    raw_sidecar: str | None = Field(default=None, max_length=256)
    evidence_count: int = Field(default=0, ge=0)
    cache_hit: bool = False
    profile: Profile
    options: dict[Annotated[str, Field(max_length=64)], Annotated[str, Field(max_length=256)]] = \
        Field(default_factory=dict, max_length=16)
    manifest: ToolManifest
    anomalies: tuple[_SHORT, ...] = Field(default=(), max_length=MAX_ANOMALIES)

    @model_validator(mode='after')
    def _consistent(self):
        if self.manifest.engine != self.engine:
            raise ValueError('manifest engine differs from the run engine')
        if self.status == 'none-found' and self.evidence_count:
            raise ValueError("'none-found' means the validated output holds zero evidence items")
        if self.status in ('ok', 'none-found') and self.error_code is not None:
            raise ValueError('a successful run carries no error code')
        if self.status not in ('ok', 'none-found') and self.error_code is None:
            raise ValueError('an unsuccessful run names its PT-TOOL error code')
        return self


def produced(run: ToolRun) -> bool:
    """True for runs whose output was validated ('ok' with evidence or 'none-found')."""
    return run.status in ('ok', 'none-found')


class EvidenceLink(_Strict):
    """Where an evidence item sits in one artifact, in canonical module-relative terms (T2, T5.3)."""
    tool_run_id: str = Field(min_length=1, max_length=128)
    artifact_sha256: Sha256
    function_id: str | None = Field(default=None, max_length=24)
    project_function_id: str | None = Field(default=None, max_length=128)
    rva: int | None = Field(default=None, ge=0, lt=2**32)
    file_offset: int | None = Field(default=None, ge=0, lt=2**40)
    source_fragment: str | None = Field(default=None, max_length=200)
    attribution: Attribution = 'none'
    # Additive (WB3-S1b): decoded strings only. `data_rva` = RVA of the decoded string's own address (GLOBAL),
    # `site_rva` = RVA of the instruction where it was decoded.
    data_rva: int | None = Field(default=None, ge=0, lt=2**32)
    site_rva: int | None = Field(default=None, ge=0, lt=2**32)

    @model_validator(mode='after')
    def _consistent(self):
        if self.function_id is not None and not _FUNCTION_ID.match(self.function_id):
            raise ValueError('function_id must be rva:0x<hex>')
        if self.attribution != 'none' and (self.function_id is None or self.rva is None):
            raise ValueError('a localized attribution names a function and an RVA')
        if self.project_function_id is not None and self.function_id is None:
            raise ValueError('a project function link needs the tool-reported function')
        return self


class CapabilityEvidence(_Strict):
    rule_id: str = Field(min_length=1, max_length=256)
    rule_sha256: Sha256
    namespace: str | None = Field(default=None, max_length=256)
    scope: CapaScope
    address_space: Literal['absolute', 'relative', 'file', 'no address']
    address: Address | None = None
    location: EvidenceLink
    kind: Literal['capability', 'library', 'limitation']
    source_run_id: str = Field(min_length=1, max_length=128)
    attack: tuple[Annotated[str, Field(max_length=32)], ...] = Field(default=(), max_length=32)
    mbc: tuple[Annotated[str, Field(max_length=32)], ...] = Field(default=(), max_length=32)
    feature_rvas: tuple[Annotated[int, Field(ge=0, lt=2**32)], ...] = Field(default=(), max_length=64)
    feature_count: int = Field(default=0, ge=0)


class StringEvidence(_Strict):
    value_hash: Sha256
    length: int = Field(ge=0)
    display_value: str = Field(max_length=DISPLAY_LIMIT)
    secret_kind: str | None = Field(default=None, max_length=32)
    encoding: Literal['ASCII', 'UTF-16LE', 'UTF-8']
    type: StringType
    source_location: EvidenceLink
    confidence_class: Literal['verified-bytes', 'tool-reported', 'unverified-location']
    extraction_method: Literal['floss-static', 'floss-stack', 'floss-tight', 'floss-decoded', 'floss-language']
    source_run_id: str = Field(min_length=1, max_length=128)


class EnvironmentEvidence(_Strict):
    category: EnvCategory
    toolchain: str | None = Field(default=None, max_length=200)
    packer: str | None = Field(default=None, max_length=200)
    protector: str | None = Field(default=None, max_length=200)
    detector_rule: str = Field(max_length=200)
    heuristic: bool
    source: Literal['diec'] = 'diec'
    certainty: Literal['signature', 'heuristic', 'unknown']
    version: str = Field(default='', max_length=120)
    detect_string: str = Field(default='', max_length=200)
    filetype: str = Field(default='', max_length=32)
    source_run_id: str = Field(min_length=1, max_length=128)


class ToolEvidenceSet(_Strict):
    """Normalised evidence of one run (row body of kind `tool-evidence`, or its sidecar)."""
    contract: Literal['tool-evidence/1'] = CONTRACT
    run_id: str = Field(min_length=1, max_length=128)
    engine: Engine
    side: Side
    artifact_sha256: Sha256
    cache_key: Sha256
    config_digest: Sha256
    image_base: Address | None = None
    analysis: dict[Annotated[str, Field(max_length=32)], str | int | None] = Field(default_factory=dict,
                                                                                 max_length=16)
    capabilities: tuple[CapabilityEvidence, ...] = ()
    strings: tuple[StringEvidence, ...] = ()
    environment: tuple[EnvironmentEvidence, ...] = ()
    truncated: bool = False
    # Additive (WB3-S1b): string types cut at their quota; empty with `truncated` = unknown types (older rows).
    truncated_types: tuple[StringType, ...] = ()
    counts: dict[Annotated[str, Field(max_length=32)], Annotated[int, Field(ge=0)]] = Field(default_factory=dict,
                                                                                          max_length=16)
    anomalies: tuple[_SHORT, ...] = Field(default=(), max_length=MAX_ANOMALIES)

    @field_validator('analysis')
    @classmethod
    def _small(cls, value: dict) -> dict:
        for item in value.values():
            if isinstance(item, str) and len(item) > 200:
                raise ValueError('analysis facts are short')
        return value

    @model_validator(mode='after')
    def _counts(self):
        actual = {'capabilities': len(self.capabilities), 'strings': len(self.strings),
                  'environment': len(self.environment)}
        for key, value in actual.items():
            if key in self.counts and self.counts[key] != value:
                raise ValueError(f'counts[{key}] does not match the evidence')
        for item in (*self.capabilities, *self.strings, *self.environment):
            ref = item.source_location if isinstance(item, StringEvidence) else \
                item.location if isinstance(item, CapabilityEvidence) else None
            if item.source_run_id != self.run_id or (ref is not None and (
                    ref.tool_run_id != self.run_id or ref.artifact_sha256 != self.artifact_sha256)):
                raise ValueError('every evidence item belongs to this run and artifact')
        return self

    def evidence_count(self) -> int:
        return len(self.capabilities) + len(self.strings) + len(self.environment)


# ---- identities ------------------------------------------------------------------------------------------------

def _options(options: dict[str, str]) -> dict[str, str]:
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in options.items()):
        raise TypeError('tool options are strings')
    return dict(sorted(options.items()))


def config_digest(manifest: ToolManifest, options: dict[str, str]) -> str:
    """Tool identity + options, without the artifact: equal digests mean comparable runs (T6.1)."""
    return domain_id('tool-evidence-config', 1, {'tool': manifest.identity(), 'options': _options(options),
                                                 'contract': CONTRACT})


def cache_key(artifact_sha256: str, manifest: ToolManifest, options: dict[str, str]) -> str:
    """T7: artifact + engine (version, executable) + rules + signatures + backend + options + parser contract."""
    return domain_id('tool-evidence-cache', 1, {'artifact_sha256': artifact_sha256, 'tool': manifest.identity(),
                                                'options': _options(options), 'contract': CONTRACT})


def new_run_id(key: str, side: str, started_at: str) -> str:
    return domain_id('tool-run', 1, {'cache_key': key, 'side': side, 'started_at': started_at})


def evidence_entry_id(evidence: ToolEvidenceSet) -> str:
    """Content identity: equal evidence gets the same row id; different content never overwrites a row."""
    body = canonical_json(evidence.model_dump(mode='json', exclude={'run_id'}) | {
        'capabilities': [c.model_dump(mode='json', exclude={'source_run_id', 'location'}) | {
            'location': c.location.model_dump(mode='json', exclude={'tool_run_id'})} for c in evidence.capabilities],
        'strings': [s.model_dump(mode='json', exclude={'source_run_id', 'source_location'}) | {
            'location': s.source_location.model_dump(mode='json', exclude={'tool_run_id'})}
            for s in evidence.strings],
        'environment': [e.model_dump(mode='json', exclude={'source_run_id'}) for e in evidence.environment]})
    return f'{evidence.engine}-{evidence.side}-' + domain_id('tool-evidence', 1, {'body': body.decode('utf-8')})[:40]


# ---- hostile output --------------------------------------------------------------------------------------------

def _reject_constant(name: str):
    raise ValueError(f'non-finite number {name}')


def _finite_float(text: str) -> float:
    value = float(text)
    if value != value or value in (float('inf'), float('-inf')):  # `1e999` parses to inf (TA-16)
        raise ValueError(f'non-finite number {text[:20]}')
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'duplicate key {key[:40]!r}')
        out[key] = value
    return out


def _depth_ok(value: object, limit: int) -> bool:
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            if depth > limit:
                return False
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if depth > limit:
                return False
            stack.extend((child, depth + 1) for child in item)
    return True


def load_json_strict(data: bytes, *, max_bytes: int, max_depth: int = 96) -> object:
    """Bounded strict JSON: UTF-8 only, no duplicate keys, no NaN/Infinity, nesting <= max_depth."""
    if len(data) > max_bytes:
        raise ToolError('PT-TOOL-LIMIT', f'tool output is larger than {max_bytes} bytes')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ToolError('PT-TOOL-OUTPUT', 'tool output is not UTF-8') from None
    if not text.strip():
        raise ToolError('PT-TOOL-OUTPUT', 'tool output is empty')
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant,
                           parse_float=_finite_float)
    except RecursionError:
        raise ToolError('PT-TOOL-OUTPUT', 'tool output nests too deeply') from None
    except ValueError as exc:
        reason = str(exc)
        if 'duplicate key' in reason or 'non-finite' in reason:
            raise ToolError('PT-TOOL-OUTPUT', f'tool output rejected: {reason[:80]}') from None
        raise ToolError('PT-TOOL-OUTPUT', 'invalid JSON in tool output (truncated or corrupted)') from None
    if not _depth_ok(value, max_depth):
        raise ToolError('PT-TOOL-OUTPUT', f'tool output nests deeper than {max_depth} levels')
    return value


_INVISIBLE = frozenset({'Cc', 'Cf', 'Cs', 'Co', 'Cn', 'Zl', 'Zp'})


def display_text(value: str, limit: int = DISPLAY_LIMIT) -> str:
    """Plain-text rendering of a hostile string: control, format (bidi, zero-width), surrogate, private-use and
    unassigned characters are escaped; the result is capped. Renderers must still treat it as text, never markup."""
    out: list[str] = []
    size = 0
    for char in value:
        if char == ' ' or unicodedata.category(char) not in _INVISIBLE:
            piece = char
        elif char == '\n':
            piece = '\\n'
        elif char == '\t':
            piece = '\\t'
        elif char == '\r':
            piece = '\\r'
        elif ord(char) < 0x100:
            piece = f'\\x{ord(char):02x}'
        elif ord(char) < 0x10000:
            piece = f'\\u{ord(char):04x}'
        else:
            piece = f'\\U{ord(char):08x}'
        if size + len(piece) > limit - 3:
            out.append('...')
            break
        out.append(piece)
        size += len(piece)
    return ''.join(out)


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ('private-key', re.compile(r'-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----')),
    ('aws-access-key', re.compile(r'\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b')),
    ('github-token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b')),
    ('slack-token', re.compile(r'\bxox[abposr]-[A-Za-z0-9-]{10,200}\b')),
    ('google-api-key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')),
    ('credential-assignment', re.compile(
        r'(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)'
        r'\s*[=:]\s*["\']?[^\s"\';]{6,}')),
)


def secret_kind(value: str) -> str | None:
    """Name of the first secret-looking pattern in `value` (bounded scan), else None."""
    sample = value[:4096]
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(sample):
            return name
    return None


def redacted_display(display: str, kind: str | None) -> str:
    return f'[redacted: {kind}]' if kind else display
