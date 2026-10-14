"""FLOSS adapter (SPEC-29 tools T1, T3, T5, T7.2): version/option probe, static-only default, consented
deobfuscation, strict 3.x result parser.

Verified against FLOSS 3.1.1 (`floss/main.py`, `floss/results.py`, `floss/render/json.py` and real runs on
SYNTHETIC PE pairs). The default argv extracts static strings only (`--only static`): FLOSS then never loads a
vivisect workspace and nothing is emulated. Stack, tight and decoded strings need the vivisect emulator and run only
with `deobfuscate=True`, which the caller may set only after showing `EMULATION_CONSENT`.
"""
from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ...jobs import run_process
from . import pins, process
from .common import (
    LICENSES,
    MAX_ADDRESS,
    EvidenceLink,
    StringEvidence,
    ToolError,
    ToolEvidenceSet,
    ToolLimits,
    ToolManifest,
    display_text,
    load_json_strict,
    secret_kind,
)
from .normalize import PeMap, bytes_match

ENGINE = 'floss'
SUPPORTED_MAJOR = 3
TESTED_VERSIONS = frozenset({'3.1.1'})
DEFAULT_TIMEOUT = 600
DEOBFUSCATE_TIMEOUT = 3600
STATIC_TYPES = ('static',)
DEOBFUSCATION_TYPES = ('static', 'stack', 'tight', 'decoded')
REQUIRED_OPTIONS = ('-j', '--json', '-q', '--quiet', '--disable-progress', '--color', '-f', '--format', '--only')
EMULATION_CONSENT = (
    "FLOSS deobfuscation (stack, tight and decoded strings) runs the vivisect CPU emulator inside the FLOSS process "
    "on this computer. The emulator interprets the target's machine code instruction by instruction in a Python "
    "model of the CPU and memory: the target is not loaded by Windows, not executed natively, and the Windows API "
    "calls it makes are answered by FLOSS's built-in stubs, not performed. Hostile code still drives a complex "
    "emulator and can take a long time or a lot of memory. PatchTrace runs it in a private scratch folder with a "
    "restricted environment and a timeout. Static strings never need it.")
EMULATION_CONSENT_SHA256 = hashlib.sha256(EMULATION_CONSENT.encode('utf-8')).hexdigest()
NOT_PE = 'supports the following formats'
_VERSION = re.compile(r'^floss v?(\d+)\.(\d+)\.(\d+)(\S*)\s*$', re.MULTILINE)
_ONLY = re.compile(r'--only \{([a-z,]+)\}')


@dataclass(frozen=True)
class FlossConfig:
    executable: Path | None
    deobfuscate: bool = False
    consent_sha256: str | None = None   # must equal EMULATION_CONSENT_SHA256 when deobfuscate is set
    timeout: int | None = None
    accept_untested: bool = False       # explicit opt-in for a build that is not the pinned release (TA-6)

    def effective_timeout(self) -> int:
        return self.timeout or (DEOBFUSCATE_TIMEOUT if self.deobfuscate else DEFAULT_TIMEOUT)


def require_consent(config: FlossConfig) -> None:
    if config.deobfuscate and config.consent_sha256 != EMULATION_CONSENT_SHA256:
        raise ToolError('PT-TOOL-CONSENT', 'FLOSS deobfuscation runs an emulator and needs explicit consent '
                        '(--floss-deobfuscate after reading the consent text)')


def _manifest(config: FlossConfig, *, supported: bool, reason: str | None = None, path: str = '',
              sha: str | None = None, **kw) -> ToolManifest:
    return ToolManifest(engine=ENGINE, cli_path=path, executable_sha256=sha, license=LICENSES[ENGINE],
                        supported=supported, reason=reason, rules_source='embedded' if sha else 'none',
                        backend='vivisect-emulation' if (config.deobfuscate and sha) else None, **kw)


_CACHE: dict[tuple, ToolManifest] = {}
_CACHE_LOCK = threading.Lock()


def clear_probe_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def probe(config: FlossConfig, *, cancel: threading.Event | None = None, runner: Callable = run_process,
          environ: Mapping[str, str] | None = None, use_cache: bool = True) -> ToolManifest:
    if config.executable is None or not str(config.executable).strip():
        return _manifest(config, supported=False, reason='FLOSS is not configured (pass --floss or set '
                         'PATCHTRACE_FLOSS to the absolute path of the floss executable)')
    exe = process.regular_file(Path(config.executable))
    if exe is None:
        return _manifest(config, supported=False, path=str(config.executable),
                         reason='the configured FLOSS executable is missing, not absolute or not a regular file')
    try:
        info = exe.stat()
        key = (str(exe), info.st_mtime_ns, info.st_size, config.deobfuscate, config.accept_untested)
    except OSError:
        return _manifest(config, supported=False, path=str(exe), reason='the FLOSS executable cannot be read')
    if use_cache:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    report, cacheable = _probe(config, exe, cancel or threading.Event(), runner, environ)
    if use_cache and cacheable and not (cancel and cancel.is_set()):
        with _CACHE_LOCK:
            _CACHE[key] = report
    return report


def _probe(config: FlossConfig, exe: Path, cancel: threading.Event, runner: Callable,
           environ: Mapping[str, str] | None) -> tuple[ToolManifest, bool]:
    """(manifest, cacheable): a timeout, cancel or spawn failure is reported but never remembered (TA-10)."""
    try:
        sha = process.sha256_file(exe)
    except (OSError, ToolError):
        return _manifest(config, supported=False, path=str(exe),
                         reason='the FLOSS executable cannot be hashed'), False
    pin_status = 'pinned' if pins.is_pinned(ENGINE, sha) else 'unpinned'

    def unsupported(reason: str, cacheable: bool = True, **kw) -> tuple[ToolManifest, bool]:
        return _manifest(config, supported=False, path=str(exe), sha=sha, reason=reason,
                         pin_status=pin_status, **kw), cacheable
    version_run = process.run_version_probe(exe, ['--version'], cancel=cancel, runner=runner, environ=environ)
    help_run = process.run_version_probe(exe, ['-H'], cancel=cancel, runner=runner, environ=environ)
    transient = process.is_transient(version_run, help_run)
    for run, what in ((version_run, 'FLOSS --version'), (help_run, 'FLOSS -H')):
        if run.reason or run.spawn_error:
            return unsupported(process.describe_failure(run, what), cacheable=not transient)
    match = _VERSION.search(f'{version_run.stdout}\n{version_run.stderr}')
    if version_run.returncode != 0 or match is None:
        return unsupported(f'FLOSS did not report a version ({process.exit_text(version_run.returncode)})')
    version = '.'.join(match.groups()[:3])
    common = {'version': version, 'version_text': process.sanitize(match.group(0), 120),
              'untested_version': version not in TESTED_VERSIONS or pin_status != 'pinned'}
    if int(match.group(1)) != SUPPORTED_MAJOR:
        return unsupported(f'FLOSS {version} is not supported (the parser contract is FLOSS {SUPPORTED_MAJOR}.x)',
                           **common)
    if pin_status != 'pinned' and not config.accept_untested:
        return unsupported(f'this FLOSS build ({sha[:12]}) is not the pinned release (FLOSS 3.1.1); a master build '
                           'can report 3.1.1 and still change the output, so results are accepted only from the '
                           'pinned build unless you pass --floss-accept-untested', **common)
    text = help_run.stdout + '\n' + help_run.stderr
    if help_run.returncode != 0:
        return unsupported('FLOSS -H failed', **common)
    for option in REQUIRED_OPTIONS:
        if not re.search(rf'(?<![\w-]){re.escape(option)}(?![\w-])', text):
            return unsupported(f'this FLOSS build lacks the option {option}', **common)
    types = set(_ONLY.search(text).group(1).split(',')) if _ONLY.search(text) else set()
    if not set(DEOBFUSCATION_TYPES if config.deobfuscate else STATIC_TYPES) <= types:
        return unsupported('this FLOSS build cannot select the required string types', **common)
    capabilities = sorted({'json', 'format:pe', 'strings:static', *(['deobfuscation'] if types >= set(
        DEOBFUSCATION_TYPES) else [])})
    return _manifest(config, supported=True, path=str(exe), sha=sha, capabilities=tuple(capabilities),
                     pin_status=pin_status, **common), True


def string_types(config: FlossConfig) -> tuple[str, ...]:
    return DEOBFUSCATION_TYPES if config.deobfuscate else STATIC_TYPES


def options(config: FlossConfig) -> dict[str, str]:
    out = {'argv': 'floss/1', 'format': 'pe', 'types': ','.join(string_types(config)), 'min_length': 'default'}
    if config.deobfuscate:
        out['emulation_consent_sha256'] = EMULATION_CONSENT_SHA256
    return out


def build_argv(config: FlossConfig, executable: str, artifact: Path) -> list[str]:
    """T3. `--only` takes nargs='+', so `--` must separate the types from the sample path."""
    require_consent(config)
    return [executable, '-j', '-q', '--disable-progress', '--color', 'never', '-f', 'pe', '--only',
            *string_types(config), '--', str(artifact)]


def classify_exit(returncode: int, stdout: str, stderr: str) -> tuple[str, str, str]:
    line = process.first_error_line(stderr, stdout)
    if NOT_PE in stderr or NOT_PE in stdout:
        return 'unsupported', 'PT-TOOL-UNSUPPORTED', 'FLOSS deobfuscation supports PE files only'
    return 'failed', 'PT-TOOL-RUN', f'FLOSS failed ({process.exit_text(returncode)}): {line or "no message"}'


# ---- strict 3.x result models ----------------------------------------------------------------------------------

class _Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


Encoding = Literal['ASCII', 'UTF-16LE', 'UTF-8']
Number = int | float


class StaticString(_Model):
    string: str
    offset: int = Field(ge=0)
    encoding: Encoding


class StackString(_Model):
    function: int = Field(ge=0)
    string: str
    encoding: Encoding
    program_counter: int
    stack_pointer: int
    original_stack_pointer: int
    offset: int
    frame_offset: int


class DecodedString(_Model):
    address: int = Field(ge=0)
    address_type: Literal['STACK', 'GLOBAL', 'HEAP']
    string: str
    encoding: Encoding
    decoded_at: int = Field(ge=0)
    decoding_routine: int = Field(ge=0)


class Functions(_Model):
    discovered: int
    library: int
    analyzed_stack_strings: int
    analyzed_tight_strings: int
    analyzed_decoded_strings: int
    decoding_function_scores: dict[str, dict[str, Number]]


class Analysis(_Model):
    enable_static_strings: bool
    enable_stack_strings: bool
    enable_tight_strings: bool
    enable_decoded_strings: bool
    functions: Functions


class Metadata(_Model):
    file_path: str
    version: str
    imagebase: int = Field(ge=0)
    min_length: int
    runtime: dict[str, Number | str]
    language: str
    language_version: str
    language_selected: str


class Strings(_Model):
    stack_strings: list[StackString]
    tight_strings: list[StackString]
    decoded_strings: list[DecodedString]
    static_strings: list[StaticString]
    language_strings: list[StaticString]
    language_strings_missed: list[StaticString]


class ResultDocument(_Model):
    analysis: Analysis
    metadata: Metadata
    strings: Strings


@dataclass(frozen=True)
class ParseContext:
    run_id: str
    side: str
    artifact: process.ArtifactCopy
    cache_key: str
    config_digest: str
    pe: PeMap
    reader: object          # VerifiedArtifactReader of the private copy (offset verification)
    limits: ToolLimits
    deobfuscate: bool


def empty_set(ctx: ParseContext) -> ToolEvidenceSet:
    """FLOSS 3.1.1 prints nothing when the file holds no static string (`floss/main.py`): 'none found'."""
    return ToolEvidenceSet(run_id=ctx.run_id, engine=ENGINE, side=ctx.side, artifact_sha256=ctx.artifact.sha256,
                           cache_key=ctx.cache_key, config_digest=ctx.config_digest,
                           analysis={'empty_output': 'no static strings (FLOSS printed nothing)'},
                           counts={'strings': 0})


def parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    """Strict parse + normalisation of one FLOSS JSON document. A value the evidence contract refuses is
    `PT-TOOL-OUTPUT`, never a bare pydantic ValidationError (TA-1)."""
    try:
        return _parse(raw, ctx)
    except ValidationError:
        raise ToolError('PT-TOOL-OUTPUT', 'FLOSS output holds a value outside the evidence contract') from None


MAX_FILE_OFFSET = 2**40 - 1


def _parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    data = load_json_strict(raw, max_bytes=ctx.limits.stdout_bytes, max_depth=ctx.limits.json_depth)
    if not isinstance(data, dict) or set(data) != {'analysis', 'metadata', 'strings'}:
        raise ToolError('PT-TOOL-OUTPUT', 'FLOSS output is not a result document (wrong parser contract)')
    try:
        doc = ResultDocument.model_validate(data)
    except ValidationError as exc:
        where = '.'.join(str(p) for p in exc.errors()[0]['loc'])[:80] if exc.errors() else '?'
        raise ToolError('PT-TOOL-OUTPUT', f'FLOSS output violates the 3.x contract at {where}') from None
    if not re.match(rf'^v?{SUPPORTED_MAJOR}\.', doc.metadata.version):
        raise ToolError('PT-TOOL-OUTPUT', f'FLOSS output version {doc.metadata.version[:20]!r} is not 3.x')
    enabled = {'static': doc.analysis.enable_static_strings, 'stack': doc.analysis.enable_stack_strings,
               'tight': doc.analysis.enable_tight_strings, 'decoded': doc.analysis.enable_decoded_strings}
    requested = set(DEOBFUSCATION_TYPES if ctx.deobfuscate else STATIC_TYPES)
    active = {name for name, on in enabled.items() if on}
    if active - requested:
        raise ToolError('PT-TOOL-OUTPUT', 'FLOSS reports string types that were not requested (emulation off)')
    if requested - active:  # TA-7: a stage that did not run must not read as "found nothing"
        raise ToolError('PT-TOOL-OUTPUT', 'FLOSS did not run every requested string type '
                        f'({", ".join(sorted(requested - active))} disabled)')
    anomalies: list[str] = []
    out: list[StringEvidence] = []
    total = 0
    base = doc.metadata.imagebase
    if base > MAX_ADDRESS:
        raise ToolError('PT-TOOL-ADDRESS', 'FLOSS reported an image base outside 64 bits')
    if base and base != ctx.pe.image_base:  # TA-12: the tool's base is not trusted over the file's own header
        anomalies.append(f'base-differs:0x{base:x}')

    def add(value: str, encoding: str, kind: str, link: EvidenceLink, confidence: str) -> None:
        nonlocal total
        total += 1
        if len(out) >= ctx.limits.max_strings:
            return
        out.append(StringEvidence(
            value_hash=hashlib.sha256(value.encode('utf-8', 'surrogatepass')).hexdigest(), length=len(value),
            display_value=display_text(value), secret_kind=secret_kind(value), encoding=encoding, type=kind,
            source_location=link, confidence_class=confidence, extraction_method=f'floss-{kind}',
            source_run_id=ctx.run_id))

    def static(items: list[StaticString], kind: str, label: str) -> None:
        for index, item in enumerate(items):
            fragment = f'strings.{label}[{index}]'
            if item.offset > MAX_FILE_OFFSET:  # TA-1: cannot be a file offset; keep the string, drop the location
                anomalies.append('offset-out-of-range')
                add(item.string, item.encoding, kind, EvidenceLink(
                    tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256, source_fragment=fragment),
                    'unverified-location')
                continue
            rva, problem = ctx.pe.offset_to_rva(item.offset)
            if problem:
                anomalies.append(problem)
            verified = bytes_match(ctx.reader, item.offset, item.string, item.encoding)
            if not verified:
                anomalies.append(f'string-bytes-differ:0x{item.offset:x}')
            add(item.string, item.encoding, kind, EvidenceLink(
                tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256, rva=rva, file_offset=item.offset,
                source_fragment=fragment), 'verified-bytes' if verified else 'unverified-location')

    def function_link(va: int, attribution: str, fragment: str) -> EvidenceLink:
        if base <= 0:
            anomalies.append('base-ambiguous')
            return EvidenceLink(tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256,
                                source_fragment=fragment)
        if base != ctx.pe.image_base:
            return EvidenceLink(tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256,
                                source_fragment=fragment)
        rva, problem = ctx.pe.va_to_rva(va, base)
        if problem or rva is None:
            anomalies.append(problem or 'address-out-of-image')
            return EvidenceLink(tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256,
                                source_fragment=fragment)
        return EvidenceLink(tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256,
                            function_id=f'rva:0x{rva:x}', rva=rva, attribution=attribution, source_fragment=fragment)

    static(doc.strings.static_strings, 'static', 'static_strings')
    static(doc.strings.language_strings, 'language', 'language_strings')
    for label, items, kind in (('stack_strings', doc.strings.stack_strings, 'stack'),
                               ('tight_strings', doc.strings.tight_strings, 'tight')):
        for index, item in enumerate(items):
            add(item.string, item.encoding, kind, function_link(item.function, 'stack-frame',
                                                                f'strings.{label}[{index}]'), 'tool-reported')
    for index, item in enumerate(doc.strings.decoded_strings):
        fragment = f'strings.decoded_strings[{index}] {item.address_type.lower()}@0x{item.address:x}'
        add(item.string, item.encoding, 'decoded', function_link(item.decoding_routine, 'decoding-routine',
                                                                 fragment[:200]), 'tool-reported')
    out.sort(key=lambda s: (s.type, s.source_location.file_offset if s.source_location.file_offset is not None
                            else -1, s.source_location.rva if s.source_location.rva is not None else -1,
                            s.value_hash))
    counted = list(dict.fromkeys(anomalies))
    unverified = sum(1 for a in anomalies if a.startswith('string-bytes-differ'))
    if len(counted) > 64:
        counted = counted[:63] + [f'more-anomalies:{len(counted) - 63}']
    return ToolEvidenceSet(
        run_id=ctx.run_id, engine=ENGINE, side=ctx.side, artifact_sha256=ctx.artifact.sha256, cache_key=ctx.cache_key,
        config_digest=ctx.config_digest, image_base=base or None,
        analysis={'version': doc.metadata.version[:32], 'language': doc.metadata.language[:32],
                  'min_length': doc.metadata.min_length, 'types': ','.join(n for n, on in enabled.items() if on),
                  'functions_discovered': doc.analysis.functions.discovered},
        strings=tuple(out), truncated=total > len(out),
        counts={'strings': len(out), 'strings_total': total, 'unverified_offsets': unverified},
        anomalies=tuple(counted))
