"""capa adapter (SPEC-29 tools T1, T3, T5): version/option probe, fixed argv, strict 9.x result-document parser.

Verified against capa 9.4.0 (`capa/main.py`, `capa/loader.py`, `capa/render/result_document.py`,
`capa/features/freeze/__init__.py` of the pinned release, and real runs on SYNTHETIC PE pairs). capa analyses the
file statically (vivisect by default, Ghidra via PyGhidra when configured); the target is never executed.
Whole-file matches (`no address`) are never confused with function matches: only function scope and basic-block
scope (through capa's own layout) name a function.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ...jobs import run_process
from . import pins, process
from .common import (
    LICENSES,
    MAX_ADDRESS,
    MAX_COVERAGE,
    MAX_FEATURES,
    MAX_LABELS,
    CapabilityEvidence,
    EvidenceLink,
    FeatureRef,
    FunctionCoverage,
    TaxonomyLabel,
    ToolError,
    ToolEvidenceSet,
    ToolLimits,
    ToolManifest,
    display_text,
    load_json_strict,
)
from .normalize import PeMap, check_binding

ENGINE = 'capa'
SUPPORTED_MAJOR = 9
TESTED_VERSIONS = frozenset({'9.4.0'})
DEFAULT_TIMEOUT = 1800
REQUIRED_OPTIONS = ('-j', '--json', '-q', '--quiet', '--color', '-f', '--format', '-b', '--backend', '--os', '-r',
                    '--rules', '-s', '--signatures')
EXIT_UNSUPPORTED = {16: 'unsupported file type', 17: 'unsupported architecture', 18: 'unsupported operating system',
                    20: 'unsupported Ghidra version', 24: 'unsupported Ghidra execution mode'}
EXIT_INPUT = {10: 'the rule set is missing', 11: 'the input file is missing', 12: 'the rule set is invalid',
              13: 'the input file is corrupt', 15: 'the signature files are invalid'}
MIN_GHIDRA = (12, 0)
MEMORY_DEFAULT = 8 * 1024 ** 3
MIN_MEMORY_LIMIT = 256 * 1024 ** 2
MAX_RULE_SOURCE = 256 * 1024
_VERSION = re.compile(r'^capa (\d+)\.(\d+)\.(\d+)\s*$', re.MULTILINE)
_BACKENDS = re.compile(r'-b \{([a-z0-9,]+)\}')
_GHIDRA_VERSION = re.compile(r'^application\.version\s*=\s*([A-Za-z0-9_.-]{1,32})\s*$', re.MULTILINE)


@dataclass(frozen=True)
class CapaConfig:
    executable: Path | None
    backend: Literal['vivisect', 'ghidra'] = 'vivisect'
    rules_dir: Path | None = None
    sigs_dir: Path | None = None
    ghidra_dir: Path | None = None
    java_home: Path | None = None
    timeout: int = DEFAULT_TIMEOUT
    accept_untested: bool = False   # explicit opt-in for a build that is not the pinned release (TA-6)
    memory_limit_bytes: int | None = None   # None: 8 GiB; 0: no cap (RLIMIT_AS counts virtual memory)
    cache_dir: Path | None = None   # raw-first output cache (CAP-4); None: no cache. Never capa's own scratch HOME

    def effective_memory_limit(self) -> int | None:
        limit = self.memory_limit_bytes
        if limit is None:
            return MEMORY_DEFAULT
        if limit == 0:
            return None
        if limit < MIN_MEMORY_LIMIT:
            raise ToolError('PT-TOOL-INPUT', 'the capa memory limit must be 0 (off) or at least 256 MiB')
        return limit


def _manifest(config: CapaConfig, *, supported: bool, reason: str | None = None, path: str = '',
              sha: str | None = None, **kw) -> ToolManifest:
    rules = ({'rules_source': 'directory', 'rules_sha256': kw.pop('rules_sha256')} if kw.get('rules_sha256')
             else {'rules_source': 'embedded' if sha else 'none'})
    kw.pop('rules_sha256', None)
    return ToolManifest(engine=ENGINE, cli_path=path, executable_sha256=sha, license=LICENSES[ENGINE],
                        supported=supported, reason=reason, backend=config.backend if sha else None, **rules, **kw)


def ghidra_extra(config: CapaConfig) -> dict[str, str]:
    if config.backend != 'ghidra':
        return {}
    return {'GHIDRA_INSTALL_DIR': str(config.ghidra_dir), 'JAVA_HOME': str(config.java_home)}


def _ghidra_version(config: CapaConfig) -> str | None:
    if config.ghidra_dir is None or config.java_home is None:
        return None
    props = config.ghidra_dir / 'Ghidra' / 'application.properties'
    java = config.java_home / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
    if not (config.ghidra_dir.is_absolute() and config.java_home.is_absolute() and props.is_file()
            and java.is_file()):
        return None
    try:
        text = props.read_text(encoding='utf-8', errors='replace')[:65536]
    except OSError:
        return None
    match = _GHIDRA_VERSION.search(text)
    return match.group(1) if match else None


def _ghidra_too_old(version: str) -> bool:
    """capa's Ghidra backend exits 20 on Ghidra before 12.0; refuse at probe time. An unreadable version is old."""
    parts = re.match(r'^(\d+)\.(\d+)', version)
    return parts is None or (int(parts.group(1)), int(parts.group(2))) < MIN_GHIDRA


_CACHE: dict[tuple, ToolManifest] = {}
_CACHE_LOCK = threading.Lock()


def clear_probe_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def probe(config: CapaConfig, *, cancel: threading.Event | None = None, runner: Callable = run_process,
          environ: Mapping[str, str] | None = None, use_cache: bool = True) -> ToolManifest:
    """T3: version, every option PatchTrace passes, backend choice and the rule/signature digests. Never raises."""
    if config.executable is None or not str(config.executable).strip():
        return _manifest(config, supported=False, reason='capa is not configured (pass --capa or set '
                         'PATCHTRACE_CAPA to the absolute path of the capa executable)')
    exe = process.regular_file(Path(config.executable))
    if exe is None:
        return _manifest(config, supported=False, path=str(config.executable),
                         reason='the configured capa executable is missing, not absolute or not a regular file')
    try:
        info = exe.stat()
        key = (str(exe), info.st_mtime_ns, info.st_size, config)
    except OSError:
        return _manifest(config, supported=False, path=str(exe), reason='the capa executable cannot be read')
    if use_cache:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    report, cacheable = _probe(config, exe, cancel or threading.Event(), runner, environ)
    if use_cache and cacheable and not (cancel and cancel.is_set()):
        with _CACHE_LOCK:
            _CACHE[key] = report
    return report


def _probe(config: CapaConfig, exe: Path, cancel: threading.Event, runner: Callable,
           environ: Mapping[str, str] | None) -> tuple[ToolManifest, bool]:
    """(manifest, cacheable): a timeout, cancel or spawn failure is reported but never remembered (TA-10)."""
    try:
        sha = process.sha256_file(exe)
    except (OSError, ToolError):
        return _manifest(config, supported=False, path=str(exe), reason='the capa executable cannot be hashed'), False

    def unsupported(reason: str, cacheable: bool = True, **kw) -> tuple[ToolManifest, bool]:
        return _manifest(config, supported=False, path=str(exe), sha=sha, reason=reason,
                         pin_status=pin_status, **kw), cacheable
    pin_status = 'pinned' if pins.is_pinned(ENGINE, sha) else 'unpinned'
    if config.backend == 'ghidra' and _ghidra_version(config) is None:
        return unsupported('the Ghidra backend needs --ghidra-dir (Ghidra/application.properties) and --java-home '
                           '(bin/java)')
    ghidra_version = _ghidra_version(config) if config.backend == 'ghidra' else None
    if ghidra_version is not None and _ghidra_too_old(ghidra_version):
        return unsupported(f'the Ghidra backend needs Ghidra {MIN_GHIDRA[0]}.{MIN_GHIDRA[1]} or newer '
                           f'(found {process.sanitize(ghidra_version, 32)})')
    version_run = process.run_version_probe(exe, ['--version'], cancel=cancel, runner=runner, environ=environ)
    help_run = process.run_version_probe(exe, ['--help'], cancel=cancel, runner=runner, environ=environ)
    transient = process.is_transient(version_run, help_run)
    for run, what in ((version_run, 'capa --version'), (help_run, 'capa --help')):
        if run.reason or run.spawn_error:
            return unsupported(process.describe_failure(run, what), cacheable=not transient)
    match = _VERSION.search(f'{version_run.stdout}\n{version_run.stderr}')
    if version_run.returncode != 0 or match is None:
        return unsupported(f'capa did not report a version ({process.exit_text(version_run.returncode)})')
    version = '.'.join(match.groups())
    common = {'version': version, 'version_text': process.sanitize(match.group(0), 120),
              'untested_version': version not in TESTED_VERSIONS or pin_status != 'pinned'}
    if int(match.group(1)) != SUPPORTED_MAJOR:
        return unsupported(f'capa {version} is not supported (the parser contract is capa {SUPPORTED_MAJOR}.x)',
                           **common)
    if pin_status != 'pinned' and not config.accept_untested:
        return unsupported(f'this capa build ({sha[:12]}) is not the pinned release (capa 9.4.0); results are '
                           'accepted only from the pinned build unless you pass --capa-accept-untested', **common)
    text = help_run.stdout + '\n' + help_run.stderr
    if help_run.returncode != 0:
        return unsupported('capa --help failed', **common)
    for option in REQUIRED_OPTIONS:
        if not re.search(rf'(?<![\w-]){re.escape(option)}(?![\w-])', text):
            return unsupported(f'this capa build lacks the option {option}', **common)
    backends = set(_BACKENDS.search(text).group(1).split(',')) if _BACKENDS.search(text) else set()
    if config.backend not in backends:
        return unsupported(f'this capa build has no {config.backend} backend', **common)
    capabilities = sorted({'json', 'format:pe', *(f'backend:{b}' for b in backends & {'vivisect', 'ghidra'})})
    extra: dict = {}
    try:
        if config.rules_dir is not None:
            extra['rules_sha256'] = process.tree_digest(Path(config.rules_dir))
            capabilities.append('rules:directory')
        if config.sigs_dir is not None:
            extra['signatures_sha256'] = process.tree_digest(Path(config.sigs_dir))
            capabilities.append('signatures:directory')
    except (OSError, ToolError) as exc:
        return unsupported(f'rule or signature directory rejected: {getattr(exc, "message", type(exc).__name__)}',
                           **common)
    if config.backend == 'ghidra':
        extra['backend_version'] = ghidra_version
    return _manifest(config, supported=True, path=str(exe), sha=sha, capabilities=tuple(sorted(capabilities)),
                     pin_status=pin_status, **common, **extra), True


def options(config: CapaConfig) -> dict[str, str]:
    """What determines the output besides the tool identity (cache key, T7)."""
    return {'argv': 'capa/1', 'format': 'pe', 'os': 'windows', 'backend': config.backend}


def prepare(config: CapaConfig, scratch: Path, manifest: ToolManifest | None = None) -> dict[str, str]:
    """Copy explicit rule/signature packs into the scratch; returns the digests of the copies. With the probed
    `manifest`, a copy that differs from the probed digest (a rule file changed since the probe) is
    `PT-TOOL-STALE` (TA-6): evidence is never stamped with a rules identity the tool did not read."""
    digests = {}
    if config.rules_dir is not None:
        digests['rules'] = process.copy_tree(Path(config.rules_dir), scratch / 'rules')
    if config.sigs_dir is not None:
        digests['signatures'] = process.copy_tree(Path(config.sigs_dir), scratch / 'sigs')
    if manifest is not None:
        for key, probed in (('rules', manifest.rules_sha256), ('signatures', manifest.signatures_sha256)):
            if key in digests and digests[key] != probed:
                raise ToolError('PT-TOOL-STALE', f'the capa {key} directory changed since it was probed')
    return digests


def build_argv(config: CapaConfig, executable: str, scratch: Path, artifact: Path) -> list[str]:
    argv = [executable, '-q', '--color', 'never', '-j', '-f', 'pe', '-b', config.backend, '--os', 'windows']
    if config.rules_dir is not None:
        argv += ['-r', str(scratch / 'rules')]
    if config.sigs_dir is not None:
        argv += ['-s', str(scratch / 'sigs')]
    return [*argv, str(artifact)]


def classify_exit(returncode: int, stdout: str, stderr: str, *, memory_limit_bytes: int | None = None,
                  peak_memory_bytes: int | None = None) -> tuple[str, str, str]:
    """(status, error code, message) for a non-zero exit (T4)."""
    line = process.first_error_line(stderr, stdout)
    if returncode in EXIT_UNSUPPORTED:
        return 'unsupported', 'PT-TOOL-UNSUPPORTED', f'capa: {EXIT_UNSUPPORTED[returncode]} ({line or "no detail"})'
    if process.memory_exhausted(stderr, returncode, peak_memory_bytes, memory_limit_bytes):
        return 'failed', 'PT-TOOL-LIMIT', 'capa stopped at the memory limit (memory)'
    if returncode in EXIT_INPUT:
        return 'failed', 'PT-TOOL-INPUT', f'capa: {EXIT_INPUT[returncode]} ({line or "no detail"})'
    return 'failed', 'PT-TOOL-RUN', f'capa failed ({process.exit_text(returncode)}): {line or "no message"}'


# ---- strict result-document models (capa 9.x) ----------------------------------------------------------------

class _Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class _Open(BaseModel):  # bounded upstream metadata whose optional keys may grow within the 9.x contract
    model_config = ConfigDict(extra='ignore', strict=True, frozen=True)


AddressType = Literal['absolute', 'relative', 'file', 'dn token', 'dn token offset', 'process', 'thread', 'call',
                      'no address']


class Address(_Model):
    type: AddressType
    value: int | list[int] | None = None


class Sample(_Model):
    md5: str
    sha1: str
    sha256: str
    path: str


class BasicBlockLayout(_Model):
    address: Address


class FunctionLayout(_Model):
    address: Address
    matched_basic_blocks: list[BasicBlockLayout]


class Layout(_Model):
    functions: list[FunctionLayout]


class FunctionCount(_Model):
    address: Address
    count: int


class FeatureCounts(_Model):
    file: int
    functions: list[FunctionCount]


class LibraryFunction(_Model):
    address: Address
    name: str


class Analysis(_Model):
    format: str
    arch: str
    os: str
    extractor: str
    rules: list[str]
    base_address: Address
    layout: Layout
    feature_counts: FeatureCounts
    library_functions: list[LibraryFunction]


class Meta(_Model):
    timestamp: str
    version: str
    argv: list[str] | None = None
    sample: Sample
    flavor: Literal['static']
    analysis: Analysis


class Scopes(_Model):
    static: str | None = None
    dynamic: str | None = None


class Spec(_Open):
    id: str = Field(default='', max_length=64)
    tactic: str = Field(default='', max_length=512)      # ATT&CK
    technique: str = Field(default='', max_length=512)
    subtechnique: str = Field(default='', max_length=512)
    objective: str = Field(default='', max_length=512)   # MBC
    behavior: str = Field(default='', max_length=512)
    method: str = Field(default='', max_length=512)


class RuleMeta(_Open):
    name: str = Field(min_length=1, max_length=1024)
    namespace: str | None = Field(default=None, max_length=1024)
    scopes: Scopes
    attack: list[Spec] = Field(default_factory=list, max_length=256)
    mbc: list[Spec] = Field(default_factory=list, max_length=256)
    lib: bool = False
    is_subscope_rule: bool = False


class Node(_Model):
    type: Literal['statement', 'feature']
    statement: dict | None = None
    feature: dict | None = None


class Match(_Model):
    success: bool
    node: Node
    children: list[Match]
    locations: list[Address]
    captures: dict[str, list[Address]]


class RuleMatches(_Model):
    meta: RuleMeta
    source: str
    matches: list[tuple[Address, Match]]

    @field_validator('matches', mode='before')
    @classmethod
    def _pairs(cls, value):
        if isinstance(value, list):
            return [tuple(item) if isinstance(item, list) and len(item) == 2 else item for item in value]
        return value


class ResultDocument(_Model):
    meta: Meta
    rules: dict[str, RuleMatches]


@dataclass(frozen=True)
class ParseContext:
    run_id: str
    side: str
    artifact: process.ArtifactCopy
    cache_key: str
    config_digest: str
    pe: PeMap
    limits: ToolLimits


def _rva(address: Address, base: int, pe: PeMap, anomalies: list[str]) -> int | None:
    if address.type == 'no address':
        return None
    if not isinstance(address.value, int):
        anomalies.append(f'address-type:{address.type}')
        return None
    if not 0 <= address.value <= MAX_ADDRESS:
        anomalies.append('address-out-of-range')
        return None
    if address.type == 'absolute':
        rva, problem = pe.va_to_rva(address.value, base)
    elif address.type == 'relative':
        rva, problem = (address.value, None) if pe.in_image(address.value) else (None, 'address-out-of-image')
    elif address.type == 'file':
        rva, problem = pe.offset_to_rva(address.value)
    else:
        rva, problem = None, f'address-type:{address.type}'
    if problem:
        anomalies.append(problem)
    return rva


def _feature_rvas(match: Match, base: int, pe: PeMap, cap: int) -> tuple[tuple[int, ...], int]:
    found: set[int] = set()
    total = 0
    stack = [match]
    while stack:
        node = stack.pop()
        if node.success and node.node.type == 'feature':
            for location in node.locations:
                total += 1
                if location.type == 'absolute' and isinstance(location.value, int):
                    rva, problem = pe.va_to_rva(location.value, base)
                    if problem is None and rva is not None:
                        found.add(rva)
        stack.extend(node.children)
    return tuple(sorted(found)[:cap]), total


_FEATURE_KINDS = {'api', 'number', 'string', 'substring', 'regex', 'bytes', 'mnemonic', 'offset', 'characteristic',
                  'section', 'export', 'import', 'function-name', 'class', 'namespace', 'property', 'com', 'match'}
_HEX_KINDS = frozenset({'number', 'offset', 'operand'})


def _feature_ref(feature: dict, rva: int | None) -> FeatureRef | None:
    """A leaf feature as a short text reference; global (os, arch, format) and unknown kinds give None."""
    kind = feature.get('type')
    if not isinstance(kind, str):
        return None
    ref_kind = 'operand' if kind.startswith('operand') else kind
    if ref_kind not in _FEATURE_KINDS and ref_kind != 'operand':
        return None
    value = feature.get(kind, feature.get(kind.replace(' ', '_')))
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        text = f'0x{value:x}' if ref_kind in _HEX_KINDS and value >= 0 else str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, sort_keys=True, separators=(',', ':'))[:240]
    return FeatureRef(kind=ref_kind, value=display_text(text, 120), rva=rva)


def _features(match: Match, base: int, pe: PeMap) -> tuple[FeatureRef, ...]:
    """Successful leaf features of a matched rule (T2): sorted, one per (kind, value) with its lowest location."""
    found: dict[tuple[str, str], int | None] = {}
    stack = [match]
    while stack:
        node = stack.pop()
        if not node.success:
            continue
        if node.node.type == 'feature' and node.node.feature is not None:
            rvas = [rva for rva in (pe.va_to_rva(a.value, base)[0] for a in node.locations
                                    if a.type == 'absolute' and isinstance(a.value, int)) if rva is not None]
            ref = _feature_ref(node.node.feature, min(rvas) if rvas else None)
            if ref is not None:
                key = (ref.kind, ref.value)
                known = found.get(key)
                found[key] = ref.rva if known is None else (known if ref.rva is None else min(known, ref.rva))
        stack.extend(node.children)
    refs = sorted(found.items(), key=lambda item: (item[0], -1 if item[1] is None else item[1]))
    return tuple(FeatureRef(kind=kind, value=value, rva=rva) for (kind, value), rva in refs[:MAX_FEATURES])


def _labels(rule: RuleMeta) -> tuple[TaxonomyLabel, ...]:
    """ATT&CK and MBC labels as capa emits them (grouping only, never ordering or counting)."""
    def name(*parts: str) -> str:
        return '::'.join(part for part in parts if part)
    labels = {TaxonomyLabel(scheme='attack', group=display_text(s.tactic, 80), ident=display_text(s.id, 32),
                            name=display_text(name(s.technique, s.subtechnique), 120)) for s in rule.attack if s.id}
    labels |= {TaxonomyLabel(scheme='mbc', group=display_text(s.objective, 80), ident=display_text(s.id, 32),
                             name=display_text(name(s.behavior, s.method), 120)) for s in rule.mbc if s.id}
    return tuple(sorted(labels, key=lambda label: (label.scheme, label.group, label.name, label.ident)))[:MAX_LABELS]


def _coverage(analysis: Analysis, base: int, pe: PeMap, anomalies: list[str]) -> FunctionCoverage:
    """Function starts capa evaluated and those it skipped as library code (everything else is unknown)."""
    def starts(addresses: list[Address]) -> tuple[tuple[int, ...], bool]:
        rvas = sorted({rva for rva in (_rva(a, base, pe, anomalies) for a in addresses) if rva is not None})
        return tuple(rvas[:MAX_COVERAGE]), len(rvas) > MAX_COVERAGE
    evaluated, cut_evaluated = starts([item.address for item in analysis.feature_counts.functions])
    library, cut_library = starts([item.address for item in analysis.library_functions])
    return FunctionCoverage(evaluated=evaluated, library=library, truncated=cut_evaluated or cut_library)


def _rule_id(name: str, anomalies: list[str]) -> str:
    """Rule names longer than the record allows get a stable hash suffix so distinct rules never collide (TA-11)."""
    if len(name) <= 256:
        return name
    anomalies.append('rule-id-shortened')
    return name[:239] + '#' + hashlib.sha256(name.encode('utf-8', 'surrogatepass')).hexdigest()[:16]


def parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    """Strict parse + normalisation of one capa JSON document (T5). Raises ToolError on contract violations; a
    record the contract refuses (out-of-range values and the like) is `PT-TOOL-OUTPUT`, never a bare
    pydantic ValidationError (TA-1)."""
    try:
        return _parse(raw, ctx)
    except ValidationError:
        raise ToolError('PT-TOOL-OUTPUT', 'capa output holds a value outside the evidence contract') from None


def _parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    data = load_json_strict(raw, max_bytes=ctx.limits.stdout_bytes, max_depth=ctx.limits.json_depth)
    if not isinstance(data, dict) or set(data) != {'meta', 'rules'}:
        raise ToolError('PT-TOOL-OUTPUT', 'capa output is not a result document (wrong parser contract)')
    try:
        doc = ResultDocument.model_validate(data)
    except ValidationError as exc:
        where = '.'.join(str(p) for p in exc.errors()[0]['loc'])[:80] if exc.errors() else '?'
        raise ToolError('PT-TOOL-OUTPUT', f'capa output violates the 9.x result-document contract at {where}') \
            from None
    if not re.match(rf'^{SUPPORTED_MAJOR}\.\d+', doc.meta.version):
        raise ToolError('PT-TOOL-OUTPUT', f'capa output version {doc.meta.version[:20]!r} is not {SUPPORTED_MAJOR}.x')
    check_binding({'sha256': doc.meta.sample.sha256, 'md5': doc.meta.sample.md5, 'sha1': doc.meta.sample.sha1},
                  {'sha256': ctx.artifact.sha256, 'md5': ctx.artifact.md5, 'sha1': ctx.artifact.sha1})
    analysis = doc.meta.analysis
    if analysis.base_address.type != 'absolute' or not isinstance(analysis.base_address.value, int):
        raise ToolError('PT-TOOL-OUTPUT', 'capa reported no absolute base address')
    base = analysis.base_address.value
    if not 0 <= base <= MAX_ADDRESS:
        raise ToolError('PT-TOOL-ADDRESS', 'capa reported a base address outside 64 bits')
    anomalies: list[str] = []
    if base != ctx.pe.image_base:
        anomalies.append(f'base-differs:0x{base:x}')
    block_owner: dict[int, int] = {}
    for function in analysis.layout.functions:
        if function.address.type == 'absolute' and isinstance(function.address.value, int):
            for block in function.matched_basic_blocks:
                if isinstance(block.address.value, int):
                    block_owner[block.address.value] = function.address.value
    # Choose which matches are kept BEFORE building records: sorted by (rule, scope, address, document index), so
    # a truncated set is a stable prefix that does not depend on the tool's dictionary order (TA-3).
    candidates = []
    total = 0
    for name, rule in doc.rules.items():
        if rule.meta.is_subscope_rule:
            continue
        scope = rule.meta.scopes.static
        if scope not in ('file', 'function', 'basic block', 'instruction'):
            anomalies.append('scope-not-static')
            continue
        if len(rule.source) > MAX_RULE_SOURCE:
            anomalies.append('rule-source-too-large')
        for index, (address, match) in enumerate(rule.matches):
            total += 1
            key_address = address.value if isinstance(address.value, int) else -1
            rank = 0 if scope in ('function', 'basic block') else 1   # a cut keeps localized scopes first
            candidates.append((rank, name, scope, key_address, index, rule, address, match))
    candidates.sort(key=lambda item: item[:5])
    evidence: list[CapabilityEvidence] = []
    rule_ids: dict[str, str] = {}
    rule_labels: dict[str, tuple[TaxonomyLabel, ...]] = {}
    for _rank, name, scope, _key, index, rule, address, match in candidates[:ctx.limits.max_rule_matches]:
        rule_sha = hashlib.sha256(rule.source.encode('utf-8')).hexdigest()
        namespace = rule.meta.namespace
        kind = 'library' if rule.meta.lib else (
            'limitation' if namespace and namespace.startswith('internal/limitation') else 'capability')
        if name not in rule_ids:
            rule_ids[name] = _rule_id(name, anomalies)
            rule_labels[name] = _labels(rule.meta)
        rva = _rva(address, base, ctx.pe, anomalies)
        function_id, attribution = None, 'none'
        if rva is not None and scope == 'function':
            function_id, attribution = f'rva:0x{rva:x}', 'function-start'
        elif rva is not None and scope == 'basic block' and isinstance(address.value, int):
            owner = block_owner.get(address.value)
            owner_rva = ctx.pe.va_to_rva(owner, base)[0] if owner is not None else None
            if owner_rva is not None:
                function_id, attribution = f'rva:0x{owner_rva:x}', 'basic-block-in-function'
        features, feature_total = _feature_rvas(match, base, ctx.pe, ctx.limits.max_feature_locations)
        link = EvidenceLink(tool_run_id=ctx.run_id, artifact_sha256=ctx.artifact.sha256, function_id=function_id,
                            rva=rva, attribution=attribution,
                            source_fragment=f'rules[{json.dumps(name)[:120]}].matches[{index}]')
        evidence.append(CapabilityEvidence(
            rule_id=rule_ids[name], rule_sha256=rule_sha, namespace=namespace[:256] if namespace else None,
            scope=scope, address_space=address.type, address=address.value if isinstance(address.value, int)
            and 0 <= address.value <= MAX_ADDRESS else None, location=link, kind=kind, source_run_id=ctx.run_id,
            attack=tuple(s.id[:32] for s in rule.meta.attack if s.id)[:32],
            mbc=tuple(s.id[:32] for s in rule.meta.mbc if s.id)[:32],
            feature_rvas=features, feature_count=feature_total, features=_features(match, base, ctx.pe),
            labels=rule_labels[name]))
    evidence.sort(key=lambda e: (e.rule_id, e.scope, -1 if e.address is None else e.address))
    coverage = _coverage(analysis, base, ctx.pe, anomalies)
    unique = list(dict.fromkeys(anomalies))[:64]
    return ToolEvidenceSet(
        run_id=ctx.run_id, engine=ENGINE, side=ctx.side, artifact_sha256=ctx.artifact.sha256,
        cache_key=ctx.cache_key, config_digest=ctx.config_digest, image_base=base,
        analysis={'format': analysis.format[:32], 'arch': analysis.arch[:32], 'os': analysis.os[:32],
                  'extractor': analysis.extractor[:64], 'functions_recovered': len(analysis.feature_counts.functions),
                  'library_functions': len(analysis.library_functions), 'version': doc.meta.version[:32]},
        capabilities=tuple(evidence), truncated=total > len(evidence),
        counts={'capabilities': len(evidence), 'rule_matches_total': total, 'rules': len(doc.rules)},
        anomalies=tuple(unique), coverage=coverage)


def reparse(raw: bytes, expected_stdout_digest: str | None, ctx: ParseContext) -> ToolEvidenceSet:
    """In-memory re-parse of a stored raw sidecar with the current parser (rows stored before coverage existed).
    The bytes must hash to the run's recorded stdout digest; otherwise they are not what the run produced."""
    if expected_stdout_digest is None or hashlib.sha256(raw).hexdigest() != expected_stdout_digest:
        raise ToolError('PT-TOOL-STORE', 'the stored capa output does not match its recorded digest')
    return parse(raw, ctx)
