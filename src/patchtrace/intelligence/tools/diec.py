"""Detect It Easy console (`diec`) adapter, quality gate only (SPEC-29 tools T1, T3, T5, T6.4).

Verified against diec 3.21 (`--help`, `--version`, JSON output of real runs on SYNTHETIC PE pairs). The spec warns
that DiE's GUI and CLI have differed, so results are accepted only from the tested version with a known signature
database digest unless the caller explicitly accepts an untested combination. The database is copied into the
scratch (`-D`), extra and custom databases are empty folders (`-E`, `-C`) so user-writable signature folders cannot
change the result. Heuristic detections (`type` prefixed `~`, string prefixed `(Heur)`) are weak and labelled;
`Unknown` is unknown. DiE output is environment evidence about toolchain and packing, never positive evidence for a
security mechanism, and no false-lead reduction is claimed (value gate unvalidated).
"""
from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from ...jobs import run_process
from . import pins, process
from .common import (
    LICENSES,
    EnvironmentEvidence,
    ToolError,
    ToolEvidenceSet,
    ToolLimits,
    ToolManifest,
    load_json_strict,
)

ENGINE = 'diec'
TESTED_VERSIONS = frozenset({'3.21'})
# tree/1 digests (process.tree_digest) of the 3.21 release databases: Linux .deb (22.04 and 24.04 builds are
# byte-identical) and the Windows portable zip (the same signatures with CRLF line endings). Measured 2026-10-14.
KNOWN_DATABASES = {'301b24a78ffb8491c377bd8d6a08a24d9faf6374f29fb072ea528596d2bc2b86': '3.21 linux deb',
                   'a862337efa9558e1c52608fdbd8c25b1537a2a11d62a38acbb9c6b9bcb39adda': '3.21 windows portable'}
DEFAULT_TIMEOUT = 120
REQUIRED_OPTIONS = ('-j', '--json', '-D', '--database', '-E', '--extradatabase', '-C', '--customdatabase', '-d',
                    '--deepscan', '-u', '--heuristicscan')
_VERSION = re.compile(r'^die (\d+)\.(\d+)\s*$', re.MULTILINE)
CATEGORIES = {'compiler', 'linker', 'tool', 'packer', 'protector', 'cryptor', 'installer', 'sfx', 'library',
              'format', 'overlay'}


@dataclass(frozen=True)
class DiecConfig:
    executable: Path | None
    database: Path | None = None
    library_path: Path | None = None
    heuristic: bool = False
    accept_untested: bool = False
    timeout: int = DEFAULT_TIMEOUT


def default_database(executable: Path) -> Path | None:
    """`<dir>/db` (Windows portable) or `<prefix>/lib/die/db` next to `<prefix>/bin/diec` (Linux package)."""
    for candidate in (executable.parent / 'db', executable.parent.parent / 'lib' / 'die' / 'db'):
        if candidate.is_dir() and not candidate.is_symlink():
            return candidate
    return None


def extra_env(config: DiecConfig) -> dict[str, str]:
    if config.library_path is None or os.name == 'nt':
        return {}
    return {'LD_LIBRARY_PATH': str(config.library_path)}


def _manifest(config: DiecConfig, *, supported: bool, reason: str | None = None, path: str = '',
              sha: str | None = None, **kw) -> ToolManifest:
    rules = {'rules_source': 'directory', 'rules_sha256': kw.pop('rules_sha256')} if kw.get('rules_sha256') else {}
    kw.pop('rules_sha256', None)
    return ToolManifest(engine=ENGINE, cli_path=path, executable_sha256=sha, license=LICENSES[ENGINE],
                        supported=supported, reason=reason, **rules, **kw)


_CACHE: dict[tuple, ToolManifest] = {}
_CACHE_LOCK = threading.Lock()


def clear_probe_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def probe(config: DiecConfig, *, cancel: threading.Event | None = None, runner: Callable = run_process,
          environ: Mapping[str, str] | None = None, use_cache: bool = True) -> ToolManifest:
    if config.executable is None or not str(config.executable).strip():
        return _manifest(config, supported=False, reason='diec is not configured (pass --diec or set '
                         'PATCHTRACE_DIEC to the absolute path of the Detect It Easy console executable)')
    exe = process.regular_file(Path(config.executable))
    if exe is None:
        return _manifest(config, supported=False, path=str(config.executable),
                         reason='the configured diec executable is missing, not absolute or not a regular file')
    if config.library_path is not None and (not config.library_path.is_absolute()
                                            or not config.library_path.is_dir()):
        return _manifest(config, supported=False, path=str(exe), reason='--diec-lib must be an absolute directory')
    try:
        info = exe.stat()
        key = (str(exe), info.st_mtime_ns, info.st_size, config)
    except OSError:
        return _manifest(config, supported=False, path=str(exe), reason='the diec executable cannot be read')
    if use_cache:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    report, cacheable = _probe(config, exe, cancel or threading.Event(), runner, environ)
    if use_cache and cacheable and not (cancel and cancel.is_set()):
        with _CACHE_LOCK:
            _CACHE[key] = report
    return report


def database_for(config: DiecConfig, exe: Path) -> Path | None:
    return Path(config.database) if config.database is not None else default_database(exe)


def _probe(config: DiecConfig, exe: Path, cancel: threading.Event, runner: Callable,
           environ: Mapping[str, str] | None) -> tuple[ToolManifest, bool]:
    """(manifest, cacheable): a timeout, cancel or spawn failure is reported but never remembered (TA-10)."""
    try:
        sha = process.sha256_file(exe)
    except (OSError, ToolError):
        return _manifest(config, supported=False, path=str(exe),
                         reason='the diec executable cannot be hashed'), False
    pin_status = 'pinned' if pins.is_pinned(ENGINE, sha) else 'unpinned'

    def unsupported(reason: str, cacheable: bool = True, **kw) -> tuple[ToolManifest, bool]:
        return _manifest(config, supported=False, path=str(exe), sha=sha, reason=reason,
                         pin_status=pin_status, **kw), cacheable
    extra = extra_env(config)
    version_run = process.run_version_probe(exe, ['--version'], cancel=cancel, runner=runner, environ=environ,
                                            extra=extra)
    help_run = process.run_version_probe(exe, ['--help'], cancel=cancel, runner=runner, environ=environ,
                                         extra=extra)
    transient = process.is_transient(version_run, help_run)
    for run, what in ((version_run, 'diec --version'), (help_run, 'diec --help')):
        if run.reason or run.spawn_error:
            return unsupported(process.describe_failure(run, what), cacheable=not transient)
    match = _VERSION.search(f'{version_run.stdout}\n{version_run.stderr}')
    if version_run.returncode != 0 or match is None:
        return unsupported(f'diec did not report a version ({process.exit_text(version_run.returncode)}); on Linux '
                           'it needs the Qt 5 Core and Script libraries')
    version = f'{match.group(1)}.{match.group(2)}'
    text = help_run.stdout + '\n' + help_run.stderr
    common = {'version': version, 'version_text': process.sanitize(match.group(0), 120)}
    if help_run.returncode != 0:
        return unsupported('diec --help failed', **common)
    for option in REQUIRED_OPTIONS:
        if not re.search(rf'(?<![\w-]){re.escape(option)}(?![\w-])', text):
            return unsupported(f'this diec build lacks the option {option}', **common)
    database = database_for(config, exe)
    if database is None:
        return unsupported('no Detect It Easy signature database found; pass --diec-db', **common)
    try:
        digest = process.tree_digest(database)
    except (OSError, ToolError) as exc:
        return unsupported(f'signature database rejected: {getattr(exc, "message", type(exc).__name__)}', **common)
    tested = version in TESTED_VERSIONS and digest in KNOWN_DATABASES and pin_status == 'pinned'
    if not tested and not config.accept_untested:
        why = ('this executable is not the pinned release' if pin_status != 'pinned'
               else 'the signature database is not the pinned one')
        return unsupported(f'diec {version}: {why}; results are accepted only from the pinned 3.21 release with '
                           'its signature database (or pass --diec-accept-untested)', rules_sha256=digest, **common)
    capabilities = sorted({'json', 'database', *(['heuristic'] if config.heuristic else [])})
    return _manifest(config, supported=True, path=str(exe), sha=sha, capabilities=tuple(capabilities),
                     rules_sha256=digest, untested_version=not tested, pin_status=pin_status, **common), True


def options(config: DiecConfig) -> dict[str, str]:
    return {'argv': 'diec/1', 'mode': 'deep+heuristic' if config.heuristic else 'signature'}


def prepare(config: DiecConfig, exe: Path, scratch: Path, manifest: ToolManifest | None = None) -> str:
    """Copy the signature database into the scratch; returns the digest of the copy. With the probed `manifest`
    a copy that differs from the probed digest is `PT-TOOL-STALE` (TA-6)."""
    database = database_for(config, exe)
    if database is None:
        raise ToolError('PT-TOOL-UNSUPPORTED', 'no Detect It Easy signature database')
    (scratch / 'empty').mkdir(exist_ok=True)
    digest = process.copy_tree(database, scratch / 'db')
    if manifest is not None and manifest.rules_sha256 != digest:
        raise ToolError('PT-TOOL-STALE', 'the signature database changed since it was probed')
    return digest


def build_argv(config: DiecConfig, executable: str, scratch: Path, artifact: Path) -> list[str]:
    flags = ['-d', '-u'] if config.heuristic else []
    return [executable, '-j', *flags, '-D', str(scratch / 'db'), '-E', str(scratch / 'empty'), '-C',
            str(scratch / 'empty'), str(artifact)]


def classify_exit(returncode: int, stdout: str, stderr: str, *, memory_limit_bytes: int | None = None,
                  peak_memory_bytes: int | None = None) -> tuple[str, str, str]:
    line = process.first_error_line(stdout, stderr)  # diec prints `Cannot find:` and usage errors on stdout
    if process.memory_exhausted(stderr, returncode, peak_memory_bytes, memory_limit_bytes):
        return 'failed', 'PT-TOOL-LIMIT', 'diec stopped at the memory limit (memory)'
    return 'failed', 'PT-TOOL-RUN', f'diec failed ({process.exit_text(returncode)}): {line or "no message"}'


class _Model(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Value(_Model):
    info: str
    name: str
    string: str
    type: str
    version: str


class Detect(_Model):
    filetype: str
    info: str
    offset: str
    parentfilepart: str
    size: str
    values: list[Value]


class Document(_Model):
    detects: list[Detect]


@dataclass(frozen=True)
class ParseContext:
    run_id: str
    side: str
    artifact_sha256: str
    cache_key: str
    config_digest: str
    limits: ToolLimits


def _evidence(value: Value, filetype: str, run_id: str) -> EnvironmentEvidence:
    heuristic = value.type.startswith('~') or value.string.startswith('(Heur)')
    kind = value.type.lstrip('~').strip().lower()
    unknown = kind == 'unknown' or value.name.strip().lower() == 'unknown'
    category = 'unknown' if unknown else kind if kind in CATEGORIES else 'other'
    name, version = process.tool_text(value.name, 200), process.tool_text(value.version, 120)
    label = process.tool_text(' '.join(part for part in (value.name.strip(), value.version.strip()) if part), 200)
    certainty = 'unknown' if unknown else 'heuristic' if heuristic else 'signature'
    return EnvironmentEvidence(
        category=category, toolchain=label if category in ('compiler', 'linker', 'tool') else None,
        packer=label if category in ('packer', 'cryptor', 'sfx', 'installer') else None,
        protector=label if category == 'protector' else None, detector_rule=name,
        heuristic=heuristic, certainty=certainty, version=version,
        detect_string=process.tool_text(value.string, 200), filetype=process.tool_text(filetype, 32),
        source_run_id=run_id)


def parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    """Strict parse + normalisation of one diec JSON document; a value the evidence contract refuses is
    `PT-TOOL-OUTPUT`, never a bare pydantic ValidationError (TA-1)."""
    try:
        return _parse(raw, ctx)
    except ValidationError:
        raise ToolError('PT-TOOL-OUTPUT', 'diec output holds a value outside the evidence contract') from None


def _parse(raw: bytes, ctx: ParseContext) -> ToolEvidenceSet:
    data = load_json_strict(raw, max_bytes=ctx.limits.stdout_bytes, max_depth=ctx.limits.json_depth)
    try:
        doc = Document.model_validate(data)
    except ValidationError as exc:
        where = '.'.join(str(p) for p in exc.errors()[0]['loc'])[:80] if exc.errors() else '?'
        raise ToolError('PT-TOOL-OUTPUT', f'diec output violates the 3.21 JSON contract at {where}') from None
    pairs = [(detect.filetype, value) for detect in doc.detects for value in detect.values]
    total = len(pairs)
    # A truncated set is a stable prefix of the sorted detections, not of the tool's order (TA-3).
    pairs.sort(key=lambda p: (p[0], p[1].type, p[1].name, p[1].version, p[1].string, p[1].info))
    items = [_evidence(value, filetype, ctx.run_id) for filetype, value in pairs[:ctx.limits.max_environment]]
    filetypes = sorted({process.tool_text(d.filetype, 32) for d in doc.detects})
    return ToolEvidenceSet(
        run_id=ctx.run_id, engine=ENGINE, side=ctx.side, artifact_sha256=ctx.artifact_sha256, cache_key=ctx.cache_key,
        config_digest=ctx.config_digest, analysis={'filetypes': ','.join(filetypes)[:200]},
        environment=tuple(items), truncated=total > len(items),
        counts={'environment': len(items), 'environment_total': total})
