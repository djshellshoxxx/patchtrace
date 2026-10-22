"""Adapter for the separately installed GPL Ghidriff CLI; no project mutations."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from .diagnostics import describe_backend_exit, redact_log
from .ingestion import safe_path
from .jobs import run_process
from .models import AnalysisRun, ComparisonProject, JobEvent, uid

JSON_LIMIT = 100 * 1024 * 1024


def _validated_ghidra_output_path(path: Path) -> Path:
    """Validate the resolved path that Ghidriff will use for Ghidra projects.

    Ghidra rejects *any* path component beginning with a dot, not just the
    output directory's basename. Never silently rename the user's project.
    Windows path-length failures are also surfaced before starting Java.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError('PT-BACKEND: Ghidra output path must be absolute')
    resolved = candidate.resolve()
    if any(part.startswith('.') for part in resolved.parts):
        raise ValueError(
            'PT-BACKEND: Ghidra cannot use a dot-prefixed directory in its output/project '
            'path; move the PatchTrace project to a directory without hidden ancestors'
        )
    if os.name == 'nt' and len(str(resolved)) >= 240:
        raise ValueError(
            'PT-BACKEND: Ghidra output path is too long for reliable Windows analysis; '
            'choose a shorter project location'
        )
    return resolved


@dataclass(frozen=True)
class BackendConfig:
    python_executable: str
    ghidra_dir: str
    timeout_seconds: int = 3600
    allow_symbol_downloads: bool = False
    java_home: str = ''
    # Empty cache_dir disables the raw-output cache, preserving pre-cache behaviour.
    cache_dir: str = ''
    no_cache: bool = False
    refresh: bool = False
    # H7: child processes inherit the full environment unless restrict_env is set (default OFF until
    # the allowlist is validated by a native Windows run; see docs/qa.md). env_passthrough lists
    # extra names kept when restricted (proxies, custom JDK helpers).
    restrict_env: bool = False
    env_passthrough: tuple[str, ...] = ()
    # BUNDLE B6: private payload next to the app. Isolated argv (-I), forced restricted env,
    # JAVA_HOME_OVERRIDE, scratch-directed TEMP/XDG_CACHE_HOME, never inside the install tree.
    bundle: bool = False
    # SPEC-31 D-05: keep the two analysed GZFs Ghidriff writes (off by default; argv and cache fingerprint unchanged).
    retain_gzf: bool = False
    # SPEC-53: '' derives from allow_symbol_downloads (False -> off, True -> online). 'local' enables symbols with an
    # empty server list and PDBs only from the analyst-chosen folders below (identity-gated, copied per run).
    symbol_mode: str = ''
    symbol_pdb_dirs: tuple[str, ...] = ()


_PASSTHROUGH_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_()]*$')
_PASSTHROUGH_DENY = ('PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'BASH_ENV', 'ENV')
_WINDOWS_ENV = frozenset(n.lower() for n in (
    'SystemRoot', 'SystemDrive', 'windir', 'ComSpec', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE',
    'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)',
    'ProgramW6432', 'CommonProgramFiles', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'USERNAME',
    'USERDOMAIN'))
_POSIX_ENV = frozenset(('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'TMPDIR', 'TZ', 'SHELL', 'XDG_RUNTIME_DIR',
                        'XDG_DATA_HOME', 'XDG_CACHE_HOME'))
_NETWORK_ENV = frozenset(n.lower() for n in ('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'SSL_CERT_FILE',
                                              'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE'))
_RIZIN_ENV = frozenset(('RZ_PREFIX', 'RZ_LIBR_PLUGINS'))
_JAVA_ENV = frozenset(('java_home', 'jdk_home'))


def parse_env_passthrough(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(part.strip() for part in text.replace(';', ',').split(',') if part.strip()))


def _passthrough_error(name: object) -> bool:
    if not isinstance(name, str) or not _PASSTHROUGH_NAME.fullmatch(name):
        return True
    upper = name.upper()
    return (upper in _PASSTHROUGH_DENY or upper.endswith('_OPTIONS')
            or upper.startswith(('PYTHON', 'LD_', 'DYLD_')))


def _symbol_config_errors(config: BackendConfig) -> list[str]:
    from .symbols.modes import SymbolError, resolve_mode
    from .symbols.staging import validate_dirs
    if not isinstance(config.allow_symbol_downloads, bool) or not isinstance(config.symbol_mode, str):
        return []   # reported by the boolean check
    if not isinstance(config.symbol_pdb_dirs, tuple) or not all(isinstance(d, str) for d in config.symbol_pdb_dirs):
        return ['PT-SYMBOL-MODE: symbol_pdb_dirs must be a tuple of absolute folder paths']
    try:
        mode = resolve_mode(config.symbol_mode, config.allow_symbol_downloads)
        if config.symbol_pdb_dirs and mode != 'local':
            raise SymbolError('PT-SYMBOL-MODE', 'PDB folders are only used in local symbol mode')
        validate_dirs(config.symbol_pdb_dirs)
    except SymbolError as exc:
        return [str(exc)]
    return []


def _symbol_mode(config: BackendConfig) -> str:
    from .symbols.modes import resolve_mode
    return resolve_mode(config.symbol_mode, config.allow_symbol_downloads)


def _is_online(config: BackendConfig) -> bool:
    try:
        return _symbol_mode(config) == 'online'
    except ValueError:
        return config.allow_symbol_downloads is True


def _config_errors(config: BackendConfig) -> list[str]:
    errors = []
    python = Path(config.python_executable)
    if not config.python_executable or not python.is_absolute() or not python.is_file():
        errors.append('PT-BACKEND: select the absolute path to an installed external Python executable')
    elif os.name != 'nt' and not os.access(python, os.X_OK):
        errors.append('PT-BACKEND: configured Python is not executable; correct its permissions')
    elif getattr(sys, 'frozen', False) and python.resolve() == Path(sys.executable).resolve():
        errors.append('PT-BACKEND: select external Python, not the packaged PatchTrace executable')
    ghidra = Path(config.ghidra_dir)
    if not config.ghidra_dir or not ghidra.is_absolute() or not ghidra.is_dir():
        errors.append('PT-BACKEND: select an absolute path to the extracted Ghidra installation')
    elif not (ghidra / 'Ghidra' / 'application.properties').is_file():
        errors.append('PT-BACKEND: Ghidra/application.properties is missing; select the installation root')
    if isinstance(config.timeout_seconds, bool) or not isinstance(config.timeout_seconds, int) or config.timeout_seconds <= 0:
        errors.append('PT-BACKEND: timeout_seconds must be a positive integer')
    if not isinstance(config.allow_symbol_downloads, bool):
        errors.append('PT-BACKEND: allow_symbol_downloads must be a boolean')
    errors.extend(_symbol_config_errors(config))
    if not isinstance(config.cache_dir, str) or (config.cache_dir and not Path(config.cache_dir).is_absolute()):
        errors.append('PT-BACKEND: cache directory must be an absolute path')
    if not isinstance(config.no_cache, bool) or not isinstance(config.refresh, bool):
        errors.append('PT-BACKEND: no_cache and refresh must be booleans')
    elif config.no_cache and config.refresh:
        errors.append('PT-BACKEND: no_cache and refresh are mutually exclusive')
    if not isinstance(config.restrict_env, bool):
        errors.append('PT-BACKEND: restrict_env must be a boolean')
    if not isinstance(config.retain_gzf, bool):
        errors.append('PT-BACKEND: retain_gzf must be a boolean')
    if not isinstance(config.env_passthrough, tuple) or any(_passthrough_error(n) for n in config.env_passthrough):
        errors.append('PT-BACKEND: env_passthrough must list plain variable names, excluding PYTHONPATH, '
                      'PYTHONHOME, PYTHON*, LD_*, DYLD_*, BASH_ENV, ENV and *_OPTIONS')
    if not isinstance(config.bundle, bool):
        errors.append('PT-BACKEND: bundle must be a boolean')
    elif config.bundle:
        errors.extend(_bundle_errors(config))
    if not isinstance(config.java_home, str):
        errors.append('PT-BACKEND: Java home must be a directory path')
    elif config.java_home:
        java_home = Path(config.java_home)
        java_name = 'java.exe' if os.name == 'nt' else 'java'
        if not java_home.is_absolute() or not (java_home / 'bin' / java_name).is_file():
            errors.append('PT-BACKEND: private Java home must contain bin/' + java_name)
    return errors


def _bundle_errors(config: BackendConfig) -> list[str]:
    """Bundle mode needs a private JDK and no writable work path inside the install tree (backend/)."""
    errors = [] if config.java_home else ['PT-BACKEND: bundle mode requires the bundled Java home']
    root = Path(config.ghidra_dir).resolve().parent.parent
    for work in (config.cache_dir, tempfile.gettempdir()):
        if work and Path(work).resolve().is_relative_to(root):
            errors.append('PT-BUNDLE-WORKDIR: work, cache and temp paths must be outside the bundle install tree')
            break
    return errors


def _apply_bundle_env(env: dict[str, str], settings_dir: Path | None, windows: bool) -> None:
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if settings_dir is None:
        return
    scratch = str(settings_dir.parent)
    for name in ('XDG_CACHE_HOME', 'TEMP', 'TMP', 'TMPDIR'):
        for key in [k for k in env if k == name or (windows and k.lower() == name.lower())]:
            del env[key]
        env[name] = scratch


def build_child_env(base: Mapping[str, str], config: BackendConfig, settings_dir: Path | None, *,
                    symbol_downloads: bool, for_tool: str, windows: bool | None = None) -> dict[str, str]:
    """Pure allowlist environment for a child process (no I/O). SPEC-07h H7."""
    if for_tool not in ('ghidra', 'rizin'):
        raise ValueError('PT-BACKEND: unknown child tool')
    if any(_passthrough_error(n) for n in config.env_passthrough):
        raise ValueError('PT-BACKEND: env_passthrough contains a forbidden or invalid variable name')
    windows = os.name == 'nt' if windows is None else windows
    private_java = bool(config.java_home)
    extra = {n.lower() for n in config.env_passthrough} if windows else set(config.env_passthrough)
    env: dict[str, str] = {}
    for name in sorted(base):
        key = name.lower() if windows else name
        keep = key in (_WINDOWS_ENV if windows else _POSIX_ENV) or key in extra
        if not windows:
            keep = keep or name.startswith('LC_')
            keep = keep or (name == 'LD_LIBRARY_PATH' and not private_java and bool(base[name]))
        if symbol_downloads and for_tool == 'ghidra':
            keep = keep or name.lower() in _NETWORK_ENV
        if for_tool == 'rizin' and name in _RIZIN_ENV:
            keep = True
        if for_tool == 'ghidra' and not private_java and name.lower() in _JAVA_ENV and bool(base[name]):
            keep = True  # diagnose accepts an inherited JDK; the restricted child must see the same one
        if keep:
            env[name] = base[name]
    if for_tool == 'rizin':
        return env
    env['GHIDRA_INSTALL_DIR'] = str(Path(config.ghidra_dir).resolve())
    if private_java:
        java_home = str(Path(config.java_home).resolve())
        env['JAVA_HOME'] = java_home
        path_key = next((k for k in env if k.lower() == 'path'), 'PATH')
        env[path_key] = str(Path(java_home) / 'bin') + os.pathsep + env.get(path_key, '')
        env['JAVA_HOME_OVERRIDE'] = java_home  # pyghidra prefers it over running bare `java` from PATH
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONNOUSERSITE'] = '1'
    if config.bundle:
        _apply_bundle_env(env, settings_dir, windows)
    if settings_dir is not None:
        env['XDG_CONFIG_HOME'] = str(settings_dir)
    return env


def _environment(config: BackendConfig, settings_dir: Path | None = None) -> dict[str, str]:
    if config.bundle or (config.restrict_env and os.environ.get('PATCHTRACE_CHILD_ENV') != 'inherit'):
        return build_child_env(os.environ, config, settings_dir, symbol_downloads=_is_online(config),
                               for_tool='ghidra')
    env = os.environ.copy()
    # A case directory or inherited development path must not supply Python modules.
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONHOME', None)
    env['GHIDRA_INSTALL_DIR'] = str(Path(config.ghidra_dir).resolve())
    if config.java_home:
        java_home = str(Path(config.java_home).resolve())
        env['JAVA_HOME'] = java_home
        env['PATH'] = str(Path(java_home) / 'bin') + os.pathsep + env.get('PATH', '')
    env['PYTHONIOENCODING'] = 'utf-8'
    if settings_dir is not None:
        # Ghidra honours XDG_CONFIG_HOME on every OS. A per-run empty settings
        # directory hides symbol-server preferences persisted by earlier runs.
        env['XDG_CONFIG_HOME'] = str(settings_dir)
    return env


def _ghidra_version(config: BackendConfig) -> str:
    path = Path(config.ghidra_dir) / 'Ghidra' / 'application.properties'
    with path.open('r', encoding='utf-8', errors='replace') as source:
        properties = source.read(65536)
    match = re.search(r'^application\.version\s*=\s*([A-Za-z0-9_.-]{1,64})\s*$', properties, re.MULTILINE)
    return match.group(1) if match else 'unknown'


def _java_executable(config: BackendConfig) -> str | None:
    java_name = 'java.exe' if os.name == 'nt' else 'java'
    java_home = config.java_home or os.environ.get('JAVA_HOME')
    if java_home and (Path(java_home) / 'bin' / java_name).is_file():
        return str((Path(java_home) / 'bin' / java_name).resolve())
    return shutil.which('java')


def _java_version(config: BackendConfig, cancel: threading.Event | None = None) -> str:
    """Probed JVM version, or 'unknown' (which makes raw output uncacheable)."""
    java = _java_executable(config)
    if java is None:
        return 'unknown'
    try:
        result = run_process([java, '-version'], cwd=Path(config.ghidra_dir), env=_environment(config),
                             cancel=cancel or threading.Event(), timeout_seconds=15, log_limit=4096)
    except OSError:
        return 'unknown'
    if result.reason or result.returncode:
        return 'unknown'
    match = re.search(r'version "([A-Za-z0-9_.+-]{1,64})"', result.log_tail)
    return match.group(1) if match else 'unknown'


def _probe_backend(config: BackendConfig, cancel: threading.Event | None = None) -> dict:
    # Metadata and find_spec do not import ghidriff or start Java.
    code = (
        'import importlib.metadata as m,importlib.util as u,json,sys;'
        'version=lambda n: m.version(n) if any(d.metadata.get("Name","").lower()==n '
        'for d in m.distributions()) else "unknown";'
        'print(json.dumps({"python":sys.version.split()[0],'
        '"ghidriff":version("ghidriff"),"pyghidra":version("pyghidra"),'
        '"available":u.find_spec("ghidriff") is not None}))'
    )
    result = run_process([str(Path(config.python_executable).resolve()), '-c', code],
                         cwd=Path(config.ghidra_dir), env=_environment(config),
                         cancel=cancel or threading.Event(), timeout_seconds=15, log_limit=16384)
    if result.reason == 'cancelled':
        raise RuntimeError('PT-CANCEL: analysis cancelled during dependency check')
    if result.reason or result.returncode:
        raise RuntimeError('PT-BACKEND: Python dependency check failed; verify the selected interpreter')
    try:
        # stdout and stderr are merged; interpreter warnings (for example a venv's
        # "Could not find platform independent libraries") may precede the JSON.
        lines = result.log_tail.strip().splitlines()
        metadata = json.loads(lines[-1] if lines else '')
        if not isinstance(metadata, dict) or not metadata.get('available'):
            raise ValueError('ghidriff absent')
        major, minor = map(int, metadata['python'].split('.')[:2])
        if (major, minor) < (3, 10):
            raise ValueError('Python is too old')
        return metadata
    except (ValueError, TypeError, KeyError):
        raise RuntimeError('PT-BACKEND: install ghidriff in the selected Python 3.10+ environment') from None


def _bundle_line(config: BackendConfig) -> str:
    """`Bundled runtime <id>: fast check ok` or the PT-BUNDLE-* problem (blocking walk; run in a worker)."""
    from .runtime_discovery import check_bundle
    try:  # config.ghidra_dir is <exe dir>/backend/payload/ghidra
        status = check_bundle(Path(config.ghidra_dir).resolve().parents[2])
    except (OSError, IndexError):
        status = None
    if status is None:
        return 'PT-BUNDLE-MISSING: no bundled runtime at this location - extract the complete ZIP again'
    return status.line()


def diagnose(config: BackendConfig) -> list[str]:
    """Actionable, credential-free configuration and dependency summaries."""
    errors = _config_errors(config)
    if errors:
        return errors
    try:
        ghidra_version = _ghidra_version(config)
    except OSError:
        return ['PT-BACKEND: Ghidra application.properties is unreadable; correct installation permissions']
    statuses = ['Python executable: configured external interpreter',
                f'Ghidra installation: root verified; version {ghidra_version}']
    if config.bundle:
        statuses.append(_bundle_line(config))
    if _symbol_mode(config) == 'local':
        statuses.append(f'Ghidriff symbol-server lookup: local PDB folders only, no servers '
                        f'({len(config.symbol_pdb_dirs)} folder(s) configured)')
    else:
        statuses.append('Ghidriff symbol-server lookup: enabled by analyst' if config.allow_symbol_downloads
                        else 'Ghidriff symbol-server lookup: disabled (local/offline option)')
    try:
        metadata = _probe_backend(config)
        statuses.append(f'Python {metadata["python"]}; ghidriff {metadata["ghidriff"]}; '
                        f'pyghidra {metadata["pyghidra"]}')
        if metadata['pyghidra'] == 'unknown':
            statuses.append('PT-BACKEND: pyghidra version unavailable; install ghidriff with its dependencies')
    except (OSError, RuntimeError, ValueError) as error:
        statuses.append(redact_log(str(error), 2048))
    java_home = config.java_home or os.environ.get('JAVA_HOME')
    java_name = 'java.exe' if os.name == 'nt' else 'java'
    java = Path(java_home) / 'bin' / java_name if java_home else None
    if not ((java and java.is_file()) or shutil.which('java')):
        statuses.append('PT-BACKEND: Java not found; install Ghidra-compatible JDK and configure JAVA_HOME')
    else:
        statuses.append('Java executable detected; Ghidra/JDK compatibility requires a real analysis check')
    statuses.append('Real Ghidriff analysis is not verified by this dependency check')
    return statuses


def _input_path(root: Path, relative: str, digest: str, cancel: threading.Event) -> Path:
    candidate = root / relative
    resolved = candidate.resolve()
    if Path(relative).is_absolute() or not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError('PT-INPUT: project artifact is missing or escapes the project directory')
    hasher = hashlib.sha256()
    with resolved.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            if cancel.is_set():
                raise RuntimeError('PT-CANCEL: analysis cancelled during input validation')
            hasher.update(chunk)
    if hasher.hexdigest() != digest:
        raise ValueError('PT-INPUT: project artifact hash changed; re-import the original binary')
    return resolved


def _output_error(directory: Path) -> str | None:
    try:
        return _output_scan(directory)
    except OSError:
        # An unreadable output tree cannot be bounded; stop and quarantine it.
        return 'output-check-failed'


def _output_scan(directory: Path) -> str | None:
    total = 0
    for path in directory.rglob('*.json'):
        if path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
            return 'unsafe-output-path'
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            continue
        if total > JSON_LIMIT:
            return 'output-limit'
    return None


def _keep_launcher_report(source: Path, target: Path) -> None:
    """Copy the (size-capped) launcher report out of scratch before it is removed; absence is validated later."""
    try:
        if source.is_file() and not source.is_symlink() and source.stat().st_size <= 64 * 1024:
            target.write_bytes(source.read_bytes())
    except OSError:
        pass


def _remove_scratch(path: Path, attempts: int = 5) -> str | None:
    """Remove private scratch, retrying briefly for Windows handle release.

    Returns the leftover path on persistent failure instead of raising, so a
    cleanup problem never changes a completed or failed run's real status.
    """
    delay = 0.1
    for attempt in range(attempts):
        try:
            shutil.rmtree(path)
            return None
        except FileNotFoundError:
            return None
        except OSError:
            if attempt + 1 < attempts:
                time.sleep(delay)
                delay *= 2  # 0.1 + 0.2 + 0.4 + 0.8 = 1.5 s total
    return str(path)


def quarantine_failed_run(root: Path, run: AnalysisRun, error: str) -> AnalysisRun:
    """Retain a CLI result rejected by normalization as a failed, hash-linked attempt.

    The service commits the returned copy; this function never changes its project.
    Only PatchTrace's canonical UUID run directory can be renamed.
    """
    root = Path(root).resolve()
    try:
        if str(UUID(run.id)) != run.id:
            raise ValueError('Noncanonical run ID')
    except (ValueError, AttributeError) as exc:
        raise ValueError('PT-SCHEMA: quarantining a run requires a canonical UUID') from exc
    if run.status != 'completed':
        raise ValueError('PT-SCHEMA: only completed CLI output can fail normalization')
    source = safe_path(root, f'runs/{run.id}')
    destination = safe_path(root, f'runs/quarantine-{run.id}')
    if not source.is_dir() or destination.exists():
        raise ValueError('PT-STORAGE: run output is missing or quarantine destination already exists')
    raw_relative = None
    if run.raw_path is not None:
        raw_path = safe_path(root, run.raw_path)
        if not raw_path.is_relative_to(source) or not raw_path.is_file():
            raise ValueError('PT-STORAGE: raw output does not belong to this run directory')
        raw_relative = raw_path.relative_to(source)
    message = redact_log(str(error), 4096) or 'PT-SCHEMA: analysis normalization failed'
    if not message.startswith('PT-'):
        message = 'PT-SCHEMA: ' + message
    # Write the explanation before the atomic directory rename. A write failure
    # leaves the original run intact and visibly propagates to the caller.
    safe_path(root, f'runs/{run.id}/failure.txt').write_text(message, encoding='utf-8')
    source.rename(destination)
    raw_path = (destination / raw_relative).relative_to(root).as_posix() if raw_relative else None
    return run.model_copy(deep=True, update={'status': 'failed', 'error': message, 'raw_path': raw_path})


RAW_ADAPTER_VERSION = 'patchtrace-ghidriff-adapter/2'  # serialized Ghidriff analysis changes raw output provenance


@dataclass(frozen=True)
class _LocalSymbols:
    """Everything `_ghidriff_argv` needs for local mode: launcher copy, its report path, the staged store, PDB names."""
    launcher: Path
    report: Path
    store: Path
    staged_names: tuple[str, ...]


def _ghidriff_argv(config: BackendConfig, older: Path, newer: Path, raw: Path,
                   engine_project: Path, engine_gzfs: Path, local: _LocalSymbols | None = None) -> list[str]:
    """Build a sequential Ghidriff invocation, testable without launching Java.

    `local` (SPEC-53) routes the call through the PatchTrace launcher with symbols on and an empty server list.
    """
    python = [str(Path(config.python_executable).resolve()), *(('-I', '-X', 'utf8') if config.bundle else ())]
    args = [str(older), str(newer), '--output-path', str(_validated_ghidra_output_path(raw)),
            '--project-location', str(engine_project), '--gzfs-path', str(engine_gzfs), '--no-threaded']
    if local is not None:
        staged = [x for name in local.staged_names for x in ('--pt-staged', name)]
        return [*python, str(local.launcher), '--pt-mode', 'local', '--pt-report', str(local.report), *staged,
                '--', *args, '--symbols-path', str(local.store)]
    if not _is_online(config):
        args.append('--no-symbols')
    return [*python, '-m', 'ghidriff', *args]


def _open_raw_cache(config: BackendConfig, backend_version: str, settings: dict,
                    cancel: threading.Event, symbol_digest: str = 'none'):
    """(cache, fingerprint) for an eligible run, else (None, None); never raises."""
    from .enrichment.cache import CacheConfig, DerivedCache, RuntimeFingerprint
    from .enrichment.contracts import EnrichmentError
    java_version = _java_version(config, cancel)
    settings['java_runtime_version'] = java_version if java_version != 'unknown' else 'unverified'
    from .symbols.modes import cache_policy
    symbols = cache_policy(_symbol_mode(config))
    # Only probed values enter the key; any unprobed value is 'unknown' and ineligible.
    fingerprint = RuntimeFingerprint(
        engine='ghidriff', ghidriff_revision=backend_version,
        ghidra_version=str(settings.get('ghidra_version', 'unknown')),
        pyghidra_version=str(settings.get('pyghidra_version', 'unknown')),
        python_version=str(settings.get('python_version', 'unknown')),
        java_version=java_version, platform_arch=platform.machine().lower() or 'unknown',
        loader_options='default', analysis_options='--no-symbols' if symbols == 'disabled' else 'symbols',
        adapter_version=RAW_ADAPTER_VERSION, symbol_policy=symbols, symbol_input_digest=symbol_digest)
    if not fingerprint.eligible()[0]:
        return None, None
    try:
        return DerivedCache(CacheConfig(root=Path(config.cache_dir),
                                        refresh_stages=frozenset({'raw'}) if config.refresh
                                        else frozenset())), fingerprint
    except (OSError, EnrichmentError, ValueError):
        return None, None


def _read_raw_cache(cache, fingerprint, settings: dict) -> tuple[bytes, dict] | None:
    try:
        payload = cache.get_raw(fingerprint, settings['older_sha256'], settings['newer_sha256'])
        if payload is None:
            return None
        key = fingerprint.raw_key(settings['older_sha256'], settings['newer_sha256'])
        manifest = cache._entry('raw', key) / 'manifest.json'
        created = json.loads(manifest.read_text(encoding='utf-8'))['created']
        return payload, {'key': key, 'created': str(created)}
    except Exception:  # noqa: BLE001 - any cache problem is a miss, never a failed run
        return None


def run_comparison(config: BackendConfig, project: ComparisonProject, root: Path,
                   cancel: threading.Event, on_event: Callable[[JobEvent], None]) -> tuple[Path, AnalysisRun]:
    """Return completed raw JSON and a new run, or a quarantined directory on failure.

    The caller validates/normalizes completed JSON and commits it transactionally.
    Failed data is retained under runs/quarantine-<id>, never published as a run.
    """
    root = root.resolve()
    run_id = uid()
    runs = root / 'runs'
    if runs.is_symlink() or not runs.resolve().is_relative_to(root):
        raise ValueError('PT-STORAGE: run directory escapes the project root')
    quarantine = root / 'runs' / f'quarantine-{run_id}'
    quarantine.mkdir(parents=True, exist_ok=False)
    raw = quarantine / 'raw'
    raw.mkdir()
    settings = {'timeout_seconds': config.timeout_seconds,
                'allow_symbol_downloads': config.allow_symbol_downloads,
                'symbol_policy': 'online' if _is_online(config) else 'disabled',
                'ghidra_settings': 'isolated-per-run',
                'older_sha256': next(a.sha256 for a in project.artifacts if a.side == 'older'),
                'newer_sha256': next(a.sha256 for a in project.artifacts if a.side == 'newer')}
    backend_version = 'unknown'
    raw_cache = None
    fingerprint = None
    scratch_root: Path | None = None    # created early in local symbol mode (PDB staging); removed in `finally`
    local_result = None
    symbol_mode = 'off'

    def publish(source: Path, origin: dict | None = None) -> tuple[Path, AnalysisRun]:
        # Fresh and cache-served output share this check and the same run layout.
        if source.is_symlink() or not source.resolve().is_relative_to(raw.resolve()):
            raise RuntimeError('PT-BACKEND: raw JSON path escapes the output directory')
        with source.open('rb') as stream:
            payload = stream.read(JSON_LIMIT + 1)
        if len(payload) > JSON_LIMIT:
            raise RuntimeError('PT-BACKEND: JSON output exceeds the 100 MiB limit')
        document = json.loads(payload)
        functions = document.get('functions') if isinstance(document, dict) else None
        if (not isinstance(functions, dict)
                or not all(isinstance(functions.get(key), list) for key in ('added', 'deleted', 'modified'))):
            raise RuntimeError('PT-SCHEMA: unrecognized Ghidriff JSON; output quarantined')
        relative = source.relative_to(quarantine)
        destination = root / 'runs' / run_id
        run_settings = dict(settings, cache_origin=origin) if origin else settings
        quarantine.rename(destination)
        json_path = destination / relative
        return json_path, AnalysisRun(id=run_id, status='completed', backend_version=backend_version,
                                      settings=run_settings, raw_path=json_path.relative_to(root).as_posix(),
                                      raw_sha256=hashlib.sha256(payload).hexdigest())

    def event(stage: str, message: str):
        # Event delivery is informational; a UI listener cannot interrupt containment
        # or turn an already renamed completed output into a failed partial run.
        try:
            on_event(JobEvent(run_id=run_id, stage=stage, message=message))
        except Exception:  # noqa: BLE001 - user-provided listeners cannot control the child lifecycle
            logging.getLogger(__name__).warning('Job event listener failed at stage %s', stage)

    try:
        event('preflight', 'Checking copied input hashes and external analysis runtime')
        if cancel.is_set():
            raise RuntimeError('PT-CANCEL: analysis cancelled')
        errors = _config_errors(config)
        if errors:
            raise RuntimeError('; '.join(errors))
        symbol_mode = _symbol_mode(config)
        paths = {a.side: _input_path(root, a.relative_path, a.sha256, cancel) for a in project.artifacts}
        _validated_ghidra_output_path(raw)
        metadata = _probe_backend(config, cancel)
        backend_version = str(metadata['ghidriff'])
        settings.update({'python_version': metadata['python'], 'pyghidra_version': metadata['pyghidra']})
        settings.update({'ghidra_version': _ghidra_version(config), 'java_runtime_version': 'unverified'})
        if settings['older_sha256'] == settings['newer_sha256']:
            destination = root / 'runs' / run_id
            quarantine.rename(destination)
            event('identical', 'Copied binaries have identical SHA-256 hashes; analysis skipped')
            return destination, AnalysisRun(id=run_id, status='identical',
                                           backend_version=backend_version, settings=settings)
        from .symbols.project import run_settings
        if symbol_mode == 'local':
            # SPEC-53: identity-gated PDBs are copied into this run's scratch; their hashes enter the cache key.
            from . import __version__
            from .symbols.project import stage_for_project
            event('symbols', 'Staging matching PDBs from the configured folders (no network)')
            scratch_root = Path(tempfile.mkdtemp(prefix='patchtrace-ghidra-')).resolve()
            local_result = stage_for_project(project, root, config.symbol_pdb_dirs, scratch_root / 'symbols', cancel)
            settings.update(run_settings(symbol_mode, local_result, __version__))
            settings['symbol_policy'] = 'local'
        elif symbol_mode != 'off':
            settings.update(run_settings(symbol_mode, None, ''))   # off keeps today's settings byte for byte
        if config.cache_dir and not config.no_cache:
            raw_cache, fingerprint = _open_raw_cache(config, backend_version, settings, cancel,
                                                     local_result.digest if local_result else 'none')
        if raw_cache is not None and fingerprint is not None and not config.refresh:
            hit = _read_raw_cache(raw_cache, fingerprint, settings)
            if hit is not None:
                payload, origin = hit
                (raw / 'json').mkdir()
                cached = raw / 'json' / 'result.ghidriff.json'
                cached.write_bytes(payload)
                (quarantine / 'analysis.log').write_text('Raw output reused from cache; Ghidriff not run\n',
                                                         encoding='utf-8')
                try:
                    json_path, run = publish(cached, origin)
                except (ValueError, RuntimeError):
                    # A verified-but-unusable entry must not fail the run; analyse for real.
                    shutil.rmtree(raw / 'json')
                    raw_cache = None
                else:
                    event('cache', 'raw output reused from cache')
                    event('completed', 'Raw static analysis saved; normalization is ready')
                    return json_path, run
        # Ghidriff defaults its large, lock-heavy Ghidra projects under --output-path.
        # Keep those transient databases and GZF caches off OneDrive/network-backed
        # case directories. The project-owned JSON and analysis log stay under raw/.
        # TemporaryDirectory has a randomized private name; no shared static workspace
        # is used between concurrent comparisons. Cleanup runs on success and failure.
        event('analysis', 'Ghidriff is performing static analysis; detailed counts are unavailable')
        if scratch_root is None:
            scratch_root = Path(tempfile.mkdtemp(prefix='patchtrace-ghidra-')).resolve()
        local = None
        try:
            engine_project = _validated_ghidra_output_path(scratch_root / 'projects')
            engine_gzfs = _validated_ghidra_output_path(scratch_root / 'gzfs')
            ghidra_settings = scratch_root / 'ghidra-settings'
            ghidra_settings.mkdir()
            if local_result is not None:
                from .ghidriff_launch.validate import write_private_copy
                launcher_dir = scratch_root / 'launcher'
                launcher_dir.mkdir()
                (scratch_root / 'symbols').mkdir(exist_ok=True)
                local = _LocalSymbols(write_private_copy(launcher_dir), scratch_root / 'ptlaunch-report.json',
                                      scratch_root / 'symbols', tuple(s.pdb_name for s in local_result.staged))
            argv = _ghidriff_argv(config, paths['older'], paths['newer'], raw, engine_project, engine_gzfs, local)
            result = run_process(argv, cwd=Path(config.ghidra_dir), env=_environment(config, ghidra_settings),
                                 cancel=cancel,
                                 timeout_seconds=config.timeout_seconds,
                                 check_output=lambda: _output_error(raw))
            if config.retain_gzf and result.returncode == 0 and not result.reason and not cancel.is_set():
                from .unified.extract.retain import retain_run_gzfs  # lazy: the unified engine stays optional
                retain_run_gzfs(engine_gzfs, quarantine, paths, settings, event)
            if local is not None:
                _keep_launcher_report(local.report, quarantine / 'ptlaunch-report.json')
        finally:
            # run_process returns only after the contained tree is terminated.
            leftover = _remove_scratch(scratch_root)
            scratch_root = None   # removed once; the outer `finally` only covers early exits
            if leftover:
                event('warning', f'Temporary Ghidra workspace could not be removed: {leftover}')
        sanitized_log = redact_log(result.log_tail)
        (quarantine / 'analysis.log').write_text(sanitized_log, encoding='utf-8')
        if sanitized_log:
            # Redact the entire collected tail first so chunk boundaries cannot split credentials.
            event('log', sanitized_log[-8192:])
        if result.reason == 'cancelled' or cancel.is_set():
            raise RuntimeError('PT-CANCEL: analysis cancelled; partial output retained in quarantine')
        if result.reason == 'timeout':
            raise RuntimeError('PT-BACKEND: analysis timed out; increase the configured timeout and retry')
        if result.reason == 'output-check-failed' or _output_error(raw) == 'output-check-failed':
            raise RuntimeError('PT-BACKEND: output directory could not be inspected; partial output quarantined')
        if result.reason or _output_error(raw):
            raise RuntimeError('PT-BACKEND: unsafe or oversized JSON output; partial output quarantined')
        if local is not None:
            from .ghidriff_launch.validate import check_exit, validate_run
            check_exit(result.returncode, sanitized_log)
        if result.returncode:
            raise RuntimeError(describe_backend_exit(result.returncode, sanitized_log))
        if local is not None:
            validate_run('local', quarantine / 'ptlaunch-report.json', sanitized_log, local.staged_names)
        candidates = list((raw / 'json').glob('*.ghidriff.json'))
        if len(candidates) != 1:
            raise RuntimeError('PT-BACKEND: expected exactly one Ghidriff PDiff JSON; check runtime compatibility')
        json_path, run = publish(candidates[0])
        if raw_cache is not None and fingerprint is not None:
            # Admission is best-effort: a cache failure must never fail a completed run.
            try:
                raw_cache.put_raw(fingerprint, settings['older_sha256'], settings['newer_sha256'],
                                  json_path.read_bytes())
            except Exception:  # noqa: BLE001 - see above
                logging.getLogger(__name__).warning('Raw output cache admission failed')
        event('completed', 'Raw static analysis saved; normalization is ready')
        return json_path, run
    except (OSError, ValueError, RuntimeError) as error:
        message = redact_log(str(error), 4096)
        status = 'cancelled' if message.startswith('PT-CANCEL:') else 'failed'
        if not message.startswith('PT-'):
            message = 'PT-BACKEND: ' + message
        (quarantine / 'failure.txt').write_text(message, encoding='utf-8')
        event(status, message)
        return quarantine, AnalysisRun(id=run_id, status=status, backend_version=backend_version,
                                       settings=settings, error=message)
    finally:
        if scratch_root is not None:
            _remove_scratch(scratch_root)
