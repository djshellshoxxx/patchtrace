"""Adapter for the separately installed GPL Ghidriff CLI; no project mutations."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import threading
from collections.abc import Callable
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
    if not isinstance(config.java_home, str):
        errors.append('PT-BACKEND: Java home must be a directory path')
    elif config.java_home:
        java_home = Path(config.java_home)
        java_name = 'java.exe' if os.name == 'nt' else 'java'
        if not java_home.is_absolute() or not (java_home / 'bin' / java_name).is_file():
            errors.append('PT-BACKEND: private Java home must contain bin/' + java_name)
    return errors


def _environment(config: BackendConfig) -> dict[str, str]:
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
    return env


def _ghidra_version(config: BackendConfig) -> str:
    path = Path(config.ghidra_dir) / 'Ghidra' / 'application.properties'
    with path.open('r', encoding='utf-8', errors='replace') as source:
        properties = source.read(65536)
    match = re.search(r'^application\.version\s*=\s*([A-Za-z0-9_.-]{1,64})\s*$', properties, re.MULTILINE)
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
        metadata = json.loads(result.log_tail)
        if not isinstance(metadata, dict) or not metadata.get('available'):
            raise ValueError('ghidriff absent')
        major, minor = map(int, metadata['python'].split('.')[:2])
        if (major, minor) < (3, 10):
            raise ValueError('Python is too old')
        return metadata
    except (ValueError, TypeError, KeyError):
        raise RuntimeError('PT-BACKEND: install ghidriff in the selected Python 3.10+ environment') from None


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
                'older_sha256': next(a.sha256 for a in project.artifacts if a.side == 'older'),
                'newer_sha256': next(a.sha256 for a in project.artifacts if a.side == 'newer')}
    backend_version = 'unknown'

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
        # Ghidriff defaults its large, lock-heavy Ghidra projects under --output-path.
        # Keep those transient databases and GZF caches off OneDrive/network-backed
        # case directories. The project-owned JSON and analysis log stay under raw/.
        # TemporaryDirectory has a randomized private name; no shared static workspace
        # is used between concurrent comparisons. Cleanup runs on success and failure.
        event('analysis', 'Ghidriff is performing static analysis; detailed counts are unavailable')
        with tempfile.TemporaryDirectory(prefix='patchtrace-ghidra-') as scratch:
            scratch_root = Path(scratch).resolve()
            engine_project = _validated_ghidra_output_path(scratch_root / 'projects')
            engine_gzfs = _validated_ghidra_output_path(scratch_root / 'gzfs')
            argv = [str(Path(config.python_executable).resolve()), '-m', 'ghidriff',
                    str(paths['older']), str(paths['newer']), '--output-path',
                    str(_validated_ghidra_output_path(raw)),
                    '--project-location', str(engine_project), '--gzfs-path', str(engine_gzfs)]
            if not config.allow_symbol_downloads:
                argv.append('--no-symbols')
            result = run_process(argv, cwd=Path(config.ghidra_dir), env=_environment(config), cancel=cancel,
                                 timeout_seconds=config.timeout_seconds,
                                 check_output=lambda: _output_error(raw))
        sanitized_log = redact_log(result.log_tail)
        (quarantine / 'analysis.log').write_text(sanitized_log, encoding='utf-8')
        if sanitized_log:
            # Redact the entire collected tail first so chunk boundaries cannot split credentials.
            event('log', sanitized_log[-8192:])
        if result.reason == 'cancelled' or cancel.is_set():
            raise RuntimeError('PT-CANCEL: analysis cancelled; partial output retained in quarantine')
        if result.reason == 'timeout':
            raise RuntimeError('PT-BACKEND: analysis timed out; increase the configured timeout and retry')
        if result.reason or _output_error(raw):
            raise RuntimeError('PT-BACKEND: unsafe or oversized JSON output; partial output quarantined')
        if result.returncode:
            raise RuntimeError(describe_backend_exit(result.returncode, sanitized_log))
        candidates = list((raw / 'json').glob('*.ghidriff.json'))
        if len(candidates) != 1:
            raise RuntimeError('PT-BACKEND: expected exactly one Ghidriff PDiff JSON; check runtime compatibility')
        source = candidates[0]
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
        quarantine.rename(destination)
        json_path = destination / relative
        run = AnalysisRun(id=run_id, status='completed', backend_version=backend_version,
                          settings=settings, raw_path=json_path.relative_to(root).as_posix(),
                          raw_sha256=hashlib.sha256(payload).hexdigest())
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
