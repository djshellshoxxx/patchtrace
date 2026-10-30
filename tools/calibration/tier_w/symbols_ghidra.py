"""Headless Ghidra driver for `ghidra_export_symbols.py` (SPEC-33 s5.2, `headless` mode).

A private project directory and private XDG config/cache directories are used, so no persisted symbol-server
preference is read. The image is only imported and analysed, never executed. Anything missing (Ghidra, the launcher,
a safe path) is BLOCKED with the reason, never silently skipped. The `pyghidra` mode and the PDB-forcing pre-script
need a live Ghidra to verify and are not built here; see the Tier W runbook open items.
"""
from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

from patchtrace.jobs import ProcessResult, run_process

from .contracts import GhidraRaw, load_ghidra_raw
from .paths import TierWError, read_bytes, tool_safe_path

SCRIPT = Path(__file__).with_name('ghidra_export_symbols.py')
RAW_LIMIT = 256 * 1024 * 1024
TIMEOUT_SECONDS = 3600.0
CMD_UNSAFE = frozenset('&|<>^%!"')
Runner = Callable[..., ProcessResult]


def launcher(ghidra_dir: Path) -> Path:
    name = 'analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless'
    path = Path(ghidra_dir) / 'support' / name
    if not path.is_file():
        raise TierWError('PT-TIERW-BLOCKED', f'Ghidra launcher not found ({name} under support/)')
    return path


def headless_argv(exe: Path, project_dir: Path, project_name: str, image: Path, out_json: Path) -> list[str]:
    argv = [str(exe), str(project_dir), project_name, '-import', str(image), '-overwrite',
            '-scriptPath', str(SCRIPT.parent), '-postScript', SCRIPT.name, str(out_json),
            '-deleteProject']
    if exe.suffix.lower() == '.bat':
        bad = [a for a in argv[1:] if CMD_UNSAFE & set(a)]
        if bad:
            raise TierWError('PT-TIERW-CONFIG', 'an argument contains a character cmd.exe would interpret; '
                                                'use a plain path for the root')
    return argv


def private_env(base: Path, environ: Mapping[str, str]) -> dict[str, str]:
    env = {k: v for k, v in environ.items() if k in ('PATH', 'SYSTEMROOT', 'JAVA_HOME', 'TEMP', 'TMP')}
    env['XDG_CONFIG_HOME'] = str(base / 'xdg-config')
    env['XDG_CACHE_HOME'] = str(base / 'xdg-cache')
    return env


def export_headless(ghidra_dir: Path, image: Path, workdir: Path, *, environ: Mapping[str, str] = os.environ,
                    cancel: threading.Event | None = None, run: Runner = run_process,
                    timeout: float = TIMEOUT_SECONDS) -> GhidraRaw:
    """Import + analyse `image`, run the exporter script, return the validated `ghidra-symbols/1` document."""
    problems = tool_safe_path(workdir)
    if problems:
        raise TierWError('PT-TIERW-CONFIG', problems[0])
    exe = launcher(ghidra_dir)
    work = Path(workdir)
    for sub in ('project', 'xdg-config', 'xdg-cache'):
        (work / sub).mkdir(parents=True, exist_ok=True)
    out = work / 'ghidra-symbols.json'
    out.unlink(missing_ok=True)
    result = run(headless_argv(exe, work / 'project', 'tw', Path(image), out), cwd=work,
                 env=private_env(work, environ), cancel=cancel or threading.Event(), timeout_seconds=timeout)
    if result.reason == 'cancelled':
        raise TierWError('PT-TIERW-CANCEL', 'Ghidra export cancelled')
    if result.returncode != 0 or not out.is_file():
        raise TierWError('PT-TIERW-VERIFY', f'Ghidra export failed (exit {result.returncode}, '
                                            f'reason {result.reason or "none"})')
    return load_ghidra_raw(read_bytes(out, RAW_LIMIT))


def blocked_reason(ghidra_dir: Path | None) -> str | None:
    """None when a live Ghidra export can run here, else the reason a live test must record as BLOCKED."""
    if ghidra_dir is None:
        return 'no --ghidra-dir given'
    try:
        launcher(Path(ghidra_dir))
    except TierWError as exc:
        return exc.message
    return None

