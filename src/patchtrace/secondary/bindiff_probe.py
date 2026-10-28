"""BinDiff capability probe and child environment (SPEC-29 §2, §4.2). No Qt; spawns only via `runner`.

The version text, the major version and every option PatchTrace passes are verified at runtime with
`--version` and `--nologo --help`. Measured on the real BinDiff 8 (2026-10-14): `--version` prints
`BinDiff 8 (@568181968, Sep 25 2023)` and exits 0; `--help` prints the flag list on stdout and exits 1
(tests/fixtures/secondary/bindiff-8-help.txt). Symlinks are resolved and the resolved path is what runs,
because argv[0]'s basename selects UI mode (`bin/bindiff_ui` is a symlink to `bindiff` in the `.deb`).
The probe never installs anything, never launches the UI and never touches inputs.
"""
from __future__ import annotations

import ntpath
import os
import re
import tempfile
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ..jobs import run_process
from .contracts import Capability
from .engine_env import engine_env

MIN_MAJOR = 8
TESTED_MAJOR = 8
PROBE_TIMEOUT = 30
PROBE_LOG_LIMIT = 64 * 1024
# `--config` is required: with `{}` it is what neutralises user and machine config (SPEC-29 §4.1).
REQUIRED_OPTIONS = ('--output_dir', '--output_format', '--primary', '--secondary', '--logo', '--config')
EXECUTABLE_NAMES = frozenset({'bindiff', 'bindiff.exe'})
WORKDIR_PARTS = ('cwd', 'home', 'tmp', 'programdata')
_VERSION = re.compile(r'^BinDiff (\d+)(.*)$')
_ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]')
_PATHISH = re.compile(r'(?:[A-Za-z]:)?(?:[\\/][^\\/\s\'"<>|]+)+[\\/]?')

MESSAGES = {
    'not-configured': 'BinDiff is not configured. Install BinDiff 8 and choose its `bindiff` executable '
                      '(Setup), or pass --bindiff.',
    'not-found': 'The selected BinDiff executable is not usable (missing, not a file, or the UI launcher).',
    'probe-failed': 'BinDiff did not report a version; it may be damaged or need a missing runtime library.',
}


@dataclass(frozen=True)
class ProbeReport:
    capability: Capability
    kind: str | None = None          # SPEC-29 §6 failure kind when unsupported
    major: int | None = None
    untested_version: bool = False


def sanitize(text: str, limit: int = 200) -> str:
    """Strip ANSI/control characters, collapse paths to basenames, cap length (no env values, no paths)."""
    text = _ANSI.sub('', text)
    text = ''.join(c if c in '\t' or (ord(c) >= 32 and ord(c) != 127) else ' ' for c in text)
    text = _PATHISH.sub(lambda m: ntpath.basename(m.group(0).rstrip('\\/')) or '<path>', text)
    return text.strip()[:limit]


def exit_text(code: int) -> str:
    """`exit N`, `signal N` (POSIX, negative) or `exit 0xC0000135` (Windows NTSTATUS-sized codes, e.g. a
    missing VC++ runtime DLL), so a probe or run failure says how the process ended."""
    if code < 0:
        return f'signal {-code}'
    return f'exit 0x{code & 0xFFFFFFFF:08X}' if code > 255 else f'exit {code}'


def first_error_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        if line.startswith('Error:'):
            return line
    return lines[0] if lines else ''


def build_env(executable: Path, workdir: Path, *, os_name: str = os.name,
              environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Allow-listed child environment built from scratch (§4.2) via the shared `engine_env`."""
    return engine_env(os.environ if environ is None else environ, 'bindiff', windows=os_name == 'nt',
                      workdir=workdir, executable=executable)


def make_private_dirs(workdir: Path) -> None:
    for part in WORKDIR_PARTS:
        (workdir / part).mkdir(parents=True, exist_ok=True)
    for part in (('home', 'AppData', 'Roaming'), ('home', 'AppData', 'Local'), ('home', '.config')):
        workdir.joinpath(*part).mkdir(parents=True, exist_ok=True)


def parse_version(text: str) -> tuple[int, str] | None:
    """First line `BinDiff <major><detail>` -> (major, detail<=120 chars, control characters stripped)."""
    for line in text.splitlines():
        if (match := _VERSION.match(line.strip())) and len(match.group(1)) <= 9:
            detail = ''.join(c for c in match.group(2) if ord(c) >= 32 and ord(c) != 127)[:120]
            return int(match.group(1)), detail
    return None


def _unsupported(path: str, kind: str, reason: str, version: str | None = None,
                 major: int | None = None) -> ProbeReport:
    return ProbeReport(Capability(engine='bindiff', supported=False, version=version, path=path,
                                  supports_json=False, reason=reason), kind, major)


def check_path(executable: str | Path | None) -> tuple[Path | None, ProbeReport | None]:
    if executable is None or not str(executable).strip():
        return None, _unsupported('', 'not-configured', MESSAGES['not-configured'])
    path = Path(executable)
    text = str(executable)
    if not path.is_absolute():
        return None, _unsupported(text, 'not-found', MESSAGES['not-found'])
    try:
        resolved = path.resolve(strict=True)
        regular = resolved.is_file()
    except (OSError, RuntimeError):
        return None, _unsupported(text, 'not-found', MESSAGES['not-found'])
    names = {path.name.casefold(), resolved.name.casefold()}
    if any(name.startswith('bindiff_cli') for name in names):
        return None, _unsupported(text, 'not-found', 'There is no `bindiff_cli` in BinDiff 8; select the '
                                  '`bindiff` executable instead.')
    if not regular or any(name.startswith('bindiff_ui') for name in names) or \
            resolved.name.casefold() not in EXECUTABLE_NAMES:
        return None, _unsupported(text, 'not-found', MESSAGES['not-found'])
    return resolved, None


_CACHE: dict[tuple[str, int, int], ProbeReport] = {}
_CACHE_LOCK = threading.Lock()


def clear_probe_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()


def probe_report(executable: str | Path | None, *, cancel: threading.Event | None = None,
                 runner: Callable = run_process, environ: Mapping[str, str] | None = None,
                 use_cache: bool = True) -> ProbeReport:
    """§2 steps 1-6. Every failure is an unsupported report with a specific kind; nothing raises."""
    resolved, failure = check_path(executable)
    if failure is not None:
        return failure
    assert resolved is not None
    path = str(resolved)
    try:
        info = resolved.stat()
        key = (path, info.st_mtime_ns, info.st_size)
    except OSError:
        return _unsupported(path, 'not-found', MESSAGES['not-found'])
    if use_cache:
        with _CACHE_LOCK:
            if key in _CACHE:
                return _CACHE[key]
    cancel = cancel or threading.Event()
    report = _probe(resolved, cancel, runner, environ)
    if use_cache and not cancel.is_set() and report.kind != 'probe-cancelled':
        with _CACHE_LOCK:
            _CACHE[key] = report
    return report


def _run(runner: Callable, argv: list[str], workdir: Path, cancel: threading.Event,
         environ: Mapping[str, str] | None):
    return runner(argv, cwd=workdir / 'cwd', env=build_env(Path(argv[0]), workdir, environ=environ),
                  cancel=cancel, timeout_seconds=PROBE_TIMEOUT, log_limit=PROBE_LOG_LIMIT,
                  separate_streams=True, stderr_limit=PROBE_LOG_LIMIT)


def _probe(exe: Path, cancel: threading.Event, runner: Callable, environ: Mapping[str, str] | None) -> ProbeReport:
    path = str(exe)
    with tempfile.TemporaryDirectory(prefix='patchtrace-bindiff-probe-') as tmp:
        workdir = Path(tmp)
        make_private_dirs(workdir)
        try:
            version_run = _run(runner, [path, '--version'], workdir, cancel, environ)
        except (OSError, ValueError, RuntimeError):
            return _unsupported(path, 'probe-failed', MESSAGES['probe-failed'])
        if version_run.reason == 'cancelled':
            return _unsupported(path, 'probe-cancelled', 'BinDiff probe was cancelled.')
        parsed = parse_version(f'{version_run.log_tail}\n{version_run.stderr_tail}')
        if not version_run.reason and version_run.returncode != 0:
            ended = exit_text(version_run.returncode)
            return _unsupported(path, 'probe-failed', f'BinDiff did not report a version ({ended}); it may be '
                                'damaged or need a missing runtime library.')
        if version_run.reason or parsed is None:
            return _unsupported(path, 'probe-failed', MESSAGES['probe-failed'])
        major, detail = parsed
        version = f'{major}{detail}'
        if major < MIN_MAJOR:
            return _unsupported(path, 'unsupported-version',
                                f'BinDiff {sanitize(version, 120)} is older than the supported version 8.',
                                version, major)
        try:
            help_run = _run(runner, [path, '--nologo', '--help'], workdir, cancel, environ)
        except (OSError, ValueError, RuntimeError):
            return _unsupported(path, 'probe-failed', MESSAGES['probe-failed'], version, major)
        if help_run.reason == 'cancelled':
            return _unsupported(path, 'probe-cancelled', 'BinDiff probe was cancelled.', version, major)
        if help_run.reason or help_run.returncode not in (0, 1):  # BinDiff 8 exits 1 after --help (measured)
            return _unsupported(path, 'probe-failed', MESSAGES['probe-failed'], version, major)
        text = f'{help_run.log_tail}\n{help_run.stderr_tail}'
        for option in REQUIRED_OPTIONS:
            if not re.search(re.escape(option) + r'(?![A-Za-z0-9_])', text):
                return _unsupported(path, 'missing-option', f'This BinDiff build lacks the command-line option '
                                    f'{option}; it cannot be driven safely.', version, major)
    return ProbeReport(Capability(engine='bindiff', supported=True, version=version, path=path,
                                  supports_json=False), None, major, major > TESTED_MAJOR)


def probe(executable: str | Path | None, env: Mapping[str, str] | None = None,
          cancel: threading.Event | None = None, runner: Callable = run_process) -> Capability:
    """SPEC-29 §2 entry point; `env` is ignored on purpose (the child env is always built from scratch)."""
    return probe_report(executable, cancel=cancel, runner=runner).capability
