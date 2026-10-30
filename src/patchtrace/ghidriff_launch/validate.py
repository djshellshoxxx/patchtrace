"""Parent-side checks for the Ghidriff launcher (SPEC-53 section 7.2). Pure apart from reading packaged bytes."""
from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

from ..symbols.modes import LAUNCHER_CONTRACT, SymbolError

SCRIPT_NAME = 'ptlaunch.py'
REPORT_LIMIT = 64 * 1024
HANDSHAKE_LIMIT = 512
EXIT_INCOMPATIBLE = 78


def script_bytes() -> bytes:
    """The packaged launcher (works from source and from the frozen onedir data file)."""
    return resources.files(__package__).joinpath(SCRIPT_NAME).read_bytes()


def script_sha256() -> str:
    return hashlib.sha256(script_bytes()).hexdigest()


def write_private_copy(directory: Path) -> Path:
    """Copy the launcher into `directory` (a private empty scratch dir) and return its path."""
    target = Path(directory) / SCRIPT_NAME
    data = script_bytes()
    if f"CONTRACT = '{LAUNCHER_CONTRACT}'".encode() not in data:
        raise SymbolError('PT-SYMBOL-LAUNCHER-MISMATCH', 'packaged launcher has another contract version')
    target.write_bytes(data)
    return target


def _mismatch(why: str) -> SymbolError:
    return SymbolError('PT-SYMBOL-LAUNCHER-MISMATCH', why)


def check_exit(returncode: int | None, log: str) -> None:
    """Exit 78 is the launcher's refusal: an incompatible Ghidriff, never a silent fallback."""
    if returncode == EXIT_INCOMPATIBLE and 'PT-SYMBOL-LAUNCHER-INCOMPATIBLE' in log:
        raise SymbolError('PT-SYMBOL-LAUNCHER-INCOMPATIBLE',
                          'the installed Ghidriff does not expose the symbol-server hook; use symbol mode off')


def validate_run(mode: str, report_path: Path, log: str, expected_staged: tuple[str, ...]) -> dict:
    """Validate the launcher report (and the handshake line when still in the log tail); returns the report."""
    try:
        if report_path.is_symlink() or not report_path.is_file() or report_path.stat().st_size > REPORT_LIMIT:
            raise _mismatch('launcher report is missing or oversized')
        report = json.loads(report_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise _mismatch('launcher report is missing or unreadable') from None
    if not isinstance(report, dict) or report.get('contract') != LAUNCHER_CONTRACT:
        raise _mismatch('launcher report has another contract')
    if report.get('mode') != mode:
        raise _mismatch('launcher ran in another symbol mode than requested')
    calls = report.get('setup_calls')
    if mode == 'local':
        if report.get('server_urls_forced_empty') is not True or not isinstance(calls, int) or calls < 1:
            raise _mismatch('local mode never forced the symbol server list to empty')
    elif report.get('server_urls_forced_empty') is not False:
        raise _mismatch('launcher patched the symbol hook outside local mode')
    if sorted(report.get('pdbs_staged') or []) != sorted(expected_staged):
        raise _mismatch('launcher reported another staged PDB set')
    for line in log.splitlines():
        if line.startswith('PT-LAUNCHER/1') and len(line) <= HANDSHAKE_LIMIT:
            if line.split()[1:2] != [f'mode={mode}'] or (mode != 'online' and 'servers=0' not in line):
                raise _mismatch('launcher handshake line differs from the request')
            break
    return report
