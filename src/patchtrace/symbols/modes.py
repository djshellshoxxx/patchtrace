"""Symbol modes for Ghidriff runs (SPEC-53 section 7.1). Pure: no I/O.

`off` is today's `--no-symbols`; `local` enables symbols with an empty server list and PDBs only from a
PatchTrace-built per-run store; `online` is today's `allow_symbol_downloads=True` and needs recorded consent.
"""
from __future__ import annotations

SYMBOL_MODES = ('off', 'local', 'online')
MAX_PDB_DIRS = 16
MAX_STAGED = 64
MAX_PDB_BYTES = 512 * 1024 * 1024
CHUNK = 1024 * 1024
LAUNCHER_CONTRACT = 'ptlaunch/1'
CODES = ('PT-SYMBOL-MODE', 'PT-SYMBOL-LAUNCHER-INCOMPATIBLE', 'PT-SYMBOL-LAUNCHER-MISMATCH',
         'PT-SYMBOL-PDB-INVALID', 'PT-SYMBOL-NETWORK-REFUSED')


class SymbolError(ValueError):
    """Carries a stable `PT-SYMBOL-*` code; the message already starts with it."""

    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code


def resolve_mode(symbol_mode: str, allow_symbol_downloads: bool) -> str:
    """Effective mode. An empty `symbol_mode` derives from the legacy boolean (False -> off, True -> online)."""
    if not isinstance(symbol_mode, str) or not isinstance(allow_symbol_downloads, bool):
        raise SymbolError('PT-SYMBOL-MODE', 'symbol_mode must be a string and allow_symbol_downloads a boolean')
    if not symbol_mode:
        return 'online' if allow_symbol_downloads else 'off'
    if symbol_mode not in SYMBOL_MODES:
        raise SymbolError('PT-SYMBOL-MODE', f'symbol mode must be one of {", ".join(SYMBOL_MODES)}')
    if allow_symbol_downloads and symbol_mode != 'online':
        raise SymbolError('PT-SYMBOL-MODE', 'allow_symbol_downloads contradicts the selected symbol mode')
    return symbol_mode


def cache_policy(mode: str) -> str:
    """RuntimeFingerprint.symbol_policy for a mode: off -> disabled, local -> local, online -> online."""
    return {'off': 'disabled', 'local': 'local', 'online': 'online'}[mode]


def parse_symbol_dirs(text: str) -> tuple[str, ...]:
    """Folder list typed in Setup: semicolon-separated (a colon is part of a Windows drive), blanks dropped."""
    return tuple(dict.fromkeys(part.strip() for part in str(text).split(';') if part.strip()))
