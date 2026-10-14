"""The single child-environment allow-list for secondary engines (SPEC-28 §9.6, SPEC-29 §4.2). Pure, no Qt.

Every engine environment is built here; nothing else in `secondary/` filters `os.environ`.
- `rz-diff`: the audited `backend.build_child_env(for_tool='rizin')` allow-list (SPEC-07h H7), so it keeps
  the same platform variables (PATHEXT, ComSpec, TMPDIR, LANG, LC_*, ...) plus RZ_PREFIX/RZ_LIBR_PLUGINS and
  drops credentials, proxies, Java and Python variables.
- `bindiff`: built from scratch around a private working directory (HOME/APPDATA/ProgramData redirected so
  user and machine BinDiff config cannot change matching); only SystemRoot/SystemDrive/windir are copied.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from ..backend import BackendConfig, build_child_env

EnvEngine = Literal['rz-diff', 'bindiff']
_RIZIN_CONFIG = BackendConfig(python_executable='', ghidra_dir='')  # no passthrough, no private Java


def engine_env(base: Mapping[str, str], engine: EnvEngine, *, windows: bool | None = None,
               workdir: Path | None = None, executable: Path | str | None = None) -> dict[str, str]:
    windows = os.name == 'nt' if windows is None else windows
    if engine == 'rz-diff':
        return build_child_env(base, _RIZIN_CONFIG, None, symbol_downloads=False, for_tool='rizin',
                               windows=windows)
    if engine == 'bindiff':
        if workdir is None or executable is None:
            raise ValueError('bindiff environment needs the private workdir and the executable path')
        return _bindiff_env(base, Path(executable), Path(workdir), windows)
    raise ValueError(f'unknown engine {engine!r}')


def _bindiff_env(base: Mapping[str, str], executable: Path, workdir: Path, windows: bool) -> dict[str, str]:
    home, tmp = workdir / 'home', workdir / 'tmp'
    if not windows:
        exe_dir = str(executable.parent)
        return {'PATH': f'{exe_dir}:/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(tmp),
                'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'XDG_CONFIG_HOME': str(home / '.config')}
    upper = {k.upper(): v for k, v in base.items()}
    system_root = upper.get('SYSTEMROOT') or upper.get('WINDIR')
    if not system_root:
        raise OSError('SystemRoot is not set; Windows DLL loading would fail')
    exe_dir = str(executable.parent)
    env = {'SystemRoot': system_root, 'windir': upper.get('WINDIR', system_root),
           'PATH': f'{exe_dir};{system_root}\\System32', 'TEMP': str(tmp), 'TMP': str(tmp),
           'USERPROFILE': str(home), 'APPDATA': str(home / 'AppData' / 'Roaming'),
           'LOCALAPPDATA': str(home / 'AppData' / 'Local'), 'PROGRAMDATA': str(workdir / 'programdata')}
    if upper.get('SYSTEMDRIVE'):
        env['SystemDrive'] = upper['SYSTEMDRIVE']
    return env
