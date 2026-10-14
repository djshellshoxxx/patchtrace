"""Portable fake engine executables: a Python script behind a native launcher (shebang on POSIX, .cmd on Windows).

The launcher is a real file with an absolute path, so `run_process` spawns it exactly like a vendor binary,
including Job Object / process-group containment of the Python child it starts.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def make_fake_exe(directory: Path, name: str, source: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    python = Path(sys.executable).resolve()
    if os.name == 'nt':
        script = directory / f'{name}.py'
        script.write_text(source, encoding='utf-8')
        launcher = directory / f'{name}.cmd'
        launcher.write_text(f'@"{python}" "{script}" %*\r\n', encoding='utf-8')
        return launcher
    launcher = directory / name
    launcher.write_text(f'#!{python}\n{source}', encoding='utf-8')
    launcher.chmod(0o755)
    return launcher
