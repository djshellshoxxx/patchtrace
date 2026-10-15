"""Collect every `patchtrace.unified` module (SPEC-31): the frozen `unified _worker --self-check` imports them all by name
(`worker.MODULES`), so PyInstaller's bytecode scan cannot see the ones that only the worker loads (`ir.cfg` was missing
from the first frozen build that ran the self-check). The names come from this tree's files, not from
`collect_submodules`: that helper imports the package in an isolated child process and silently returns [] when a stale
editable install elsewhere shadows the source tree. The extractor script runs in the external Python and is never imported.
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2] / 'src'
_PACKAGE = _ROOT / 'patchtrace' / 'unified'
hiddenimports = sorted(
    '.'.join(path.relative_to(_ROOT).with_suffix('').parts).removesuffix('.__init__')
    for path in _PACKAGE.rglob('*.py') if path.name != 'ghidra_script.py')
if not hiddenimports:
    raise SystemExit(f'PT-BUILD: no unified modules found under {_PACKAGE}; refusing to build the package')
