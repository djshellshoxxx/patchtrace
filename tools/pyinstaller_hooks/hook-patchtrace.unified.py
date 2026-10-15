"""Collect every submodule of `patchtrace.unified` (the frozen `unified _worker --self-check` imports all of them).

The unified engine imports most of its modules lazily (worker, ladder, ir, facts), which PyInstaller's static scan
misses; the Windows frozen smoke then fails with `ModuleNotFoundError: patchtrace.unified.ir.cfg`. As in the
cli_commands hook, `on_error='raise'` fails the build instead of shipping an exe that crashes, and the files of THIS
tree must all be among the results (an editable install elsewhere can make the isolated child resolve another tree).
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules('patchtrace.unified', on_error='raise')
_root = Path(__file__).resolve().parents[2] / 'src' / 'patchtrace' / 'unified'
_missing = {'patchtrace.unified.' + '.'.join(path.relative_to(_root).with_suffix('').parts)
            for path in _root.rglob('*.py')
            if path.name != '__init__.py' and 'extract/ghidra_script' not in path.as_posix()} - set(hiddenimports)
if _missing:
    raise RuntimeError(f'patchtrace.unified did not collect {sorted(_missing)}; refusing to build an exe without them')
