"""Collect every `patchtrace.cli_commands` verb module (GUI plan 8.12, F19).

Verbs are found at run time by `pkgutil.iter_modules`, which PyInstaller's bytecode scan cannot see. The
isolated child of `collect_submodules` returns [] WITHOUT an error when it resolves another tree (an editable
install shadowing `--paths src`), so every verb file of THIS tree must be among the results. A tree without
verb files passes.
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# on_error='raise': a registry that fails to import fails the build instead of shipping a crashing exe
hiddenimports = collect_submodules('patchtrace.cli_commands', on_error='raise')
_files = (Path(__file__).resolve().parents[2] / 'src' / 'patchtrace' / 'cli_commands').glob('[!_]*.py')
_missing = {f'patchtrace.cli_commands.{path.stem}' for path in _files} - set(hiddenimports)
if _missing:
    raise RuntimeError(f'patchtrace.cli_commands did not collect {sorted(_missing)}; '
                       'refusing to build an exe without them')
