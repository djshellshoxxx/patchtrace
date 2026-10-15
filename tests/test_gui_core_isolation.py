"""GUI core (slice F1): the pure core never imports Qt, stays cheap to import, and keeps its layering (plan 6, 8.8).

`patchtrace/gui/*.py` (not the future `gui/qt/` subpackage) and `patchtrace/panel_manifest.py` are the pure core.
A subprocess proves the runtime claim; an AST scan proves the static ones, including imports that only run under
`TYPE_CHECKING` or inside a function.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / 'src'
PACKAGE = SRC / 'patchtrace'
GUI = PACKAGE / 'gui'
PURE_FILES = [*sorted(GUI.glob('*.py')), PACKAGE / 'panel_manifest.py']
QT_ROOTS = {'PySide6', 'shiboken6', 'PyQt5', 'PyQt6'}
HEAVY_ROOTS = {'networkx', 'rapidfuzz', 'pygments', 'yara', 'yara_x', 'pydantic'}


def dotted(path: Path) -> str:
    parts = path.relative_to(SRC).with_suffix('').parts
    return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)


def scan(path: Path):
    """Every import of a module as (absolute module, at module level, only under TYPE_CHECKING)."""
    package = dotted(path) if path.name == '__init__.py' else dotted(path).rpartition('.')[0]
    found = []

    def absolute(node: ast.ImportFrom) -> str:
        base = package.split('.')
        base = base[:len(base) - (node.level - 1)] if node.level else []
        return '.'.join([*base, *([node.module] if node.module else [])])

    def visit(nodes, in_function, type_checking):
        for node in nodes:
            if isinstance(node, ast.Import):
                found.extend((alias.name, not in_function, type_checking) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                found.append((absolute(node), not in_function, type_checking))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(node.body, True, type_checking)
            elif isinstance(node, ast.ClassDef):
                visit(node.body, in_function, type_checking)
            elif isinstance(node, ast.If):
                guarded = isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING'
                visit(node.body, in_function, type_checking or guarded)
                visit(node.orelse, in_function, type_checking)
            elif isinstance(node, (ast.Try, ast.With)):
                visit(node.body, in_function, type_checking)

    visit(ast.parse(path.read_text(encoding='utf-8')).body, False, False)
    return found


def test_the_pure_core_is_what_the_card_lists():
    names = {path.stem for path in GUI.glob('*.py')}
    assert {'__init__', 'anchors', 'projection', 'ports', 'registry', 'capabilities', 'state', 'text', 'theme_math',
            'shortcuts', 'cli'} <= names
    assert (PACKAGE / 'panel_manifest.py') in PURE_FILES


def test_gui_core_has_no_qt():
    """Qt is made unimportable, every pure module is imported, and neither Qt nor a UI module nor a heavy library has
    been loaded (the same gate keeps a panel spec cheap to import)."""
    modules = [dotted(path) for path in PURE_FILES]
    code = ('import importlib.abc, sys\n'
            'class Block(importlib.abc.MetaPathFinder):\n'
            '    def find_spec(self, name, path=None, target=None):\n'
            f'        if name.split(".")[0] in {sorted(QT_ROOTS)!r}: raise ImportError("blocked: " + name)\n'
            'sys.meta_path.insert(0, Block())\n'
            'for name in sys.argv[1:]:\n    __import__(name)\n'
            'bad = sorted(m for m in sys.modules if m.split(".")[0] in '
            f'{sorted(QT_ROOTS | HEAVY_ROOTS)!r} or m == "patchtrace.ui" or m.startswith(("patchtrace.ui_", '
            '"patchtrace.gui.qt")))\nprint("BAD", bad)\nraise SystemExit(90 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONUTF8='1')
    result = subprocess.run([sys.executable, '-c', code, *modules], capture_output=True, text=True, env=env,
                            timeout=120)
    assert result.returncode == 0 and 'BAD []' in result.stdout, (result.stdout, result.stderr)


def test_panel_specs_import_cheaply():
    """What a feature's `panel.py` pays for by importing `patchtrace.gui.registry`: standard library plus the pure
    core. No tooltip table, no models (so no pydantic), no CLI, no manifest."""
    code = ('import sys\nbefore = set(sys.modules)\nimport patchtrace.gui.registry\n'
            'print("\\n".join(sorted(set(sys.modules) - before)))\n')
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONUTF8='1')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0, result.stderr
    added = set(result.stdout.split())
    roots = {name.split('.')[0] for name in added}
    assert roots <= set(sys.stdlib_module_names) | {'patchtrace'}, sorted(roots - set(sys.stdlib_module_names))
    ours = {name for name in added if name.startswith('patchtrace')}
    assert {'patchtrace.gui.registry', 'patchtrace.gui.text'} <= ours
    assert not ours & {'patchtrace.tooltips', 'patchtrace.models', 'patchtrace.cli', 'patchtrace.gui.cli',
                       'patchtrace.panel_manifest'}


@pytest.mark.parametrize('path', PURE_FILES, ids=lambda path: dotted(path).removeprefix('patchtrace.'))
def test_no_pure_module_mentions_qt_a_ui_module_or_dynamic_imports(path):
    for module, _, _ in scan(path):
        root = module.split('.')[0]
        assert root not in QT_ROOTS, f'{path.name} imports {module}'
        assert module != 'patchtrace.ui' and not module.startswith(('patchtrace.ui_', 'patchtrace.gui.qt')), (
            f'{path.name} imports {module}')
        assert root != 'importlib', f'{path.name} imports importlib'
    names = {node.id for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(ast.parse(path.read_text(encoding='utf-8')))
              if isinstance(node, ast.Attribute)}
    assert not names & {'__import__', 'import_module'}, f'{path.name} imports dynamically'


def test_the_core_depends_on_no_feature_package():
    """Outside the core only `tooltips` (pure data), `models` (for typing) and, inside the verb's own functions,
    `cli` (it imports the adapters that import this) and the manifest are named, and never at import time."""
    allowed = {'patchtrace.tooltips', 'patchtrace.cli', 'patchtrace.models', 'patchtrace.panel_manifest'}
    for path in sorted(GUI.glob('*.py')):
        for module, module_level, typing_only in scan(path):
            if not module.startswith('patchtrace.') or module.startswith('patchtrace.gui'):
                continue
            assert module in allowed, f'{path.name} imports the feature module {module}'
            assert typing_only or not module_level, f'{path.name} imports {module} at import time'
            if module in ('patchtrace.cli', 'patchtrace.panel_manifest'):
                assert path.name == 'cli.py', f'{path.name} imports {module}'


def test_the_manifest_imports_no_feature_at_import_time():
    at_import = {module for module, module_level, _ in scan(PACKAGE / 'panel_manifest.py') if module_level}
    assert at_import == {'__future__', 'patchtrace.gui.registry'}


# Lower layers never import higher ones at module level, which makes the graph acyclic. Modules that a later slice
# adds to `gui/` are not ranked here and are not checked by this test.
RANK = {'text': 0, 'theme_math': 0, 'shortcuts': 0, 'projection': 0, 'capabilities': 1, 'state': 1, 'anchors': 1,
        'ports': 2, 'registry': 3, 'cli': 4}


def test_module_level_imports_only_point_down_the_layers():
    seen = 0
    for path in sorted(GUI.glob('*.py')):
        if path.stem not in RANK:
            continue
        for module, module_level, typing_only in scan(path):
            target = module.removeprefix('patchtrace.gui.') if module.startswith('patchtrace.gui.') else None
            if module_level and not typing_only and target in RANK:
                seen += 1
                assert RANK[path.stem] > RANK[target], f'{path.stem} imports {target} at import time'
    assert seen >= 8  # the graph is not vacuous
    assert set(RANK) <= {path.stem for path in GUI.glob('*.py')}
