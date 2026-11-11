"""kev/1 import rules (plan section 6): the pure modules import no Qt, network, sqlite or ranking code, read no
clock and reach no sibling package except the identity and tooltip data modules. KEV can therefore never alter a
ranking."""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import patchtrace

PACKAGE = Path(patchtrace.__file__).resolve().parent
KEV = PACKAGE / 'kev'
SRC = str(PACKAGE.parent)
NOT_PURE = {'transport', 'service', 'cli', 'project_context'}        # later slices: network, a store, the project
FORBIDDEN = {'PySide6', 'shiboken6', 'urllib', 'urllib3', 'socket', '_socket', 'sqlite3', '_sqlite3', 'ssl', 'http',
             'ftplib', 'smtplib', 'subprocess', 'ctypes', 'requests', 'httpx'}
# At run time pydantic loads some of the modules above by itself (pathlib imports urllib.parse and its schema building
# imports socket on Python 3.12), so the process-wide check names the ones that can actually do network I/O, plus Qt
# and sqlite; the source check above covers every spelling in the kev files themselves.
NEVER_LOADED = {'PySide6', 'shiboken6', 'sqlite3', '_sqlite3', 'ssl', 'http', 'urllib3', 'requests', 'httpx',
                'ftplib', 'smtplib'}
NEVER_LOADED_MODULES = {'urllib.request', 'urllib.response'}
ALLOWED_SIBLINGS = {'patchtrace.enrichment.identity', 'patchtrace.tooltips'}
PANEL_SIBLINGS = {'patchtrace.gui.registry', 'patchtrace.gui.text', 'patchtrace.ui_kev'}  # PanelSpec declaration + lazy factory
CLOCK_CALLS = {'now', 'utcnow', 'today', 'monotonic', 'perf_counter', 'time_ns'}
RANKING_MODULES = ('patchtrace.enrichment.ranking', 'patchtrace.enrichment.cve', 'patchtrace.enrichment.signals',
                   'patchtrace.enrichment.pipeline', 'patchtrace.enrichment.views', 'patchtrace.evidence')


def pure_modules() -> list[str]:
    return sorted(path.stem for path in KEV.glob('*.py') if path.stem not in NOT_PURE and path.stem != '__init__')


def imports_of(path: Path, module: str) -> list[str]:
    """Absolute dotted names imported anywhere in the file, lazy imports and TYPE_CHECKING blocks included."""
    package = module.split('.')[:-1]
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[:len(package) - (node.level - 1)] if node.level else []
            name = '.'.join([*base, *(node.module.split('.') if node.module else [])]) if node.level else node.module
            found.append(name)
            found += [f'{name}.{alias.name}' for alias in node.names]
    return found


def test_the_pure_module_list_is_what_the_plan_names():
    named = {'contracts', 'limits', 'parse', 'join', 'view_model', 'ports', 'teach', 'tooltip_entries', 'store'}
    assert named <= set(pure_modules())


def test_kev_modules_import_without_qt_network_or_sqlite():
    code = textwrap.dedent(f'''
        import importlib, json, sys
        sys.path.insert(0, {SRC!r})
        for name in {pure_modules()!r}:
            importlib.import_module('patchtrace.kev.' + name)
        top = lambda module: module.split('.')[0]
        never, exact = {sorted(NEVER_LOADED)!r}, {sorted(NEVER_LOADED_MODULES)!r}
        print(json.dumps({{
            'loaded': sorted(m for m in sys.modules if top(m) in never or m in exact),
            'ranking': [m for m in {RANKING_MODULES!r} if m in sys.modules]}}))
    ''')
    result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'loaded': [], 'ranking': []}


@pytest.mark.parametrize('name', pure_modules())
def test_pure_modules_import_only_what_they_may(name):
    for target in imports_of(KEV / f'{name}.py', f'patchtrace.kev.{name}'):
        top = target.split('.')[0]
        assert top not in FORBIDDEN, f'{name} imports {target}'
        if top == 'patchtrace' and not target.startswith('patchtrace.kev'):
            allowed = ALLOWED_SIBLINGS | (PANEL_SIBLINGS if name == 'panel' else set())
            assert any(target == ok or target.startswith(ok + '.') or ok.startswith(target + '.')
                       for ok in allowed), f'{name} reaches {target}'
        assert not any(target == rank or target.startswith(rank + '.') for rank in RANKING_MODULES), (name, target)
        assert not target.startswith('patchtrace.ui') or (name == 'panel' and target.startswith('patchtrace.ui_kev')), (name, target)


@pytest.mark.parametrize('name', pure_modules())
def test_pure_modules_read_no_clock(name):
    tree = ast.parse((KEV / f'{name}.py').read_text(encoding='utf-8'))
    calls = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in CLOCK_CALLS]
    time_module = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr == 'time'
                   and isinstance(node.value, ast.Name) and node.value.id == 'time']
    assert not calls and not time_module, f'{name} reads the clock: {calls + time_module}'


def test_the_port_offers_no_score_or_ranking_surface():
    from patchtrace.kev.ports import KevLookupPort
    names = {name for name in vars(KevLookupPort) if not name.startswith('_')}
    assert names >= {'meta', 'cell', 'lookup', 'summary_line'}
    assert not {name for name in names if any(word in name for word in ('score', 'rank', 'weight', 'boost'))}
