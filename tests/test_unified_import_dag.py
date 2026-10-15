"""SPEC-31 import rules (01 s3): no Qt, network or process modules under `unified/`, spawning only through
`jobs.run_process` in `pipeline.py`, a layered import order, and no other package importing `unified`."""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

import patchtrace
from patchtrace.unified import worker

PACKAGE = Path(patchtrace.__file__).resolve().parent
UNIFIED = PACKAGE / 'unified'
FORBIDDEN = {'PySide6', 'shiboken6', 'urllib', 'urllib3', 'http', 'socket', 'ssl', 'ftplib', 'smtplib', 'xmlrpc',
             'requests', 'httpx', 'aiohttp', 'subprocess', 'ctypes', 'ghidriff', 'pyghidra', 'jpype'}
FORBIDDEN_OS_CALLS = ('system', 'popen', 'spawn', 'exec', 'fork', 'startfile')
SPAWN_MODULES = {'patchtrace.jobs'}
MAY_SPAWN = {'pipeline', 'extract/runner'}
EXEMPT = {'extract/ghidra_script'}  # runs inside the external Python and never imports patchtrace (S1)
# 01 s3 rule 3, completed with the modules of this slice: a module may import only modules of a lower or equal rank.
RANK = {'limits': 0, 'contracts': 1, 'addressing': 1, 'exchange': 1, 'keys': 2, 'registry': 2, 'store': 3,
        'read_text': 3, 'sources': 4, 'fusion': 5, 'facts': 6, 'compute': 7, 'pipeline': 8, 'read_model': 9,
        'worker': 9, 'cli': 10}
NEVER = {('ladder', 'fusion'), ('ladder', 'facts'), ('fusion', 'ladder'), ('sources', 'fusion'),
         ('sources', 'facts'), ('fusion', 'facts'), ('pipeline', 'worker'), ('pipeline', 'cli'),
         ('compute', 'pipeline'), ('compute', 'worker')}


def files():
    return sorted(p for p in UNIFIED.rglob('*.py') if '__pycache__' not in p.parts)


def dotted(path: Path) -> str:
    parts = list(path.relative_to(PACKAGE.parent).with_suffix('').parts)
    if parts[-1] == '__init__':
        parts.pop()
    return '.'.join(parts)


def is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == 'TYPE_CHECKING') or (
        isinstance(test, ast.Attribute) and test.attr == 'TYPE_CHECKING')


def import_time_nodes(body):
    """Statements that run when the module is imported: not function or class bodies, not `if TYPE_CHECKING:`."""
    for node in body:
        if isinstance(node, ast.If):
            yield from import_time_nodes([] if is_type_checking(node.test) else node.body)
            yield from import_time_nodes(node.orelse)
        elif isinstance(node, ast.Try):
            for part in (node.body, *(h.body for h in node.handlers), node.orelse, node.finalbody):
                yield from import_time_nodes(part)
        elif isinstance(node, ast.With):
            yield from import_time_nodes(node.body)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            yield node


def imports(module: str, is_package: bool, source: str, *, import_time_only: bool = False):
    """Absolute dotted names imported in `source`: everywhere (lazy imports inside functions included), or with
    `import_time_only` just those that run when the module is imported (what an import cycle needs)."""
    package = module.split('.') if is_package else module.split('.')[:-1]
    found = []
    tree = ast.parse(source)
    for node in (import_time_nodes(tree.body) if import_time_only else ast.walk(tree)):
        if isinstance(node, ast.Import):
            found += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = package[:len(package) - (node.level - 1)] if node.level else []
            name = '.'.join([*base, *(node.module.split('.') if node.module else [])]) if node.level else node.module
            found.append(name)
            found += [f'{name}.{alias.name}' for alias in node.names]
    return found


def local_module(name: str) -> str | None:
    """`patchtrace.unified.sources.ghidriff` -> `sources/ghidriff`, if it is a module of this package."""
    if not name.startswith('patchtrace.unified.'):
        return None
    relative = name[len('patchtrace.unified.'):].replace('.', '/')
    if (UNIFIED / f'{relative}.py').exists() or (UNIFIED / relative / '__init__.py').exists():
        return relative
    return None


def rank_group(relative: str) -> str:
    return relative.split('/')[0]


def violations(module: str, relative: str, is_package: bool, source: str) -> list[str]:
    found = []
    for name in imports(module, is_package, source):
        top = name.split('.')[0]
        if relative not in EXEMPT and top in FORBIDDEN:
            found.append(f'{relative} imports {name}')
        if relative not in EXEMPT and (name == 'patchtrace.ui' or name.startswith(('patchtrace.ui.', 'patchtrace.ui_'))):
            found.append(f'{relative} imports the GUI module {name}')
        if name in SPAWN_MODULES and relative not in MAY_SPAWN:
            found.append(f'{relative} imports {name}, but only {sorted(MAY_SPAWN)} may spawn processes')
        target = local_module(name)
        if target is None:
            continue
        here, there = rank_group(relative), rank_group(target)
        if (here, there) in NEVER:
            found.append(f'{relative} must never import {target}')
        if here in RANK and there in RANK and RANK[there] > RANK[here]:
            found.append(f'{relative} (layer {RANK[here]}) imports {target} (layer {RANK[there]})')
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'os'
                and node.attr.startswith(FORBIDDEN_OS_CALLS)):
            found.append(f'{relative} uses os.{node.attr}')
    return found


def scan() -> list[str]:
    found = []
    for path in files():
        relative = path.relative_to(UNIFIED).with_suffix('').as_posix()
        relative = relative.removesuffix('/__init__') if relative.endswith('/__init__') else relative
        if relative == '__init__':
            relative = ''
        found += violations(dotted(path), relative or '__init__', path.name == '__init__.py',
                            path.read_text(encoding='utf-8'))
    return found


def test_unified_import_dag():
    assert scan() == []


def test_the_checker_can_fail():
    """A rule check that cannot fail proves nothing: feed it violations."""
    bad = {
        ('sources/ghidriff', 'import subprocess'): 'subprocess',
        ('facts/pseudo', 'import socket'): 'socket',
        ('keys', 'from PySide6 import QtCore'): 'PySide6',
        ('contracts', 'from ..ui import MainWindow'): 'GUI module',
        ('fusion/arbiter', 'from ..facts import verdict'): 'must never import facts',
        ('sources/manual', 'from .. import pipeline'): 'layer',
        ('store', 'from ..jobs import run_process'): 'may spawn',
        ('compute', 'import os\nos.system("x")'): 'os.system',
        ('exchange', 'import ctypes'): 'ctypes',
    }
    for (relative, source), expected in bad.items():
        module = 'patchtrace.unified.' + relative.replace('/', '.')
        found = violations(module, relative, False, source)
        assert any(expected in item for item in found), (relative, source, found)
    allowed = violations('patchtrace.unified.pipeline', 'pipeline', False, 'from ..jobs import run_process')
    assert allowed == []
    assert violations('patchtrace.unified.extract.ghidra_script', 'extract/ghidra_script', False,
                      'import subprocess') == []


def test_the_layers_cover_the_modules_of_this_slice():
    top = {path.relative_to(UNIFIED).parts[0].removesuffix('.py') for path in files()}
    owned = {'limits', 'contracts', 'addressing', 'exchange', 'keys', 'registry', 'store', 'read_text', 'sources',
             'fusion', 'facts', 'compute', 'pipeline', 'read_model', 'worker', 'cli'}
    assert owned <= top and owned <= set(RANK)


def test_the_cycle_scan_counts_what_runs_at_import_time_only():
    """A lazy import (inside a function) and a type-checking import never form an import cycle; a plain one does."""
    source = ('from __future__ import annotations\nfrom typing import TYPE_CHECKING\nfrom . import plain\n'
              'if TYPE_CHECKING:\n    from . import typed\nelse:\n    from . import fallback\n'
              'try:\n    from . import guarded\nexcept ImportError:\n    guarded = None\n'
              'def later():\n    from . import lazy\n')
    seen = imports('patchtrace.unified.one', False, source, import_time_only=True)
    assert 'patchtrace.unified.plain' in seen and 'patchtrace.unified.fallback' in seen
    assert 'patchtrace.unified.guarded' in seen
    assert 'patchtrace.unified.typed' not in seen and 'patchtrace.unified.lazy' not in seen
    everything = imports('patchtrace.unified.one', False, source)
    assert 'patchtrace.unified.typed' in everything and 'patchtrace.unified.lazy' in everything


def test_there_is_no_import_cycle():
    graph: dict[str, set[str]] = {}
    for path in files():
        relative = path.relative_to(UNIFIED).with_suffix('').as_posix().removesuffix('/__init__')
        targets = {local_module(n) for n in imports(dotted(path), path.name == '__init__.py',
                                                    path.read_text(encoding='utf-8'), import_time_only=True)}
        graph[relative] = {t for t in targets if t and t != relative}
    state: dict[str, int] = {}

    def visit(node, trail):
        state[node] = 1
        for nxt in sorted(graph.get(node, ())):
            if state.get(nxt) == 1:
                raise AssertionError(' -> '.join([*trail, node, nxt]))
            if nxt not in state:
                visit(nxt, [*trail, node])
        state[node] = 2
    for module in sorted(graph):
        if module not in state:
            visit(module, [])


def test_unified_has_no_qt():
    """Every module imports with PySide6 unavailable, and importing them all loads no Qt and no GUI module."""
    modules = sorted(dotted(p).removesuffix('.__init__') for p in files() if p.name != 'ghidra_script.py')
    code = ('import importlib, sys\nsys.modules["PySide6"] = None\n'
            'for name in sys.argv[1:]:\n    importlib.import_module(name)\n'
            'bad = sorted(m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui")) '
            'and sys.modules[m] is not None)\nprint("BAD", bad)\nraise SystemExit(90 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(PACKAGE.parent), PYTHONUTF8='1')
    result = subprocess.run([sys.executable, '-c', code, *modules], capture_output=True, text=True, env=env,
                            timeout=120)
    assert result.returncode == 0 and 'BAD []' in result.stdout, (result.stdout, result.stderr)


def test_no_other_package_imports_unified():
    """01 s3 rule 4: secondary, enrichment, calibration and nway are read-only dependencies of unified."""
    offenders = []
    for package in ('secondary', 'enrichment', 'calibration', 'nway'):
        for path in sorted((PACKAGE / package).rglob('*.py')):
            names = imports(dotted(path), path.name == '__init__.py', path.read_text(encoding='utf-8'))
            offenders += [f'{path.name} imports {n}' for n in names
                          if n == 'patchtrace.unified' or n.startswith('patchtrace.unified.')]
    assert offenders == []


def test_the_frozen_self_check_lists_every_module_of_the_package():
    """`worker.MODULES` is the one list that the frozen smoke (`unified _worker --self-check`) imports: it must name
    every module on disk, so a new module cannot be forgotten and a removed one cannot linger. The extractor script is
    the one exception: it runs in the external Python and PatchTrace never imports it."""
    on_disk = {dotted(path).removeprefix('patchtrace.unified.') for path in files()
               if path.name != 'ghidra_script.py' and dotted(path) != 'patchtrace.unified'}
    assert on_disk == set(worker.MODULES)


def test_no_module_reads_a_private_name_of_a_sibling_module():
    """The read layer once reached into `store._lines`: a reader that two modules share is public API or it is not
    shared (`store.part_lines`, `store.parse_line`)."""
    found = []
    for path in files():
        source = path.read_text(encoding='utf-8')
        siblings = {name.rsplit('.', 1)[-1] for name in imports(dotted(path), path.name == '__init__.py', source)
                    if local_module(name) is not None}
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in siblings
                    and node.attr.startswith('_') and not node.attr.startswith('__')):
                found.append(f'{path.name}:{node.lineno} {node.value.id}.{node.attr}')
    assert found == []


@pytest.mark.parametrize('name', ['contracts', 'limits', 'keys', 'exchange', 'addressing'])
def test_the_lowest_layers_import_nothing_heavy(name):
    """The parser registers `unified` on every CLI call and the contracts are imported by everything: no engine
    code, no project database and no process helper below the compute layer's inputs."""
    path = UNIFIED / f'{name}.py'
    names = imports(dotted(path), False, path.read_text(encoding='utf-8'))
    assert not [n for n in names if n.startswith(('patchtrace.jobs', 'patchtrace.service', 'patchtrace.unified.pipeline',
                                                   'patchtrace.unified.compute', 'patchtrace.unified.sources'))]
