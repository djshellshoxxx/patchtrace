"""CI-checked inventory of every child launch (SPEC-28 §9 inv. 3 and 6; audit PS-9, PS-12, hazards 1/4/5/7).

Only `jobs.py` may hold a spawn primitive, so every child starts through `run_process`. Each call that reaches it
(a direct `run_process(...)` or an injected runner called with `cwd=` and `timeout_seconds=`) is a site here, with
its environment source, its output bound, its memory policy and whether it sits in a file workers may not edit.
A new site fails `test_discovered_sites_equal_the_inventory` until it is classified.
"""
from __future__ import annotations

import ast
import re
import threading
from functools import cache
from pathlib import Path
from typing import NamedTuple

import pytest

from patchtrace.backend import BackendConfig, build_child_env
from patchtrace.intelligence.tools import process
from patchtrace.rules import runner as rules_runner
from patchtrace.secondary import bindiff_probe, binexport_run, registry
from patchtrace.secondary.engine_env import engine_env

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src' / 'patchtrace'
SPAWN_MODULE = 'jobs.py'
FROZEN_FILES = frozenset({'backend.py'})  # its gaps are integrator asks (#121 ask D), tracked by strict xfails


class Site(NamedTuple):
    env: str      # the env= source; a bare local name is resolved to its assignment in the same function
    output: str   # max_output_bytes | check_output-files | tail-only:<why a kept tail suffices>
    memory: str   # cap | exempt:<repo-relative doc>#<text that doc contains>
    frozen: bool


JVM = 'exempt:docs/audits/process-supervision-20261014.md#Do not cap a JVM that way'
NO_INVENTED_CAP = 'exempt:docs/specs/architecture.md#No invented hard memory cap'
BINDIFF_D10 = 'exempt:docs/specs/bindiff-execution.md#| D10 | Memory cap | None in v1'
RZDIFF = 'exempt:docs/specs/multi-engine-orchestration.md#rz-diff has no memory cap in v1'
EXTRACTOR_JVM = 'exempt:docs/specs/unified-engine/03-extraction.md#NO memory_limit_bytes: RLIMIT_AS breaks JVM'
GHIDRIFF_8 = 'exempt:docs/audits/20261104-dispositions-121-116.md#Ghidriff run has no memory/output cap'
GHIDRA_ENV = "backend_module._environment(cfg, work / 'ghidra-settings')"

INVENTORY: dict[str, Site] = {
    'backend.py::_java_version': Site('_environment(config)', 'tail-only:java -version probe', JVM, True),
    'backend.py::_probe_backend': Site('_environment(config)', 'tail-only:15 s import probe, 16 KiB tail',
                                       NO_INVENTED_CAP, True),
    'backend.py::run_comparison': Site('_environment(config, ghidra_settings)', 'check_output-files', GHIDRIFF_8,
                                       True),
    # env is built by the caller with `process.tool_env`; memory is forwarded through **kwargs when configured
    'intelligence/tools/process.py::execute': Site('dict(env)', 'max_output_bytes', 'cap', False),
    'rules/runner.py::_run': Site('worker_env()', 'max_output_bytes', 'cap', False),
    'secondary/bindiff_probe.py::_run': Site('build_env(Path(argv[0]), workdir, environ=environ)',
                                             'tail-only:30 s version probe', BINDIFF_D10, False),
    'secondary/bindiff_run.py::execute': Site('build_env(Path(cap.path), workdir, environ=environ)',
                                              'check_output-files', BINDIFF_D10, False),
    'secondary/binexport_run.py::accept_binexport': Site('worker_env()', 'tail-only:own worker, result is a file',
                                                         'cap', False),
    # job.env / env come from the caller: `engine_env(os.environ, 'rz-diff')`
    'secondary/registry.py::RzDiffAdapter.run': Site('job.env', 'max_output_bytes', RZDIFF, False),
    'secondary/rzdiff.py::probe': Site('env', 'tail-only:30 s version probe', RZDIFF, False),
    'secondary/rzdiff.py::run_rzdiff': Site('env', 'max_output_bytes', RZDIFF, False),
    'unified/extract/runner.py::_spawn': Site(GHIDRA_ENV, 'check_output-files', EXTRACTOR_JVM, False),
    'unified/extract/runner.py::self_check': Site(GHIDRA_ENV, 'tail-only:120 s self-check, no target',
                                                  EXTRACTOR_JVM, False),
    'unified/pipeline.py::_spawn': Site(
        "{k: v for k, v in worker_env().items() if k != 'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'}",
        'tail-only:own worker, result is a file; check_output only forwards progress', 'cap', False),
}

# ---- scanners ------------------------------------------------------------------------------------------------------

SPAWN_MODULES = frozenset({'subprocess', 'multiprocessing'})
_OS_SPAWN = re.compile(r'system|popen|exec\w*|spawn\w*|posix_spawn\w*|startfile')


def spawn_primitives(source: str) -> list[str]:
    """Every way `source` could start a process without `run_process`, in source order."""
    tree = ast.parse(source)
    os_names = {'os'} | {a.asname for n in ast.walk(tree) if isinstance(n, ast.Import)
                         for a in n.names if a.name == 'os' and a.asname}
    found: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        hits: list[str] = []
        if isinstance(node, ast.Import):
            hits = [a.name for a in node.names if a.name.split('.')[0] in SPAWN_MODULES]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ''
            hits = [module] if module.split('.')[0] in SPAWN_MODULES else []
            hits += [f'{module}.{a.name}' for a in node.names
                     if a.name == 'QProcess' or (module == 'os' and _OS_SPAWN.fullmatch(a.name))]
        elif isinstance(node, ast.Attribute):
            if node.attr == 'QProcess' or (isinstance(node.value, ast.Name) and node.value.id in os_names
                                           and _OS_SPAWN.fullmatch(node.attr)):
                hits = [ast.unparse(node)]
        elif isinstance(node, ast.Name) and node.id == 'QProcess':
            hits = ['QProcess']
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and ast.unparse(node.func) in ('__import__', 'importlib.import_module', 'import_module') \
                and str(node.args[0].value).split('.')[0] in SPAWN_MODULES:
            hits = [f'{ast.unparse(node.func)}({node.args[0].value})']
        found += [(node.lineno, node.col_offset, hit) for hit in hits]
    return [hit for *_, hit in sorted(found)]


class LaunchSite(NamedTuple):
    call: ast.Call
    function: ast.FunctionDef | ast.AsyncFunctionDef | None

    @property
    def keywords(self) -> frozenset[str]:
        return frozenset(k.arg for k in self.call.keywords if k.arg)

    @property
    def splats(self) -> tuple[str, ...]:
        return tuple(ast.unparse(k.value) for k in self.call.keywords if k.arg is None)


def _is_launch(call: ast.Call) -> bool:
    func = call.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ''
    return name == 'run_process' or {'cwd', 'timeout_seconds'} <= {k.arg for k in call.keywords}


class _Finder(ast.NodeVisitor):
    def __init__(self, prefix: str):
        self.prefix, self.scope, self.functions = prefix, [], []
        self.sites: dict[str, LaunchSite] = {}

    def _enter(self, node, function: bool) -> None:
        self.scope.append(node.name)
        if function:
            self.functions.append(node)
        self.generic_visit(node)
        if function:
            self.functions.pop()
        self.scope.pop()

    def visit_ClassDef(self, node):
        self._enter(node, False)

    def visit_FunctionDef(self, node):
        self._enter(node, True)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if _is_launch(node):
            key, n = f'{self.prefix}::{".".join(self.scope)}', 2
            while key in self.sites:
                key, n = f'{self.prefix}::{".".join(self.scope)}#{n}', n + 1
            self.sites[key] = LaunchSite(node, self.functions[-1] if self.functions else None)
        self.generic_visit(node)


def launch_sites(source: str, prefix: str) -> dict[str, LaunchSite]:
    finder = _Finder(prefix)
    finder.visit(ast.parse(source))
    return finder.sites


@cache
def product_sites() -> dict[str, LaunchSite]:
    sites: dict[str, LaunchSite] = {}
    for path in sorted(SRC.rglob('*.py')):
        sites.update(launch_sites(path.read_text(encoding='utf-8'), path.relative_to(SRC).as_posix()))
    return sites


def env_source(site: LaunchSite) -> str:
    value = next((k.value for k in site.call.keywords if k.arg == 'env'), None)
    if value is None:
        return '<missing>'
    if isinstance(value, ast.Name) and site.function is not None:
        assigned = [n for n in ast.walk(site.function) if isinstance(n, ast.Assign) and n.lineno < site.call.lineno
                    and any(isinstance(t, ast.Name) and t.id == value.id for t in n.targets)]
        if assigned:
            return ast.unparse(max(assigned, key=lambda n: n.lineno).value)
    return ast.unparse(value)


def _forwards_memory(site: LaunchSite) -> bool:
    """`**kwargs` carrying `memory_limit_bytes`: the function assigns `kwargs['memory_limit_bytes']`."""
    if site.function is None:
        return False
    return any(isinstance(t, ast.Subscript) and ast.unparse(t.value) in site.splats
               and isinstance(t.slice, ast.Constant) and t.slice.value == 'memory_limit_bytes'
               for n in ast.walk(site.function) if isinstance(n, ast.Assign) for t in n.targets)


def output_matches(kind: str, site: LaunchSite) -> bool:
    names = site.keywords
    if kind == 'max_output_bytes':
        return 'max_output_bytes' in names
    if kind == 'check_output-files':
        return 'check_output' in names and 'max_output_bytes' not in names
    if kind.startswith('tail-only:') and kind.removeprefix('tail-only:').strip():
        return 'log_limit' in names and 'max_output_bytes' not in names
    return False


def memory_matches(policy: str, site: LaunchSite) -> bool:
    if policy == 'cap':
        return 'memory_limit_bytes' in site.keywords or _forwards_memory(site)
    if policy.startswith('exempt:'):
        doc, _, needle = policy.removeprefix('exempt:').partition('#')
        path = ROOT / doc
        return (bool(needle) and path.is_file() and needle in path.read_text(encoding='utf-8')
                and 'memory_limit_bytes' not in site.keywords and not site.splats)
    return False


# ---- the scanner itself (SYNTHETIC is only parsed, never executed) ----------------------------------------------

SYNTHETIC = '''\
import os, subprocess
import os as o
import multiprocessing.pool
from subprocess import run
from os import execv, posix_spawnp, getcwd
from PySide6.QtCore import QProcess
import importlib
os.system('x'); os.popen('x'); o.spawnl(0, 'x'); os.startfile('x'); os.execvpe('x', [], {})
QtCore.QProcess(); __import__('subprocess'); importlib.import_module('multiprocessing.pool')
os.getpid(); os.path.join('a'); run_process(['x'], cwd=1, timeout_seconds=1)
'''


def test_scanner_flags_every_spawn_primitive_on_a_synthetic_source():
    assert spawn_primitives(SYNTHETIC) == [
        'subprocess', 'multiprocessing.pool', 'subprocess', 'os.execv', 'os.posix_spawnp', 'PySide6.QtCore.QProcess',
        'os.system', 'os.popen', 'o.spawnl', 'os.startfile', 'os.execvpe', 'QtCore.QProcess',
        '__import__(subprocess)', 'importlib.import_module(multiprocessing.pool)']
    assert spawn_primitives('import os\nos.getpid()\nfrom os import path\nexecutor.submit(f)\n') == []


def test_only_jobs_holds_a_spawn_primitive():
    found = {path.relative_to(SRC).as_posix(): hits for path in sorted(SRC.rglob('*.py'))
             if (hits := spawn_primitives(path.read_text(encoding='utf-8')))}
    assert 'subprocess' in found.pop(SPAWN_MODULE)  # the scanner sees the one legitimate spawner
    assert found == {}


def test_site_finder_on_a_synthetic_source():
    source = ('def a(env):\n    env = clean()\n    runner(["x"], cwd=c, env=env, timeout_seconds=1)\n'
              'class K:\n    def b(self):\n        run_process(argv, env=job.env)\n        f(cwd=c)\n'
              '        r(cwd=c, timeout_seconds=2, env=x)\n')
    sites = launch_sites(source, 'm.py')
    assert list(sites) == ['m.py::a', 'm.py::K.b', 'm.py::K.b#2']
    assert [env_source(s) for s in sites.values()] == ['clean()', 'job.env', 'x']


# ---- the inventory -------------------------------------------------------------------------------------------------

def test_discovered_sites_equal_the_inventory():
    discovered = set(product_sites())
    assert sorted(discovered - set(INVENTORY)) == [], 'unclassified child launch: add an INVENTORY row'
    assert sorted(set(INVENTORY) - discovered) == [], 'stale INVENTORY row'


@pytest.mark.parametrize('key', list(INVENTORY), ids=list(INVENTORY))
def test_declared_output_bound_matches_the_call(key):
    site = product_sites()[key]
    assert output_matches(INVENTORY[key].output, site), sorted(site.keywords)


@pytest.mark.parametrize('key', list(INVENTORY), ids=list(INVENTORY))
def test_declared_memory_policy_matches_the_call(key):
    site = product_sites()[key]
    assert memory_matches(INVENTORY[key].memory, site), (sorted(site.keywords), site.splats)


@pytest.mark.parametrize('key', list(INVENTORY), ids=list(INVENTORY))
def test_env_source_matches_the_row(key):
    assert env_source(product_sites()[key]) == INVENTORY[key].env


def test_frozen_flag_marks_exactly_the_frozen_files():
    assert {k for k, row in INVENTORY.items() if row.frozen} == {k for k in INVENTORY
                                                                 if k.split('::')[0] in FROZEN_FILES}


# ---- allow-list builders -------------------------------------------------------------------------------------------

SENTINELS = ('GH_TOKEN', 'NVD_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'HTTPS_PROXY',
             'LD_PRELOAD', 'JAVA_TOOL_OPTIONS', 'PYTHONSTARTUP')


def _base() -> dict[str, str]:
    secrets = {spelling: f'pt-sentinel-{name}' for name in SENTINELS for spelling in (name, name.lower())}
    return {'PATH': '/usr/bin', 'HOME': '/home/u', 'SystemRoot': 'C:\\Windows', 'TEMP': '/tmp', **secrets}


def _builders(tmp_path: Path):
    exe, cfg = tmp_path / 'tool', BackendConfig(python_executable='/py', ghidra_dir=str(tmp_path))
    yield 'rules-worker', lambda base: rules_runner.worker_env(base)
    yield 'binexport-worker', lambda base: binexport_run.worker_env(base)
    for windows in (False, True):
        flavour = 'win' if windows else 'posix'
        yield f'engine-rz-{flavour}', lambda base, w=windows: engine_env(base, 'rz-diff', windows=w)
        yield f'engine-bd-{flavour}', lambda base, w=windows: engine_env(base, 'bindiff', windows=w,
                                                                         workdir=tmp_path, executable=exe)
        yield f'bindiff-probe-{flavour}', lambda base, w=windows: bindiff_probe.build_env(
            exe, tmp_path, os_name='nt' if w else 'posix', environ=base)
        yield f'tool-env-{flavour}', lambda base, w=windows: process.tool_env(exe, tmp_path, environ=base, windows=w)
        for tool in ('ghidra', 'rizin'):
            yield f'child-{tool}-{flavour}', lambda base, w=windows, t=tool: build_child_env(
                base, cfg, None, symbol_downloads=False, for_tool=t, windows=w)


BUILDER_IDS = [name for name, _ in _builders(Path('.'))]


@pytest.mark.parametrize('builder', BUILDER_IDS, ids=BUILDER_IDS)
def test_sentinel_secrets_never_survive_an_allow_list(builder, tmp_path):
    build = dict(_builders(tmp_path))[builder]
    env = build(_base())
    assert not {k for k in env if k.upper() in SENTINELS}
    assert not [k for k, v in env.items() if 'pt-sentinel' in v]
    assert env  # the builder did produce an environment


# ---- PS-9 ----------------------------------------------------------------------------------------------------------

def test_ps9_relative_which_result_is_unsupported_and_never_spawns(monkeypatch):
    """On Windows `shutil.which` consults the cwd first and can return `.\\rz-diff.exe` (a planted binary)."""
    probed: list = []
    monkeypatch.setattr(registry.shutil, 'which', lambda name, path=None: '.\\rz-diff.exe')
    monkeypatch.setattr(registry.rzdiff, 'probe', lambda *a, **k: probed.append(a))
    cap = registry.RzDiffAdapter().probe({'PATH': '.'}, threading.Event())
    assert (cap.supported, cap.path, probed) == (False, '.\\rz-diff.exe', [])
    assert 'not found' in (cap.reason or '')
