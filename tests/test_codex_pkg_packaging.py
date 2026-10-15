"""Static packaging checks for codex-packaging-1.md; never freeze or run binaries."""
from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def source(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


def tree(relative):
    return ast.parse(source(relative), filename=relative)


def function(relative, name):
    return next(node for node in tree(relative).body
                if isinstance(node, ast.FunctionDef) and node.name == name)


def assignment(relative, name):
    return next(node.value for node in tree(relative).body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))


def manifest():
    return tomllib.loads(source('pyproject.toml'))


def runtime_requirements():
    project = manifest()['project']
    return project['dependencies'] + [requirement for extra in ('search', 'rules')
                                      for requirement in project['optional-dependencies'][extra]]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-9')
def test_runtime_requirements_have_exact_pins():
    loose = [requirement for requirement in runtime_requirements()
             if not re.fullmatch(r'[\w.-]+==[^*,;\s]+', requirement)]
    assert not loose, loose


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-10')
def test_all_declared_dependencies_have_pin_or_upper_bound():
    document = manifest()
    requirements = document['build-system']['requires'] + document['project']['dependencies']
    requirements += [requirement for extra in document['project']['optional-dependencies'].values()
                     for requirement in extra]
    loose = [requirement for requirement in requirements
             if not re.search(r'==[^*,;\s]+|<', requirement)]
    assert not loose, loose


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-11')
def test_optional_runtime_dependencies_have_notice_rows():
    rows = '\n'.join(line.lower() for line in source('docs/notices.md').splitlines()
                     if line.startswith('|'))
    names = ast.literal_eval(assignment('tools/build_linux.py', 'OPTIONAL_DISTRIBUTIONS'))
    assert all(name.lower() in rows for name in names), names


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-12')
def test_license_copy_loops_require_nonempty_license_sets():
    permissive = []
    for path in ('tools/build_linux.py', 'tools/build_windows.py'):
        for node in ast.walk(function(path, 'main')):
            if not isinstance(node, ast.For) or not isinstance(node.iter, ast.BoolOp):
                continue
            values = node.iter.values
            if (isinstance(node.iter.op, ast.Or) and len(values) == 2
                    and isinstance(values[0], ast.Attribute) and values[0].attr == 'files'
                    and isinstance(values[1], ast.List) and not values[1].elts):
                permissive.append(f'{path}:{node.lineno}')
    assert not permissive, permissive


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-13')
def test_full_payload_validation_parses_manifest():
    functions = [function('tools/build_linux.py', name) for name in ('payload_problems', 'attach_backend')]
    calls = [node.func for func in functions for node in ast.walk(func) if isinstance(node, ast.Call)]
    # Currently there is no JSON/strict verifier call at all. A repair should use
    # the canonical validator, with behavioral tests, rather than an ad hoc parser.
    validates = any((isinstance(call, ast.Attribute) and call.attr in {'load', 'loads', 'model_validate'})
                    or (isinstance(call, ast.Name) and call.id in
                        {'validate_manifest', 'verify_bundle', 'inspect_offline_bundle'}) for call in calls)
    assert validates, 'Backend attachment checks presence but never parses/verifies the manifest'


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-14')
def test_linux_package_runs_full_cli_smoke():
    workflow = source('.github/workflows/qa-windows.yml')
    linux = workflow.split('  linux-package:\n', 1)[1].split('  # Decides', 1)[0]
    assert 'frozen_smoke' in linux or 'frozen_smoke' in source('tools/build_linux.py')


@pytest.mark.xfail(strict=True, raises=AssertionError, reason='CODEX-15')
def test_full_bundle_pin_has_no_other_gpl_components():
    pins = json.loads(source('tools/backend_pin.json'))

    def forbidden(node, path=''):
        findings = []
        if isinstance(node, dict):
            spdx = node.get('spdx', '')
            if re.search(r'(?<!L)\b(?:A?GPL)-', spdx) and not path.startswith('ghidriff'):
                findings.append((path, spdx))
            for key, value in node.items():
                findings.extend(forbidden(value, f'{path}.{key}' if path else key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                findings.extend(forbidden(value, f'{path}[{index}]'))
        return findings

    assert not forbidden(pins), forbidden(pins)


def test_core_runtime_declarations_are_exactly_pinned():
    for requirement in manifest()['project']['dependencies']:
        assert re.fullmatch(r'[\w.-]+==[^*,;\s]+', requirement), requirement


def test_frozen_smoke_enumerates_registry_names():
    commands = assignment('tools/frozen_smoke.py', 'COMMANDS')
    assert isinstance(commands, ast.Call) and isinstance(commands.func, ast.Name)
    assert commands.func.id == 'names'
    registry = function('src/patchtrace/cli_commands/__init__.py', 'names')
    identifiers = {node.id for node in ast.walk(registry) if isinstance(node, ast.Name)}
    assert {'COMMANDS', '_modules'} <= identifiers
    smoke = function('tools/frozen_smoke.py', 'run_checks')
    assert any(isinstance(node, ast.For) and isinstance(node.iter, ast.Name)
               and node.iter.id == 'COMMANDS' for node in ast.walk(smoke))


def test_dynamic_loader_hooks_cover_known_runtime_imports():
    imports = ast.literal_eval(assignment(
        'tools/pyinstaller_hooks/hook-patchtrace.secondary.binexport_proto.py', 'hiddenimports'))
    assert {'google._upb._message', 'google.protobuf.descriptor_pool',
            'google.protobuf.message_factory'} <= set(imports)
    optional = source('tools/pyinstaller_hooks/hook-patchtrace.optional_deps.py')
    assert "collect_submodules('rapidfuzz')" in optional and "'yara_x'" in optional
    verbs = source('tools/pyinstaller_hooks/hook-patchtrace.cli_commands.py')
    assert "collect_submodules('patchtrace.cli_commands', on_error='raise')" in verbs
    assert 'if _missing:' in verbs
    extractor = source('tools/pyinstaller_hooks/hook-patchtrace.unified.extract.py')
    assert "datas = [(str(_SCRIPT), 'patchtrace/unified/extract')]" in extractor


def test_freezer_source_does_not_import_external_gpl_engines():
    paths = ['tools/build_windows.py', 'tools/build_linux.py']
    paths += [str(path.relative_to(ROOT)) for path in (ROOT / 'tools/pyinstaller_hooks').glob('*.py')]
    imports = set()
    for path in paths:
        for node in ast.walk(tree(path)):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
    assert not {'ghidriff', 'diaphora', 'pyghidra'} & imports
