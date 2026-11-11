"""Security regression: source-wide rules for process spawning and temporary names, checked on the syntax tree.

Each rule is an invariant the hardening relies on. A new spawn site, a shell, or a predictable temporary name
fails here before it reaches review.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = sorted((ROOT / 'src').rglob('*.py'))
TOOL_FILES = sorted((ROOT / 'tools').rglob('*.py'))
JOB_RUNNER = ROOT / 'src' / 'patchtrace' / 'jobs.py'
SPAWNERS = {'Popen', 'run', 'call', 'check_call', 'check_output'}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding='utf-8'), filename=str(path))


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def _is_false(value: ast.expr | None) -> bool:
    return isinstance(value, ast.Constant) and value.value is False


def test_no_call_enables_a_shell_anywhere():
    offenders = []
    for path in SOURCE_FILES + TOOL_FILES:
        for call in _calls(_tree(path)):
            shell = _keyword(call, 'shell')
            if shell is not None and not _is_false(shell):
                offenders.append(f'{path.relative_to(ROOT)}:{call.lineno}')
    assert offenders == []


def _is_shell_out_api(node: ast.AST) -> bool:
    """os.system, os.popen and the os.spawn*/os.exec* family start processes outside the job runner."""
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'os'):
        return False
    return node.attr in {'system', 'popen'} or node.attr.startswith(('spawn', 'exec'))


def _is_subprocess_spawn(call: ast.Call) -> bool:
    func = call.func
    return (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            and func.value.id == 'subprocess' and func.attr in SPAWNERS)


def test_only_the_job_runner_imports_subprocess_or_uses_os_process_apis():
    offenders = []
    for path in SOURCE_FILES:
        if path == JOB_RUNNER:
            continue
        for node in ast.walk(_tree(path)):
            imported = (isinstance(node, ast.Import) and any(a.name.split('.')[0] == 'subprocess' for a in node.names)
                        or isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[0] == 'subprocess')
            if imported or _is_shell_out_api(node):
                offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
    assert offenders == []


def test_the_job_runner_spawns_without_a_shell_and_with_an_explicit_environment():
    spawns = [call for call in _calls(_tree(JOB_RUNNER)) if _is_subprocess_spawn(call)]
    assert spawns, 'the job runner must still own its spawn site'
    for call in spawns:
        assert _is_false(_keyword(call, 'shell')), f'jobs.py:{call.lineno} must pass shell=False'
        assert _keyword(call, 'env') is not None, f'jobs.py:{call.lineno} must pass an explicit env'


def test_no_source_uses_the_predictable_temporary_api_or_a_fixed_tmp_path():
    offenders = []
    for path in SOURCE_FILES:
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Attribute) and node.attr == 'mktemp':
                offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                    node.value == '/tmp' or node.value.startswith('/tmp/')):
                offenders.append(f'{path.relative_to(ROOT)}:{node.lineno}')
    assert offenders == []
