"""`patchtrace doctor` through the real entry point: one health report that starts no process and opens no socket.

Hermetic and synthetic: every per-user directory and discovery hint is redirected into `tmp_path`, the bundle is the
stub tree of tests/test_backend_bundle.py and the runtime candidates are empty files. Nothing here shows that a runtime
can compare two binaries; doctor itself says so."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_backend_bundle import make_bundle

import patchtrace
from patchtrace import cli, cli_commands, optional_deps
from patchtrace.cli_commands import discover

SRC = Path(__file__).resolve().parents[1] / 'src'
HOST = 'windows' if os.name == 'nt' else 'linux'
CHECK_IDS = ['version', 'python', 'platform', 'optional-deps', 'cli-verbs', 'bundle', 'runtimes', 'work-dir',
             'profiles-dir']
STATUSES = {'ok', 'warning', 'problem', 'not-applicable'}
ENVIRONMENT = ('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'XDG_STATE_HOME', 'XDG_CONFIG_HOME', 'PROGRAMFILES',
               'SYSTEMDRIVE', 'PATCHTRACE_BUNDLE_DIR', 'PATCHTRACE_BACKEND_PYTHON', 'GHIDRA_INSTALL_DIR',
               'PATCHTRACE_BINDIFF')


def run(capsys, *argv):
    code = cli.main([str(item) for item in argv])
    out, err = capsys.readouterr()
    return code, out, err


def jrun(capsys, *argv):
    code, out, err = run(capsys, *argv, '--json')
    assert out.endswith('\n') and out.count('\n') == 1, out  # exactly one document
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'doctor'
    return code, doc, err


def tree(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): 'dir' if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*'))}


def by_id(doc) -> dict[str, dict]:
    return {check['id']: check for check in doc['result']['checks']}


class Box:
    """A machine in `tmp_path`: home, work and profile directories, and where candidates are planted. The `box`
    fixture also clears every discovery variable and reports every optional dependency as present, so the expected
    statuses do not depend on the developer's machine."""

    def __init__(self, root: Path):
        self.root = root
        self.home = root / 'home'
        self.work = root / 'work'
        self.profiles = root / 'profiles'
        self.exe = root / 'App Dir'
        for directory in (self.home, self.work, self.profiles, self.exe):
            directory.mkdir()

    @property
    def flags(self) -> list[str]:
        return ['--bundle-dir', str(self.exe), '--work-dir', str(self.work), '--profiles-dir', str(self.profiles)]

    def python(self) -> Path:
        path = self.root / 'venv' / 'python-stub'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(b'not an interpreter')
        return path

    def ghidra(self) -> Path:
        path = self.root / 'ghidra_stub'
        (path / 'Ghidra').mkdir(parents=True)
        (path / 'Ghidra' / 'application.properties').write_text('application.version=0', encoding='utf-8')
        return path


@pytest.fixture
def box(tmp_path, monkeypatch) -> Box:
    for variable in ENVIRONMENT:
        monkeypatch.delenv(variable, raising=False)
    for name, (extra, distribution, module, _error) in list(optional_deps._REGISTRY.items()):
        monkeypatch.setitem(optional_deps._REGISTRY, name, (extra, distribution, module or object(), ''))
    made = Box(tmp_path)
    monkeypatch.setenv('HOME', str(made.home))
    monkeypatch.setenv('USERPROFILE', str(made.home))
    return made


@pytest.fixture
def with_runtime(box, monkeypatch) -> Box:
    monkeypatch.setenv('PATCHTRACE_BACKEND_PYTHON', str(box.python()))
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', str(box.ghidra()))
    return box


@pytest.fixture
def forbidden(monkeypatch) -> list[str]:
    """Every way to start a process or reach the network records its use and fails."""
    used: list[str] = []

    def trap(name):
        def fail(*args, **kwargs):
            used.append(name)
            raise AssertionError(f'{name} must not be used by doctor')
        return fail

    monkeypatch.setattr(subprocess, 'Popen', trap('subprocess.Popen'))
    for name in ('system', 'popen', 'startfile', 'posix_spawn', 'fork', 'execv', 'spawnv'):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, trap(f'os.{name}'))
    for name in ('socket', 'create_connection', 'getaddrinfo', 'gethostbyname'):
        monkeypatch.setattr(socket, name, trap(f'socket.{name}'))
    return used


# --- the report ----------------------------------------------------------------------------------------------

def test_the_verb_is_discovered(capsys):
    found, failed = discover()
    assert 'doctor' in found and 'doctor' not in failed
    code, out, _err = run(capsys, 'doctor', '--help')
    assert code == 0 and all(flag in out for flag in ('--json', '--bundle-dir', '--work-dir', '--profiles-dir'))


def test_a_healthy_machine_reports_every_check_and_exits_0(with_runtime, capsys):
    box = with_runtime
    code, doc, err = jrun(capsys, 'doctor', *box.flags)
    assert (code, doc['status'], doc['warnings'], err) == (0, 'complete', [], '')
    result = doc['result']
    assert result['contract'] == 'doctor/1' and result['healthy'] is True
    assert [check['id'] for check in result['checks']] == CHECK_IDS
    for check in result['checks']:
        assert set(check) == {'id', 'status', 'detail', 'remedy'} and check['status'] in STATUSES
        assert check['detail'] and '\n' not in check['detail'] + check['remedy']
        assert (check['remedy'] == '') == (check['status'] in ('ok', 'not-applicable')), check
    checks = by_id(doc)
    assert {name: check['status'] for name, check in checks.items()} == {
        'version': 'ok', 'python': 'ok', 'platform': 'ok', 'optional-deps': 'ok', 'cli-verbs': 'ok',
        'bundle': 'not-applicable', 'runtimes': 'ok', 'work-dir': 'ok', 'profiles-dir': 'ok'}
    assert result['summary'] == {'ok': 8, 'warning': 0, 'problem': 0, 'not-applicable': 1}
    assert checks['version']['detail'] == f'PatchTrace {patchtrace.__version__}'
    assert 'optional-deps: ' + checks['optional-deps']['detail'] == optional_deps.summary_line()
    assert '.'.join(map(str, sys.version_info[:3])) in checks['python']['detail']
    assert sys.platform in checks['platform']['detail']


def test_the_facts_are_structured_for_scripts(with_runtime, capsys):
    box = with_runtime
    code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    facts = doc['result']['facts']
    assert code == 0 and facts['version'] == patchtrace.__version__
    assert facts['python'] == {'version': '.'.join(map(str, sys.version_info[:3])),
                               'implementation': sys.implementation.name,
                               'bits': 64 if sys.maxsize > 2 ** 32 else 32,
                               'frozen': False}
    assert facts['platform']['system'] == sys.platform and facts['platform']['os'] == os.name
    assert facts['optional_deps'] == [{'name': cap.name, 'extra': cap.extra, 'available': cap.available,
                                       'version': cap.version} for cap in optional_deps.probe().values()]
    assert facts['verbs'] == {'loaded': len(discover()[0]), 'failed': {}}
    assert facts['bundle'] is None
    candidates = facts['runtime_candidates']
    assert candidates['verified'] is False
    assert candidates['python'] == [str((box.root / 'venv' / 'python-stub').resolve())]
    assert candidates['ghidra'] == [str((box.root / 'ghidra_stub').resolve())]
    assert facts['directories'] == {'work': str(box.work), 'profiles': str(box.profiles)}


def test_text_output_is_one_line_per_check_then_the_verdict(with_runtime, capsys):
    code, out, err = run(capsys, 'doctor', *with_runtime.flags)
    assert (code, err) == (0, '')
    lines = out.splitlines()
    assert [line.split()[1].rstrip(':') for line in lines[:len(CHECK_IDS)]] == CHECK_IDS
    assert all(line.split()[0] in STATUSES for line in lines[:len(CHECK_IDS)])
    assert lines[0] == f'ok              version: PatchTrace {patchtrace.__version__}'
    assert lines[len(CHECK_IDS)] == 'doctor: no problem found (8 ok, 0 warning, 0 problem, 1 not-applicable)'
    assert 'patchtrace backend diagnose' in lines[-1] and len(lines) == len(CHECK_IDS) + 2


def test_doctor_starts_no_process_and_opens_no_socket(with_runtime, forbidden, capsys):
    box = with_runtime
    make_bundle(box.exe, HOST)
    code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    assert code == 0 and by_id(doc)['bundle']['status'] == 'ok' and forbidden == []
    code, _out, _err = run(capsys, 'doctor', *box.flags)
    assert code == 0 and forbidden == []


def test_doctor_writes_nothing(with_runtime, capsys):
    box = with_runtime
    make_bundle(box.exe, HOST)
    absent = box.root / 'state' / 'never' / 'created'
    before = tree(box.root)
    for argv in (box.flags, ['--bundle-dir', box.exe, '--work-dir', absent, '--profiles-dir', absent / 'profiles']):
        code, doc, _err = jrun(capsys, 'doctor', *argv)
        assert code == 0 and by_id(doc)['work-dir']['status'] == 'ok'
        assert tree(box.root) == before
    assert 'does not exist yet' in by_id(doc)['work-dir']['detail'] and not (box.root / 'state').exists()


def test_the_default_directories_are_the_per_user_ones(box, capsys):
    from patchtrace.enrichment.profiles import default_profiles_dir
    from patchtrace.runtime_discovery import bundle_work_dir
    for variable in ('LOCALAPPDATA', 'APPDATA', 'XDG_STATE_HOME', 'XDG_CONFIG_HOME'):
        os.environ[variable] = str(box.home / variable)  # removed again by the box fixture's monkeypatch
    code, doc, _err = jrun(capsys, 'doctor')
    assert code == 0
    assert doc['result']['facts']['directories'] == {'work': str(bundle_work_dir()),
                                                     'profiles': str(default_profiles_dir())}
    assert bundle_work_dir().is_relative_to(box.home) and default_profiles_dir().is_relative_to(box.home)
    assert tree(box.home) == {}  # the probe ran in the nearest existing ancestor and left nothing


# --- warnings never change the exit code ---------------------------------------------------------------------

def test_no_runtime_candidate_is_a_warning_with_a_remedy(box, capsys):
    code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    check = by_id(doc)['runtimes']
    assert (code, doc['status'], doc['result']['healthy']) == (0, 'complete', True)
    assert check['status'] == 'warning' and 'no Python and no Ghidra candidate' in check['detail']
    # the remedy names only what exists: `patchtrace runtime` is specified but not built yet
    assert 'offline backend ZIP' in check['remedy'] and 'patchtrace runtime' not in check['remedy']
    assert doc['result']['summary']['warning'] == 1


def test_a_hint_that_is_not_accepted_is_named(box, capsys, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_BACKEND_PYTHON', str(box.root / 'missing' / 'python'))
    monkeypatch.setenv('GHIDRA_INSTALL_DIR', str(box.ghidra()))
    code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    check = by_id(doc)['runtimes']
    assert code == 0 and check['status'] == 'warning'
    assert 'PATCHTRACE_BACKEND_PYTHON' in check['detail'] and 'GHIDRA_INSTALL_DIR' not in check['detail']
    assert doc['result']['facts']['runtime_candidates']['python'] == []


def test_candidates_are_reported_as_unverified(with_runtime, capsys):
    code, doc, _err = jrun(capsys, 'doctor', *with_runtime.flags)
    detail = by_id(doc)['runtimes']['detail']
    assert code == 0 and '1 Python and 1 Ghidra candidate' in detail and 'not verified' in detail


def test_a_missing_optional_dependency_is_a_warning(with_runtime, capsys, monkeypatch):
    extra, distribution, _module, _error = optional_deps._REGISTRY['yara-x']
    monkeypatch.setitem(optional_deps._REGISTRY, 'yara-x', (extra, distribution, None, 'ImportError()'))
    code, doc, _err = jrun(capsys, 'doctor', *with_runtime.flags)
    check = by_id(doc)['optional-deps']
    assert (code, doc['result']['healthy']) == (0, True)
    assert check['status'] == 'warning' and 'optional-deps: ' + check['detail'] == optional_deps.summary_line()
    assert 'missing=yara-x' in check['detail'] and check['remedy'] == 'pip install "patchtrace[rules]"'


def test_a_profiles_directory_that_cannot_be_written_is_a_warning(with_runtime, capsys):
    box = with_runtime
    blocker = box.root / 'blocker'
    blocker.write_text('x', encoding='utf-8')
    code, doc, _err = jrun(capsys, 'doctor', '--bundle-dir', box.exe, '--work-dir', box.work,
                           '--profiles-dir', blocker / 'profiles')
    check = by_id(doc)['profiles-dir']
    assert (code, check['status']) == (0, 'warning') and '--profiles-dir' in check['remedy']


# --- problems exit 4 -----------------------------------------------------------------------------------------

def test_a_work_directory_that_cannot_be_written_is_a_problem(with_runtime, capsys):
    box = with_runtime
    blocker = box.root / 'blocker'
    blocker.write_text('x', encoding='utf-8')
    before = tree(box.root)
    code, doc, _err = jrun(capsys, 'doctor', '--bundle-dir', box.exe, '--work-dir', blocker / 'work',
                           '--profiles-dir', box.profiles)
    check = by_id(doc)['work-dir']
    assert (code, doc['status'], doc['result']['healthy']) == (4, 'no-results', False)
    assert check['status'] == 'problem' and 'not writable' in check['detail'] and '--work-dir' in check['remedy']
    assert doc['result']['summary']['problem'] == 1 and tree(box.root) == before
    code, out, _err = run(capsys, 'doctor', '--bundle-dir', box.exe, '--work-dir', blocker / 'work',
                          '--profiles-dir', box.profiles)
    assert code == 4 and 'doctor: 1 problem found' in out
    assert next(line for line in out.splitlines() if ' work-dir:' in line).startswith('problem ')


@pytest.mark.parametrize(('damage', 'code'), [('missing', 'PT-BUNDLE-MISSING'), ('size', 'PT-BUNDLE-SIZE'),
                                               ('no-manifest', 'PT-BUNDLE-MISSING')],
                         ids=['missing-file', 'wrong-size', 'no-manifest'])
def test_a_damaged_bundle_is_a_problem_with_its_code(with_runtime, capsys, forbidden, damage, code):
    box = with_runtime
    backend = make_bundle(box.exe, HOST)
    if damage == 'missing':
        (backend / 'payload' / 'ghidra' / 'docs' / 'a.txt').unlink()
    elif damage == 'size':
        (backend / 'payload' / 'ghidra' / 'docs' / 'a.txt').write_bytes(b'short')
    else:
        (backend / 'manifest.json').unlink()
    exit_code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    check = by_id(doc)['bundle']
    assert (exit_code, doc['status'], doc['result']['healthy']) == (4, 'no-results', False)
    assert check['status'] == 'problem' and check['detail'].startswith(code)
    assert 'extract the complete ZIP again' in check['remedy'] and forbidden == []
    assert doc['result']['facts']['bundle']['code'] == code and doc['result']['facts']['bundle']['ok'] is False


def test_a_healthy_bundle_is_reported_with_its_runtime_id(box, capsys):
    make_bundle(box.exe, HOST)
    code, doc, _err = jrun(capsys, 'doctor', *box.flags)
    check, fact = by_id(doc)['bundle'], doc['result']['facts']['bundle']
    assert code == 0 and check['status'] == 'ok' and 'fast check ok' in check['detail']
    assert fact == {'runtime_id': f'ghidra-12.0.4-ghidriff-4f5d895-{HOST}-amd64', 'ok': True, 'code': '',
                    'files': 5, 'bytes': fact['bytes']} and fact['bytes'] > 0
    assert by_id(doc)['runtimes']['status'] == 'ok'  # the bundle's own Python and Ghidra are candidates


def test_a_verb_that_cannot_be_loaded_is_a_problem(with_runtime, capsys, tmp_path, monkeypatch):
    extra = tmp_path / 'fake_verbs'
    extra.mkdir()
    (extra / 'zz_broken.py').write_text('import no_such_module_zz\n', encoding='utf-8', newline='\n')
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)
    monkeypatch.setattr(cli_commands, '__path__', [*cli_commands.__path__, str(extra)])
    importlib.invalidate_caches()
    try:
        code, doc, _err = jrun(capsys, 'doctor', *with_runtime.flags)
    finally:
        sys.modules.pop('patchtrace.cli_commands.zz_broken', None)
        importlib.invalidate_caches()
    check = by_id(doc)['cli-verbs']
    assert (code, doc['status']) == (4, 'no-results') and check['status'] == 'problem'
    assert 'zz_broken (ModuleNotFoundError)' in check['detail']
    assert doc['result']['facts']['verbs']['failed'] == {'zz_broken': 'ModuleNotFoundError'}


def test_a_32_bit_interpreter_is_a_problem():
    from patchtrace import doctor_cli
    assert doctor_cli.python_check(64).status == 'ok'
    narrow = doctor_cli.python_check(32)
    assert narrow.status == 'problem' and '32-bit' in narrow.detail and '64-bit' in narrow.remedy


# --- usage, cancellation, entry point ------------------------------------------------------------------------

def test_usage_errors_exit_2(capsys):
    for argv, needle in ((['doctor', '--no-such-flag'], 'unrecognized arguments: --no-such-flag'),
                         (['doctor', 'extra-argument'], 'unrecognized arguments: extra-argument'),
                         (['doctor', '--work-dir'], 'patchtrace doctor: argument --work-dir: expected one argument')):
        code, out, err = run(capsys, *argv)
        assert (code, out) == (2, '') and needle in err, (argv, err)


def test_cancellation_during_the_bundle_walk_exits_5(box, capsys):
    from patchtrace import doctor_cli
    make_bundle(box.exe, HOST)
    args = cli._parser(['doctor']).parse_args(['doctor', '--json', *box.flags])
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(cli.CliError) as caught:
        doctor_cli.run(args, cancel)
    assert caught.value.code == 5
    assert capsys.readouterr().out == ''  # no half report


def test_the_installed_entry_point_prints_one_json_report(tmp_path):
    env = {key: value for key, value in os.environ.items() if key not in ENVIRONMENT}
    env.update(PYTHONPATH=str(SRC), HOME=str(tmp_path), USERPROFILE=str(tmp_path), LOCALAPPDATA=str(tmp_path),
               APPDATA=str(tmp_path), XDG_STATE_HOME=str(tmp_path / 'state'), XDG_CONFIG_HOME=str(tmp_path / 'config'))
    result = subprocess.run([sys.executable, '-m', 'patchtrace', 'doctor', '--json'], capture_output=True, text=True,
                            timeout=120, env=env)
    doc = json.loads(result.stdout)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'doctor'
    assert [check['id'] for check in doc['result']['checks']] == CHECK_IDS
    assert result.returncode == (0 if doc['result']['healthy'] else 4), result.stderr
    assert doc['status'] == ('complete' if doc['result']['healthy'] else 'no-results')
    assert list(tmp_path.iterdir()) == []


def test_doctor_imports_no_qt(tmp_path):
    code = ('import sys\nfrom patchtrace import cli\nimport patchtrace.doctor_cli\n'
            'code = cli.main(["doctor", "--json"])\n'
            'print(code, sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))),'
            ' file=sys.stderr)')
    env = {key: value for key, value in os.environ.items() if key not in ENVIRONMENT}
    env.update(PYTHONPATH=str(SRC), HOME=str(tmp_path), USERPROFILE=str(tmp_path), LOCALAPPDATA=str(tmp_path),
               APPDATA=str(tmp_path))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip().splitlines()[-1] in ('0 []', '4 []')
