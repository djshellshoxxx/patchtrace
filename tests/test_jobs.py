"""Fake child coverage; this does not claim Ghidra runtime acceptance."""
import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from patchtrace import backend
from patchtrace.backend import BackendConfig, quarantine_failed_run, run_comparison
from patchtrace.diagnostics import redact_log
from patchtrace.jobs import run_process
from patchtrace.models import Artifact, ComparisonProject


def execute(tmp_path, code, cancel=None, timeout=5, **kwargs):
    return run_process([str(Path(sys.executable).resolve()), '-c', code], cwd=tmp_path,
                       env=os.environ.copy(), cancel=cancel or threading.Event(),
                       timeout_seconds=timeout, **kwargs)


def test_output_tail_is_bounded(tmp_path):
    result = execute(tmp_path, 'import sys;sys.stdout.write("x"*100000+"END")', log_limit=1024)
    assert result.returncode == 0
    assert len(result.log_tail.encode()) <= 1024
    assert result.log_tail.endswith('END')


@pytest.mark.parametrize('cancelled', [True, False])
def test_cancel_and_timeout_terminate_children(tmp_path, cancelled):
    event = threading.Event()
    pidfile = tmp_path / 'pid.txt'

    def cancel_after_spawn():
        deadline = time.monotonic() + 10
        while not pidfile.exists() and time.monotonic() < deadline:
            event.wait(.02)
        event.set()

    timer = threading.Thread(target=cancel_after_spawn) if cancelled else None
    if timer:
        timer.start()
    code = (
        'import subprocess,sys,time,pathlib;'
        'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
        f'pathlib.Path({str(pidfile)!r}).write_text(str(p.pid));'
        'time.sleep(60)'
    )
    started = time.monotonic()
    result = execute(tmp_path, code, event, timeout=2 if not cancelled else 15)
    if timer:
        timer.join()
    assert result.reason == ('cancelled' if cancelled else 'timeout')
    assert time.monotonic() - started < 12
    assert pidfile.exists()
    pid = int(pidfile.read_text())
    if os.name == 'nt':
        import ctypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x100000, False, pid)
        if handle:
            assert kernel.WaitForSingleObject(handle, 5000) == 0
            kernel.CloseHandle(handle)
    else:
        state = Path(f'/proc/{pid}/stat')
        # A terminated orphan may briefly remain a zombie until host init reaps it.
        if state.exists():
            assert state.read_text().split()[2] == 'Z'


def test_precancel_does_not_start(tmp_path):
    cancel = threading.Event()
    cancel.set()
    result = execute(tmp_path, 'raise RuntimeError("must not run")', cancel)
    assert result.reason == 'cancelled'
    assert result.log_tail == ''


def test_output_limit_stops_process(tmp_path):
    result = execute(tmp_path, 'import time;time.sleep(60)', check_output=lambda: 'output-limit')
    assert result.reason == 'output-limit'


@pytest.fixture
def fake_runtime(tmp_path, monkeypatch):
    ghidra = tmp_path / 'ghidra'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    package = ghidra / 'ghidriff'
    package.mkdir()
    (package / '__init__.py').write_text('')
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: {
        'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': 'fake-test-only', 'available': True})
    artifacts = []
    for side, content in [('older', b'old-static-data'), ('newer', b'new-static-data')]:
        artifact = tmp_path / f'{side}.bin'
        artifact.write_bytes(content)
        artifacts.append(Artifact(side=side, name=artifact.name, size=len(content),
                                  sha256=hashlib.sha256(content).hexdigest(), relative_path=artifact.name))
    project = ComparisonProject(name='fake-runtime-fixture', artifacts=artifacts)
    config = BackendConfig(str(Path(sys.executable).resolve()), str(ghidra))
    return tmp_path, package, project, config


def write_backend(package, body):
    (package / '__main__.py').write_text(
        'import pathlib,sys,json,os\n'
        'out=pathlib.Path(sys.argv[sys.argv.index("--output-path")+1])\n'
        '(out/"json").mkdir(parents=True)\n' + body)


def test_completed_raw_is_unique_and_project_unchanged(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package, '(out/"json"/"old-new.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    original = project.model_dump_json()
    events = []
    path, run = run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'completed'
    assert path.is_file()
    assert run.raw_path == path.relative_to(root).as_posix()
    assert run.raw_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert project.model_dump_json() == original
    assert [event.stage for event in events] == ['preflight', 'analysis', 'completed']
    path2, run2 = run_comparison(config, project, root, threading.Event(), events.append)
    assert path != path2 and run.id != run2.id


@pytest.mark.parametrize('body', [
    '(out/"partial.txt").write_text("preserve me");sys.exit(7)\n',
    '(out/"json"/"old-new.ghidriff.json").write_text("{}")\n',
    '(out/"json"/"old-new.ghidriff.json").write_text("not-json")\n',
])
def test_failure_quarantines_without_publishing(fake_runtime, body):
    root, package, project, config = fake_runtime
    write_backend(package, body)
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    assert path.name.startswith('quarantine-')
    assert (path / 'failure.txt').is_file()
    assert not (root / 'runs' / run.id).exists()
    assert not project.runs
    assert run.raw_path is None


def test_input_hash_change_fails_before_child(fake_runtime):
    root, _package, project, config = fake_runtime
    (root / 'older.bin').write_bytes(b'tampered')
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed' and 'PT-INPUT' in run.error
    assert path.is_dir()


def test_frozen_app_requires_external_python(fake_runtime, monkeypatch):
    _, _, _, config = fake_runtime
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    assert any('external Python' in error for error in backend.diagnose(config))


def test_json_size_limit_and_untrusted_path(fake_runtime, monkeypatch):
    root, package, project, config = fake_runtime
    monkeypatch.setattr(backend, 'JSON_LIMIT', 8)
    write_backend(package, '(out/"json"/"old-new.ghidriff.json").write_text("x"*100)\n')
    _, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed' and 'oversized' in run.error


def test_log_redacts_credentials():
    log = redact_log('Authorization: Bearer abc123\napi_key=verysecret password=hunter2 '
                     'https://bob:credential@example.com sk-abcdefghijklmnop '
                     '{"api_key": "jsonsecret"} Authorization: Basic base64secret')
    secrets = ['abc123', 'verysecret', 'hunter2', 'credential', 'abcdefghijklmnop', 'jsonsecret', 'base64secret']
    assert all(secret not in log for secret in secrets)


def test_completed_log_event_is_bounded_and_redacted(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package, 'print("x"*20000+" Authorization: Bearer private-secret")\n'
                  '(out/"json"/"old-new.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    events = []
    _, run = run_comparison(config, project, root, threading.Event(), events.append)
    assert run.status == 'completed'
    log = next(event.message for event in events if event.stage == 'log')
    assert len(log) <= 8192 and 'private-secret' not in log and '[redacted]' in log
    assert run.settings['ghidra_version'] == '12.0.4'
    assert run.settings['java_runtime_version'] == 'unverified'


def test_normalization_failure_quarantines_complete_output(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package, '(out/"json"/"old-new.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    path, completed = run_comparison(config, project, root, threading.Event(), lambda _: None)
    payload = path.read_bytes()
    failed = quarantine_failed_run(root, completed, 'PT-SCHEMA: bad identity token=private-secret')
    assert failed.status == 'failed' and completed.status == 'completed'
    assert 'private-secret' not in failed.error and '[redacted]' in failed.error
    assert failed.raw_sha256 == completed.raw_sha256
    assert (root / failed.raw_path).read_bytes() == payload
    assert (root / 'runs' / f'quarantine-{failed.id}' / 'failure.txt').read_text() == failed.error
    assert not path.exists() and not (root / 'runs' / completed.id).exists()
    assert not project.runs


def test_quarantine_rejects_foreign_raw_path(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package, '(out/"json"/"old-new.ghidriff.json").write_text('
                  'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    run.raw_path = '../outside.json'
    with pytest.raises(ValueError, match='relative and contained'):
        quarantine_failed_run(root, run, 'normalization failed')
    assert path.is_file()


@pytest.mark.skipif(os.name != 'nt', reason='Windows Job Object platform acceptance')
def test_windows_containment_failure_fails_closed(tmp_path, monkeypatch):
    # The actual Windows branch is exercised by the cancellation/timeout tests above.
    # A launcher error must propagate rather than falling back to an uncontained Popen.
    from patchtrace import jobs

    def fail(*_):
        raise OSError('Job Object assignment denied')

    monkeypatch.setattr(jobs, '_windows_process', fail)
    with pytest.raises(OSError, match='assignment denied'):
        execute(tmp_path, 'print("must not start")')


@pytest.mark.skipif(os.name != 'nt', reason='Windows suspended-child failure cleanup')
def test_windows_assignment_denial_terminates_suspended_child(tmp_path, monkeypatch):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    pids = []

    def deny_assignment(_job, process):
        pids.append(kernel.GetProcessId(process))
        ctypes.set_last_error(5)
        return False

    class DeniedKernel:
        def __getattr__(self, name):
            return deny_assignment if name == 'AssignProcessToJobObject' else getattr(kernel, name)

    monkeypatch.setattr(ctypes, 'WinDLL', lambda *_args, **_kwargs: DeniedKernel())
    marker = tmp_path / 'must-not-start.txt'
    with pytest.raises(OSError):
        execute(tmp_path, f'import pathlib;pathlib.Path({str(marker)!r}).write_text("started")')
    assert not marker.exists()
    assert len(pids) == 1 and pids[0]
    handle = kernel.OpenProcess(0x100000, False, pids[0])
    if handle:
        try:
            assert kernel.WaitForSingleObject(handle, 5000) == 0
        finally:
            kernel.CloseHandle(handle)


def test_ghidriff_output_never_passes_dot_prefixed_directory(fake_runtime):
    """Reproduce Ghidra's IllegalArgumentException instead of mocking success."""
    root, package, project, config = fake_runtime
    write_backend(
        package,
        'if any(part.startswith(".") for part in out.parts):\n'
        '    print("java.lang.IllegalArgumentException: Path element starting with dot is not permitted")\n'
        '    sys.exit(1)\n'
        '(out/"json"/"old-new.ghidriff.json").write_text('
        'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n',
    )
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'completed', run.error
    assert path.is_file()


def test_dot_prefixed_project_ancestor_fails_before_ghidriff(fake_runtime, monkeypatch):
    """A user-selected project directory can also contain an unsafe ancestor."""
    root, _package, project, config = fake_runtime
    hidden_root = root / '.hidden-project'
    hidden_root.mkdir()
    for side in ('older', 'newer'):
        (hidden_root / f'{side}.bin').write_bytes((root / f'{side}.bin').read_bytes())

    def must_not_start(*_args, **_kwargs):
        pytest.fail('ghidriff must never start with an unsafe output path')

    monkeypatch.setattr(backend, 'run_process', must_not_start)
    directory, run = run_comparison(
        config, project, hidden_root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    assert 'dot-prefixed' in run.error
    assert (directory / 'failure.txt').is_file()


def test_ghidra_output_path_preserves_spaces_and_onedrive_names(tmp_path):
    output = tmp_path / 'OneDrive - Research' / 'Projects with spaces' / 'runs' / 'quarantine-123' / 'raw'
    assert backend._validated_ghidra_output_path(output) == output.resolve()


@pytest.mark.skipif(os.name != 'nt', reason='Windows Ghidra path-length preflight')
def test_ghidra_output_path_rejects_overlong_windows_path(tmp_path):
    output = tmp_path / ('a' * 90) / ('b' * 90) / 'raw'
    with pytest.raises(ValueError, match='shorter'):
        backend._validated_ghidra_output_path(output)


def test_native_engine_workspace_is_local_temporary_and_removed(fake_runtime):
    """Ghidra databases must not be created inside a OneDrive-backed case."""
    root, package, project, config = fake_runtime
    script = (
        'args=sys.argv\n'
        'if "--project-location" not in args or "--gzfs-path" not in args:\n'
        '    print("Missing isolated engine workspace");sys.exit(9)\n'
        'workspace=pathlib.Path(args[args.index("--project-location")+1])\n'
        'gzfs=pathlib.Path(args[args.index("--gzfs-path")+1])\n'
        'if out in workspace.parents or out.parent in workspace.parents or workspace==out:\n'
        '    print("Ghidra project created beneath the case");sys.exit(9)\n'
        'if any(part.startswith(".") for part in workspace.parts):\n'
        '    print("Unsafe dot-prefixed workspace");sys.exit(9)\n'
        'workspace.mkdir(parents=True,exist_ok=True)\n'
        '(workspace/"created.txt").write_text("transient")\n'
        '(out/"workspace-path.txt").write_text(str(workspace))\n'
        '(out/"gzfs-path.txt").write_text(str(gzfs))\n'
        '(out/"json"/"old-new.ghidriff.json").write_text('
        'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n'
    )
    write_backend(package, script)
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'completed', run.error
    workspace = Path((path.parent.parent / 'workspace-path.txt').read_text())
    gzfs = Path((path.parent.parent / 'gzfs-path.txt').read_text())
    assert workspace.is_absolute() and gzfs.is_absolute()
    assert workspace.parent == gzfs.parent
    assert not workspace.parent.exists()
    assert path.is_file()
    assert not (root / 'runs' / run.id / 'raw' / 'ghidra_projects').exists()


def test_native_engine_workspace_removed_when_analysis_fails(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package,
        'args=sys.argv\n'
        'if "--project-location" not in args:\n'
        '    print("Missing isolated workspace");sys.exit(9)\n'
        'workspace=pathlib.Path(args[args.index("--project-location")+1])\n'
        'workspace.mkdir(parents=True,exist_ok=True)\n'
        '(workspace/"marker").write_text("transient")\n'
        '(out/"workspace-path.txt").write_text(str(workspace))\n'
        'sys.exit(7)\n')
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    workspace = Path((path / 'raw' / 'workspace-path.txt').read_text())
    assert not workspace.parent.exists()
    assert (path / 'failure.txt').is_file()


def test_symbol_lookup_requires_explicit_opt_in(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package,
        '(out/"argv.json").write_text(json.dumps(sys.argv))\n'
        '(out/"json"/"old-new.ghidriff.json").write_text('
        'json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))\n')

    path, offline = run_comparison(config, project, root, threading.Event(), lambda _: None)
    argv = json.loads((path.parent.parent / 'argv.json').read_text())
    assert offline.status == 'completed', offline.error
    assert '--no-symbols' in argv
    assert offline.settings['allow_symbol_downloads'] is False

    online_config = backend.BackendConfig(
        config.python_executable, config.ghidra_dir, allow_symbol_downloads=True)
    path, online = run_comparison(online_config, project, root, threading.Event(), lambda _: None)
    argv = json.loads((path.parent.parent / 'argv.json').read_text())
    assert online.status == 'completed', online.error
    assert '--no-symbols' not in argv
    assert online.settings['allow_symbol_downloads'] is True


@pytest.mark.parametrize('value', ['false', 0, None, 1])
def test_symbol_policy_rejects_ambiguous_non_boolean_values(fake_runtime, value):
    root, _package, project, config = fake_runtime
    invalid = backend.BackendConfig(
        config.python_executable, config.ghidra_dir, allow_symbol_downloads=value)
    directory, run = run_comparison(invalid, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    assert 'allow_symbol_downloads' in run.error
    assert (directory / 'failure.txt').is_file()


@pytest.mark.parametrize(('upstream_log', 'expected'), [
    ("java.lang.IllegalArgumentException: Path element starting with '.' is not permitted", 'dot-prefixed'),
    ('java.lang.UnsupportedClassVersionError: class file version', 'JDK'),
    ("ModuleNotFoundError: No module named 'ghidriff'", 'Ghidriff installation'),
    ('java.lang.OutOfMemoryError: Java heap space', 'memory'),
    ('OSError: No space left on device', 'disk space'),
    ('java.nio.file.AccessDeniedException: C:/work', 'permissions'),
])
def test_exit_diagnostics_identify_common_failures_without_echoing_raw_logs(upstream_log, expected):
    from patchtrace.diagnostics import describe_backend_exit

    text = describe_backend_exit(1, 'api_key=secretvalue\n' + upstream_log)
    assert text.startswith('PT-BACKEND:')
    assert expected.lower() in text.lower()
    assert 'secretvalue' not in text
    assert 'analysis.log' in text


def test_unknown_exit_diagnostics_keep_original_status_code():
    from patchtrace.diagnostics import describe_backend_exit

    assert 'code 17' in describe_backend_exit(17, 'unknown failure')


def test_nonzero_backend_exit_preserves_classified_error_and_log(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package, 'print("java.lang.UnsupportedClassVersionError: class version")\n'
                  'sys.exit(7)\n')
    directory, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    assert 'JDK' in run.error
    assert 'UnsupportedClassVersionError' in (directory / 'analysis.log').read_text()
    assert not project.runs


# Emulates pinned Ghidriff 1.0.0 setup_project()/get_pdb() symbol handling: Ghidra
# resolves user settings from XDG_CONFIG_HOME, else %APPDATA% / ~/.config; a
# symbol store persisted there by an earlier run is consulted even under
# --no-symbols, and a matching PDB raises FileExistsError.
_GHIDRIFF_SYMBOL_EMULATOR = '''
def settings_root():
    if os.environ.get("XDG_CONFIG_HOME"):
        return pathlib.Path(os.environ["XDG_CONFIG_HOME"])
    return pathlib.Path(os.environ["APPDATA"] if os.name == "nt" else pathlib.Path.home() / ".config")
prefs = settings_root() / "ghidra" / "ghidra_12.1.4_PUBLIC" / "preferences"
(out/"settings-root.txt").write_text(str(settings_root()))
store = None
if prefs.is_file():
    for line in prefs.read_text().splitlines():
        if line.startswith("PdbSymbolServerConfig="):
            store = pathlib.Path(line.split("=", 1)[1])
no_symbols = "--no-symbols" in sys.argv
if not no_symbols:
    symbols = out / "symbols"
    symbols.mkdir(exist_ok=True)
    prefs.parent.mkdir(parents=True, exist_ok=True)
    prefs.write_text("PdbSymbolServerConfig=" + str(symbols) + "\\n")
elif store is not None and store.is_dir():
    pdbs = sorted(store.rglob("clfs.pdb"))
    pdbs = [p for p in pdbs if p.is_file()]
    if pdbs:
        print("INFO | ghidriff | Pdb stored at: " + str(pdbs[0]))
        print("ERROR | ghidriff | Symbols are disabled, but the symbol is already downloaded " + str(pdbs[0]))
        raise FileExistsError("Symbols are disabled, but the symbol is already downloaded " + str(pdbs[0]))
(out/"json"/"old-new.ghidriff.json").write_text(json.dumps({"functions":{"added":[],"deleted":[],"modified":[]}}))
'''


@pytest.fixture
def persisted_symbol_cache(tmp_path, monkeypatch):
    """A user profile whose global Ghidra prefs point at a populated PDB cache."""
    home = tmp_path / 'userhome'
    appdata = home / 'AppData'
    cache = tmp_path / 'ghidriff-out' / 'symbols'
    for guid, data in [('8534452A12A8D8DC1008FCBE61915A2F1', b'MSF pdb v1'),
                       ('0000000000000000000000000000000002', b'corrupt\x00')]:
        (cache / 'clfs.pdb' / guid).mkdir(parents=True)
        (cache / 'clfs.pdb' / guid / 'clfs.pdb').write_bytes(data)
    settings_root = appdata if os.name == 'nt' else home / '.config'
    prefs = settings_root / 'ghidra' / 'ghidra_12.1.4_PUBLIC' / 'preferences'
    prefs.parent.mkdir(parents=True)
    prefs.write_text(f'PdbSymbolServerConfig={cache}\n')
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('USERPROFILE', str(home))
    monkeypatch.setenv('APPDATA', str(appdata))
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
    snapshot = {p: p.read_bytes() for p in [prefs, *cache.rglob('*.pdb')] if p.is_file()}
    assert len(snapshot) == 3
    return prefs, cache, snapshot


def _assert_unchanged(snapshot):
    for path, data in snapshot.items():
        assert path.read_bytes() == data


def test_emulator_reproduces_cached_pdb_failure_without_isolation(fake_runtime, persisted_symbol_cache):
    """Guard: the emulator triggers the user's failure when global settings are visible."""
    root, package, project, config = fake_runtime
    write_backend(package, _GHIDRIFF_SYMBOL_EMULATOR)
    out = root / 'manual-out'
    env = backend._environment(config)  # no per-run settings directory
    result = run_process([config.python_executable, '-m', 'ghidriff', 'a', 'b', '--output-path', str(out),
                          '--no-symbols'], cwd=Path(config.ghidra_dir), env=env,
                         cancel=threading.Event(), timeout_seconds=30)
    assert result.returncode != 0
    assert 'symbol is already downloaded' in result.log_tail


def test_disabled_symbols_ignore_persisted_cached_pdbs(fake_runtime, persisted_symbol_cache):
    root, package, project, config = fake_runtime
    _prefs, _cache, snapshot = persisted_symbol_cache
    write_backend(package, _GHIDRIFF_SYMBOL_EMULATOR)
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'completed', run.error
    assert run.settings['symbol_policy'] == 'disabled'
    assert run.settings['ghidra_settings'] == 'isolated-per-run'
    used = Path((path.parent.parent / 'settings-root.txt').read_text())
    assert used.name == 'ghidra-settings' and not used.exists()  # scratch removed
    _assert_unchanged(snapshot)


def test_online_symbols_do_not_persist_into_global_ghidra_settings(fake_runtime, persisted_symbol_cache):
    root, package, project, config = fake_runtime
    _prefs, _cache, snapshot = persisted_symbol_cache
    write_backend(package, _GHIDRIFF_SYMBOL_EMULATOR)
    online = backend.BackendConfig(config.python_executable, config.ghidra_dir, allow_symbol_downloads=True)
    _path, run = run_comparison(online, project, root, threading.Event(), lambda _: None)
    assert run.status == 'completed', run.error
    assert run.settings['symbol_policy'] == 'online'
    _assert_unchanged(snapshot)
    # A following offline run is unaffected by the symbol-enabled run.
    _path, offline = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert offline.status == 'completed', offline.error


def test_cached_pdb_conflict_is_classified_and_run_preserved(fake_runtime):
    root, package, project, config = fake_runtime
    write_backend(package,
        'print("Traceback (most recent call last):")\n'
        'raise FileExistsError("Symbols are disabled, but the symbol is already downloaded C:/x/clfs.pdb")\n')
    path, run = run_comparison(config, project, root, threading.Event(), lambda _: None)
    assert run.status == 'failed'
    assert 'cached-symbol conflict' in run.error
    assert 'C:/x' not in run.error
    assert 'FileExistsError' in (path / 'analysis.log').read_text()
    assert (path / 'failure.txt').is_file()


def test_cached_pdb_classifier_does_not_capture_unrelated_file_exists():
    from patchtrace.diagnostics import describe_backend_exit

    text = describe_backend_exit(1, 'FileExistsError: [Errno 17] File exists: out/json')
    assert 'symbol' not in text.lower()


def test_backend_private_java_home_changes_child_environment_only(tmp_path, monkeypatch):
    from patchtrace.backend import BackendConfig, _config_errors, _environment

    python = tmp_path / 'python.exe'
    python.write_bytes(b'fake')
    python.chmod(0o700)
    ghidra = tmp_path / 'ghidra'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    jdk = tmp_path / 'my private jdk'
    (jdk / 'bin').mkdir(parents=True)
    (jdk / 'bin' / ('java.exe' if os.name == 'nt' else 'java')).write_bytes(b'fake')
    monkeypatch.setenv('JAVA_HOME', 'parent-untouched')
    config = BackendConfig(str(python), str(ghidra), java_home=str(jdk))
    assert _config_errors(config) == []
    child_env = _environment(config)
    assert child_env['JAVA_HOME'] == str(jdk)
    assert child_env['PATH'].split(os.pathsep)[0] == str(jdk / 'bin')
    assert os.environ['JAVA_HOME'] == 'parent-untouched'
    bad_config = BackendConfig(str(python), str(ghidra), java_home=str(tmp_path / 'missing'))
    assert any('Java' in item for item in _config_errors(bad_config))
