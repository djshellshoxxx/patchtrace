"""Isolation and evidence-completeness tests for tools/bundle_acceptance.py (BUNDLE-acceptance-isolation-spec s3,
s4.2, s7, s9). Hermetic: no network, no admin rights, no unshare, no Microsoft binaries, no target execution.

The Windows-branch tests run `os_name='windows'` on a POSIX host: the fake bundle's `python.exe` is a shebang
wrapper and every icacls/firewall command goes to a recording fake `host_run`. They prove the harness logic only;
the real Windows ACL and firewall behaviour stays a native CI gate (G4/G5).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if 'bundle_acceptance' in sys.modules:
    ba = sys.modules['bundle_acceptance']
else:
    _spec = importlib.util.spec_from_file_location('bundle_acceptance', ROOT / 'tools' / 'bundle_acceptance.py')
    ba = importlib.util.module_from_spec(_spec)
    sys.modules['bundle_acceptance'] = ba
    _spec.loader.exec_module(ba)

posix_only = pytest.mark.skipif(sys.platform == 'win32', reason='shebang fake bundle on a POSIX host')

_LAUNCHER = f'#!{sys.executable}\nimport sys\nsys.exit(0)\n'
_EXEC_TAIL = ['-I', '-c', 'print(1)']


def _write_exe(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')
    path.chmod(0o755)


def _windows_bundle(tmp_path: Path, python_body: str = ba.FAKE_PYTHON) -> tuple[Path, Path, Path]:
    """(root, launcher, python.exe) of a fake Windows release folder runnable on a POSIX host."""
    root = tmp_path / 'rel'
    payload = root / 'backend' / 'payload'
    (payload / 'jdk' / 'bin').mkdir(parents=True)
    (payload / 'ghidra').mkdir()
    (root / 'backend' / 'manifest.json').write_text('{"schema": 1, "files": []}\n', encoding='utf-8', newline='\n')
    py = payload / 'python' / 'python.exe'
    _write_exe(py, f'#!{sys.executable}\n' + python_body)
    launcher = root / 'PatchTrace.exe'
    _write_exe(launcher, _LAUNCHER)
    return root, launcher, py


class FakeHost:
    """Recording stand-in for subprocess.run on icacls/firewall commands; `hook(argv)` may act or raise."""

    def __init__(self, events: list | None = None, hook=None):
        self.events = events if events is not None else []
        self.hook = hook

    def __call__(self, argv, **kwargs):
        self.events.append(('host', list(argv)))
        result = self.hook(list(argv)) if self.hook else None
        return result if result is not None else subprocess.CompletedProcess(argv, 0, 'ok', '')

    @property
    def calls(self) -> list[list[str]]:
        return [argv for kind, argv in self.events if kind == 'host']


def _recording_run(monkeypatch, events: list, connected=lambda: False):
    """Real `_run` for the exec probe; the control probe answers `connected()` and every other command exits 0,
    both without a subprocess (no socket is ever opened)."""
    real = ba._run

    def fake(argv, env, timeout, cwd=None):
        events.append(('run', list(argv)))
        if list(argv[-3:]) == _EXEC_TAIL:
            return real(argv, env, timeout, cwd)
        if 'CONNECTED' in argv[-1]:
            if connected():
                return subprocess.CompletedProcess(argv, 0, 'CONNECTED\n', '')
            return subprocess.CompletedProcess(argv, 7, 'BLOCKED ConnectionRefusedError\n', '')
        return subprocess.CompletedProcess(argv, 0, '{}\n', '')
    monkeypatch.setattr(ba, '_run', fake)


def _is_deny(argv: list[str]) -> bool:
    return argv[:1] == ['icacls'] and '/deny' in argv


def _is_remove_deny(argv: list[str]) -> bool:
    return argv[:1] == ['icacls'] and '/remove:d' in argv


def _names(ev) -> list[str]:
    return [s.name for s in ev.steps]


def _run_windows(tmp_path, host, **kw):
    root, launcher, _ = kw.pop('bundle', None) or _windows_bundle(tmp_path)
    return ba.run_acceptance(root, tmp_path / 'old.dll', tmp_path / 'new.dll', 'read_item', os_name='windows',
                             launcher=launcher, control=('127.0.0.1', 9), dry_run=True, work=tmp_path / 'work',
                             host_run=host, **kw)


# ---------------------------------------------------------------- icacls command shape (s4.2)

def test_windows_readonly_command_denies_only_write_and_delete_rights():
    deny = ba.windows_readonly_command(r'C:\b', 'bob')
    assert deny == ['icacls', r'C:\b', '/deny', 'bob:(OI)(CI)(WD,AD,WEA,WA,DE,DC)']
    text = ' '.join(deny)
    for forbidden in ('(W,', ',W,', ',W)', '(D,', ',D,', ',D)', 'SYNCHRONIZE', '(F', '(M', '(R', 'RX', ',S'):
        assert forbidden not in text, forbidden
    rights = set(deny[-1].rsplit('(', 1)[1].rstrip(')').split(','))
    assert rights == {'WD', 'AD', 'WEA', 'WA', 'DE', 'DC'}       # never S, RC, RD, RA, REA or X
    assert ba.windows_readonly_command(r'C:\b', 'bob', deny=False) == ['icacls', r'C:\b', '/remove:d', 'bob', '/T']


# ---------------------------------------------------------------- cleanup and exec probes (s3 additions, s7.4)

def _boom(_root):
    raise RuntimeError('injected after the lock')


@posix_only
@pytest.mark.parametrize('failure', ['exec', 'raise'], ids=['exec', 'raise'])
def test_readonly_removal_runs_in_finally(tmp_path, monkeypatch, failure):
    monkeypatch.setenv('USERNAME', 'bob')
    host = FakeHost()
    bundle = _windows_bundle(tmp_path)
    if failure == 'exec':                       # the deny makes python.exe unstartable (run 38676664372)
        host.hook = lambda argv: bundle[2].chmod(0o644) if _is_deny(argv) else None
    else:                                       # an unexpected harness error after the lock
        monkeypatch.setattr(ba, 'writable_probe', _boom)
    ev = _run_windows(tmp_path, host, bundle=bundle)
    backend = str((tmp_path / 'rel' / 'backend').resolve())
    assert host.calls[0] == ba.windows_readonly_command(backend, 'bob')
    assert host.calls[-1] == ba.windows_readonly_command(backend, 'bob', deny=False), host.calls
    assert not ev.ok
    assert _names(ev)[-1] == ('exec-after-readonly' if failure == 'exec' else 'harness-exception')


@posix_only
def test_run_acceptance_records_harness_exception_and_still_writes_evidence(tmp_path, monkeypatch):
    root = tmp_path / 'rel'
    root.mkdir()
    ba.make_fake_bundle(root, _LAUNCHER)
    backend = root / 'backend'

    def fake_run(argv, env, timeout, cwd=None):
        if list(argv[-3:]) == _EXEC_TAIL:
            return subprocess.CompletedProcess(argv, 0, '1\n', '')
        raise PermissionError(13, '[WinError 5] Access is denied')
    monkeypatch.setattr(ba, '_run', fake_run)
    out = tmp_path / 'evidence.json'
    rc = ba.main([str(root), '--older', str(tmp_path / 'o'), '--newer', str(tmp_path / 'n'),
                  '--expect-function', 'f', '--control', '127.0.0.1:9', '--evidence', str(out), '--dry-run'])
    assert rc == 1
    doc = json.loads(out.read_text(encoding='utf-8'))
    steps = {s['name']: s for s in doc['steps']}
    assert doc['ok'] is False and doc['schema'] == ba.SCHEMA
    assert steps['exec-before-readonly']['ok'] and steps['exec-after-readonly']['ok']
    assert doc['steps'][-1]['name'] == 'harness-exception'
    detail = steps['harness-exception']['detail']
    assert 'PermissionError' in detail and 'Access is denied' in detail and 0 < len(detail) <= 400
    assert ba.set_tree_readonly(backend, False) == 0                # modes were restored in finally


@pytest.mark.parametrize('exc', [RuntimeError, KeyboardInterrupt], ids=['error', 'interrupt'])
def test_main_writes_evidence_even_when_run_raises(tmp_path, monkeypatch, exc):
    def explode(*args, **kwargs):
        evidence = kwargs.get('evidence')
        if evidence is not None:
            evidence.add('layout', True)
        raise exc('injected')
    monkeypatch.setattr(ba, 'run_acceptance', explode)
    out = tmp_path / 'evidence.json'
    argv = [str(tmp_path), '--older', 'a', '--newer', 'b', '--expect-function', 'f', '--evidence', str(out)]
    if exc is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            ba.main(argv)
    else:
        assert ba.main(argv) == 1
    doc = json.loads(out.read_text(encoding='utf-8'))
    assert doc['ok'] is False and doc['steps'][0]['name'] == 'layout'      # a partial file is never a pass
    assert doc['steps'][-1]['name'] == 'harness-exception' and exc.__name__ in doc['steps'][-1]['detail']


@posix_only
@pytest.mark.parametrize('os_name', ['linux', 'windows'], ids=['lin', 'win'])
def test_exec_probe_runs_before_and_after_the_lock(tmp_path, monkeypatch, os_name):
    events: list = []
    _recording_run(monkeypatch, events)
    work = tmp_path / 'work'
    if os_name == 'windows':
        root, launcher, py = _windows_bundle(tmp_path)
        lock_index = lambda: next(i for i, e in enumerate(events) if e[0] == 'host' and _is_deny(e[1]))  # noqa: E731
    else:
        root = tmp_path / 'rel'
        root.mkdir()
        ba.make_fake_bundle(root, _LAUNCHER)
        launcher, py = root / 'PatchTrace' / 'PatchTrace', root / 'backend' / 'payload' / 'python' / 'bin' / 'python3'
        real_lock = ba.set_tree_readonly

        def lock(path, readonly):
            events.append(('lock', readonly))
            return real_lock(path, readonly)
        monkeypatch.setattr(ba, 'set_tree_readonly', lock)
        lock_index = lambda: events.index(('lock', True))  # noqa: E731
    ev = ba.run_acceptance(root, tmp_path / 'o', tmp_path / 'n', 'f', os_name=os_name, launcher=launcher,
                           control=('127.0.0.1', 9), dry_run=True, work=work, host_run=FakeHost(events))
    probe = [str(py.resolve()), *_EXEC_TAIL]
    runs = [i for i, e in enumerate(events) if e == ('run', probe)]
    assert len(runs) == 2 and runs[0] < lock_index() < runs[1], events
    control = next(i for i, e in enumerate(events) if e[0] == 'run' and e[1] != probe)
    assert runs[1] < control
    names = _names(ev)
    i = names.index('exec-before-readonly')
    expected = ['digest-before', 'exec-before-readonly', 'exec-after-readonly']
    expected += ['readonly-effective', 'control-before', 'firewall-block'] if os_name == 'windows' else ['control-before']
    assert names[i - 1:i - 1 + len(expected)] == expected, names
    steps = {s.name: s for s in ev.steps}
    for name in ('exec-before-readonly', 'exec-after-readonly'):
        assert steps[name].ok and steps[name].data['argv'] == probe and steps[name].data['duration_s'] >= 0
    for name in ('control-before', 'control-after'):
        assert steps[name].data['argv'][0] == str(py.resolve()) and steps[name].data['duration_s'] >= 0
    assert str(work) not in json.dumps([s.data for s in ev.steps])      # argv only, never env values


@posix_only
@pytest.mark.parametrize('case', ['before-exit', 'after-denied', 'after-output'], ids=['b-exit', 'a-deny', 'a-out'])
def test_exec_probe_failure_is_reported_before_the_control(tmp_path, monkeypatch, case):
    events: list = []
    _recording_run(monkeypatch, events, connected=lambda: True)
    body = ba.FAKE_PYTHON
    if case == 'before-exit':
        body = 'import sys\nif sys.argv[1:] == ["-I", "-c", "print(1)"]:\n    sys.exit(3)\n' + body
    bundle = _windows_bundle(tmp_path, body)
    py = bundle[2]

    def hook(argv):
        if _is_deny(argv) and case == 'after-denied':
            py.chmod(0o644)                                       # spawning it now raises PermissionError
        if _is_deny(argv) and case == 'after-output':
            _write_exe(py, f'#!{sys.executable}\nprint("noise")\n')
    host = FakeHost(events, hook)
    ev = _run_windows(tmp_path, host, bundle=bundle)
    names = _names(ev)
    failed = 'exec-before-readonly' if case == 'before-exit' else 'exec-after-readonly'
    assert names[-1] == failed and not ev.steps[-1].ok, names
    assert 'control-before' not in names and 'harness-exception' not in names and not ev.ok
    assert not any('Firewall' in ' '.join(argv) for argv in host.calls)
    detail = ev.steps[-1].detail
    if case == 'before-exit':
        assert host.calls == [] and 'exit 3' in detail                  # never locked, nothing to remove
    else:
        assert _is_deny(host.calls[0]) and _is_remove_deny(host.calls[-1])
        assert ('PermissionError' in detail) if case == 'after-denied' else ('noise' in detail)


@posix_only
@pytest.mark.parametrize('mode', ['exit', 'raise'], ids=['exit', 'raise'])
def test_firewall_command_failure_is_a_step_not_a_crash(tmp_path, monkeypatch, mode):
    events: list = []
    _recording_run(monkeypatch, events, connected=lambda: True)
    adds: list[list[str]] = []

    def hook(argv):
        if 'New-NetFirewallRule' in argv[-1]:
            adds.append(argv)
            if len(adds) == 2:
                if mode == 'raise':
                    raise OSError('powershell: Access is denied')
                return subprocess.CompletedProcess(argv, 1, '', 'New-NetFirewallRule : Access is denied')
        return None
    host = FakeHost(events, hook)
    ev = _run_windows(tmp_path, host)
    names = _names(ev)
    assert names[-1] == 'firewall-block' and not ev.steps[-1].ok, names
    assert 'Access is denied' in ev.steps[-1].detail and len(ev.steps[-1].detail) <= 400
    assert 'control-after' not in names and 'harness-exception' not in names and not ev.ok
    assert len(adds) == 2                                           # stopped at the failing rule
    programs = ba.windows_programs((tmp_path / 'rel').resolve())
    _, removes = ba.windows_firewall_commands(programs)
    assert removes[0] in host.calls[host.calls.index(adds[1]) + 1:]  # the rule already added is removed
    assert _is_remove_deny(host.calls[-1])


@posix_only
def test_windows_branch_full_order_and_subprocess_records(tmp_path, monkeypatch):
    events: list = []
    blocked = []
    _recording_run(monkeypatch, events, connected=lambda: not blocked)

    def hook(argv):
        if 'New-NetFirewallRule' in argv[-1]:
            blocked.append(argv)
    monkeypatch.setattr(ba, 'writable_probe', lambda _root: False)
    ev = _run_windows(tmp_path, FakeHost(events, hook))
    assert _names(ev) == ['layout', 'path-shape', 'env-scrub', 'path-has-no-java-python', 'digest-before',
                          'exec-before-readonly', 'exec-after-readonly', 'readonly-effective', 'control-before',
                          'firewall-block', 'control-after', 'backend-verify-full', 'backend-selftest',
                          'ghidriff-compare', 'no-external-connections', 'digest-after-equal'], ev.to_json()
    assert ev.ok, ev.to_json()
    steps = {s.name: s for s in ev.steps}
    for name in ('exec-before-readonly', 'exec-after-readonly', 'readonly-effective', 'control-before',
                 'control-after', 'backend-verify-full', 'backend-selftest', 'ghidriff-compare'):
        assert isinstance(steps[name].data['argv'], list) and steps[name].data['duration_s'] >= 0, name
    assert steps['firewall-block'].data['commands'] == blocked
    assert steps['digest-after-equal'].detail == steps['digest-before'].detail


@posix_only
@pytest.mark.parametrize('mode', ['timeout', 'verbose'], ids=['timeout', 'verbose'])
def test_cleanup_records_every_failed_removal_with_argv_and_duration(tmp_path, monkeypatch, mode):
    """Each failed removal keeps its own bounded reason, so verbose firewall errors can never push the ACL deny
    removal result out of the evidence (spec s3 `cleanup`)."""
    monkeypatch.setenv('USERNAME', 'bob')
    events: list = []
    blocked = []
    _recording_run(monkeypatch, events, connected=lambda: not blocked)

    def hook(argv):
        if 'New-NetFirewallRule' in argv[-1]:
            blocked.append(argv)
        elif 'Remove-NetFirewallRule' in argv[-1]:
            if mode == 'timeout':
                raise subprocess.TimeoutExpired(argv, ba.HOST_TIMEOUT)
            return subprocess.CompletedProcess(argv, 1, '', 'Remove-NetFirewallRule : ' + 'x' * 900)
        elif _is_remove_deny(argv):
            return subprocess.CompletedProcess(argv, 5, '', 'bob: Access is denied.')
        return None
    monkeypatch.setattr(ba, 'writable_probe', lambda _root: False)
    ev = _run_windows(tmp_path, FakeHost(events, hook))
    steps = {s.name: s for s in ev.steps}
    assert 'cleanup' in steps and not steps['cleanup'].ok and not ev.ok, _names(ev)
    cleanup = steps['cleanup']
    programs = ba.windows_programs((tmp_path / 'rel').resolve())
    _, removes = ba.windows_firewall_commands(programs)
    backend = str((tmp_path / 'rel' / 'backend').resolve())
    acl = ba.windows_readonly_command(backend, 'bob', deny=False)
    assert len(removes) >= 2
    assert cleanup.data['commands'] == [*removes, acl]                     # every removal argv that ran
    assert [f['argv'] for f in cleanup.data['failures']] == [*removes, acl]  # structured, never truncated away
    assert all(0 < len(f['reason']) <= ba.DETAIL_LIMIT for f in cleanup.data['failures'])
    assert cleanup.data['failures'][-1]['reason'] == 'exit 5: bob: Access is denied.'
    if mode == 'timeout':                       # the argv is recorded once, not repeated inside every reason
        assert cleanup.data['failures'][0]['reason'] == f'TimeoutExpired: no exit after {ba.HOST_TIMEOUT} s'
    assert cleanup.data['duration_s'] >= 0
    detail = cleanup.detail
    assert len(detail) <= ba.DETAIL_LIMIT
    assert 'icacls /remove:d: exit 5: bob: Access is denied.' in detail, detail  # the ACL result survives
    for program in programs:                                                # and so does every firewall failure
        assert f'firewall {Path(program).name}: ' in detail, detail
    assert detail.startswith(f'{len(removes) + 1} of {len(removes) + 1} removals failed'), detail
    assert json.loads(ev.to_json())['steps'][-2]['name'] == 'cleanup'
