"""Unit tests for tools/bundle_acceptance.py (BUNDLE slice B5a). Hermetic: no network beyond a loopback listener.

Everything here is synthetic. The dry run uses a fake bundle and proves harness logic plus the Linux namespace
denial; it is NOT evidence about the real Ghidra/JDK payload or the Windows firewall (CI only, B5b).
"""
from __future__ import annotations

import importlib.util
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('bundle_acceptance', ROOT / 'tools' / 'bundle_acceptance.py')
ba = importlib.util.module_from_spec(_spec)
sys.modules['bundle_acceptance'] = ba
_spec.loader.exec_module(ba)


@pytest.mark.parametrize('os_name', ['linux', 'windows'])
def test_scrub_env_has_no_forbidden_variables(os_name):
    env = ba.scrub_env(os_name, '/h', '/t', ba.minimal_path(os_name))
    assert ba.env_violations(env, os_name) == []
    assert env['TEMP'] == '/t' and 'PATH' in env


@pytest.mark.parametrize('key', ['JAVA_HOME', 'PYTHONPATH', 'GHIDRA_INSTALL_DIR', 'PIP_INDEX_URL', 'HTTPS_PROXY'])
def test_env_violations_flags_each_forbidden_name(key):
    assert ba.env_violations({'PATH': 'x', key: '1'}) == [key]


def test_env_violations_windows_is_case_insensitive():
    assert ba.env_violations({'java_home': 'x'}, 'windows') == ['java_home']
    assert ba.env_violations({'java_home': 'x'}, 'linux') == []   # POSIX names are case-sensitive
    assert ba.env_violations({'Path': 'x'}, 'windows') == []


@pytest.mark.parametrize('os_name, path, present, hits', [
    ('linux', '/usr/bin:/bin', {'/usr/bin/python3'}, 1),
    ('linux', '/nonexistent', {'/usr/bin/java'}, 0),
    ('windows', r'C:\jdk\bin;C:\Windows', {r'C:\jdk\bin\java.exe'}, 1),
])
def test_path_tool_hits(os_name, path, present, hits):
    found = ba.path_tool_hits(path, os_name, exists=lambda p: str(p).replace('\\', '/').lower() in
                              {x.replace('\\', '/').lower() for x in present} or str(p) in present)
    assert len(found) == hits


def test_path_tool_hits_on_real_minimal_path_is_empty():
    assert ba.path_tool_hits(ba.minimal_path(ba.host_os()), ba.host_os()) == []


def test_run_path_puts_jdk_first():
    assert ba.run_path('linux', '/jdk/bin', '/nonexistent').split(os.pathsep)[0] == '/jdk/bin'
    assert ba.run_path('linux', None, '/nonexistent') == '/nonexistent'


def test_path_is_hostile_needs_space_and_non_ascii():
    assert ba.path_is_hostile(f'/tmp/{ba.UNICODE_DIRNAME}')
    assert not ba.path_is_hostile('/tmp/plain')
    assert not ba.path_is_hostile('/tmp/with space')


def _tree(root: Path) -> Path:
    (root / 'a' / 'b').mkdir(parents=True)
    (root / 'a' / 'one.txt').write_bytes(b'one')
    (root / 'a' / 'b' / 'two.txt').write_bytes(b'two')
    return root


def test_tree_digest_stable_and_detects_each_change(tmp_path):
    root = _tree(tmp_path / 't')
    base = ba.tree_digest(root)
    assert ba.tree_digest(root) == base
    (root / 'a' / 'one.txt').write_bytes(b'One')            # flipped content, same size
    assert ba.tree_digest(root) != base
    (root / 'a' / 'one.txt').write_bytes(b'one')
    assert ba.tree_digest(root) == base
    (root / 'extra').write_bytes(b'')                       # extra file
    assert ba.tree_digest(root) != base
    (root / 'extra').unlink()
    (root / 'a' / 'b' / 'two.txt').unlink()                 # missing file
    assert ba.tree_digest(root) != base


def test_tree_digest_distinguishes_rename_and_empty_dir(tmp_path):
    root = _tree(tmp_path / 't')
    base = ba.tree_digest(root)
    (root / 'a' / 'one.txt').rename(root / 'a' / 'uno.txt')
    assert ba.tree_digest(root) != base
    (root / 'a' / 'uno.txt').rename(root / 'a' / 'one.txt')
    (root / 'emptydir').mkdir()
    assert ba.tree_digest(root) != base


@pytest.mark.skipif(sys.platform == 'win32', reason='posix modes')
def test_readonly_round_trip_changes_modes_not_digest(tmp_path):
    root = _tree(tmp_path / 't')
    base = ba.tree_digest(root)
    assert ba.set_tree_readonly(root, True) > 0
    try:
        assert not (root / 'a' / 'one.txt').stat().st_mode & 0o200
        assert ba.tree_digest(root) == base
    finally:
        ba.set_tree_readonly(root, False)
    assert (root / 'a' / 'one.txt').stat().st_mode & 0o200
    assert ba.set_tree_readonly(root, False) == 0


@pytest.mark.parametrize('before, after, verdict', [
    (True, False, 'proven'),
    (False, False, 'invalid-no-baseline'),
    (True, True, 'denial-ineffective'),
    (False, True, 'invalid-no-baseline'),
])
def test_control_verdict(before, after, verdict):
    assert ba.control_verdict(before, after) == verdict


@pytest.mark.parametrize('text', ['1.1.1.1:443', '127.0.0.1:1', '[::1]:80'])
def test_parse_target_accepts(text):
    host, port = ba.parse_target(text)
    assert f'{host}:{port}' == text


@pytest.mark.parametrize('text', ['1.1.1.1', ':443', 'h:0', 'h:70000', 'h:x'])
def test_parse_target_rejects(text):
    with pytest.raises(ValueError):
        ba.parse_target(text)


def test_probe_code_compiles_and_embeds_target():
    code = ba.probe_code('203.0.113.9', 443)
    compile(code, '<probe>', 'exec')
    assert "'203.0.113.9'" in code and '443' in code


def test_probe_connects_to_loopback_listener_then_reports_blocked():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    ok = subprocess.run([sys.executable, '-I', '-c', ba.probe_code('127.0.0.1', port)], capture_output=True, text=True)
    assert ok.returncode == 0 and 'CONNECTED' in ok.stdout
    listener.close()
    bad = subprocess.run([sys.executable, '-I', '-c', ba.probe_code('127.0.0.1', port, 1.0)], capture_output=True, text=True)
    assert bad.returncode == 7 and 'BLOCKED' in bad.stdout


def test_linux_denial_argv_shape():
    argv = ba.linux_denial_argv(['/b/PatchTrace', 'backend', 'selftest'], {'PATH': '/nonexistent', 'HOME': '/h'}, 1001, 1002,
                                 resolve=lambda n: n)
    assert argv[:4] == ['unshare', '--net', '--', 'sh']
    tail = argv[argv.index('setpriv'):]
    assert tail[:6] == ['setpriv', '--reuid', '1001', '--regid', '1002', '--clear-groups']
    assert tail[6:9] == ['env', '-i', 'HOME=/h']
    assert tail[-3:] == ['/b/PatchTrace', 'backend', 'selftest']
    assert ba.linux_denial_argv(['x'], {}, 0, 0, sudo=True, resolve=lambda n: n)[:2] == ['sudo', '-n']


def test_ps_quote_doubles_single_quotes():
    assert ba.ps_quote("C:\\O'Neil\\x.exe") == "'C:\\O''Neil\\x.exe'"


def test_windows_firewall_commands_one_block_rule_per_program_and_matching_removal():
    progs = [r'C:\p\PatchTrace.exe', r'C:\p\backend\payload\jdk\bin\java.exe']
    add, remove = ba.windows_firewall_commands(progs)
    assert len(add) == len(remove) == 2
    for cmd, prog in zip(add, progs, strict=True):
        assert cmd[0] == 'powershell' and '-Direction Outbound -Action Block' in cmd[-1]
        assert ba.ps_quote(prog) in cmd[-1]
    assert len({ba.firewall_rule_name('PatchTraceAccept', p) for p in progs}) == 2
    assert all(ba.firewall_rule_name('PatchTraceAccept', p) in r[-1] for p, r in zip(progs, remove, strict=True))


def test_windows_programs_lists_only_existing(tmp_path):
    (tmp_path / 'backend' / 'payload' / 'jdk' / 'bin').mkdir(parents=True)
    (tmp_path / 'backend' / 'payload' / 'jdk' / 'bin' / 'java.exe').write_bytes(b'')
    (tmp_path / 'PatchTrace.exe').write_bytes(b'')
    listed = ba.windows_programs(tmp_path)
    assert [Path(p).name for p in listed] == ['PatchTrace.exe', 'java.exe']


def test_windows_readonly_command_pair():
    assert ba.windows_readonly_command(r'C:\b', 'bob')[:3] == ['icacls', r'C:\b', '/deny']
    assert '/remove:d' in ba.windows_readonly_command(r'C:\b', 'bob', deny=False)


_TCP_HEADER = '  sl  local_address rem_address   st tx_queue rx_queue\n'


@pytest.mark.parametrize('line, expected', [
    ('   0: 0100007F:9C40 0100007F:0050 01 00000000:00000000', 0),      # loopback established
    ('   1: 0A00000A:9C40 0101A8C0:01BB 01 00000000:00000000', 1),      # external established
    ('   2: 0A00000A:9C40 0101A8C0:01BB 06 00000000:00000000', 0),      # TIME_WAIT
    ('   3: 0A00000A:0050 00000000:0000 0A 00000000:00000000', 0),      # LISTEN
])
def test_parse_proc_net_tcp(line, expected):
    assert len(ba.parse_proc_net_tcp(_TCP_HEADER + line + '\n')) == expected


def test_parse_proc_net_tcp_ipv6_loopback_is_ignored():
    line = '   0: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:0050 01 0:0\n'
    assert ba.parse_proc_net_tcp(_TCP_HEADER + line) == []


def test_connection_monitor_collects_distinct_and_survives_sampler_errors():
    calls = []

    def sample():
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError('boom')
        return ['1.2.3.4:443']
    with ba.ConnectionMonitor(sample, interval=0.01) as mon:
        while len(calls) < 4:
            pass
    assert mon.seen == {'1.2.3.4:443'} and mon.polls >= 3


def test_evidence_wording_requires_proven_control():
    ev = ba.Evidence('linux', '/r')
    ev.add('control-after', True)
    assert 'passed with OS network block' in ev.wording()
    bad = ba.Evidence('linux', '/r')
    bad.add('control-after', False)
    assert 'FAILED' in bad.wording() and not bad.ok
    assert 'dry run' in ba.Evidence('linux', '/r', dry_run=True).wording()
    assert not ba.Evidence('linux', '/r').ok                       # no steps is never a pass


def test_run_acceptance_rejects_missing_layout(tmp_path):
    ev = ba.run_acceptance(tmp_path, tmp_path / 'o', tmp_path / 'n', 'f', os_name='linux', dry_run=True)
    assert not ev.ok and ev.steps[0].name == 'layout'


# ---- dry run with a fake bundle (Linux, needs unshare)

_LAUNCHER = f"""#!{sys.executable}
import sys
sys.exit(0 if sys.argv[1:3] in (['backend', 'verify'], ['backend', 'selftest']) else 2)
"""


def _unshare_works() -> bool:
    if sys.platform != 'linux':
        return False
    try:
        return subprocess.run(['unshare', '--net', 'true'], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.fixture
def listener():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sock.listen(8)
    stop = threading.Event()

    def accept():
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                sock.accept()[0].close()
            except OSError:
                pass
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield sock.getsockname()[1]
    stop.set()
    thread.join(timeout=2)
    sock.close()


@pytest.mark.skipif(not _unshare_works(), reason='needs Linux unshare --net')
def test_dry_run_with_fake_bundle_proves_denial_and_equal_digest(tmp_path, listener):
    root = tmp_path / 'rel'
    root.mkdir()
    ba.make_fake_bundle(root, _LAUNCHER)
    older, newer = tmp_path / 'old.bin', tmp_path / 'new.bin'
    older.write_bytes(b'a')
    newer.write_bytes(b'b')
    ev = ba.run_acceptance(root, older, newer, 'read_item', control=('127.0.0.1', listener), dry_run=True,
                           work=tmp_path / 'work')
    names = {s.name: s for s in ev.steps}
    assert names['control-before'].ok and names['control-after'].data['verdict'] == 'proven', ev.to_json()
    assert ev.ok, ev.to_json()
    assert names['digest-after-equal'].detail == names['digest-before'].detail
    assert names['ghidriff-compare'].ok and names['no-external-connections'].ok
    assert 'dry run' in ev.wording()
    assert ba.set_tree_readonly(root / 'backend', False) == 0       # modes were restored


@pytest.mark.skipif(not _unshare_works(), reason='needs Linux unshare --net')
def test_dry_run_fails_when_control_has_no_baseline(tmp_path):
    root = tmp_path / 'rel'
    root.mkdir()
    ba.make_fake_bundle(root, _LAUNCHER)
    dead = socket.socket()
    dead.bind(('127.0.0.1', 0))
    port = dead.getsockname()[1]
    dead.close()                                                    # nothing listens: baseline cannot connect
    ev = ba.run_acceptance(root, tmp_path / 'o', tmp_path / 'n', 'f', control=('127.0.0.1', port), dry_run=True,
                           work=tmp_path / 'work')
    assert not ev.ok
    assert {s.name: s for s in ev.steps}['control-after'].data['verdict'] == 'invalid-no-baseline'
    assert 'backend-selftest' not in {s.name for s in ev.steps}      # no run without a proven block


@pytest.mark.skipif(not _unshare_works(), reason='needs Linux unshare --net')
def test_dry_run_detects_launcher_mutating_the_tree(tmp_path, listener):
    root = tmp_path / 'rel'
    root.mkdir()
    evil = _LAUNCHER.replace('import sys', f'import sys, os\nos.chmod({str(root / "backend")!r}, 0o755)\n'
                             f'open({str(root / "backend" / "dropped.txt")!r}, "w").write("x")', 1)
    ba.make_fake_bundle(root, evil)
    ev = ba.run_acceptance(root, tmp_path / 'o', tmp_path / 'n', 'f', control=('127.0.0.1', listener), dry_run=True,
                           work=tmp_path / 'work')
    # root can write (digest differs), non-root is denied by the read-only tree (launcher crashes): both fail.
    assert not ev.ok


def test_main_usage_error_on_bad_control(tmp_path, capsys):
    rc = ba.main([str(tmp_path), '--older', 'a', '--newer', 'b', '--expect-function', 'f', '--control', 'nope'])
    assert rc == 2
