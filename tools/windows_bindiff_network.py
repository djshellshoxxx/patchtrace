"""Bounded Windows native BinDiff acceptance; not shipped product isolation.

See docs/specs/windows-bindiff-network-acceptance.md. Pure validators run on any
host. Windows SDK builds and actual AppContainer/network observations are a
separate native gate. Missing capabilities never become successful evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON = 2 * 1024 * 1024
MAX_FILES = 4096
MAX_TOOL_BYTES = 512 * 1024 * 1024
SOCKET_CASES = ('tcp4-loopback', 'tcp6-loopback', 'udp4-loopback', 'udp6-loopback', 'tcp4-external')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SHA1 = re.compile(r'[0-9a-f]{40}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')
APP_SID = re.compile(r'S-1-15-2-(?:[0-9]{1,10}-){6}[0-9]{1,10}\Z')
CREATION_TIME = re.compile(r'[1-9][0-9]{0,19}\Z')
PROFILE_PREFIX = 'PatchTrace.Acceptance.'
NATIVE_SOURCES = ('launcher.c', 'probe.c', 'common.h')


class NetworkEvidenceError(ValueError):
    """Missing, contradictory or malformed qualification evidence."""


class NetworkUnavailable(NetworkEvidenceError):
    """Native capability or a positive control is unavailable (blocked)."""


def require(condition, reason):
    if not condition:
        raise NetworkEvidenceError(reason)


def _integer(value, low=0, high=(1 << 63) - 1):
    return type(value) is int and low <= value <= high


def _digest(value, pattern=SHA256):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _creation_time(value):
    """One canonical spelling for the native helper's nonzero uint64 identity."""
    return isinstance(value, str) and CREATION_TIME.fullmatch(value) is not None and int(value) < 1 << 64


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def semantic_fingerprint(match_set):
    """All imported semantics, independent of row order and execution identity."""
    data = match_set.model_dump(mode='json')
    data.pop('file_sha256', None)
    data.pop('run_id', None)
    for row in data['matches']:
        row['flags'] = sorted(row['flags'])
    data['matches'] = sorted(data['matches'], key=_canonical)
    alternatives = data.setdefault('alternatives', [])
    for row in alternatives:
        row['candidate']['flags'] = sorted(row['candidate']['flags'])
    data['alternatives'] = sorted(alternatives, key=_canonical)
    data['limitations'] = sorted(data['limitations'])
    return hashlib.sha256(b'patchtrace-bindiff-semantics/1\0' + _canonical(data)).hexdigest()


def read_evidence_bytes(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON, 'receipt byte bound')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def number(text):
        value = float(text)
        require(math.isfinite(value), 'nonfinite JSON number')
        return value

    def constant(_text):
        raise NetworkEvidenceError('nonfinite JSON constant')

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=number,
                           parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise NetworkEvidenceError('invalid strict JSON: ' + str(exc)[:160]) from exc
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(depth <= 24 and count <= 50000, 'JSON structural bound')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


def _chain_identity(rows, *, sid, nonce, blocked):
    require(isinstance(rows, list) and len(rows) == 3, 'incomplete native process chain')
    seen = set()
    for depth, row in enumerate(rows):
        require(isinstance(row, dict), 'malformed native process')
        pid, parent = row.get('pid'), row.get('parent_pid')
        require(_integer(pid, 1, (1 << 32) - 1) and _integer(parent, 1, (1 << 32) - 1) and
                pid != parent and pid not in seen, 'invalid/duplicate native process identity')
        require(row.get('depth') == depth and type(row.get('depth')) is int and
                (depth == 0 or parent == rows[depth - 1]['pid']), 'native descendant ownership')
        seen.add(pid)
        require(row.get('nonce') == nonce and row.get('appcontainer') is blocked and
                row.get('sid') == (sid if blocked else '') and
                type(row.get('capability_count')) is int and row['capability_count'] == 0,
                'native token or nonce differs')
        created = row.get('created')
        require(_creation_time(created), 'missing or noncanonical native process creation identity')


def _probe_chain(rows, *, sid, nonce, blocked):
    _chain_identity(rows, sid=sid, nonce=nonce, blocked=blocked)
    for row in rows:
        cases = row.get('cases')
        require(isinstance(cases, list) and len(cases) == len(SOCKET_CASES) and
                all(isinstance(case, dict) for case in cases), 'missing socket cases')
        require(all(case.get('case') in SOCKET_CASES for case in cases) and
                sorted(case['case'] for case in cases) == sorted(SOCKET_CASES),
                'ambiguous socket case ownership')
        for case in cases:
            require(case.get('status') == ('denied' if blocked else 'connected') and
                    type(case.get('error')) is int and case['error'] == (10013 if blocked else 0),
                    'socket observation is not the required positive/access-denied control')


def validate_evidence(doc, *, source_sha, source_tree, helper_sha, probe_sha, executable_sha, nonce,
                      baseline_count, baseline_semantic):
    """Validate observations against independently known source/build/input ownership."""
    require(_digest(source_sha, SHA1) and _digest(source_tree, SHA1) and _digest(helper_sha) and _digest(probe_sha) and
            _digest(executable_sha) and _digest(nonce, NONCE) and _digest(baseline_semantic) and
            _integer(baseline_count, 1), 'invalid expected evidence ownership')
    require(isinstance(doc, dict) and doc.get('contract') == 'bindiff-network/1' and
            doc.get('native') is True and doc.get('nonce') == nonce, 'not native owned evidence')
    require(doc.get('source') == {'commit': source_sha, 'tree': source_tree} and
            doc.get('helper_sha256') == helper_sha and doc.get('probe_sha256') == probe_sha and
            doc.get('executable_sha256') == executable_sha,
            'source/build identity differs')
    elapsed = doc.get('elapsed_s')
    require(type(elapsed) in (int, float) and 0 <= elapsed <= 600 and math.isfinite(elapsed),
            'invalid native execution duration')
    profile = doc.get('profile')
    require(isinstance(profile, dict) and profile.get('name') == PROFILE_PREFIX + nonce and
            isinstance(profile.get('sid'), str) and APP_SID.fullmatch(profile['sid']) and
            all(int(part) < 1 << 32 for part in profile['sid'].split('-')[4:]) and
            type(profile.get('capability_count')) is int and profile['capability_count'] == 0,
            'invalid owned zero-capability profile')
    probes = doc.get('probes')
    require(isinstance(probes, dict) and set(probes) == {'before', 'denied', 'after'},
            'missing before/denied/after control')
    for phase, rows in probes.items():
        _probe_chain(rows, sid=profile['sid'], nonce=nonce, blocked=phase == 'denied')
    probe_launch = doc.get('probe_launch')
    first = probes['denied'][0]
    require(isinstance(probe_launch, dict) and probe_launch.get('pid') == first['pid'] and
            probe_launch.get('created') == first['created'] and
            probe_launch.get('owner_pid') == first['parent_pid'] and
            probe_launch.get('executable_sha256') == probe_sha,
            'denied probe launch ownership differs')
    launches = doc.get('launches')
    require(isinstance(launches, list) and len(launches) == 3 and
            all(isinstance(row, dict) for row in launches), 'missing native probe/diff launch')
    require([row.get('purpose') for row in launches] == ['probe-version', 'probe-help', 'diff'],
            'native probe/diff launch ownership')
    seen = set()
    for row in [probe_launch, *launches]:
        pid = row.get('pid')
        created = row.get('created')
        require(_integer(pid, 1, (1 << 32) - 1), 'invalid launch process identity')
        require(row.get('sid') == profile['sid'] and type(row.get('capability_count')) is int and
                row['capability_count'] == 0 and
                row.get('executable_sha256') == (probe_sha if row is probe_launch else executable_sha),
                'native launch token/image identity')
        require(all(row.get(key) is True for key in
                    ('appcontainer', 'suspended', 'job_before_resume', 'token_before_resume', 'image_locked',
                     'tree_empty')) and
                row.get('handles') == ['nul', 'pipe', 'pipe'], 'native launch containment unverified')
        require(_creation_time(created) and _integer(row.get('owner_pid'), 1, (1 << 32) - 1) and
                row['owner_pid'] != pid, 'native launch creation/owner identity is incomplete')
        require((pid, created) not in seen, 'duplicate native process creation identity')
        seen.add((pid, created))
    lifecycle = doc.get('lifecycle')
    require(isinstance(lifecycle, dict) and set(lifecycle) == {'cancel', 'timeout', 'owner_exit'},
            'native lifecycle control incomplete')
    for label, record in lifecycle.items():
        require(isinstance(record, dict), 'lifecycle summary has no observations')
        reason = {'cancel': 'cancelled', 'timeout': 'timeout', 'owner_exit': 'owner-exit'}[label]
        require(record.get('reason') == reason and
                _integer(record.get('owner_exit_code'), -(1 << 31), (1 << 32) - 1) and
                record['owner_exit_code'] != 0 and
                record.get('observed') == {'alive': [], 'uncertain': False}, 'lifecycle interruption unverified')
        rows = record.get('processes')
        _lifetime_tokens(rows, profile, nonce)
        start = record.get('launch')
        require(isinstance(start, dict) and start.get('pid') == rows[0]['pid'] and
                start.get('created') == rows[0]['created'] and start.get('sid') == profile['sid'] and
                _integer(start.get('owner_pid'), 1, (1 << 32) - 1) and
                start['owner_pid'] not in {row['pid'] for row in rows} and
                rows[0]['parent_pid'] == start['owner_pid'] and
                start.get('executable_sha256') == probe_sha and
                type(start.get('capability_count')) is int and start['capability_count'] == 0 and
                all(start.get(key) is True for key in ('appcontainer', 'suspended', 'job_before_resume',
                                                       'token_before_resume', 'image_locked')) and
                start.get('handles') == ['nul', 'pipe', 'pipe'], 'lifecycle launch ownership differs')
    adapter = doc.get('adapter')
    require(isinstance(adapter, dict) and adapter.get('status') == 'passed' and
            _integer(adapter.get('matches'), 1) and adapter['matches'] == baseline_count and
            adapter.get('semantic_sha256') == baseline_semantic and
            _digest(adapter.get('output_sha256')) and adapter.get('acceptance') == 'C3 accept_binexport',
            'adapter acceptance/count/complete semantics differ')
    cleanup = doc.get('cleanup')
    require(isinstance(cleanup, dict) and set(cleanup) == {'profile_deleted', 'tree_removed',
                                                         'process_tree_empty'} and
            all(value is True for value in cleanup.values()), 'owned cleanup is incomplete')


def directory_identity(path):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'owned directory is not plain')
    return info.st_dev, info.st_ino


def _state(info):
    # Reading can update access time. It is not a content/ownership mutation.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            getattr(info, 'st_file_attributes', 0))


def remove_owned_tree(path, identity):
    require(directory_identity(path) == identity, 'owned directory was replaced; cleanup refused')
    # Python 3.12's rmtree does not traverse Windows junction contents. The root
    # itself must still be the ordinary directory created by this attempt.
    def retry_readonly(function, failed, _error):
        failed = Path(failed)
        info = failed.lstat()
        require(directory_identity(path) == identity and failed.is_relative_to(path) and
                stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'cleanup cannot retry an unowned/non-regular entry')
        os.chmod(failed, stat.S_IWRITE | stat.S_IREAD)
        function(failed)

    shutil.rmtree(path, onexc=retry_readonly)
    require(not Path(path).exists(), 'owned directory remains after cleanup')


def _write(path, value):
    raw = _canonical(value) + b'\n'
    require(len(raw) <= MAX_JSON, 'output receipt exceeds bound')
    with Path(path).open('xb') as stream:
        stream.write(raw)


def _read(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400 and
            0 < info.st_size <= MAX_JSON, 'receipt is not a bounded regular file')
    with path.open('rb') as stream:
        raw = stream.read(MAX_JSON + 1)
    require(_state(path.lstat()) == _state(info), 'receipt changed while reading')
    return read_evidence_bytes(raw)


def _sha(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400 and
            info.st_size <= MAX_TOOL_BYTES, 'image is not bounded/plain')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    require(_state(path.lstat()) == _state(info), 'image changed while hashing')
    return digest.hexdigest()


def _pinned_executable(path, expected_version):
    pin = _read(ROOT / 'tools' / 'bindiff_pin.json')
    require(isinstance(pin, dict) and pin.get('contract') == 'bindiff-pin/1' and
            isinstance(expected_version, str) and pin.get('version_text') == 'BinDiff ' + expected_version,
            'native version differs from existing repository pin')
    assets = pin.get('assets')
    require(isinstance(assets, dict) and isinstance(assets.get('windows'), dict), 'missing native pin')
    asset = assets['windows']
    require(_integer(asset.get('executable_size'), 1, MAX_TOOL_BYTES) and
            Path(path).stat().st_size == asset['executable_size'], 'native executable pin size differs')
    digest = _sha(path)
    require(asset.get('executable_sha256') == digest, 'native executable pin hash differs')
    return digest


def _source():
    # Held commits are valid acceptance inputs. Publication retains its separate
    # literal [no release] hold. This reuses the reviewed canonical-byte checker.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.dependency_security import checked_tree
    sha = subprocess.check_output(['git', '--no-replace-objects', 'rev-parse', '--verify', 'HEAD'],
                                  cwd=ROOT, timeout=15, text=True).strip()
    tree = checked_tree(ROOT, sha)
    # The full-tree checker verifies tracked bytes. Require this new tooling to
    # be part of that tree as well: an older clean commit plus untracked helper
    # files is not exact-source acceptance.
    paths = ['tools/windows_bindiff_network.py', 'tests/test_live_bindiff.py',
             *('tools/windows_network/' + name for name in NATIVE_SOURCES)]
    for path in paths:
        result = subprocess.run(['git', '--no-replace-objects', 'cat-file', '-e', sha + ':' + path],
                                cwd=ROOT, timeout=15, capture_output=True)
        require(result.returncode == 0, 'acceptance implementation is absent from canonical source: ' + path)
    return {'commit': sha, 'tree': tree}


def _environment(work):
    keys = {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'LOCALAPPDATA', 'APPDATA',
            'USERPROFILE', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMDATA'}
    env = {key: value for key, value in os.environ.items() if key.upper() in keys}
    env.update(TEMP=str(work), TMP=str(work), PYTHONPATH=str(ROOT / 'src'), PYTHONNOUSERSITE='1',
               PYTHONDONTWRITEBYTECODE='1')
    return env


def _run(argv, *, cwd, env=None, timeout=120, cancel=None, progress=None):
    if str(ROOT / 'src') not in sys.path:
        sys.path.insert(0, str(ROOT / 'src'))
    from patchtrace.jobs import run_process
    return run_process([str(a) for a in argv], cwd=Path(cwd), env=env or _environment(cwd),
                       cancel=cancel or threading.Event(), timeout_seconds=timeout,
                       separate_streams=True, log_limit=MAX_JSON, stderr_limit=MAX_JSON,
                       max_output_bytes=MAX_JSON, on_progress=progress)


def _completed(result, label):
    require(result.reason is None and result.returncode == 0,
            label + ': ' + (result.reason or str(result.returncode)) + ' ' + result.stderr_tail[:200])


def _raw_result(out, name, result):
    for suffix, raw, fallback in (('stdout', result.log_bytes, result.log_tail),
                                  ('stderr', result.stderr_bytes, result.stderr_tail)):
        with (out / (name + '.' + suffix)).open('xb') as stream:
            stream.write(raw if raw is not None else fallback.encode('utf-8'))
    _write(out / (name + '.process.json'), {'returncode': result.returncode, 'reason': result.reason,
                                           'elapsed_s': result.elapsed_seconds})


def build_helper(destination):
    destination = Path(destination).absolute()
    destination.mkdir(parents=True, exist_ok=False)
    record = {'engine': 'bindiff', 'status': 'blocked', 'reason': 'Windows build capability unavailable'}
    try:
        if os.name != 'nt':
            raise NetworkUnavailable('Windows SDK helper requires native Windows')
        record['source'] = _source()
        sources = {name: _sha(ROOT / 'tools' / 'windows_network' / name) for name in NATIVE_SOURCES}
        vswhere = Path(os.environ.get('ProgramFiles(x86)', '')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        if not vswhere.is_file():
            raise NetworkUnavailable('existing Visual Studio discovery tool unavailable')
        found = _run([vswhere, '-latest', '-products', '*', '-requires',
                      'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'],
                     cwd=destination, timeout=30)
        _raw_result(destination, 'compiler-discovery', found)
        _completed(found, 'compiler discovery')
        installation = Path(found.log_tail.strip())
        vcvars = installation / 'VC/Auxiliary/Build/vcvars64.bat'
        if not vcvars.is_file():
            raise NetworkUnavailable('existing x64 Visual C++ compiler/SDK unavailable')
        # This generated cmd file contains only checked local paths, never a
        # workflow input or shell text supplied by the caller.
        for path in (vcvars, ROOT, destination):
            require(not any(ch in str(path) for ch in '\r\n"%&|<>^!'), 'unsupported build path characters')
        commands = ['@echo off', 'call "' + str(vcvars) + '"', 'if errorlevel 1 exit /b 1',
                    'set VCToolsVersion', 'set WindowsSDKVersion']
        for name in ('launcher', 'probe'):
            source = ROOT / 'tools' / 'windows_network' / (name + '.c')
            commands.extend(['cl.exe /nologo /W4 /WX /std:c17 /utf-8 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0602 '
                             '/Fe"' + str(destination / (name + '.exe')) + '" "' + str(source) +
                             '" /link userenv.lib advapi32.lib ws2_32.lib ole32.lib',
                             'if errorlevel 1 exit /b 1'])
        script = destination / 'compile.cmd'
        script.write_bytes(('\r\n'.join(commands) + '\r\n').encode('utf-8'))
        command = Path(os.environ['SystemRoot']) / 'System32/cmd.exe'
        built = _run([command, '/d', '/c', script], cwd=destination, timeout=120)
        _raw_result(destination, 'compiler', built)
        _completed(built, 'native helper build')
        images = {name: _sha(destination / (name + '.exe')) for name in ('launcher', 'probe')}
        require(_source() == record['source'], 'source changed during helper build')
        record.update(status='passed', reason='built from exact source; runtime acceptance still pending',
                      sources=sources, images=images, compiler_output_sha256=_sha(destination / 'compiler.stdout'))
    except (NetworkEvidenceError, OSError, subprocess.SubprocessError) as exc:
        record.update(status='blocked' if isinstance(exc, NetworkUnavailable) else 'failed', reason=str(exc)[:600])
    _write(destination / 'build.json', record)
    return record


def _build(destination, source):
    destination = Path(destination)
    record = _read(destination / 'build.json')
    if record.get('status') == 'blocked':
        raise NetworkUnavailable('native helper build blocked: ' + str(record.get('reason', ''))[:400])
    require(record.get('status') == 'passed' and record.get('source') == source, 'helper build/source mismatch')
    require(record.get('sources') == {name: _sha(ROOT / 'tools' / 'windows_network' / name)
                                     for name in NATIVE_SOURCES}, 'native helper source bytes differ')
    require(record.get('images') == {name: _sha(destination / (name + '.exe'))
                                    for name in ('launcher', 'probe')}, 'native helper image bytes differ')
    return record


def _lines(path):
    raw = Path(path).read_bytes()
    require(0 < len(raw) <= MAX_JSON, 'native receipt byte bound')
    rows = [read_evidence_bytes(line) for line in raw.splitlines() if line]
    require(len(rows) <= 8 and all(isinstance(row, dict) for row in rows), 'native receipt row bound')
    return rows


def _probe_rows(result):
    raw = result.log_bytes
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON and
            type(result.stdout_total) is int and result.stdout_total == len(raw),
            'native probe byte capture is missing or truncated')
    return [read_evidence_bytes(line) for line in raw.splitlines() if line]


def _copy_tree(source, target):
    source, target = Path(source), Path(target)
    directory_identity(source)
    target.mkdir()
    pending, inventory, total = [(source, target)], {}, 0
    while pending:
        old, new = pending.pop()
        for entry in sorted(old.iterdir()):
            info = entry.lstat()
            require(not getattr(info, 'st_file_attributes', 0) & 0x400 and not stat.S_ISLNK(info.st_mode),
                    'tool copy contains a link/reparse entry')
            relative = entry.relative_to(source).as_posix()
            require(len(inventory) < MAX_FILES, 'tool copy file-count bound')
            if stat.S_ISDIR(info.st_mode):
                (new / entry.name).mkdir()
                inventory[relative] = {'directory': True}
                pending.append((entry, new / entry.name))
            else:
                require(stat.S_ISREG(info.st_mode), 'tool copy contains a special file')
                total += info.st_size
                require(total <= MAX_TOOL_BYTES, 'tool copy byte bound')
                digest = _sha(entry)
                shutil.copyfile(entry, new / entry.name)
                require(_sha(new / entry.name) == digest and _state(entry.lstat()) == _state(info),
                        'tool changed during copy')
                inventory[relative] = {'bytes': info.st_size, 'sha256': digest}
    return inventory


@contextmanager
def echo_listeners(nonce):
    sockets, threads, stop = [], [], threading.Event()
    expected = nonce.encode('ascii')

    def serve(listener, udp):
        while not stop.is_set():
            try:
                if udp:
                    data, peer = listener.recvfrom(64)
                    if data == expected:
                        listener.sendto(data, peer)
                else:
                    connection, _peer = listener.accept()
                    with connection:
                        connection.settimeout(1)
                        data = b''
                        while len(data) < len(expected):
                            chunk = connection.recv(len(expected) - len(data))
                            if not chunk:
                                break
                            data += chunk
                        if data == expected:
                            connection.sendall(data)
            except (OSError, TimeoutError):
                if stop.is_set():
                    return

    try:
        for family, udp in ((socket.AF_INET, False), (socket.AF_INET6, False),
                            (socket.AF_INET, True), (socket.AF_INET6, True)):
            listener = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            sockets.append(listener)
            listener.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
            listener.settimeout(0.2)
            if not udp:
                listener.listen(8)
            thread = threading.Thread(target=serve, args=(listener, udp), daemon=True)
            threads.append(thread)
            thread.start()
        yield [item.getsockname()[1] for item in sockets]
    except OSError as exc:
        raise NetworkUnavailable('IPv4/IPv6 echo-listener capability unavailable: ' + str(exc)[:160]) from exc
    finally:
        stop.set()
        for listener in sockets:
            listener.close()
        for thread in threads:
            thread.join(2)
        require(not any(thread.is_alive() for thread in threads), 'echo-listener cleanup failed')


class NativeContext:
    def __init__(self, build, stage, output, nonce, executable):
        self.launcher = Path(build) / 'launcher.exe'
        self.stage, self.output, self.nonce = Path(stage), Path(output), nonce
        self.executable = Path(executable)
        self.name = PROFILE_PREFIX + nonce
        self.profile = None
        self.launches = []
        self.serial = 0
        self.close_attempts = 0
        self.tree_empty = True

    def _command(self, args, name):
        result = _run([self.launcher, *args], cwd=self.stage, timeout=30)
        _raw_result(self.output, name, result)
        return result

    def create(self):
        result = self._command(['profile-create', self.name], 'profile-create')
        try:
            record = read_evidence_bytes(result.log_tail.encode('utf-8'))
        except NetworkEvidenceError:
            _completed(result, 'profile creation')
            raise
        if record.get('created') is True and record.get('name') == self.name and \
                isinstance(record.get('sid'), str) and APP_SID.fullmatch(record['sid']):
            # Only the exact newly created profile can become a cleanup target.
            # Later capability/storage/ACL failures still clean this owned object.
            self.profile = record
        if result.returncode or result.reason:
            # A collision is never adopted or deleted by this attempt.
            if record.get('error') in {0x80070005, 0x80004001, 0x80070032}:
                raise NetworkUnavailable('AppContainer profile API/access unavailable')
            raise NetworkEvidenceError('AppContainer profile creation refused: ' + str(record)[:200])
        require(self.profile is not None and record.get('name') == self.name and
                isinstance(record.get('sid'), str) and APP_SID.fullmatch(record['sid']) and
                type(record.get('capability_count')) is int and record['capability_count'] == 0 and
                isinstance(record.get('folder'), str) and record['folder'], 'profile identity is incomplete')
        icacls = Path(os.environ['SystemRoot']) / 'System32/icacls.exe'
        access = _run([icacls, self.stage, '/grant', '*' + record['sid'] + ':(RX)'],
                      cwd=self.stage, timeout=60)
        _raw_result(self.output, 'acl-stage-root', access)
        _completed(access, 'owned staging root traversal ACL')
        for name, write in (('bin', False), ('probes', False), ('work', True)):
            folder = self.stage / name
            directory_identity(folder)
            access = _run([icacls, folder, '/grant', '*' + record['sid'] +
                           (':(OI)(CI)(M)' if write else ':(OI)(CI)(RX)'), '/T'],
                          cwd=self.stage, timeout=60)
            _raw_result(self.output, 'acl-' + name, access)
            _completed(access, 'owned staging ACL')
            if write:
                label = _run([icacls, folder, '/setintegritylevel', '(OI)(CI)L', '/T'],
                             cwd=self.stage, timeout=60)
                _raw_result(self.output, 'label-' + name, label)
                _completed(label, 'owned write-tree integrity label')

    def close(self):
        if self.profile is None:
            return True
        self.close_attempts += 1
        result = self._command(['profile-delete', self.name], f'profile-delete-{self.close_attempts}')
        _completed(result, 'owned profile deletion')
        deleted = read_evidence_bytes(result.log_tail.encode('utf-8'))
        require(deleted.get('deleted') is True and deleted.get('error') == 0,
                'owned profile deletion unverified')
        folder = self.profile.get('folder')
        require(isinstance(folder, str) and not Path(folder).exists(), 'owned profile storage remains')
        return True

    def launch_args(self, argv, label, timeout):
        require(self.profile is not None and 0 < timeout <= 120, 'invalid owned native launch')
        self.serial += 1
        receipt = self.output / f'{self.serial:02d}-{label}.ndjson'
        return ([self.launcher, 'launch', self.profile['sid'], receipt, str(max(1, int(timeout * 1000))),
                 '--', *argv], receipt)

    def started(self, receipt):
        rows = _lines(receipt)
        require(rows and rows[0].get('phase') == 'started', 'native child did not start under verified token')
        start = rows[0]
        require(_creation_time(start.get('created')), 'missing or noncanonical native launch creation identity')
        require(start.get('appcontainer') is True and start.get('sid') == self.profile['sid'] and
                type(start.get('capability_count')) is int and start['capability_count'] == 0 and
                all(start.get(key) is True for key in ('suspended', 'job_before_resume', 'token_before_resume',
                                                      'image_locked')) and
                start.get('handles') == ['nul', 'pipe', 'pipe'], 'native launch boundary incomplete')
        return start, rows

    def wrapped(self, argv, label, *, cwd, env=None, timeout=120, cancel=None, progress=None, **kwargs):
        image_before = _sha(argv[0])
        # The outer supervisor must apply its cancellation/timeout first. An
        # equal native timer races that observation and can turn a timeout into
        # a normal exit. The helper retains an independent bounded failsafe.
        args, receipt = self.launch_args(argv, label, min(timeout + 10, 120))
        if str(ROOT / 'src') not in sys.path:
            sys.path.insert(0, str(ROOT / 'src'))
        from patchtrace.jobs import run_process
        result = run_process([str(a) for a in args], cwd=Path(cwd), env=env or _environment(cwd),
                             cancel=cancel or threading.Event(), timeout_seconds=min(timeout, 120),
                             on_progress=progress, **kwargs)
        _raw_result(self.output, f'{self.serial:02d}-{label}', result)
        start, rows = self.started(receipt)
        require(_sha(argv[0]) == image_before, 'native executable changed during launch')
        if result.reason is None:
            require(len(rows) == 2 and rows[1].get('phase') == 'finished' and
                    rows[1].get('tree_empty') is True and rows[1].get('timed_out') is False and
                    rows[1].get('returncode') == result.returncode, 'native cleanup/result receipt incomplete')
            start = {**start, 'tree_empty': True}
        if label in {'probe-version', 'probe-help', 'diff'}:
            require(result.reason is None, 'native adapter launch was interrupted')
            self.launches.append({**start, 'purpose': label, 'executable_sha256': image_before})
        return result, receipt

    def runner(self, argv, **kwargs):
        require(Path(argv[0]) == self.executable, 'adapter tried an unowned executable')
        cwd = Path(kwargs['cwd']).resolve(strict=True)
        require(cwd.is_relative_to((self.stage / 'work').resolve(strict=True)), 'adapter workdir is not owned')
        label = ('probe-version' if list(argv[1:]) == ['--version'] else
                 'probe-help' if list(argv[1:]) == ['--nologo', '--help'] else 'diff')
        if label == 'diff':
            from patchtrace.secondary.bindiff_run import check_argv
            check_argv(argv)
        timeout = kwargs.pop('timeout_seconds')
        return self.wrapped(argv, label, timeout=min(timeout, 120), **kwargs)[0]

    def gone(self, rows, label):
        identities = []
        for row in rows:
            created = row.get('created')
            require(_integer(row.get('pid'), 1, (1 << 32) - 1) and _creation_time(created),
                    'missing or noncanonical native process creation identity')
            identities.append(str(row['pid']) + ':' + created)
        result = self._command(['alive', *identities], label + '-alive')
        _completed(result, 'native descendant liveness query')
        observed = read_evidence_bytes(result.log_tail.encode('utf-8'))
        require(observed == {'alive': [], 'uncertain': False}, 'native descendants remain or cannot be verified')
        return observed


def _lifetime_tokens(rows, profile, nonce):
    _chain_identity(rows, sid=profile['sid'], nonce=nonce, blocked=True)
    for row in rows:
        require(isinstance(row, dict) and row.get('cases') == [], 'invalid lifecycle probe')


def _owner_exit(context, argv, environment):
    args, receipt = context.launch_args(argv, 'owner-exit', 120)
    output, errors = bytearray(), bytearray()
    lock = threading.Lock()

    def drain(stream, target):
        with stream:
            while chunk := os.read(stream.fileno(), 4096):
                with lock:
                    target.extend(chunk[:max(0, MAX_JSON - len(target))])

    process = subprocess.Popen([str(a) for a in args], cwd=context.stage / 'work', env=environment,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True)
    readers = [threading.Thread(target=drain, args=(process.stdout, output), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, errors), daemon=True)]
    for reader in readers:
        reader.start()
    rows = []
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and process.poll() is None:
            with lock:
                raw = bytes(output)
            if raw.count(b'\n') >= 3:
                rows = [read_evidence_bytes(line) for line in raw.splitlines() if line]
                break
            time.sleep(0.05)
        _lifetime_tokens(rows, context.profile, context.nonce)
        start, _records = context.started(receipt)
        require(start.get('owner_pid') == process.pid and start.get('pid') == rows[0]['pid'],
                'owner-exit launch identity differs')
        # No outer run_process Job Object owns this launcher. Terminating this
        # process tests the launcher's own non-inherited kill-on-close job handle.
        process.terminate()
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for reader in readers:
            reader.join(5)
        (context.output / 'owner-exit.stdout').write_bytes(output)
        (context.output / 'owner-exit.stderr').write_bytes(errors)
    require(not any(reader.is_alive() for reader in readers), 'owner-exit output reader remains')
    require(process.returncode != 0, 'owner-exit control did not interrupt the owner')
    observed = context.gone(rows, 'owner-exit')
    record = {'reason': 'owner-exit', 'launch': {**start, 'executable_sha256': _sha(argv[0])},
              'owner_exit_code': process.returncode,
              'processes': rows, 'observed': observed}
    _write(context.output / 'owner-exit-control.json', record)
    return record


def _lifecycle(context, argv, environment):
    results = {}
    for label in ('cancel', 'timeout'):
        cancel = threading.Event()

        def progress(snapshot, label=label, cancel=cancel):
            if label == 'cancel' and snapshot.log_tail.count('\n') >= 3:
                cancel.set()

        result, receipt = context.wrapped(argv, 'lifecycle-' + label, cwd=context.stage / 'work',
                                          env=environment, timeout=8, cancel=cancel, progress=progress,
                                          separate_streams=True, log_limit=MAX_JSON, stderr_limit=MAX_JSON)
        require(result.reason == ('cancelled' if label == 'cancel' else 'timeout'),
                'lifecycle interruption was not applied')
        rows = _probe_rows(result)
        _lifetime_tokens(rows, context.profile, context.nonce)
        start, _records = context.started(receipt)
        require(start.get('pid') == rows[0]['pid'], 'lifecycle launch identity differs')
        observed = context.gone(rows, label)
        record = {'reason': result.reason, 'launch': {**start, 'executable_sha256': _sha(argv[0])},
                  'owner_exit_code': result.returncode,
                  'processes': rows, 'observed': observed}
        _write(context.output / (label + '-control.json'), record)
        results[label] = record
    results['owner_exit'] = _owner_exit(context, argv, environment)
    return results


def _adapter(request, context, output):
    sys.path.insert(0, str(ROOT / 'tests'))
    sys.path.insert(0, str(ROOT / 'src'))
    from test_live_bindiff import Inputs, _accept_both, _end_to_end

    from patchtrace.secondary.cli_bindiff import c3_acceptor
    work = context.stage / 'work'
    pair = work / 'pair'
    pair.mkdir()
    copies = {}
    for role in ('older', 'newer'):
        for kind in ('binexport', 'artifact'):
            item = request['inputs'][role][kind]
            source = Path(item['path'])
            require(_sha(source) == item['sha256'], 'acceptance input bytes changed')
            target = pair / (role + ('.BinExport' if kind == 'binexport' else '.artifact'))
            shutil.copyfile(source, target)
            require(_sha(target) == item['sha256'], 'acceptance input copy mismatch')
            copies[role, kind] = target
    older_sha, newer_sha = (request['inputs'][role]['artifact']['sha256'] for role in ('older', 'newer'))
    acceptor = c3_acceptor(work / 'accepted')
    require(acceptor is not None, 'C3 input acceptance unavailable')
    older, newer = _accept_both(acceptor, copies['older', 'binexport'], copies['newer', 'binexport'],
                                older_sha, newer_sha)
    inputs = Inputs(older, newer, older_sha, newer_sha, copies['older', 'artifact'], copies['newer', 'artifact'],
                    'authored synthetic network acceptance', 'C3 accept_binexport', True,
                    (copies['older', 'binexport'], copies['newer', 'binexport']), acceptor)
    result = _end_to_end(str(context.executable), inputs, work / 'adapter', request['expected_version'],
                         runner=context.runner, evidence_dir=output / 'adapter')
    return {**result, 'acceptance': 'C3 accept_binexport'}


def worker(request_file):
    request_file = Path(request_file).absolute()
    request, started = _read(request_file), time.monotonic()
    output = request_file.parent
    result = {'engine': 'bindiff', 'status': 'failed', 'reason': 'incomplete native acceptance',
              'contract': 'bindiff-network/1', 'native': os.name == 'nt', 'nonce': request['nonce'],
              'source': request['source'], 'helper_sha256': request['helper_sha256'],
              'probe_sha256': request['probe_sha256'],
              'executable_sha256': request['executable_sha256']}
    stage, identity, context = None, None, None
    cleanup = {'profile_deleted': False, 'tree_removed': False, 'process_tree_empty': False}
    try:
        require(os.name == 'nt', 'worker requires Windows')
        require(_digest(request['nonce'], NONCE) and _source() == request['source'], 'worker source/nonce differs')
        build = ROOT / 'build' / 'windows-network-helper'
        built = _build(build, request['source'])
        require(built['images']['launcher'] == request['helper_sha256'] and
                built['images']['probe'] == request['probe_sha256'], 'worker helper differs')
        require(_pinned_executable(request['executable'], request['expected_version']) ==
                request['executable_sha256'], 'worker native tool differs from repository pin')
        stage = Path(tempfile.mkdtemp(prefix='patchtrace-native-network-'))
        identity = directory_identity(stage)
        (stage / 'work').mkdir()
        (stage / 'probes').mkdir()
        inventory = _copy_tree(Path(request['executable']).parent, stage / 'bin')
        _write(output / 'tool-copy.json', inventory)
        executable = stage / 'bin' / Path(request['executable']).name
        require(_sha(executable) == request['executable_sha256'], 'staged native executable differs')
        probes = []
        for name in ('probe-parent.exe', 'probe-child.exe', 'probe-grandchild.exe'):
            path = stage / 'probes' / name
            shutil.copyfile(build / 'probe.exe', path)
            require(_sha(path) == built['images']['probe'], 'authored probe copy differs')
            probes.append(path)
        # This private harness process alone selects its default tempfile root.
        # The production scheduler/probe/C3 code remains unchanged.
        tempfile.tempdir = str(stage / 'work')
        os.environ.update(TEMP=str(stage / 'work'), TMP=str(stage / 'work'))
        environment = _environment(stage / 'work')
        context = NativeContext(build, stage, output, request['nonce'], executable)
        observations = {}
        with echo_listeners(request['nonce']) as ports:
            probe = [probes[0], 'chain', request['nonce'], '0', *map(str, ports), probes[1], probes[2]]
            before = _run(probe, cwd=stage / 'work', env=environment, timeout=120)
            _raw_result(output, 'probe-before', before)
            _completed(before, 'positive control process chain')
            observations['before'] = _probe_rows(before)
            try:
                _probe_chain(observations['before'], sid='', nonce=request['nonce'], blocked=False)
            except NetworkEvidenceError as exc:
                raise NetworkUnavailable('positive network control unavailable: ' + str(exc)) from exc
            context.create()
            result['profile'] = {key: context.profile[key] for key in ('name', 'sid', 'capability_count')}
            denied, _receipt = context.wrapped(probe, 'probe-denied', cwd=stage / 'work', env=environment,
                                               timeout=120, separate_streams=True, log_limit=MAX_JSON,
                                               stderr_limit=MAX_JSON)
            _completed(denied, 'restricted control process chain')
            observations['denied'] = _probe_rows(denied)
            _probe_chain(observations['denied'], sid=context.profile['sid'], nonce=request['nonce'], blocked=True)
            probe_start, _records = context.started(_receipt)
            result['probe_launch'] = {**probe_start, 'tree_empty': True,
                                       'executable_sha256': built['images']['probe']}
            lifetime = [*probe]
            lifetime[1] = 'lifetime'
            result['lifecycle'] = _lifecycle(context, lifetime, environment)
            result['adapter'] = _adapter(request, context, output)
            result['launches'] = context.launches
            require(result['adapter']['status'] == 'passed', 'restricted native adapter run failed')
            cleanup['process_tree_empty'] = True
            cleanup['profile_deleted'] = context.close()
            context = None
            after = _run(probe, cwd=stage / 'work', env=environment, timeout=120)
            _raw_result(output, 'probe-after', after)
            _completed(after, 'post-cleanup control process chain')
            observations['after'] = _probe_rows(after)
            _probe_chain(observations['after'], sid='', nonce=request['nonce'], blocked=False)
        result['probes'] = observations
        result.update(status='passed', reason='native AppContainer denial and adapter semantics observed')
    except (NetworkEvidenceError, OSError, ValueError, subprocess.SubprocessError) as exc:
        result.update(status='blocked' if isinstance(exc, NetworkUnavailable) else 'failed', reason=str(exc)[:600])
    finally:
        if context is not None:
            try:
                cleanup['profile_deleted'] = context.close()
            except (OSError, NetworkEvidenceError) as exc:
                result.update(status='failed', reason='owned profile cleanup failed: ' + str(exc)[:400])
        if stage is not None and identity is not None:
            try:
                remove_owned_tree(stage, identity)
                cleanup['tree_removed'] = True
            except (OSError, NetworkEvidenceError) as exc:
                result.update(status='failed', reason='owned staging cleanup failed: ' + str(exc)[:400])
        result['cleanup'], result['elapsed_s'] = cleanup, time.monotonic() - started
        if result['status'] == 'passed':
            try:
                validate_evidence(result, source_sha=request['source']['commit'], source_tree=request['source']['tree'],
                                  helper_sha=request['helper_sha256'], probe_sha=request['probe_sha256'],
                                  executable_sha=request['executable_sha256'],
                                  nonce=request['nonce'], baseline_count=request['baseline_count'],
                                  baseline_semantic=request['baseline_semantic'])
            except NetworkEvidenceError as exc:
                result.update(status='failed', reason='final receipt refused: ' + str(exc)[:400])
        _write(output / 'receipt.json', result)
    return 0 if result['status'] in {'passed', 'blocked'} else 1


def windows_no_network(executable, inputs, baseline_count, baseline_semantic, expected_version, evidence_dir):
    output = Path(evidence_dir)
    output.mkdir(parents=True, exist_ok=False)
    try:
        if os.name != 'nt':
            raise NetworkUnavailable('native Windows acceptance is unavailable on this host')
        require(inputs.synthetic, 'network acceptance currently requires the authored synthetic pair')
        source = _source()
        try:
            built = _build(ROOT / 'build' / 'windows-network-helper', source)
        except FileNotFoundError as exc:
            raise NetworkUnavailable('native Windows helper has not been built for this exact source') from exc
        files = {}
        for role in ('older', 'newer'):
            binary = Path(getattr(inputs, role + '_artifact'))
            export = Path(getattr(inputs, role).snapshot_path)
            files[role] = {'artifact': {'path': str(binary), 'sha256': _sha(binary)},
                           'binexport': {'path': str(export), 'sha256': _sha(export)}}
        request = {'source': source, 'helper_sha256': built['images']['launcher'],
                   'probe_sha256': built['images']['probe'], 'nonce': uuid.uuid4().hex,
                   'executable': str(Path(executable).absolute()),
                   'executable_sha256': _pinned_executable(executable, expected_version),
                   'inputs': files, 'baseline_count': baseline_count, 'baseline_semantic': baseline_semantic,
                   'expected_version': expected_version}
        _write(output / 'request.json', request)
        result = _run([sys.executable, '-P', ROOT / 'tools' / 'windows_bindiff_network.py', 'worker',
                       output / 'request.json'], cwd=ROOT, env=_environment(output), timeout=600)
        _raw_result(output, 'worker', result)
        require(result.reason is None, 'native acceptance worker did not complete: ' + str(result.reason))
        receipt = _read(output / 'receipt.json')
        if receipt.get('status') == 'blocked':
            raise NetworkUnavailable(str(receipt.get('reason'))[:600])
        require(result.returncode == 0 and receipt.get('status') == 'passed',
                'native acceptance failed: ' + str(receipt.get('reason'))[:600])
        require(_source() == source, 'source changed during native acceptance')
        validate_evidence(receipt, source_sha=source['commit'], source_tree=source['tree'],
                          helper_sha=request['helper_sha256'], probe_sha=request['probe_sha256'],
                          executable_sha=request['executable_sha256'],
                          nonce=request['nonce'], baseline_count=baseline_count, baseline_semantic=baseline_semantic)
        return {'status': 'passed', 'reason': 'native BinDiff tree denied network with complete semantic parity',
                'matches': baseline_count, 'semantic_sha256': baseline_semantic,
                'receipt': 'network/receipt.json', 'receipt_sha256': _sha(output / 'receipt.json')}
    except (NetworkEvidenceError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return {'status': 'blocked' if isinstance(exc, NetworkUnavailable) else 'failed', 'reason': str(exc)[:600]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--output', type=Path, default=ROOT / 'build' / 'windows-network-helper')
    run = commands.add_parser('worker')
    run.add_argument('request', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'build':
        record = build_helper(args.output)
        print(json.dumps(record, sort_keys=True))
        return 1 if record['status'] == 'failed' else 0
    return worker(args.request)


if __name__ == '__main__':
    sys.exit(main())
