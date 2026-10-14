"""Zero-download backend bundle acceptance harness (BUNDLE plan sections 6, 10.2; slice B5a).

usage: bundle_acceptance.py BUNDLE_ROOT --older P --newer P --expect-function NAME
           [--launcher PATH] [--control HOST:PORT] [--evidence FILE] [--run-uid N --run-gid N] [--dry-run]

BUNDLE_ROOT is the extracted release artifact (the folder holding the launcher and `backend/`). Steps, in order:
  1 scrub     minimal environment, no java/python on PATH, no JAVA_HOME/GHIDRA_INSTALL_DIR/PYTHON*
  2 digest    SHA-256 tree digest of `backend/` (before)
  3 readonly  `backend/` made read-only (chmod a-w; icacls deny on Windows)
  4 control   socket probe with the bundle's own python MUST succeed before the block (positive control)
  5 block     Linux: `unshare --net` (+ setpriv, env -i); Windows: outbound firewall rules per program
  6 control   the same probe MUST now fail, otherwise the denial is not proven and the run fails
  7 run       `backend verify --full`, `backend selftest` (CLI contract of slice B7), and a real Ghidriff
              comparison of the pair through the bundle's python, all under the block, sampling connections
  8 digest    tree digest again; it must equal the first one

The pure helpers carry the unit tests (tests/test_bundle_acceptance_unit.py). The OS-level steps run for real
only in CI (`backend-bundle.yml`, B5b) on a release artifact; locally the `--dry-run` mode and the unit tests use
a fake bundle and a loopback listener as the control target, which proves the harness logic and the Linux
namespace denial but nothing about the real Ghidra/JDK payload. Nothing here executes the target binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = 'patchtrace-bundle-acceptance/1'
FORBIDDEN_ENV = frozenset({'JAVA_HOME', 'JDK_HOME', 'JRE_HOME', 'GHIDRA_INSTALL_DIR', 'PYTHONHOME', 'PYTHONPATH',
                           'CLASSPATH', '_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'VIRTUAL_ENV', 'CONDA_PREFIX',
                           'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'})
FORBIDDEN_PREFIXES = ('PYTHON', 'JAVA', 'GHIDRA', 'PIP_')
FORBIDDEN_TOOLS = ('java', 'javaw', 'python', 'python3', 'pythonw')
PROBE_TIMEOUT = 5.0
SAMPLE_INTERVAL = 0.5
UNICODE_DIRNAME = 'Patch Trace \u00e9\u4e2d'


def _upper(name: str, os_name: str) -> str:
    return name.upper() if os_name == 'windows' else name


# ---------------------------------------------------------------- environment scrub

def scrub_env(os_name: str, home: str, temp: str, path: str) -> dict[str, str]:
    """The only environment the program under test receives. No inherited variable survives."""
    env = {'PATH': path, 'TEMP': temp, 'TMP': temp, 'TMPDIR': temp}
    if os_name == 'windows':
        root = os.environ.get('SystemRoot', r'C:\Windows')
        env.update({'USERPROFILE': home, 'SystemRoot': root, 'LOCALAPPDATA': str(Path(home) / 'AppData' / 'Local')})
    else:
        env.update({'HOME': home, 'LANG': 'C.UTF-8', 'XDG_CONFIG_HOME': str(Path(home) / '.config'),
                    'XDG_CACHE_HOME': str(Path(home) / '.cache')})
    return env


def env_violations(env: dict[str, str], os_name: str = 'linux') -> list[str]:
    bad = []
    for key in env:
        up = _upper(key, os_name)
        if up in FORBIDDEN_ENV or up.startswith(FORBIDDEN_PREFIXES):
            bad.append(key)
    return sorted(bad)


def path_dirs(path: str, os_name: str) -> list[str]:
    return [p for p in path.split(';' if os_name == 'windows' else ':') if p]


def path_tool_hits(path: str, os_name: str, exists: Callable[[Path], bool] = Path.is_file,
                   tools: Sequence[str] = FORBIDDEN_TOOLS) -> list[str]:
    """Every java/python executable reachable through PATH (the `where java` / `which java` must-fail check)."""
    suffixes = ('', '.exe', '.bat', '.cmd') if os_name == 'windows' else ('',)
    hits = []
    for directory in path_dirs(path, os_name):
        for tool in tools:
            for suffix in suffixes:
                candidate = Path(directory) / (tool + suffix)
                if exists(candidate):
                    hits.append(str(candidate))
    return hits


def path_is_hostile(text: str) -> bool:
    return ' ' in text and any(ord(c) > 127 for c in text)


def minimal_path(os_name: str) -> str:
    if os_name == 'windows':
        root = os.environ.get('SystemRoot', r'C:\Windows')
        return rf'{root}\System32;{root}'
    return '/nonexistent'


def run_path(os_name: str, jdk_bin: str | None, base: str) -> str:
    """PATH for the Ghidriff step: the bundle's JDK first, then the java-free base."""
    return os.pathsep.join([jdk_bin, base]) if jdk_bin else base


# ---------------------------------------------------------------- tree digest and read-only

def tree_digest(root: Path) -> str:
    """Order-independent digest of relative path, kind, size and content hash for every entry under root."""
    outer = hashlib.sha256()
    entries: list[tuple[str, str]] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        base = Path(current)
        for name in sorted(dirs):
            full = base / name
            rel = full.relative_to(root).as_posix()
            entries.append((rel, 'L:' + os.readlink(full) if full.is_symlink() else 'D'))
        for name in sorted(files):
            full = base / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                entries.append((rel, 'L:' + os.readlink(full)))
                continue
            inner = hashlib.sha256()
            with full.open('rb') as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b''):
                    inner.update(chunk)
            entries.append((rel, f'F:{full.stat().st_size}:{inner.hexdigest()}'))
    for rel, kind in sorted(entries):
        outer.update(f'{rel}\0{kind}\n'.encode())
    return outer.hexdigest()


def set_tree_readonly(root: Path, readonly: bool) -> int:
    """chmod a-w (or restore u+w) on every entry; symlinks are skipped. Returns the number of entries changed."""
    changed = 0
    paths = [root]
    for current, dirs, files in os.walk(root, followlinks=False):
        paths += [Path(current) / n for n in dirs + files]
    for path in reversed(paths) if not readonly else paths:
        if path.is_symlink():
            continue
        mode = path.stat().st_mode
        new = mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) if readonly else mode | stat.S_IWUSR
        if new != mode:
            path.chmod(new)
            changed += 1
    return changed


def writable_probe(root: Path) -> bool:
    """True when this process can create a file in root (the tree is NOT effectively read-only for it)."""
    probe = root / '.pt-write-probe'
    try:
        probe.write_bytes(b'x')
    except OSError:
        return False
    probe.unlink(missing_ok=True)
    return True


def windows_readonly_command(root: str, account: str, deny: bool = True) -> list[str]:
    if deny:
        return ['icacls', root, '/deny', f'{account}:(OI)(CI)(W,D,DC)']
    return ['icacls', root, '/remove:d', account, '/T']


# ---------------------------------------------------------------- network probe and denial

def probe_code(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> str:
    """Source for `python -I -c`: exit 0 and print CONNECTED when a TCP connect succeeds, exit 7 otherwise."""
    return ('import socket,sys\n'
            f'try:\n s=socket.create_connection(({host!r},{int(port)}),{float(timeout)!r});s.close();print("CONNECTED")\n'
            'except OSError as e:\n print("BLOCKED",type(e).__name__);sys.exit(7)\n')


def parse_target(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(':')
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f'control target must be HOST:PORT, got {text!r}')
    return host, int(port)


def control_verdict(before_connected: bool, after_connected: bool) -> str:
    """'proven' only when the probe worked before the block and failed after it."""
    if not before_connected:
        return 'invalid-no-baseline'
    if after_connected:
        return 'denial-ineffective'
    return 'proven'


def _which(name: str) -> str:
    """Absolute path of a host tool: the scrubbed PATH of the program under test cannot find it."""
    return shutil.which(name) or name


def linux_denial_argv(argv: Sequence[str], env: dict[str, str], uid: int, gid: int, sudo: bool = False,
                      resolve: Callable[[str], str] = _which) -> list[str]:
    """Run argv in a fresh network namespace (loopback up), as uid:gid, with exactly `env`."""
    inner = [resolve('setpriv'), '--reuid', str(uid), '--regid', str(gid), '--clear-groups',
             resolve('env'), '-i', *[f'{k}={v}' for k, v in sorted(env.items())], *argv]
    script = f'{resolve("ip")} link set lo up >/dev/null 2>&1 || true; exec "$@"'
    wrapper = [resolve('unshare'), '--net', '--', resolve('sh'), '-c', script, 'sh', *inner]
    return ([resolve('sudo'), '-n'] if sudo else []) + wrapper


def ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def firewall_rule_name(prefix: str, program: str) -> str:
    return f'{prefix}-{hashlib.sha256(program.encode()).hexdigest()[:10]}'


def windows_firewall_commands(programs: Iterable[str], prefix: str = 'PatchTraceAccept') -> tuple[list[list[str]], list[list[str]]]:
    """(add, remove) PowerShell argv lists: one outbound block rule per absolute program path."""
    add, remove = [], []
    for program in programs:
        name = firewall_rule_name(prefix, program)
        add.append(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                    f'New-NetFirewallRule -DisplayName {ps_quote(name)} -Direction Outbound -Action Block '
                    f'-Program {ps_quote(program)} | Out-Null'])
        remove.append(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                       f'Remove-NetFirewallRule -DisplayName {ps_quote(name)} -ErrorAction SilentlyContinue'])
    return add, remove


def windows_programs(root: Path) -> list[str]:
    """Programs that must be blocked; only those that exist are listed (absolute paths)."""
    candidates = [*sorted(root.glob('PatchTrace*.exe')),
                  root / 'backend' / 'payload' / 'python' / 'python.exe',
                  root / 'backend' / 'payload' / 'jdk' / 'bin' / 'java.exe',
                  root / 'backend' / 'payload' / 'jdk' / 'bin' / 'javaw.exe',
                  *sorted((root / 'backend' / 'payload' / 'ghidra').glob('Ghidra/Features/Decompiler/os/*/decompile.exe'))]
    return [str(p.resolve()) for p in candidates if p.is_file()]


_TCP_ESTABLISHED = '01'


def _hex_addr_is_loopback(addr: str) -> bool:
    host = addr.rsplit(':', 1)[0]
    if len(host) == 8:
        return host.endswith('7F')  # little-endian 127.x.x.x
    return host in ('00000000000000000000000001000000', '0000000000000000FFFF00000100007F')


def parse_proc_net_tcp(text: str) -> list[str]:
    """Remote endpoints of ESTABLISHED, non-loopback sockets from the text of /proc/<pid>/net/tcp{,6}."""
    found = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and fields[3] == _TCP_ESTABLISHED and not _hex_addr_is_loopback(fields[2]):
            found.append(fields[2])
    return found


def linux_sampler(pid: int, host_ns: str | None = None) -> Callable[[], list[str]]:
    """Connections of pid's network namespace. Samples taken before the child has left the host namespace
    (fork/unshare race) describe the host, not the child, and are skipped."""
    def sample() -> list[str]:
        try:
            if host_ns is not None and os.readlink(f'/proc/{pid}/ns/net') == host_ns:
                return []
        except OSError:
            return []
        out: list[str] = []
        for name in ('tcp', 'tcp6'):
            try:
                out += parse_proc_net_tcp(Path(f'/proc/{pid}/net/{name}').read_text())
            except OSError:
                pass
        return out
    return sample


def windows_sample_command(pids: Sequence[int]) -> list[str]:
    ids = ','.join(str(int(p)) for p in pids)
    return ['powershell', '-NoProfile', '-NonInteractive', '-Command',
            f'Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | '
            f'Where-Object {{ @({ids}) -contains $_.OwningProcess -and $_.RemoteAddress -notin "127.0.0.1","::1" }} | '
            f'ForEach-Object {{ "$($_.RemoteAddress):$($_.RemotePort)" }}']


class ConnectionMonitor:
    """Polls `sample` every `interval` seconds on a thread and keeps every distinct external connection seen."""

    def __init__(self, sample: Callable[[], list[str]], interval: float = SAMPLE_INTERVAL):
        self.sample, self.interval = sample, interval
        self.seen: set[str] = set()
        self.polls = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.poll()
            self._stop.wait(self.interval)

    def poll(self) -> None:
        try:
            self.seen.update(self.sample())
        except Exception:  # sampling is evidence only; it never breaks the run
            pass
        self.polls += 1

    def __enter__(self) -> ConnectionMonitor:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self.poll()


# ---------------------------------------------------------------- evidence

@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ''
    data: dict = field(default_factory=dict)


@dataclass
class Evidence:
    os_name: str
    root: str
    steps: list[Step] = field(default_factory=list)
    dry_run: bool = False

    def add(self, name: str, ok: bool, detail: str = '', **data) -> bool:
        self.steps.append(Step(name, bool(ok), detail, data))
        return bool(ok)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(s.ok for s in self.steps)

    def wording(self) -> str:
        """Evidence wording: the OS-block claim is only made when the positive control proved the denial."""
        proven = any(s.name == 'control-after' and s.ok for s in self.steps)
        if self.dry_run:
            return 'dry run with fake bundle: harness logic only, not release evidence'
        return ('passed with OS network block (positive control proven)' if self.ok and proven
                else 'FAILED or network block not proven')

    def to_json(self) -> str:
        return json.dumps({'schema': SCHEMA, 'os': self.os_name, 'root': self.root, 'ok': self.ok,
                           'dry_run': self.dry_run, 'wording': self.wording(),
                           'steps': [vars(s) for s in self.steps]}, indent=2, sort_keys=True)


# ---------------------------------------------------------------- orchestration

def bundle_python(root: Path, os_name: str) -> Path:
    base = root / 'backend' / 'payload' / 'python'
    return base / 'python.exe' if os_name == 'windows' else base / 'bin' / 'python3'


def default_launcher(root: Path, os_name: str) -> Path:
    return root / 'PatchTrace' / ('PatchTrace.exe' if os_name == 'windows' else 'PatchTrace')


def host_os() -> str:
    return 'windows' if sys.platform == 'win32' else 'linux'


def _run(argv: Sequence[str], env: dict[str, str], timeout: float, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def _run_monitored(argv: Sequence[str], env: dict[str, str], timeout: float, os_name: str):
    """Run argv while sampling the child's established external connections (cheap extra evidence)."""
    proc = subprocess.Popen(list(argv), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def windows_sample() -> list[str]:
        out = subprocess.run(windows_sample_command([proc.pid]), capture_output=True, text=True, check=False)
        return out.stdout.split()
    sample = linux_sampler(proc.pid, os.readlink('/proc/self/ns/net')) if os_name == 'linux' else windows_sample
    with ConnectionMonitor(sample) as monitor:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr), monitor


def _tail(proc: subprocess.CompletedProcess, n: int = 400) -> str:
    return ((proc.stdout or '') + (proc.stderr or ''))[-n:].strip()


def selftest_argv(launcher: Path, older: Path, newer: Path, expect: str) -> list[str]:
    return [str(launcher), 'backend', 'selftest', '--older', str(older), '--newer', str(newer),
            '--expect-function', expect, '--json']


def ghidriff_argv(python: Path, older: Path, newer: Path, out: Path, scratch: Path) -> list[str]:
    return [str(python), '-I', '-X', 'utf8', '-m', 'ghidriff', str(older), str(newer), '--output-path', str(out),
            '--project-location', str(scratch / 'projects'), '--gzfs-path', str(scratch / 'gzfs'), '--no-symbols']


def run_acceptance(root: Path, older: Path, newer: Path, expect_function: str, *, os_name: str | None = None,
                   launcher: Path | None = None, control: tuple[str, int] = ('1.1.1.1', 443),
                   run_uid: int | None = None, run_gid: int | None = None, dry_run: bool = False,
                   work: Path | None = None, step_timeout: float = 3600.0) -> Evidence:
    os_name = os_name or host_os()
    root = root.resolve()
    ev = Evidence(os_name, str(root), dry_run=dry_run)
    backend, py = root / 'backend', bundle_python(root, os_name)
    launcher = launcher or default_launcher(root, os_name)
    if not (backend / 'manifest.json').is_file() or not py.is_file() or not launcher.is_file():
        ev.add('layout', False, f'need backend/manifest.json, {py.name} and the launcher under {root}')
        return ev
    ev.add('layout', True)
    ev.add('path-shape', dry_run or path_is_hostile(str(root)),
           'extract the artifact to a path with a space and a non-ASCII character')
    work = work or Path(tempfile.mkdtemp(prefix='pt-accept-'))
    home = work / 'home'
    for sub in (home, work / 'tmp', work / 'out'):
        sub.mkdir(parents=True, exist_ok=True)
    if os_name == 'linux':
        for sub in (work, home, work / 'tmp', work / 'out'):
            sub.chmod(0o777)  # private scratch; a different run identity must be able to write it
    base_path = minimal_path(os_name)
    env = scrub_env(os_name, str(home), str(work / 'tmp'), base_path)
    ev.add('env-scrub', not env_violations(env, os_name), ','.join(env_violations(env, os_name)))
    hits = path_tool_hits(base_path, os_name)
    ev.add('path-has-no-java-python', not hits, ';'.join(hits))
    before = tree_digest(backend)
    ev.add('digest-before', True, before, digest=before)
    run_env = dict(env)
    jdk_bin = backend / 'payload' / 'jdk' / 'bin'
    run_env['PATH'] = run_path(os_name, str(jdk_bin), base_path)
    run_env['JAVA_HOME_OVERRIDE'] = str(backend / 'payload' / 'jdk')
    run_env['GHIDRA_INSTALL_DIR'] = str(backend / 'payload' / 'ghidra')
    uid = os.getuid() if run_uid is None and os_name == 'linux' else (run_uid or 0)
    gid = os.getgid() if run_gid is None and os_name == 'linux' else (run_gid or 0)
    firewall_added: list[list[str]] = []
    try:
        if os_name == 'linux':
            set_tree_readonly(backend, True)
        else:
            subprocess.run(windows_readonly_command(str(backend), os.environ.get('USERNAME', 'Users')), check=False)
        probe = [str(py), '-I', '-c', probe_code(*control)]
        base = _run(probe, env, 30)
        before_ok = base.returncode == 0 and 'CONNECTED' in base.stdout
        ev.add('control-before', before_ok, _tail(base), target=f'{control[0]}:{control[1]}')

        wrap: Callable[[Sequence[str], dict[str, str]], list[str]]
        if os_name == 'linux':
            def wrap(argv, e):
                return linux_denial_argv(argv, e, uid, gid, sudo=os.getuid() != 0 and not dry_run)
        else:
            add, remove = windows_firewall_commands(windows_programs(root))
            for cmd in add:
                subprocess.run(cmd, check=True)
            firewall_added = remove
            wrap = lambda argv, e: list(argv)  # noqa: E731

        after = _run(wrap(probe, env), env, 60)
        after_ok = after.returncode == 0 and 'CONNECTED' in after.stdout
        verdict = control_verdict(before_ok, after_ok)
        ev.add('control-after', verdict == 'proven', _tail(after) or verdict, verdict=verdict)
        if verdict != 'proven':
            return ev
        if os_name == 'linux':
            ev.add('readonly-effective', dry_run or not writable_probe_as(backend, uid, gid, env, wrap),
                   'run as a non-owner (--run-uid/--run-gid) so the tree is not writable; advisory in dry run')

        steps = [('backend-verify-full', [str(launcher), 'backend', 'verify', '--full', '--json'], run_env),
                 ('backend-selftest', selftest_argv(launcher, older, newer, expect_function), run_env)]
        for name, argv, e in steps:
            proc = _run(wrap(argv, e), e, step_timeout)
            ev.add(name, proc.returncode == 0, f'exit {proc.returncode}: {_tail(proc)}', returncode=proc.returncode)
        gout = work / 'out'
        gcmd = ghidriff_argv(py, older, newer, gout, work / 'ghidriff-scratch')
        gproc, monitor = _run_monitored(wrap(gcmd, run_env), run_env, step_timeout, os_name)
        results = sorted(p.name for p in gout.rglob('*.ghidriff.json'))
        ev.add('ghidriff-compare', gproc.returncode == 0 and bool(results),
               f'exit {gproc.returncode}; results={results}; {_tail(gproc)}', returncode=gproc.returncode)
        ev.add('no-external-connections', not monitor.seen,
               f'{monitor.polls} polls; seen={sorted(monitor.seen)}', polls=monitor.polls)
    finally:
        for cmd in firewall_added:
            subprocess.run(cmd, check=False)
        if os_name == 'linux':
            set_tree_readonly(backend, False)
    after_digest = tree_digest(backend)
    ev.add('digest-after-equal', after_digest == before, after_digest, digest=after_digest)
    return ev


def writable_probe_as(backend: Path, uid: int, gid: int, env: dict[str, str], wrap) -> bool:
    """True when the run identity can write into backend/ (read-only is then only proven by the digest)."""
    code = ('import sys\ntry:\n open(sys.argv[1]+"/.pt-write-probe","wb").close()\n import os;os.unlink(sys.argv[1]+"/.pt-write-probe")\n'
            ' print("WROTE")\nexcept OSError:\n print("DENIED")\n')
    proc = _run(wrap([sys.executable, '-I', '-c', code, str(backend)], env), env, 30)
    return 'WROTE' in (proc.stdout or '')


FAKE_PYTHON = """import os, sys
if sys.argv[1:5] == ['-I', '-X', 'utf8', '-m'] and sys.argv[5] == 'ghidriff':
    out = sys.argv[sys.argv.index('--output-path') + 1]
    os.makedirs(os.path.join(out, 'json'), exist_ok=True)
    open(os.path.join(out, 'json', 'fake.ghidriff.json'), 'w').write('{}')
    sys.exit(0)
os.execv(sys.executable, [sys.executable] + sys.argv[1:])
"""


def make_fake_bundle(root: Path, launcher_script: str, os_name: str = 'linux') -> None:
    """A tiny fake release folder for the dry run: wrapper python, fake launcher and JDK dir. Linux only."""
    payload = root / 'backend' / 'payload'
    (payload / 'python' / 'bin').mkdir(parents=True)
    (payload / 'jdk' / 'bin').mkdir(parents=True)
    (payload / 'ghidra').mkdir()
    (root / 'backend' / 'manifest.json').write_text('{"schema": 1, "files": []}\n')
    py = payload / 'python' / 'bin' / 'python3'
    py.write_text(f"#!{sys.executable}\n" + FAKE_PYTHON)
    py.chmod(0o755)
    (root / 'PatchTrace').mkdir()
    launcher = root / 'PatchTrace' / 'PatchTrace'
    launcher.write_text(launcher_script)
    launcher.chmod(0o755)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('root', type=Path)
    parser.add_argument('--older', type=Path, required=True)
    parser.add_argument('--newer', type=Path, required=True)
    parser.add_argument('--expect-function', required=True)
    parser.add_argument('--launcher', type=Path)
    parser.add_argument('--control', default='1.1.1.1:443', help='HOST:PORT reachable before the block')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--run-uid', type=int)
    parser.add_argument('--run-gid', type=int)
    parser.add_argument('--dry-run', action='store_true', help='fake bundle / local control: not release evidence')
    args = parser.parse_args(argv)
    try:
        target = parse_target(args.control)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    ev = run_acceptance(args.root, args.older, args.newer, args.expect_function, launcher=args.launcher,
                        control=target, run_uid=args.run_uid, run_gid=args.run_gid, dry_run=args.dry_run)
    text = ev.to_json()
    if args.evidence:
        args.evidence.write_text(text + '\n', encoding='utf-8')
    print(text)
    return 0 if ev.ok else 1


if __name__ == '__main__':
    sys.exit(main())
