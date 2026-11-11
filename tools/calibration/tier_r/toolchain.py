"""Tool discovery, BLOCKED reasons and the factory's process runner (SPEC-32 s2, s4).

Every external program (compilers, linkers, LLVM inspectors, git) runs through `patchtrace.jobs.run_process`: absolute
executable, `shell=False`, private cwd, a small allow-listed environment without credentials or proxy variables (the
network variables are added only for `fetch`), a timeout and bounded output. Built images are never executed.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from patchtrace.jobs import ProcessResult, run_process

from . import msvc

OUTPUT_LIMIT = 256 * 1024 * 1024
DEFAULT_TIMEOUT = 300.0
TOOL_ENV_PREFIX = 'PATCHTRACE_KA_'   # e.g. PATCHTRACE_KA_CLANG=/opt/llvm/bin/clang overrides discovery
# name -> candidate executable names (first found wins); Windows names resolve through PATHEXT.
_V = ('', '-18', '-19', '-20', '-17')
CANDIDATES: dict[str, tuple[str, ...]] = {
    'clang': tuple('clang' + v for v in _V),
    'lld-link': tuple('lld-link' + v for v in _V),
    'llvm-pdbutil': tuple('llvm-pdbutil' + v for v in _V),
    'llvm-objdump': tuple('llvm-objdump' + v for v in _V),
    'llvm-nm': tuple('llvm-nm' + v for v in _V),
    'llvm-dwarfdump': tuple('llvm-dwarfdump' + v for v in _V),
    'llvm-strip': tuple('llvm-strip' + v for v in _V),
    'mingw-gcc': ('x86_64-w64-mingw32-gcc', 'x86_64-w64-mingw32-gcc-win32') + (('gcc',) if os.name == 'nt' else ()),
    'cl': ('cl',),
    'msvc-link': ('link',),             # on a POSIX host `link` is coreutils: the banner check in probe rejects it
    'git': ('git',),
}
# tools whose `--version` probe must print a Microsoft banner (cl prints it on stderr, link on stdout)
BANNERS = {'cl': msvc.CL_MARKER, 'msvc-link': msvc.LINK_MARKER}
PROFILE_TOOLS: dict[str, tuple[str, ...]] = {
    'msvc-free': ('clang', 'lld-link', 'llvm-pdbutil', 'llvm-objdump', 'llvm-nm', 'llvm-strip'),
    'mingw-gcc': ('mingw-gcc', 'llvm-dwarfdump', 'llvm-objdump', 'llvm-nm', 'llvm-strip'),
    'mingw-clang': ('clang', 'mingw-gcc', 'llvm-dwarfdump', 'llvm-objdump', 'llvm-nm', 'llvm-strip'),
    'msvc': ('cl', 'msvc-link', 'llvm-pdbutil', 'llvm-objdump', 'llvm-nm', 'llvm-strip'),
}
HOST_ONLY = {'msvc': 'nt'}   # profile -> the only `os.name` that can build it
_POSIX_KEEP = ('LANG',)
_WINDOWS_KEEP = ('SYSTEMROOT', 'WINDIR', 'SYSTEMDRIVE', 'PATHEXT', 'COMSPEC', 'NUMBER_OF_PROCESSORS',
                 'PROCESSOR_ARCHITECTURE')
_NETWORK_KEEP = ('HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
                 'GIT_SSL_CAINFO', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE')


class Blocked(Exception):
    """A required tool is unavailable: reported as BLOCKED, never as a pass or a silent skip."""


class ToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    path: str | None
    version: str | None = None
    reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.path is not None


@dataclass
class Toolchain:
    tools: dict[str, Tool] = field(default_factory=dict)
    host: str = os.name

    def get(self, name: str) -> Tool:
        return self.tools.get(name) or Tool(name, None, reason=f'{name} was not probed')

    def path(self, name: str) -> str:
        tool = self.get(name)
        if not tool.ok:
            raise Blocked(f'{name}: {tool.reason}')
        return tool.path  # type: ignore[return-value]

    def require(self, *names: str) -> None:
        missing = [f'{n}: {self.get(n).reason}' for n in names if not self.get(n).ok]
        if missing:
            raise Blocked('; '.join(missing))

    def profile_status(self, profile: str) -> str | None:
        """None when the profile can build here, else the BLOCKED reason."""
        if HOST_ONLY.get(profile, self.host) != self.host:
            return f'profile {profile} builds only on a Windows host (this host is {self.host})'
        missing = [f'{n} ({self.get(n).reason})' for n in PROFILE_TOOLS.get(profile, ()) if not self.get(n).ok]
        return None if not missing else 'missing ' + ', '.join(missing)

    def versions(self, *names: str) -> dict[str, str]:
        return {n: (self.get(n).version or 'unknown') for n in names}

    def describe(self) -> dict:
        return {n: {'path': t.path, 'version': t.version, 'reason': t.reason} for n, t in sorted(self.tools.items())}


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return 'unknown'


def probe(environ: Mapping[str, str] | None = None, names: Sequence[str] | None = None) -> Toolchain:
    env = os.environ if environ is None else environ
    chain = Toolchain()
    for name in names or CANDIDATES:
        override = env.get(TOOL_ENV_PREFIX + name.upper().replace('-', '_'))
        found = None
        if override:
            found = override if Path(override).is_absolute() and Path(override).is_file() else None
            if found is None:
                chain.tools[name] = Tool(name, None, reason=f'override {override!r} is not an absolute file')
                continue
        else:
            for candidate in CANDIDATES[name]:
                hit = shutil.which(candidate, path=env.get('PATH'))
                if hit:
                    # absolute but NOT symlink-resolved: multi-call tools (lld-link -> lld, llvm-strip ->
                    # llvm-objcopy) choose their personality from argv[0]
                    found = os.path.abspath(hit)
                    break
        if found is None:
            chain.tools[name] = Tool(name, None, reason='not installed (not on PATH)')
            continue
        try:
            result = run_tool([found, '--version'], timeout=60)
            if name in BANNERS:
                version = msvc.banner_line(result.stderr_tail + '\n' + result.log_tail, BANNERS[name])
                if version is None:
                    chain.tools[name] = Tool(name, None, reason=f'{found} is not the Microsoft tool (no banner)')
                    continue
            else:
                version = _first_line(result.log_tail or result.stderr_tail)
        except (OSError, ValueError, ToolError) as exc:
            chain.tools[name] = Tool(name, None, reason=f'cannot run --version: {type(exc).__name__}')
            continue
        chain.tools[name] = Tool(name, found, version)
    return chain


def tool_env(*, tmp: Path, extra: Mapping[str, str] | None = None, network: bool = False,
             base: Mapping[str, str] | None = None, path_dirs: Sequence[str] = ()) -> dict[str, str]:
    """Allow-listed child environment: locale/time fixed, private temp, PATH limited to tool and system dirs."""
    base = os.environ if base is None else base
    windows = os.name == 'nt'
    env: dict[str, str] = {}
    upper = {k.upper(): k for k in base}
    for key in (_WINDOWS_KEEP if windows else _POSIX_KEEP):
        if key in upper:
            env[upper[key]] = base[upper[key]]
    if network:
        for key in _NETWORK_KEEP:
            if key in base:
                env[key] = base[key]
    system = [r'C:\Windows\System32', r'C:\Windows'] if windows else ['/usr/bin', '/bin']
    if windows and 'SYSTEMROOT' in upper:
        root = base[upper['SYSTEMROOT']]
        system = [str(Path(root) / 'System32'), root]
    dirs = list(dict.fromkeys([*path_dirs, *system]))
    env['PATH'] = os.pathsep.join(dirs)
    env.update({'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC', 'TMPDIR': str(tmp), 'TMP': str(tmp), 'TEMP': str(tmp)})
    env.update(extra or {})
    return env


def run_tool(argv: Sequence[str], *, cwd: Path | None = None, timeout: float = DEFAULT_TIMEOUT,
             env: Mapping[str, str] | None = None, output_limit: int = OUTPUT_LIMIT,
             check: bool = False, cancel: threading.Event | None = None) -> ProcessResult:
    """Run one tool. Without `cwd` a private empty directory is used. `check=True` raises ToolError on failure."""
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError('tool executable must be an absolute path')
    with tempfile.TemporaryDirectory(prefix='pt-ka-') as private:
        work = Path(cwd) if cwd is not None else Path(private)
        child_env = dict(env) if env is not None else tool_env(tmp=Path(private),
                                                               path_dirs=[str(Path(argv[0]).parent)])
        result = run_process(list(argv), cwd=work, env=child_env, cancel=cancel or threading.Event(),
                             timeout_seconds=timeout, log_limit=output_limit, separate_streams=True,
                             stderr_limit=1024 * 1024)
    if check and (result.reason or result.returncode != 0):
        tail = (result.stderr_tail or result.log_tail)[-2000:]
        raise ToolError(f'{Path(argv[0]).name} failed ({result.reason or result.returncode}): {tail}')
    if result.reason == 'timeout':
        raise ToolError(f'{Path(argv[0]).name} exceeded {timeout:g} s')
    if len(result.log_tail) >= output_limit:  # the runner keeps a tail: a full buffer means lost output
        raise ToolError(f'{Path(argv[0]).name} output reached the {output_limit} byte limit')
    return result
