"""Supervised execution of one tool on one artifact (SPEC-29 tools T4). No Qt; spawns only via `jobs.run_process`.

Each run gets a private scratch directory holding a verified, read-only copy of the artifact under a fixed name,
copies of any rule/signature database it needs (hashed while copied, so the digest describes exactly what the tool
reads) and private HOME/TMP/APPDATA folders. The child environment is the shared from-scratch allow-list of
`secondary/engine_env.py`; the only additions come from explicit configuration (diec library path, capa's Ghidra
backend). Targets are never executed: the tools analyse them statically (FLOSS emulation only after consent).
"""
from __future__ import annotations

import hashlib
import ntpath
import os
import re
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ...enrichment.identity import canonical_json
from ...jobs import run_process
from ...secondary.engine_env import engine_env
from .common import STDERR_EXCERPT, ToolError, ToolLimits, display_text

INPUT_NAME = 'artifact.bin'
MAX_INPUT_PATH = 200
MAX_TREE_FILES = 20_000
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
COPY_CHUNK = 4 * 1024 * 1024
EXTRA_ENV = frozenset({'LD_LIBRARY_PATH', 'GHIDRA_INSTALL_DIR', 'JAVA_HOME'})
_ANSI = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]')
_PATHISH = re.compile(r'(?:[A-Za-z]:)?(?:[\\/][^\\/\s\'"<>|]+)+[\\/]?')


def sanitize(text: str, limit: int = 200) -> str:
    """One line of tool STDERR/ERROR text that is safe to show: ANSI/control characters removed, paths reduced to
    their last component (no local paths or user names), whitespace collapsed, length capped. Not for names the
    tool reports about the file (use `tool_text`): the path scrubber would mangle `C/C++` or `UPX/LZMA`."""
    text = _ANSI.sub('', text)
    text = ''.join(c if c == '\t' or (ord(c) >= 32 and ord(c) != 127) else ' ' for c in text)
    text = _PATHISH.sub(lambda m: ntpath.basename(m.group(0).rstrip('\\/')) or '<path>', text)
    return ' '.join(text.split())[:limit]


def tool_text(text: str, limit: int = 200) -> str:
    """A name or label the tool reported (compiler, packer, detection string): ANSI sequences dropped, whitespace
    collapsed, then control, format (bidi, zero-width) and unassigned characters escaped by `display_text`. Slashes
    and every other printable character are kept, so distinct detections stay distinct."""
    return display_text(' '.join(_ANSI.sub('', text).split()), limit)


def excerpt(text: str) -> str:
    """Bounded multi-line stderr excerpt (stored, never shown by default)."""
    lines = [sanitize(line, 400) for line in text.splitlines() if line.strip()]
    return '\n'.join(lines)[-STDERR_EXCERPT:]


def first_error_line(*texts: str) -> str:
    for text in texts:
        for line in text.splitlines():
            clean = sanitize(line)
            if clean and any(word in clean.lower() for word in ('error', 'cannot', 'failed', 'invalid', 'unable')):
                return clean
    for text in texts:
        for line in text.splitlines():
            if sanitize(line):
                return sanitize(line)
    return ''


def exit_text(code: int | None) -> str:
    if code is None:
        return 'no exit code'
    if code < 0:
        return f'signal {-code}'
    return f'exit 0x{code & 0xFFFFFFFF:08X}' if code > 255 else f'exit {code}'


# ---- files ------------------------------------------------------------------------------------------------------

def sha256_file(path: Path, limit: int = MAX_EXECUTABLE_BYTES) -> str:
    digest, total = hashlib.sha256(), 0
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            total += len(chunk)
            if total > limit:
                raise ToolError('PT-TOOL-LIMIT', 'file is larger than the hashing limit')
            digest.update(chunk)
    return digest.hexdigest()


def verify_executable(path: Path, expected_sha256: str) -> Path:
    """Re-hash the executable immediately before it is spawned (TA-6). The probe hashed it once; a binary swapped
    in a user-writable folder afterwards, with size and mtime restored, would otherwise run under the pinned
    identity. Returns the resolved path to spawn; `PT-TOOL-STALE` when it is gone or differs. The window between
    this hash and the spawn is not zero (a hash cannot be bound to an exec on every OS)."""
    resolved = regular_file(Path(path))
    if resolved is None:
        raise ToolError('PT-TOOL-STALE', 'the tool executable is no longer available at the probed path')
    try:
        actual = sha256_file(resolved)
    except (OSError, ToolError):
        raise ToolError('PT-TOOL-STALE', 'the tool executable can no longer be read') from None
    if actual != expected_sha256:
        raise ToolError('PT-TOOL-STALE', 'the tool executable changed since it was probed; probe it again')
    return resolved


def regular_file(path: Path) -> Path | None:
    """The resolved path of an existing regular file given as an absolute path, else None (never PATH lookup)."""
    try:
        if not path.is_absolute():
            return None
        resolved = path.resolve(strict=True)
        return resolved if stat.S_ISREG(os.stat(resolved).st_mode) else None
    except (OSError, RuntimeError, ValueError):
        return None


def _tree_entries(root: Path, max_files: int, max_bytes: int):
    if root.is_symlink() or not root.is_dir():
        raise ToolError('PT-TOOL-INPUT', f'{root.name or "directory"} is not a directory')
    count = total = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        base = Path(current)
        for name in dirs:
            if (base / name).is_symlink():
                raise ToolError('PT-TOOL-INPUT', 'rule or signature directory contains a link')
        for name in sorted(files):
            path = base / name
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                raise ToolError('PT-TOOL-INPUT', 'rule or signature directory contains a non-regular file')
            count += 1
            total += info.st_size
            if count > max_files or total > max_bytes:
                raise ToolError('PT-TOOL-LIMIT', 'rule or signature directory is too large')
            yield path, path.relative_to(root).as_posix()


def tree_digest(root: Path, *, max_files: int = MAX_TREE_FILES, max_bytes: int = MAX_TREE_BYTES) -> str:
    """Deterministic digest of a directory tree: sorted (relative path, size, SHA-256) of every regular file."""
    items = []
    for path, rel in _tree_entries(root, max_files, max_bytes):
        items.append([rel, path.stat().st_size, sha256_file(path, max_bytes)])
    return hashlib.sha256(canonical_json(['tree/1', items])).hexdigest()


def copy_tree(source: Path, dest: Path, *, max_files: int = MAX_TREE_FILES,
              max_bytes: int = MAX_TREE_BYTES) -> str:
    """Copy regular files only and return the digest of the copy (what the tool will actually read)."""
    items = []
    for path, rel in _tree_entries(source, max_files, max_bytes):
        target = dest / Path(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest, size = hashlib.sha256(), 0
        with open(path, 'rb') as src, open(target, 'xb') as out:
            while chunk := src.read(COPY_CHUNK):
                digest.update(chunk)
                size += len(chunk)
                out.write(chunk)
        items.append([rel, size, digest.hexdigest()])
    dest.mkdir(parents=True, exist_ok=True)
    return hashlib.sha256(canonical_json(['tree/1', items])).hexdigest()


@dataclass(frozen=True)
class ArtifactCopy:
    path: Path
    sha256: str
    md5: str
    sha1: str
    size: int


def copy_artifact(source: Path, dest: Path, expected_sha256: str, *, expected_size: int | None = None,
                  cancel: threading.Event | None = None) -> ArtifactCopy:
    """Stream the verified artifact into `dest`, hash the copy and make it read-only (T4)."""
    from ...artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    try:
        reader = VerifiedArtifactReader.open_path(source, expected_sha256, expected_size,
                                                  cancel=(cancel.is_set if cancel else None))
    except ArtifactBytesError as exc:
        code = 'PT-TOOL-CANCEL' if exc.code == 'cancelled' else 'PT-TOOL-ARTIFACT'
        raise ToolError(code, f'artifact cannot be read for analysis ({exc.code})') from None
    sha256, md5, sha1 = hashlib.sha256(), hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False)
    try:
        with open(dest, 'xb') as out:
            offset = 0
            while offset < reader.size:
                if cancel is not None and cancel.is_set():
                    raise ToolError('PT-TOOL-CANCEL', 'cancelled while copying the artifact')
                chunk = reader.read(offset, min(COPY_CHUNK, reader.size - offset), clip=False)
                for digest in (sha256, md5, sha1):
                    digest.update(chunk)
                out.write(chunk)
                offset += len(chunk)
    finally:
        reader.close()
    if sha256.hexdigest() != expected_sha256:
        raise ToolError('PT-TOOL-ARTIFACT', 'the private copy differs from the recorded artifact SHA-256')
    os.chmod(dest, stat.S_IREAD)
    return ArtifactCopy(dest, sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest(), reader.size)


# ---- scratch ----------------------------------------------------------------------------------------------------

PRIVATE_DIRS = (('cwd',), ('home',), ('tmp',), ('programdata',), ('in',), ('home', 'AppData', 'Roaming'),
                ('home', 'AppData', 'Local'), ('home', '.config'), ('home', '.cache'))


def make_scratch(engine: str, parent: Path | None = None) -> Path:
    try:
        if parent is not None:
            parent.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix=f'patchtrace-{engine}-', dir=parent))  # 0o700 on POSIX
        for parts in PRIVATE_DIRS:
            root.joinpath(*parts).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ToolError('PT-TOOL-INPUT', f'could not prepare a private scratch folder ({type(exc).__name__})') \
            from None
    if len(str(root / 'in' / INPUT_NAME)) > MAX_INPUT_PATH:
        remove_tree(root)
        raise ToolError('PT-TOOL-INPUT', 'the scratch folder path is too long; choose a shorter scratch location')
    return root


def remove_tree(path: Path) -> None:
    def writable(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            func(target)
        except OSError:
            pass
    for attempt in range(3):  # antivirus or a lingering handle may delay removal; never changes a result
        try:
            shutil.rmtree(path, onexc=writable)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.1 * (attempt + 1))
    shutil.rmtree(path, ignore_errors=True)


def tool_env(executable: Path, scratch: Path, *, extra: Mapping[str, str] | None = None,
             environ: Mapping[str, str] | None = None, windows: bool | None = None) -> dict[str, str]:
    """The from-scratch allow-list of `secondary/engine_env.py` (private HOME/TMP/APPDATA under `scratch`) plus
    explicitly configured additions only (T4)."""
    env = engine_env(os.environ if environ is None else environ, 'bindiff', windows=windows, workdir=scratch,
                     executable=executable)
    windows = os.name == 'nt' if windows is None else windows
    for key, value in (extra or {}).items():
        if key not in EXTRA_ENV or not value or any(c in value for c in '\0\r\n'):
            raise ToolError('PT-TOOL-INPUT', f'environment addition {key[:40]!r} is not allowed')
        env[key] = value
    if extra and extra.get('JAVA_HOME'):
        path_key = next((k for k in env if k.upper() == 'PATH'), 'PATH')
        java_bin = str(Path(extra['JAVA_HOME']) / 'bin')
        env[path_key] = java_bin + (';' if windows else ':') + env.get(path_key, '')
    return env


# ---- execution --------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Execution:
    """Outcome of one supervised run. `stdout_raw`/`stderr_raw` are the exact bytes captured (stdout complete when
    `oversize` is false); `stdout`/`stderr` are their lossy text, for classification and messages only."""
    returncode: int | None
    reason: str | None          # 'cancelled' | 'timeout' | 'output-limit' | None
    stdout: str
    stderr: str
    oversize: bool
    elapsed_ms: int
    spawn_error: str | None = None
    stdout_raw: bytes = b''
    stderr_raw: bytes = b''
    peak_memory_bytes: int | None = None

    @property
    def stdout_bytes(self) -> bytes:
        return self.stdout_raw

    def digests(self) -> tuple[str | None, str | None]:
        out = hashlib.sha256(self.stdout_raw).hexdigest() if self.stdout_raw else None
        err = hashlib.sha256(self.stderr_raw).hexdigest() if self.stderr_raw else None
        return out, err


def total_ram_bytes() -> int | None:
    """Physical memory of this machine, or None when the platform does not say (callers then use their ceiling)."""
    if os.name == 'nt':
        import ctypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong), ('total_phys', ctypes.c_ulonglong),
                        *((name, ctypes.c_ulonglong) for name in ('avail_phys', 'total_page', 'avail_page',
                                                                  'total_virtual', 'avail_virtual',
                                                                  'avail_extended'))]
        status = MemoryStatus(ctypes.sizeof(MemoryStatus))
        ok = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # type: ignore[attr-defined]
        return int(status.total_phys) if ok and status.total_phys > 0 else None
    try:
        total = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    except (ValueError, OSError, AttributeError):
        return None
    return total if total > 0 else None


def execute(argv: list[str], *, scratch: Path, env: Mapping[str, str], cancel: threading.Event, timeout: float,
            limits: ToolLimits, runner: Callable = run_process, memory_limit_bytes: int | None = None) -> Execution:
    """Run once with separated, bounded streams. The child is stopped as soon as its stdout passes the limit
    (`max_output_bytes`), so a flood costs seconds, not the whole timeout; stdout is kept as the exact bytes
    written (TA-4) and `oversize` is decided on byte counts. `memory_limit_bytes` is passed to `run_process`
    (Job Object per-process cap on Windows, RLIMIT_AS on POSIX); None leaves memory unlimited."""
    started = time.monotonic()
    kwargs: dict = {}
    if memory_limit_bytes is not None:
        kwargs['memory_limit_bytes'] = memory_limit_bytes
    try:
        result = runner(argv, cwd=scratch / 'cwd', env=dict(env), cancel=cancel, timeout_seconds=timeout,
                        log_limit=limits.stdout_bytes + 1, separate_streams=True, stderr_limit=limits.stderr_bytes,
                        max_output_bytes=limits.stdout_bytes, **kwargs)
    except (OSError, ValueError, RuntimeError) as exc:
        return Execution(None, None, '', '', False, int((time.monotonic() - started) * 1000), type(exc).__name__)
    elapsed = int((time.monotonic() - started) * 1000)
    out_raw = result.log_bytes if result.log_bytes is not None else result.log_tail.encode('utf-8')
    err_raw = result.stderr_bytes if result.stderr_bytes is not None else result.stderr_tail.encode('utf-8')
    total = max(result.stdout_total, len(out_raw))
    oversize = total > limits.stdout_bytes or result.reason == 'output-limit'
    return Execution(result.returncode, result.reason, out_raw.decode('utf-8', errors='replace'),
                     err_raw.decode('utf-8', errors='replace'), oversize, elapsed, None, out_raw, err_raw,
                     result.peak_memory_bytes)


_MEMORY_TEXT = ('MemoryError', 'Cannot allocate memory', 'std::bad_alloc', 'out of memory', 'Out of memory')


def memory_exhausted(stderr: str, returncode: int | None, peak_memory_bytes: int | None = None,
                     memory_limit_bytes: int | None = None) -> bool:
    """True when a failed run looks like it hit the memory cap (`PT-TOOL-LIMIT`, 'memory'): allocation failure text
    on stderr, STATUS_NO_MEMORY (0xC0000017), or a Job Object peak at the cap. Only meaningful with a cap set."""
    if memory_limit_bytes is None:
        return False
    if returncode is not None and (returncode & 0xFFFFFFFF) == 0xC0000017:
        return True
    if peak_memory_bytes is not None and peak_memory_bytes >= 0.95 * memory_limit_bytes:
        return True
    return any(text in stderr for text in _MEMORY_TEXT)


def describe_failure(run: Execution, what: str) -> str:
    """One sanitised sentence for a run that did not finish normally (probe messages; TA-10)."""
    if run.spawn_error:
        return f'{what} could not be started ({run.spawn_error})'
    if run.reason == 'timeout':
        return f'{what} timed out'
    if run.reason == 'cancelled':
        return f'{what} was cancelled'
    if run.reason == 'output-limit':
        return f'{what} printed more output than allowed'
    return f'{what} failed ({exit_text(run.returncode)})'


def is_transient(*runs: Execution) -> bool:
    """True when a probe outcome says nothing stable about the tool (timeout, cancel, spawn failure): it must not
    be cached for the process lifetime (a cold PyInstaller start can exceed the probe timeout once)."""
    return any(r.reason in ('timeout', 'cancelled') or r.spawn_error for r in runs)


def run_version_probe(executable: Path, args: list[str], *, cancel: threading.Event, runner: Callable,
                      environ: Mapping[str, str] | None = None, extra: Mapping[str, str] | None = None,
                      timeout: float = 60) -> Execution:
    """`--version`/`--help` style probe in a throw-away scratch (never touches inputs). Never raises: an unusable
    environment (Windows without SystemRoot) or a scratch failure becomes an Execution with `spawn_error`."""
    started = time.monotonic()
    try:
        scratch = make_scratch('probe')
    except ToolError as exc:
        return Execution(None, None, '', '', False, 0, exc.message)
    try:
        env = tool_env(executable, scratch, extra=extra, environ=environ)
        return execute([str(executable), *args], scratch=scratch, env=env, cancel=cancel, timeout=timeout,
                       limits=ToolLimits(256 * 1024, 64 * 1024), runner=runner)
    except (OSError, ToolError) as exc:
        return Execution(None, None, '', '', False, int((time.monotonic() - started) * 1000), getattr(
            exc, 'message', type(exc).__name__))
    finally:
        remove_tree(scratch)
