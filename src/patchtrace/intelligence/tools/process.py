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
from .common import STDERR_EXCERPT, ToolError, ToolLimits

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
    """One line of tool text that is safe to show: ANSI/control characters removed, paths reduced to their last
    component (no local paths or user names), whitespace collapsed, length capped."""
    text = _ANSI.sub('', text)
    text = ''.join(c if c == '\t' or (ord(c) >= 32 and ord(c) != 127) else ' ' for c in text)
    text = _PATHISH.sub(lambda m: ntpath.basename(m.group(0).rstrip('\\/')) or '<path>', text)
    return ' '.join(text.split())[:limit]


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
    returncode: int | None
    reason: str | None          # 'cancelled' | 'timeout' | None
    stdout: str
    stderr: str
    oversize: bool
    elapsed_ms: int
    spawn_error: str | None = None

    @property
    def stdout_bytes(self) -> bytes:
        return self.stdout.encode('utf-8')

    def digests(self) -> tuple[str | None, str | None]:
        out = hashlib.sha256(self.stdout_bytes).hexdigest() if self.stdout else None
        err = hashlib.sha256(self.stderr.encode('utf-8')).hexdigest() if self.stderr else None
        return out, err


def execute(argv: list[str], *, scratch: Path, env: Mapping[str, str], cancel: threading.Event, timeout: float,
            limits: ToolLimits, runner: Callable = run_process) -> Execution:
    """Run once with separated, bounded streams. Captured stdout above the limit is reported as `oversize`
    (run_process keeps a bounded tail; the limit is passed + 1 so overflow is detectable)."""
    started = time.monotonic()
    try:
        result = runner(argv, cwd=scratch / 'cwd', env=dict(env), cancel=cancel, timeout_seconds=timeout,
                        log_limit=limits.stdout_bytes + 1, separate_streams=True, stderr_limit=limits.stderr_bytes)
    except (OSError, ValueError, RuntimeError) as exc:
        return Execution(None, None, '', '', False, int((time.monotonic() - started) * 1000), type(exc).__name__)
    elapsed = int((time.monotonic() - started) * 1000)
    oversize = len(result.log_tail.encode('utf-8')) > limits.stdout_bytes
    return Execution(result.returncode, result.reason, result.log_tail, result.stderr_tail, oversize, elapsed)


def run_version_probe(executable: Path, args: list[str], *, cancel: threading.Event, runner: Callable,
                      environ: Mapping[str, str] | None = None, extra: Mapping[str, str] | None = None,
                      timeout: float = 60) -> Execution:
    """`--version`/`--help` style probe in a throw-away scratch (never touches inputs)."""
    scratch = make_scratch('probe')
    try:
        env = tool_env(executable, scratch, extra=extra, environ=environ)
        return execute([str(executable), *args], scratch=scratch, env=env, cancel=cancel, timeout=timeout,
                       limits=ToolLimits(256 * 1024, 64 * 1024), runner=runner)
    finally:
        remove_tree(scratch)
