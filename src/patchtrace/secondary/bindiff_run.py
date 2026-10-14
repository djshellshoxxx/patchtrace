"""Supervised BinDiff execution (SPEC-29 §4-§6). Pure + injected runner; no Qt, no new spawn code.

Flow: copy the bound `.BinExport` snapshots into a private workdir under fixed names and re-hash them,
run `bindiff` with a fixed CLI-only argv and an allow-listed environment through `jobs.run_process`,
require exactly one `older_vs_newer.BinDiff`, preserve it (temp + `os.replace`) BEFORE parsing, then
import the preserved copy with the hardened read-only importer. Every failure is a `SecondaryError` with
a §6 `kind`; previously stored results are never touched here.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..jobs import run_process
from .bindiff import import_bindiff
from .bindiff_inputs import BoundPair, copy_and_hash
from .bindiff_probe import build_env, exit_text, first_error_line, make_private_dirs, sanitize
from .contracts import Capability, SecondaryError, SecondaryMatchSet

DEFAULT_TIMEOUT = 1800
TIMEOUT_RANGE = (60, 86_400)
OUTPUT_LIMIT = 1024 * 1024 * 1024    # above the importer's 512 MiB so oversize is classified distinctly
MAX_OUTPUT_FILES = 4
STDOUT_LIMIT = 64 * 1024
STDERR_LIMIT = 256 * 1024
CONFIG_BYTES = b'{}'
CONFIG_SHA256 = hashlib.sha256(CONFIG_BYTES).hexdigest()
EXPECTED_NAME = 'older_vs_newer.BinDiff'
MAX_OUTPUT_PATH = 250   # BinDiff truncates the name parts when output_dir + name exceeds this (SPEC-29 §3)
USAGE_BANNER = 'bindiff: Find similarities'
# Never passed (SPEC-29 §4.1): UI/IDA/batch modes, config dumps, and the absl flags that would let a file or
# the environment inject arbitrary flags (`--flagfile`, `--fromenv`, `--tryfromenv`) or hide typos (`--undefok`).
FORBIDDEN_FLAGS = ('--ui', '--export', '--ls', '--md_index', '--print_config', '--flagfile', '--fromenv',
                   '--tryfromenv', '--undefok', '--help', '--helpfull', '--helpshort', '--helppackage', '--helpon',
                   '--helpmatch', '--only_check_args', '--version')
_ARGV_FIXED = ('--nologo', '--output_format=bin')
_ARGV_VALUED = ('--output_dir', '--config', '--primary', '--secondary')
_MATCHED = re.compile(r'^matched:\s*(\d{1,9}) of (\d{1,9})/(\d{1,9})', re.MULTILINE)
_SIMILARITY = re.compile(r'^Similarity:\s*([0-9]{1,3}(?:\.[0-9]{1,6})?)%\s*\(Confidence:\s*'
                         r'([0-9]{1,3}(?:\.[0-9]{1,6})?)%\)', re.MULTILINE)


def _err(code, kind: str, message: str) -> SecondaryError:
    return SecondaryError(code, message, kind=kind)


def validate_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not TIMEOUT_RANGE[0] <= value <= TIMEOUT_RANGE[1]:
        raise _err('PT-SECONDARY-INPUT', 'invalid-timeout', 'BinDiff timeout must be an integer between 60 and '
                   '86400 seconds.')
    return value


def check_argv(argv: list[str]) -> list[str]:
    """Allow-list of the run argv after argv[0]: exactly `--nologo`, `--output_format=bin` and one non-empty
    `--output_dir=`, `--config=`, `--primary=`, `--secondary=` each. Raises ValueError otherwise."""
    names = []
    for arg in argv[1:]:
        name, _, value = arg.partition('=')
        if name in FORBIDDEN_FLAGS or not (arg in _ARGV_FIXED or (name in _ARGV_VALUED and value)):
            raise ValueError(f'BinDiff argument {name[:40]!r} is not allowed')
        names.append(name)
    if sorted(names) != sorted(('--nologo', '--output_format', *_ARGV_VALUED)):
        raise ValueError('BinDiff argument set is not allowed (each option exactly once)')
    return argv


def build_argv(executable: str | Path, workdir: Path) -> list[str]:
    """§4.1: named `=`-joined flags only; user filenames never reach argv (inputs have fixed names)."""
    return check_argv([str(executable), '--nologo', '--output_format=bin', f'--output_dir={workdir / "out"}',
                       f'--config={workdir / "bindiff.json"}', f'--primary={workdir / "in" / "older.BinExport"}',
                       f'--secondary={workdir / "in" / "newer.BinExport"}'])


def argv_template(executable: str | Path) -> tuple[str, ...]:
    """Placeholder form for `argv_digest`/cache key: stable across workdirs, OSes and project moves."""
    return (str(executable), '--nologo', '--output_format=bin', '--output_dir=<workdir>/out',
            '--config=<workdir>/bindiff.json', f'--config-sha256={CONFIG_SHA256}',
            '--primary=<workdir>/in/<older>', '--secondary=<workdir>/in/<newer>')


def output_path_fits(workdir: Path) -> bool:
    """True if `<workdir>/out/older_vs_newer.BinDiff` stays within BinDiff's 250-character cap (encoded bytes,
    conservative on Windows), so BinDiff writes exactly the expected name instead of a truncated one."""
    return len(os.fsencode(str(workdir / 'out' / EXPECTED_NAME))) <= MAX_OUTPUT_PATH


def out_guard(out_dir: Path, *, max_bytes: int = OUTPUT_LIMIT, max_files: int = MAX_OUTPUT_FILES) -> str | None:
    """Polled by `run_process`: size/count -> 'output-limit'; a symlink or directory -> 'output-unexpected'.

    While BinDiff writes, `out/` legitimately holds the database plus a transient SQLite rollback journal
    (`older_vs_newer.BinDiff-journal`, measured); both are regular files and are tolerated here. Only a clean
    exit 0 with exactly the database (no journal) is accepted afterwards (`execute`)."""
    total = count = 0
    try:
        with os.scandir(out_dir) as entries:
            for entry in entries:
                count += 1
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    return 'output-unexpected'
                total += info.st_size
                if count > max_files or total > max_bytes:
                    return 'output-limit'
    except OSError:
        return None
    return None


def parse_summary(stdout: str) -> dict[str, str]:
    """Advisory stdout lines only (bounded regexes); never trusted over the database."""
    summary: dict[str, str] = {}
    if match := _MATCHED.search(stdout):
        summary.update(matched=match.group(1), primary_functions=match.group(2), secondary_functions=match.group(3))
    if match := _SIMILARITY.search(stdout):
        summary.update(similarity=match.group(1), confidence=match.group(2))
    return summary


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_tree(path: Path) -> None:
    for attempt in range(3):  # antivirus or a lingering handle may delay removal; never changes the result
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.1 * (attempt + 1))
    shutil.rmtree(path, ignore_errors=True)


def preserve(source: Path, raw_dir: Path, sha256: str) -> Path:
    """Copy the produced `.BinDiff` into the project raw area atomically, keyed by content hash."""
    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
        kept = raw_dir / f'bindiff-{sha256}.BinDiff'
        if not kept.exists():
            fd, temp = tempfile.mkstemp(prefix='.bindiff-', suffix='.part', dir=raw_dir)
            try:
                with os.fdopen(fd, 'wb') as out, open(source, 'rb') as src:
                    shutil.copyfileobj(src, out, 1 << 20)
                os.replace(temp, kept)
            except BaseException:
                Path(temp).unlink(missing_ok=True)
                raise
        if sha256_file(kept) != sha256:
            raise OSError('preserved copy hash mismatch')
        return kept
    except OSError as exc:
        raise _err('PT-SECONDARY-RUN', 'store-failed', 'The BinDiff result could not be preserved '
                   f'({type(exc).__name__}).') from None


@dataclass(frozen=True)
class BindiffRaw:
    returncode: int
    stdout: str
    stderr_tail: str
    reason: str | None                 # 'cancelled' | 'timeout' | None (others raise)
    kept_path: Path | None = None
    output_sha256: str | None = None
    input_file_sha256: tuple[str, str] | None = None
    summary: dict[str, str] = field(default_factory=dict)


def execute(cap: Capability, pair: BoundPair, raw_dir: Path, *, cancel: threading.Event, timeout_seconds: float,
            runner: Callable = run_process, parent_dir: Path | None = None, output_limit: int = OUTPUT_LIMIT,
            environ=None) -> BindiffRaw:
    """§5 up to (and including) raw preservation. Raises SecondaryError with a §6 kind on failure."""
    if not cap.supported or not cap.version or not cap.path:
        raise _err('PT-SECONDARY-UNSUPPORTED', 'not-configured', cap.reason or 'BinDiff is not available.')
    if timeout_seconds <= 0:
        raise _err('PT-SECONDARY-INPUT', 'invalid-timeout', 'BinDiff timeout must be positive.')
    try:
        workdir = Path(tempfile.mkdtemp(prefix='patchtrace-bindiff-', dir=parent_dir))  # 0o700 on POSIX
    except OSError as exc:
        raise _err('PT-SECONDARY-RUN', 'workdir-error', f'Could not prepare a private working folder '
                   f'({type(exc).__name__}).') from None
    try:
        if not output_path_fits(workdir):
            raise _err('PT-SECONDARY-RUN', 'workdir-error', 'Could not prepare a private working folder (its path '
                       "exceeds BinDiff's 250-character output path limit).")
        try:
            make_private_dirs(workdir)
            for part in ('in', 'out'):
                (workdir / part).mkdir()
            (workdir / 'bindiff.json').write_bytes(CONFIG_BYTES)
        except OSError as exc:
            raise _err('PT-SECONDARY-RUN', 'workdir-error', f'Could not prepare a private working folder '
                       f'({type(exc).__name__}).') from None
        h_old = copy_and_hash(pair.older.path, workdir / 'in' / 'older.BinExport')
        h_new = copy_and_hash(pair.newer.path, workdir / 'in' / 'newer.BinExport')
        if (h_old, h_new) != (pair.older.file_sha256, pair.newer.file_sha256):  # validate -> use window
            raise _err('PT-SECONDARY-RUN', 'workdir-error', 'Could not prepare a private working folder '
                       '(input changed after validation).')
        try:
            argv = build_argv(cap.path, workdir)
            env = build_env(Path(cap.path), workdir, environ=environ)
            result = runner(argv, cwd=workdir / 'cwd', env=env, cancel=cancel, timeout_seconds=timeout_seconds,
                            check_output=lambda: out_guard(workdir / 'out', max_bytes=output_limit),
                            log_limit=STDOUT_LIMIT, separate_streams=True, stderr_limit=STDERR_LIMIT)
        except (OSError, ValueError, RuntimeError) as exc:
            raise _err('PT-SECONDARY-RUN', 'spawn-failed', f'Could not start BinDiff ({type(exc).__name__}); the '
                       'process could not be contained.') from None
        stdout, stderr = result.log_tail, result.stderr_tail
        # Any non-clean stop discards out/ unread (SPEC-29 §4.4): a kill during the write phase leaves a valid
        # looking .BinDiff with an empty `function` table (measured), so nothing below runs unless the process
        # ended by itself with exit 0. The `finally` removes the whole workdir.
        if result.reason in ('cancelled', 'timeout'):
            return BindiffRaw(result.returncode, stdout, stderr, result.reason)
        if result.reason == 'output-limit':
            raise _err('PT-SECONDARY-LIMIT', 'output-limit', 'BinDiff output exceeded the safety limit and was '
                       'stopped.')
        if result.reason == 'output-unexpected':
            raise _err('PT-SECONDARY-RUN', 'output-ambiguous', 'BinDiff produced an unexpected set of output '
                       'files; the result was discarded.')
        if result.reason:
            raise _err('PT-SECONDARY-RUN', 'stopped', f'BinDiff was stopped ({sanitize(result.reason, 40)}).')
        if result.returncode < 0:
            raise _err('PT-SECONDARY-RUN', 'nonzero-exit', f'BinDiff terminated abnormally ('
                       f'{exit_text(result.returncode)}); its partial output was discarded.')
        if result.returncode != 0:
            line = sanitize(first_error_line(stderr or stdout))
            raise _err('PT-SECONDARY-RUN', 'nonzero-exit', f'BinDiff reported an error: {line or "no message"} '
                       f'({exit_text(result.returncode)}).')
        out = workdir / 'out'
        entries = sorted(out.iterdir())
        expected = out / EXPECTED_NAME
        if not entries:
            if stdout.lstrip().startswith(USAGE_BANNER):  # exit 0 + usage text: inputs were not diffed
                raise _err('PT-SECONDARY-RUN', 'output-missing', 'BinDiff printed its usage text instead of '
                           'comparing the inputs and wrote no result file.')
            raise _err('PT-SECONDARY-RUN', 'output-missing', 'BinDiff finished without writing a result file.')
        if entries != [expected] or expected.is_symlink() or not expected.is_file():
            raise _err('PT-SECONDARY-RUN', 'output-ambiguous', 'BinDiff produced an unexpected set of output '
                       'files; the result was discarded.')
        if expected.stat().st_size == 0:
            raise _err('PT-SECONDARY-INPUT', 'output-invalid', 'BinDiff wrote a database that failed validation: '
                       'the file is empty.')
        out_sha = sha256_file(expected)
        kept = preserve(expected, raw_dir, out_sha)  # preserved BEFORE parsing (AGENTS.md)
        return BindiffRaw(0, stdout, stderr, None, kept, out_sha, (h_old, h_new), parse_summary(stdout))
    finally:
        _remove_tree(workdir)


def import_output(kept: Path, output_sha256: str, pair: BoundPair, older_sha256: str, newer_sha256: str,
                  summary: dict[str, str] | None = None) -> SecondaryMatchSet:
    """Validate and import the preserved copy; importer errors keep their code and gain a §6 kind."""
    try:
        match_set = import_bindiff(kept, older_sha256, newer_sha256,
                                   expected_hashes=pair.expected_file_hashes() if pair.asserted else None)
    except SecondaryError as exc:
        kind = 'output-pair-mismatch' if exc.code in ('PT-SECONDARY-PAIR', 'PT-SECONDARY-ORIENTATION') \
            else 'output-invalid'
        raise SecondaryError(exc.code, f'BinDiff wrote a database that failed validation: {exc.message}',
                             kind=kind) from None
    if match_set.file_sha256 != output_sha256:
        raise _err('PT-SECONDARY-INPUT', 'output-invalid', 'BinDiff wrote a database that failed validation: '
                   'the preserved copy changed while it was imported.')
    claimed = int((summary or {}).get('matched', '0'))
    if claimed > 0 and not match_set.matches:
        raise _err('PT-SECONDARY-INPUT', 'output-invalid', 'BinDiff wrote a database that failed validation: '
                   f'stdout reports {claimed} matches but the database holds none.')
    return match_set


def version_consistent(match_set: SecondaryMatchSet, cap: Capability) -> bool:
    major = re.match(r'\d+', cap.version or '')
    return bool(major) and re.match(rf'{major.group(0)}(?!\d)', match_set.engine_version) is not None


@dataclass(frozen=True)
class BindiffOutcome:
    match_set: SecondaryMatchSet
    raw: BindiffRaw
    version_consistent: bool


def run_bindiff(cap: Capability, pair: BoundPair, raw_dir: Path, older_sha256: str, newer_sha256: str, *,
                cancel: threading.Event, timeout_seconds: int = DEFAULT_TIMEOUT, runner: Callable = run_process,
                output_limit: int = OUTPUT_LIMIT) -> BindiffOutcome:
    """Standalone §5 pipeline (live checks, tools). The scheduler path goes through the registry adapter."""
    validate_timeout(timeout_seconds)
    raw = execute(cap, pair, raw_dir, cancel=cancel, timeout_seconds=timeout_seconds, runner=runner,
                  output_limit=output_limit)
    if raw.reason == 'cancelled':
        raise _err('PT-SECONDARY-CANCEL', 'cancelled', 'BinDiff was cancelled; its process tree was stopped and '
                   'no result was stored.')
    if raw.reason == 'timeout':
        raise _err('PT-SECONDARY-TIMEOUT', 'timeout', f'BinDiff exceeded the {timeout_seconds} s limit and was '
                   'stopped. Increase the timeout or use smaller inputs.')
    assert raw.kept_path is not None and raw.output_sha256 is not None
    match_set = import_output(raw.kept_path, raw.output_sha256, pair, older_sha256, newer_sha256, raw.summary)
    return BindiffOutcome(match_set, raw, version_consistent(match_set, cap))
