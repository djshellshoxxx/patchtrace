"""Optional rz-diff secondary engine (SPEC-11): probe, supervised run and strict JSON parser.

stdout (the JSON document) and stderr (diagnostics) are captured independently with
`run_process(separate_streams=True)`, so diagnostics written on success cannot corrupt the
document. Stdout that is still not strict JSON is an error rather than salvaged: a
partially recovered match list would look complete.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

from ..jobs import run_process
from .contracts import (
    RZDIFF_LIMITATIONS,
    Capability,
    SecondaryError,
    SecondaryMatch,
    SecondaryMatchSet,
    to_milli,
)

MIN_VERSION = (0, 9, 0)
STDOUT_LIMIT = 64 * 1024 * 1024
STDERR_TAIL = 2 * 1024 * 1024
DEFAULT_TIMEOUT = 1800
TIMEOUT_RANGE = (60, 86_400)
PROBE_TIMEOUT = 30
TYPES = frozenset({'COMPLETE', 'PARTIAL', 'UNLIKE'})
ENTRY_KEYS = frozenset({'similarity', 'type', 'original', 'modified'})
SIDE_KEYS = frozenset({'addr', 'name', 'size'})
_VERSION = re.compile(r'^rz-diff (\d+)\.(\d+)\.(\d+)\b')


def parse_version(text: str) -> tuple[str, tuple[int, int, int]] | None:
    for line in text.splitlines():
        if match := _VERSION.match(line.strip()):
            numbers = tuple(int(g) for g in match.groups())
            return '.'.join(match.groups()), numbers  # type: ignore[return-value]
    return None


def probe(executable: Path, env: Mapping[str, str], cancel: threading.Event | None = None,
          runner: Callable = run_process) -> Capability:
    """Never installs anything; an unrecognised or old version is `unsupported`, not an error."""
    path = str(executable)
    with tempfile.TemporaryDirectory(prefix='patchtrace-rzprobe-') as cwd:
        try:
            result = runner([path, '-v'], cwd=Path(cwd), env=env, cancel=cancel or threading.Event(),
                            timeout_seconds=PROBE_TIMEOUT, log_limit=64 * 1024)
        except (OSError, ValueError) as exc:
            return Capability(engine='rz-diff', supported=False, version=None, path=path, supports_json=False,
                              reason=f'cannot run rz-diff: {exc}')
    if result.reason or result.returncode != 0:
        return Capability(engine='rz-diff', supported=False, version=None, path=path, supports_json=False,
                          reason=f'rz-diff -v failed ({result.reason or result.returncode})')
    parsed = parse_version(result.log_tail)
    if parsed is None:
        return Capability(engine='rz-diff', supported=False, version=None, path=path, supports_json=False,
                          reason='rz-diff -v printed no recognisable version')
    text, numbers = parsed
    if numbers < MIN_VERSION:
        return Capability(engine='rz-diff', supported=False, version=text, path=path, supports_json=False,
                          reason=f'rz-diff {text} is older than 0.9.0')
    return Capability(engine='rz-diff', supported=True, version=text, path=path, supports_json=True)


def _fail(message: str) -> SecondaryError:
    return SecondaryError('PT-SECONDARY-INPUT', message)


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise _fail('duplicate key in rz-diff JSON object')
    return dict(pairs)


def _reject_constant(name):
    raise _fail(f'non-finite number {name} in rz-diff JSON')


def _side(value, index: int, label: str) -> tuple[int, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != SIDE_KEYS:
        raise _fail(f'entry {index}: {label} must be null or an object with addr, name, size')
    addr, name, size = value['addr'], value['name'], value['size']
    if isinstance(addr, bool) or not isinstance(addr, int) or not 0 <= addr < 2**64:
        raise _fail(f'entry {index}: {label}.addr is not an unsigned 64-bit integer')
    if not isinstance(name, str):
        raise _fail(f'entry {index}: {label}.name is not a string')
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise _fail(f'entry {index}: {label}.size is not a non-negative integer')
    return addr, name


def parse_output(stdout: str, version: str, older_sha256: str, newer_sha256: str) -> SecondaryMatchSet:
    if not stdout.strip():
        raise _fail('rz-diff produced no output')
    try:
        document = json.loads(stdout, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except ValueError as exc:
        if isinstance(exc, SecondaryError):
            raise
        raise _fail('rz-diff output is not valid JSON') from None
    if not isinstance(document, list):
        raise _fail('rz-diff output is not a JSON array')
    matches = []
    for index, entry in enumerate(document):
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise _fail(f'entry {index}: expected keys similarity, type, original, modified')
        if not isinstance(entry['type'], str) or entry['type'] not in TYPES:
            raise _fail(f'entry {index}: unknown type {entry["type"]!r}')
        try:
            milli, text = to_milli(entry['similarity'], f'entry {index}: similarity')
        except SecondaryError as exc:
            raise _fail(exc.message) from None
        older = _side(entry['original'], index, 'original')
        newer = _side(entry['modified'], index, 'modified')
        if older is None and newer is None:
            raise _fail(f'entry {index}: both sides are null')
        matches.append(SecondaryMatch(
            engine='rz-diff', engine_version=version,
            older_address=older[0] if older else None, newer_address=newer[0] if newer else None,
            older_name=older[1] if older else None, newer_name=newer[1] if newer else None,
            similarity_milli=milli, similarity_text=text, confidence_milli=None, confidence_text=None,
            flags=(), algorithm='levenshtein-bytes', match_type=entry['type']))
    return SecondaryMatchSet(engine='rz-diff', engine_version=version, older_sha256=older_sha256,
                             newer_sha256=newer_sha256,
                             file_sha256=hashlib.sha256(stdout.encode('utf-8')).hexdigest(),
                             matches=tuple(matches), limitations=RZDIFF_LIMITATIONS)


def run_rzdiff(capability: Capability, older: Path, newer: Path, older_sha256: str, newer_sha256: str, *,
               env: Mapping[str, str], cancel: threading.Event, timeout_seconds: int = DEFAULT_TIMEOUT,
               runner: Callable = run_process) -> SecondaryMatchSet:
    if not capability.supported or capability.version is None:
        raise SecondaryError('PT-SECONDARY-UNSUPPORTED', capability.reason or 'rz-diff is not supported')
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or \
            not TIMEOUT_RANGE[0] <= timeout_seconds <= TIMEOUT_RANGE[1]:
        raise SecondaryError('PT-SECONDARY-INPUT', 'timeout must be an integer between 60 and 86400 seconds')
    older, newer = Path(older).resolve(), Path(newer).resolve()
    for item in (older, newer):
        if not item.is_file():
            raise SecondaryError('PT-SECONDARY-INPUT', f'artifact {item.name} is not a readable file')
    argv = list(rzdiff_argv(capability.path, older, newer))
    with tempfile.TemporaryDirectory(prefix='patchtrace-rzdiff-') as cwd:
        # One byte over the limit lets truncation be detected rather than silently parsed.
        result = runner(argv, cwd=Path(cwd), env=env, cancel=cancel, timeout_seconds=timeout_seconds,
                        log_limit=STDOUT_LIMIT + 1, separate_streams=True, stderr_limit=STDERR_TAIL)
    if result.reason == 'cancelled':
        raise SecondaryError('PT-SECONDARY-CANCEL', 'rz-diff was cancelled')
    if result.reason == 'timeout':
        raise SecondaryError('PT-SECONDARY-RUN', f'rz-diff exceeded the {timeout_seconds} s timeout')
    if result.reason:
        raise SecondaryError('PT-SECONDARY-RUN', f'rz-diff stopped: {result.reason}')
    return interpret(result.returncode, result.log_tail, result.stderr_tail, capability.version,
                     older_sha256, newer_sha256)


def rzdiff_argv(executable: str, older: Path, newer: Path) -> tuple[str, ...]:
    """Flags frozen for rizin 0.9.x (SPEC-28 C2 re-verifies them on the pinned release)."""
    return (executable, '-C', '-j', '-t', 'functions', str(older), str(newer))


def interpret(returncode: int, output: str, stderr_tail: str, version: str, older_sha256: str,
              newer_sha256: str, stdout_limit: int = STDOUT_LIMIT) -> SecondaryMatchSet:
    """Turn a finished rz-diff process (no cancel/timeout) into a strict match set."""
    if returncode != 0:
        tail = (stderr_tail or output).encode('utf-8')[-STDERR_TAIL:].decode('utf-8', errors='replace')
        raise SecondaryError('PT-SECONDARY-RUN', f'rz-diff exited with {returncode}: {tail}')
    if len(output.encode('utf-8')) > stdout_limit:
        raise SecondaryError('PT-SECONDARY-LIMIT', 'rz-diff output exceeds 64 MiB')
    if '\ufffd' in output:
        raise SecondaryError('PT-SECONDARY-INPUT', 'rz-diff output is not valid UTF-8')
    return parse_output(output, version, older_sha256, newer_sha256)
