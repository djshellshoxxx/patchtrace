"""Build-only producer for the bounded packaged observation record.

The record is not a release receipt or a compiled-bytecode attestation. See
docs/specs/version-provenance.md for the mutable-source observation boundary.
"""
from __future__ import annotations

import importlib.metadata
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event


class PackageBuildInfoError(RuntimeError):
    """The package cannot establish the declared build observation."""


def _observer(root: Path):
    from patchtrace import buildinfo

    root = Path(os.path.abspath(root))
    expected = root / 'src' / 'patchtrace' / 'buildinfo.py'
    if Path(os.path.abspath(buildinfo.__file__)) != expected:
        raise PackageBuildInfoError('build observer was imported from another source tree')
    buildinfo.owned.directory_anchor(root)
    return buildinfo


def _record(raw: bytes):
    from patchtrace import buildinfo

    if type(raw) is not bytes or len(raw) > buildinfo.MAX_BUILD_BYTES:
        raise PackageBuildInfoError('build record exceeds its byte limit')
    try:
        record = buildinfo._validate_record(raw)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PackageBuildInfoError('build record is invalid') from exc
    if record['source_sha256'] == buildinfo.UNKNOWN or record['dirty'] is not None:
        raise PackageBuildInfoError('build record needs a source digest and unknown cleanliness')
    if record['built_utc'] is None or record['pyinstaller'] is None or record['pyside6'] is None:
        raise PackageBuildInfoError('build record is missing build-time observations')
    return record


def _source_observation(root: Path):
    observer = _observer(root)
    before = observer.git_info(root)
    digest = observer.source_sha256(root / 'src')
    if observer.git_info(root) != before:
        raise PackageBuildInfoError('Git observation changed during source observation')
    return digest, before


def prepare_record(root: Path) -> bytes:
    """Observe this source before freezing; never infer cleanliness or trust a CI SHA."""
    root = Path(os.path.abspath(root))
    observer = _observer(root)
    digest, git = _source_observation(root)
    try:
        pyinstaller = importlib.metadata.version('PyInstaller')
        pyside = importlib.metadata.version('PySide6')
    except importlib.metadata.PackageNotFoundError as exc:
        raise PackageBuildInfoError('build dependency metadata is unavailable') from exc
    record = {'version': observer.__version__, 'git_commit': git['commit'],
              'git_describe': git['describe'], 'dirty': None, 'source_sha256': digest,
              'python': '.'.join(map(str, sys.version_info[:3])), 'pyinstaller': pyinstaller,
              'pyside6': pyside, 'built_utc': datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
              'frozen': True}
    raw = (json.dumps(record, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('utf-8')
    _record(raw)
    return raw


def install_record(root: Path, package: Path, raw: bytes) -> Path:
    """Refuse detected source changes and exclusively install into an existing onedir package."""
    root, package = Path(os.path.abspath(root)), Path(os.path.abspath(package))
    expected = _record(raw)
    observer = _observer(root)
    package_anchor = observer.owned.directory_anchor(package)
    internal = package / '_internal'
    internal_anchor = observer.owned.directory_anchor(internal)
    digest, git = _source_observation(root)
    if (digest != expected['source_sha256'] or git['commit'] != expected['git_commit'] or
            git['describe'] != expected['git_describe']):
        raise PackageBuildInfoError('source or Git observation changed during freezing')
    observer.owned.verify_anchor(package_anchor)
    target = internal / observer.BUILD_INFO_RELATIVE
    observer.owned.publish_bytes(target, raw, anchor=internal_anchor)
    observer.owned.verify_anchor(package_anchor)
    if observer.owned.read_bytes(target, maximum=observer.MAX_BUILD_BYTES, anchor=internal_anchor) != raw:
        raise PackageBuildInfoError('packaged build record differs after publication')
    return target


def check_frozen_record(executable: Path, expected_raw: bytes, *, cwd: Path) -> None:
    """Read the freshly built application's record with bounded output before archiving."""
    from patchtrace import buildinfo
    from patchtrace.jobs import run_process
    from patchtrace.persistence import strict_json

    expected = _record(expected_raw)
    executable = Path(executable)
    if not executable.is_absolute():
        raise PackageBuildInfoError('frozen executable path must be absolute')
    env = {**buildinfo._git_env(), 'QT_QPA_PLATFORM': 'offscreen'}
    result = run_process([str(executable), 'version', '--json'], cwd=cwd, env=env,
                         cancel=Event(), timeout_seconds=30, log_limit=buildinfo.MAX_BUILD_BYTES,
                         stderr_limit=4096, max_output_bytes=buildinfo.MAX_BUILD_BYTES,
                         separate_streams=True)
    raw = result.log_bytes
    # A quick successful exit can precede the supervisor's output-limit check.
    # A retained tail is not the complete version response, even when it parses.
    if (result.returncode != 0 or result.reason is not None or type(raw) is not bytes
            or result.stdout_total > buildinfo.MAX_BUILD_BYTES or len(raw) != result.stdout_total):
        raise PackageBuildInfoError('frozen version observation failed or exceeded its process bounds')
    try:
        response = strict_json(raw.decode('utf-8', errors='strict'))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PackageBuildInfoError('frozen version observation is not strict JSON') from exc
    expected_response = {'contract': 'enrichment-cli/1', 'command': 'version', 'status': 'complete',
                         'warnings': [],
                         'result': {'contract': 'build-info/1', 'basis': 'packaged-record', **expected}}
    # JSON bools and integers compare equal in Python; enforce the record's types
    # before comparing the whole response, including frozen=True versus 1.
    payload = response.get('result') if isinstance(response, dict) else None
    if not isinstance(payload, dict) or set(payload) != {*buildinfo.VERSION_KEYS, 'contract', 'basis'}:
        raise PackageBuildInfoError('frozen version observation has invalid build fields')
    _record(json.dumps({key: payload[key] for key in buildinfo.VERSION_KEYS}, allow_nan=False).encode())
    if response != expected_response:
        raise PackageBuildInfoError('frozen version observation differs from the prepared build record')
