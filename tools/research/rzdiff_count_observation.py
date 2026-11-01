"""Decode a retained static-query capture; never authorize orientation or execute a tool.

See docs/research/rzdiff-orientation-witness-20261101.md. Capture metadata is a
claim from the collector, not a filesystem/runtime attestation by this decoder.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from patchtrace.persistence import strict_json

SOURCE_TREE = 'c3a90e9226d977f58f4e9c75f78fa6b07afe13c7'
ARCHIVE_SHA256 = '9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf'
EXECUTABLE_SHA256 = '536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e'
MAX_STDOUT = 65536
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_COUNT = re.compile(r'(0|[1-9][0-9]{0,19})\n\Z')


def query_argv(executable: str, artifact: str) -> tuple[str, ...]:
    """Prepare only the two source-proven commands, with the same artifact twice."""
    for value in (executable, artifact):
        if not isinstance(value, str) or not value or len(value) > 4096 or '\x00' in value:
            raise ValueError('invalid capture path')
    if artifact.startswith('-'):
        raise ValueError('artifact must not be parsed as a tool option')
    return (executable, '-C', '-j', '-B', '-t', 'command', '-0', 'aflc', '-1', '%vi -1', artifact, artifact)


@dataclass(frozen=True)
class Capture:
    argv: tuple[str, ...]
    artifact_sha256: str
    runtime_config_sha256: str
    archive_sha256: str = ARCHIVE_SHA256
    executable_sha256: str = EXECUTABLE_SHA256
    returncode: int = 0
    reason: str | None = None


def observation(capture: Capture, stdout: bytes, stderr: bytes) -> dict:
    """Accept only the exact count-vs-sentinel shape, with conservative abstention."""
    def require(condition: bool) -> None:
        if not condition:
            raise ValueError('unverified or anomalous Rizin count observation')

    require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STDOUT)
    require(type(stderr) is bytes and not stderr)
    require(type(capture.returncode) is int and capture.returncode == 0 and capture.reason is None)
    require(type(capture.argv) is tuple and len(capture.argv) == 12)
    require(capture.argv == query_argv(capture.argv[0], capture.argv[-1]))
    require(capture.archive_sha256 == ARCHIVE_SHA256 and capture.executable_sha256 == EXECUTABLE_SHA256)
    require(all(isinstance(digest, str) and _DIGEST.fullmatch(digest) is not None for digest in (
        capture.artifact_sha256, capture.runtime_config_sha256)))
    data = strict_json(stdout.decode('utf-8'))
    require(type(data) is dict and set(data) == {'from', 'to', 'diff'})
    require(data['from'] == data['to'] == capture.argv[-1])
    groups = data['diff']
    require(type(groups) is list and len(groups) == 1)
    group = groups[0]
    require(type(group) is dict and set(group) == {'from', 'to', 'ops'})
    for side in ('from', 'to'):
        require(type(group[side]) is list and len(group[side]) == 2
                and all(type(n) is int and n == 1 for n in group[side]))
    ops = group['ops']
    require(type(ops) is list and len(ops) == 2)
    require(all(type(op) is dict and set(op) == {'op', 'value'} for op in ops))
    require(ops[0]['op'] == 'delete' and ops[1] == {'op': 'insert', 'value': '-1\n'})
    count = ops[0]['value']
    require(isinstance(count, str) and _COUNT.fullmatch(count) is not None)
    require(int(count) <= (1 << 64) - 1)
    return {
        'schema': 'rzdiff-count-observation/1', 'source_tree': SOURCE_TREE,
        'orientation_authorized': False, 'capture_binding_verified': False,
        'recovered_count': int(count), 'argv': list(capture.argv),
        'artifact_sha256': capture.artifact_sha256,
        'runtime_config_sha256': capture.runtime_config_sha256,
        'archive_sha256': capture.archive_sha256, 'executable_sha256': capture.executable_sha256,
        'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
        'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
    }
