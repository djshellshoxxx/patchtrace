"""Regression tests for the 2026-10-15 secondary-engine audit (SEC-n ids match docs/audits)."""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from types import SimpleNamespace

from patchtrace.secondary import scheduler
from patchtrace.secondary.contracts import Capability
from patchtrace.secondary.registry import RzDiffAdapter


class _FakeRizin(RzDiffAdapter):
    def probe(self, job_env, cancel):
        return Capability(engine='rz-diff', supported=True, version='0.9.0', path='/fake/rizin', supports_json=True)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_rzdiff(older: Path, newer: Path, old_sha: str, new_sha: str):
    seen: list[list[str]] = []

    def runner(argv, **kw):
        seen.append(list(argv))
        return SimpleNamespace(returncode=0, log_tail='[]', stderr_tail='', reason=None)

    ref = scheduler.ProjectRef(older, newer, old_sha, new_sha)
    (out,) = scheduler.run_engines(ref, ['rz-diff'], cancel=threading.Event(), env={},
                                   registry={'rz-diff': _FakeRizin()}, runner=runner)
    return out, seen


def test_sec1_rzdiff_refuses_artifact_not_matching_declared_hash(tmp_path):
    older, newer = tmp_path / 'o.bin', tmp_path / 'n.bin'
    older.write_bytes(b'tampered')
    newer.write_bytes(b'new')
    out, seen = _run_rzdiff(older, newer, _sha(b'original'), _sha(b'new'))
    assert out.run.status == 'failed' and out.run.error_code == 'PT-SECONDARY-INPUT'
    assert seen == [] and out.match_set is None


def test_sec1_rzdiff_reads_verified_copy_not_original(tmp_path):
    older, newer = tmp_path / 'o.bin', tmp_path / 'n.bin'
    older.write_bytes(b'old')
    newer.write_bytes(b'new')
    out, seen = _run_rzdiff(older, newer, _sha(b'old'), _sha(b'new'))
    assert out.run.status == 'ok'
    assert str(older) not in seen[0] and str(newer) not in seen[0]
