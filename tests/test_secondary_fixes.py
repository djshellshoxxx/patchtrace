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


def _row(entry_id, created, engine, older, newer):
    from patchtrace.enrichment.storage import Entry, Guard
    entry = Entry(id=entry_id, kind='secondary-matches', guard=Guard('p', 'r', 'x', 'y'), project_revision=1,
                  created=created, status='complete', body={}, stale=False)
    return entry, SimpleNamespace(engine=engine, older_sha256=older, newer_sha256=newer)


def test_sec2_newer_row_for_another_pair_does_not_hide_current_pair():
    from patchtrace.secondary.store import select_current
    mine = _row('a', '2026-01-01T00:00:00', 'bindiff', 'o1', 'n1')
    other = _row('b', '2026-02-01T00:00:00', 'bindiff', 'o2', 'n2')
    chosen, _ = select_current([other, mine], pair=('o1', 'n1'))
    assert [e.id for e, _ in chosen] == ['a']
    chosen, _ = select_current([other, mine], pair=('o9', 'n9'))  # no row for the pair: newest, shown as stale
    assert [e.id for e, _ in chosen] == ['b']


def test_sec4_user_bindiff_is_preserved_before_parse(tmp_path):
    from bindiff_builder import NEW, OLD, build

    from patchtrace.secondary.bindiff import import_bindiff
    source = build(tmp_path / 'user.BinDiff')
    raw = tmp_path / 'raw'
    match_set = import_bindiff(source, OLD, NEW, preserve_dir=raw)
    kept = raw / f'bindiff-{match_set.file_sha256}.BinDiff'
    assert kept.read_bytes() == source.read_bytes()
    assert hashlib.sha256(kept.read_bytes()).hexdigest() == match_set.file_sha256


def _fake_binexport_worker(argv, **kw):
    import json

    from patchtrace.secondary.binexport_descriptor import PROTO_SHA256
    from patchtrace.secondary.binexport_models import BinExportSummary, WorkerResult
    req = json.loads(Path(argv[-1]).read_text(encoding='utf-8'))
    data = Path(req['src']).read_bytes()
    Path(req['snapshot']).write_bytes(data)
    summary = BinExportSummary(
        file_sha256=_sha(data), file_size=len(data), executable_id='0' * 64, executable_name='x',
        architecture_name='x', timestamp=None, id_binding='sha256', role=req['role'], address_basis='unknown',
        counts={}, function_addresses=(1,), vertex_types=(0,), warnings=(), protobuf_version='7.36.2',
        descriptor_proto_sha256=PROTO_SHA256)
    Path(req['result']).write_text(WorkerResult(kind='ok', summary=summary).model_dump_json(), encoding='utf-8')
    return SimpleNamespace(returncode=0, reason=None, stderr_tail='', log_tail='')


def test_sec5_repeated_accepts_of_one_file_keep_a_single_snapshot(tmp_path, monkeypatch):
    from patchtrace.secondary import binexport_run
    monkeypatch.setattr(binexport_run, 'load_binexport2_class', lambda: None)
    monkeypatch.setattr(binexport_run, 'run_process', _fake_binexport_worker)
    source = tmp_path / 'a.BinExport'
    source.write_bytes(b'binexport-bytes')
    private = tmp_path / 'raw'
    private.mkdir()
    paths = [binexport_run.accept_binexport(source, artifact_sha256='0' * 64, role='older', private_dir=private,
                                            cancel=threading.Event(), accept_unbound=True).snapshot_path
             for _ in range(3)]
    assert len(list(private.iterdir())) == 1 and len(set(paths)) == 1
    assert paths[0].read_bytes() == b'binexport-bytes'
