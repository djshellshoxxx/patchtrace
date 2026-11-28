"""Whole-source acquisition retention through real local stores and a denied-network fixture."""
from __future__ import annotations

import gzip
import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_acquire_cli import HOSTS, NET, SHA_N, SHA_O, plan_of
from test_kbc_acquire_cli import ready as ready
from test_kbc_acquire_cli import staging_root as staging_root

from patchtrace import owned_publication
from patchtrace.kbcorrelation import service as kbc_service
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.acquisition_evidence import canonical, read_evidence
from patchtrace.kbcorrelation.store import KbcStoreError, ProjectAttachment, WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')


def source_path(kb):
    return kb.workspace / 'winbindex' / f'{NET}@2099-02-12.json'


def complete(ready):
    kb, _server, inv, flags, project = ready
    plan = plan_of(kb, inv, flags, project)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', plan['plan_sha'])
    return code, doc, plan


def stored(project):
    (path,) = (project / 'kb' / 'acquisitions').glob('*.json')
    return read_evidence(path.read_bytes())


def test_preview_binds_complete_raw_source_without_publishing(ready):
    kb, server, inv, flags, project = ready
    raw = source_path(kb).read_bytes()
    preview = plan_of(kb, inv, flags, project)
    source = preview['source']['replay']['source']
    assert source['sha256'] == hashlib.sha256(raw).hexdigest()
    assert source['byte_count'] == len(raw) and source['compressed'] is False
    assert not (kb.workspace / 'winbindex-objects').exists()
    assert server.calls == [] and not project.exists()


def test_preview_capture_budget_refuses_without_publication_or_staging(ready, monkeypatch):
    kb, server, inv, flags, project = ready
    monkeypatch.setattr(kbc_service, 'MAX_CAPTURE_BYTES', len(source_path(kb).read_bytes()) - 1)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags)
    assert code == 3 and 'PT-KBC-LIMIT' in doc['error']
    assert not (kb.workspace / 'winbindex-objects').exists()
    assert server.calls == [] and not project.exists()


def test_resolution_and_delivery_use_one_held_record_read(ready, monkeypatch):
    kb, _server, inv, flags, project = ready
    original, calls = wiring.WorkspaceFileIndex._record, []

    def record(index, name):
        calls.append(name)
        return original(index, name)

    monkeypatch.setattr(wiring.WorkspaceFileIndex, '_record', record)
    assert plan_of(kb, inv, flags, project)
    assert calls == [NET]


@pytest.mark.parametrize('compressed', [False, True])
def test_original_bytes_and_replay_survive_in_project_and_workspace(ready, staging_root, compressed):
    kb, _server, _inv, _flags, project = ready
    raw = source_path(kb).read_bytes()
    if compressed:
        raw = gzip.compress(raw, mtime=12345)
        source_path(kb).with_suffix('.json.gz').write_bytes(raw)
        source_path(kb).unlink()
    code, doc, preview = complete(ready)
    assert code == 0, doc
    evidence = stored(project)
    assert evidence.evidence_version == 2
    assert evidence.source.model_dump(mode='json') == preview['source']
    source = evidence.source.replay.source
    assert (project / source.relative_path).read_bytes() == raw
    assert (kb.workspace / source.workspace_path).read_bytes() == raw
    assert source.compressed is compressed
    assert not any(staging_root.iterdir())


def test_whitespace_only_change_rejects_old_consent_before_download(ready, staging_root):
    kb, server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    path = source_path(kb)
    path.write_bytes(path.read_bytes() + b'\n')
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', preview['plan_sha'])
    assert code == 2 and 'PT-KBC-CONSENT' in doc['error']
    assert doc['result']['plan']['requests'] == preview['requests']
    assert doc['result']['plan']['plan_sha'] != preview['plan_sha']
    assert server.calls == [] and not project.exists()
    assert not (kb.workspace / 'winbindex-objects').exists()
    assert not any(staging_root.iterdir())


def test_repeated_older_binary_uses_exact_predecessor_membership(ready):
    kb, server, inv, flags, project = ready
    path = source_path(kb)
    body = json.loads(path.read_bytes())
    updates = body[SHA_O]['windowsVersions']['11-24H2']
    updates['KB5095000'] = {'updateInfo': {'releaseDate': '2098-01-01', 'releaseVersion': '26100.1',
                                         'heading': 'Earlier retained occurrence of identical bytes'}}
    path.write_text(json.dumps(body), encoding='utf-8')
    preview = plan_of(kb, inv, flags, project)
    assert preview is not None
    assert preview['source']['older']['kb'] == 'KB5096000'
    assert preview['source']['replay']['older']['kb'] == 'KB5096000'
    assert server.calls == [] and not project.exists()


@pytest.mark.parametrize('native', [False, True])
def test_raw_capture_preserves_newer_copy_ambiguity_refusal_and_native_precedence(ready, native):
    kb, server, inv, flags, project = ready
    path = source_path(kb)
    body = json.loads(path.read_bytes())
    versions = body[SHA_N]['windowsVersions']
    selected = deepcopy(versions['11-24H2']['KB5099001'])
    if not native:
        del versions['11-24H2']['KB5099001']
    for key in ('11-22H2', '11-23H2'):
        copied = deepcopy(selected)
        copied['updateInfo']['otherWindowsVersions'] = ['11-24H2']
        copied['updateInfo']['heading'] += f' conflicting claim from {key}'
        versions.setdefault(key, {})['KB5099001'] = copied
    path.write_text(json.dumps(body), encoding='utf-8')
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags)
    assert code == 2
    if native:
        assert 'PT-KBC-CONSENT' in doc['error']
        assert doc['result']['plan']['source']['replay']['newer']['source_version_key'] == '11-24H2'
    else:
        assert 'PT-KBC-INPUT' in doc['error'] and doc['result'] is None
    assert server.calls == [] and not project.exists()


def test_replacing_mutable_record_after_capture_cannot_mix_resolution_and_delivery(ready, monkeypatch):
    kb, server, inv, flags, project = ready
    path = source_path(kb)
    raw = path.read_bytes()
    original = wiring.WorkspaceFileIndex.capture

    def capture(index, name):
        snapshot = original(index, name)
        body = json.loads(raw)
        body[SHA_O]['fileInfo']['timestamp'] += 1
        path.write_text(json.dumps(body), encoding='utf-8')
        return snapshot

    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'capture', capture)
    preview = plan_of(kb, inv, flags, project)
    assert preview['source']['replay']['source']['sha256'] == hashlib.sha256(raw).hexdigest()
    assert preview['source']['older']['timestamp'] == json.loads(raw)[SHA_O]['fileInfo']['timestamp']
    assert server.calls == [] and not project.exists()


def test_raw_object_publication_failure_prevents_any_staging(ready, monkeypatch, staging_root):
    kb, server, _inv, _flags, project = ready
    publish = owned_publication.publish_bytes

    def fail_raw(target, data, **kwargs):
        if target.parent.name == 'winbindex-objects':
            raise owned_publication.OwnedPublicationError('authored raw retention failure')
        return publish(target, data, **kwargs)

    monkeypatch.setattr(owned_publication, 'publish_bytes', fail_raw)
    code, doc, _ = complete(ready)
    assert code == 3 and 'PT-KBC-STORAGE' in doc['error']
    assert server.calls == [] and not project.exists() and not any(staging_root.iterdir())


def test_conflicting_retained_raw_object_is_not_replaced(ready, staging_root):
    kb, server, _inv, _flags, project = ready
    digest = hashlib.sha256(source_path(kb).read_bytes()).hexdigest()
    cache = kb.workspace / 'winbindex-objects' / f'{digest}.bin'
    cache.parent.mkdir()
    cache.write_bytes(b'foreign data')
    code, doc, _ = complete(ready)
    assert code == 3 and 'PT-KBC-VERIFY' in doc['error']
    assert cache.read_bytes() == b'foreign data'
    assert server.calls == [] and not project.exists() and not any(staging_root.iterdir())


def test_repair_retains_exact_raw_source_after_mutable_index_removal(ready, staging_root):
    kb, _server, inv, _flags, project = ready
    raw = source_path(kb).read_bytes()

    def interrupted(point):
        if point == 'after_sidecar_write':
            raise KbcStoreError('PT-KBC-STORAGE', 'authored interruption after all source sidecars')

    kb.env = replace(kb.env, fault=interrupted)
    code, doc, _ = complete(ready)
    assert code == 3 and doc['result']['project']['state'] == 'context-pending'
    evidence = stored(project)
    source_path(kb).unlink()
    (kb.workspace / evidence.source.replay.source.workspace_path).unlink()
    kb.env = replace(kb.env, fault=None)
    code, repaired, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0, repaired
    assert stored(project) == evidence
    assert (project / evidence.source.replay.source.relative_path).read_bytes() == raw
    with WorkspaceStore(kb.workspace) as workspace:
        assert all(state == 'done' for _op, state, _body in workspace.journal_ops())


def test_legacy_evidence_serialization_and_content_identity_remain_unchanged():
    path = Path(__file__).resolve().parents[1] / 'docs/schemas/kbcorrelation/examples.json'
    original = json.loads(path.read_bytes())['AcquisitionEvidence']['valid']
    assert original['evidence_version'] == 1 and 'replay' not in original['source']
    evidence = read_evidence(canonical(original))
    assert evidence.source.replay is None
    assert evidence.as_bytes() == canonical(original)
    assert evidence.model_dump(mode='json') == original


@pytest.mark.parametrize('field,value', [('evidence_version', 1), ('evidence_version', True)])
def test_raw_backed_evidence_cannot_masquerade_as_a_legacy_record(ready, field, value):
    _kb, _server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    record = stored(project).model_dump(mode='json')
    record[field] = value
    with pytest.raises(ValueError):
        read_evidence(canonical(record))


def test_missing_retained_source_refuses_before_project_creation(ready, staging_root, monkeypatch):
    kb, _server, _inv, _flags, project = ready
    original = wiring.WorkspaceFileIndex.retain

    def removed_after_publication(index, snapshot):
        original(index, snapshot)
        (index.root / snapshot.source.workspace_path).unlink()

    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'retain', removed_after_publication)
    code, doc, _ = complete(ready)
    assert code == 3 and 'PT-KBC-STORAGE' in json.dumps(doc)
    assert not project.exists() and not any(staging_root.iterdir())
    with WorkspaceStore(kb.workspace) as workspace:
        assert workspace.journal_ops() == ()


def test_conflicting_project_raw_source_is_preserved_and_attachment_stays_pending(ready, staging_root):
    kb, _server, inv, _flags, project = ready
    digest = hashlib.sha256(source_path(kb).read_bytes()).hexdigest()
    target = project / 'kb' / 'winbindex' / f'{digest}.bin'

    def foreign_source(point):
        if point == 'after_project_create':
            target.parent.mkdir(parents=True)
            target.write_bytes(b'foreign project evidence')

    kb.env = replace(kb.env, fault=foreign_source)
    code, doc, _ = complete(ready)
    assert code == 3 and doc['result']['project']['state'] == 'context-pending'
    assert target.read_bytes() == b'foreign project evidence'
    assert not (project / 'kb' / 'acquisitions').exists()
    with WorkspaceStore(kb.workspace) as workspace:
        original = workspace.journal_ops()[0][2]['acquisition_evidence']
    target.unlink()  # explicit removal of the authored conflict, outside the application
    source_path(kb).unlink()
    kb.env = replace(kb.env, fault=None)
    assert kb('attach', str(project), '--investigation', inv, '--repair')[0] == 0
    assert stored(project).model_dump(mode='json') == original


def test_aliased_raw_cache_is_refused_without_touching_its_target(ready, tmp_path):
    kb, server, _inv, _flags, project = ready
    raw = source_path(kb).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    cache = kb.workspace / 'winbindex-objects' / f'{digest}.bin'
    cache.parent.mkdir()
    foreign = tmp_path / 'foreign-source.bin'
    foreign.write_bytes(raw)
    try:
        cache.symlink_to(foreign)
    except OSError:
        pytest.skip('host cannot create a symbolic link')
    code, doc, _ = complete(ready)
    assert code == 3 and 'PT-KBC-STORAGE' in json.dumps(doc)
    assert foreign.read_bytes() == raw and cache.is_symlink()
    assert server.calls == [] and not project.exists()


def test_resume_checks_retained_source_before_advancing_the_created_journal(ready, staging_root):
    kb, _server, inv, _flags, project = ready

    class Interrupted(BaseException):
        pass

    def interrupted(point):
        if point == 'after_sidecar_write':
            raise Interrupted()

    kb.env = replace(kb.env, fault=interrupted)
    with pytest.raises(Interrupted):
        complete(ready)
    evidence = stored(project)
    source = evidence.source.replay.source
    (project / source.relative_path).write_bytes(b'damaged project evidence')
    (kb.workspace / source.workspace_path).unlink()
    with WorkspaceStore(kb.workspace) as workspace:
        op, state, _body = workspace.journal_ops()[0]
        assert state == 'created'
        before = workspace.revisions(inv), workspace.attempts(inv), workspace.journal_ops()
        result = ProjectAttachment(workspace, kb.env.project(workspace, '')).resume(op)
        assert result.status == 'error' and result.value is None
        assert any(issue.code == 'PT-KBC-VERIFY' for issue in result.issues)
        assert (workspace.revisions(inv), workspace.attempts(inv), workspace.journal_ops()) == before
    assert not any(staging_root.iterdir())
