"""PIL-C1 store and review events (docs/specs/program-e/PIL-integration-plan.md s7 "Store and keys", s9 PIL-C1).

A result is a sidecar directory plus one tiny pointer row; the pointer certifies the manifest and the manifest the
assessment, so a copied, truncated or edited sidecar is a cache miss, never data. Retention keeps the newest three
results per (pair, advisories, config) after a verified backup and never touches review events or other features'
rows. Review events are separate append-only rows. Synthetic data only: the sample project and invented digests.
"""
from __future__ import annotations

import dataclasses
import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pilot_localize_support import CVE_A, build, hypothesis, observation, run, sha
from pilot_synergy_support import StaticKev

from patchtrace import verified_backup
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import DERIVED_KINDS, KINDS, EnrichmentStore, Guard
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, limits, review, store
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as opened:
        yield opened


@pytest.fixture
def enrichment(service):
    return EnrichmentStore(service.store)


def facts_of(service) -> dict:
    sha_of = {a.side: a.sha256 for a in service.project.artifacts}
    run_row = service.project.runs[-1]
    return {'older': sha_of['older'], 'newer': sha_of['newer'], 'run': run_row.id, 'raw': run_row.raw_sha256}


def make(service, seed: int = 0, *, config: c.PilotConfig | None = None, facts_id: str | None = None,
         swapped: bool = False, **changes) -> tuple[c.PilotAssessment, c.PilotConfig]:
    """A real localized assessment of the sample project. `seed` changes the KEV snapshot id and so the result id only,
    `facts_id` the advisory document (another family), `config` the configuration (another family), `swapped` the
    orientation and `changes` any other field of the input bundle (a foreign project, run, raw output or artifact)."""
    f = facts_of(service)
    older, newer = (f['newer'], f['older']) if swapped else (f['older'], f['newer'])
    cand = c.Candidate(candidate_key=keys.candidate_key(older, newer, [0x1000], [0x1080]),
                       older=(c.FunctionRef(rva=0x1000, name='read_item'),),
                       newer=(c.FunctionRef(rva=0x1080, name='read_item'),), identity='unassessed')
    bundle = build([cand], [(cand, observation('b1:BND', ref='signal-1', line=14))],
                   cves={CVE_A: (hypothesis('R-MEMORY-READ', 'CWE-125'),)})
    advisory = bundle.advisory if facts_id is None else type(bundle.advisory)(bundle.advisory._reports, (facts_id,))
    fields = dict(advisory=advisory, kev=StaticKev(sha('kev', seed), {}), project_id=service.project.id,
                  revision=service.project.revision, older_sha256=older, newer_sha256=newer,
                  ghidriff_run_id=f['run'], raw_sha256=f['raw'])
    config = config or keys.default_config()
    fixed = datetime(2099, 1, 1, tzinfo=UTC)
    return run(dataclasses.replace(bundle, **{**fields, **changes}), config, clock=lambda: fixed), config


def stamp(index: int) -> str:
    return (datetime(2099, 1, 1, tzinfo=UTC) + timedelta(seconds=index)).strftime('%Y-%m-%dT%H:%M:%SZ')


def put(service, enrichment, seed: int = 0, *, created: int | None = None, **kw):
    assessment, config = make(service, seed, **kw)
    current = store.current_guard(service.project, assessment.result_id)
    return store.publish(enrichment, assessment, config, current=current,
                         created_utc=stamp(seed if created is None else created))


def rows(service, kind: str = store.KIND) -> dict[str, tuple]:
    db = service.store.connection
    return {r[0]: tuple(r[1:]) for r in db.execute(
        'SELECT id, body_sha256, created, stale FROM enrichment_entries WHERE kind=? ORDER BY id', (kind,))}


def pointer_ids(service) -> list[str]:
    return sorted(i for i in rows(service) if i.startswith(keys.POINTER_PREFIX))


def sidecars(service) -> list[str]:
    base = service.root / 'intelligence' / 'pilot'
    return sorted(p.name for p in base.iterdir()) if base.is_dir() else []


# --- layout, round trip and stale detection -------------------------------------------------------------------------

def test_store_roundtrip_and_stale(service, enrichment):
    assessment, config = make(service)
    current = store.current_guard(service.project, assessment.result_id)
    published = store.publish(enrichment, assessment, config, current=current, created_utc=stamp(0))
    assert not published.entry.stale and published.deleted == 0
    loaded = store.load(enrichment)
    assert (loaded.state, loaded.reason, loaded.changed) == ('current', None, ())
    assert loaded.assessment == assessment and loaded.manifest.config == config  # nothing lost, nothing added
    assert keys.canonical_bytes(loaded.assessment) == keys.canonical_bytes(assessment)
    keys.verify_assessment(loaded.assessment)
    keys.verify_manifest(loaded.manifest, loaded.assessment)
    keys.verify_pointer(loaded.pointer, loaded.manifest)
    f = facts_of(service)
    known = {'older_sha256': f['older'], 'newer_sha256': f['newer'], 'ghidriff_run_id': f['run'],
             'raw_sha256': f['raw']}
    assert store.load(enrichment, known).state == 'current'
    # a new analysis run replaces the raw output: the stored result is shown, for reference, as stale
    moved = store.load(enrichment, {**known, 'raw_sha256': sha('another raw output')})
    assert (moved.state, moved.reason, moved.changed) == ('stale', 'inputs-changed', ('raw_sha256',))
    assert moved.assessment == assessment
    # the same function pair after an orientation swap is a different question, never the same result
    swapped = store.load(enrichment, {**known, 'older_sha256': f['newer'], 'newer_sha256': f['older']})
    assert swapped.state == 'stale' and swapped.changed == ('older_sha256', 'newer_sha256')


def test_a_result_stored_while_the_project_moved_is_stale_for_reference(service, enrichment):
    assessment, config = make(service)
    moved = Guard(service.project.id, service.project.runs[-1].id, sha('a newer raw output'), assessment.result_id)
    published = store.publish(enrichment, assessment, config, current=moved, created_utc=stamp(0))
    assert published.entry.stale
    loaded = store.load(enrichment)
    assert (loaded.state, loaded.reason) == ('stale', 'guard-moved') and loaded.assessment == assessment


def test_swapped_orientation_gives_another_result_and_a_stale_old_one(service, enrichment):
    forward, _ = make(service)
    reverse, _ = make(service, swapped=True)
    assert forward.result_id != reverse.result_id and forward.leads[0].candidate_key != reverse.leads[0].candidate_key
    put(service, enrichment)
    f = facts_of(service)
    now = {'older_sha256': f['newer'], 'newer_sha256': f['older']}
    assert store.load(enrichment, now).changed == ('older_sha256', 'newer_sha256')


def test_the_documented_layout_and_the_pointer_row(service, enrichment):
    published = put(service, enrichment)
    result = published.manifest.result_id
    assert result == published.pointer.result_id and published.entry.id == f'pilot-result:{result}'
    assert published.entry.kind == 'patch-intent' and 'patch-intent' in KINDS and 'patch-intent' not in DERIVED_KINDS
    assert published.pointer.contract == 'pilot-ptr/1' and published.pointer.relative_dir == (
        f'intelligence/pilot/{result[:16]}')
    directory = service.root / published.pointer.relative_dir
    assert directory == published.directory and sorted(p.name for p in directory.iterdir()) == [
        'assessment.json.gz', 'manifest.json']
    for name in ('manifest.json', 'assessment.json.gz'):
        assert len(f'{published.pointer.relative_dir}/{name}') <= 120  # plan: sidecar paths of 120 characters or fewer
    raw = (directory / 'assessment.json.gz').read_bytes()
    assert raw[:2] == b'\x1f\x8b' and raw[4:8] == b'\x00\x00\x00\x00'  # gzip with mtime 0
    plain = gzip.decompress(raw)
    part = published.manifest.parts[0]
    assert (part.name, part.bytes, part.sha256) == ('assessment.json.gz', len(plain), hashlib.sha256(plain).hexdigest())
    assert plain == keys.canonical_bytes(store.read_sidecar(directory)[1])
    body = json.loads(service.store.connection.execute(
        'SELECT body FROM enrichment_entries WHERE id=?', (published.entry.id,)).fetchone()[0])
    assert body == published.pointer.model_dump(mode='json') and len(json.dumps(body)) <= limits.DEFAULT_LIMITS.p06_pointer_bytes
    assert (published.entry.guard.project_id, published.entry.guard.run_id, published.entry.guard.raw_sha256,
            published.entry.guard.input_digest) == (service.project.id, facts_of(service)['run'],
                                                    facts_of(service)['raw'], result)


def test_the_sidecar_is_byte_deterministic(service, tmp_path):
    assessment, config = make(service)
    first = store.stage(service.root, assessment, config, created_utc=stamp(0))
    second = store.stage(service.root, assessment, config, created_utc=stamp(0))
    for name in ('manifest.json', 'assessment.json.gz'):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert first != second and first.parent == second.parent == service.root / 'intelligence' / 'pilot'


def test_staging_needs_no_database_and_runs_on_a_worker_thread(service):
    assessment, config = make(service)
    found = {}

    def work():
        found['dir'] = store.stage(service.root, assessment, config, created_utc=stamp(0))  # no connection is passed
    worker = threading.Thread(target=work)
    worker.start()
    worker.join()
    manifest, read = store.read_sidecar(found['dir'])
    assert read == assessment and manifest.result_id == assessment.result_id


def test_nothing_in_a_stored_result_is_a_float_or_a_path(service, enrichment):
    published = put(service, enrichment)
    body = json.dumps(store.load(enrichment).assessment.model_dump(mode='json'))
    assert str(service.root) not in body
    for text in (body, (published.directory / 'manifest.json').read_text(encoding='utf-8')):
        assert not any(isinstance(v, float) for v in _walk(json.loads(text)))


def _walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


# --- a damaged sidecar is a cache miss ---------------------------------------------------------------------------------

def damage_manifest(directory: Path) -> None:
    (directory / 'manifest.json').write_bytes(b'{"contract": "pilot-manifest/1"')


def edit_manifest(directory: Path) -> None:
    doc = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    doc['status'] = 'abstained'
    (directory / 'manifest.json').write_text(json.dumps(doc), encoding='utf-8')


def truncate_part(directory: Path) -> None:
    data = (directory / 'assessment.json.gz').read_bytes()
    (directory / 'assessment.json.gz').write_bytes(data[:len(data) // 2])


def swap_part(directory: Path) -> None:
    plain = gzip.decompress((directory / 'assessment.json.gz').read_bytes()).replace(b'read_item', b'read_itex')
    (directory / 'assessment.json.gz').write_bytes(gzip.compress(plain, mtime=0))


def delete_part(directory: Path) -> None:
    (directory / 'assessment.json.gz').unlink()


def grow_part(directory: Path) -> None:  # a decompression bomb: far more output than the manifest declares
    (directory / 'assessment.json.gz').write_bytes(gzip.compress(b'0' * (8 * 1024 * 1024), mtime=0))


DAMAGE = {'manifest-cut': damage_manifest, 'manifest-edited': edit_manifest, 'part-truncated': truncate_part,
          'part-swapped': swap_part, 'part-missing': delete_part, 'part-bomb': grow_part}


@pytest.mark.parametrize('how', DAMAGE, ids=list(DAMAGE))
def test_a_damaged_sidecar_is_a_miss_that_never_hides_an_intact_older_result(service, enrichment, how):
    older = put(service, enrichment, seed=1, created=1)
    newest = put(service, enrichment, seed=2, created=2)
    DAMAGE[how](newest.directory)
    loaded = store.load(enrichment)
    assert loaded.state == 'current' and loaded.assessment.result_id == older.manifest.result_id
    DAMAGE[how](older.directory)
    nothing = store.load(enrichment)
    assert nothing.state == 'invalid' and nothing.assessment is None and nothing.reason


def test_a_pointer_that_disagrees_with_its_manifest_is_a_miss(service, enrichment):
    published = put(service, enrichment)
    db = service.store.connection
    body = dict(published.pointer.model_dump(mode='json'), manifest_sha256=sha('another manifest'))
    text = json.dumps(body, sort_keys=True, separators=(',', ':'))
    with db:
        db.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
                   (text, hashlib.sha256(text.encode()).hexdigest(), published.entry.id))
    assert store.load(enrichment).state == 'invalid'


def test_a_symlinked_sidecar_directory_is_never_followed(service, enrichment, tmp_path):
    published = put(service, enrichment)
    elsewhere = tmp_path / 'elsewhere'
    shutil.move(published.directory, elsewhere)
    try:
        published.directory.symlink_to(elsewhere, target_is_directory=True)
    except OSError:
        pytest.skip('symbolic links are not available here')
    assert store.load(enrichment).state == 'invalid'


def test_a_corrupt_or_foreign_pointer_row_is_skipped_not_fatal(service, enrichment):
    good = put(service, enrichment)
    junk = Guard(service.project.id, 'run', sha('raw'), sha('junk'))
    enrichment.publish(store.KIND, junk, junk, 1, 'complete', {'contract': 'pilot-ptr/9', 'x': 1},
                       keys.pointer_entry_id(sha('junk')))
    loaded = store.load(enrichment)
    assert loaded.state == 'current' and loaded.assessment.result_id == good.manifest.result_id
    assert loaded.skipped == (keys.pointer_entry_id(sha('junk')),)


def test_nothing_stored_is_none(service, enrichment):
    assert (store.load(enrichment).state, store.load(enrichment).reason) == ('none', 'no-result')


def test_the_newest_current_result_wins_over_a_newer_stale_one(service, enrichment):
    current = put(service, enrichment, seed=1, created=1)
    f = facts_of(service)
    other, config = make(service, seed=2)
    moved = Guard(service.project.id, f['run'], sha('moved'), other.result_id)
    store.publish(enrichment, other, config, current=moved, created_utc=stamp(2))
    assert store.load(enrichment).assessment.result_id == current.manifest.result_id
    assert len(pointer_ids(service)) == 2


# --- ownership --------------------------------------------------------------------------------------------------------

REFUSED = {'foreign-project': dict(project_id='another-project'), 'unknown-run': dict(ghidriff_run_id='no-such-run'),
           'wrong-raw': dict(raw_sha256=sha('wrong raw')), 'foreign-artifact': dict(older_sha256=sha('a stranger'))}


@pytest.mark.parametrize('how', REFUSED, ids=list(REFUSED))
def test_a_result_the_project_does_not_own_is_refused_before_anything_is_written(service, enrichment, how):
    assessment, config = make(service, **REFUSED[how])  # valid and self-consistent, but about another project or run
    keys.verify_assessment(assessment)
    current = store.current_guard(service.project, assessment.result_id)
    with pytest.raises(limits.PilotError) as raised:
        store.publish(enrichment, assessment, config, current=current)
    assert raised.value.code == 'PT-PILOT-MISMATCH'
    assert pointer_ids(service) == [] and sidecars(service) == []


def test_a_result_whose_id_does_not_follow_from_its_inputs_is_refused(service, enrichment):
    assessment, config = make(service)
    forged = assessment.model_copy(update={'result_id': sha('forged')})
    with pytest.raises(limits.PilotError) as raised:
        store.publish(enrichment, forged, config, current=store.current_guard(service.project, forged.result_id))
    assert raised.value.code == 'PT-PILOT-INTEGRITY' and pointer_ids(service) == [] and sidecars(service) == []


def test_either_orientation_of_the_projects_pair_is_owned(service, enrichment):
    assessment, config = make(service, swapped=True)
    current = store.current_guard(service.project, assessment.result_id)
    assert store.publish(enrichment, assessment, config, current=current).entry.kind == 'patch-intent'


def test_a_read_only_enrichment_store_is_never_written(service, enrichment):
    enrichment.ensure()
    enrichment.read_only = True  # written by a newer PatchTrace
    assessment, config = make(service)
    with pytest.raises(limits.PilotError) as raised:
        store.publish(enrichment, assessment, config, current=store.current_guard(service.project, assessment.result_id))
    assert raised.value.code == 'PT-PILOT-STALE' and sidecars(service) == []


# --- idempotence ------------------------------------------------------------------------------------------------------

def test_publishing_the_same_result_again_changes_nothing(service, enrichment):
    first = put(service, enrichment)
    before = (rows(service), (first.directory / 'manifest.json').read_bytes())
    again = put(service, enrichment, created=7)  # only the clock of the manifest differs
    assert again.manifest == first.manifest and again.directory == first.directory
    assert (first.directory / 'manifest.json').read_bytes() == before[1]
    assert sorted(rows(service)) == sorted(before[0]) and sidecars(service) == [first.directory.name]


def test_other_content_under_the_same_result_id_replaces_the_older_derived_copy(service, enrichment):
    first = put(service, enrichment)
    assessment, config = make(service)
    changed = assessment.model_copy(update={'limitations': ('A note added after the fact.',), 'status': 'partial'})
    published = store.publish(enrichment, changed, config,
                              current=store.current_guard(service.project, changed.result_id), created_utc=stamp(3))
    assert published.directory == first.directory and published.manifest.status == 'partial'
    loaded = store.load(enrichment)
    assert loaded.assessment.limitations == ('A note added after the fact.',) and len(pointer_ids(service)) == 1
    assert sidecars(service) == [first.directory.name]  # the replaced copy leaves no leftover


def test_a_failed_pointer_row_leaves_the_previous_row_current(service, enrichment, monkeypatch):
    kept = put(service, enrichment, seed=1, created=1)
    assessment, config = make(service, 2)

    def refuse(*_a, **_k):
        raise EnrichmentError('PT-ENRICH-LIMIT', 'full')
    monkeypatch.setattr(EnrichmentStore, 'publish', refuse)
    with pytest.raises(limits.PilotError) as raised:
        store.publish(enrichment, assessment, config, current=store.current_guard(service.project, assessment.result_id))
    assert raised.value.code == 'PT-PILOT-STORAGE'
    monkeypatch.undo()
    assert store.load(enrichment).assessment.result_id == kept.manifest.result_id
    assert sidecars(service) == [kept.directory.name]  # the directory that had no row is not left behind


def test_replace_retries_a_locked_file_a_bounded_number_of_times(service, monkeypatch):
    real, calls = os.replace, []

    def flaky(source, target):
        calls.append(source)
        if len(calls) <= 3:
            raise PermissionError(13, 'locked by an indexer')
        return real(source, target)
    monkeypatch.setattr(os, 'replace', flaky)
    monkeypatch.setattr(time, 'sleep', lambda _s: None)
    assessment, config = make(service)
    store.stage(service.root, assessment, config, created_utc=stamp(0))
    assert len(calls) >= 4
    calls.clear()
    monkeypatch.setattr(os, 'replace', lambda *_a: (_ for _ in ()).throw(PermissionError(13, 'locked')))
    with pytest.raises(limits.PilotError) as raised:
        store.stage(service.root, assessment, config, created_utc=stamp(1))
    assert raised.value.code == 'PT-PILOT-STORAGE'


def test_a_result_over_the_sidecar_limit_is_refused_and_leaves_no_staging_directory(service):
    assessment, config = make(service)
    small = dataclasses.replace(limits.DEFAULT_LIMITS, p06_sidecar_bytes=1024, p06_pointer_bytes=512)
    with pytest.raises(limits.PilotError) as raised:
        store.stage(service.root, assessment, config, created_utc=stamp(0), limits=small)
    assert raised.value.code == 'PT-PILOT-LIMIT' and sidecars(service) == []


# --- retention ------------------------------------------------------------------------------------------------------

def backups(service) -> list[Path]:
    return sorted((service.root / 'backups').glob('project-pre-pilot-retention-*.sqlite3'))


def ids_in(path: Path, ids: list[str]) -> int:
    db = sqlite3.connect(f'{path.resolve().as_uri()}?mode=ro', uri=True)
    try:
        marks = ','.join('?' * len(ids))
        return db.execute(f'SELECT COUNT(*) FROM enrichment_entries WHERE id IN ({marks})', ids).fetchone()[0]
    finally:
        db.close()


def test_retention_keeps_three_and_reviews(service, enrichment):
    for index in range(3):
        review.append(enrichment, project_id=service.project.id, revision=1, candidate_key=sha('k', index),
                      cve=None, action='pin' if index != 1 else 'note', text='' if index != 1 else 'looked at it')
    foreign = Guard(service.project.id, 'run', sha('raw'), sha('other'))
    enrichment.publish('cve-snapshot', foreign, foreign, 1, 'complete', {'cve': 'CVE-2099-1'}, 'cve-snapshot:keep')
    before = {kind: rows(service, kind) for kind in ('cve-snapshot',)}
    reviews_before = {i: v for i, v in rows(service).items() if i.startswith(keys.REVIEW_PREFIX)}
    assert len(reviews_before) == 3
    published = [put(service, enrichment, seed=i, created=i) for i in range(5)]  # one family, oldest first
    other = put(service, enrichment, seed=9, created=9, config=keys.default_config(lexical_moderate=False))
    kept = sorted(keys.pointer_entry_id(p.manifest.result_id) for p in published[2:]) + [other.entry.id]
    assert pointer_ids(service) == sorted(kept)  # three newest of the family, the other family untouched
    for gone in published[:2]:
        assert not gone.directory.exists()
    for stays in (*published[2:], other):
        assert stays.directory.is_dir() and store.read_sidecar(stays.directory)
    assert {i: v for i, v in rows(service).items() if i.startswith(keys.REVIEW_PREFIX)} == reviews_before
    assert {kind: rows(service, kind) for kind in before} == before  # other features' rows are never touched
    assert sum(p.deleted for p in published) == 2
    (backup,) = backups(service)  # one verified backup serves every deletion, and it holds the rows that went
    assert ids_in(backup, [keys.pointer_entry_id(p.manifest.result_id) for p in published[:2]]) == 2
    assert verified_backup.find_verified_backup(service.root, store.BACKUP_LABEL, project_id=service.project.id)


def test_the_newest_is_the_newest_by_creation_not_by_name(service, enrichment):
    results = [put(service, enrichment, seed=i, created=i) for i in (4, 1, 3, 0, 2)]  # published out of seed order
    assert len(pointer_ids(service)) == 3
    survivors = {p.manifest.result_id for p in results if p.directory.exists()}
    assert survivors == {p.manifest.result_id for p in results[-3:]}


def test_each_pair_and_each_advisory_set_has_its_own_three(service, enrichment):
    for family in range(3):
        for seed in range(4):
            put(service, enrichment, seed=family * 10 + seed, facts_id=sha('doc', family))
    assert len(pointer_ids(service)) == 9  # three advisory sets, three results each
    swapped = [put(service, enrichment, seed=40 + seed, facts_id=sha('doc', 0), swapped=True) for seed in range(4)]
    assert len(pointer_ids(service)) == 12 and sum(p.deleted for p in swapped) == 1  # the other orientation: its own three
    assert len({r for r in pointer_ids(service)}) == 12 and all(p.directory.exists() for p in swapped[1:])


def test_retention_does_not_reuse_a_backup_that_lacks_the_rows_it_deletes(service, enrichment, monkeypatch):
    enrichment.ensure()
    early = verified_backup.write_verified_backup(service.root, service.store.connection, store.BACKUP_LABEL)
    monkeypatch.setattr(store, 'apply_retention', lambda *_a, **_k: 0)  # publish only, evict afterwards
    results = [put(service, enrichment, seed=i, created=i) for i in range(5)]
    monkeypatch.undo()
    doomed = [keys.pointer_entry_id(p.manifest.result_id) for p in results[:2]]
    assert ids_in(early, doomed) == 0  # a verified copy of this project, but older than the rows
    assert store.apply_retention(enrichment) == 2
    assert len(backups(service)) == 2 and ids_in(backups(service)[-1], doomed) == 2
    assert store.apply_retention(enrichment) == 0 and len(backups(service)) == 2


def test_without_a_verified_backup_nothing_is_deleted_and_the_publish_still_succeeds(service, enrichment, monkeypatch):
    enrichment.ensure()  # the tables (and their own backup) exist; only the retention backup is unavailable

    def broken(*_a, **_k):
        raise verified_backup.BackupError('PT-STORAGE: no backup')
    monkeypatch.setattr(verified_backup, 'write_verified_backup', broken)
    monkeypatch.setattr(verified_backup, 'find_verified_backup', lambda *_a, **_k: None)
    results = [put(service, enrichment, seed=i, created=i) for i in range(5)]
    assert len(pointer_ids(service)) == 5 and all(p.directory.is_dir() for p in results)  # no backup, no deletion
    with pytest.raises(limits.PilotError) as raised:
        store.apply_retention(enrichment)
    assert raised.value.code == 'PT-PILOT-STORAGE'


def test_retention_never_deletes_rows_it_cannot_read_or_that_are_not_results(service, enrichment):
    junk = Guard(service.project.id, 'run', sha('raw'), sha('junk'))
    for index, body in enumerate(({'contract': 'pilot-ptr/9'}, {'unrelated': True})):
        enrichment.publish(store.KIND, junk, junk, 1, 'complete', body, keys.pointer_entry_id(sha('junk', index)))
    review.append(enrichment, project_id=service.project.id, revision=1, candidate_key=sha('k'), cve=None, action='pin')
    for i in range(5):
        put(service, enrichment, seed=i, created=i)
    names = pointer_ids(service)
    assert keys.pointer_entry_id(sha('junk', 0)) in names and keys.pointer_entry_id(sha('junk', 1)) in names
    assert len(names) == 5 and len([i for i in rows(service) if i.startswith(keys.REVIEW_PREFIX)]) == 1


def test_only_pilot_result_rows_can_be_deleted_by_this_module(service, enrichment):
    """The delete is bound to the kind AND the id prefix: a review row or another kind is out of reach."""
    review.append(enrichment, project_id=service.project.id, revision=1, candidate_key=sha('k'), cve=None, action='pin')
    foreign = Guard(service.project.id, 'run', sha('raw'), sha('other'))
    enrichment.publish('cve-snapshot', foreign, foreign, 1, 'complete', {'cve': 'x'}, 'cve-snapshot:x')
    impostor = keys.pointer_entry_id(sha('impostor'))  # the id of a result, but a row of another feature
    enrichment.publish('cve-snapshot', foreign, foreign, 1, 'complete', {'cve': 'y'}, impostor)
    ids = sorted(r[0] for r in service.store.connection.execute('SELECT id FROM enrichment_entries'))
    assert impostor in ids and store.delete_results(enrichment, ids) == 0
    assert sorted(r[0] for r in service.store.connection.execute('SELECT id FROM enrichment_entries')) == ids


def test_retention_runs_inside_publish_and_its_failure_never_fails_a_publish(service, enrichment, monkeypatch):
    def boom(*_a, **_k):
        raise sqlite3.OperationalError('disk I/O error')
    monkeypatch.setattr(store, 'apply_retention', boom)
    published = put(service, enrichment)
    assert published.deleted == 0 and store.load(enrichment).state == 'current'


def test_orphan_directories_are_swept_but_never_a_fresh_one_or_one_a_bad_row_names(service, enrichment):
    published = put(service, enrichment)
    parent = published.directory.parent
    old_orphan, fresh_orphan = parent / ('a' * 16), parent / ('b' * 16)
    junk_named = parent / sha('junk')[:16]
    staging_old, staging_fresh = parent / ('tmp-' + 'c' * 16), parent / ('tmp-' + 'd' * 16)
    for directory in (old_orphan, fresh_orphan, junk_named, staging_old, staging_fresh):
        directory.mkdir()
        (directory / 'assessment.json.gz').write_bytes(b'x')
    long_ago = time.time() - 3 * 3600
    for directory in (old_orphan, junk_named, staging_old):
        os.utime(directory, (long_ago, long_ago))
    junk = Guard(service.project.id, 'run', sha('raw'), sha('junk'))
    enrichment.publish(store.KIND, junk, junk, 1, 'complete', {'contract': 'pilot-ptr/9'}, keys.pointer_entry_id(sha('junk')))
    assert store.sweep_orphans(enrichment) == 2
    assert sorted(p.name for p in parent.iterdir()) == sorted([published.directory.name, fresh_orphan.name,
                                                               junk_named.name, staging_fresh.name])


def test_a_stray_file_beside_the_results_is_left_alone(service, enrichment):
    published = put(service, enrichment)
    note = published.directory.parent / 'README.txt'
    note.write_text('not ours', encoding='utf-8')
    os.utime(note, (1, 1))
    assert store.sweep_orphans(enrichment) == 0 and note.exists()


# --- the store is Qt free ------------------------------------------------------------------------------------------

def test_the_store_and_review_modules_import_no_qt_and_no_other_feature_internals():
    import ast
    root = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'pilot'
    for name in ('store', 'review'):
        tree = ast.parse((root / f'{name}.py').read_text(encoding='utf-8'))
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
            a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not [m for m in imported if m.split('.')[0] in ('PySide6', 'shiboken6')], name
        assert not [m for m in imported if m.endswith('unified.store')], name  # amendment 6: no unified internals


# --- review events: separate, append-only rows ---------------------------------------------------------------------------

def reviews_of(service) -> dict[str, tuple]:
    return {i: v for i, v in rows(service).items() if i.startswith(keys.REVIEW_PREFIX)}


def append(service, enrichment, action, *, key=None, cve=None, text='', clock=None):
    return review.append(enrichment, project_id=service.project.id, revision=service.project.revision,
                         candidate_key=key or sha('lead'), cve=cve, action=action, text=text, clock=clock)


def test_review_events_append_only(service, enrichment):
    frozen = datetime(2099, 2, 1, 12, 0, 0, tzinfo=UTC)
    first = append(service, enrichment, 'pin', clock=lambda: frozen)
    seen = reviews_of(service)
    assert len(seen) == 1 and next(iter(seen)).startswith('pilot-review:')
    events = [first]
    for action, text in (('note', 'checked the copy'), ('dismiss', 'compiler churn'), ('restore', ''), ('unpin', '')):
        events.append(append(service, enrichment, action, text=text, clock=lambda: frozen))  # the clock never moves
        for row_id, value in seen.items():
            assert reviews_of(service)[row_id] == value  # an earlier row is never rewritten
        seen = reviews_of(service)
    assert len(seen) == 5 and len({e.created_utc for e in events}) == 5  # a stalled clock still orders the events
    assert [e.created_utc for e in events] == sorted(e.created_utc for e in events)
    read = review.read(enrichment)
    assert read.events == tuple(events) and read.skipped == ()
    assert all(e.contract == 'pilot-review/1' for e in read.events)


def test_an_event_id_is_never_reused(service, enrichment, monkeypatch):
    append(service, enrichment, 'pin')
    ((row_id, before),) = reviews_of(service).items()
    monkeypatch.setattr(review, '_new_id', lambda: row_id.removeprefix(keys.REVIEW_PREFIX))
    with pytest.raises(limits.PilotError) as raised:
        append(service, enrichment, 'unpin')
    assert raised.value.code == 'PT-PILOT-INTEGRITY' and reviews_of(service) == {row_id: before}


def test_the_module_offers_no_way_to_change_or_delete_an_event():
    public = {name for name in dir(review) if not name.startswith('_')}
    assert not {name for name in public if any(w in name.lower() for w in ('delete', 'remove', 'update', 'edit'))}


def test_the_clock_of_a_second_writer_that_ran_behind_cannot_reorder_events(service, enrichment):
    late = append(service, enrichment, 'pin', clock=lambda: datetime(2099, 3, 1, tzinfo=UTC))
    early = append(service, enrichment, 'unpin', clock=lambda: datetime(2098, 1, 1, tzinfo=UTC))
    assert early.created_utc > late.created_utc and review.read(enrichment).events == (late, early)
    state = review.fold(review.read(enrichment).events)
    assert state[(sha('lead'), None)].pinned is False  # the unpin came last


def test_events_are_validated_like_the_contract(service, enrichment):
    with pytest.raises(limits.PilotError) as raised:
        append(service, enrichment, 'note', text='   ')
    assert raised.value.code == 'PT-PILOT-INPUT'
    for bad in (dict(action='shred'), dict(key='not-a-key'), dict(cve='cve-1'), dict(text='x' * 2049),
                dict(text='bell\x07'), dict(text=chr(0x202e) + 'evil')):
        action = bad.pop('action', 'note')
        with pytest.raises(limits.PilotError) as raised:
            append(service, enrichment, action, **({'text': 'ok'} | bad))
        assert raised.value.code == 'PT-PILOT-INPUT', bad
    append(service, enrichment, 'note', text='x' * 2048)  # exactly the limit
    assert reviews_of(service) and len(review.read(enrichment).events) == 1


def test_an_event_of_another_project_is_refused(service, enrichment):
    enrichment.ensure()
    with pytest.raises(limits.PilotError) as raised:
        review.append(enrichment, project_id='someone-elses', revision=1, candidate_key=sha('k'), cve=None, action='pin')
    assert raised.value.code == 'PT-PILOT-MISMATCH' and reviews_of(service) == {}


def test_a_row_this_version_cannot_read_is_skipped_and_named(service, enrichment):
    append(service, enrichment, 'pin')
    junk = Guard(service.project.id, review.GUARD_RUN, sha('k'), sha('v2'))
    enrichment.publish(store.KIND, junk, junk, 1, 'complete', {'contract': 'pilot-review/2', 'candidate_key': sha('k')},
                       'pilot-review:11111111-1111-4111-8111-111111111111')
    read = review.read(enrichment)
    assert len(read.events) == 1 and read.skipped == ('pilot-review:11111111-1111-4111-8111-111111111111',)


def test_results_and_events_never_read_each_others_rows(service, enrichment):
    put(service, enrichment)
    append(service, enrichment, 'pin')
    assert len(review.read(enrichment).events) == 1 and store.load(enrichment).state == 'current'
    assert len(pointer_ids(service)) == 1 and len(reviews_of(service)) == 1


def test_fold_pins_dismissals_and_statements_per_lead_and_context(service, enrichment):
    a, b = sha('a'), sha('b')
    frozen = lambda: datetime(2099, 2, 1, tzinfo=UTC)  # noqa: E731
    for key, cve, action, text in ((a, None, 'pin', ''), (a, None, 'note', 'first look'), (a, 'CVE-2099-1000', 'dismiss', 'noise'),
                                   (b, None, 'dismiss', ''), (b, None, 'restore', ''), (a, None, 'unpin', ''),
                                   (a, None, 'pin', ''), (a, None, 'note', 'second look')):
        append(service, enrichment, action, key=key, cve=cve, text=text, clock=frozen)
    state = review.fold(review.read(enrichment).events)
    assert state[(a, None)].pinned and not state[(a, None)].dismissed
    assert [e.text for e in state[(a, None)].statements] == ['first look', 'second look']
    assert state[(a, 'CVE-2099-1000')].dismissed and not state[(a, 'CVE-2099-1000')].pinned  # another context
    assert [e.text for e in state[(a, 'CVE-2099-1000')].statements] == ['noise']
    assert not state[(b, None)].dismissed and not state[(b, None)].pinned and state[(b, None)].statements == ()
    assert (sha('absent'), None) not in state


def test_pinned_leads_sort_first_without_changing_anything_else(service, enrichment):
    assessment, _ = make(service)
    lead = assessment.leads[0]
    other = lead.model_copy(update={'candidate_key': sha('second'), 'rank': 2, 'tie': c.Tie(size=1, first=2, last=2)})
    key = (other.candidate_key, other.cve)
    state = {key: review.LeadReview(pinned=True)}
    ordered = review.pinned_first([lead, other], state)
    assert ordered == [other, lead] and ordered[0].lead_class == other.lead_class and ordered[0].rank == 2
    assert review.pinned_first([lead, other], {}) == [lead, other]
