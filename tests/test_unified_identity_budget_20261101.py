"""Complete evidence identities retain cooperative cancellation and reuse verified store bytes."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
from types import SimpleNamespace

import pytest
from unified_s0_fixtures import addr_map, bd, bindiff_set, inputs, loaded, make_project

from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.secondary import load_secondary
from patchtrace.secondary.contracts import SecondaryMatchSet
from patchtrace.secondary.store import publish_engine_set
from patchtrace.unified import keys, pipeline
from patchtrace.unified.compute import plan_identity
from patchtrace.unified.limits import Budget, BudgetExhausted
from patchtrace.unified.sources import LoadedSecondary
from patchtrace.unified.sources import secondary as secondary_source
from patchtrace.unified.sources.secondary import SecondaryAdapter, bindiff_flags, source_ref_of


def test_already_cancelled_secondary_preparation_performs_no_content_hash(monkeypatch):
    value = inputs(secondary=[loaded(bindiff_set([bd(0x1000 + i, 0x1100 + i) for i in range(8)]))])
    cancel = threading.Event()
    cancel.set()
    calls = []
    original = keys.source_content_digest

    def hashing(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(keys, 'source_content_digest', hashing)
    with pytest.raises(BudgetExhausted) as rejected:
        SecondaryAdapter().atoms(value, addr_map(), Budget(cancel=cancel, check_every=1))
    assert rejected.value.code == 'PT-UNIFIED-CANCEL'
    assert calls == []


def test_immutable_loaded_set_content_is_serialized_once_across_source_and_facts_reads(monkeypatch):
    source = loaded(bindiff_set([bd(0x1000, 0x1080)]))
    calls = []
    original = SecondaryMatchSet.model_dump

    def dumping(self, *args, **kwargs):
        calls.append(id(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(SecondaryMatchSet, 'model_dump', dumping)
    a, b = source_ref_of(source), source_ref_of(source)
    SecondaryAdapter().atoms(inputs(secondary=[source]), addr_map(), Budget())
    bindiff_flags(inputs(secondary=[source]), addr_map())
    assert a == b and calls == [id(source.match_set)]


def test_owner_repeated_planning_uses_existing_verified_body_checksum_without_serializing_sets(tmp_path, monkeypatch):
    project = make_project(tmp_path / 'project')
    try:
        sides = {value.side: value.sha256 for value in project.project.artifacts}
        normalized = bindiff_set([bd(0x1000, 0x1080)], older=sides['older'], newer=sides['newer'])
        run = project.project.runs[-1]
        guard = Guard(project.project.id, run.id, run.raw_sha256, normalized.file_sha256)
        publish_engine_set(EnrichmentStore(project.store), guard, guard, project.project.revision, normalized)
        calls = []
        original = SecondaryMatchSet.model_dump

        def dumping(self, *args, **kwargs):
            calls.append(id(self))
            return original(self, *args, **kwargs)

        monkeypatch.setattr(SecondaryMatchSet, 'model_dump', dumping)
        first, second = pipeline.make_plan(project), pipeline.make_plan(project)
        assert first.result_id == second.result_id
        assert calls == []
    finally:
        project.close()


def test_cancel_during_record_ordering_publishes_no_partial_identity_cache(monkeypatch):
    source = loaded(bindiff_set([bd(0x1000 + i, 0x1100 + i) for i in range(8)]))
    cancel, calls = threading.Event(), []
    original = secondary_source._record_key

    def ordering(record):
        calls.append(record)
        if len(calls) == 3:
            cancel.set()
        return original(record)

    monkeypatch.setattr(secondary_source, '_record_key', ordering)
    with pytest.raises(BudgetExhausted):
        source_ref_of(source, Budget(cancel=cancel, check_every=1))
    assert len(calls) == 3 and source._ordered is None and source._source_ref is None


def test_chunked_source_hash_checks_deadline_while_encoding_large_text():
    ticks = []

    def clock():
        ticks.append(len(ticks) + 1)
        return ticks[-1]

    with pytest.raises(BudgetExhausted) as rejected:
        keys.source_content_digest('manual', {'code': 'x' * 1_000_000}, budget=Budget(deadline=5, clock=clock))
    assert rejected.value.code == 'PT-UNIFIED-TIMEOUT' and len(ticks) == 5


def test_verified_immutable_body_is_authoritative_and_replacement_drops_its_cache(tmp_path):
    project = make_project(tmp_path / 'project')
    try:
        sides = {value.side: value.sha256 for value in project.project.artifacts}
        normalized = bindiff_set([bd(0x1000, 0x1080)], older=sides['older'], newer=sides['newer'])
        run = project.project.runs[-1]
        guard = Guard(project.project.id, run.id, run.raw_sha256, normalized.file_sha256)
        storage = EnrichmentStore(project.store)
        publish_engine_set(storage, guard, guard, project.project.revision, normalized)
        [entry] = storage.entries('secondary-matches')
        assert hashlib.sha256(entry.body_json.encode()).hexdigest() == entry.body_sha256
        entry.body['matches'][0]['older_name'] = 'mutated mutable dictionary'
        [(_, validated)] = load_secondary(SimpleNamespace(entries=lambda *args, **kwargs: [entry]))
        assert validated.matches[0].older_name is None
        [bound] = pipeline.make_plan(project).secondary
        first = source_ref_of(bound)
        replacement = dataclasses.replace(bound, match_set=normalized.model_copy(update={'limitations': ('changed',)}))
        assert replacement._body_json is None and replacement._body_sha256 is None
        assert source_ref_of(replacement) != first
        path = tmp_path / 'worker-source.json'
        digest, size = secondary_source.write_loaded(path, bound)
        reloaded = secondary_source.read_loaded(path, expected_sha256=digest, expected_size=size, budget=Budget())
        assert source_ref_of(reloaded) == first
        # The worker transports body bytes, not an unchecked trusted checksum.
        payload = json.loads(path.read_text())
        body = json.loads(payload['body_json'])
        body['matches'][0]['older_name'] = 'new normalized content'
        payload['body_json'] = json.dumps(body)
        raw = json.dumps(payload).encode()
        path.write_bytes(raw)
        changed = secondary_source.read_loaded(path, expected_sha256=hashlib.sha256(raw).hexdigest(),
                                               expected_size=len(raw), budget=Budget())
        assert source_ref_of(changed) != first and changed.match_set.matches[0].older_name == 'new normalized content'
        # The existing KB panel capture/reconstruction shape accepts and retains the new immutable metadata.
        from patchtrace.enrichment.storage import Entry
        captured = json.loads(json.dumps(dataclasses.asdict(entry)))
        captured['guard'] = Guard(**captured['guard'])
        restored = Entry(**captured)
        assert restored.body_json == entry.body_json and restored.body_sha256 == entry.body_sha256
    finally:
        project.close()


def test_stored_and_worker_source_ids_bind_nfc_distinct_original_entry_references(tmp_path):
    value = bindiff_set([bd(0x1000, 0x1080)])
    body = json.dumps(value.model_dump(mode='json'), ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    body_sha = hashlib.sha256(body.encode()).hexdigest()
    originals = ('caf\u00e9', 'cafe\u0301')
    references, identities, emitted = [], [], []
    for number, entry_id in enumerate(originals):
        source = LoadedSecondary.from_verified_body(entry_id, value, body, body_sha)
        data = inputs(secondary=[source])
        references.append(source_ref_of(source))
        identities.append(plan_identity(data, addr_map(), ['bindiff']))
        emitted.append(SecondaryAdapter().atoms(data, addr_map(), Budget()))
        assert emitted[-1].atoms[0].ref == entry_id
        path = tmp_path / f'source-{number}.json'
        sha, size = secondary_source.write_loaded(path, source)
        worker = secondary_source.read_loaded(path, expected_sha256=sha, expected_size=size, budget=Budget())
        assert worker.entry_id == entry_id and source_ref_of(worker) == references[-1]
        assert plan_identity(inputs(secondary=[worker]), addr_map(), ['bindiff']) == identities[-1]
    assert references[0].file_sha256 == references[1].file_sha256 == value.file_sha256
    assert emitted[0].atoms != emitted[1].atoms
    assert references[0] != references[1]
    assert identities[0].result_id != identities[1].result_id
