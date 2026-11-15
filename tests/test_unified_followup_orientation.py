"""Defect p1 (amendment A-28): the raw Ghidriff `address_matches` table is read in the orientation of its own document
identity, not of the project's current sides. SYNTHETIC ONLY: documents and PE images are made up in code; no engine
or Microsoft binary was run, so nothing here is live evidence."""
from __future__ import annotations

import hashlib
import json

from unified_s0_fixtures import (
    NEW_SHA,
    OLD_SHA,
    RAW_SHA,
    addr_map,
    func,
    inputs,
    make_project,
    match,
    raw_ok,
    va,
)

from patchtrace.unified import pipeline, store
from patchtrace.unified.compute import is_degrading
from patchtrace.unified.limits import Budget
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.sources import DEGRADING, RawGhidriff
from patchtrace.unified.sources.ghidriff import GhidriffAdapter, load_raw

TABLE = {va(0x1000): [[va(0x1080), ['SymbolsHash']]], va(0x1300): [[va(0x1380), ['ExactBytesFunctionHasher']]]}


def pairs(service):
    loaded = pipeline.load_current(service, pipeline.make_plan(service))
    rows = list(store.read_rows(loaded.directory, loaded.manifest))
    two = {(r.older[0].rva, r.newer[0].rva) for r in rows if r.older and r.newer
           and any(a.source == 'ghidriff' for a in r.atoms)}
    one = {(r.older[0].rva if r.older else None, r.newer[0].rva if r.newer else None)
           for r in rows if not (r.older and r.newer)}
    return loaded, two, one


def run(service):
    report = pipeline.run_unified(service, UnifiedOptions(isolate=False))
    assert report.status == 'ok'
    return report


def raw_of(older: str | None, newer: str | None, status='ok') -> RawGhidriff:
    return RawGhidriff(status=status, address_matches=TABLE, sha256=RAW_SHA, older_sha256=older, newer_sha256=newer)


def atoms_of(raw, matches=()):
    return GhidriffAdapter().atoms(inputs(matches=matches, raw=raw), addr_map(), Budget())


def test_p1_a_swapped_project_reads_the_raw_table_in_the_swapped_orientation(tmp_path):
    service = make_project(tmp_path / 'project')
    try:
        run(service)
        first_loaded, first, first_one = pairs(service)
        assert (0x1300, 0x1380) in first            # exists only in address_matches
        service.swap_orientation()
        second_report = run(service)
        loaded, second, second_one = pairs(service)
        assert second == {(n, o) for o, n in first}
        assert (0x1380, 0x1300) in second
        # nothing that is paired in the first result is one-sided in the swapped one
        paired = {x for pair in first for x in pair}
        assert not ({r for r in second_one if r is not None} & paired)
        assert {s for s in second_one if s is not None}.isdisjoint(paired)
        for limitation in (*loaded.manifest.limitations, *second_report.limitations):
            assert not limitation.startswith(('raw-identity-mismatch', 'raw-identity-unverified'))
        assert loaded.manifest.result_id != first_loaded.manifest.result_id
    finally:
        service.close()


def test_p1_the_worker_and_the_owner_thread_agree_on_an_identity_mismatch(tmp_path):
    service = make_project(tmp_path / 'project')
    try:
        plan = pipeline.make_plan(service)
        document = json.loads(plan.raw_path.read_text(encoding='utf-8'))
        document['old_meta'] = {'Executable SHA256': 'd' * 64}
        data = json.dumps(document).encode()
        path = tmp_path / 'other.json'
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        sides = (plan.older_sha256, plan.newer_sha256)
        assert load_raw(path, digest).status == 'ok'                     # no sides given: identity only recorded
        raw = load_raw(path, digest, sides=sides)
        assert raw.status == 'identity-mismatch' and raw.address_matches is None
        assert (raw.older_sha256, raw.newer_sha256) == ('d' * 64, plan.newer_sha256)
    finally:
        service.close()


def test_p1_identity_is_read_like_verify_diff_identity(tmp_path):
    def write(document):
        path = tmp_path / 'raw.json'
        data = json.dumps(document).encode()
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()
    base = {'matches': {'address_matches': TABLE}}
    path, digest = write({**base, 'old_meta': {'SHA256': 'A' * 64}, 'new_meta': {'sha256': 'B' * 64}})
    raw = load_raw(path, digest)
    assert (raw.older_sha256, raw.newer_sha256) == ('a' * 64, 'b' * 64)
    path, digest = write({**base, 'old_meta': {'SHA256': 'a' * 64, 'sha256': 'c' * 64}, 'new_meta': {'sha256': 'b' * 64}})
    raw = load_raw(path, digest, sides=(OLD_SHA, NEW_SHA))              # disagreeing keys: identity absent, not mismatch
    assert (raw.status, raw.older_sha256, raw.newer_sha256) == ('ok', None, 'b' * 64)
    path, digest = write(base)
    assert load_raw(path, digest, sides=(OLD_SHA, NEW_SHA)).status == 'ok'


def test_p1_an_identity_matching_neither_orientation_is_the_fourth_failure_kind():
    assert 'raw-identity-mismatch' in DEGRADING and is_degrading('raw-identity-mismatch')
    snapshot = match('g1', 'modified', older=[func('f', 0x1500)], newer=[func('f', 0x1580)], types=['SymbolsHash'])
    added = match('g2', 'added', newer=[func('new_fn', 0x1800)])
    bad = raw_of('d' * 64, 'e' * 64)
    out = atoms_of(bad, [snapshot, added])
    assert 'raw-identity-mismatch' in out.limitations
    assert {(a.older_rva, a.newer_rva) for a in out.atoms} == {(0x1500, 0x1580), (None, 0x1800)}   # snapshot only
    adapter = GhidriffAdapter()
    ok_ref = adapter.source_ref(inputs(raw=raw_of(OLD_SHA, NEW_SHA)))
    bad_ref = adapter.source_ref(inputs(raw=bad))
    assert bad_ref.version.endswith('[raw-identity-mismatch]') and bad_ref.file_sha256 is None
    assert bad_ref != ok_ref
    # one side only matching is still a mismatch; a status set by the loader gives the same reference
    assert 'raw-identity-mismatch' in atoms_of(raw_of(OLD_SHA, 'e' * 64)).limitations
    assert adapter.source_ref(inputs(raw=RawGhidriff(status='identity-mismatch', sha256=RAW_SHA))) == bad_ref
    availability = adapter.available(inputs(raw=bad))
    assert (availability.state, availability.reason) == ('missing', 'identity-mismatch')


def test_p1_an_unswapped_identity_keeps_the_source_ref_and_the_atoms():
    adapter = GhidriffAdapter()
    forward = inputs(raw=raw_of(OLD_SHA, NEW_SHA))
    today = adapter.source_ref(inputs(raw=raw_ok(TABLE, older_sha256=None, newer_sha256=None)))  # identity-less
    assert adapter.source_ref(forward) == today
    assert (today.entry_id, today.file_sha256, today.version) == ('run-1', RAW_SHA, '1')
    assert adapter.available(forward).state == 'ok'
    out = atoms_of(raw_of(OLD_SHA, NEW_SHA))
    assert {(a.older_rva, a.newer_rva) for a in out.atoms} == {(0x1000, 0x1080), (0x1300, 0x1380)}
    assert not any(x.startswith('raw-identity') for x in out.limitations)
    flipped = atoms_of(raw_of(NEW_SHA, OLD_SHA))
    assert {(a.older_rva, a.newer_rva) for a in flipped.atoms} == {(0x1080, 0x1000), (0x1380, 0x1300)}
    assert not any(x.startswith('raw-identity') for x in flipped.limitations)
    # reading an identity never changes the id of a crosswise table: the sha256 pair in the key differs already
    assert adapter.source_ref(inputs(raw=raw_of(NEW_SHA, OLD_SHA))) == today


def test_p1_a_raw_without_identity_is_read_forward_and_counted():
    out = atoms_of(raw_ok(TABLE, older_sha256=None, newer_sha256=None))
    assert {(a.older_rva, a.newer_rva) for a in out.atoms} == {(0x1000, 0x1080), (0x1300, 0x1380)}
    assert 'raw-identity-unverified:1' in out.limitations
    assert not any(is_degrading(x) for x in out.limitations)
