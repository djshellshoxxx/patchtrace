"""R5: the append-only rule rows (YRX-integration-plan section 7, "Storage, keys, limits"): five reserved kinds that retention
never deletes, one write per row, the accept path that a crash cannot half-finish, and the sidecar of a large test grid. The
candidates are made by the real proposal path from the SYNTHETIC `capa-api` pair.
"""
from __future__ import annotations

import hashlib
import json

import pytest
import rules_fixtures as rf
from rules_store_support import DECIDED, PROJECT_ID, accepted, candidate_of, rule_store

from patchtrace.enrichment.storage import DERIVED_KINDS, KINDS
from patchtrace.rules import matrix, store
from patchtrace.rules.contracts import CellResult, MatrixRun, RunRule, TargetRef
from patchtrace.rules.errors import RuleError


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def candidate(bench):
    return candidate_of(bench)


def rows(rules, kind: str) -> list[dict]:
    columns = 'id, project_id, run_id, raw_sha256, input_digest, status, stale'
    found = rules.enrichment.store.connection.execute(
        f'SELECT {columns} FROM enrichment_entries WHERE kind=? ORDER BY id', (kind,)).fetchall()
    return [dict(zip(columns.split(', '), row, strict=True)) for row in found]


def a_run(version, *, cells=1, finished='2026-10-14T10:00:00+00:00') -> MatrixRun:
    target = TargetRef(target_id='b0001', label='older.dll', role='older-anchor', sha256='1' * 64, size=10, ordinal=1,
                       expect='hit')
    cell = CellResult(state='hit', hits=1, offsets=(5,), rvas=(0x1005,), verdict='as-expected')
    engine = version.engine
    return MatrixRun(run_id=f'test-{finished[11:13]}{cells}', cache_key='2' * 64, engine=engine, status='complete',
                     rules=(RunRule(version_id=version.version_id, rule_sha256=version.rule_sha256),),
                     targets=(target,), cells=(cell,) * cells, limits={'cells': 105000}, finished_at=finished)


def test_the_five_kinds_are_reserved_and_never_derived():
    kinds = {store.CANDIDATE, store.DECISION, store.VERSION, store.TEST, store.EXPORT}
    assert kinds == {'rule-candidate', 'rule-decision', 'rule-version', 'rule-test', 'rule-export'}
    assert kinds <= KINDS and not kinds & set(DERIVED_KINDS)       # retention only ever deletes DERIVED_KINDS


def test_a_candidate_is_stored_once_with_the_guard_of_its_pair(tmp_path, candidate):
    rules = rule_store(tmp_path)
    assert rules.add_candidate(candidate) is True and rules.add_candidate(candidate) is False
    (row,) = rows(rules, store.CANDIDATE)
    assert row['id'] == f'rule-candidate:{candidate.candidate_id}' and (row['project_id'], row['run_id']) == (PROJECT_ID, 'rules')
    assert row['raw_sha256'] == store.pair_key((candidate.source.older_sha256, candidate.source.newer_sha256))
    assert row['status'] == 'ok' and row['stale'] == 0
    assert rules.candidates() == [candidate] and rules.candidate(candidate.candidate_id) == candidate
    assert rules.candidate('f' * 64) is None and rules.skipped == []


def test_a_row_is_never_overwritten(tmp_path, candidate):
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    row_id = f'rule-candidate:{candidate.candidate_id}'
    rules.enrichment.store.connection.execute(          # a different body under the same id, as a damaged copy would be
        'UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?', ('{"contract":"yara-rules/1"}',
                                                                      hashlib.sha256(b'{"contract":"yara-rules/1"}').hexdigest(), row_id))
    with pytest.raises(RuleError) as caught:
        rules.add_candidate(candidate)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INTEGRITY', 'row-differs')
    assert rules.candidates() == [] and rules.skipped == [row_id]       # unreadable as a candidate, reported, not hidden


def test_decisions_are_history_the_last_one_is_in_force(tmp_path, candidate):
    rules = rule_store(tmp_path)
    reject = store.decision_for(candidate, 'reject', '2026-10-14T09:00:00+00:00')
    defer = store.decision_for(candidate, 'defer', '2026-10-14T09:05:00+00:00')
    for decision in (defer, reject):
        rules.add_decision(decision, candidate.source)
    assert [d.action for d in rules.decisions(candidate.candidate_id)] == ['reject', 'defer']
    assert rules.decisions('e' * 64) == [] and len(rows(rules, store.DECISION)) == 2


def test_a_decision_is_validated_before_it_is_made(candidate):
    with pytest.raises(RuleError) as caught:
        store.decision_for(candidate, 'accept', DECIDED, label=None)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INPUT', 'bad-decision')
    with pytest.raises(RuleError):
        store.decision_for(candidate, 'accept', DECIDED, label='ok', cve=['CVE-1'])


def test_versions_follow_one_another_and_a_gap_is_refused(tmp_path, candidate):
    rules = rule_store(tmp_path)
    first_decision, first = accepted(candidate)
    second_decision, second = accepted(candidate, 'Terminate removed again', previous=first,
                                       decided_at='2026-10-14T09:10:00+00:00')
    for decision in (first_decision, second_decision):
        rules.add_decision(decision, candidate.source)
    with pytest.raises(RuleError) as caught:                      # version 2 before version 1
        rules.add_version(second)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INTEGRITY', 'version-chain')
    assert rules.add_version(first) is True and rules.add_version(first) is False and rules.add_version(second) is True
    assert [(v.version, v.supersedes) for v in rules.versions(candidate.lineage_id)] == [
        (1, None), (2, first.version_id)]
    assert rules.version(second.version_id) == second and rules.versions('d' * 64) == []
    assert first.rule_text != second.rule_text and 'Terminate removed again' in second.rule_text


def test_the_version_numbers_stop_at_the_limit(candidate):
    decision, first = accepted(candidate)
    tip = first.model_copy(update={'version': 50})
    with pytest.raises(RuleError) as caught:
        store.version_for(candidate, decision, tip, first.rule_text)
    assert caught.value.code == 'PT-RULE-LIMIT'


def test_a_crash_between_the_decision_and_the_version_is_finished_by_repeating(tmp_path, candidate):
    rules = rule_store(tmp_path)
    decision, version = accepted(candidate)
    rules.add_decision(decision, candidate.source)                       # ... the process died here
    assert [d.decision_id for d in rules.pending_accepts()] == [decision.decision_id] and rules.versions() == []
    again_decision, again_version = accepted(candidate)                  # the same command, run again
    assert (again_decision, again_version) == (decision, version)          # a pure function of the stored rows
    assert rules.add_decision(again_decision, candidate.source) is False   # nothing written twice
    rules.add_version(again_version)
    assert rules.pending_accepts() == [] and len(rows(rules, store.DECISION)) == 1 == len(rows(rules, store.VERSION))


def test_a_rejected_candidate_is_not_pending(tmp_path, candidate):
    rules = rule_store(tmp_path)
    decision, _ = accepted(candidate)
    rules.add_decision(decision, candidate.source)
    rules.add_decision(store.decision_for(candidate, 'reject', '2026-10-14T09:30:00+00:00'), candidate.source)
    assert rules.pending_accepts() == []                                  # the later mind is in force


def test_a_row_that_fails_its_hash_is_skipped_and_reported(tmp_path, candidate):
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    rules.enrichment.store.connection.execute('UPDATE enrichment_entries SET body_sha256=? WHERE kind=?', ('0' * 64, store.CANDIDATE))
    assert rules.candidates() == [] and len(rules.skipped) == 1 and rules.skipped[0].startswith('rule-candidate:')


def test_rows_of_a_newer_contract_are_left_alone(tmp_path, candidate):
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    row = rows(rules, store.CANDIDATE)[0]['id']
    body = rules.enrichment.entries(store.CANDIDATE)[0].body
    body['contract'] = 'yara-rules/2'
    text = json.dumps(body, sort_keys=True, separators=(',', ':'))
    rules.enrichment.store.connection.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?', (
        text, hashlib.sha256(text.encode()).hexdigest(), row))
    assert rules.candidates() == [] and rules.skipped == []


def test_a_large_grid_goes_to_a_hash_verified_sidecar(tmp_path, candidate, monkeypatch):
    rules = rule_store(tmp_path)
    _, version = accepted(candidate)
    run = a_run(version, cells=1)
    monkeypatch.setattr(store, 'INLINE_LIMIT', 10)
    assert rules.add_test(run, candidate.source) is True and rules.add_test(run, candidate.source) is False
    (sidecar,) = (tmp_path / 'project' / 'rules' / 'tests').glob('*.json')
    body = rules.enrichment.entries(store.TEST)[0].body
    assert body['kind'] == 'sidecar' and body['sidecar'] == f'rules/tests/{sidecar.name}' and 'cells' not in body
    assert rules.tests() == [run] and rules.find_test(run.cache_key) == run
    sidecar.write_bytes(sidecar.read_bytes().replace(b'older.dll', b'newer.dll'))        # the file was altered
    assert rules.tests() == [] and rules.skipped == [f'rule-test:{run.run_id}']


@pytest.mark.parametrize('bad', [b'{"not json', b'\xff\xfe', b'[' * 100_000], ids=['json', 'utf8', 'deep'])
def test_a_sidecar_that_passes_its_hash_but_is_not_json_is_skipped(tmp_path, candidate, monkeypatch, bad):
    """#105 BUG-RULE-4: a tampered sidecar with a matching hash must be skipped and listed, never raise."""
    rules = rule_store(tmp_path)
    _, version = accepted(candidate)
    run = a_run(version, cells=1)
    monkeypatch.setattr(store, 'INLINE_LIMIT', 10)
    rules.add_test(run, candidate.source)
    (sidecar,) = (tmp_path / 'project' / 'rules' / 'tests').glob('*.json')
    sidecar.write_bytes(bad)
    row = rows(rules, store.TEST)[0]['id']
    body = rules.enrichment.entries(store.TEST)[0].body
    body['sidecar_sha256'] = hashlib.sha256(bad).hexdigest()
    text = json.dumps(body, sort_keys=True, separators=(',', ':'))
    rules.enrichment.store.connection.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?', (
        text, hashlib.sha256(text.encode()).hexdigest(), row))
    assert rules.tests() == [] and rules.skipped == [f'rule-test:{run.run_id}']


def test_tests_are_listed_newest_first_and_only_a_complete_run_is_a_cache_hit(tmp_path, candidate):
    rules = rule_store(tmp_path)
    _, version = accepted(candidate)
    early, late = a_run(version, finished='2026-10-14T10:00:00+00:00'), a_run(version, finished='2026-10-14T11:00:00+00:00')
    cancelled = late.model_copy(update={'status': 'cancelled', 'cache_key': '3' * 64, 'run_id': 'test-cancelled',
                                                     'finished_at': '2026-10-14T11:30:00+00:00'})
    for run in (early, late, cancelled):
        rules.add_test(run, candidate.source)
    assert [r.run_id for r in rules.tests()] == ['test-cancelled', late.run_id, early.run_id]
    assert rules.find_test('3' * 64) is None and rules.find_test('2' * 64) == late


def test_the_cache_key_is_hashes_only(candidate):
    _, version = accepted(candidate)
    target = TargetRef(target_id='b0001', label='older.dll', role='series', sha256='1' * 64, size=10, ordinal=1)
    key = matrix.cache_key([version], [target], '1.21.0', 30)
    assert key == matrix.cache_key([version], [target.model_copy(update={'label': 'renamed.dll', 'expect': 'hit'})],
                                   '1.21.0', 30)
    assert key != matrix.cache_key([version], [target], '1.22.0', 30) and key != matrix.cache_key([version], [target], '1.21.0', 60)
    assert key != matrix.cache_key([version], [target.model_copy(update={'sha256': '4' * 64})], '1.21.0', 30)
