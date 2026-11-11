"""Regression tests for the round-2 rules and call-graph bugs of issue #105 (BUG-RULE-1..7, BUG-CG-1..3).

Each test reproduces the reported failure on `main` 241a777 and passes with the fix; the repro scripts are kept in
docs/qa/bug-repros-20261029/round2/."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of, rule_store
from test_rules_store import a_run

from patchtrace.callgraph.algo import simple_paths
from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.export_json import build_export
from patchtrace.callgraph.project_input import Entry, ProjectInput
from patchtrace.callgraph.raw_matches import RawMatchesResult
from patchtrace.callgraph.snapshot import build_snapshot
from patchtrace.rules import export, matrix, store, window
from patchtrace.rules.contracts import CellResult, EngineStamp, FunctionRef, PairSource
from patchtrace.rules.errors import RuleError
from patchtrace.rules.masks import MaskedFunction, MaskedInstruction
from patchtrace.rules.runner import ScanOutcome

T = '2026-10-14T09:00:00+00:00'


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def candidate(bench):
    return candidate_of(bench)


# --- RULE-1: a cached grid is matched to its files by hash, not by position --------------------------------------
def test_a_cached_grid_follows_its_files_when_they_come_in_another_order(tmp_path, candidate):
    _, version = accepted(candidate)
    hit, miss = tmp_path / 'a.bin', tmp_path / 'b.bin'
    hit.write_bytes(b'MATCHME' + b'\0' * 20)
    miss.write_bytes(b'nothing here' + b'\0' * 20)
    stamp = EngineStamp(version='1.21.0', version_source='pin')

    def scan(rules, targets, **_):
        return ScanOutcome(stamp, (), tuple(
            CellResult(state='hit', hits=1, offsets=(0,), rvas=(None,)) if b'MATCHME' in Path(t.path).read_bytes()
            else CellResult(state='no-hit', hits=0) for t in targets))

    first, _ = matrix.gather(version.source, {}, extra=[hit, miss])
    run = matrix.run_matrix(first, [version], scan=scan)
    again, _ = matrix.gather(version.source, {}, extra=[miss, hit])
    shown = matrix.rescored(run, [e.target for e in again], [version])
    assert {t.label: c.state for t, c in zip(shown.targets, shown.cells, strict=True)} == {'a.bin': 'hit', 'b.bin': 'no-hit'}


# --- RULE-2: of two decisions made in one second, the one made last is in force ----------------------------------
@pytest.mark.parametrize('order', [('accept', 'reject'), ('reject', 'accept')])
def test_the_decision_made_last_in_one_second_is_in_force(tmp_path, candidate, order):
    rules = rule_store(tmp_path)
    for action in order:
        decision = store.decision_for(candidate, action, T, label='L' if action == 'accept' else None)
        rules.add_decision(decision, candidate.source)
    history = rules.decisions(candidate.candidate_id)
    assert [d.action for d in history] == list(order)
    assert history[-1].decided_at > history[0].decided_at


def test_a_backdated_decision_still_sorts_where_it_belongs(tmp_path, candidate):
    rules = rule_store(tmp_path)
    for action, stamp in (('defer', '2026-10-14T09:05:00+00:00'), ('reject', T)):
        rules.add_decision(store.decision_for(candidate, action, stamp), candidate.source)
    assert [(d.action, d.decided_at) for d in rules.decisions(candidate.candidate_id)] == [
        ('reject', T), ('defer', '2026-10-14T09:05:00+00:00')]


def test_storing_the_same_decision_twice_keeps_one_row(tmp_path, candidate):
    rules = rule_store(tmp_path)
    decision = store.decision_for(candidate, 'reject', T)
    rules.add_decision(decision, candidate.source)
    rules.add_decision(decision, candidate.source)
    assert [d.decision_id for d in rules.decisions(candidate.candidate_id)] == [decision.decision_id]


# --- RULE-3: an export name the record refuses is refused before the file is written -------------------------------
def test_an_overlong_export_name_is_refused_before_a_file_is_written(tmp_path, candidate):
    _, version = accepted(candidate)
    plan = export.ExportPlan(text=version.rule_text, warnings=(), rule_name=candidate.rule_name)
    out = tmp_path / ('long-descriptive-name-' * 7 + '.yar')
    with pytest.raises(RuleError) as caught:
        export.write(plan, version, out)
    assert caught.value.reason == 'name' and not out.exists()


# --- RULE-4: a hash-consistent sidecar that is not JSON is skipped, never a crash ----------------------------------
def test_a_sidecar_that_is_not_json_is_skipped(tmp_path, candidate, monkeypatch):
    rules = rule_store(tmp_path)
    _, version = accepted(candidate)
    monkeypatch.setattr(store, 'INLINE_LIMIT', 10)
    rules.add_test(a_run(version), candidate.source)
    (sidecar,) = (tmp_path / 'project' / 'rules' / 'tests').glob('*.json')
    bad = b'not json {'
    sidecar.write_bytes(bad)
    connection = rules.enrichment.store.connection
    row_id, text = connection.execute("SELECT id, body FROM enrichment_entries WHERE kind='rule-test'").fetchone()
    body = json.loads(text)
    body['sidecar_sha256'] = hashlib.sha256(bad).hexdigest()
    text = json.dumps(body, sort_keys=True, separators=(',', ':'))
    connection.execute('UPDATE enrichment_entries SET body=?, body_sha256=? WHERE id=?',
                       (text, hashlib.sha256(text.encode()).hexdigest(), row_id))
    assert rules.tests() == [] and len(rules.skipped) == 1


# --- RULE-5: a deeply nested expectations file is a typed input error ---------------------------------------------
def test_a_deeply_nested_expectations_file_is_a_typed_error(tmp_path):
    path = tmp_path / 'expect.json'
    path.write_text('[' * 200_000 + ']' * 200_000)
    with pytest.raises(RuleError) as caught:
        matrix.read_expectations(path)
    assert caught.value.code == 'PT-RULE-INPUT'


# --- RULE-6: a device, FIFO or oversized file given as --extra is refused, never read forever ---------------------
def _pair() -> PairSource:
    return PairSource(project_id='p', revision=1, run_id='r', older_sha256='a' * 64, newer_sha256='b' * 64,
                      match_id='m', category='added', review='accepted', materiality='material',
                      analyst_confirmed_material=False, newer=FunctionRef(rva=0x1000, size=10, extent='pdata'))


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='needs a POSIX FIFO')
def test_a_fifo_given_as_an_extra_file_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / 'pipe'
    os.mkfifo(fifo)
    with pytest.raises(RuleError) as caught:
        matrix.gather(_pair(), {}, extra=[fifo])
    assert caught.value.code == 'PT-RULE-INPUT'


def test_an_extra_file_over_the_byte_limit_is_refused(tmp_path):
    big = tmp_path / 'big.bin'
    big.write_bytes(b'\0' * 64)
    with pytest.raises(RuleError) as caught:
        matrix._digest(big, max_bytes=32)
    assert caught.value.code == 'PT-RULE-INPUT'
    assert matrix._digest(big, max_bytes=64) == (hashlib.sha256(b'\0' * 64).hexdigest(), 64)


# --- RULE-7: the instruction diff stays within its bound when equal pairs are few but the middle is long ----------
def _body(order) -> MaskedFunction:
    instructions, offset = [], 0
    for k in order:
        tokens = ('B8',) + tuple(f'{b:02X}' for b in k.to_bytes(4, 'little'))    # mov eax, imm32 (5 bytes)
        instructions.append(MaskedInstruction(offset, 5, tokens, (), 'next', None, ()))
        offset += 5
    return MaskedFunction(0x1000, tuple(instructions))


def test_a_long_reordered_body_is_one_replace_not_a_quadratic_diff():
    n = 8000                                                       # about 4.4 s before the fix
    older = _body(range(1, n + 1))
    newer = _body([x for i in range(0, n, 2) for x in (i + 2, i + 1)])
    started = time.perf_counter()
    assert window.diff_opcodes(older, newer) == [('replace', 0, n, 0, n)]
    assert time.perf_counter() - started < 1.0


def test_a_short_diff_is_still_exact():
    older, newer = _body([1, 2, 3, 4]), _body([1, 9, 3, 4])
    assert window.diff_opcodes(older, newer) == [('replace', 1, 2, 1, 2)]


# --- CG-1: every successor examined counts against the path-search budget ----------------------------------------
def test_the_path_budget_counts_successor_scans():
    k, dead = 50, 20_000
    a, b = list(range(4, 4 + k)), list(range(4 + k, 4 + 2 * k))
    sink = list(range(4 + 2 * k, 4 + 2 * k + dead))
    edges = [(0, 2), (2, 1), (3, 0)] + [(0, x) for x in a] + [(x, y) for x in a for y in b] \
        + [(y, 3) for y in b] + [(3, d) for d in sink]
    graph = build_csr(4 + 2 * k + dead, edges)
    started = time.perf_counter()
    result = simple_paths(graph, 0, 1, budget=5_000)              # about 2.2 s before the fix, about 1 ms after
    assert result.truncated and time.perf_counter() - started < 0.5


# --- CG-2 / CG-3 --------------------------------------------------------------------------------------------------
def _project(older, newer=()) -> ProjectInput:
    entries = [Entry(side, label, f'f-{side}-{i}', f'm{i}', 0x1000 + i, False, tuple(callees), ())
               for side, items in (('older', older), ('newer', newer)) for i, (label, callees) in enumerate(items)]
    return ProjectInput('p', 1, 'r', 'v', None, 'a' * 64, 'b' * 64, tuple(entries), (), 'd',
                        RawMatchesResult(None, 'absent', ()))


def test_a_callee_label_with_a_huge_numeric_suffix_does_not_break_the_graph():
    snapshot = build_snapshot(_project([('main', ['helper-' + '9' * 5000])]))
    assert snapshot is not None


def test_an_export_cut_by_the_neighbour_cap_says_it_is_truncated():
    callees = [f'callee_{i:03d}' for i in range(100)]
    exported = build_export(build_snapshot(_project([('main', callees)], [('main', callees)])), 'm0', 1)
    assert exported.truncated
