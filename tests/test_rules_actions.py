"""Panel actions of the Detection rules dock (Qt-free): accept, test and export on the SYNTHETIC `capa-api` pair.
The engine is the in-process stand-in of `rules_store_support` except where the hidden worker child is named."""
from __future__ import annotations

import pytest
import rules_fixtures as rf
from rules_store_support import accepted, candidate_of, engine_scan, rule_store

from patchtrace.rules import actions, store
from patchtrace.rules.contracts import CellResult, Gate
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import RuleLimits

NOW = '2026-10-14T09:00:00+00:00'
LATER = '2026-10-14T09:05:00+00:00'


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def candidate(bench):
    return candidate_of(bench, 'term')


@pytest.fixture
def builds(bench, tmp_path):
    paths = {}
    for side in rf.SIDES:
        paths[side] = tmp_path / f'{side}.exe'
        paths[side].write_bytes(bench.build('capa-api', side).data)
    return paths


# ---- accept --------------------------------------------------------------------------------------------------------

def test_accept_plan_equals_the_cli_accept_and_is_not_stored_yet(candidate):
    plan = actions.plan_accept(candidate, [], [], label='  Terminate removed ', now=NOW)
    _, version = accepted(candidate, 'Terminate removed', decided_at=NOW)
    assert plan.fresh and plan.version.version_id == version.version_id and plan.version.version == 1
    assert 'Terminate removed' in plan.version.rule_text


def test_the_same_accept_twice_changes_nothing_and_a_new_label_is_a_new_version(candidate, tmp_path):
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    first = actions.plan_accept(candidate, [], [], label='One', now=NOW)
    assert actions.commit_accept(rules, candidate, first) is True
    again = actions.plan_accept(candidate, rules.decisions(candidate.candidate_id), rules.versions(candidate.lineage_id),
                                label='One', now=LATER)
    assert not again.fresh and again.version.version_id == first.version.version_id
    assert actions.commit_accept(rules, candidate, again) is False
    second = actions.plan_accept(candidate, rules.decisions(candidate.candidate_id),
                                 rules.versions(candidate.lineage_id), label='Two', now=LATER)
    assert second.fresh and second.version.version == 2 and second.version.supersedes == first.version.version_id
    actions.commit_accept(rules, candidate, second)
    assert [v.version for v in rules.versions(candidate.lineage_id)] == [1, 2]   # additive: version 1 is untouched
    assert len(rules.decisions(candidate.candidate_id)) == 2


def test_a_proposal_alone_is_never_an_accept(candidate, tmp_path):
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    assert rules.versions() == [] and rules.decisions() == []


@pytest.mark.parametrize('label,reason', [('   ', 'label-required'), ('bad\x00label', 'bad-decision'),
                                          ('x' * 121, 'bad-decision')])
def test_a_bad_label_is_refused(candidate, label, reason):
    with pytest.raises(RuleError) as caught:
        actions.plan_accept(candidate, [], [], label=label, now=NOW)
    assert caught.value.reason == reason


def test_a_failed_hard_gate_blocks_the_accept(candidate):
    gates = tuple(Gate(gate_id='sep', state='fail', measured=1) if g.gate_id == 'sep' else g for g in candidate.gates)
    with pytest.raises(RuleError) as caught:
        actions.plan_accept(candidate.model_copy(update={'gates': gates}), [], [], label='x', now=NOW)
    assert caught.value.code == 'PT-RULE-GATE'


def test_the_accepted_text_compiles_in_the_engine(candidate):
    from patchtrace.rules import engine
    plan = actions.plan_accept(candidate, [], [], label='Terminate removed', now=NOW)
    actions.check_compiles(plan.version, lint=lambda rules, **kw: engine.RuleSet.compile(tuple(rules)).lint)
    broken = plan.version.model_copy(update={'rule_text': 'rule broken {'})
    from patchtrace.rules.contracts import WorkerLimits
    with pytest.raises(RuleError) as caught:
        actions.check_compiles(broken, lint=lambda rules, **kw: (engine.lint('accept', rules[0].text, WorkerLimits()),))
    assert caught.value.code == 'PT-RULE-COMPILE'


# ---- test ----------------------------------------------------------------------------------------------------------

def test_the_rule_matches_the_side_it_describes_and_not_the_other(candidate, builds):
    outcome = actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds, scan=engine_scan)
    states = {item.side: item.cell.state for item in outcome.sides}
    assert states == {'older': 'hit', 'newer': 'no-hit'}
    assert outcome.sentence().startswith('Older build: Match') and 'Newer build: No match' in outcome.sentence()


def test_the_worker_gets_one_rule_two_hash_checked_files_and_a_timeout(candidate, builds):
    seen = {}

    def spy(rules, targets, **kw):
        seen.update(rules=rules, targets=targets, kw=kw)
        return engine_scan(rules, targets, **kw)
    actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds, timeout_s=7, scan=spy)
    assert len(seen['rules']) == 1 and seen['kw']['timeout_s'] == 7
    assert [t.sha256 for t in seen['targets']] == [candidate.source.older_sha256, candidate.source.newer_sha256]
    assert all(t.size == builds[t.target_id].stat().st_size for t in seen['targets'])


def test_an_unreadable_or_oversize_build_is_not_scanned_never_no_match(candidate, builds):
    calls = []
    builds['newer'].unlink()
    outcome = actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds,
                                 scan=lambda *a, **k: calls.append(1) or engine_scan(*a, **k))
    newer = outcome.sides[1]
    assert newer.cell.state == 'not-scanned' and newer.text == 'Not scanned: file could not be read'
    small = RuleLimits(file_bytes=1024)
    big = actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source,
                             {'older': builds['older'], 'newer': builds['older']}, limits=small,
                             scan=lambda *a, **k: calls.append(2))
    assert {i.cell.reason for i in big.sides} == {'too-large'} and calls == [1]   # nothing was sent for the big files


def test_a_timeout_stays_a_timeout(candidate, builds):
    from patchtrace.rules.runner import ScanOutcome

    def slow(rules, targets, **kw):
        real = engine_scan(rules, targets, **kw)
        cells = (CellResult(state='timeout'), real.cells[1])
        return ScanOutcome(real.engine, real.lint, cells)
    outcome = actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds, scan=slow)
    assert outcome.sides[0].text == 'Timed out'


def test_timeout_range_and_cancel(candidate, builds):
    with pytest.raises(RuleError) as caught:
        actions.scan_sides('r', 'x', candidate.source, builds, timeout_s=4, scan=engine_scan)
    assert caught.value.reason == 'timeout-range'

    def cancelled(*a, **k):
        raise RuleError('PT-RULE-CANCEL', 'Rule work was cancelled', reason='cancelled')
    with pytest.raises(RuleError) as caught:
        actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds, scan=cancelled)
    assert caught.value.code == 'PT-RULE-CANCEL'


def test_the_real_worker_child_scans_both_builds(candidate, builds):
    outcome = actions.scan_sides(candidate.rule_name, candidate.rule_text, candidate.source, builds)
    assert [i.cell.state for i in outcome.sides] == ['hit', 'no-hit']


def test_a_saved_version_is_tested_as_a_stored_grid(candidate, builds, tmp_path):
    _, version = accepted(candidate)
    outcome = actions.run_version_grid(version, builds, scan=engine_scan)
    assert [i.cell.state for i in outcome.sides] == ['hit', 'no-hit'] and outcome.run is not None
    assert [i.cell.verdict for i in outcome.sides] == ['as-expected', 'as-expected']
    rules = rule_store(tmp_path)
    rules.add_candidate(candidate)
    assert actions.commit_test(rules, version, outcome.run) is True
    assert len(rules.tests()) == 1
    assert actions.commit_test(rules, version, outcome.run.model_copy(update={'status': 'cancelled'})) is False


def test_a_build_that_is_not_the_recorded_file_is_refused(candidate, builds):
    _, version = accepted(candidate)
    builds['newer'].write_bytes(b'MZ' + b'\x00' * 200)
    with pytest.raises(RuleError) as caught:
        actions.run_version_grid(version, builds, scan=engine_scan)
    assert caught.value.reason == 'build-moved'


# ---- export --------------------------------------------------------------------------------------------------------

def exportable(candidate):
    decision, version = accepted(candidate)
    return decision, version


def test_the_preview_is_exactly_the_file_and_never_replaces(candidate, tmp_path):
    decision, version = exportable(candidate)
    preview, plan = actions.plan_export(version, [decision], candidate, [])
    assert preview.warnings == ('not-tested',) and 'not been tested' in preview.warning_sentences[0]
    target = actions.sanitise_export_path(str(tmp_path / 'out' / 'rule'))
    (tmp_path / 'out').mkdir()
    record = actions.write_export(plan, version, target)
    assert target.name == 'rule.yar' and target.read_text(encoding='ascii') == preview.text
    import hashlib
    assert record.sha256 == hashlib.sha256(preview.text.encode('ascii')).hexdigest()
    with pytest.raises(RuleError) as caught:
        actions.write_export(plan, version, target)
    assert caught.value.reason == 'exists'


def test_export_record_is_appended_and_a_git_tree_needs_consent(candidate, tmp_path):
    decision, version = exportable(candidate)
    _, plan = actions.plan_export(version, [decision], candidate, [])
    repo = tmp_path / 'repo'
    (repo / '.git').mkdir(parents=True)
    with pytest.raises(RuleError) as caught:
        actions.write_export(plan, version, repo / 'a.yar')
    assert caught.value.reason == 'git-tree'
    record = actions.write_export(plan, version, repo / 'a.yar', allow_git_tree=True)
    rules = rule_store(tmp_path / 'proj')
    rules.add_candidate(candidate)
    assert actions.commit_export(rules, version, record) is True and len(rules.exports()) == 1


def test_a_failed_hard_check_cannot_be_previewed(candidate):
    decision, version = exportable(candidate)
    gates = tuple(Gate(gate_id='secret', state='fail', measured=1) if g.gate_id == 'secret' else g
                  for g in candidate.gates)
    with pytest.raises(RuleError) as caught:
        actions.plan_export(version, [decision], candidate.model_copy(update={'gates': gates}), [])
    assert caught.value.code == 'PT-RULE-GATE'


@pytest.mark.parametrize('text,reason', [('', 'no-name'), ('   ', 'no-name'), ('a\x00b.yar', 'no-name'),
                                         ('bad\x07name.yar', 'bad-name'), ('co<n>.yar', 'bad-name'),
                                         ('rule.txt', 'suffix'), ('rule.', 'bad-name'), ('x' * 130 + '.yar', 'bad-name')])
def test_unsafe_export_names_are_refused(text, reason, tmp_path):
    with pytest.raises(RuleError) as caught:
        actions.sanitise_export_path(str(tmp_path / text) if text.strip() and '\x00' not in text else text)
    assert caught.value.reason == reason


def test_export_path_gets_the_suffix_and_a_folder_is_refused(tmp_path):
    assert actions.sanitise_export_path(str(tmp_path / 'r')).name == 'r.yar'
    assert actions.sanitise_export_path(str(tmp_path / 'r.YAR')).name == 'r.yar'
    with pytest.raises(RuleError):
        actions.sanitise_export_path(str(tmp_path))


def test_decision_helper_is_the_store_helper():
    assert actions.store is store
