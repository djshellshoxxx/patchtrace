"""R5: saving an accepted rule as a `.yar` file (YRX-integration-plan section 7, "Export header"). The header is pinned by a
golden file; the hard checks, the informational warnings, the file policy (never replace, no Git tree unless told) and what
the header must not hold are pinned by tests. The rule is the real candidate of the SYNTHETIC `capa-api` pair.
"""
from __future__ import annotations

import getpass
import hashlib
import re
from pathlib import Path

import pytest
import rules_fixtures as rf
from rules_store_support import PROJECT_ID, accepted, candidate_of, engine_scan
from test_rules_matrix import World

from patchtrace.rules import export, matrix
from patchtrace.rules.contracts import Gate
from patchtrace.rules.errors import RuleError

GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'rules' / 'export' / 'export-term-v1.yar'
FINISHED = '2026-10-14T10:00:00+00:00'


@pytest.fixture(autouse=True)
def fixed_build(monkeypatch):
    monkeypatch.setattr(export, '__version__', '0.1.0')


@pytest.fixture
def bench(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


class Rule:
    def __init__(self, bench, root: Path, **kw):
        self.candidate = candidate_of(bench, 'term', name=kw.pop('name', None))
        self.decision, self.version = accepted(self.candidate, 'Terminate removed', cve=['CVE-2026-0001'], kb=['KB5034123'])
        self.world = World(bench, root)

    def grid(self, vanish: str | None = None, **kw):
        entries, _ = self.world.entries(series=self.world.series, clean_dir=self.world.clean, **kw)
        if vanish:   # gone between hashing and scanning
            (self.world.clean / vanish).unlink()
        return matrix.run_matrix(entries, [self.version], scan=engine_scan, now=lambda: FINISHED)

    def build(self, runs=(), **kw):
        return export.build(self.version, self.decision, self.candidate, list(runs), **kw)


@pytest.fixture
def rule(bench, tmp_path):
    return Rule(bench, tmp_path)


def header_of(text: str) -> list[str]:
    return text.split('\nimport "pe"\n')[0].splitlines()


def test_the_export_equals_its_golden_file(rule):
    plan = rule.build([rule.grid()], basenames={'older': 'older.dll', 'newer': 'newer.dll'})
    assert plan.text.encode('ascii') == GOLDEN.read_bytes() and plan.warnings == ()
    assert b'\r' not in GOLDEN.read_bytes() and plan.rule_name == rule.candidate.rule_name


def test_the_header_lines_say_what_the_plan_says(rule):
    lines = header_of(rule.build([rule.grid()]).text)
    assert lines[0] == '// patchtrace-rule-export/1'
    assert lines[1] == f'// Rule {rule.candidate.rule_name} version 1, label "Terminate removed"'
    assert lines[2] == '// Built by PatchTrace 0.1.0 with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 standin'
    assert lines[3] == f'// Project {PROJECT_ID}, analysis run run-1'
    assert re.fullmatch(r'// Older build sha256 [0-9a-f]{64}; newer build sha256 [0-9a-f]{64}', lines[4])
    assert lines[5] == '// Source change: removed function at older RVA 0x104d, reviewed as material; function names omitted'
    assert lines[6] == f'// Accepted 2026-10-14T09:00:00+00:00. Tested {FINISHED}: 4 builds, 4 clean files, 0 unexpected matches, 0 not scanned'
    assert lines[7] == '// Advisory anchors given by the analyst and not checked by this rule: CVE-2026-0001 KB5034123'
    assert lines[8].startswith('// Origin: byte patterns copied from the analysed files') and 'licence' in lines[8]
    assert lines[9] == '// A match means a file contains this pattern. It does not show whether the file is affected by a flaw.'


def test_export_header_has_no_paths_or_names_by_default(rule, tmp_path):
    plan = rule.build([rule.grid()])
    forbidden = [str(tmp_path), tmp_path.name, getpass.getuser(), '/home', 'C:\\', 'older.dll', '0-V1']
    assert not [word for word in forbidden if word and word in plan.text]
    assert re.fullmatch(r'[\x20-\x7e\n]+', plan.text) and plan.text.endswith('\n')
    assert all(line.startswith('//') for line in header_of(plan.text))
    assert re.search(r'function_older\s+= "0x104d"', plan.text)                  # an RVA, no name


def test_the_unknown_is_not_made_up(rule):
    plan = rule.build()
    assert plan.warnings == ('not-tested',) and '// Accepted 2026-10-14T09:00:00+00:00. Not tested' in plan.text
    unvetted = rule.candidate.model_copy(update={'unvetted': True})
    line = export.header_lines(rule.version, rule.decision, unvetted, None, include_names=False, basenames={})[5]
    assert 'not reviewed as material, confirmed by the analyst' in line


def test_names_are_written_only_when_asked_for(bench, tmp_path):
    named = Rule(bench, tmp_path, name='TermProc')
    assert 'TermProc' not in named.build().text and 'TermProc' not in named.version.rule_text
    asked = named.build(include_names=True)
    assert re.search(r'function_older\s+= "0x104d TermProc"', asked.text)
    assert '// Source change: removed function at older RVA 0x104d, reviewed as material; function names included' in asked.text


@pytest.mark.parametrize('failed', ['sep', 'compile', 'secret'], ids=['sep', 'compile', 'secret'])
def test_a_failed_hard_check_refuses_the_export(rule, failed):
    gates = tuple(Gate(gate_id=g.gate_id, state='fail', measured=1) if g.gate_id == failed else g
                  for g in rule.candidate.gates)
    broken = rule.candidate.model_copy(update={'gates': gates})
    with pytest.raises(RuleError) as caught:
        export.build(rule.version, rule.decision, broken, [])
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-GATE', 'hard-gate')


def test_an_unknown_hard_check_is_not_a_pass(rule):
    gates = tuple(g for g in rule.candidate.gates if g.gate_id != 'sep')
    with pytest.raises(RuleError) as caught:
        export.build(rule.version, rule.decision, rule.candidate.model_copy(update={'gates': gates}), [])
    assert caught.value.code == 'PT-RULE-GATE'


def test_the_candidate_must_be_stored(rule):
    with pytest.raises(RuleError) as caught:
        export.build(rule.version, rule.decision, None, [])
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-INTEGRITY', 'candidate-missing')


def test_secret_strings_never_exported(rule):
    secret = rule.version.rule_text.replace('  condition:', '    $s1 = "AKIAIOSFODNN7EXAMPLE" ascii\n\n  condition:', 1)
    # the candidate's checks passed once; the text that would be written is checked again
    leaking = rule.version.model_copy(update={'rule_text': secret})
    with pytest.raises(RuleError) as caught:
        export.build(leaking, rule.decision, rule.candidate, [])
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-GATE', 'secret')
    assert 'AKIA' not in str(caught.value)
    fine = rule.version.rule_text.replace('  condition:', '    $s1 = "PatchTrace synthetic" ascii\n\n  condition:', 1)
    assert export.build(rule.version.model_copy(update={'rule_text': fine}), rule.decision, rule.candidate, []).text


def test_a_decision_of_another_version_is_refused(rule):
    other = rule.decision.model_copy(update={'decision_id': 'f' * 64})
    with pytest.raises(RuleError) as caught:
        export.build(rule.version, other, rule.candidate, [])
    assert caught.value.reason == 'decision-mismatch'
    rejected = rule.decision.model_copy(update={'action': 'reject'})
    with pytest.raises(RuleError):
        export.build(rule.version, rejected, rule.candidate, [])


def test_the_warnings_are_findings_not_refusals(rule, tmp_path):
    clean = rule.grid()
    assert export.warnings_for(rule.version, clean, '1.21.0') == ()
    assert export.warnings_for(rule.version, clean, '1.22.0') == ('grid-stale',)
    unread = rule.grid(vanish='1-clean-2.dll')
    assert export.warnings_for(rule.version, unread, None) == ('not-scanned',)
    assert '4 builds, 4 clean files, 0 unexpected matches, 1 not scanned' in rule.build([unread]).text
    (rule.world.clean / '1-clean-2.dll').write_bytes(rule.world.builds['clean-2'])
    flagged = rule.grid(expect={'0-clean-1.dll': 'hit'})                  # the analyst expected a match that did not come
    assert export.warnings_for(rule.version, flagged, None) == ('unexpected-results',)
    leaked = rule.grid(expect={'1-V1r.dll': 'no-hit'})
    assert export.warnings_for(rule.version, leaked, None) == ('unexpected-results',)
    assert '4 builds, 4 clean files, 1 unexpected matches, 0 not scanned' in rule.build([leaked]).text


def test_only_a_finished_grid_of_this_version_counts_as_tested(rule, bench, tmp_path):
    grid = rule.grid()
    cancelled = grid.model_copy(update={'status': 'cancelled'})
    assert export.tested_run(rule.version, [cancelled]) is None
    foreign = grid.model_copy(update={'rules': (grid.rules[0].model_copy(update={'rule_sha256': '9' * 64}),)})
    assert export.tested_run(rule.version, [foreign]) is None
    assert export.tested_run(rule.version, [cancelled, grid]) == grid


def test_the_file_is_created_with_lf_line_ends_and_recorded_without_a_path(rule, tmp_path):
    plan = rule.build([rule.grid()])
    out = tmp_path / 'term.yar'
    record = export.write(plan, rule.version, out, allow_git_tree=True)
    data = out.read_bytes()
    assert data == plan.text.encode('ascii') and b'\r' not in data
    assert (record.basename, record.sha256, record.version_id) == ('term.yar', hashlib.sha256(data).hexdigest(),
                                                                 rule.version.version_id)
    assert str(tmp_path) not in record.model_dump_json() and record.warnings == ()


def test_a_file_is_never_replaced(rule, tmp_path):
    out = tmp_path / 'term.yar'
    out.write_text('mine', encoding='utf-8')
    with pytest.raises(RuleError) as caught:
        export.write(rule.build(), rule.version, out, allow_git_tree=True)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-EXPORT', 'exists') and out.read_text(encoding='utf-8') == 'mine'


@pytest.mark.parametrize('name,reason', [('term.txt', 'suffix'), ('missing/term.yar', 'no-folder')], ids=['suffix', 'folder'])
def test_the_path_policy(rule, tmp_path, name, reason):
    with pytest.raises(RuleError) as caught:
        export.write(rule.build(), rule.version, tmp_path / name, allow_git_tree=True)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-EXPORT', reason)


def test_a_git_working_tree_needs_the_explicit_word(rule, tmp_path):
    repo = tmp_path / 'repo'
    (repo / '.git').mkdir(parents=True)
    (repo / 'sub').mkdir()
    out = repo / 'sub' / 'term.yar'
    with pytest.raises(RuleError) as caught:
        export.write(rule.build(), rule.version, out)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-EXPORT', 'git-tree') and not out.exists()
    export.write(rule.build(), rule.version, out, allow_git_tree=True)
    assert out.is_file()


def test_the_warnings_of_an_export_are_recorded(rule, tmp_path):
    plan = rule.build()
    record = export.write(plan, rule.version, tmp_path / 'term.yar', allow_git_tree=True)
    assert record.warnings == ('not-tested',)
