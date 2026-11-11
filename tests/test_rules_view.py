"""R6a: the pure view model and panel service of the detection-rules panel. States and cell copy are exact, no string holds a
banned stem, hostile text is cleaned, an unscanned cell never reads as No match, and nothing here imports Qt or the engine.
Grids are built by hand (no engine); the store-backed tests use the real candidate and skip without YARA-X."""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace.rules import cli, panel_service, view
from patchtrace.rules.contracts import (
    BytesFeature,
    CellResult,
    EngineStamp,
    Gate,
    MatrixRun,
    RunRule,
    TargetRef,
)
from patchtrace.rules.errors import RuleError

BANNED = ('vulnerab', 'exploit', 'safe', 'secure', 'fixed', 'verified', 'proven', 'probab')
ENGINE = EngineStamp(version='1.21.0', version_source='pin')
SHA = 'a' * 64
SRC = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'rules'


def target(n: int, role='series', expect='unknown', label=None, **kw) -> TargetRef:
    return TargetRef(target_id=f'b{n:04d}', label=label or f'build{n}.dll', role=role, sha256=f'{n:064x}', size=10,
                     ordinal=None if role == 'clean' else n, expect=expect, **kw)


def run(targets, cells, rules=1, engine=ENGINE, status='complete', finished='2026-10-14T10:00:00+00:00') -> MatrixRun:
    return MatrixRun(run_id='run-1', cache_key='2' * 64, engine=engine, status=status,
                     rules=tuple(RunRule(version_id=f'{i + 1:064x}', rule_sha256=f'{i + 1:064x}') for i in range(rules)),
                     targets=tuple(targets), cells=tuple(cells), limits={'cells': 105000}, finished_at=finished)


HIT = CellResult(state='hit', hits=1, offsets=(5,), rvas=(0x1005,), verdict='as-expected')
MISS = CellResult(state='no-hit', hits=0, verdict='unexpected-miss')


def test_state_texts_are_the_plan_text():
    assert view.status('R0').text == 'Open a project to work with detection rules.'
    assert view.status('R4t', rules=3, files=12).text.startswith('Testing 3 rules against 12 files. Files that cannot')
    assert view.status('R7', code='PT-RULE-ENGINE', message='boom').text == \
        'Rule work could not finish: PT-RULE-ENGINE: boom. Saved rules are unchanged.'
    assert view.status('R8', count=200000).state_id == 'R8'


def test_no_string_of_the_view_holds_a_banned_stem():
    strings = [*view.STATES.values(), *view.REASONS.values(), *view.VERDICTS.values(), *view.EXPECTED.values(),
               view.FOOTER]
    from patchtrace.rules.gates import LABELS
    strings += list(LABELS.values())
    for text in strings:
        assert not any(stem in text.lower() for stem in BANNED), text


def test_footer_matches_the_cli():
    assert view.FOOTER == cli.FOOTER


def test_cell_copy_is_closed():
    cells = [CellResult(state='hit', hits=1), CellResult(state='no-hit', hits=0), CellResult(state='timeout'), CellResult(state='error', reason='engine'),
             CellResult(state='not-scanned', reason='too-large')]
    assert [view.cell_text(c) for c in cells] == [
        'Match', 'No match', 'Timed out', 'Error', 'Not scanned: file is larger than the limit']


def test_a_failed_run_has_no_cells_and_reads_error_never_no_match():
    grid = view.GridView(run([target(1), target(2)], [], status='failed'), ['PT_0123456789ab_older'])
    assert [r.cells for r in grid.rows] == [('Error',), ('Error',)]
    assert grid.summary()[0].not_scanned == 2 and grid.summary()[0].no_match == 0


def test_grid_summary_filters_and_verdicts():
    targets = [target(1, 'older-anchor', 'hit'), target(2, 'newer-anchor', 'no-hit'), target(3, 'clean', 'no-hit')]
    grid = view.GridView(run(targets, [HIT, CellResult(state='hit', hits=1, verdict='unexpected-hit'), MISS],
                             rules=1), ['PT_0123456789ab_older'])
    assert grid.row_indexes() == (0, 1, 2)
    assert grid.row_indexes(role='clean') == (2,)
    assert grid.row_indexes(unexpected_only=True) == (1, 2)
    assert grid.row_indexes(state='hit', unexpected_only=True) == (1,)
    assert grid.rows[1].verdicts == ('unexpected match',) and grid.rows[2].verdicts == ('unexpected no match',)
    assert grid.summary()[0].text == '2 Match, 1 No match, 0 Not scanned, 2 unexpected'
    assert grid.footer == view.FOOTER


def test_accessible_text_names_build_kb_rule_state_and_expectation():
    targets = [target(i, kb=f'KB500000{i}') for i in range(1, 4)]
    grid = view.GridView(run(targets, [HIT, CellResult(state='no-hit', hits=0), HIT]), ['PT_0123456789ab_older'])
    assert grid.accessible(1, 0) == 'Build 2 of 3, KB5000002, rule PT_0123456789ab_older: No match, no expectation'


def test_hostile_text_is_cleaned_and_bounded():
    hostile = 'a\x00b\u202ec\x1b[31md\n' + 'x' * 500
    text = view.clean(hostile)
    assert not re.search('[\x00-\x1f\u202a-\u202e]', text) and len(text) <= view.TEXT_LIMIT + 3
    grid = view.GridView(run([target(1)], [HIT]), [hostile])
    assert '\u202e' not in grid.rows[0].label and '\x00' not in grid.rule_names[0]
    assert '\u202e' not in view.status('R7', code='x', message=hostile).text


def test_advisory_column_is_the_advisory_word_not_a_verdict():
    grid = view.GridView(run([target(1, advisory_says='under_investigation')], [HIT]), ['PT_0123456789ab_older'])
    assert grid.rows[0].advisory == 'Advisory says: under investigation'


def test_presence_words_distinguish_absent_from_unknown():
    assert view._presence('older-only') == ('present', 'absent')
    assert view._presence('newer-only') == ('absent', 'present')
    assert view._presence('both-sides') == ('present', 'present')
    assert view._presence('unknown') == ('unknown', 'unknown')


def test_check_rows_show_the_measure():
    (row,) = view.check_rows([Gate(gate_id='len', state='pass', measured=20, detail='20 literal bytes, longest run 15')])
    assert row.text == 'Long enough: 20 literal bytes, longest run 15' and row.state == 'pass'


def version(n: int, label='lbl') -> SimpleNamespace:
    return SimpleNamespace(version_id=f'{n:064x}', lineage_id='l' * 64, version=n, candidate_id='c' * 64, decision_id='d' * 64)


def test_tested_text_states():
    assert view.tested_text(version(1), [], '1.21.0') == 'Not tested'
    targets = [target(1, 'older-anchor'), target(2, 'newer-anchor'), target(3, 'clean'), target(4, 'clean')]
    done = run(targets, [HIT] * 4)
    assert view.tested_text(version(1), [done], '1.21.0') == 'Tested on 2026-10-14: 2 builds, 2 clean files'
    assert view.tested_text(version(1), [done], '1.22.0') == 'Grid stale: YARA-X version changed'
    assert view.tested_text(version(2), [done], '1.21.0') == 'Not tested'
    partial = run(targets, [HIT] * 4, status='partial')
    assert view.tested_text(version(1), [partial], '1.21.0') == 'Not tested'


def test_status_order_and_missing_project():
    service = panel_service.PanelService(None, engine_version='1.21.0')
    assert service.status(panel_service.Session(project_open=False)).state_id == 'R0'
    assert service.candidates() == () and service.saved() == () and service.grid() is None
    assert service.too_large(105001).state_id == 'R8' and service.too_large(10) is None


def test_failure_outranks_everything_but_a_missing_project():
    service = panel_service.PanelService(object(), engine_version='1.21.0')
    error = RuleError('PT-RULE-ENGINE', 'The rule engine stopped', reason='exit')
    text = service.status(panel_service.Session(error=error, engine_available=False)).text
    assert text.startswith('Rule work could not finish: PT-RULE-ENGINE:')
    assert service.status(panel_service.Session(engine_available=False)).state_id == 'R1'
    assert service.status(panel_service.Session()).state_id == 'R2'


def test_view_modules_import_neither_qt_nor_the_engine_nor_the_network():
    banned = {'PySide6', 'yara_x', 'iced_x86', 'socket', 'urllib', 'http', 'requests', 'subprocess'}
    for name in ('view.py', 'panel_service.py'):
        tree = ast.parse((SRC / name).read_text(encoding='utf-8'))
        imported = {a.name.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {n.module.split('.')[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and not n.level}
        assert not imported & banned, (name, imported & banned)


def test_importing_the_view_loads_no_qt_or_engine():
    code = 'import sys, patchtrace.rules.panel_service, patchtrace.rules.view; ' \
           'print(sorted(m for m in sys.modules if m.split(".")[0] in ("PySide6", "yara_x", "iced_x86")))'
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True,
                         env={**os.environ, 'PYTHONPATH': str(SRC.parents[1])})
    assert out.stdout.strip() == '[]'


def test_a_feature_row_of_each_kind_is_plain_text():
    feature = BytesFeature(included=True, side='older', window_rva=0x1000, length=16, pattern=' '.join(['90'] * 16),
                           literal=16, longest_run=16, mask_source='iced-x86', source_hits=1, other_hits=0,
                           separation='older-only')
    row = view.feature_row(feature)
    assert (row.kind, row.older, row.newer, row.where) == ('bytes', 'present', 'absent', '0x1000')


def test_store_backed_panel_lists_candidates_saved_rules_and_grid(tmp_path):
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    import rules_fixtures as rf
    from rules_store_support import accepted, candidate_of, rule_store

    bench = rf.Bench(tmp_path)
    try:
        candidate = candidate_of(bench)
        rules = rule_store(tmp_path)
        rules.add_candidate(candidate)
        service = panel_service.PanelService(rules, engine_version=candidate.engine.version)
        (row,) = service.candidates(candidate.source)
        assert row.chip == 'Proposed' and row.name.endswith('-build rule')
        decision, ver = accepted(candidate)
        rules.add_decision(decision, candidate.source)
        rules.add_version(ver)
        (shown,) = service.candidates(candidate.source)
        assert shown.chip == 'Accepted v1'
        (saved,) = service.saved()
        assert saved.label == 'Terminate removed' and saved.tested == 'Not tested'
        features, checks, text = service.detail(candidate.candidate_id)
        assert text == candidate.rule_text and len(checks) == len(candidate.gates) and features
        assert service.status(panel_service.Session(selected=candidate.source)).state_id == 'ready'
    finally:
        bench.close()
