"""C6 pure evidence view-model (docs/specs/multi-engine-evidence-panel.md §3, §10.1)."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import fields

import pytest

from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.secondary.contracts import (
    BINDIFF_LIMITATIONS,
    RZDIFF_LIMITATIONS,
    AlternativeMatch,
    SecondaryMatch,
    SecondaryMatchSet,
)
from patchtrace.secondary.evidence_view import (
    BANNED,
    ENGINE_COLUMNS,
    FOOTER,
    PROVENANCE_FOOTER,
    PROVENANCE_HEADER,
    STATE_TEXT,
    VERDICT_FROM_CODE,
    VERDICT_LABELS,
    EngineOutcomeView,
    EvidenceRow,
    EvidenceViewModel,
    build_view_model,
    calibration_display_level,
    filter_rows,
    format_cell_detail,
    format_provenance_block,
    format_provenance_blocks,
    format_row_detail,
    format_triage_index,
    resolve_state,
    sanitize_text,
    state_text,
)

OLD, NEW = 'a' * 64, 'b' * 64
RUN = 'run-1'


def gmatch(mid, older, newer, name='f', category='modified', types=('Exact',), quality='high', manual=False):
    older_recs = [] if older is None else [FunctionRecord(artifact_id='o', run_id=RUN, name=f'{name}_old',
                                                          address=older)]
    newer_recs = [] if newer is None else [FunctionRecord(artifact_id='n', run_id=RUN, name=name, address=newer)]
    return FunctionMatch(id=mid, run_id=RUN, older=older_recs, newer=newer_recs, category=category,
                         match_types=list(types), quality=quality, manual=manual)


def bd(older, newer, sim=970, conf=910, algo='name hash matching', name=None):
    return SecondaryMatch(engine='bindiff', engine_version='8', older_address=older, newer_address=newer,
                          older_name=name, newer_name=name, similarity_milli=sim, similarity_text=f'{sim / 1000}',
                          confidence_milli=conf, confidence_text=f'{conf / 1000}', flags=('G',), algorithm=algo)


def rz(older, newer, sim=880):
    return SecondaryMatch(engine='rz-diff', engine_version='0.9.1', older_address=older, newer_address=newer,
                          older_name=None, newer_name=None, similarity_milli=sim, similarity_text=f'{sim / 1000}',
                          confidence_milli=None, confidence_text=None, flags=(), algorithm='levenshtein-bytes')


def mset(engine, *rows, older=OLD, newer=NEW, alternatives=()):
    limits = BINDIFF_LIMITATIONS if engine == 'bindiff' else RZDIFF_LIMITATIONS
    return SecondaryMatchSet(contract='secondary/2', engine=engine,
                             engine_version='8' if engine == 'bindiff' else '0.9.1', older_sha256=older,
                             newer_sha256=newer, file_sha256=('c' if engine == 'bindiff' else 'd') * 64,
                             image_base_subtracted='no', matches=tuple(rows), limitations=limits,
                             alternatives=tuple(alternatives))


def standard_matches():
    return [gmatch('m-agree', '10', '20', 'ParseHeader'),
            gmatch('m-contest', '30', '40', 'ValidateBuf'),
            gmatch('m-single', '50', '60', 'InitTable'),
            gmatch('m-unknown', '70', '80', 'FooThunk')]


def standard_sets():
    # FooThunk: many-to-many in neither engine -> make it not-comparable by unparsable address instead.
    return (mset('bindiff', bd(0x10, 0x20), bd(0x30, 0x99, sim=820, conf=640), bd(0x500, 0x600, name='orphan')),
            mset('rz-diff', rz(0x10, 0x20), rz(0x30, 0x40)))


def build(matches=None, sets=None, **kw):
    matches = standard_matches() if matches is None else matches
    sets = standard_sets() if sets is None else sets
    base = dict(project_id='p1', run_id=RUN, revision=3, older_sha256=OLD, newer_sha256=NEW)
    base.update(kw)
    return build_view_model(matches=matches, sets=sets, **base)


def unknown_vm():
    matches = standard_matches()[:3] + [gmatch('m-unknown', 'zz-not-hex', '80', 'FooThunk')]
    return build(matches=matches)


def row(vm, match_id) -> EvidenceRow:
    return next(r for r in vm.rows if r.match_id == match_id)


def visible_strings(vm: EvidenceViewModel, show_index=True):
    yield state_text(vm)
    yield from vm.warnings
    for info in vm.engines:
        yield info.label
        yield info.detail
    for r in vm.rows + vm.engine_only:
        yield r.verdict_text
        yield r.reason
        for cell in r.cells:
            yield cell.text
            yield cell.accessible
            yield format_cell_detail(cell)
        yield format_row_detail(vm, r, show_index)
        yield format_provenance_block(vm, r, show_index)


SANCTIONED = (FOOTER, PROVENANCE_HEADER, PROVENANCE_FOOTER, *BINDIFF_LIMITATIONS, *RZDIFF_LIMITATIONS,
              'algorithm-dependent, not a probability', 'not vulnerabilities')


def assert_no_banned(text: str) -> None:
    for phrase in SANCTIONED:
        text = text.replace(phrase, '')
    lowered = text.lower()
    for word in BANNED:  # stems match as prefixes, the rest as whole words ('provenance' is fine)
        tail = '' if word in ('probab', 'vulnerab', 'exploit', 'likelihood') else r'\b'
        assert not re.search(r'\b' + re.escape(word) + tail, lowered), (word, text[:400])
    assert '%' not in text, text[:400]


# ---- tests --------------------------------------------------------------------------------------


def test_verdict_map_is_total_and_ui_names_exact():
    assert set(VERDICT_FROM_CODE) == {'corroborated', 'contested', 'single-engine', 'insufficient'}
    assert [VERDICT_LABELS[VERDICT_FROM_CODE[c]] for c in ('corroborated', 'contested', 'single-engine',
                                                           'insufficient')] == [
        'Agree', 'Contested', 'Single engine', 'Unknown']


def test_rows_map_verdicts_and_default_order_contested_first():
    vm = unknown_vm()
    assert vm.state == 'ready'
    assert [r.verdict for r in vm.rows] == ['contested', 'unknown', 'single-engine', 'agree']
    assert vm.counts == {'contested': 1, 'unknown': 1, 'single-engine': 1, 'agree': 1}
    assert all(len(r.cells) == len(ENGINE_COLUMNS) for r in vm.rows)
    assert [c.engine for c in vm.rows[0].cells] == list(ENGINE_COLUMNS)


def test_cells_never_combine_scores():
    vm = build()
    agree = row(vm, 'm-agree')
    ghidriff, bindiff, rzdiff = agree.cells
    assert bindiff.text == 'sim 0.97  algo name hash matching' and bindiff.sort_key == 970
    assert rzdiff.text == 'byte sim 0.88' and rzdiff.sort_key == 880
    assert ghidriff.sort_key is None
    for cell in agree.cells:  # no cell carries another engine's value
        others = {'0.97', '0.88'} - ({'0.97'} if cell.engine == 'bindiff' else {'0.88'} if cell.engine == 'rz-diff'
                                     else set())
        assert not any(value in cell.text for value in others)
    names = {f.name for cls in (EvidenceRow, EvidenceViewModel) for f in fields(cls)}
    assert not any(word in name for name in names for word in ('combined', 'average', 'overall', 'consensus'))


def test_units_in_every_score_cell():
    vm = build()
    agree = row(vm, 'm-agree')
    assert agree.cells[0].text == 'Exact'  # raw match type; no invented score (flag F3)
    ghidriff_detail = format_cell_detail(agree.cells[0])
    assert 'Quality label (raw, recorded by PatchTrace): high' in ghidriff_detail
    assert 'text diff ratio' in ghidriff_detail and 'not a match score' in ghidriff_detail
    assert agree.cells[1].text.startswith('sim ') and 'algo ' in agree.cells[1].text
    assert agree.cells[2].text.startswith('byte sim ')
    assert 'similarity' in agree.cells[1].accessible and 'byte similarity' in agree.cells[2].accessible
    assert 'raw-byte Levenshtein, not semantic' in format_cell_detail(agree.cells[2])
    assert 'confidence value 0.91' in format_cell_detail(agree.cells[1])


def test_absent_and_not_comparable_are_not_negative():
    vm = unknown_vm()
    single = row(vm, 'm-single')
    assert single.verdict == 'single-engine'
    assert [c.text for c in single.cells[1:]] == ['no record', 'no record']
    assert single.contradicting == ()
    unknown = row(vm, 'm-unknown')
    assert unknown.verdict == 'unknown' and [c.text for c in unknown.cells[1:]] == ['n/c', 'n/c']
    assert 'many-to-many' in format_cell_detail(unknown.cells[1])


def test_contested_has_alternatives_and_wins_over_majority():
    vm = build()
    contested = row(vm, 'm-contest')
    assert contested.verdict == 'contested'
    assert contested.cells[1].kind == 'pairs-elsewhere' and contested.cells[1].text == 'pairs elsewhere'
    assert contested.cells[2].kind == 'value'  # rz-diff agrees, still contested
    assert contested.contradicting == ('bindiff',) and contested.supporting == ('rz-diff',)
    engines = [a.engine for a in contested.alternatives]
    assert engines == ['bindiff', 'ghidriff']
    assert contested.alternatives[0].newer_address == 0x99
    detail = format_row_detail(vm, contested)
    assert 'BinDiff: older 0x30 -> newer 0x99' in detail and 'Ghidriff (baseline): older 0x30' in detail


def test_alternative_rank_candidates_listed():
    alts = (AlternativeMatch(anchor_side='older', anchor_address=0x30, candidate=bd(0x30, 0x40), source='bindiff',
                             rank=2),)
    sets = (mset('bindiff', bd(0x30, 0x99), alternatives=alts),)
    vm = build(matches=[gmatch('m', '30', '40')], sets=sets)
    notes = [a.note for a in vm.rows[0].alternatives]
    assert 'alternative rank 2' in notes and vm.rows[0].verdict == 'contested'


def test_secondary_only_records_listed_separately():
    vm = build()
    assert all(r.verdict != 'engine-only' for r in vm.rows)
    assert [r.function_label for r in vm.engine_only] == ['orphan']
    only = vm.engine_only[0]
    assert only.verdict_text == 'Engine-only record' and only.cells[1].text.startswith('sim ')
    assert filter_rows(vm.engine_only, {'engine-only'}) == [0]


def test_banned_strings_never_appear():
    models = [unknown_vm(), build(sets=()), build(sets=(standard_sets()[0],),
                                                  outcomes=(EngineOutcomeView('rz-diff', 'failed',
                                                                              error_code='PT-SECONDARY-RUN',
                                                                              message='exited 1'),))]
    for vm in models:
        for text in visible_strings(vm):
            assert_no_banned(text)
    for text in STATE_TEXT.values():
        assert_no_banned(text)


def test_index_hidden_by_default_and_never_percent():
    vm = build()
    agree = row(vm, 'm-agree')
    assert 'Triage index' not in format_row_detail(vm, agree)
    assert 'Triage index: hidden by default' in format_provenance_block(vm, agree)
    shown = format_row_detail(vm, agree, show_index=True)
    assert 'Triage index 83 (uncalibrated, ordering aid only)' in shown
    assert 'of 83' not in shown and '%' not in shown
    assert format_triage_index(None).startswith('Triage index: not assessed')


def test_calibration_level_falls_back_to_ordinal():
    assert calibration_display_level() in {'ordinal'} or isinstance(calibration_display_level(), str)
    assert build().calibration_level == 'ordinal'


def test_sanitize_text_strips_controls_bidi_and_truncates():
    assert sanitize_text('a\x00b\x1b[31mc\u202ed\u2066e\u200ff\u2028g') == 'ab[31mcdefg'
    assert sanitize_text('<b>x</b> {0} %s file:///C:/x') == '<b>x</b> {0} %s file:///C:/x'
    assert sanitize_text('x' * 500, 10) == 'xxxxxxx...'
    assert sanitize_text(None) == ''


def test_provenance_block_is_deterministic_plain_text_and_capped():
    vm = build()
    contested = row(vm, 'm-contest')
    first = format_provenance_block(vm, contested)
    assert first == format_provenance_block(vm, contested)
    lines = first.split('\n')
    assert lines[0] == PROVENANCE_HEADER
    assert lines[1] == f'Project: p1 | Ghidriff run: {RUN} | STALE: no'
    assert lines[3].startswith('Verdict: Contested (code: contested)')
    assert lines[4] == 'Ghidriff: types=Exact quality=high'
    assert lines[5].startswith('BinDiff 8: older 0x30') and '[set sha256 ' + 'c' * 64 + ']' in lines[5]
    assert lines[-1] == PROVENANCE_FOOTER and '\r' not in first and '<' not in first
    many = format_provenance_blocks(vm, list(vm.rows) * 100)
    assert len(many) <= 16 * 1024 and 'more omitted' in many


def test_filter_rows_verdict_search_hide_agree_hex_with_and_without_0x():
    vm = unknown_vm()
    rows = vm.rows
    every = {'agree', 'contested', 'single-engine', 'unknown'}
    assert len(filter_rows(rows, every)) == 4
    assert [rows[i].match_id for i in filter_rows(rows, {'contested'})] == ['m-contest']
    assert len(filter_rows(rows, every, hide_agree=True)) == 3
    assert [rows[i].match_id for i in filter_rows(rows, every, 'parseheader')] == ['m-agree']
    assert [rows[i].match_id for i in filter_rows(rows, every, '0x30')] == ['m-contest']
    assert [rows[i].match_id for i in filter_rows(rows, every, '  30 ')] == ['m-contest']
    assert filter_rows(rows, every, 'zzz-nothing') == []


def test_state_resolution_precedence():
    assert resolve_state(project=False, failed=True) == 'no-project'
    assert resolve_state(project=True, failed=True, stale=True, partial=True) == 'failed'
    assert resolve_state(project=True, stale=True, partial=True) == 'stale'
    assert resolve_state(project=True, partial=True) == 'partial'
    assert resolve_state(project=True) == 'ready'
    assert resolve_state(project=True, has_sets=False) == 'no-engines'
    assert resolve_state(project=True, has_sets=False, all_unsupported=True) == 'unsupported'
    assert resolve_state(project=True, too_large=True) == 'too-large'


def test_no_engines_unsupported_and_partial_models():
    assert build(sets=()).state == 'no-engines'
    assert state_text(build(sets=())) == STATE_TEXT['no-engines']
    unsupported = tuple(EngineOutcomeView(e, 'unsupported', message=f'{e} missing') for e in ('bindiff', 'rz-diff'))
    vm = build(sets=(), outcomes=unsupported)
    assert vm.state == 'unsupported' and 'rz-diff missing' in state_text(vm)
    partial = build(sets=(standard_sets()[0],), outcomes=(EngineOutcomeView('rz-diff', 'failed'),))
    assert partial.state == 'partial' and partial.failed_engines == 1
    assert [c.text for c in partial.rows[0].cells][2] == 'failed'
    assert '1 engine(s) did not produce results' in state_text(partial)


def test_one_engine_other_column_reads_not_run():
    vm = build(sets=(standard_sets()[0],))
    assert vm.state == 'ready' and all(r.cells[2].text == 'not run' for r in vm.rows)


def test_stale_pair_from_set_hashes():
    sets = (mset('bindiff', bd(0x10, 0x20), older='e' * 64),)
    vm = build(sets=sets)
    assert vm.state == 'stale' and 'different older/newer artifact pair' in state_text(vm)
    assert 'STALE: yes' in format_provenance_block(vm, vm.rows[0])


def test_too_large_guard(monkeypatch):
    from patchtrace.secondary import evidence_view
    monkeypatch.setattr(evidence_view, 'DISPLAY_ROW_CAP', 2)
    vm = build()
    assert vm.state == 'too-large' and vm.rows == () and 'Too many rows to display (4)' in state_text(vm)


def test_inconsistent_match_sets_yield_failed_model_not_exception():
    vm = build(sets=(standard_sets()[0], standard_sets()[0]))  # duplicate engines -> ValueError in assess
    assert vm.state == 'failed' and vm.error.startswith('PT-EVIDENCE-ASSEMBLY')
    assert 'could not be assembled' in state_text(vm)


def test_hostile_names_survive_as_literal_plain_text():
    hostile = '<b>pwn</b>\x1b[31m\u202e{0}%s'
    vm = build(matches=[gmatch('m', '10', '20', hostile)], sets=(mset('bindiff', bd(0x10, 0x20)),))
    assert vm.rows[0].function_label == '<b>pwn</b>[31m{0}%s'


def test_evidence_view_has_no_qt():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.secondary.evidence_view, patchtrace.secondary.evidence_panel_service\n'
            'assert not any(m.startswith("PySide6") for m in sys.modules)\n')
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src')
    env = dict(os.environ, PYTHONPATH=src + os.pathsep + os.environ.get('PYTHONPATH', ''))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('code,expected', [('corroborated', 'agree'), ('insufficient', 'unknown')])
def test_verdict_code_mapping(code, expected):
    assert VERDICT_FROM_CODE[code] == expected
