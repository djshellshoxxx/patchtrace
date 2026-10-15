"""K4a: the Qt-free leads view model that the K4b dock wraps (KB-integration-plan 8.2). Synthetic, offline."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from kbc_k4a_golden import banned_in

from patchtrace.kbcorrelation.contracts import Chip, LeadNav, LeadRow
from patchtrace.kbcorrelation.leads import LeadGroup, LeadsReport, NotApplicableCve
from patchtrace.kbcorrelation.view_model import COLUMNS, COPY_LIMIT, TEXT_EMPTY, LeadsViewModel

SRC = Path(__file__).resolve().parent.parent / 'src'
CVE = 'CVE-2099-20001'


def lead(index: int, group: str = CVE, *, total: int = 5, stale: bool = False, name: str | None = None,
         text: str = 'observed BND signal (moderate)') -> LeadRow:
    chips = (Chip(channel='code-change', state='supports', text=text),
             Chip(channel='exploitation', state='not-run', text='KEV: not loaded'),
             Chip(channel='applicability', state='unknown', text='unknown (no loaded document states it)'))
    return LeadRow(lead_id=f'{index:064x}', level='function', group=group, subject=name or f'fn_{index}', chips=chips,
                   rank_basis=f'attention order {index} of {total} (the engine\'s own order, not a measure of risk)',
                   nav=LeadNav(match_id=None if stale else f'm{index}', project_revision=3, run_id='run-1'),
                   stale=stale, hooks=('kb.next.review_lead',))


def report(grouped=(1, 2), loose=(3,), *, state='ready', stale=False, **extra) -> LeadsReport:
    total = len(grouped) + len(loose)
    group = LeadGroup(group=CVE, kev='no-snapshot', kev_text='KEV: not loaded', cwe='CWE-125',
                      cwe_text='CWE-125 stated by vendor (CVRF)', hypotheses=('R-MEMORY-READ',),
                      leads=tuple(lead(i, total=total, stale=stale) for i in grouped))
    return LeadsReport(state=state, text='Leads pair the advisory context with the comparison.', stale=stale,
                       coverage_text=('Checked 1 of 1 documents (2099-Feb); nothing else was checked.',),
                       groups=(group,), unattributed=tuple(lead(i, 'unattributed', total=total, stale=stale)
                                                           for i in loose),
                       not_applicable=(NotApplicableCve(cve='CVE-2099-20002', products=('Example Server',),
                                                        text='CVE-2099-20002 (Example Server only)'),),
                       mention_only=('CVE-2099-20003',), **{'limitations': ('A limit.',), **extra})


def test_rows_are_group_headers_then_numbered_leads_in_report_order():
    model = LeadsViewModel.from_report(report())
    assert model.columns == COLUMNS and model.row_count == 5 and model.lead_count == 3
    kinds = [model.row(i).kind for i in range(model.row_count)]
    assert kinds == ['group', 'lead', 'lead', 'group', 'lead']
    assert [model.cell(i, 0) for i in (1, 2, 4)] == ['1', '2', '3']
    assert model.cell(0, 1).startswith(f'{CVE}  KEV: not loaded | CWE-125 stated by vendor (CVRF) | hypothesis R-MEMORY')
    assert model.cell(3, 1) == 'unattributed (always visible)'
    assert [model.cell(i, 1) for i in (1, 2, 4)] == ['fn_1', 'fn_2', 'fn_3']


def test_attention_order_cell_and_spoken_units():
    model = LeadsViewModel.from_report(report())
    assert model.cell(2, 4) == '2 of 3'
    assert model.accessible(2, 4) == 'attention order 2 of 3, the engine\'s own order'
    assert model.accessible(2, 0) == 'Order 2' and model.accessible(2, 1) == 'Function fn_2'
    assert model.accessible(2, 3).startswith('Evidence: supports: observed BND signal')


def test_state_is_words_and_glyphs_never_colour_alone():
    from patchtrace.kbcorrelation.view_model import chip_lines
    lines = chip_lines(lead(1))
    assert lines == ('[+] supports  code-change: observed BND signal (moderate)',
                     '[-] not-run  exploitation: KEV: not loaded',
                     '[?] unknown  applicability: unknown (no loaded document states it)')


def test_navigation_is_off_for_headers_stale_reports_and_missing_matches():
    model = LeadsViewModel.from_report(report())
    assert model.navigation_enabled and model.goto(0) is None and model.goto(1) == 'm1'
    stale = LeadsViewModel.from_report(report(state='stale', stale=True))
    assert not stale.navigation_enabled and all(stale.goto(i) is None for i in range(stale.row_count))


def test_group_filter_keeps_numbering_within_the_shown_rows():
    model = LeadsViewModel.from_report(report())
    assert model.group_options() == ('all', CVE, 'unattributed')
    only = model.filtered('unattributed')
    assert only.row_count == 2 and only.selected_group == 'unattributed' and only.cell(1, 0) == '1'
    assert model.filtered(CVE).lead_count == 2


def test_an_empty_list_is_explained_and_coverage_is_always_present():
    empty = LeadsViewModel.from_report(report((), ()))
    assert empty.lead_count == 0 and empty.status_text == TEXT_EMPTY
    assert empty.coverage_line.startswith('Checked 1 of 1')
    bare = LeadsViewModel.from_report(LeadsReport(state='no-advisory', text='No advisory context.'))
    assert bare.coverage_line == 'No advisory coverage is recorded for this project.'
    assert bare.status_text == 'No advisory context.' and bare.row_count == 1  # the unattributed header stays


def test_footer_lists_not_applicable_mention_only_and_limits():
    assert LeadsViewModel.from_report(report()).footer_lines == (
        'Not applicable: CVE-2099-20002 (Example Server only)', 'Mention only: CVE-2099-20003', 'Limit: A limit.')


def test_copy_block_is_plain_text_with_provenance_and_bounded():
    model = LeadsViewModel.from_report(report(context_key='c' * 64))
    block = model.copy_block(1)
    assert f'Lead: {1:064x}' in block and f'Context: {"c" * 64}' in block and 'Run: run-1' in block
    assert 'Project revision: 3' in block and 'Limit: A limit.' in block
    huge = LeadsViewModel.from_report(report(grouped=(1,), loose=(), limitations=tuple(f'L{i} ' * 200
                                                                                      for i in range(100))))
    assert len(huge.copy_block(1)) <= COPY_LIMIT


def test_hostile_text_is_plain_in_every_cell():
    evil = '‮evil\n\x07 <b>x</b>'
    row = lead(1, name=evil, text=evil)
    group = LeadGroup(group=CVE, kev='no-snapshot', kev_text='KEV: not loaded', leads=(row,))
    model = LeadsViewModel.from_report(LeadsReport(state='ready', text='t', groups=(group,)))
    cells = [model.cell(r, c) for r in range(model.row_count) for c in range(5)]
    spoken = [model.accessible(r, c) for r in range(model.row_count) for c in range(5)]
    for text in (*cells, *spoken, model.copy_block(1)):
        assert not any(ch in text for ch in '\u202e\u2028\x07')
    assert all('\n' not in text for text in (*cells, *spoken))


def test_banned_word_sweep_over_every_cell_and_spoken_text():
    model = LeadsViewModel.from_report(report())
    texts = [model.cell(r, c) for r in range(model.row_count) for c in range(5)]
    texts += [model.accessible(r, c) for r in range(model.row_count) for c in range(5)]
    texts += [model.status_text, model.coverage_line, *model.footer_lines]
    assert banned_in(texts) == []


@pytest.mark.parametrize('count', [10_000], ids=['10k'])
def test_large_lists_are_indexed_not_recomputed(count):
    rows = tuple(lead(i, total=count) for i in range(1, count + 1))
    group = LeadGroup(group=CVE, kev='no-snapshot', kev_text='KEV: not loaded', leads=rows)
    model = LeadsViewModel.from_report(LeadsReport(state='ready', text='t', groups=(group,)))
    assert model.row_count == count + 2 and model.cell(count, 1) == f'fn_{count}'
    assert model.cell(count, 4) == f'{count} of {count}' and model.row(count) is model.row(count)


def test_view_model_modules_do_not_import_qt():
    code = ('import sys\nimport patchtrace.kbcorrelation.view_model, patchtrace.kbcorrelation.leads, '
            'patchtrace.kbcorrelation.cli_leads\n'
            'bad = [m for m in sys.modules if m.split(".")[0] in ("PySide6", "PyQt5", "PyQt6", "PySide2")]\n'
            'print(",".join(bad))\n')
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True,
                         env={'PYTHONPATH': str(SRC)}, timeout=120)
    assert out.stdout.strip() == ''
