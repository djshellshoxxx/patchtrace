"""K4a: the E0 synergy test (KB-integration-plan 5). Offline (sockets denied), synthetic data only.

Each channel alone answers part of the question; together (`rank` then `kb leads`) the KB-stated CWE, the product scope
and the engine's own order give a short, honest list. The golden holds the shape and the measured baseline scores as
provenance: a later engine re-tune fails the baseline test, not the lead-shape tests.

Regenerate the golden with ``KBC_REGEN_GOLDEN=1 pytest tests/test_kbc_synergy.py -k golden``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import Kb
from kbc_k4a_golden import GOLDEN, all_text, banned_in, baseline_scores, projection
from kbc_k4a_support import analysed_project

from patchtrace.kbcorrelation import cli
from patchtrace.kbcorrelation.cli_leads import RealEngine
from patchtrace.kbcorrelation.leads import EngineRow, EngineSignal

pytestmark = pytest.mark.usefixtures('no_sockets')
CVE_A, CVE_B, CVE_MENTION = 'CVE-2099-20001', 'CVE-2099-20002', 'CVE-2099-20003'


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@pytest.fixture
def project(kb, tmp_path, capsys):
    return analysed_project(kb, tmp_path, capsys)


def leads(kb, project, *extra):
    code, doc, _ = kb('leads', str(project), *extra)
    return code, doc['result']


class FakeEngine:
    def __init__(self, view):
        self.view = view

    def read(self, project_dir):
        return self.view


def run_with(kb, project, view, *argv):
    """``kb leads`` with a replaced engine view; returns (exit code, result)."""
    import io
    out = io.StringIO()
    code = cli.main(['leads', str(project), '--workspace', str(kb.workspace), '--json', *argv], env=kb.env,
                    engine=FakeEngine(view), stdout=out)
    return code, json.loads(out.getvalue())['result']


def test_synergy_golden_shape_and_baseline(kb, project, tmp_path, capsys):
    scores = baseline_scores(project, tmp_path, capsys)
    code, result = leads(kb, project)
    actual = {'engine_scores': scores, 'leads': projection(result)}
    if os.environ.get('KBC_REGEN_GOLDEN') == '1':
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    assert code == 0
    assert actual == json.loads(GOLDEN.read_text(encoding='utf-8'))


def test_each_channel_alone_is_incomplete_and_the_bulletin_wide_cve_list_misleads(project, tmp_path, capsys):
    scores = baseline_scores(project, tmp_path, capsys)
    ranked = scores['rank']
    assert abs(ranked['read_item'] - ranked['alloc_items']) <= 2  # a one-point gap carries no CVE meaning
    assert all(ranked[name] == 0 for name in ('report_invalid_index', 'get_version', 'debug_dump'))
    one, both = scores['correlate_20001'], scores['correlate_20001_20002']
    assert one['read_item'] > ranked['read_item'] and one['alloc_items'] == ranked['alloc_items']
    assert both['alloc_items'] > ranked['alloc_items']  # +CWE-190 credit from a CVE that is not for the client


def test_leads_have_no_group_or_context_for_the_cve_that_does_not_apply(kb, project):
    code, result = leads(kb, project)
    assert code == 0 and [g['group'] for g in result['groups']] == [CVE_A]
    assert [n['cve'] for n in result['not_applicable']] == [CVE_B] and result['mention_only'] == [CVE_MENTION]
    names = [row['subject'] for row in result['groups'][0]['leads']]
    assert names == ['read_item']
    alloc = next(row for row in result['unattributed'] if row['subject'] == 'alloc_items')
    chips = {c['channel']: c for c in alloc['chips']}
    assert CVE_B in chips['applicability']['text'] and 'Example Server' in chips['applicability']['text']
    assert 'hypothesis' not in chips  # nothing from the other CVE leaks into the context of the client


def test_every_function_is_listed_once_and_inside_group_order_is_the_engine_order(kb, project):
    _, result = leads(kb, project)
    rows = result['groups'][0]['leads'] + result['unattributed']
    assert [r['subject'] for r in rows] == ['read_item', 'alloc_items', 'debug_dump', 'get_version',
                                            'report_invalid_index']
    orders = [int(r['rank_basis'].split()[2]) for r in rows]
    assert orders == sorted(orders)


def test_no_number_except_the_labelled_attention_order_and_coverage_on_every_view(kb, project):
    code, text, _ = kb('leads', str(project), as_json=False)
    assert code == 0 and text.splitlines()[0].startswith('Checked 1 of 1 documents')
    for line in text.splitlines():
        if line.lstrip()[:1].isdigit():
            assert 'attention order' in line
    assert 'score' not in text.lower() and '%' not in text


def test_banned_word_sweep_is_clean(kb, project):
    _, result = leads(kb, project)
    assert banned_in(all_text(result)) == []
    assert banned_in([kb('leads', str(project), as_json=False)[1]]) == []


def test_kev_never_changes_function_order(kb, project):
    from patchtrace.kbcorrelation.leads import KevFact

    class Listed:
        def status(self, cve):
            return KevFact('listed', '2099-02-12', 'a' * 64) if cve == CVE_A else KevFact('not-listed')

    import io
    out = io.StringIO()
    assert cli.main(['leads', str(project), '--workspace', str(kb.workspace), '--json'], env=kb.env,
                    kev=Listed(), stdout=out) == 0
    with_kev = json.loads(out.getvalue())['result']
    _, without = leads(kb, project)
    assert with_kev['groups'][0]['kev_text'].startswith('KEV listed 2099-02-12')
    assert without['groups'][0]['kev_text'] == 'KEV: not loaded'
    def order(r):
        return [x['subject'] for g in r['groups'] for x in g['leads']] + [x['subject'] for x in r['unattributed']]
    assert order(with_kev) == order(without)


def test_contested_engine_verdict_stays_contested_and_membership_is_kept(kb, project):
    view = RealEngine().read(str(project))
    rows = tuple(dataclasses.replace(r, verdicts=(('bindiff', 'unchanged'), ('ghidriff', 'changed')))
                 if r.name == 'read_item' else r for r in view.rows)
    code, result = run_with(kb, project, dataclasses.replace(view, rows=rows))
    row = result['groups'][0]['leads'][0]
    chip = next(c for c in row['chips'] if c['channel'] == 'code-change')
    assert code == 0 and row['subject'] == 'read_item'
    assert chip['state'] == 'contradicts' and 'engines disagree' in chip['text']


def test_leads_are_stale_when_the_file_pair_is_swapped_and_navigation_is_off(kb, project):
    view = RealEngine().read(str(project))
    swapped = dataclasses.replace(view, older_sha=view.newer_sha, newer_sha=view.older_sha)
    code, result = run_with(kb, project, swapped)
    rows = result['groups'][0]['leads'] + result['unattributed']
    assert code == 0 and result['state'] == 'stale' and result['stale'] is True
    assert rows and all(r['stale'] and r['nav']['match_id'] is None for r in rows)


def test_without_a_ranked_run_only_the_context_is_shown_with_exit_4(kb, tmp_path, capsys):
    project = analysed_project(kb, tmp_path, capsys, rank=False)
    code, result = leads(kb, project)
    assert code == 4 and result['state'] == 'no-comparison'
    assert [g['group'] for g in result['groups']] == [CVE_A] and result['groups'][0]['leads'] == []
    assert result['hooks'] == ['kb.next.run_comparison']


def test_without_cvrf_the_engine_order_stands_alone(tmp_path, capsys):
    kb = Kb(tmp_path / 'k', capsys)
    project = analysed_project(kb, tmp_path / 'k', capsys)
    view = RealEngine().read(str(project))
    from patchtrace.kbcorrelation.leads import Alignment, build_leads
    report = build_leads(None, view, alignment=Alignment({}, frozenset()))
    assert report.state == 'no-advisory' and report.groups == ()
    assert [r.subject for r in report.unattributed] == ['read_item', 'alloc_items', 'debug_dump', 'get_version',
                                                        'report_invalid_index']


def test_kb_leads_leaves_the_project_and_the_workspace_unchanged(kb, project):
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()
    files = [project / 'project.sqlite3', kb.workspace / 'kbc.sqlite3']
    before = [digest(f) for f in files]
    assert leads(kb, project)[0] == 0
    assert [digest(f) for f in files] == before


def test_a_project_with_no_context_and_no_ranking_is_exit_4_with_the_kb17_copy(kb, tmp_path, capsys):
    from kbc_k3_support import write_pair

    from patchtrace.service import ProjectService
    old, new = write_pair(tmp_path / 'plain')
    ProjectService.create(old, new, 'plain', tmp_path / 'plain' / 'P').close()
    code, doc, _ = kb('leads', str(tmp_path / 'plain' / 'P'))
    assert code == 4 and doc['status'] == 'unavailable' and doc['result']['state'] == 'no-advisory'


def test_unaligned_signal_does_not_join_a_group_and_absence_is_not_a_negative(kb, project):
    view = RealEngine().read(str(project))
    rows = tuple(dataclasses.replace(r, signals=(EngineSignal('SCRUB', 'strong', 'g' * 64, 'zeroing added'),))
                 if r.name == 'read_item' else r for r in view.rows)
    code, result = run_with(kb, project, dataclasses.replace(view, rows=rows))
    assert code == 0 and result['groups'][0]['leads'] == []
    quiet = next(r for r in result['unattributed'] if r['subject'] == 'get_version')
    chip = next(c for c in quiet['chips'] if c['channel'] == 'code-change')
    assert chip['state'] == 'unknown' and 'not a negative finding' in chip['text']


def test_engine_row_without_attention_order_is_listed_last(kb, project):
    view = RealEngine().read(str(project))
    extra = EngineRow('m-extra', 'extra_fn', 'modified', None)
    code, result = run_with(kb, project, dataclasses.replace(view, rows=(*view.rows, extra)))
    assert code == 0 and result['unattributed'][-1]['subject'] == 'extra_fn'
    assert 'no attention order' in result['unattributed'][-1]['rank_basis']


@pytest.mark.parametrize('argv,expect', [(['--cve', CVE_A], 0), (['--cve', CVE_B], 4), (['--cve', 'CVE-12'], 2),
                                        (['--limit', '1'], 0), (['--limit', '0'], 2)], ids=['cve', 'other', 'bad',
                                                                                            'limit', 'zero'])
def test_cve_and_limit_options(kb, project, argv, expect):
    assert kb('leads', str(project), *argv)[0] == expect


def test_limit_caps_each_group_and_says_how_many_were_left_out(kb, project):
    _, result = leads(kb, project, '--limit', '1')
    assert len(result['unattributed']) == 1 and result['truncated'] == 3


def test_attach_only_project_without_workspace_still_lists_leads(kb, project, tmp_path):
    other = Kb(tmp_path / 'elsewhere', None)
    import io
    out = io.StringIO()
    code = cli.main(['leads', str(project), '--workspace', str(other.workspace), '--json'], env=other.env,
                    stdout=out)
    result = json.loads(out.getvalue())['result']
    assert code == 0 and result['not_applicable'] == [] and [g['group'] for g in result['groups']] == [CVE_A]
