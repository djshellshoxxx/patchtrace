"""K4a: lead grouping rules of ``kbcorrelation.leads`` (KB-integration-plan 4, 6). Offline, synthetic."""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, FixedClock, fixture, write_pair
from kbc_k4a_golden import all_text, banned_in
from kbc_k4a_support import apply_diff
from pydantic import ValidationError

from patchtrace import cli as main_cli
from patchtrace.kbcorrelation import cli, wiring
from patchtrace.kbcorrelation.cli_leads import RealEngine, default_alignment
from patchtrace.kbcorrelation.contracts import Chip, LeadNav, LeadRow
from patchtrace.kbcorrelation.leads import (
    Alignment,
    EngineRow,
    EngineSignal,
    EngineView,
    KevFact,
    NullExploitation,
    build_leads,
    render_text,
)
from patchtrace.kbcorrelation.service import KbService

pytestmark = pytest.mark.usefixtures('no_sockets')
EXTRA = 'CVE-2099-20009'


@pytest.fixture(scope='module')
def baked(tmp_path_factory):
    """One analysed project shared by the module: (bundle, engine view). Read-only use."""
    root = tmp_path_factory.mktemp('leads')
    env = wiring.build_env(clock=FixedClock())
    ws = str(root / 'ws')

    def kb(*argv):
        out = io.StringIO()
        code = cli.main([*argv, '--workspace', ws, '--json'], env=env, stdout=out)
        return code, json.loads(out.getvalue())
    assert kb('index', 'import', fixture(BASELINE))[0] == 0
    inv = kb('search', 'KB5099001')[1]['result']['investigation_id']
    older, newer = write_pair(root)
    assert kb('import-pair', inv, '--older', str(older), '--newer', str(newer), '--project', str(root / 'P'))[0] == 0
    apply_diff(root / 'P', root)
    with contextlib.redirect_stdout(io.StringIO()):
        assert main_cli.main(['rank', str(root / 'P')]) == 0
    bundle = KbService(root / 'ws', env)._project_bundles(str(root / 'P'))[-1]
    return bundle, RealEngine().read(str(root / 'P'))


def two_cve_bundle(bundle, cwe='CWE-787'):
    """The baseline bundle plus a second CVE of the same detector family (BND) for the same changes."""
    card = bundle.context.cards[0].model_copy(update={'cve': EXTRA, 'stated_cwe': cwe})
    cards = tuple(sorted([*bundle.context.cards, card], key=lambda c: c.cve))
    profile = bundle.cwe_profiles[0].model_copy(update={'cve': EXTRA})
    hypothesis = bundle.hypotheses[0].model_copy(update={'cve': EXTRA})
    context = bundle.context.model_copy(update={'cards': cards})
    return bundle.model_copy(update={'context': context, 'cwe_profiles': (*bundle.cwe_profiles, profile),
                                     'hypotheses': (*bundle.hypotheses, hypothesis)})


def order(report):
    return [r.subject for g in report.groups for r in g.leads] + [r.subject for r in report.unattributed]


def test_a_function_may_join_several_groups_one_row_each(baked):
    bundle, view = baked
    report = build_leads(two_cve_bundle(bundle), view, alignment=default_alignment())
    assert [g.group for g in report.groups] == [bundle.context.cards[0].cve, EXTRA]
    assert [[r.subject for r in g.leads] for g in report.groups] == [['read_item'], ['read_item']]
    ids = {r.lead_id for g in report.groups for r in g.leads}
    assert len(ids) == 2  # one id per (group, function)
    assert [r.subject for r in report.unattributed].count('read_item') == 0


def test_two_aligned_signals_of_one_edit_make_one_lead(baked):
    bundle, view = baked
    rows = tuple(dataclasses.replace(r, signals=(*r.signals, EngineSignal('SIZE', 'strong', r.signals[0].group_key,
                                                                          'size compared')))
                 if r.name == 'read_item' else r for r in view.rows)
    report = build_leads(bundle, dataclasses.replace(view, rows=rows), alignment=default_alignment())
    leads = report.groups[0].leads
    assert [r.subject for r in leads] == ['read_item']
    assert len({c.channel for c in leads[0].chips}) == len(leads[0].chips)  # channels listed, never counted
    documentary = next(c for c in leads[0].chips if c.channel == 'documentary')
    assert '1 source family' in documentary.text


def test_groups_sort_by_kev_then_supporting_channels_then_cve_id(baked):
    bundle, view = baked
    both = two_cve_bundle(bundle)

    class Kev:
        def __init__(self, listed):
            self.listed = listed

        def status(self, cve):
            return KevFact('listed', '2099-02-12') if cve == self.listed else KevFact('not-listed')
    plain = build_leads(both, view, alignment=default_alignment(), kev=Kev(None))
    assert [g.group for g in plain.groups] == ['CVE-2099-20001', EXTRA]
    flipped = build_leads(both, view, alignment=default_alignment(), kev=Kev(EXTRA))
    assert [g.group for g in flipped.groups] == [EXTRA, 'CVE-2099-20001']
    assert order(plain)[:2] == order(flipped)[:2] == ['read_item', 'read_item']
    assert order(plain) == order(flipped)


def test_missing_and_unavailable_evidence_is_unknown_never_negative(baked):
    bundle, view = baked
    report = build_leads(bundle, view, alignment=default_alignment())
    removed = next(r for r in report.unattributed if r.subject == 'debug_dump')
    chip = next(c for c in removed.chips if c.channel == 'code-change')
    assert chip.state == 'unknown' and 'removed' in chip.text
    states = {c.channel: c.state for c in report.groups[0].leads[0].chips}
    assert states['applicability'] == 'unknown' and states['exploitation'] == 'not-run' \
        and states['anchor'] == 'not-run'


def test_alignment_needs_an_aligning_confidence_and_the_cwe_family():
    alignment = Alignment({'CWE-125': ('BND',)}, frozenset({'strong'}))
    row = EngineRow('m', 'f', 'modified', 1, (EngineSignal('BND', 'weak', 'g'), EngineSignal('OVF', 'strong', 'h')))
    assert alignment.hits('CWE-125', row) == ()
    strong = dataclasses.replace(row, signals=(EngineSignal('BND', 'strong', 'g'),))
    assert [s.detector for s in alignment.hits('CWE-125', strong)] == ['BND']
    assert alignment.hits(None, strong) == () and alignment.hits('CWE-1', strong) == ()


def test_state_wording_and_hooks_per_state(baked):
    bundle, view = baked
    alignment = default_alignment()
    cases = [(bundle, view, 'ready', 'kb.next.review_lead'), (bundle, None, 'no-comparison', 'kb.next.run_comparison'),
             (None, view, 'no-advisory', 'kb.next.import_documents'),
             (bundle, dataclasses.replace(view, newer_sha=view.older_sha), 'stale', 'kb.next.run_comparison')]
    for b, v, state, hook in cases:
        report = build_leads(b, v, alignment=alignment)
        assert report.state == state and report.hooks == (hook,)
        assert banned_in(all_text(report.model_dump(mode='json'))) == []


def test_text_report_numbers_leads_and_lists_the_footer(baked):
    bundle, view = baked
    text = render_text(build_leads(bundle, view, alignment=default_alignment(),
                                   mention_only=['CVE-2099-20003']))
    lines = text.splitlines()
    assert lines[0].startswith('Checked 1 of 1') and any(line.startswith('GROUP CVE-2099-20001') for line in lines)
    assert [line.split()[0] for line in lines if line.startswith('  ')] == ['1', '2', '3', '4', '5']
    assert 'MENTION ONLY  CVE-2099-20003' in text and 'GROUP unattributed (always visible)' in text


def test_null_exploitation_answers_not_loaded():
    assert NullExploitation().status('CVE-2099-20001') == KevFact('no-snapshot')


def test_view_without_rows_still_lists_the_context_group(baked):
    bundle, view = baked
    report = build_leads(bundle, dataclasses.replace(view, rows=()), alignment=default_alignment())
    assert report.state == 'ready' and [g.group for g in report.groups] == ['CVE-2099-20001']
    assert report.unattributed == ()


def test_lead_row_contract_rejects_two_chips_per_channel_and_free_groups():
    chip = Chip(channel='anchor', state='not-run', text='x')
    nav = LeadNav(project_revision=0)
    base = {'lead_id': 'a' * 64, 'level': 'function', 'subject': 's', 'rank_basis': 'b', 'nav': nav}
    with pytest.raises(ValidationError):
        LeadRow(**base, group='unattributed', chips=(chip, chip))
    with pytest.raises(ValidationError):
        LeadRow(**base, group='some group')
    assert isinstance(EngineView(0, None, 'a', 'b', ()), EngineView)


def test_hostile_function_name_is_plain_text(baked):
    bundle, view = baked
    evil = EngineRow('m', 'f‮oo\n\x07<script>', 'modified', 9, (EngineSignal('BND', 'strong', 'g', 'x y'),))
    report = build_leads(bundle, dataclasses.replace(view, rows=(evil,)), alignment=default_alignment())
    texts = all_text(report.model_dump(mode='json'))
    assert not any(ch in text for text in texts for ch in '‮ \x07\n')
