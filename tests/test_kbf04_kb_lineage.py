"""KBF-04 KB-side guard-lock: a shared lineage is ONE independent supporting component, never summed.

Spec docs/specs/kb/cve-to-function-matching-spec.md section 5, row "shared origin counted twice": the pilot-fusion side
is owned by ``tests/test_pilot_fusion.py``; the planned KB-side ``test_lineage_counts_once`` was never written. In
``kbcorrelation.leads`` every lead of one CVE group cites the same advisory lineage (one source family) and the same
pair identity, so a group backed by many changed functions has exactly the supporting channels of a group backed by
one. ``_supporting`` is a channel SET and ``build_leads`` ranks groups by its size; summing it per lead would let
repetition of one lineage outrank a group with the same evidence. Synthetic data only; offline.
"""
from __future__ import annotations

import contextlib
import dataclasses
import io
import json

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import BASELINE, FixedClock, fixture, write_pair
from kbc_k4a_support import apply_diff

from patchtrace import cli as main_cli
from patchtrace.kbcorrelation import cli, wiring
from patchtrace.kbcorrelation.cli_leads import RealEngine
from patchtrace.kbcorrelation.leads import (
    Alignment,
    EngineRow,
    EngineSignal,
    _supporting,
    build_leads,
)
from patchtrace.kbcorrelation.service import KbService

pytestmark = pytest.mark.usefixtures('no_sockets')
FEW, MANY = 'CVE-2099-20001', 'CVE-2099-20009'  # the CVE that sorts first has ONE lead; the later one has several
ALIGNMENT = Alignment({'CWE-125': ('BND',), 'CWE-190': ('MULT',)}, frozenset({'strong', 'moderate'}))


@pytest.fixture(scope='module')
def baked(tmp_path_factory):
    """(bundle with two CVEs of two CWE families, engine view): one analysed project built through the real CLI."""
    root = tmp_path_factory.mktemp('kbf04')
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
    first = bundle.context.cards[0]
    assert (first.cve, first.stated_cwe) == (FEW, 'CWE-125')
    card = first.model_copy(update={'cve': MANY, 'stated_cwe': 'CWE-190'})
    context = bundle.context.model_copy(update={'cards': (first, card)})
    bundle = bundle.model_copy(update={
        'context': context, 'cwe_profiles': (*bundle.cwe_profiles, bundle.cwe_profiles[0].model_copy(
            update={'cve': MANY})),
        'hypotheses': (*bundle.hypotheses, bundle.hypotheses[0].model_copy(update={'cve': MANY}))})
    return bundle, RealEngine().read(str(root / 'P'))


def _rows(view, many: int):
    """One BND-aligned function (joins FEW only) and ``many`` MULT-aligned functions (join MANY only)."""
    one = dataclasses.replace(view.rows[0], match_id='m-one', name='one', attention_rank=1, verdicts=(),
                              signals=(EngineSignal('BND', 'strong', 'g-one', 'bound added'),))
    rest = tuple(EngineRow(f'm-{i}', f'many_{i}', 'modified', i + 2,
                           (EngineSignal('MULT', 'strong', f'g-{i}', 'multiply guarded'),))
                 for i in range(many))
    return (one, *rest)


def _report(baked, many: int):
    bundle, view = baked
    return build_leads(bundle, dataclasses.replace(view, rows=_rows(view, many)), alignment=ALIGNMENT)


def test_lineage_counts_once(baked):
    """Three functions backed by the same advisory lineage give the same independent support as one function, and
    the repeated lineage never lifts its group above a group with equal evidence (ties break by CVE id)."""
    report = _report(baked, many=3)
    groups = {g.group: g for g in report.groups}
    few, many = groups[FEW], groups[MANY]
    assert (len(few.leads), len(many.leads)) == (1, 3)

    # The counted quantity: independent supporting channels of a group. One lineage = one channel each, however many
    # leads repeat it; exploitation (a CVE-level fact) never joins.
    expected = frozenset({'documentary', 'hypothesis', 'binary-identity', 'code-change'})
    assert _supporting(few.leads) == _supporting(many.leads) == expected
    assert len(_supporting(many.leads)) == len(_supporting(many.leads[:1])) == 4

    # Every repeating lead cites the one source family; none carries a doubled channel.
    for lead in many.leads:
        channels = [c.channel for c in lead.chips]
        assert len(channels) == len(set(channels))
        assert '1 source family' in next(c for c in lead.chips if c.channel == 'documentary').text

    # Observable consequence: equal independent support is a tie, so the lower CVE id stays first. Summing the
    # repeated lineage (3 leads x 4 channels = 12 > 4) would put the repeated group on top.
    assert [g.group for g in report.groups] == [FEW, MANY]
    assert [g.group for g in _report(baked, many=1).groups] == [FEW, MANY]
