"""G-L7: paired engine-vs-engine deltas persisted in `tier-r-report/1` (additive `deltas`), and the L4 residual
(non-inferiority sizing at the one-sided level the decision rule actually uses). Synthetic fixture output only: never
live evidence, and the numbers are dev-only and ordinal."""
from __future__ import annotations

import copy
import dataclasses
import inspect
import json
import math
from pathlib import Path
from statistics import NormalDist

import pytest

from patchtrace.calibration.scope import BANNED_STEMS
from tools.calibration.common import digest
from tools.calibration.evalcore import boot, power
from tools.calibration.evalcore import report as ER
from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import evaluate as E
from tools.calibration.tier_r import schemas as S
from tools.calibration.tier_r import shard as SH

FIXTURE = Path(__file__).parent / 'fixtures' / 'known_answer' / 'synergy-1'
# report_sha256 of the single-engine (rz-diff) synergy-1 report at b_count=100, pinned on the base before `deltas`
# existed: a report without deltas must keep its exact bytes and digest.
SINGLE_ENGINE_SHA = '1a7eb24a5b112981c69551e4591465fbab643607c7bf97647ffdd2d45b6b8dd4'
KEY = 'rz-diff vs ghidriff'


def _labels() -> C.KnownAnswerLabels:
    return C.load_labels((FIXTURE / 'labels.json').read_bytes())


def _output(name: str) -> E.EngineOutput:
    """Synthetic engine output rebuilt from the hand-written fixture rows (never live evidence)."""
    doc = {e['engine']: e for e in json.loads((FIXTURE / 'engines.json').read_text(encoding='utf-8'))['engines']}[name]
    paired = [r for r in doc['pairs'] if r['identity'] == 'paired']
    keyed = name == 'unified'
    return E.EngineOutput(
        name, 'ok', version=doc['version'],
        predictions=tuple(E.Prediction(r['old_rva'], r['new_rva'], r['flag'],
                                       None if r['native'] is None else round(r['native'] * 1000),
                                       old_name=r['order_key'][1] if r['order_key'] and not keyed else None,
                                       order_key=tuple(r['order_key']) if keyed and r['order_key'] else None)
                          for r in paired),
        new_only=frozenset(r['new_rva'] for r in doc['pairs'] if r['identity'] == 'unpaired'),
        implicit_unchanged=doc['implicit_unchanged'])


def _providers(*names: str) -> list:
    return [E.StaticProvider(n, {_labels().pair_id: _output(n)}) for n in names]


def _copy(suffix: str) -> C.KnownAnswerLabels:
    doc = _labels().model_dump(mode='json')
    doc.update(pair_id=f'synergy-1-{suffix}', lineage=f'L-synergy-1-{suffix}', digest_sha256='0' * 64)
    return C.load_labels(C.dump_json(C.finalize_labels(doc)))


def _three_lineages() -> tuple[list[C.KnownAnswerLabels], list]:
    """Three lineages; on the third rz-diff flags nothing, so the per-lineage deltas differ and sd is defined."""
    docs = [_labels(), _copy('b'), _copy('c')]
    rz, quiet = _output('rz-diff'), _output('rz-diff')
    quiet = dataclasses.replace(quiet, predictions=tuple(dataclasses.replace(p, changed=False)
                                                         for p in quiet.predictions))
    return docs, [E.StaticProvider('ghidriff', {d.pair_id: _output('ghidriff') for d in docs}),
                  E.StaticProvider('rz-diff', {docs[0].pair_id: rz, docs[1].pair_id: rz, docs[2].pair_id: quiet})]


def _with_deltas() -> dict:
    return E.evaluate([_labels()], _providers('ghidriff', 'rz-diff'), b_count=20)


def _load(doc: dict) -> C.TierRReport:
    return C.load_report(C.dump_json(doc))


# ---- persisted ---------------------------------------------------------------------------------------------------

def test_two_engine_report_persists_the_returned_delta():
    doc, deltas = E.evaluate_full([_labels()], _providers('ghidriff', 'rz-diff'), b_count=100)
    summary = deltas['cve']['real-fix'][KEY]['ndcg']
    cell = doc['deltas']['cve']['real-fix'][KEY]['ndcg']
    expected = {f.name: getattr(summary, f.name) for f in dataclasses.fields(summary)}
    expected['delta'] = summary.delta.model_dump(mode='json')
    assert cell == expected
    assert doc['deltas'] == ER.delta_fields(deltas)  # the whole returned block is what the report persists
    assert set(doc['deltas']['cve']['real-fix'][KEY]) == {'hit@10', 'ndcg'}
    assert cell['delta']['anti_conservative'] and cell['non_inferior'] is None  # one lineage: never a claim


def test_report_with_deltas_round_trips_through_load_report():
    docs, providers = _three_lineages()
    doc = E.evaluate(docs, providers, b_count=50)
    loaded = _load(doc)
    cell = loaded.deltas['cve']['real-fix'][KEY]['ndcg']
    assert isinstance(cell, C.DeltaCell) and (cell.pairs, cell.lineages) == (3, 3)
    assert cell.sd is not None and cell.sd > 0 and cell.min_detectable is not None and cell.power is not None
    assert loaded.model_dump(mode='json')['deltas'] == doc['deltas']
    assert loaded.report_sha256 == doc['report_sha256']


def test_single_engine_report_has_no_deltas_key_and_keeps_its_digest():
    doc = E.evaluate([_labels()], _providers('rz-diff'), b_count=100)
    assert 'deltas' not in doc and b'"deltas"' not in C.dump_json(doc)
    assert doc['report_sha256'] == SINGLE_ENGINE_SHA
    assert _load(doc).deltas is None


def test_finalize_drops_a_none_deltas_key():
    doc = E.evaluate([_labels()], _providers('rz-diff'), b_count=100)
    again = E.finalize_report({**doc, 'deltas': None})
    assert 'deltas' not in again and again['report_sha256'] == SINGLE_ENGINE_SHA


def test_report_with_deltas_is_byte_identical_across_runs():
    docs, providers = _three_lineages()
    first = E.evaluate(docs, providers, b_count=50)
    second = E.evaluate(list(reversed(docs)), list(reversed(providers)), b_count=50)
    assert 'deltas' in first and C.dump_json(first) == C.dump_json(second)


# ---- rejected keys -----------------------------------------------------------------------------------------------

def _rename(old: str, new: str):
    def mutate(deltas: dict) -> None:
        per = deltas['cve']['real-fix']
        per[new] = per.pop(old)
    return mutate


def _cells(fn):
    def mutate(deltas: dict) -> None:
        fn(deltas['cve']['real-fix'][KEY])
    return mutate


LITERAL_METRIC = "Input should be 'hit@10' or 'ndcg'"


@pytest.mark.parametrize('mutate, match', [
    (_rename(KEY, 'ghidriff vs rz-diff'), 'comparison'),
    (_rename(KEY, 'rz-diff vs rz-diff'), 'comparison'),
    (_rename(KEY, 'rz-diff vs ida'), 'comparison'),
    (_rename(KEY, 'rz-diff/ghidriff'), 'comparison'),
    (_rename(KEY, ' rz-diff vs ghidriff'), 'comparison'),
    (_cells(lambda c: c.update(mrr={**c['ndcg'], 'metric': 'mrr'})), LITERAL_METRIC),
    (_cells(lambda c: c.update({'hit@1': {**c['ndcg'], 'metric': 'hit@1'}})), LITERAL_METRIC),
    (_cells(lambda c: c.update({'hit@10': copy.deepcopy(c['ndcg'])})), 'does not match its cell'),
    (lambda d: d.update(windows=d.pop('cve')), 'unknown stratum'),
    (lambda d: d['cve'].update(pooled=d['cve'].pop('real-fix')), "'real-fix' or 'planted'"),
    (_cells(lambda c: c['ndcg'].update(non_inferior=True)), 'non_inferior needs'),
    (_cells(lambda c: c['ndcg'].update(power=1.5)), 'less than or equal to 1'),
    (_cells(lambda c: c['ndcg'].update(lineages=c['ndcg']['pairs'] + 1)), 'more lineages than pairs'),
], ids=['reversed', 'self', 'unknown-engine', 'format', 'padded', 'metric-mrr', 'metric-hit1', 'metric-mismatch',
        'stratum', 'population', 'ni-anti', 'power-range', 'lineages-gt-pairs'])
def test_bad_delta_sections_are_rejected(mutate, match):
    doc = _with_deltas()
    _load(doc)  # the unmutated document is valid
    mutate(doc['deltas'])
    doc['report_sha256'] = digest(doc, 'report_sha256')
    with pytest.raises(C.ContractError, match='report invalid') as caught:
        _load(doc)
    assert match in str(caught.value)


def test_every_ordered_engine_pair_is_a_valid_key():
    engines = E.ENGINE_ORDER
    doc = _with_deltas()
    cells = doc['deltas']['cve']['real-fix'][KEY]
    doc['deltas']['cve']['real-fix'] = {f'{a} vs {b}': cells for i, a in enumerate(engines) for b in engines[i + 1:]}
    doc['report_sha256'] = digest(doc, 'report_sha256')
    assert len(_load(doc).deltas['cve']['real-fix']) == 10


def test_schema_examples_cover_deltas():
    examples = S.examples()
    assert examples['valid-report-deltas.json']['deltas']
    assert _load(examples['valid-report-deltas.json']).deltas is not None
    with pytest.raises(C.ContractError, match='comparison'):
        _load(examples['invalid-report-deltas-reversed.json'])
    assert 'ghidriff vs rz-diff' in json.dumps(examples['invalid-report-deltas-reversed.json'])


# ---- Markdown ----------------------------------------------------------------------------------------------------

def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find('\n## ', start + 1)
    return text[start:] if end < 0 else text[start:end]


def test_markdown_has_the_paired_delta_table_and_no_percent():
    text = E.render_markdown(_with_deltas())
    section = _section(text, '## Paired deltas')
    assert ('| stratum | population | comparison | metric | pairs | lineages | delta [lo, hi] | sd | MDD | '
            'observed power | NI | anti-conservative |') in section
    assert '| cve | real-fix | rz-diff vs ghidriff | ndcg | 1 | 1 | 0.069 [0.069, 0.069] | n/a | n/a | n/a | n/a | yes |' \
        in section
    assert '| cve | real-fix | rz-diff vs ghidriff | hit@10 | 1 | 1 |' in section
    assert E.POWER_NOTE in section and 'Hoenig & Heisey 2001' in E.POWER_NOTE
    assert 'never evidence of no difference' in E.POWER_NOTE
    assert '%' not in text
    assert not [s for s in BANNED_STEMS if s in section.lower()]


def test_markdown_shows_sd_mdd_and_power_when_defined():
    docs, providers = _three_lineages()
    doc = E.evaluate(docs, providers, b_count=50)
    cell = doc['deltas']['cve']['real-fix'][KEY]['ndcg']
    row = next(line for line in _section(E.render_markdown(doc), '## Paired deltas').splitlines()
               if line.startswith(f'| cve | real-fix | {KEY} | ndcg |'))
    cols = [c.strip() for c in row.strip('|').split('|')]
    assert cols[4:6] == ['3', '3']
    assert cols[7:10] == [f'{cell["sd"]:.3f}', f'{cell["min_detectable"]:.3f}', f'{cell["power"]:.3f}']
    assert cols[10:] == ['n/a', 'yes']


def test_markdown_without_deltas_has_no_delta_section():
    text = E.render_markdown(E.evaluate([_labels()], _providers('rz-diff'), b_count=20))
    assert '## Paired deltas' not in text


# ---- shard merge -------------------------------------------------------------------------------------------------

def _shard(i: int, reports: list) -> dict:
    doc = {'contract': SH.SHARD_CONTRACT, 'shard': i, 'of': 2, 'seed': 1, 'plan_sha256': 'b' * 64, 'subset': 'smoke',
           'engines': ['ghidriff', 'rz-diff'], 'cases': [], 'labels': [], 'features': [], 'reports': reports}
    doc['shard_sha256'] = SH.digest(doc, 'shard_sha256')
    return doc


def test_shard_merge_leaves_deltas_out_and_still_validates():
    """Lineage bootstraps cannot be recombined from shard reports, so the aggregate carries no `deltas`."""
    a, b = _labels(), _copy('b')
    reports = [E.evaluate([d], [E.StaticProvider(n, {d.pair_id: _output(n)}) for n in ('ghidriff', 'rz-diff')],
                          b_count=20) for d in (a, b)]
    assert all('deltas' in r for r in reports)
    merged, _ = SH.merge([_shard(0, [reports[0]]), _shard(1, [reports[1]])])
    assert 'deltas' not in merged
    loaded = C.load_report(json.dumps(merged).encode())
    assert loaded.deltas is None and len(loaded.inputs) == 2


# ---- L4 residual: non-inferiority sizing -------------------------------------------------------------------------

def test_ni_alpha_is_the_one_sided_level_of_the_decision_interval():
    """`boot.non_inferior` reads the lower bound of the two-sided 95% interval: a one-sided test at 0.025 (ICH E9 5.5)."""
    two_sided = inspect.signature(boot.paired_delta_bootstrap).parameters['alpha'].default
    assert power.NI_ALPHA == two_sided / 2 == 0.025
    assert inspect.signature(power.noninferiority_lineages).parameters['alpha'].default == power.NI_ALPHA


@pytest.mark.parametrize('margin, true_delta, sd', [(-0.02, 0.0, 0.1), (-0.05, 0.01, 0.2), (-0.1, -0.02, 0.35)],
                         ids=['m02', 'm05', 'm10'])
def test_noninferiority_sizing_reaches_power_under_the_0025_rule(margin, true_delta, sd):
    n = power.noninferiority_lineages(margin, true_delta, sd)
    z = NormalDist()
    achieved = z.cdf((true_delta - margin) * math.sqrt(n) / sd - z.inv_cdf(0.975))
    assert achieved >= 0.8
    assert power.power_for_delta(true_delta - margin, n, sd, alpha=power.NI_ALPHA, one_sided=True) >= 0.8
