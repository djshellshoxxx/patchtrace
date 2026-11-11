"""LBL s5 acceptance: the hand-written `synergy-1` fixture reproduces the plan's numbers through evalcore."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.calibration.evalcore import boot, change, descriptors, identity, protocols, rank
from tools.calibration.tier_r import contracts as C

FIXTURE = Path(__file__).parent / 'fixtures' / 'known_answer' / 'synergy-1'
ID = {'f01': 0x1000, 'f02': 0x1010, 'f03': 0x1020, 'f04': 0x1030, 'f05': 0x1040, 'f06': 0x1050, 'f08': 0x1060,
      'f09': 0x1070, 'f10': 0x1080, 'f07': 0x1090, 'f11': 0x10A0, 'f12': 0x10C0}
NAME = {rva: name for name, rva in ID.items()}


@pytest.fixture(scope='module')
def labels() -> C.KnownAnswerLabels:
    return C.load_labels((FIXTURE / 'labels.json').read_bytes())


@pytest.fixture(scope='module')
def engines() -> dict[str, protocols.EnginePairs]:
    doc = json.loads((FIXTURE / 'engines.json').read_text(encoding='utf-8'))
    return {e['engine']: protocols.pairs_from_doc(e) for e in doc['engines']}


@pytest.fixture(scope='module')
def capa() -> dict[int, int]:
    doc = json.loads((FIXTURE / 'channels.json').read_text(encoding='utf-8'))
    return {row['rva']: len(row['rules']) for row in doc['capa']['behaviour_deltas']}


def _flagged_names(pairs) -> list[str]:
    ranks = change.flagged_ranks(pairs)
    return [NAME[old] for (old, _), _r in sorted(ranks.items(), key=lambda kv: (kv[1], kv[0]))]


# plan s5 table: engine -> (flagged list, rank of f07, hit@1, hit@3, RR, nDCG@10)
TABLE = {
    'ghidriff': (['f09', 'f05', 'f11', 'f07', 'f03'], 4, 0, 0, 0.25, 0.4307),
    'rz-diff': (['f05', 'f11', 'f07', 'f09', 'f03', 'f01'], 3, 0, 1, 1 / 3, 0.5),
    'unified': (['f10', 'f07', 'f02'], 2, 0, 1, 0.5, 0.6309),
}


def test_fixture_is_a_valid_one_lineage_label_document(labels):
    assert labels.lineage == 'L-synergy-1' and len(labels.functions) == 12
    assert labels.summary.by_label == {'changed': 1, 'cosmetic': 1, 'no-counterpart': 1, 'unchanged': 9}
    assert labels.case['declared_changed'] == ['read_len']


@pytest.mark.parametrize('engine', list(TABLE), ids=list(TABLE))
def test_synergy_ranks_are_hand_computed(engines, engine):
    flagged, r, h1, h3, rr, ndcg = TABLE[engine]
    pairs = engines[engine]
    assert _flagged_names(pairs) == flagged
    got = rank.pair_metrics(change.flagged_ranks(pairs)[(ID['f07'], ID['f07'])])
    assert got['rank'] == r and (got['hit@1'], got['hit@3']) == (h1, h3)
    assert got['rr'] == pytest.approx(rr, abs=1e-12) and round(got['ndcg'], 4) == ndcg
    assert change.pool_size(pairs) == len(flagged)


def _combined(unified: protocols.EnginePairs, capa: dict[int, int]) -> list[str]:
    """Plan s5 ordinal rule (no scores): material+delta, material, review+delta, review; ties by RVA."""
    rows = []
    for pair in unified.pairs:
        if pair.flag:
            tier = pair.order_key[0]  # 0 material, 1 review
            rows.append(((tier * 2 + (0 if pair.old_rva in capa else 1)), pair.old_rva))
    return [NAME[rva] for _, rva in sorted(rows)]


def test_combined_beats_each_channel_alone(engines, capa):
    combined = _combined(engines['unified'], capa)
    assert combined == ['f07', 'f10', 'f02']
    got = rank.pair_metrics(rank.rank_map({n: i for i, n in enumerate(combined)})['f07'])
    assert (got['rank'], got['hit@1'], got['rr'], got['ndcg']) == (1, 1, 1.0, 1.0)
    capa_list = sorted(capa, key=lambda rva: (-capa[rva], rva))
    assert [NAME[r] for r in capa_list] == ['f02', 'f07']
    capa_m = rank.pair_metrics(rank.rank_map({NAME[r]: i for i, r in enumerate(capa_list)})['f07'])
    assert (capa_m['rank'], capa_m['hit@3'], round(capa_m['ndcg'], 4)) == (2, 1, 0.6309)
    others = [rank.pair_metrics(change.flagged_ranks(engines[e])[(ID['f07'], ID['f07'])])['ndcg'] for e in TABLE]
    assert all(got['ndcg'] > o for o in [*others, capa_m['ndcg']])


# per-label expectations (9 truth-unchanged functions): false leads, cosmetic f03, changed recall, f12
LEADS = {'ghidriff': 3, 'rz-diff': 4, 'unified': 2}
COSMETIC_FLAGGED = {'ghidriff': 1, 'rz-diff': 1, 'unified': 0}


@pytest.mark.parametrize('engine', list(LEADS), ids=list(LEADS))
def test_per_label_false_leads_exact(labels, engines, engine):
    counts = change.count_by_label(identity.classify(labels.functions, engines[engine]))
    unchanged = counts['unchanged']
    assert (unchanged.paired_correct, unchanged.flagged) == (9, LEADS[engine])
    assert change.flag_rate(unchanged) == LEADS[engine] / 9
    assert counts['cosmetic'].paired_correct == 1 and counts['cosmetic'].flagged == COSMETIC_FLAGGED[engine]
    changed = counts['changed']
    assert (changed.paired_correct, changed.flagged) == (1, 1) and change.flag_rate(changed) == 1.0
    assert (counts['no-counterpart'].unpaired, counts['no-counterpart'].paired_wrong) == (1, 0)
    assert all(c.paired_wrong == 0 and c.abstained == 0 for c in counts.values())


def test_swapped_pairing_is_counted_wrong_not_dropped(labels, engines):
    swapped = [p for p in engines['rz-diff'].pairs if p.old_rva not in (ID['f01'], ID['f02'])]
    swapped += [protocols.EnginePair(ID['f01'], ID['f02'], False, 1.0, None),
                protocols.EnginePair(ID['f02'], ID['f01'], False, 1.0, None)]
    pairs = protocols.EnginePairs('rz-diff', 'v', 'hidden', tuple(swapped))
    unchanged = change.count_by_label(identity.classify(labels.functions, pairs))['unchanged']
    assert (unchanged.paired_correct, unchanged.paired_wrong) == (7, 2)


def test_report_is_deterministic_under_row_order(labels, engines):
    pairs = engines['unified']
    flipped = protocols.EnginePairs(pairs.engine, pairs.version, pairs.symbols, tuple(reversed(pairs.pairs)))
    assert identity.classify(labels.functions, pairs) == identity.classify(labels.functions, flipped)
    assert change.flagged_ranks(pairs) == change.flagged_ranks(flipped)


def test_channel_gate_insufficient_with_one_lineage(labels):
    obs = {labels.pair_id: (labels.lineage, 1.0)}
    delta = boot.paired_delta_bootstrap(obs, {labels.pair_id: (labels.lineage, 0.0)}, 200)
    assert delta.anti_conservative and boot.non_inferior(delta, -0.02) is None
    assert not boot.headline_ok(1)


def test_shift_block_hand_computed(labels):
    # 23 sizes: f01..f11 are 32+8k on both sides (f07: 88 -> 104), f12 is new-only at 128
    size_range = descriptors.reference_size_range([labels])
    assert size_range == (40, pytest.approx(120 + 0.978 * 8))
    block = descriptors.shift_block([labels], size_range)
    q = block.descriptors['function-size']
    assert (q.n, q.q05, q.q25, q.q50, q.q75, q.q95) == (23, pytest.approx(40.8), 60, 80, 104, 120)
    ratio = block.descriptors['size-ratio']
    assert (ratio.n, ratio.q50, ratio.q95) == (11, 1.0, pytest.approx(1 + (104 / 88 - 1) * 0.5))
    assert block.shares == {'size-outside': pytest.approx(1 / 12), 'thunk': 0.0, 'n9': 0.0}
    assert block.n_lineages == 1
