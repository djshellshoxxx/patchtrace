"""SPEC-31 06 s5: the Diaphora source adapter over loaded, synthetic `diaphora/1` sets. Synthetic: no Diaphora, IDA or
Microsoft binary was run, so nothing here is live evidence of Diaphora's output."""
from __future__ import annotations

import random

import pytest
from unified_s0_fixtures import (
    NEW_SHA,
    OLD_SHA,
    addr_map,
    bd,
    bindiff_set,
    func,
    inputs,
    loaded,
    match,
    raw_ok,
    va,
)

from patchtrace.diaphora.contracts import DiaphoraMatch, DiaphoraMatchSet, DiaphoraUnmatched
from patchtrace.unified.contracts import Atom
from patchtrace.unified.fusion import arbiter
from patchtrace.unified.limits import Budget
from patchtrace.unified.sources import LoadedDiaphora, SourceAdapter
from patchtrace.unified.sources.diaphora import (
    DiaphoraAdapter,
    heuristic_class,
    read_loaded,
    source_ref_of,
    write_loaded,
)
from patchtrace.unified.sources.ghidriff import GhidriffAdapter

RESULT_SHA = 'e' * 64


def dm(index, older, newer, category='best', heuristic='Same name', ratio='0.980', status='verified-rva',
       older_name='old_fn', newer_name='new_fn') -> DiaphoraMatch:
    verified = status == 'verified-rva'
    return DiaphoraMatch(
        index=index, category=category, older_ea_text=f'{0x180000000 + older:x}', newer_ea_text=f'{0x180000000 + newer:x}',
        older_ea=0x180000000 + older, newer_ea=0x180000000 + newer, older_rva=older if verified else None,
        newer_rva=newer if verified else None, older_name=older_name, newer_name=newer_name, ratio_text=ratio,
        ratio_milli=min(1000, int(float(ratio) * 1000)),
        ratio_transform='capped-bonus' if float(ratio) > 1 else 'direct', older_nodes=5, newer_nodes=6,
        heuristic=heuristic, address_status=status)


def du(index, side, rva, status='verified-rva', name='lonely') -> DiaphoraUnmatched:
    return DiaphoraUnmatched(index=index, source_side='primary' if side == 'older' else 'secondary', side=side,
                             ea_text=f'{rva:x}', ea=0x180000000 + rva, rva=rva if status == 'verified-rva' else None,
                             name=name, address_status=status)


def dset(matches=(), unmatched=(), *, trust='manifest-bound', older=OLD_SHA, newer=NEW_SHA, result=RESULT_SHA):
    return DiaphoraMatchSet(engine_version='3.4.3', older_sha256=older, newer_sha256=newer, result_sha256=result,
                            trust=trust, matches=tuple(matches), unmatched=tuple(unmatched))


def dl(match_set, entry_id='dia-1') -> LoadedDiaphora:
    return LoadedDiaphora(entry_id=entry_id, match_set=match_set)


def data(*sets, **kw):
    import dataclasses
    return dataclasses.replace(inputs(**kw), diaphora=tuple(sets))


def run(*sets, **kw):
    return DiaphoraAdapter().atoms(data(*sets, **kw), addr_map(), Budget())


def test_adapter_follows_the_source_protocol():
    adapter = DiaphoraAdapter()
    assert isinstance(adapter, SourceAdapter) and adapter.available(inputs()).state == 'missing'
    assert adapter.available(data(dl(dset()))).state == 'ok'


def test_tiers_per_category_and_native_text():
    rows = [dm(0, 0x1000, 0x1080, 'best', ratio='1.010'), dm(1, 0x1200, 0x1280, 'partial', ratio='0.600'),
            dm(2, 0x1300, 0x1380, 'unreliable', ratio='0.200')]
    out = run(dl(dset(rows)))
    by = {(a.older_rva, a.newer_rva): a for a in out.atoms}
    assert {k: (a.tier, a.cardinality, a.source) for k, a in by.items()} == {
        (0x1000, 0x1080): ('B', '1:1', 'diaphora'), (0x1200, 0x1280): ('C', '1:1', 'diaphora'),
        (0x1300, 0x1380): ('C', '1:1', 'diaphora')}
    best = by[(0x1000, 0x1080)]
    assert best.step == 'Same name' and dict(best.native) == {'category': 'best', 'ratio': '1.010'}
    assert best.ref == 'dia-1:0' and out.groups == () and out.limitations == ()
    assert {(n.side, n.rva): n.name for n in out.nodes}[('older', 0x1000)] == 'old_fn'
    [ref] = out.source_refs
    assert (ref.source, ref.file_sha256) == ('diaphora', RESULT_SHA) and ref.version == '3.4.3+ad1'


def test_ratio_is_never_read_by_any_rule():
    def decisions(ratio):
        out = run(dl(dset([dm(0, 0x1000, 0x1080, ratio=ratio), dm(1, 0x1200, 0x1280, 'partial', ratio=ratio)])))
        return [(a.tier, a.cls, a.step, a.cardinality) for a in out.atoms]
    assert decisions('0.010') == decisions('1.010')


def test_unverified_addresses_are_skipped_and_counted():
    rows = [dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280, status='external-ea-only'),
            dm(2, 0x1300, 0x1380, status='ambiguous'), dm(3, 0x1400, 0x1480, status='ambiguous')]
    out = run(dl(dset(rows, [du(0, 'older', 0x1500, status='external-ea-only')])))
    assert [(a.older_rva, a.newer_rva) for a in out.atoms] == [(0x1000, 0x1080)]
    assert out.limitations == ('diaphora-ambiguous-address-skipped:2', 'diaphora-external-ea-skipped:2')


def test_unmatched_rows_are_one_sided_w_observations():
    out = run(dl(dset([], [du(0, 'older', 0x1400), du(1, 'newer', 0x1800)])))
    assert sorted((a.older_rva or 0, a.newer_rva or 0, a.tier, a.step) for a in out.atoms) == [
        (0, 0x1800, 'W', 'unmatched'), (0x1400, 0, 'W', 'unmatched')]
    assert {(a.older_rva is None, a.newer_rva is None) for a in out.atoms} == {(True, False), (False, True)}
    assert all(a.cls == 'E-UNKNOWN' for a in out.atoms)


def test_multimatch_becomes_one_group_and_a_lone_pair_a_plain_c_edge():
    rows = [dm(0, 0x1000, 0x1080, 'multimatch'), dm(1, 0x1000, 0x1100, 'multimatch'),
            dm(2, 0x1010, 0x1100, 'multimatch'), dm(3, 0x1600, 0x1700, 'multimatch')]
    out = run(dl(dset(rows)))
    assert [(a.older_rva, a.newer_rva, a.tier, a.cardinality) for a in out.atoms] == [(0x1600, 0x1700, 'C', '1:1')]
    [group] = out.groups
    assert (group.kind, group.source, group.decision) == ('diaphora-multimatch', 'diaphora', 'ambiguous')
    assert group.older == (0x1000, 0x1010) and group.newer == (0x1080, 0x1100)
    assert {(a.older_rva, a.newer_rva): a.cardinality for a in group.atoms} == {
        (0x1000, 0x1080): '1:N', (0x1000, 0x1100): 'N:M', (0x1010, 0x1100): 'N:1'}
    assert {a.tier for a in group.atoms} == {'C'}


@pytest.mark.parametrize('text,cls', [
    ('Pseudo-code fuzzy hash', 'E-DECOMP'), ('Equal pseudocode', 'E-DECOMP'), ('Microcode hash', 'E-DECOMP'),
    ('Graph isomorphism', 'E-CFG'), ('Same basic blocks', 'E-CFG'), ('Same name', 'E-UNKNOWN'),
    ('Pseudo-code graph hash', 'E-UNKNOWN'), ('', 'E-UNKNOWN')])
def test_evidence_class_comes_from_unambiguous_heuristic_text_only(text, cls):
    assert heuristic_class(text) == cls


def test_heuristic_step_is_sanitized_and_bounded():
    out = run(dl(dset([dm(0, 0x1000, 0x1080, heuristic='Same\x00 ‮name ' + 'x' * 200)])))
    [atom] = out.atoms
    assert len(atom.step) <= 64 and '\x00' not in atom.step and '‮' not in atom.step


def test_user_attested_set_is_display_only_one_sided_and_flagged():
    rows = [dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280, status='external-ea-only')]
    out = run(dl(dset(rows, [du(0, 'older', 0x1400)], trust='user-attested')))
    assert out.groups == () and out.nodes == ()
    assert all(None in (a.older_rva, a.newer_rva) and a.tier == 'W' and a.cls == 'E-UNKNOWN' for a in out.atoms)
    assert len(out.atoms) == 3 and all(dict(a.native)['unverified'] for a in out.atoms)
    assert out.limitations == ('diaphora-external-ea-skipped:1', 'diaphora-unverified-rows:2',
                               'diaphora-unverified-set')


def test_user_attested_set_never_supports_or_contests_a_row():
    """A misattributed attested set claims a different pairing for every function; nothing may change (R-15)."""
    ghid = match('g1', 'modified', [func('read_item', 0x1000)], [func('read_item', 0x1080)], types=['SymbolsHash'])
    ghid2 = match('g2', 'modified', [func('get_version', 0x1600)], [func('get_version', 0x1700)],
                  types=['ExactBytesFunctionHasher'])
    table = {va(0x1000): [[va(0x1080), ['SymbolsHash']]], va(0x1600): [[va(0x1700), ['ExactBytesFunctionHasher']]]}
    base = inputs([ghid, ghid2], raw_ok(table))
    wrong = dset([dm(0, 0x1000, 0x1700), dm(1, 0x1600, 0x1080)], trust='user-attested')
    import dataclasses
    with_dia = dataclasses.replace(base, diaphora=(dl(wrong),))
    g = GhidriffAdapter().atoms(base, addr_map(), Budget())
    d = DiaphoraAdapter().atoms(with_dia, addr_map(), Budget())
    plain = arbiter.decide(list(g.atoms), list(g.groups), None)
    mixed = arbiter.decide([*g.atoms, *d.atoms], [*g.groups, *d.groups], None)
    assert [(r.older, r.newer, r.decision, r.support, r.contest) for r in plain] == [
        (r.older, r.newer, r.decision, r.support, r.contest) for r in mixed if r.pair is not None]
    assert all(r.contest is None for r in mixed) and not any(r.decision == 'contested' for r in mixed)
    assert [r.decision for r in mixed if r.pair is not None] == ['matched', 'matched']


@pytest.mark.parametrize('older,newer,reversed_flag', [(NEW_SHA, OLD_SHA, True), ('1' * 64, '2' * 64, False)])
def test_other_pair_or_reversed_orientation_is_refused_but_stays_an_input(older, newer, reversed_flag):
    out = run(dl(dset([dm(0, 0x1000, 0x1080)], older=older, newer=newer)))
    assert out.atoms == () and out.groups == () and len(out.source_refs) == 1
    expected = ['diaphora-pair-mismatch'] + (['diaphora-orientation-reversed'] if reversed_flag else [])
    assert list(out.limitations) == sorted(expected)


def test_output_is_identical_under_input_permutation():
    rows = [dm(i, 0x1000 + 0x100 * i, 0x1080 + 0x100 * i, ('best', 'partial', 'unreliable')[i % 3],
               heuristic=('Same name', 'Pseudo-code fuzzy hash', 'Graph isomorphism')[i % 3]) for i in range(9)]
    rows += [dm(9, 0x3000, 0x3080, 'multimatch'), dm(10, 0x3000, 0x3100, 'multimatch'),
             dm(11, 0x3010, 0x3100, 'multimatch'), dm(12, 0x4000, 0x4080, status='external-ea-only')]
    unmatched = [du(0, 'older', 0x5000), du(1, 'newer', 0x5100), du(2, 'older', 0x5200, status='ambiguous')]
    second = dset([dm(0, 0x1000, 0x1080)], result='f' * 64)
    reference = run(dl(dset(rows, unmatched)), dl(second, 'dia-2'))
    rng = random.Random(7)
    for _ in range(5):
        shuffled_rows, shuffled_unmatched = rows[:], unmatched[:]
        rng.shuffle(shuffled_rows)
        rng.shuffle(shuffled_unmatched)
        sets = [dl(dset(shuffled_rows, shuffled_unmatched)), dl(second, 'dia-2')]
        rng.shuffle(sets)
        assert run(*sets) == reference


def test_source_ref_binds_content_and_trust_but_not_row_order():
    base = dl(dset([dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280)]))
    same = dl(dset([dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280)]))
    assert source_ref_of(base) == source_ref_of(same)
    changed = [dl(dset([dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1288)])),
               dl(dset([dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280)], trust='user-attested')),
               dl(dset([dm(0, 0x1000, 0x1080), dm(1, 0x1200, 0x1280)]), 'other-entry')]
    assert len({source_ref_of(base), *(source_ref_of(c) for c in changed)}) == 4


def test_worker_file_round_trip_and_tamper_refusal(tmp_path):
    from patchtrace.unified.limits import UnifiedError
    item = dl(dset([dm(0, 0x1000, 0x1080)], [du(0, 'older', 0x1400)]))
    path = tmp_path / 'diaphora-0.json'
    sha, size = write_loaded(path, item)
    back = read_loaded(path, expected_sha256=sha, expected_size=size)
    assert back.entry_id == 'dia-1' and back.match_set == item.match_set
    assert source_ref_of(back) == source_ref_of(item)
    for kwargs in ({'expected_sha256': '0' * 64, 'expected_size': size}, {'expected_sha256': sha, 'expected_size': size + 1}):
        with pytest.raises(UnifiedError) as caught:
            read_loaded(path, **kwargs)
        assert caught.value.code == 'PT-UNIFIED-INPUT'
    import hashlib
    for bad in (b'{"entry_id":"a","entry_id":"b","body_json":"{}"}', b'{"entry_id":"a","body_json":"{}"}',
                b'not json', b'{"entry_id":"a","body_json":"{}","extra":1}'):
        path.write_bytes(bad)
        with pytest.raises(UnifiedError) as caught:
            read_loaded(path, expected_sha256=hashlib.sha256(bad).hexdigest(), expected_size=len(bad))
        assert caught.value.code == 'PT-UNIFIED-INPUT' and caught.value.reason == 'diaphora-invalid'


def test_budget_is_ticked_per_row():
    class Spent(Budget):
        ticks = 0

        def tick(self, n=1):
            Spent.ticks += 1
            super().tick(n)
    DiaphoraAdapter().atoms(data(dl(dset([dm(i, 0x1000 + i, 0x2000 + i) for i in range(5)]))), addr_map(), Spent())
    assert Spent.ticks >= 5


# --- fusion with an agreeing Ghidriff edge ---------------------------------------------------------------------------------------

def test_agreeing_ghidriff_edge_is_one_independent_component_not_two():
    """F-DIAPHORA and F-GHIDRIFF share D_symbols/D_callgraph, so they are one component (K1): a Diaphora `best` (B)
    next to a Ghidriff B atom of the same class must not make the row `matched` by two-component corroboration."""
    ghid = match('g1', 'modified', [func('read_item', 0x1000)], [func('read_item', 0x1080)], types=['BSIM'])
    base = inputs([ghid], raw_ok({}))
    import dataclasses
    d = DiaphoraAdapter().atoms(dataclasses.replace(
        base, diaphora=(dl(dset([dm(0, 0x1000, 0x1080, heuristic='Pseudo-code fuzzy hash')])),)), addr_map(), Budget())
    g = GhidriffAdapter().atoms(base, addr_map(), Budget())
    [row] = [r for r in arbiter.decide([*g.atoms, *d.atoms], [], None) if r.pair == (0x1000, 0x1080)]
    assert {a.source for a in row.atoms} == {'ghidriff', 'diaphora'}
    assert [s.component for s in row.support] == ['K1'] and row.decision == 'tentative'
    # a genuinely independent source (K2 rz-diff is W only) is not needed here; the agreement stays one component
    assert len({s.component for s in row.support}) == 1


def test_diaphora_plus_bindiff_of_another_class_is_still_one_component():
    """Sanity of the class rule with the adapter's output: Diaphora E-DECOMP (K1) + BinDiff edges flowgraph (K1)
    are the same component, so even different classes do not make `matched`."""
    d = DiaphoraAdapter().atoms(data(dl(dset([dm(0, 0x1000, 0x1080, heuristic='Pseudo-code fuzzy hash')]))),
                                addr_map(), Budget())
    from patchtrace.unified.sources.secondary import SecondaryAdapter
    flow = bindiff_set([bd(0x1000, 0x1080, 'function: md index matching (flow graph, top down)')])
    b = SecondaryAdapter().atoms(inputs(secondary=[loaded(flow)]), addr_map(), Budget())
    [row] = arbiter.decide([*d.atoms, *b.atoms], [], None)
    assert [s.component for s in row.support] == ['K1'] and row.decision == 'tentative'


def test_atoms_validate_as_contract_atoms():
    out = run(dl(dset([dm(0, 0x1000, 0x1080)], [du(0, 'older', 0x1400)])))
    assert all(isinstance(a, Atom) and Atom.model_validate(a.model_dump()) == a for a in out.atoms)
