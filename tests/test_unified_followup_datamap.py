"""Follow-up A-30 (05 s2.7 rules 2, 3, 4(b)): DATA-MAP/1 soundness (p15) and orientation symmetry (p11).

p15: a coordinated retarget of several functions to an EXISTING global must never become COS-ADDR/1. By votes alone it
cannot be told from "that global moved and the others were retargeted", so the consensus abstains when a competing
claim with >= 2 voters is not explained as the dissent of another consensus (rule 3), and row r is judged by a strict
majority of the OTHER voters with at least one of them (rule 4(b)): r's own vote never tips the majority.
p11: a call operand votes only when neither target is in a matched pair, so `TargetMap(newer, older, mirrored pairs)` is
the mirror of `TargetMap(older, newer, pairs)`. Synthetic images only (hand-assembled through the real ingest, plus a
minimal in-memory reader stub for the property test); never live evidence.
"""
from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from unified_facts_builder import DATA_SECTIONS, NEW_SHA, OLD_SHA, build_reader, function, run_facts

from patchtrace.unified.facts.datamap import CONFLICT, MAPPED, UNMAPPED, TargetMap
from patchtrace.unified.ir.reader import RefRow

RET = ('ret',)
COS_ADDR = ('cosmetic', 'COS-ADDR/1')


def users(prefix, data, reg='EAX', *, count, base):
    """`count` tiny functions that each load the global `data` (they vote for its mapping)."""
    return [(f'{prefix}{i}', base + 0x40 * i, [('load_g', reg, data), RET]) for i in range(count)]


def image(tmp_path, label, specs, sym, sha):
    fns = [function(rva, items, name=name, sym=sym) for name, rva, items in specs]
    return build_reader(tmp_path, label, sorted(fns, key=lambda f: f['rva']), sha=sha)


def targets_of(tmp_path, old_specs, new_specs, old_sym, new_sym, *, sections=DATA_SECTIONS, **kwargs):
    old = image(tmp_path, 'old', old_specs, old_sym, OLD_SHA)
    new = image(tmp_path, 'new', new_specs, new_sym, NEW_SHA)
    names_new = {name: rva for name, rva, _ in new_specs}
    pairs = [(rva, names_new[name]) for name, rva, _ in old_specs if name in names_new]
    return TargetMap(old, new, pairs, older_sections=sections, newer_sections=sections, **kwargs)


def fns(specs, sym):
    return sorted((function(rva, items, name=name, sym=sym) for name, rva, items in specs), key=lambda f: f['rva'])


G_A, G_B = 0x3000, 0x3040
BOTH = {'g_a': G_A, 'g_b': G_B}              # both globals exist, at the same address, in both images


def retarget(count_f, count_g):
    """f0.. read g_a in the older image and g_b in the newer one (a coordinated retarget); g0.. read g_b on both sides
    (its genuine, unchanged referrers)."""
    old = users('f', 'g_a', count=count_f, base=0x1000) + users('g', 'g_b', 'ECX', count=count_g, base=0x1400)
    new = users('f', 'g_b', count=count_f, base=0x1000) + users('g', 'g_b', 'ECX', count=count_g, base=0x1400)
    return old, new


# --- p15: a coordinated retarget to an existing global -------------------------------------------------------------------

def test_p15_two_functions_retargeted_to_an_existing_global_never_prove_each_other(tmp_path):
    """p15: f0, f1 retarget g_a -> g_b, g_b keeps one unchanged referrer g0. The old rule mapped (g_a, g_b) for f0
    because f0 and f1 form the strict majority of g_b's voters and each counted the other. Carried by leave-one-out
    (rule 4(b)): without f0's vote, g_b's other voters are f1 (g_a) and g0 (g_b), a 1:1 tie (g0's dissent counts, g_b-old
    has no consensus), so consensus(g_b) fails; no competing claim blocks here (g0 is a single vote)."""
    old, new = retarget(2, 1)
    tm = targets_of(tmp_path, old, new, BOTH, BOTH)
    for voter in ((0x1000, 0x1000), (0x1040, 0x1040)):
        assert tm.data_state(G_A, G_B, voter) in (UNMAPPED, CONFLICT)
    assert tm.data_state(G_B, G_B, (0x1400, 0x1400)) != MAPPED
    run = run_facts(tmp_path, fns(old, BOTH), fns(new, BOTH))
    for name in ('f0', 'f1'):
        assert run.verdict(name) != COS_ADDR and run.facts(name).proof is None, (name, run.verdict(name))
        assert run.verdict(name)[0] in ('review', 'material')


def test_p15_three_retargets_beat_two_genuine_referrers_but_never_prove(tmp_path):
    """p15: three retargeting functions against two unchanged referrers of g_b. g_b's raw majority (3 of 5) is the
    retarget, but the competing claim (g_b, g_b) has two voters and its own raw consensus is g_b, so consensus(g_a) is
    blocked and nobody maps (g_a, g_b). The unchanged referrers g0, g1 stay `conflict` as before A-30: the u-side
    consensus(g_b) = g_a has no competing claim (g_a's voters claim nothing else), so they are its dissenters. That is a
    `review` with a data-ref delta, never a cosmetic proof; rule 4 as written prescribes it. Carried by the competing
    claim of rule 3: the claim (g_b, g_b) has two voters and raw consensus g_b, so it blocks consensus(g_a) = g_b
    (without f0 the others of g_a are 2:0 for g_b, so leave-one-out alone would not stop that direction; the u side of
    f0 is also a 2:2 tie among the others, and the full-table data_token is closed only by the claim)."""
    old, new = retarget(3, 2)
    tm = targets_of(tmp_path, old, new, BOTH, BOTH)
    for i in range(3):
        voter = (0x1000 + 0x40 * i, 0x1000 + 0x40 * i)
        assert tm.data_state(G_A, G_B, voter) in (UNMAPPED, CONFLICT)
    for i in range(2):
        voter = (0x1400 + 0x40 * i, 0x1400 + 0x40 * i)
        assert tm.data_state(G_B, G_B, voter) == CONFLICT
    assert tm.data_token('older', G_A) is None and tm.data_token('newer', G_B) is None
    run = run_facts(tmp_path, fns(old, BOTH), fns(new, BOTH))
    for name in ('f0', 'f1', 'f2', 'g0', 'g1'):
        assert run.verdict(name) != COS_ADDR and run.facts(name).proof is None, (name, run.verdict(name))
    for name in ('g0', 'g1'):
        assert run.verdict(name)[0] == 'review' and {d.cls for d in run.facts(name).deltas} == {'data-ref'}


def test_the_typical_patch_still_maps_the_innocent_and_flags_the_dissenter(tmp_path):
    """A-30 keeps the majority decision for a lone dissenter: r retargets g_a -> g_b while u0..u2 keep g_a, which
    moved. The u's map (COS-ADDR/1), r conflicts (a semantic data-ref delta)."""
    old = users('u', 'g_a', count=3, base=0x1400) + [('r', 0x1000, [('load_g', 'EAX', 'g_a'), RET])]
    new = users('u', 'g_a', count=3, base=0x1400) + [('r', 0x1000, [('load_g', 'EAX', 'g_b'), RET])]
    old_sym, new_sym = {'g_a': 0x3000, 'g_b': 0x3040}, {'g_a': 0x3100, 'g_b': 0x3040}
    tm = targets_of(tmp_path, old, new, old_sym, new_sym)
    for i in range(3):
        assert tm.data_state(0x3000, 0x3100, (0x1400 + 0x40 * i, 0x1400 + 0x40 * i)) == MAPPED
    assert tm.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == CONFLICT
    run = run_facts(tmp_path, fns(old, old_sym), fns(new, new_sym))
    for name in ('u0', 'u1', 'u2'):
        assert run.verdict(name) == COS_ADDR, (name, run.verdict(name))
    assert run.verdict('r')[0] == 'review' and {d.cls for d in run.facts('r').deltas} == {'data-ref'}


# --- leave-one-out (rule 4(b), literal) ---------------------------------------------------------------------------------

def test_leave_one_out_needs_one_other_voter_and_never_lets_r_tip_a_tie(tmp_path):
    """p15, rule 4(b): r is judged by the other voters only. One function alone never proves its own reference; two that
    agree (no competing claim) map each other; and when the others split 1:1, r's own vote never breaks the tie."""
    moved = ({'g_a': 0x3000}, {'g_a': 0x3080})
    one = targets_of(tmp_path, users('u', 'g_a', count=1, base=0x1400), users('u', 'g_a', count=1, base=0x1400), *moved)
    assert one.data_state(0x3000, 0x3080, (0x1400, 0x1400)) == UNMAPPED
    two = targets_of(tmp_path, users('u', 'g_a', count=2, base=0x1400), users('u', 'g_a', count=2, base=0x1400), *moved)
    assert all(two.data_state(0x3000, 0x3080, (0x1400 + 0x40 * i,) * 2) == MAPPED for i in range(2))
    assert two.data_token('older', 0x3000) == two.data_token('newer', 0x3080) is not None
    old = users('u', 'g_a', count=3, base=0x1400)
    new = [('u0', 0x1400, [('load_g', 'EAX', 'g_a'), RET]), ('u1', 0x1440, [('load_g', 'EAX', 'g_a'), RET]),
           ('u2', 0x1480, [('load_g', 'EAX', 'X'), RET])]
    split = targets_of(tmp_path, old, new, {'g_a': 0x3000}, {'g_a': 0x3080, 'X': 0x30c0})
    assert split.data_state(0x3000, 0x3080, (0x1400, 0x1400)) == UNMAPPED     # others: u1 -> g_a, u2 -> X, a tie


def test_two_innocent_referrers_beside_a_lone_explained_dissenter_keep_their_mapping(tmp_path):
    """Rule 4(b), explained dissent (A-30): u0, u1 keep g_a, f swaps g_a -> g_b, and g_b keeps its own referrers v0, v1.
    Without u0's vote, g_a's others are u1 (g_a) and f (g_b); f's vote is ignored because g_b has a full-table consensus
    (g_b) other than g_a, so u0 and u1 map; f is the conflict."""
    old = (users('u', 'g_a', count=2, base=0x1400) + users('v', 'g_b', 'ECX', count=2, base=0x1500)
           + [('f', 0x1000, [('load_g', 'EAX', 'g_a'), RET])])
    new = (users('u', 'g_a', count=2, base=0x1400) + users('v', 'g_b', 'ECX', count=2, base=0x1500)
           + [('f', 0x1000, [('load_g', 'EAX', 'g_b'), RET])])
    tm = targets_of(tmp_path, old, new, BOTH, BOTH)
    for rva in (0x1400, 0x1440):
        assert tm.data_state(G_A, G_A, (rva, rva)) == MAPPED
    for rva in (0x1500, 0x1540):
        assert tm.data_state(G_B, G_B, (rva, rva)) == MAPPED
    assert tm.data_state(G_A, G_B, (0x1000, 0x1000)) == CONFLICT


def test_a_dissent_whose_other_datum_has_no_consensus_still_counts(tmp_path):
    """Rule 4(b), p15 2+1 shape: f0, f1 retarget g_a -> g_b, g0 keeps g_b. Without f0, g_b-new's others are f1 (g_a)
    and g0 (g_b); g0's vote is NOT ignored because g_b-old has one voter and so no consensus: a tie, unmapped."""
    old, new = retarget(2, 1)
    tm = targets_of(tmp_path, old, new, BOTH, BOTH)
    assert tm._consensus('o', 'data', G_B) is None
    assert tm.data_state(G_A, G_B, (0x1000, 0x1000)) == UNMAPPED
    assert tm.data_state(G_A, G_B, (0x1040, 0x1040)) == UNMAPPED


def test_two_functions_that_disagree_with_a_third_never_prove_each_other(tmp_path):
    """p15: f0, f1 read g_a -> X, f2 reads g_a -> Y. The old rule mapped (g_a, X) for f0 (2 of 3); without its own
    vote f0 sees one X and one Y, no majority. f2 is the lone dissenter of the full-table consensus and conflicts."""
    old = users('f', 'g_a', count=3, base=0x1000)
    new = users('f', 'X', count=2, base=0x1000) + [('f2', 0x1080, [('load_g', 'EAX', 'Y'), RET])]
    tm = targets_of(tmp_path, old, new, {'g_a': 0x3000}, {'X': 0x3040, 'Y': 0x3080})
    assert tm.data_state(0x3000, 0x3040, (0x1000, 0x1000)) == UNMAPPED
    assert tm.data_state(0x3000, 0x3040, (0x1040, 0x1040)) == UNMAPPED
    assert tm.data_state(0x3000, 0x3080, (0x1080, 0x1080)) == CONFLICT


def test_p11_a_call_into_a_matched_newer_function_does_not_vote(tmp_path):
    """p11: a0..a2 call `tiny` (unpaired) in the older image and `paired` (in a matched row) in the newer one; b0..b2
    call `tiny` and `other`, an equal body. The a's must not vote: the mirrored run never lets them (there the target
    of the older side is in a pair), so with their votes the forward run saw a 3:3 tie where the mirror maps."""
    body, seven = [('xor_rr', 'EAX', 'EAX'), RET], [('mov_ri', 'EAX', 7), RET]
    group = lambda prefix, base, callee: [(f'{prefix}{i}', base + 0x40 * i, [('call', callee), RET])  # noqa: E731
                                          for i in range(3)]
    old = [('tiny', 0x1100, body), ('paired', 0x1200, seven), *group('a', 0x1400, 'tiny'), *group('b', 0x1500, 'tiny')]
    new = [('paired', 0x1100, seven), ('other', 0x1200, body), *group('a', 0x1400, 'paired'),
           *group('b', 0x1500, 'other')]
    older = image(tmp_path, 'old', old, {'tiny': 0x1100, 'paired': 0x1200}, OLD_SHA)
    newer = image(tmp_path, 'new', new, {'paired': 0x1100, 'other': 0x1200}, NEW_SHA)
    caller_pairs = [(base + 0x40 * i,) * 2 for base in (0x1400, 0x1500) for i in range(3)]
    forward = TargetMap(older, newer, [*caller_pairs, (0x1200, 0x1100)])
    mirror = TargetMap(newer, older, [*caller_pairs, (0x1100, 0x1200)])
    assert mirror.function_state(0x1200, 0x1100) == MAPPED          # the b's are the consensus of `other`/`tiny`
    for voter in (None, *caller_pairs):
        assert forward.function_state(0x1100, 0x1200, voter) == mirror.function_state(0x1200, 0x1100, voter), voter


# --- the orientation property --------------------------------------------------------------------------------------------

class _Functions:
    def __init__(self, rows):
        self.rows = rows
        self.rva_to_fid = {row['rva']: fid for fid, row in enumerate(rows)}
        self.import_key = [None] * len(rows)
        self.n = len(rows)

    def get(self, column, fid):
        return self.rows[fid].get(column)


class StubReader:
    """The part of `IrReader` `TargetMap` reads without strings: `functions.rva_to_fid`, `functions.get(h1|h0|kind|
    thunk_target)`, `functions.import_key`, `refs(fid)`."""

    def __init__(self, rows):
        self.functions = _Functions(rows)

    def refs(self, fid):
        return self.functions.rows[fid]['refs']


OLD_DATA = (0x3000, 0x3040, 0x3080, 0x30c0)
NEW_DATA = (0x3000, 0x3040, 0x3080, 0x3100, 0x3140)
SECTION_CHOICES = ((), ((0x3000, 0x3200),), ((0x3000, 0x3080), (0x3080, 0x3200)))


@st.composite
def vote_tables(draw):
    count = draw(st.integers(2, 6))
    old_rvas = [0x1000 + 0x40 * i for i in range(count)]
    new_rvas = [0x1000 + 0x40 * i + draw(st.sampled_from((0, 0x800))) for i in range(count)]
    callees = draw(st.integers(0, 2))
    old_callees = [0x1800 + 0x40 * j for j in range(callees)]
    new_callees = [0x1900 + 0x40 * j for j in range(callees)]
    code_old, code_new = old_callees + old_rvas, new_callees + new_rvas
    old_rows, new_rows = [], []
    for o, n in zip(old_rvas, new_rvas, strict=True):
        refs_old, refs_new = [], []
        for k in range(draw(st.integers(1, 3))):
            if code_old and draw(st.booleans()):              # mostly unpaired callees, sometimes a paired function
                a = draw(st.sampled_from(old_callees or code_old) if draw(st.integers(0, 3)) else st.sampled_from(code_old))
                b = draw(st.sampled_from(new_callees or code_new) if draw(st.integers(0, 3)) else st.sampled_from(code_new))
                kind = 'code'
            else:
                a, b, kind = draw(st.sampled_from(OLD_DATA)), draw(st.sampled_from(NEW_DATA)), 'data'
            refs_old.append(RefRow(k, 0, kind, a, None))
            refs_new.append(RefRow(k, 0, kind, b, None))
        h1_new = 1 if draw(st.integers(0, 5)) else 2
        old_rows.append({'rva': o, 'h1': 1, 'h0': 10 + o, 'kind': 0, 'refs': refs_old})
        new_rows.append({'rva': n, 'h1': h1_new, 'h0': 10 + n, 'kind': 0, 'refs': refs_new})
    h0s = st.sampled_from((1, 2))
    old_rows += [{'rva': c, 'h1': 0, 'h0': draw(h0s), 'kind': 0, 'refs': []} for c in old_callees]
    new_rows += [{'rva': c, 'h1': 0, 'h0': draw(h0s), 'kind': 0, 'refs': []} for c in new_callees]
    pairs = list(zip(old_rvas, new_rvas, strict=True))
    if draw(st.integers(0, 4)) == 0:
        pairs.append((draw(st.sampled_from(old_rvas)), draw(st.sampled_from(new_rvas))))   # a contradictory row
    sections = (draw(st.sampled_from(SECTION_CHOICES)), draw(st.sampled_from(SECTION_CHOICES)))
    return old_rows, new_rows, pairs, sections, code_old, code_new


@settings(max_examples=300, deadline=None, derandomize=True, database=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(vote_tables())
def test_p11_p15_target_map_is_orientation_symmetric(table):
    """p11 (04 s9 style, over a reader stub): swapping the images and mirroring the pairs mirrors every answer of
    `data_state`, `function_state` and `data_token`."""
    old_rows, new_rows, pairs, (sections_old, sections_new), code_old, code_new = table
    older, newer = StubReader(old_rows), StubReader(new_rows)
    forward = TargetMap(older, newer, pairs, older_sections=sections_old, newer_sections=sections_new)
    mirror = TargetMap(newer, older, [(n, o) for o, n in pairs], older_sections=sections_new,
                       newer_sections=sections_old)
    voters = [None, *sorted(set(pairs))]
    for voter in voters:
        flipped = None if voter is None else (voter[1], voter[0])
        for t in OLD_DATA:
            for u in NEW_DATA:
                assert forward.data_state(t, u, voter) == mirror.data_state(u, t, flipped), (t, u, voter)
        for t in code_old:
            for u in code_new:
                assert forward.function_state(t, u, voter) == mirror.function_state(u, t, flipped), (t, u, voter)
    for t in OLD_DATA:
        token = forward.data_token('older', t)
        assert token == mirror_label(mirror.data_token('newer', t)), t
    for u in NEW_DATA:
        assert forward.data_token('newer', u) == mirror_label(mirror.data_token('older', u)), u


def mirror_label(token):
    """`@D:<t>.<u>` of the mirrored run is `@D:<u>.<t>` of the forward one."""
    if token is None:
        return None
    first, second = token[3:].split('.')
    return f'@D:{second}.{first}'
