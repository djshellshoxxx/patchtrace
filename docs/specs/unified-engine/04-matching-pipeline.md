# SPEC-31 / 04 L1 matching pipeline: pass ladder, propagation, residual alignment

Purpose: from two `IrReader`s produce a `Correspondence` (1:1 pairs with per-pair provenance, N:M groups, one-sided leftovers) with precision first and abstention on ambiguity. It produces atoms of sources `pt-ladder` and `pt-bytes`; it never sees other engines' output except tier-M manual anchors (fusion happens later, 05). Owner slices S2 (ladder MVP, propagation, groups) and S5 (residual). Numbers: L-xx (02 s6). Sources of the ideas: R02 s3-s6 (BinDiff), R03 s1 (Ghidriff/VT), R04 s1-s5 (prior art).

**S5 status (2026-10-14):** s6 (residual) is BUILT in `ladder/{blocking,assign,residual}.py` as `PassSpec.run` rows at stages 5 (P16-P18) and 6 (P19); `pass_table(residual=False)` is the B-07 fallback and equals the S2 table. Synthetic evidence only; the choices the text leaves open (token vocabulary, split chain, exact integer arithmetic, majority and margin rules, P19 buckets) are listed in `docs/modules.md` [S5:residual]. The assignment bucket cap is L-24 (01 s2 says L-31). Open: per-pass precision on real IR (G-U3) and G-U5 on Windows.

## 1. Contract
```python
def run_ladder(older: IrReader, newer: IrReader, *, anchors: Sequence[CorrPair], limits: UnifiedLimits,
               budget: Budget, passes: Sequence[PassSpec] = PASSES) -> Correspondence: ...
```
Invariants: (I1) every function appears in at most one 1:1 pair OR one group, never both; (I2) a pair exists only if its key was unique among the still-unmatched functions of the pool it was evaluated in (global or neighbour set); (I3) an accepted pair is never re-opened (BinDiff greedy, R02 s9); (I4) output is a pure function of (IR content digests, anchors, pass table, limits): byte-identical across runs and OSes; (I5) tier-M anchors win over every pass; (I6) thunks, imports and tiny functions (L-10) are never matched by content keys; (I7) work is bounded by `Budget` (cancel + deadline checked every 4,096 units) -> on exhaustion the result is `partial` with the passes completed so far.

## 2. Keys computed at ingest (`ir/features.py`, `ir/mdindex.py`)
- Hashes `h0..h3`, `hm`, `hms` as defined in 02 s3 (64-bit blake2b; collision probability per pair ~2^-64).
- MD index (port of BinDiff v8 `graph_util.h`/`flow_graph.cc`, Apache-2.0, attribution in the module header, 09 s2):
```python
SQ = (sqrt(2), sqrt(3), sqrt(5), sqrt(7), sqrt(11), sqrt(13))      # math.sqrt is correctly rounded on every IEEE-754 platform
def md_index(vertices, edges, *, bottom_up=False) -> float:
    level = bfs_levels(vertices, edges, reverse=bottom_up)           # roots: in-degree 0 (top-down) / out-degree 0 (bottom-up)
    terms = sorted(1.0 / (SQ[0]*indeg[s] + SQ[1]*outdeg[s] + SQ[2]*indeg[t] + SQ[3]*outdeg[t]
                          + SQ[4]*level[s] + SQ[5]*level[t]) for (s, t) in edges)
    total = 0.0
    for x in terms: total += x                                       # plain loop: Python 3.12 sum() is compensated (C-16)
    return total
key = round(md_index(...) * 10**12)                                  # NULL when n_bb < L-11
```
  Parity quirks kept behind `bindiff_quirks=True` (default, documented in the module): level 0 doubles as "unvisited", a graph without an in-degree-0 vertex keeps all top-down levels 0, duplicate/self edges counted as BinDiff counts them (R02 s6). Test vector: diamond A->B, A->C, B->D, C->D -> 0.277559753195558 (R02 s6, hand-computed) and, when BinDiff is installed, `bindiff --md_index` dumps (parity gate G-U3).
- Call-graph MD per function: sum of the stored MD of its incident call-graph edges (BinDiff call-graph vertex MD); hubs (fan-in > L-17) included as in BinDiff but the key is tier B only.

## 3. Driver (BinDiff drill-down + VT-style provenance)
```python
def run_ladder(older, newer, *, anchors, limits, budget, passes=PASSES):
    st = State(older, newer)                                   # unmatched pools as sorted fid arrays; pair maps
    for p in anchors: st.accept(p, pass_id='P00-manual', tier='M', round=0)
    rnd = 0
    for tier_group in group_by_stage(passes):                 # stages T0..T3 in table order (s4); T4/T5 only in S5
        rnd += 1
        for idx, p in enumerate(tier_group):
            find(st, p, st.pool_a(p), st.pool_b(p), tail=tier_group[idx + 1:], rnd=rnd, budget=budget)
        propagate_to_fixpoint(st, limits, budget, rnd)        # s5; worklist of pairs accepted since the last call
    rehash_exact(st, limits, budget)                           # P15, then one more propagation
    propagate_to_fixpoint(st, limits, budget, rnd + 1)
    groups = build_groups(st)                                  # s7: duplicates, ICF, inline/outline hints
    return st.to_correspondence(groups)

def find(st, p, pool_a, pool_b, tail, rnd, budget, cap='A', chain=()):
    a_by, b_by = bucket(pool_a, p.key, p.gate), bucket(pool_b, p.key, p.gate)   # dict key -> sorted fids
    for k in sorted(a_by.keys() & b_by.keys()):               # sorted: determinism
        budget.tick()
        A, B = unmatched(st, a_by[k]), unmatched(st, b_by[k])
        if len(A) == 1 and len(B) == 1:
            st.accept(CorrPair(A[0], B[0], pass_id=p.id, tier=weaker(cap, p.tier), round=rnd, via=chain))
        elif A and B and tail:                                 # ambiguity: drill down with the next keys INSIDE the bucket
            find(st, tail[0], A, B, tail[1:], rnd, budget, cap=weaker(cap, p.tier), chain=(*chain, p.id))
        elif A and B:
            st.note_ambiguous(p.id, A, B)                       # abstain; may become a group (s7)
```
`unmatched()` re-reads the pools because a drill-down may have consumed members. Recursion depth <= number of passes (< 20). A drill-down pair never gets a stronger tier than any key of its chain (`weaker` = lower of two tiers) and records the chain (`via`). Provenance per pair: pass id, tier, round, chain, and for propagated pairs the anchor pair(s) that created the neighbour set. A pass commits its accepts only at its end (all-or-nothing on budget expiry, s8).

## 4. Pass table (function level; order = execution order; all keys over UNMATCHED functions only)

| ID | Key | Gate (both sides) | Tier | Family (05 s1.1) | Cost (n functions) | Origin |
|---|---|---|---|---|---|---|
| P00 manual | analyst correction (1:1 only; N:M becomes a group) | owned by this project, artifact pair matches | M | F-MANUAL | O(m) | SPEC-01 correction flow; user-confirmed passes in Ghidra VT and QBinDiff (R04 s4.16) |
| P01 import-key | `(dll.lower(), name or '#'+ordinal)` | kind import/external | A | F-PT-PE | O(n) | Ghidriff ExternalsName; BinDiff name hash for library |
| P02 export-key | export name, else ordinal (`pe_overview` exports) | function at the export RVA | A | F-PT-PE | O(n) | R04 s3 anchor 1 |
| P03 name-exact | demangled non-default name (`name_src` IMPORTED or USER_DEFINED; not `FUN_`/`thunk_FUN_`/`LAB_` + hex; length >= 3) | size ratio in L-21 OR >= 1 shared mapped callee; else atom tier C + hint `name-body-mismatch` (R05 F13) | A | F-PT-NAMES | O(n) | VT Exact Symbol, BinDiff name hash |
| P04 bytes-exact | `h0` | size >= L-09, > L-10 instructions, kind normal | A | F-PT-BYTES if both sides pdata-confirmed, else F-PT-STRUCT | O(n) | BinDiff hash, VT Exact Bytes |
| P05 masked-exact | `h1` | as P04 | A | as P04 | O(n) | VT Exact Instructions (finer: registers kept) |
| P06 operand-class | `h2` | >= L-12 instructions | B | as P04 | O(n) | R04 s5 level L2 |
| P07 register-agnostic | `h3` | >= L-12 instructions | B | as P04 | O(n) | Ghidra ExactInstructions |
| P08 mnemonic-seq | `hm` | >= L-12 instructions | B | as P04 | O(n) | VT Exact Mnemonics |
| P09 mnemonic-multiset | `hms` | >= L-12 instructions | B | as P04 | O(n) | BinDiff prime signature (exact multiset) |
| P10 md-flowgraph | `(md_td, md_bu, n_bb, n_edge)` | `n_bb` >= L-11 | B | F-PT-STRUCT | O(n) | BinDiff MD flow graph (Diaphora files pure-graph rules under Unreliable, R04 s1 #5: demote to C if its G-U3 precision fails) |
| P11 md-callgraph | call-graph vertex MD | >= 2 call edges | B | F-PT-STRUCT | O(n + E) | BinDiff MD call graph |
| P12 string-set | sorted rare string SHA-256 set (L-13/L-14) | >= L-16 elements | B | F-PT-STRUCT | O(refs) | BinDiff/VT string refs (live here, inert in BinDiff, R04 s0.4) |
| P13 import-callee-set | sorted called import keys | >= L-16 elements | B | F-PT-STRUCT | O(calls) | Diaphora import-names idea (own code) |
| P14 const-set | sorted rare constants (L-15) | >= L-16 elements | B | as P04 | O(consts) | Diaphora "same rare constants" idea (own code) |
| P15 rehash-exact | `h1` recomputed with call/xref targets replaced by matched pair ids | unmatched, >= 1 call, after the first fixpoint; every call target must be resolved to an import key, self-reference or existing matched pair | A if every substituted pair is tier A/M, else B | F-PT-STRUCT | O(insns of unmatched) | R04 s4.14 |

| P16 ref-vector | VT reference vector (s6.2) | candidates from blocking only | B (>= 2 feature types) / C | F-PT-STRUCT | O(blocked pairs) | VT Reference correlators (clean-room) |
| P17 bb-vote | rare block `h1` votes (L-25) | blocks >= 4 instructions | C | F-PT-STRUCT | O(blocks) | DarunGrim/binkit idea |
| P18 layout-gap | singleton gap between monotone anchors (L-26) | size ratio L-21 | C | F-PT-STRUCT | O(n) | BinDiff address sequence, Diaphora local affinity |
| P19 assignment | LAP with reject cost on blocked buckets (s6.4) | bucket <= L-24 | C | F-PT-STRUCT | O(k^3) per bucket | QBinDiff/BinSlayer idea |
**P15 unresolved-target rule (UE-R7/U7-12):** A direct call with no import key and an unresolved callee (`callee < 0`) excludes the entire caller from P15 rehash matching. It is not a shared `?` token: two otherwise identical wrappers can call unrelated external targets. Do not accept P15 at tier A/B from an incomplete call-site substitution. Identified imports, self-calls, and previously matched call targets keep their existing treatment. Bump the ladder version used by `pass_table_digest` when implementing this correction so cached config identities cannot reuse the previous semantics.

Stages: T0 = P00-P03, T1 = P04-P05, T2 = P06-P11, T3 = P12-P14, then P15; T4/T5 = P16-P19 (S5 only). Basic-block matching inside accepted pairs is NOT part of L1 (it is L2 alignment, 05 s2), unlike BinDiff. Each pass also carries an evidence class (05 s1.1: P01-P03 E-NAME, P04-P09 E-BODY, P10 E-CFG, P11/P13/P15 E-CALL, P12/P14 E-DATA, P16/P17/P19 E-RESID, P18 E-LAYOUT); tier-B corroboration needs two classes and two components. P02 export names are symbols in Ghidra's table (source IMPORTED [own]), so P02 and P03 never corroborate each other.

## 5. Propagation to a fixpoint (`ladder/propagate.py`)
```python
def propagate_to_fixpoint(st, limits, budget, rnd):
    wave = sorted(st.new_pairs_since_last_call())                  # sorted by (older rva, newer rva)
    while wave:                                                    # deterministic waves: no decision depends on queue order
        nxt, votes = [], VoteTable()                               # votes: (x, y) -> set of anchor pairs (s5.1)
        for a, b in wave:
            budget.tick()
            for rel in ('callees', 'callers'):                    # BinDiff: callees then callers; D&R alternate up/down
                Na = [x for x in st.rel(a, rel) if st.is_unmatched_a(x) and not st.is_hub_a(x)][:limits.l18]
                Nb = [y for y in st.rel(b, rel) if st.is_unmatched_b(y) and not st.is_hub_b(y)][:limits.l18]
                if Na and Nb:
                    for p in NEIGHBOUR_PASSES:                     # P04-P14 keys evaluated inside the neighbour sets
                        for pair in find_local(st, p, Na, Nb):     # uniqueness RELATIVE to the neighbour sets
                            tier = p.tier if p.id in ('P04', 'P05') else demote(p.tier)   # B -> C unless a 2nd key agrees (C-18)
                            if accept_local(st, pair, tier, via=(a, b), rnd=rnd): nxt.append(pair)
            votes.add_call_site_votes(st, a, b)                    # s5.1: collect only, never accept here
            nxt += thunk_targets(st, a, b)                         # thunk pairs whose targets matched: tier = target tier
        for pair, tier in votes.decide(st, limits):                # after the whole wave: >= L-19 votes, 0 conflicts on EITHER endpoint
            if accept_local(st, pair, tier, via=votes.anchors(pair), rnd=rnd): nxt.append(pair)
        wave = sorted(set(nxt))
```
Hubs: callees with fan-in > L-17 (CRT, `__security_check_cookie`, CFG dispatch, R04 s6) are excluded from neighbour sets and from votes; they can only match by P01-P05. Neighbour lists are truncated deterministically (sorted by rva) at L-18 and the truncation is recorded (`limits_hit`).

### 5.1 Implied matches (VT clean-room; votes and conflicts, R03 s1)
For an accepted pair (a, b) align their call-site sequences (callee keys in site order; import keys and already-matched pair ids as tokens) with a bounded LCS (sequences <= 512; longer -> skip, recorded). Each aligned position whose callees (x, y) are both unmatched casts one vote for (x, y) from anchor (a, b) (one vote per anchor, however many call sites agree). Conflicts are symmetric: a vote for (x, z) with z != y OR for (w, y) with w != x from any anchor is a conflict for every pair sharing exactly one endpoint. Decision only after the whole wave was collected (the earlier draft accepted inside the worklist with partial counts, which made the result order-dependent, R-06): >= 2 votes and 0 conflicts -> tier B (class E-CALL); exactly 1 vote, 0 conflicts -> tier C candidate; any conflict -> no pair, hint `implied-conflict`. Votes and conflicts persist across waves, so a later wave can only add conflicts, never erase one. BinDiff "call reference matching" (positional callees of matched blocks, conf 0.75) is subsumed: it is the same alignment restricted to equal call counts and yields only tier C.

### 5.2 Complexity and memory
Global passes: 15 dict passes x 2 sides x n -> ~7.5 M dict operations at n = 250,000 (L-01). Propagation: each pair processed once; per pair O(L-18 x passes) = O(64 x 11); worst case 60,000 pairs -> ~42 M operations, typical patch pairs (99 % matched by T0/T1, R04 s0.3) touch < 5 % of that. Memory: `FunctionTable` columns 30 x 8 B x n (= 60 MB at L-01) + CSR call adjacency 16 B x E + transient buckets; no per-instruction objects (R04 s7). Budget targets: L-35. Prototype [own, synthetic]: global unique-key passes with drill-down plus neighbour propagation over a power-law call graph took 0.4 s / 93 MiB at 60k functions and 2.2 s / 362 MiB at 250k, so the ladder core is not the bottleneck; P15 (re-hash from instruction blobs), alignment and residual LAP are, and are bench-gated separately.

## 6. Residual stage (S5; only on functions still unmatched after s3-s5)
### 6.1 Blocked candidate generation (`ladder/blocking.py`)
Tokens per unmatched function: size bucket `floor(log2(n_insn))`, `n_bb` bucket, called import keys, rare strings, rare constants, matched-callee pair ids, and MinHash (16 permutations as 4 bands x 4 rows) over mnemonic 3-gram shingles read on demand from `ins`. Candidate pairs = share >= 1 MinHash band OR >= 2 non-size tokens. Keep the top L-22 per function per direction by shared-token count (ties: lower rva). Buckets above L-23 are split by the next token type; if still too large they abstain (`limits_hit: block-cap`). Never an n x m matrix.

### 6.2 P16 reference vectors (clean-room from the VT help text)
Feature = a matched callee/caller pair id, a called import key or a rare string; weight `w(f) = sqrt(-ln p_f)`, `p_f = (refs_A(f) + refs_B(f)) / (F_A + F_B)`; each unmatched reference adds a feature with `p = 0.5`. Similarity = cosine; confidence = dot product x 10. Accept as mutual best iff cosine >= 0.95, confidence >= 10.0 and margin to the runner-up >= 0.05 in both directions (L-20); ties drop.

### 6.3 P17 BB votes and P18 layout gaps
P17: blocks with >= 4 instructions whose `h1` is unique across all unmatched functions of both sides vote for their function pair; candidate iff >= 2 distinct votes (L-25) and the pair is the vote majority for both functions. P18: walk accepted anchors in RVA order on both sides; where the anchor order is monotone and the gap holds exactly one unmatched function per side (L-26) within the size ratio L-21 -> candidate.

### 6.4 P19 assignment with rejection (`ladder/assign.py`)
Within one blocked bucket (<= L-24 functions per side): in-house similarity `s(a,b)` = Jaccard over the union of the function's tokens (6.1) (an internal ranking aid of one source, never compared with another engine's score); cost = 1 - s; add one dummy column per row with cost `1 - floor` (floor 0.6, L-24) so a function may stay unassigned; solve with a pure-Python Jonker-Volgenant LAP (O(k^3); k = 200 -> 8 M inner steps); accept an assignment only if `s - best_alternative >= 0.05`; total LAP time across buckets <= 30 s, then abstain. Output tier C only.

## 7. Groups and leftovers (`ladder/groups.py`)
- Duplicates: content-identical buckets (`h0`/`h1`) with |A| > 1 or |B| > 1 that drill-down and propagation did not resolve -> group `duplicate` (cardinality from sizes), never cross-multiplied (R03 s7.2; contrast Ghidriff pass 11, 1:N cross products, R03 s1).
- ICF: one function carrying several alias names on one side whose names map to several functions on the other -> group `icf` (N:1); materiality (05) `review` ("fold set changed"), never added/removed (R04 s6).
- Inline/outline hints (R05 F11): an older-only function whose >= 2 rare blocks (`h1`, >= 4 instructions) all occur inside one matched newer function -> group `inlined-into` (tier C); symmetric `outlined-from`. Partial containment -> hint `moved-or-inlined` only.
- Leftovers: `older-only` / `newer-only` with reason `no-unique-evidence` (default), `tiny`, `oversize`, `thunk-unresolved`.

## 8. Failure modes

| Situation | Behaviour |
|---|---|
| IR of one side missing or produced by another producer/options digest | ladder not run (F1); S0 path |
| budget exhausted (cancel/deadline) | `partial` correspondence with passes done so far; never a half-applied pass (a pass commits its accepts at its end) |
| key NULL (oversize, truncated, n_bb < L-11) | function skipped by that pass only |
| hub truncation, block-cap, LAP time cap | recorded in `limits_hit`; abstain |
| contradictory tier-M anchors (same function in two corrections) | `INPUT` error before matching (manual corrections are validated by the service already) |

## 9. Tests (red/green, named) and parity hooks
- Pure fixtures are hand-built IR tables (`tests/unified_ir_builder.py`, planned) - no Ghidra needed.
- `test_unique_key_matches_and_duplicate_bucket_abstains`; `test_drill_down_uses_next_key_inside_bucket`; `test_accepted_pair_never_reopened`; `test_tiny_and_thunk_never_content_matched`.
- `test_md_index_diamond_vector` (0.277559753195558); `test_md_index_plain_loop_not_compensated_sum` (planted sum where `sum()` and the loop differ); `test_md_null_below_min_blocks`.
- `test_name_pass_body_mismatch_becomes_tier_c_hint`; `test_icf_alias_group_not_added_removed`.
- `test_propagation_hub_excluded`; `test_neighbour_truncation_is_deterministic_and_recorded`; `test_implied_two_votes_zero_conflicts_tier_b`; `test_implied_conflict_produces_no_pair`; `test_implied_conflict_on_newer_endpoint_blocks_pair`; `test_implied_decision_independent_of_anchor_order` (shuffle the wave); `test_drill_down_tier_never_exceeds_chain`.
- `test_rehash_exact_matches_function_with_moved_callee`.
- `test_refvector_mutual_best_with_margin`; `test_lap_reject_cost_leaves_function_unmatched`; `test_blocking_never_builds_full_matrix` (counter on pair evaluations <= K x n).
- Properties (hypothesis): permutation of input order -> identical correspondence; swapping sides -> mirrored correspondence; adding an unrelated function never changes existing tier-A pairs; budget expiry yields a prefix of the full run's accepted pairs.
- Perf (marked, 5x slack): `test_ladder_10k_under_budget`, `test_ladder_60k_synthetic_under_budget` (L-35).
- Parity: `tools/unified/parity.py` compares pairs with Ghidriff `address_matches`/`modified` and, when available, BinDiff `.BinDiff` rows and `--md_index` dumps (08 s4).

## 10. Security notes
The ladder reads only validated IR; names are opaque strings (never interpreted, never formatted into messages); recursion and loops are bounded (passes < 20, neighbour sets L-18, LCS 512, LAP L-24); no float result leaves the ladder except the internal LAP similarity, which is not persisted.
