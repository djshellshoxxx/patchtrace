# SPEC-31 / 05 Fusion (independence components, decisions) and L2 noise control (proof tiers)

Basis: R05 s0-s4 (cited, not repeated). Owner slices: S0b (fusion, S0 channels, verdicts), S3 (IR channels). Hard rules restated as invariants: no averaging, conflicts preserved, missing = unknown, no probability, AI never decides. Numbers: L-xx (02 s6).

## 1. Fusion (`fusion/components.py`, `fusion/arbiter.py`)
### 1.1 Evidence families and dependency tags (registry data, D-08)

| Family | Sources / steps | Tags | Joining tags |
|---|---|---|---|
| F-GHIDRIFF | every `ghidriff` atom | D_ghidra, D_symbols, D_callgraph, D_compiler | all |
| F-BINDIFF | `bindiff` | D_ghidra (Ghidra BinExport) or D_ida, D_symbols, D_callgraph | all |
| F-DIAPHORA | `diaphora` | D_ida, D_hexrays, D_symbols, D_callgraph | all |
| F-RZDIFF | `rz-diff` | D_rizin, D_bytes | all |
| F-PT-NAMES | P03 | D_symbols | all |
| F-PT-PE | P01, P02 | D_pe_tables | all |
| F-PT-BYTES | P04-P09, P14 when BOTH functions are `pdata-confirmed` (source id `pt-bytes`) | D_bytes, D_ghidra_decode | D_bytes only |
| F-PT-STRUCT | every other `pt-ladder` step, and P04-P09/P14 without pdata confirmation | D_ghidra, D_ghidra_decode, D_callgraph | D_ghidra, D_callgraph |
| F-MANUAL | P00 | D_analyst | all |
Components = connected components of the family graph where two families are joined iff they share a joining tag (union-find, deterministic order by family name; component ids `K<n>` by sorted first family). With today's registry: K1 = {F-GHIDRIFF, F-BINDIFF, F-DIAPHORA, F-PT-NAMES, F-PT-STRUCT} (shared D_symbols/D_ghidra/D_callgraph), K2 = {F-RZDIFF, F-PT-BYTES} (D_bytes), K3 = {F-PT-PE}, K0 = {F-MANUAL}. Assumption **A-IND-1**: `D_ghidra_decode` (SLEIGH instruction decoding and masks, deterministic, no analysis heuristics) does not join; it is validated by ablation G-U7 (08) and is reviewer item W1. The table reproduces `calibration.features.family_dependencies` for G/B/R (features.py:40-47) and only adds families.

### 1.2 Source atoms -> tiers (adapters, 06)

| Source | A | B | C | W |
|---|---|---|---|---|
| ghidriff (`match_types`, strongest of the list wins) | SymbolsHash, ExternalsName, ExactBytesFunctionHasher, ExactInstructionsFunctionHasher | ExactMnemonicsFunctionHasher, BSIM, BulkInstructionHash, StringsRefsHasher, StrUniqueFuncRefsHasher, Decomp Match | StructuralGraphExactHash, StructuralGraphHash, BulkBasicBlockMnemonicHash, SigCallingCalledHasher, SwitchSigHasher, Implied Match, unknown names | added/deleted one-sided observations |
| bindiff (`algorithm`; R02 s14 tiers) | name hash, hash matching, edges flowgraph MD index (rows with `basicblocks = 0` only when both ends are imports) | edges callgraph MD, MD flowgraph top-down/bottom-up, prime signature, MD callgraph top-down/bottom-up | every step with confidence <= 0.75, unknown names | - |
| rz-diff | - | - | - | every row (`non-exclusive` when its newer endpoint is shared) |
| diaphora | - | best | partial, unreliable, multimatch (as N:M) | unmatched observations |
| pt-ladder / pt-bytes | pass tier (04 s4) | | | |
Ratios, similarities and confidences are copied to `Atom.native` as upstream text only; no rule reads them (R03 s2: Ghidriff ratios are text-diff statistics; R02 s7: BinDiff confidence is an evidence-quality index).

### 1.3 Decision algorithm (pure, deterministic)
```python
TIER_RANK = {'M': 5, 'A': 4, 'B': 3, 'C': 2, 'W': 1}
def decide(atoms, groups, registry) -> list[UnifiedMatch]:
    edges = defaultdict(list)                                    # (older_rva, newer_rva) -> atoms; one-sided atoms kept apart
    for a in atoms: (edges[(a.older_rva, a.newer_rva)] if a.older_rva is not None and a.newer_rva is not None
                     else one_sided[a]).append(a)
    rows = []
    for cluster in connected_clusters(edges, groups):            # bipartite components over rvas
        strength = {e: (max(TIER_RANK[x.tier] for x in edges[e]), n_components(edges[e]), has_ghidriff(edges[e]), -e[0], -e[1])
                    for e in cluster.edges}
        chosen = greedy_matching(sorted(cluster.edges, key=strength.get, reverse=True))   # each rva used once
        for e in chosen:
            against = [x for f in cluster.edges if f not in chosen and touches(f, e) for x in edges[f]]
            rows.append(row(e, edges[e], decision=base_decision(edges[e], registry), against=against))
        rows += one_sided_rows(cluster.nodes - covered(chosen), one_sided)   # older-only / newer-only, never "removed"
    rows += group_rows(groups)                                   # ladder N:M, ICF, inline hints, ghidriff 1:N -> 'ambiguous'
    return sorted(rows, key=lambda r: (min_rva(r.older), min_rva(r.newer), r.row_id))

def base_decision(edge_atoms, registry):
    if any(a.tier == 'M' for a in edge_atoms): return 'matched'      # analyst control; contests still recorded
    best = max_pool_per_component(edge_atoms, registry)            # {component: strongest atom}; idempotent inside a component
    if any(a.tier == 'A' for a in best.values()): return 'matched'
    if sum(a.tier == 'B' for a in best.values()) >= 2: return 'matched'   # tier B in two INDEPENDENT components (C-08)
    if any(a.tier == 'B' for a in best.values()): return 'tentative'
    return 'candidate'                                             # only C or W evidence
```
`row()` sets `decision='contested'` when `against` is non-empty (SPEC-27: any source pairing an endpoint differently), keeps the uncontested decision in `hints` (`uncontested:matched`), and sets `Contest.strength = 'strong'` iff any against-atom has tier M, A or B, else `'weak'` (D-12). Contested rows are never auto-anything; a manual row stays `matched` with its contest shown.

### 1.4 Invariants and what fusion never does
Never averages, sums or ranks native scores across sources; never treats a missing atom as a vote (absent sources leave `support` shorter, nothing else); never converts counts of agreeing sources into a number shown to users; never lets a model override `contested` (SPEC-28 calibration s9.5). Display level is read from `calibration.policy.display_level()` and is `'ordinal'` today; a future validated artifact for a unified profile may add bands through the read model only (C-09). Tests: `test_fusion_never_emits_numbers`, `test_absent_source_is_not_a_vote`, `test_weak_contest_still_contested`, `test_two_ghidra_derived_sources_are_one_component`, `test_manual_row_accepted_with_contest_shown`, `test_greedy_matching_keeps_every_against_atom`.

### 1.5 How the L1 false-positive rate is bounded
1. Construction: `matched` needs a unique tier-A key (hash collisions ~2^-64 per pair; duplicates fail uniqueness; names guarded by size/callee checks; tiny/thunk excluded) or tier B from two independent components; propagated tier-B pairs need >= 2 votes and 0 conflicts; tail passes give `candidate` only.
2. Conflict surfacing: any contradicting atom makes the row `contested`; nothing is silently resolved.
3. Measurement gates (08): G-U3 matched-pair precision on Tier R with exact truth >= 99.5 % (lineage-cluster CI lower bound >= 99.0 %) and zero truth-contradicted tier-A pairs on A/A corpora; per-pass precision table published; a pass whose precision CI lower bound < 98 % is demoted one tier by config change (recorded in `config_digest`). Targets are [inf] proposals to preregister.

## 2. L2 ChangeFacts (`facts/*`)
### 2.1 Channels

| ID | Observation (equal / differs) | Data group | Needs | Slice |
|---|---|---|---|---|
| C0 | raw body bytes `h0` | bytes | IR | S3 |
| C1 | address-masked bytes `h1` | bytes | IR | S3 |
| C2 | aligned operand-class deltas (2.2) | bytes | IR instructions | S3 |
| C3 | layout-independent CFG: `n_bb`, `n_edge`, block `hms` multiset, `md_td`, `md_bu` | cfg | IR | S3 |
| C4 | callee multiset mapped through `matched` rows (thunks -> targets, imports by key) | calls | IR (S3) or Ghidriff `called` names mapped through Ghidriff pairs (S0 variant C4n) | S0b/S3 |
| C5 | constant multiset (ALL non-address immediates, not only rare ones) and string-hash multiset | bytes (IR) / decompiler (S0 variant C5t from code literals) | IR or Ghidriff code | S0b/S3 |
| C6 | canonical pseudo-code (2.4) | decompiler | Ghidriff `code` on both sides (today: modified pairs only); S3b on-demand decompile | S0b |
| C7 | BSim-style features | decompiler | not in v1 (B-09) | - |
| C8 | BinDiff flags for this exact pair: differs iff any of G I E L C; J alone is branch inversion (cosmetic hint) | bindiff | stored BinDiff set | S0b |
Matching keys use the rarity filter L-15; facts never do (a `cmp edx, 0x40 -> 0x41` bound fix uses a small constant, R03 s3).

### 2.2 Operand-delta classifier C2 (`facts/operands.py`), the first channel to build (R05 R1)
```python
def operand_deltas(a_ins, b_ins, align, rows, pe) -> list[Delta]:
    out = []
    for i, j in align.matched_pairs():                         # aligned by L2 tokens (opcode + operand classes), 2.3
        x, y = a_ins[i], b_ins[j]
        if x.l1 == y.l1: continue                              # address-only difference or none: checked below
        for ox, oy in zip(x.ops, y.ops):
            if ox.vkind == oy.vkind == 'address':
                if mapped(rows, ox.target, oy.target, min_tier='A'): continue          # address shift to counterpart
                out.append(Delta('callee' if x.is_call else 'data-ref', 'C2', x.rva, y.rva, x.text, y.text))
            elif ox.vkind == oy.vkind == 'scalar' and ox.value != oy.value:
                cls = 'constant'                                # context recorded in the delta text: cmp/test/and/or/shift/size arg
                out.append(Delta(cls, 'C2', x.rva, y.rva, x.text, y.text))
            elif ox.is_displacement and ox.value != oy.value:
                out.append(Delta('struct-offset', 'C2', x.rva, y.rva, x.text, y.text))
            elif ox.vkind == oy.vkind == 'register' and ox.value != oy.value:
                out.append(Delta('register-only', 'C2', x.rva, y.rva, x.text, y.text))
        if x.mnem != y.mnem and x.is_cond_branch and y.is_cond_branch:
            out.append(Delta('condition', 'C2', x.rva, y.rva, x.text, y.text))
    out += [Delta('block-added' if side == 'b' else 'block-removed', 'C2', ...) for side, blk in align.unmatched_blocks()]
    return out[:L28]                                            # rest counted in deltas_omitted
```
An address operand counts as "mapped" only when both targets belong to rows whose decision is `matched` with tier A or M; otherwise the delta stays (soundness of COS-ADDR depends on L1, reviewer item W4).

### 2.3 Alignment (`facts/align.py`)
Block level first: blocks paired by unique block `h1` inside the pair, then by CFG position (entry, then successors of paired blocks, unique only); instruction level inside paired blocks: patience diff on L2 tokens, Hirschberg LCS fallback (linear space) when patience leaves gaps; whole-function cap L-27 (beyond: prefix/suffix only, verdict at most `review`, `limits_hit: align-cap`). Deterministic tie-breaks by RVA.

### 2.4 Canonical pseudo-code C6 (`facts/pseudo.py`, version `canon/1`)
Input: Ghidriff `code` of both functions (bounded L-29). Rules (R05 R7): strip comments and whitespace; alpha-rename locals, parameters and decompiler temporaries per function in order of first definition (`uVar1`, `local_18`, `param_3`, `in_RAX` -> `v1`, `v2` ...); replace `FUN_<hex>`/`DAT_<hex>`/`LAB_<hex>`/`PTR_<hex>` labels by the counterpart's row id when that address belongs to an accepted row, else `UNMAPPED_<side>_<rva>`; keep literal values and casts. Never canonicalise operators, constants or call names. C6 equal = token sequences identical.

### 2.5 Verdicts and proofs (`facts/verdict.py`; first match wins)
```python
def judge(ch: Channels, deltas, row) -> ChangeFacts:
    if row.decision in ('older-only', 'newer-only'): return facts('not-applicable')
    if ch.C0 == 'equal': return facts('unchanged')
    semantic = [d for d in deltas if d.cls in SEMANTIC]        # constant, comparison, condition, callee, call-added, call-removed,
                                                               # data-ref, struct-offset, block-added/removed holding a store or call
    if not semantic:
        if ch.C1 == 'equal' and ch.C4 == ch.C5 == 'equal' and all_address_deltas_mapped(deltas):
            return facts('cosmetic', proof='COS-ADDR/1')
        if ch.C3 == 'equal' and block_h1_multiset_equal(row) and ch.C4 == ch.C5 == 'equal' and all_address_deltas_mapped(deltas):
            return facts('cosmetic', proof='COS-LAYOUT/1')
        if ch.C6 == 'equal' and ch.C4 == ch.C5 == 'equal' and not ir_channels_report_semantic(ch):
            return facts('cosmetic', proof='COS-PSEUDO/1')
    if semantic:
        first = group_of(semantic[0].channel)
        second = next((c for c in ('C6', 'C3', 'C8', 'C4', 'C5') if ch[c] == 'differs' and group_of(c) != first), None)
        if second: return facts('material', second_channel=second, deltas=deltas)
    if any(ch[c] in ('equal', 'differs') for c in CHANNELS): return facts('review', deltas=deltas)
    return facts('unknown')
```
Channel data groups (2.1) make the second channel independent of the first observation: a constant-only edit seen only in bytes (C2/C5) and not in C3/C4/C6/C8 is `review`, ranked first among reviews (2.6), and S3b may decompile that pair on demand to obtain C6. `register-only` and `address-only` deltas that fail a proof stay `review` (no register-renaming proof in v1: calling-convention registers make it unsound). A cheap-tier semantic delta always beats `COS-PSEUDO` (cross-tier consistency, R05 s7). Without IR (S0) the only possible proofs are `COS-PSEUDO/1` and the only second channel is C8.

### 2.6 Review ordering (sort key, never shown as a number)
Severity order: callee / call-added / call-removed > condition / comparison > constant in a compare, test, mask, shift or size-argument context > struct-offset > data-ref > block-added/removed > constant elsewhere > cfg > string > size-only > refcount-only > address-only > register-only > name-only. Ties: attention/1 score when the row maps to a Ghidriff match (read-only), then RVA.

## 3. Noise-filter catalogue (R05 s4 F1-F15 -> where implemented)

| F | Filter | Module / slice | Guard against hiding real change | Test |
|---|---|---|---|---|
| F1 | symmetric producer/mode/options on both sides | extract, pipeline / S1 | asymmetric -> no ladder, S0 only | `test_asymmetric_ir_falls_back_to_s0` |
| F2 | relocation-aware masked hash | ir/ingest / S1 | mask only positive address evidence | `test_l1_masks_only_positive_address_evidence` |
| F3 | operand-delta classifier | facts/operands / S3 | unmapped targets stay deltas | `test_unmapped_target_is_callee_delta` |
| F4 | typed downgrade of Ghidriff non-code diff types | sources/ghidriff + verdict / S0b | hint only; cosmetic still needs a proof | `test_diff_types_alone_never_cosmetic` |
| F5 | thunk/import collapse in C4 | facts/channels / S3 | collapse pure jump thunks only | `test_wrapper_with_logic_not_collapsed` |
| F6 | callee mapping through rows | facts/channels / S0b+S3 | unmatched callee = semantic delta | `test_unmatched_callee_is_material_candidate` |
| F7 | canonical pseudo-code | facts/pseudo / S0b | literals, operators, call names kept | `test_canon_keeps_constants_and_operators` |
| F8 | layout-independent CFG | facts/channels / S3 | block content multiset must match | `test_block_reorder_is_cos_layout` |
| F9 | rarity, minimum size, tiny functions | ladder gates / S2 | tiny changes go to review, never dropped | `test_tiny_change_is_review_not_hidden` |
| F10 | cross-function edit-group dedup (identical canonical deltas in >= 3 rows -> one group, rows flagged `induced-candidate`) | read_model / S4 | rows stay listed; group is a view | `test_edit_group_never_removes_rows` |
| F11 | added/removed reconciliation (inline/outline) | ladder/groups / S2 | partial containment -> hint only | `test_inlined_function_not_reported_removed` |
| F12 | N-way churn index | deferred (B-12) | - | - |
| F13 | name/body consistency | ladder P03 + fusion / S2 | mismatch -> tier C + contest | `test_name_body_mismatch_contests` |
| F14 | string/constant significance | 2.1 (keys rare, facts complete) / S3 | small constants count in facts | `test_small_constant_bound_change_detected` |
| F15 | Windows loader idioms (`.reloc` in masks; `/GS`, CFG dispatch as hubs; DVRT/GuardCF tables not parsed in v1) | ir/pe_tables, propagate / S1-S2 | hubs excluded only from propagation, never from facts | `test_hub_call_change_still_reported` |

## 4. How the L2 noise (false "changed") rate is bounded
Construction: `cosmetic` exists only through named sound proofs (its only failure mode is an unsound normaliser, hunted by the leakage gate); `material` needs a semantic-class delta plus a second channel from another data group; everything else is `review` (visible, ordered, never auto-hidden; default filters only collapse `cosmetic`/`unchanged` with a visible count, U-03). Measurement (08): G-U1 A/A rebuilds produce 0 `material` and <= 0.1 % `review` rows [inf target]; G-U2 planted mutations: leakage into `cosmetic`/`unchanged` = 0 and recall (material or review) >= 95 % per class; G-U6: the `material` set has >= 20 % fewer false leads than the best legacy output at non-decreasing planted recall (R05 s7 proposal).

## 5. Failure modes

| Case | Result |
|---|---|
| a channel's data unavailable (no IR, no code, oversize) | that channel `unavailable`; verdict computed from the rest; never `cosmetic` by absence |
| alignment cap hit | `review` + `limits_hit` |
| row contested | facts still computed for the chosen edge (labelled "for the shown pairing") |
| group rows (N:M) | `not-applicable` for facts in v1 (B-13) |
