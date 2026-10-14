# SPEC-31 / 05 Fusion (independence components, evidence classes, decisions) and L2 noise control (proof tiers)

Basis: R05 s0-s4 (cited, not repeated); review corrections R-xx in [11-review-log](11-review-log.md). Owner slices: S0b (fusion, S0 channels, verdicts), S3 (IR channels, DATA-MAP, proofs), S3b (on-demand decompile). Hard rules restated as invariants: no averaging, conflicts preserved, missing = unknown, no probability, AI never decides. Numbers: L-xx (02 s6).

## 1. Fusion (`fusion/components.py`, `fusion/arbiter.py`)
### 1.1 Evidence families, components and evidence classes (registry data, D-08)

| Family | Sources / steps | Tags | Joining tags |
|---|---|---|---|
| F-GHIDRIFF | every `ghidriff` atom | D_ghidra, D_symbols, D_callgraph, D_compiler | all |
| F-BINDIFF | `bindiff` | D_ghidra (Ghidra BinExport) or D_ida, D_symbols, D_callgraph | all |
| F-DIAPHORA | `diaphora` | D_ida, D_hexrays, D_symbols, D_callgraph | all |
| F-RZDIFF | `rz-diff` | D_rizin, D_bytes | all |
| F-PT-NAMES | P03 | D_symbols | all |
| F-PT-PE | P01, P02 (import/export names are symbols in Ghidra's table, R-17) | D_pe_tables, D_symbols | all |
| F-PT-BYTES | P04-P09, P14 when BOTH functions are `pdata-confirmed` (source id `pt-bytes`) | D_bytes, D_ghidra_decode | D_bytes only |
| F-PT-STRUCT | every other `pt-ladder` step, and P04-P09/P14 without pdata confirmation | D_ghidra, D_ghidra_decode, D_callgraph | D_ghidra, D_callgraph |
| F-MANUAL | P00 | D_analyst | all |
Components = connected components of the family graph where two families are joined iff they share a joining tag (union-find, deterministic order by family name; `K0` = the component holding F-MANUAL, the others `K1`, `K2`, ... in order of their alphabetically first family). Today: K0 = {F-MANUAL}, K1 = {F-BINDIFF, F-DIAPHORA, F-GHIDRIFF, F-PT-NAMES, F-PT-PE, F-PT-STRUCT}, K2 = {F-PT-BYTES, F-RZDIFF}. The table reproduces `calibration.features.family_dependencies` for G/B/R (features.py:40-47) and only adds families.

Components alone over-count: Ghidriff's ExactMnemonics and `pt-bytes` P08 are the same key over the same Ghidra decoding (and, in `gzf` mode, the same function bodies), yet sit in K1 and K2 (R-05). Every step therefore also has an **evidence class** (what information the key reads); two atoms corroborate only if they differ in BOTH component and class.

| Class | Steps (any source; unknown steps -> E-UNKNOWN, which never corroborates) |
|---|---|
| E-NAME | P01, P02, P03; Ghidriff SymbolsHash, ExternalsName; BinDiff name hash |
| E-BODY | P04-P09; Ghidriff ExactBytes/ExactInstructions/ExactMnemonics/BulkInstructionHash; BinDiff hash, prime signature, instruction count; rz-diff |
| E-CFG | P10; Ghidriff StructuralGraphExactHash, StructuralGraphHash, BulkBasicBlockMnemonicHash, SwitchSigHasher; BinDiff (edges) MD flowgraph, relaxed MD, loop count |
| E-CALL | P11, P13, P15, neighbour-propagated pairs, implied matches; Ghidriff SigCallingCalledHasher, Implied Match; BinDiff callgraph MD steps, call reference, call sequence |
| E-DATA | P12, P14; Ghidriff StringsRefsHasher, StrUniqueFuncRefsHasher; BinDiff string references |
| E-DECOMP | Ghidriff BSIM, Decomp Match; Diaphora pseudo-code rules (registry maps DA-01 descriptions) |
| E-LAYOUT / E-RESID / E-MANUAL | P18, BinDiff address sequence / P16, P17, P19 / P00 |
Assumption **A-IND-1** (narrowed): an E-BODY atom of K2 (pdata-confirmed extents) and a non-E-BODY atom of K1 err independently enough to corroborate; G-U7 (08) measures it per class pair and can join classes by configuration.

### 1.2 Source atoms -> tiers (adapters, 06)

| Source | A | B | C | W |
|---|---|---|---|---|
| ghidriff (`match_types`, strongest of the list wins) | SymbolsHash, ExternalsName, ExactBytesFunctionHasher, ExactInstructionsFunctionHasher | ExactMnemonicsFunctionHasher, BSIM, BulkInstructionHash, StringsRefsHasher, StrUniqueFuncRefsHasher, Decomp Match | StructuralGraphExactHash, StructuralGraphHash, BulkBasicBlockMnemonicHash, SigCallingCalledHasher, SwitchSigHasher, Implied Match, unknown names | added/deleted one-sided observations |
| bindiff (`algorithm`; R02 s14 tiers) | name hash, hash matching, edges flowgraph MD index (rows with `basicblocks = 0` only when both ends are imports) | edges callgraph MD, MD flowgraph top-down/bottom-up, prime signature, MD callgraph top-down/bottom-up | every step with confidence <= 0.75, unknown names | - |
| rz-diff | - | - | - | every row (`non-exclusive` when its newer endpoint is shared) |
| diaphora (verified sets only, 06 s5) | - | best | partial, unreliable, multimatch (as N:M) | unmatched observations |
| pt-ladder / pt-bytes | pass tier (04 s4) | | | |
Ratios, similarities and confidences are copied to `Atom.native` as upstream text only; no rule reads them (R03 s2: Ghidriff ratios are text-diff statistics; R02 s7: BinDiff confidence is an evidence-quality index).

### 1.3 Decision algorithm (pure, deterministic)
```python
TIER_RANK = {'M': 5, 'A': 4, 'B': 3, 'C': 2, 'W': 1}
def decide(atoms, groups, registry) -> list[UnifiedMatch]:
    edges = defaultdict(list); one_sided = defaultdict(list)     # (older_rva, newer_rva) -> atoms
    for a in atoms: (edges[(a.older_rva, a.newer_rva)] if a.older_rva is not None and a.newer_rva is not None
                     else one_sided[a.older_rva if a.older_rva is not None else ('n', a.newer_rva)]).append(a)
    rows = []
    for cluster in connected_clusters(edges, groups):            # bipartite components over rvas, sorted by min rva
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
    b = [a for a in edge_atoms if a.tier in ('A', 'B') and registry.cls(a) != 'E-UNKNOWN']
    if any(registry.comp(x) != registry.comp(y) and registry.cls(x) != registry.cls(y) for x, y in combinations(b, 2)):
        return 'matched'                                           # two components AND two evidence classes (C-08, R-05)
    if b: return 'tentative'
    return 'candidate'                                             # only C or W evidence
```
`row()` sets `decision='contested'` when `against` is non-empty (SPEC-27: any source pairing an endpoint differently), keeps the uncontested decision in `hints` (`uncontested:matched`), and sets `Contest.strength = 'strong'` iff any against-atom has tier M, A or B, else `'weak'` (D-12). Contested rows are never auto-anything; a manual row stays `matched` with its contest shown. One-sided observations (Ghidriff `added`/`deleted`, unmatched lists) are absence of evidence (D-14): they never contest a pairing; the row carries hint `one-sided-by:<source>` instead. This deliberately differs from the C6 reconcile verdict for "removed(A) vs engine A->B" (R01 s3): A-08 records it and the Unified tab shows both texts (R-19).

### 1.4 Invariants and what fusion never does
Never averages, sums or ranks native scores across sources; never treats a missing atom as a vote (absent sources leave `support` shorter, nothing else); never converts counts of agreeing sources into a number shown to users; never lets a model override `contested` (SPEC-28 calibration s9.5). Display level is read from `calibration.policy.display_level()` and is `'ordinal'` today; a future validated artifact for a unified profile may add bands through the read model only (C-09). Tests: `test_fusion_never_emits_numbers`, `test_absent_source_is_not_a_vote`, `test_weak_contest_still_contested`, `test_two_ghidra_derived_sources_are_one_component`, `test_same_class_never_corroborates_across_components` (Ghidriff ExactMnemonics + `pt-bytes` P08 -> `tentative`), `test_manual_row_accepted_with_contest_shown`, `test_greedy_matching_keeps_every_against_atom`, `test_one_sided_observation_never_contests`.

### 1.5 How the L1 false-positive rate is bounded
1. Construction: `matched` needs a unique tier-A key (hash collisions ~2^-64 per pair; duplicates fail uniqueness; names guarded by size/callee checks; tiny/thunk excluded) or tier B from two components AND two evidence classes; propagated tier-B pairs need >= 2 votes and 0 conflicts on both endpoints; tail passes give `candidate` only.
2. Conflict surfacing: any contradicting atom makes the row `contested`; nothing is silently resolved.
3. Measurement gates (08): G-U3 matched-pair precision on Tier R with exact truth >= 99.5 % (lineage-cluster CI lower bound >= 99.0 %) and zero truth-contradicted tier-A pairs on A/A corpora; per-pass precision table published; a pass whose precision CI lower bound < 98 % is demoted one tier by config change (recorded in `config_digest`). Targets are [inf] proposals to preregister; every borrowed threshold is a hypothesis (02 s6.1).

## 2. L2 ChangeFacts (`facts/*`)
Scope: a verdict describes the function's code (instruction stream, CFG, referenced targets) and, when `.pdata` exists, its unwind/handler metadata (EH-EQ); data-only patches (tables, strings, globals) are out of scope and belong to SPEC-26 file-level views (R-16).
### 2.1 Channels

| ID | Observation (equal / differs) | Data group | Needs | Slice |
|---|---|---|---|---|
| C0 | raw body bytes `h0` | bytes | IR | S3 |
| C1 | address-masked bytes `h1` (displacement/immediate bytes of address-bearing operands only, 03 s6) | bytes | IR | S3 |
| C2 | aligned operand-class deltas including the target consistency of EVERY address operand (2.2, 2.7) | bytes | IR instructions | S3 |
| C3 | CFG: `n_bb`, `n_edge`, block body multiset, `md_td`, `md_bu`; equality here is a filter, never a proof (COS-LAYOUT needs 2.5) | cfg | IR | S3 |
| C4 | callee multiset mapped through `matched` rows (thunks -> targets, imports by key) | calls | IR (S3) or Ghidriff `called` names mapped through Ghidriff pairs (S0 variant C4n) | S0b/S3 |
| C5 | constant multiset (ALL non-address immediates, not only rare ones) and string-hash multiset | bytes (IR) / decompiler (S0 variant C5t from code literals) | IR or Ghidriff code | S0b/S3 |
| C6 | canonical pseudo-code (2.4) | decompiler | Ghidriff `code` (modified pairs only: Ghidriff never examines same-size, same-refcount pairs, R05 s0.1) or S3b decompile (2.8) | S0b/S3b |
| C7 | BSim-style features | decompiler | not in v1 (B-09) | - |
| C8 | BinDiff flags for this exact pair: differs iff any of G I E L C; J alone is branch inversion (cosmetic hint); O is never set by BinDiff (R02 s7) | bindiff | stored BinDiff set | S0b |
Matching keys use the rarity filter L-15; facts never do (a `cmp edx, 0x40 -> 0x41` bound fix uses a small constant, R03 s3).

### 2.2 Operand-delta classifier C2 (`facts/operands.py`), the first channel to build (R05 R1)
```python
def operand_deltas(a_ins, b_ins, align, rows, dmap, pe) -> tuple[list[Delta], Consistency]:
    out, cons = [], Consistency()                              # cons counts address pairs: mapped / unmapped / conflict
    for i, j in align.matched_pairs():                         # aligned by L2 tokens (opcode + operand classes), 2.3
        x, y = a_ins[i], b_ins[j]
        for ox, oy in zip(x.ops, y.ops):                       # EVERY operand, also when x.l1 == y.l1 (R-01)
            if ox.vkind == oy.vkind == 'address':
                state = target_state(ox.target, oy.target, rows, dmap, i, j, align)   # 2.7: mapped|unmapped|conflict|string
                cons.add(state)
                if state == 'conflict':
                    out.append(Delta('callee' if x.is_call else 'data-ref', 'C2', x.rva, y.rva, x.text, y.text))
                elif state == 'string':                        # both strings, different content
                    out.append(Delta('string', 'C2', x.rva, y.rva, x.text, y.text))
            elif ox.vkind == oy.vkind == 'scalar' and ox.value != oy.value:
                cls = 'frame' if is_frame_alloc(x) and is_frame_alloc(y) else 'constant'   # sub/add rsp, imm (R-14)
                out.append(Delta(cls, 'C2', x.rva, y.rva, x.text, y.text))   # context (cmp/test/and/shift/size arg) in text
            elif ox.vkind == oy.vkind == 'stack' and ox.value != oy.value:
                out.append(Delta('frame', 'C2', x.rva, y.rva, x.text, y.text))      # RSP/RBP frame offsets (R-14)
            elif ox.vkind == oy.vkind == 'memory' and ox.value != oy.value:
                out.append(Delta('struct-offset', 'C2', x.rva, y.rva, x.text, y.text))   # non-frame base + displacement
            elif ox.vkind == oy.vkind == 'register' and ox.value != oy.value:
                out.append(Delta('register-only', 'C2', x.rva, y.rva, x.text, y.text))
            elif ox.vkind != oy.vkind:
                out.append(Delta('unknown', 'C2', x.rva, y.rva, x.text, y.text))
        if x.mnem != y.mnem and x.is_cond_branch and y.is_cond_branch and not inverted_pair(x, y, align):
            out.append(Delta('condition', 'C2', x.rva, y.rva, x.text, y.text))
    out += [Delta('block-added' if side == 'b' else 'block-removed', 'C2', ...) for side, blk in align.unmatched_blocks()]
    return out[:L28], cons                                      # rest counted in deltas_omitted
```
`target_state` (2.7) never trusts a raw address: a function target is `mapped` only through a `matched` row of tier A or M (or equal import keys, or thunks resolving to mapped targets); an intra-function branch target must hit the aligned instruction; a data target needs DATA-MAP/1. `unmapped` (no evidence either way) is not a delta but blocks every cosmetic proof; `conflict` (the target maps elsewhere) and `string` (both strings, different content) are semantic deltas; `cons` counts `string` with the conflicts, so neither can pass a proof.

### 2.3 Alignment (`facts/align.py`)
Pairs with equal `h1` are aligned positionally (instruction k <-> k). Otherwise block level first: blocks paired by unique block body key (block `h1` without its terminating branch) inside the pair, then by CFG position (entry, then successors of paired blocks, unique only); instruction level inside paired blocks: patience diff on L2 tokens, Hirschberg LCS fallback (linear space) when patience leaves gaps; whole-function cap L-27 (beyond: prefix/suffix only, verdict at most `review`, `limits_hit: align-cap`). Deterministic tie-breaks by RVA.

### 2.4 Canonical pseudo-code C6 (`facts/pseudo.py`, version `canon/1`)
Input: Ghidriff `code` of both functions (bounded L-29) or S3b output. Rules (R05 R7): strip comments and whitespace; alpha-rename locals, parameters and decompiler temporaries per function in order of first definition (`uVar1`, `local_18`, `param_3`, `in_RAX` -> `v1`, `v2` ...); replace `FUN_<hex>`/`DAT_<hex>`/`LAB_<hex>`/`PTR_<hex>`/`switchD_`/`caseD_` labels by the counterpart's row id (functions) or DATA-MAP pair id (data) when mapped, else by `U<k>` numbered in order of first use per function and count the unmapped label pairs; keep literal values, operators, casts and call names. C6 `equal` = token sequences identical; `unmapped_labels` > 0 forbids COS-PSEUDO (an alpha-renamed unmapped label could hide a swapped global, R-02). Literals are normalised for comparison only (hex/decimal/char spelling, sign extension to the operand width) so value-anchored corroboration (2.5) can match `0x200` with `512`.

### 2.5 Verdicts and proofs (`facts/verdict.py`; first match wins)
```python
def judge(ch: Channels, deltas, cons, row, eh) -> ChangeFacts:
    if row.decision in ('older-only', 'newer-only'): return facts('not-applicable')
    targets_ok = cons.unmapped == cons.conflict == 0           # target consistency of every address operand (2.7)
    structural_ok = targets_ok and eh in ('equal', 'absent')   # eh: equal | differs | absent | unavailable (EH-EQ, R-16)
    if ch.C0 == 'equal' and structural_ok: return facts('unchanged', proof='UNCH/1')   # equal bytes alone are NOT enough (R-03)
    semantic = [d for d in deltas if d.cls in SEMANTIC]        # constant, comparison, condition, callee, call-added, call-removed,
                                                               # data-ref, struct-offset, string, block-added/removed holding a store or call
    if not semantic and ch.C4 == ch.C5 == 'equal':
        if structural_ok and ch.C1 == 'equal' and cfg_positional_equal(row): return facts('cosmetic', proof='COS-ADDR/1')
        if structural_ok and layout_bijection(row): return facts('cosmetic', proof='COS-LAYOUT/1')   # polarity-preserving (R-04)
        if targets_ok and eh != 'differs' and ch.C6 == 'equal' and ch.unmapped_labels == 0:
            return facts('cosmetic', proof='COS-PSEUDO/1')    # decompiler-relative: never hidden by default (R-04, U-03)
    for d in semantic:                                         # value-anchored second channel (MAT-ANCHOR, R-08)
        second = anchored_second_channel(d, ch, row)           # table below; None if no OTHER data group shows THIS change
        if second: return facts('material', second_channel=second, deltas=deltas)
    if any(ch[c] in ('equal', 'differs') for c in CHANNELS) or deltas or cons.unmapped:
        return facts('review', deltas=deltas)                  # incl. address-only (unmapped targets), frame, eh
    return facts('unknown')
```

| Proof / rule | Holds iff (all) | Why sound |
|---|---|---|
| UNCH/1 | `h0` equal; every address operand target `mapped` (2.7); EH-EQ | equal bytes at a moved RVA re-target relative operands; mapping proves they still reach the counterparts |
| COS-ADDR/1 | `h1` equal; every address operand `mapped`; block successors equal positionally (switch tables included); C4, C5 equal; EH-EQ | same opcodes, registers, immediates, order, flags; only address fields differ and each maps to the counterpart |
| COS-LAYOUT/1 | bijection of blocks by unique body key (h1 without terminator) covering all blocks; every edge maps to an edge with the same polarity (jcc inverted only by the closed table JZ/JNZ, JB/JAE, JBE/JA, JL/JGE, JLE/JG, JS/JNS, JO/JNO, JP/JNP with swapped successors); terminators otherwise equal or an added/removed unconditional JMP to the fall-through block; all address operands `mapped`; C4, C5 equal; EH-EQ | equal counts/MD/multisets do NOT prove isomorphism (a then/else swap passes them); the polarity-preserving bijection does |
| COS-PSEUDO/1 | C6 equal with zero unmapped labels; C4, C5 equal; no semantic delta in IR channels when IR exists; EH-EQ when IR exists | relative to Ghidra's decompiler only (it can drop arguments beyond an inferred prototype or flag-only effects), so its rows are listed, never hidden |
| EH-EQ | both sides without unwind data, or equal normalised UNWIND_INFO (version, flags, prolog size, frame register/offset, unwind codes), same handler (mapped or equal import key) and equal handler-data length; `__C_specific_handler` scope records equal after subtracting the function start and mapping filters | SEH scopes are invisible to bytes and decompiler (R-16); otherwise class `eh` -> `review` |

MAT-ANCHOR (second channel must observe the SAME change, from another data group; any other difference does not count):

| Semantic delta (first channel C2) | Anchored second channel |
|---|---|
| callee, call-added, call-removed | C4 differs by that callee pair (mapped ids); or C8 flag C |
| constant, comparison, struct-offset | C6 token diff contains the normalised old -> new literal pair of that instruction (S3b supplies C6 for same-size edits) |
| condition | C6 shows a changed relational operator or condition expression at an aligned statement |
| data-ref (conflict) | C6 shows the corresponding label changing to another mapped datum |
| block-added/removed holding a store or call | C3 block/edge counts differ; or C8 flag G |
| string | C6 shows the changed string literal (C5 is in the same data group as C2 and never anchors) |
A constant-only edit without C6 therefore stays `review` ranked first (2.6) until S3b decompiles it (2.8); with S3b it is promoted only when the decompiler shows the same value change, which also rejects a mis-classified address. `register-only`, `address-only`, `frame` and `eh` never make `material` (no register-renaming or frame proof in v1: calling-convention registers and buffer resizing make them unsound), they stay `review`. A cheap-tier semantic delta always beats `COS-PSEUDO` (cross-tier consistency, R05 s7). Without IR (S0) the only proof is `COS-PSEUDO/1` and the only anchored second channels are C4n and C8.

### 2.6 Review ordering (sort key, never shown as a number)
Severity order: callee / call-added / call-removed > condition / comparison > constant in a compare, test, mask, shift or size-argument context > struct-offset > data-ref > block-added/removed > eh > constant elsewhere > cfg > string > frame > size-only > refcount-only > address-only > register-only > name-only. Ties: hint `trace-arg` last (F17), then attention/1 score when the row maps to a Ghidriff match (read-only), then RVA.

### 2.7 DATA-MAP/1 and target consistency (`facts/datamap.py`, S3; R-01)
1. Inputs: IR `ref` rows (fid, ord, opi, target, kind code|data|import|stack, 02 s3), `str` rows, `matched` rows of tier A/M.
2. Votes: every `matched` A/M pair whose `h1` is equal is aligned positionally; each operand position with a data reference on both sides votes for the data pair (t, u), recording the voting function pair. Pairs with differing `h1` never vote.
3. Consensus: for an older datum t, the newer datum voted by a strict majority of the function pairs voting for t, with at least 2 voters; symmetrically for a newer datum u. A voter whose pair differs from an existing consensus is a dissenter (the typical patched function).
4. Data targets for row r: `mapped` if (a) both are defined strings with equal SHA-256, unique per side; or (b) u is the consensus of t and t the consensus of u, with at least one supporting voter other than r (leave-one-out: a function never proves its own references); or (c) region shift (B-21 can cut it, U-12): neither t nor u has a consensus or a vote from a function other than r, and the nearest (b)-mapped data pairs below and above t in the same section have the same displacement u - t and keep order. Both defined strings with different SHA-256 -> delta class `string`. `conflict` if t or u has a consensus that differs from r's pair (r swapped to another datum). Otherwise `unmapped`.
5. Function targets: mapped iff (i) a `matched` A/M row pairs them, (ii) both are imports with equal key, (iii) both are thunks whose targets are mapped, or (iv) both bodies have equal `h0` and they either sit at the same RVA or are the consensus (rule 3 applied to call operands) of a matched caller pair other than r. Rule (iv) covers tiny and unnamed callees, which I6 keeps out of content-key matching; without it G-U1's X vs X run could not reach 100 % `unchanged`. `conflict` if either is in a `matched` A/M row with a different partner. Intra-function targets: mapped iff they land on aligned instructions.
Complexity O(data refs of matched pairs) using the `ref` table only (no instruction decoding); deterministic order by (t, u). Tests: `test_moved_global_is_cosmetic_via_other_function_votes`, `test_swapped_global_same_shape_is_not_cosmetic` (the R-01 hole: the patched function is a dissenter -> `conflict` -> semantic `data-ref`), `test_innocent_functions_keep_mapping_beside_a_dissenter`, `test_single_use_global_needs_region_shift`, `test_function_never_votes_for_itself`, `test_two_way_tie_is_unmapped`.

### 2.8 On-demand decompile S3b (`decompile` mode of `extract/ghidra_script.py`, driven by `extract/runner.py`; R-08)
After facts, rows in `review` whose first semantic delta is constant, comparison, condition or struct-offset and lack C6 are ranked (2.6); the top L-41 pairs are decompiled in ONE extractor session that re-opens both retained GZFs (03 s8) with the same Ghidra and canonicalised by `canon/1`; results feed C6 and MAT-ANCHOR, never L1. Measured [own, 11-review-log]: decompiler open 0.28 s, median 0.013 s, p90 0.16 s, max 2.6 s per function on an analysed program, so L-41 = 64 pairs fits well inside its 600 s budget. Absent GZFs or Ghidra -> rows stay `review` (B-08).

## 3. Noise-filter catalogue (R05 s4 F1-F15 -> where implemented)

| F | Filter | Module / slice | Guard against hiding real change | Test |
|---|---|---|---|---|
| F1 | symmetric producer, mode, options and symbol policy on both sides | extract, pipeline / S1 | asymmetric -> no ladder, S0 only | `test_asymmetric_ir_falls_back_to_s0` |
| F2 | relocation-aware masked hash (displacement/immediate bytes only, 03 s6) | ir/ingest / S1 | mask only positive address evidence; SIB/ModRM never masked | `test_l1_masks_only_positive_address_evidence` |
| F3 | operand-delta classifier with target consistency | facts/operands, facts/datamap / S3 | unmapped targets block proofs; conflicts are deltas | `test_unmapped_target_blocks_cosmetic` |
| F4 | typed downgrade of Ghidriff non-code diff types | sources/ghidriff + verdict / S0b | hint only; cosmetic still needs a proof | `test_diff_types_alone_never_cosmetic` |
| F5 | thunk/import collapse in C4 | facts/channels / S3 | collapse pure jump thunks only | `test_wrapper_with_logic_not_collapsed` |
| F6 | callee mapping through rows | facts/channels / S0b+S3 | unmatched callee = semantic delta | `test_unmatched_callee_is_material_candidate` |
| F7 | canonical pseudo-code with DATA-MAP labels | facts/pseudo / S0b | literals, operators, call names kept; unmapped labels counted | `test_canon_keeps_constants_and_operators` |
| F8 | layout-independent CFG with polarity-preserving bijection | facts/channels / S3 | then/else swap is not cosmetic | `test_block_reorder_is_cos_layout`, `test_then_else_swap_not_cosmetic` |
| F9 | rarity, minimum size, tiny functions | ladder gates / S2 | tiny changes go to review, never dropped | `test_tiny_change_is_review_not_hidden` |
| F10 | cross-function edit-group dedup (identical canonical deltas in >= 3 rows -> one group, rows flagged `induced-candidate`) | read_model / S4 | rows stay listed; group is a view | `test_edit_group_never_removes_rows` |
| F11 | added/removed reconciliation (inline/outline) | ladder/groups / S2 | partial containment -> hint only | `test_inlined_function_not_reported_removed` |
| F12 | N-way churn index | deferred (B-12) | - | - |
| F13 | name/body consistency | ladder P03 + fusion / S2 | mismatch -> tier C + contest | `test_name_body_mismatch_contests` |
| F14 | string/constant significance | 2.1 (keys rare, facts complete) / S3 | small constants count in facts | `test_small_constant_bound_change_detected` |
| F15 | Windows loader idioms (`.reloc` and RVA-form operands in masks; `/GS`, CFG dispatch as hubs; DVRT/GuardCF tables not parsed in v1) | ir/pe_tables, propagate / S1-S2 | hubs excluded only from propagation, never from facts | `test_hub_call_change_still_reported` |
| F16 | library tagging: functions Ghidra FID matched to known library bodies (IR `lib`, row flag `library`) sort after first-party rows (R04 s8 addition) | extract + read_model / S1, S4 | tag and order only; a changed library function stays listed with its verdict; FID names are not P03 anchors (source ANALYSIS) | `test_library_rows_ordered_last_never_hidden` |
| F17 | trace-argument ordering: a `constant` delta whose instruction feeds an argument register (RCX/RDX/R8/R9 or [RSP+0x20..]) of a call in the same block to a tracing callee (closed import table: `EtwWrite*`, `WmiTraceMessage*`, `TraceMessage*`, `TraceLogging*`/`_tlgWrite*`; WPP thunks resolved to them) gets hint `trace-arg` and sorts last inside its verdict | facts/channels / S3 | ordering only; verdict unchanged; never hidden | `test_trace_arg_constant_ordered_last_not_hidden` |
| F18 | frame-only edits (`sub/add rsp`, RSP/RBP displacements) classed `frame`, not `struct-offset` (R04 s5) | facts/operands / S3 | `review`, never cosmetic (a buffer resize is a real change) | `test_frame_only_change_is_review_not_material` |

## 4. How the L2 noise (false "changed") rate is bounded
Construction: `unchanged` and `cosmetic` exist only through the named rules of 2.5, each requiring target consistency (2.7); `material` needs a semantic-class delta plus an anchored second channel from another data group; everything else is `review` (visible, ordered, never auto-hidden; default filters collapse only `unchanged` and structural `cosmetic` rows with a visible count, U-03). Measurement (08): G-U1 A/A rebuilds produce 0 `material` and <= 0.1 % `review` rows [inf target]; G-U2 planted mutations: leakage into `cosmetic`/`unchanged` = 0 and recall (material or review) >= 95 % per class; G-U6: the `material` set has >= 20 % fewer false leads than the best legacy output at non-decreasing planted recall (R05 s7 proposal).

## 5. Failure modes

| Case | Result |
|---|---|
| a channel's data unavailable (no IR, no code, oversize) | that channel `unavailable`; verdict computed from the rest; never `cosmetic` by absence |
| alignment cap hit | `review` + `limits_hit` |
| DATA-MAP cannot map a target | `unmapped`: no proof, row `review` (class `address-only`); never `material` |
| row contested | facts still computed for the chosen edge (labelled "for the shown pairing") |
| group rows (N:M) | `not-applicable` for facts in v1 (B-13) |
| S3b unavailable or over budget | C6 stays `unavailable`; rows stay `review` ranked by 2.6 |

## 6. S0 mode as built by S0b (2026-10-14; no ProgramIR)
Inputs per two-sided row of decision matched, tentative, candidate or contested (for the chosen edge): the Ghidriff function records by RVA (code, callee names, diff types; records of ANY match, so a pair another source made from an `added` and a `deleted` function still has code), the stored BinDiff flags of the exact pair, and the mapping of function RVAs through `matched` rows that hold a tier A or M support (B+B rows never map, U-06). One-sided and group rows get no facts (materiality `not-applicable`).
| Channel | S0 definition | State |
|---|---|---|
| C0-C3, C7 | need IR (C7: not in v1) | always `unavailable` |
| C4 (C4n) | multiset of callee identities from the Ghidriff callee names: a default `FUN_`/`thunk_FUN_` label or a unique real name found in the records resolves to an RVA, then to its row token if mapped, else to a side-specific unmapped identity; other real names are their own identity | `equal`/`differs`; `unavailable` without both records |
| C5 (C5t) | multiset of numeric (value-normalised) and string literals of the canonical code | `equal`/`differs`; `unavailable` without code |
| C6 | `canon/1` token sequences identical (2.4); code over L-29 is omitted (`pseudo-cap`) | `equal`/`differs`/`unavailable` |
| C8 | differs iff the BinDiff row of the exact pair carries G, I, E, L or C; J alone is a hint | `unavailable` without that row |
`canon/1` as built: comments and whitespace dropped; locals, parameters and temporaries (`[a-z]{1,4}Var<n>`, `local_<hex>`, `param_<n>`, `in_/unaff_/extraout_*`) renamed `v<k>` by first occurrence; `LAB_/switchD_/caseD_` labels renamed `L<k>` (they stay inside the function); `FUN_/thunk_FUN_` labels become the token of the mapped row or `U<k>` (counted unmapped); `DAT_/PTR_/EXT_/UNK_/BYTE_/WORD_/DWORD_/QWORD_` data labels are always unmapped in S0 (DATA-MAP is S3) and counted; numeric literals are compared by value (`0x200` = `512`), strings and operators exactly. A pair with unmapped labels never gets COS-PSEUDO/1 (R-02): it is `review`, class `address-only`.
Deltas (<= L-28, sorted by 2.6 severity): callee identity differences from C4 (`callee` when a replaced pair exists, else `call-added`/`call-removed`; channel C4, or C6 when only C6 is available); literal differences from C5 (`constant`, `string`); relational/logical operator count differences from C6 (`comparison`, `condition`); remaining C6 differences `unknown` (never semantic). `ChangeFacts.targets` = (distinct mapped function labels, distinct unmapped labels, callee replacements between two different mapped rows).
Verdict (first match): not-applicable for one-sided/group rows; `cosmetic` with COS-PSEUDO/1 iff no semantic delta, C4 = C5 = C6 `equal`, unmapped = conflict = 0 and eh is not `differs`; `material` iff a callee-class delta has an ANCHORED second channel of another data group that differs by the same callee identity: delta seen by C4 -> C6 (its call tokens contain the identity) or C8 flag C; delta seen by C6 -> C4 or C8 flag C; constants, strings, comparisons and conditions have no anchor in S0 (C5 and C6 share the decompiler group), so they stay `review` ranked first (S3b promotes them); else `review` when any of: a semantic delta, a differing channel, unmapped or conflicting labels, a Ghidriff `modified` pair, a differing C8; else `unknown` (no signal, never `cosmetic` or `unchanged` by absence). `unchanged` and COS-ADDR/COS-LAYOUT cannot be issued in S0 (they need IR bytes and DATA-MAP). Ghidriff diff types never decide (F4): they add the hint `ghidriff-diff-types:<csv>` and, when ALL listed types are non-code (`address`, `refcount`, `size`, `name`), the row classes `address-only`, `refcount-only`, `size-only`, `name-only` for ordering only.
