# 02 - BinDiff (google/bindiff 8) at reimplementation level (unified diff engine research)

Research date 2026-10-14. Extends, does not repeat: `../phase3/binexport-bindiff.md`, `../phase-c/bindiff-automation.md`, `../../specs/bindiff-adapter.md` (SPEC-10), `../../specs/bindiff-execution.md` (SPEC-29). Labels: **[src]** read in code, **[doc]** official doc or paper, **[inf]** my inference, **[unv]** not verified. Every effort figure is [inf].
Sources (11 families; no clone, no git): **S1** `google/bindiff` tag `v8` via raw.githubusercontent.com. Algorithm files sit at the repo ROOT (`src/...` URLs 404): `bindiff.json differ.cc flow_graph.cc call_graph.cc graph_util.h instruction.cc prime_signature.* fixed_points.cc change_classifier.cc config.cc database_writer.cc main_portable.cc match/*`. `main` (2026-10-14) was re-fetched for 9 of them: default config byte-identical, refactors plus one return-value fix, so v8 findings hold for `main`. **S2** same repo `docs/concepts.md`, `version-history.md`, `README.md`, `LICENSE`, `cmake/BinDiffDeps.cmake`. **S3** Flake, DIMVA 2004. **S4** Dullien and Rolles, SSTIC 2005 (both PDFs from `docs/papers/`). **S5** `google/binexport` `binexport2.proto` at `v12-20230925-bindiff8` and `main`. **S6** BinExport `main` `java/src/main/java/com/google/security/binexport/BinExport2Builder.java`. **S7** quarkslab `qbindiff`, `python-bindiff`, `python-binexport`. **S8** angr `analyses/bindiff.py`. **S9** Diaphora README. **S10** GitHub issue/code search. **S11** `blacktop/bindiff-rs`.
Unreachable: zynamics.com manual (DNS failure) and arxiv.org (403 from the egress proxy). No manual text and no third-party accuracy benchmark is used.

## 1. Verdict
- BinDiff is a greedy, uniqueness-gated, strongest-first matcher. A pair is created only when a feature value occurs exactly once on each side; ambiguity triggers a drill-down with the next steps, else abstention. No score threshold, no global optimisation, no backtracking.
- It sees only names, call graph, CFG shape, mnemonic ids, raw bytes and call targets. Operands and constants are never compared (flag `O` is never set) and string-reference steps are inert, so constant-only patches report similarity 1.0.
- Precision sits in the top steps (confidence >= 0.9). The tail (<= 0.7) pairs leftovers and must be tiered, not trusted.
- The matcher is ~3.8k non-comment C++ lines, Apache-2.0. Recommendation (section 13): port the core to Python as PatchTrace's in-process structural matcher (L1 correspondence); keep SPEC-29 only as an optional oracle and second opinion; build the Ghidra extraction layer once for both.

## 2. BinExport2 data actually used [src differ.cc, flow_graph.cc, call_graph.cc; S5; S6]
| Field | Use |
|---|---|
| `meta_information` | `executable_id` -> `file.hash`, `executable_name` -> `exefilename`; `architecture_name`, `timestamp` unused |
| `call_graph.vertex` | address (sorted, else load error), name (demangled else mangled; "real" = exporter set one), `LIBRARY` -> library flag, `THUNK` -> stub flag that no matcher reads; `IMPORTED`, `INVALID`, library/module indexes ignored |
| `call_graph.edge` | multi-edges flagged duplicate, self edges "circular"; degrees count every edge |
| `flow_graph` | BB list (address-sorted), entry BB, edges; edge types are parsed but no step reads them; `is_back_edge` unused (loops recomputed by dominators) |
| `instruction` | address (when present), mnemonic string -> id, `raw_bytes`, `call_target[]`; comments for the UI only |
| NOT read | `expression`, `operand`, `string_reference`, `data_reference`, `section`, `library`, `module`, `md_index` (field 93992622 exists only on BinExport `main`, not in the v8-era proto) |
No normalisation: mnemonic spelling is the exporter's (Ghidra exporter has an optional IDA remap); `raw_bytes` are raw, so RIP-relative or relocated operands change the byte hash [inf]. A function with >= 5000 BBs, >= 5000 edges or >= 10000 instructions keeps prime and hash but loses its graph (MD index 0 = "trivial"). Call-graph vertices without a flow graph (imports, externs) get an empty flow graph flagged stub+library; library+trivial functions match only by name.
Ghidra exporter [S6 `main`, not checked at the release tag]: `executable_id` = `getExecutableSHA256()` (L164); jump references to a function entry are exported as `call_target` like calls (L686-703); vertex types THUNK and IMPORTED only, never LIBRARY; name set only if not the default `FUN_` name (L910-918); `build()` promotes undefined code to functions, mutating the program (L752, L1211).

## 3. Driver and generic matcher [src differ.cc `Diff`, match/call_graph.h]
```text
Diff(steps = config.function_matching, config order IS execution order):      # 17 by default
  for L in suffixes(steps):                          # L[0] = current step, L[1:] = drill-down tail
    find(L[0], parent=None, A=all primary graphs, B=all secondary graphs, tail=L)
    repeat until nothing new:                        # fixed points visited in primary-address order
      for fp in fixed_points: kids = unmatched callees (2nd loop: callers), duplicate edges skipped
        if kids_A and kids_B: find(L[0], fp, kids_A, kids_B, L)
    for fp in fixed points created at this level: call_reference_matching(fp)   # conf 0.75, positional callee pairing
  classify_changes()
find(step, A, B, tail):        # node steps; edge steps key an EDGE by (f(src), f(tgt)) and match both endpoints
  bucket candidates (unmatched, not (trivial and library)) by step.key
  for key in bucket_A:
    if |A[key]|>1 or |B[key]|>1: find(tail[0], A[key], B[key], tail[1:]) if tail else abstain; drop key
    elif key in B and (not step.strict or MD(a)==MD(b)): fixed_point(a, b, step.name); match_basic_blocks(a, b); rescore(a, b)
```
Propagation at level k uses steps k.. only, so earlier strong steps are not retried around late anchors [src]. MD keys are compared by exact double equality (summands sorted before summing). The BB engine is the same loop over the BBs of one function pair (propagation to unmatched CFG preds/succs, then a last-resort fixpoint "propagation (size==1)"). Output is deterministic (sets ordered by entry address; a `stable_sort` fix exists because Linux and Windows once diverged). Lineage: initial unique 3-tuple (#BB, #edges, #calltree edges) [S3 eq. 1], caller/callee propagation [S3 4.2, S4 4.3.2].

## 4. Function steps in default execution order [src `bindiff.json`, match/function_*.cc; conf = default]
| # | Step | Conf | Key and gate |
|---|---|---|---|
| 1 | name hash | 1.0 | SDBM32 of demangled-else-raw name; real names only; allowed for library/trivial, so imports match only here |
| 2 | hash | 1.0 | SDBM32 of all raw bytes in BB order; non-trivial only |
| 3 | edges flowgraph MD index | 1.0 | call edge keyed (MD(src), MD(tgt)); unique pair matches both ends; skips duplicate/self edges and MD==0 ends |
| 4 | edges callgraph MD index | 0.9 | call-graph edge MD (position in the global call graph) |
| 5-6 | MD index flowgraph top down / bottom up | 0.9 | function MD, BFS from entry / from exits; trivial functions all key 0.0 |
| 7 | prime signature | 0.9 | sum of mnemonic ids over the function (multiset) |
| 8-9 | MD index callgraph top down / bottom up | 0.8 | sum of incident call-graph edge MD (context dependent) |
| 10 | relaxed MD index | 0.7 | call-graph node MD, weights (2,3,5,7,0,0): local degrees only |
| 11 | instruction count | 0.4 | instruction count; strict: flow-graph MD must be equal |
| 12 | address sequence | 0.4 | rank by (size desc, address) of candidates; strict: MD equal; docs' "equal-size sets" rule is not in code |
| 13 | string references | 0.7 | INERT: hash fixed at 1, step needs > 1 [src flow_graph.cc "we don't export string references"] |
| 14 | loop count | 0.6 | back edges (dominator), needs >= 1 |
| 15-17 | call sequence exact / topology / sequence | 0.1 / 0 / 0 | only during propagation (needs matched parent); key (BB level, call ordinal) / level / rank |
| + | call reference matching | 0.75 | hard-coded, after each level: callees of matched BB pairs with equal call counts paired by position, no content check |
| + | edges proximity MD index | - | registered, absent from default config (docs: speed "poor") |

## 5. Basic-block and instruction level [src bindiff.json, match/basic_block_*.cc]
| # | Step | Conf | Key |
|---|---|---|---|
| 1 | edges prime product | 1.0 | edge key prime(src)+prime(tgt)+1 (a sum despite the name) |
| 2-3 | hash / prime, >= 4 instructions | 1.0 / 0.9 | SDBM32 of BB bytes / sum of mnemonic ids |
| 4 | call reference | 0.8 | BB whose callees are all matched; key n*(addr_a+addr_b) of the LAST callee only (value overwritten) |
| 5 | string references | 0.8 | inert, as in section 4 |
| 6-9 | edges MD / MD, top down and bottom up | 0.7 | CFG edge or node MD with BFS levels |
| 10 | relaxed MD index | 0.6 | node MD, weights (2,3,5,7,0,0) |
| 11 | prime, 0 instructions minimum | 0.5 | as step 3 without the size gate |
| 12-16 | Lengauer-Tarjan back edges 0.4, loop entry 0.4, self loop 0.3, entry 0.2, exit 0.1 | | back-edge / k-th loop entry / self-edge count / in-degree 0 / out-degree 0 |
| 17-18 | instruction count, jump sequence | 0 / 0 | key MD*1e18 + instruction count / MD*1e18 + running index (k-th block of equal MD) |
| + | propagation (size==1) | 0.0 | lone unmatched pred/succ of a matched pair, content ignored |
Instruction level: Hirschberg LCS (linear space) over mnemonic ids inside each matched BB pair; the pairs fill the `instruction` table. Operands are never compared.

## 6. Feature definitions [src graph_util.h, flow_graph.cc, call_graph.cc, prime_signature.cc]
- Edge MD = 1 / (sqrt2*in(s) + sqrt3*out(s) + sqrt5*in(t) + sqrt7*out(t) + sqrt11*lvl(s) + sqrt13*lvl(t)); graph MD = sum over edges. Node MD = sum over incident in+out edges (relaxed variant: weights 2,3,5,7,0,0). lvl = BFS depth from in-degree-0 roots (top down) or from out-degree-0 sinks over reversed edges (bottom up). Call-graph vertex MD = sum of the stored global edge values.
- Quirks to decide on in a port: level 0 doubles as "unvisited"; a CFG whose entry has an incoming edge has no root, so all levels stay 0; loop detection assumes vertex 0 (lowest address) is the entry; levels are uint16. Test vector, diamond CFG A->B, A->C, B->D, C->D: levels 0,1,1,2, graph MD 0.277559753195558 (hand-computed, not cross-checked [inf]). Python 3.12+ `sum()` of floats is compensated; use a plain loop to match C++ accumulation.
- Mnemonic id = product over characters c > 32 of prime[c-32]^(position+1), wrapping mod 2^32 (a Goedel-style hash, not a prime; only the first 95 of the 12.5k-line prime table are reachable). BB prime = SUM of ids, function prime = sum of BB primes (uint64). Docs and S4 say "product"; any order-independent multiset hash works for a port, and the sum is algebraically weaker than S4 4.4's argument [inf].
- Hashes are 32-bit SDBM, so unrelated functions can collide (about 2^-32 per pair) [inf]. Loop count = back edges whose target dominates the source. Call level = (BFS level of the BB, call ordinal in BB).

## 7. Scores and change flags [src differ.cc, change_classifier.cc; S2 concepts.md]
- Confidence of a match: m = weighted mean of step confidences over its histogram (function step x1, each matched BB's step x1); conf = 1/(1+exp(-(m-0.5)*10)). m 1.0 -> 0.993, 0.9 -> 0.982, 0.7 -> 0.881, 0.5 -> 0.500, 0.3 -> 0.119, 0 -> 0.007. Whole-binary confidence uses all matches. Not a probability, not calibrated.
- Function similarity: exactly 1.0 if every BB and instruction is matched on both sides, else t = min(1, 0.55 E/avgE + 0.30 B/avgB + 0.15 I/avgI); sim = (t + 1 - |MD1-MD2|/(1+MD1+MD2))/2 * conf. Effective weights 27.5/15/7.5/50 % (docs say ~25/15/10/50). A code TODO says the `* conf` makes good matches "voted down"; it is still applied.
- Binary similarity: min(1, 0.35 edges + 0.25 BBs + 0.10 functions + 0.10 instructions + 0.20 (1 - call-graph MD gap)) * conf, non-library only.
- Flags, set once after matching: G BB/edge count differs or a primary edge has an unmatched end; I a matched BB's instruction count differs from its LCS length; O never set; J branch-inversion heuristic; E entry BB not paired with the other entry or changed; L loop counts differ; C positionally paired callees not matched to each other.
- `similarity == 1.0` therefore means mnemonic-level identity, not byte identity.

## 8. `.BinDiff` and config additions to the existing notes [src database_writer.cc 216-290, config.cc, main_portable.cc]
- DDL equals the existing note. There is no similarity or confidence table: both are columns of `function`, plus `metadata` for the whole binary. Default-run ids: function 1-17 in config order, 18 call reference, 19 manual; BB 1-18, 19 propagation, 20 manual (still join by name).
- Rows exist only for matches. Imports and stubs are written like any match (`function.basicblocks = 0`, similarity 1.0 by the shortcut): an importer must not count them as code matches. `evaluate` is 0 from the CLI; names are omitted if `binary_format.exclude_function_names`.
- `--config=F` runs `config = Defaults(); MergeInto(F)`: `{}` gives pure defaults (answers SPEC-29 U5); a non-empty, name-unique `function_matching` or `basic_block_matching` list REPLACES the default, so order and confidences are settable and edge steps can be dropped for speed (docs advise this). `Proto()` has already read machine and user config and called `GetOrCreateAppDataDirectory`, so keep SPEC-29's private HOME/APPDATA.
- `bindiff --md_index --primary=x.BinExport` prints the call-graph MD and every function's MD to 12 decimals: a ready oracle for a port.

## 9. Strengths worth keeping
- Abstention on ambiguity plus strongest-first order: weak steps only see leftovers, early pairs are never re-opened [src].
- Neighbourhood propagation shrinks candidate sets (callers/callees, CFG preds/succs), raising uniqueness [S2, S4].
- Position-independent keys (topology, mnemonic multiset, names); addresses are never compared across binaries, so rebasing is harmless [src].
- Per-match provenance (`function.algorithm`, `basicblock.algorithm`) plus confidence; deterministic; function -> BB -> instruction hierarchy; a change taxonomy.
- Small and documented: the algorithm fits in ~3.8k lines (differ 453, flow_graph 534, call_graph 434, match core 809, function steps 362, BB steps 472, classifier 166, LCS 137, MD util 137, fixed points 134) [src, counted].

## 10. Weaknesses, false-positive and false-negative sources
| Cause | Effect | Evidence |
|---|---|---|
| Operands, constants, data refs never compared | Constant-only or register-only patches look identical (FN). Flake: "possible false negatives ... constants or buffer sizes" | src `TODO`; S3 6.3 |
| String-reference steps dead on BinExport2 input | Error-handling stubs lose a key | src flow_graph.cc |
| Tail steps (relaxed MD, loop count, instruction count, address sequence, call sequence, call reference, BB entry/exit/jump/propagation) | Low-confidence pairings of unrelated small functions; FPs concentrate here | inf from confidences |
| Thunks, stubs, one-block functions (MD 0) | Skipped by hash and edge steps; `THUNK` never consulted; imports match by name only; others pair by prime/context or not | src |
| Changed functions have no strong key (hash, MD, prime all move) | Matched by name, context or weak steps, or left unmatched ("no unique evidence", not "removed") | inf; S3 intro |
| Inlining, outlining, LTO, other compiler or flags | CFG and mnemonic multiset change. Flake: free of FPs "unless heavy ... inlining". No block-merge pass in the differ; exporters do it (issue #53: IDA merges blocks on unconditional branches) | S3 6.1; S10 |
| Size caps (>= 5000 BB/edges, >= 10000 instructions) | Graph dropped, only name/prime/hash keys remain | src |
| Greedy, no repair | One early wrong pair anchors propagation | src |
| Exporter semantics (Ghidra: jump = call, no LIBRARY, `FUN_` not a name, raw bytes) | Hash, name and call-reference behaviour differ from IDA-based expectations | S6 |
| Stripped binaries | Name step only for imports/exports; everything else needs structure | src |

## 11. Runtime and memory
- No v8 measurement exists in primary sources [unv]. Old data: 2310 functions in 183 s (2004 hardware) [S3 5.1]; 1655-function DLL under 5 min [S4]. Docs rate edge and proximity steps "medium"/"poor" and say to disable edge steps first on slow inputs; source TODOs flag proximity worst case and `Diff` re-scanning all fixed points.
- One pair is single-threaded (`num_threads` only drives batch mode). The whole `.BinExport` is parsed in memory plus Boost graphs; format limit 2 GiB since 4.2 [S2]; memory a few times file size [inf]. A pure-Python port is plausibly 10-50x slower than C++ unless keys are integer-coded and per-instruction objects are avoided [inf]. SPEC-29 U8 stays open.

## 12. Licence and reuse
- BinDiff and BinExport are Apache-2.0 (`LICENSE` 11358 bytes, standard text; headers "Copyright 2011-2023 Google LLC"); v8 has no NOTICE file (404). Porting code is a derivative: ship the licence text, keep headers, mark changed files (s4b), do not use the name "BinDiff" for our engine (s6). The s3 patent grant covers contributions we derive from, not a clean-room rewrite; patents were not examined [unv]. No legal review was done.
- GUI needs commercial yFiles (README): never redistribute, irrelevant to the engine. Core deps (SQLite 3.38.5 amalgamation via CMake, Boost, Abseil, protobuf) are not needed by a Python port. PatchTrace is MIT; Apache-2.0 files may sit in it with notices; GPL-3.0 ghidriff stays a separate process (`docs/notices.md`).
- Do not copy the 12.5k-line prime table (regenerate or use any multiset hash) and nothing from Diaphora.

## 13. Existing ports, reimplementations and reuse candidates
- No port of the v8 step list found: code search for exact step names outside `google/bindiff` hits only quarkslab `python-bindiff` (DB reader), research dumps and `.results` files [S10].
- angr `analyses/bindiff.py` (BSD-2-Clause, ~1.5k lines): paper-era Python matcher on angr CFGs (function tuple (#BB, #edges, #calls) plus name/PLT matches, worklist over callers/callees, block tuple (dist to entry, dist to exit, #calls) with Euclidean nearest neighbour). It also reports differing constants, the gap BinDiff leaves [S8]. Ideas and snippets are reusable with the BSD notice; it is bound to angr objects.
- quarkslab (all Apache-2.0): `python-binexport` BinExport2 reader (IDA, Ghidra, Binary Ninja files); `python-bindiff` runs the tool and reads results (looks for a `differ` executable, the pre-v8 name); `qbindiff` is a different algorithm (network alignment, belief propagation) whose README warns of memory blow-up above ~10k functions [S7]. `bindiff-rs` (MIT) only reads `.BinDiff` [S11].
- Diaphora (AGPL-3.0 since 2.0, commercial option): ideas only, no code read or copied: dozens of tiered heuristics, similarity ratios, decompiler-output heuristics [S9]. Ghidra Version Tracking correlators not examined [unv].

## 14. Port versus run, recommendation
| | A. Run BinDiff (SPEC-29) | B. Python port of the core |
|---|---|---|
| Effort | SPEC-29 P2-P5 8-12 d, live gate P6 2-4 d, BinExport producer for Ghidra 12.x (own writer 3-5 d, or build the extension, unverified) = 13-21 d | extraction 3-5 d (shared), MVP engine 12-16 d, parity harness 6-10 d, performance 3-5 d = 24-36 d; MVP with extraction 15-21 d |
| Fidelity | Authoritative BinDiff output and `.BinDiff` interop | "BinDiff-style"; parity provable only with an oracle |
| Control | Cannot add operand awareness, tiers or provenance beyond the DB | Full: tiers, `O` flag, real string/data-ref steps from Ghidra, cooperative cancel |
| Main risks | External install (MSI/deb), version drift, unknown runtime/memory, blocked live checks, no bundling | Parity drift (float keys, quirks), pure-Python speed, upkeep, attribution |
MVP = MD index and BFS, name/hash/edges-flowgraph/MD/prime/callgraph-MD/relaxed steps, propagation, call reference, 10 BB steps, LCS, scores, flags G I J E L C. Full = default config.
Recommendation (hybrid, staged):
1. Build the extraction layer first: a BinExport-lite graph from pyghidra (functions, BBs, mnemonics, raw bytes, call targets, names, thunk/extern flags) that can also write BinExport2. It feeds both A and B and removes the Ghidra-version coupling of the BinExport extension.
2. Finish SPEC-29 only as far as an oracle (P2-P5, one live run, 5 real pairs); keep it an optional reference engine in reconciliation, never bundled.
3. Port the core as the in-process L1 structural matcher. Add what BinDiff lacks: operand/constant change detection (L2 input), string and data-reference steps, a fuzzy second pass for leftovers, and cross-engine acceptance (a Tier C pair, conf <= 0.7, stays a candidate until Ghidriff or rz-diff agree). Do not port the UI, the DB writer (own schema, `.BinDiff` export optional), edges-proximity or the dead string steps.
4. Gates [proposals]: G1 MD index equal to 12 decimals on >= 99.9 % of functions of the oracle exports; G2 >= 98 % agreement on matches with conf >= 0.8 and no contradictory top-tier pair. If either fails, stay on A with post-processing.

## 15. Corrections and extensions to the existing notes
- `phase3/binexport-bindiff.md`: `md_index` 93992622 is `main`-only and unused by the differ; `edges proximity MD index` is absent from default `functionalgorithm`; the string-reference rows exist but are never produced; flag `O` is defined but never set.
- SPEC-29: U5 answered (section 8); U9 confirmed for BinExport `main` (L164); a single pair is single-threaded; cited `src/main_portable.cc` is root `main_portable.cc` at `v8` and `main`; confidence stays in (0.007, 0.993) for non-empty runs.
- SPEC-10: treat `basicblocks = 0` rows as import/stub matches. `concepts.md` differs from code on prime product vs sum, function weights, and the address-sequence size rule.

## 16. Open questions
1. Real v8 runtime and memory on PatchTrace targets (10-50 MB drivers, 40k functions); needs a live install.
2. Per-step hit rates on Ghidra-exported patch pairs (hash vs RIP-relative bytes, thunks); needs the oracle.
3. Effect of the Ghidra vs IDA block model on MD parity; bug-for-bug or fixed quirks (section 6) in a port.
4. Patent, trademark and NOTICE review of a derived port; the zynamics manual may add guidance (unreachable here).
5. Precision and recall per confidence tier on PatchTrace's labelled pairs.
