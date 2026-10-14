# 03 Ghidriff (+ Ghidra Version Tracking) and Rizin rz-diff as inputs to a unified diff engine

Research date 2026-10-14. Labels: **[src]** read in upstream source; **[run]** executed by me on controlled inputs (numbers in 3 and 4); **[doc]** upstream documentation; **[inf]** inference, unverified.
Validates and extends `docs/research/phase3/rizin.md`, SPEC-11 and SPEC-27 (delta list in 9). This file records observable behaviour; it is not a porting guide (GPL source was read, see 6).

## 0. Sources (13) and pins
- G1 `clearbluejar/ghidriff` `ghidriff/*.py` and `README.md` on `main`, raw.githubusercontent.com, fetched 2026-10-14. Commit SHA unobtainable (GitHub API blocked here).
  The brief's `clearcut-cyber/ghidriff` returns 404; the canonical repo is clearbluejar. G2 issue #121. G3 PyPI `ghidriff 1.0.0` (2025-07-04, GPL-3.0).
  1.0.0 is older: its `skip_types` has a missing comma, so BulkBasicBlock/Decomp skipping never applied.
- V1 Ghidra `master` (Apache-2.0) `Features/Base/.../plugin/match/*` (hashers, `MatchFunctions`, `MatchSymbol`). V2 `Features/VersionTracking/.../correlator/{program,address}/*`, `gui/util/ImpliedMatchUtils.java`, `ghidra_scripts/AutoVersionTrackingScript.java`.
  V3 VT help `VT_Correlators.html`, `VT_AutoVT.html`. V4 `Framework/SoftwareModeling/.../correlate/HashedFunctionAddressCorrelation.java`. V5 `VersionTrackingBSim/.../BSimProgramCorrelatorFactory.java`.
- R1 rizin tag `v0.9.1` `librz/main/rz-diff.c` (`dev`, v0.10.0-dev, compared). R2 `librz/arch/similarity.c`, `librz/diff/{distance,diff}.c`, `include/rz_analysis.h`. R3 `REUSE.toml`, `COPYING*`, `librz/core/cconfig.c`. R4 official `rizin-v0.9.1-static-x86_64` binary (sha256 9102249a...e8cf).
- Test inputs: zlib 1.3 and 1.3.1 (madler/zlib tags) built gcc -O2 x86-64 ELF; Ghidra 12.0.4 + pyghidra 3.0.2 + JPype 1.5.2; Python 3.13 difflib. **No Windows PE was available here: all PE statements are [inf].**

## 1. Ghidriff `VersionTrackingDiff` (default engine): pass order [src; order and names confirmed in a real log]
- Not Ghidra VT proper: no VT session except a synthetic one fed to BSim. It calls Ghidra's Match-plugin APIs (`MatchSymbol`, `MatchFunctions`, built-in hashers) plus Python `FunctionHasher` proxies.
- Matched functions leave the candidate sets after every pass, so order matters (source comment: "order has major impact on accuracy").
- Hash passes consider non-thunk functions with body >= `--min-func-len` (10 address bytes). Preflight: same language ID and |#symbols old-new| < 4000, else abort unless `--force-diff`.

| # | `match_types` name | What is compared (origin) | Cardinality / note |
|---|---|---|---|
| 0 | SymbolsHash | Ghidra `MatchSymbol`: namespace+name, address suffix stripped, len>=3, DEFAULT (`FUN_`) names excluded; functions only, then `getName(True)` equal | 1:1 by name; only pass that sees thunks; externals included |
| 1 | ExactBytesFunctionHasher | FNV-1a-64 of raw bytes of every code unit in the body | 1:1 |
| 2 | ExactInstructionsFunctionHasher | same bytes after the SLEIGH instruction mask: operand bits (imm, disp, rel targets, reg fields) zeroed, opcode bits kept | 1:1 |
| 3 | StructuralGraphExactHash | hash(#blocks, #CALL/bl, #edges), Halvar Flake 2004 style | 1:1; tiny entropy, accepts any unique shape |
| 4 | ExactMnemonicsFunctionHasher | sequence of (mnemonic, #operands) | 1:1 |
| 5 | BSIM | Ghidra BSim correlator (decompiler features, LSH), unmatched sets only (`--bsim-full`: all); off with `--no-bsim` or if absent. Seeds = SymbolsHash, ExactBytes, ExactInstructions, ExactMnemonics matches (seed list says `StructuralGraphExactHasher`, the match type is `...Hash`: typo, those never seed) | seed confidence 10.0 [V5]; 1 pair in each of my zlib runs |
| 6 | BulkInstructionHash | hash(sorted instruction texts, operands included) | 1:1 |
| 7-10 | SigCallingCalledHasher, StringsRefsHasher, StrUniqueFuncRefsHasher, SwitchSigHasher | called-name set + signature (the "calling" list is also built from `getCalledFunctions`: upstream defect); sorted referenced strings (uuid if none: never matches); string set + refcount; signature + `switchD/caseD` symbol names (address-bearing [inf]) | 1:1 |
| 11 | StructuralGraphHash | hash(name unless default, #blocks, #edges, #calls, body bytes, #params, refcount) | **1:N allowed: every (a,b) of a bucket is emitted** |
| 12 | BulkBasicBlockMnemonicHash | hash(sorted mnemonics of all blocks) | 1:N allowed; listed in `skip_types` |
| 13-16 | repeat of 7-10 on residual sets | earlier removals make buckets unique | 1:1 |
| 17 | Implied Match | port of VT `ImpliedMatchUtils`: per pair, align instructions (`HashedFunctionAddressCorrelation`), pair CALL targets (data refs ignored, thunks resolved) | accepted if src OR dst is unmatched; **no vote/conflict threshold** |
| 18 | Decomp Match | decompile residuals (memoised), equal C body minus signature, O(n*m) compares, labels not renumbered | first hit; in `skip_types` |
| 19 | ExternalsName | externals by qualified name | - |

Ghidra's own AutoVT [V3, V2]:
- Order: Exact Symbol Name -> Exact Data (min len 5) -> Exact Function Bytes -> Instructions -> Mnemonics -> Duplicate Function Instructions (non-1:1, confidence 10/(a*b)) -> one Reference correlator (Data | Function | Combined) -> Implied Matches applied only with >= 2 votes and 0 conflicts.
- Exact Bytes/Instructions/Duplicate require equal size, Mnemonics does not. **Not used by ghidriff:** data matching, duplicate and similar-symbol (trigram LSH cosine >= 0.5) correlators, and all Reference correlators.
- Reference correlator: each ACCEPTED match is a feature weighted sqrt(-ln p), p = (src refs + dst refs)/(F_src + F_dst); per-function sparse vectors plus "unmatched reference" features at p = 0.5.
  Similarity = cosine, confidence = dot product x 10; script thresholds 0.95 / 10.0 (help text says 9.5); refine: top 5, within 0.2 of best, ties dropped.
- Instruction alignment inside a pair [V4]: greedy anchored n-gram matching on mnemonic hashes, basic-block aware, parent/child/bytes disambiguation, several passes. VT scores "should NOT be compared" across correlators [V3].

## 2. Ghidriff scoring, classification, output [src unless marked]
- `ratio` = round(2M/T, 2) of `difflib.SequenceMatcher` over decompiler C lines (signature removed; `LAB_/DAT_/FUN_` renumbered by first appearance, only the first label per line: TODO in code).
- `i_ratio`: over `str(instruction)` (operands and absolute addresses included). `b_ratio`: over per-block sorted mnemonics concatenated in block order.
- `m_ratio`: over `mnemonics`, but `enhance_sym` stores `str(code.getMnemonicString)` without the call. Real Ghidra 12.0.4 returns the constant `ghidra.program.database.code.InstructionDB.getMnemonicString` for every instruction **[run]**.
  So `m_ratio` = 2*min(n1,n2)/(n1+n2), an instruction-count ratio, not a mnemonic similarity.
- All ratios are text-diff statistics of an already paired function, not match confidence. Two-decimal rounding hides a one-instruction edit above ~100 instructions.
  difflib `autojunk` (>= 200 items) cut the ratio by > 0.05 in 128/300 synthetic mnemonic lists with one change **[run]** (13-token vocabulary; real text has more entropy [inf]).
- Gate `syms_need_diff`: a pair is examined only if no skip type AND (body bytes differ OR symbol refcount differs OR weak-pass match of a function <= `min_func_len` when `min_func_len` < 10).
  Same size + same refcount = unchanged, whatever pass paired it (issue #121, open).
- `diff_type` in {code, name, fullname, refcount, length, sig, address, calling, called, parent}. `code` needs a decompiled-text diff AND (`m_ratio` < 1 OR `b_ratio` < 1) and no "Could not recover jumptable" in the diff.
  `ratio == 0 and b_ratio == 0` is dropped as a bad match; empty `diff_type` is dropped.
- Buckets: added/deleted = unmatched non-thunk functions >= min length plus unmatched externals, minus names that also appear as unmatched non-function symbols; modified = gated pairs with a `diff_type`.
  Unchanged pairs exist only in `matches.address_matches` (old address text -> [[new address text, [match_types in pass order]]]; may be 1:N; keys such as `EXTERNAL:0000000c` occur **[run]**).
- `stats.matched_funcs_len` = (F_old + F_new) - (added + deleted): counts thunks, tiny functions and both sides (100.0000% in my run). Do not use.
- JSON root **[run]**: program_options, matches{address_matches,name_matches}, stats, symbols, strings, functions{added,deleted,modified}, old_meta/new_meta (incl. Executable SHA256/MD5), md_credits, html_credits (+ old_pe_url/new_pe_url for MSVC PEs [src]).
  Enhanced function: name, fullname, parent, refcount, length, called, calling, paramcount, address, sig, code, instructions|mnemonics|blocks (saved as hash ints), sym_type, sym_source, external. modified = {old,new,diff,diff_type,ratio,i_ratio,m_ratio,b_ratio,match_types}.
- Markdown: mermaid chart, metadata and analysis options, stats, strings, Deleted, Added, Modified (only `code`), Modified (No Code Changes) (slight mods, filtered by `m_ratio` < 1 or empty diff, FUN_-only noise rules); `--sxs` adds HTML.
- Tuning: `--min-func-len` 10, `--bsim/--no-bsim`, `--bsim-full`, `--use-calling-counts`, `--decompiler-timeout` 60, `--program-options`, `--no-symbols`, `--force-diff`, `--base-address`, `--gdt`, `--threaded`, `--max-ram-percent` 60, `--engine` {VersionTrackingDiff, SimpleDiff, StructualGraphDiff}.
  The documented analyzer defaults ("Decompiler Parameter ID", "Shared Return Calls") are applied only when a `--program-options` file is supplied (guard in `analyze_program`).

## 3. Ghidriff measured behaviour and noise **[run]**
- zlib 1.3 -> 1.3.1, stripped (138 text symbols per build): about 1 min wall including JVM start and two analyses; diff stage 6.9 s; 8 decompilers. 130 correct internal pairs plus 19 external pairs.
  4 "wrong" pairs are alias groups (gzoffset/gzoffset64, gztell/gztell64, identical bodies) cross-multiplied by pass 11.
- 3 genuine code changes (independent objdump text diff):
  - zError (+bounds check): flagged `code`, paired by BSIM.
  - deflateCopy (+1 instruction): `diff_type ['length']` only (m/b ratio round to 1.0); absent from the markdown (0 hits for its FUN_ name).
  - inflateSync (`shl rbx,cl` -> `shr rbx,cl`, same size; zlib's bit-buffer fix): paired at pass 3 by the weak structural hash, silently unchanged by the gate.
  - Recall of real changes: 1/3 as `code`, 2/3 in JSON, 1/3 invisible.
- Constant-only edits (`cmp esi,0x100` -> `0x200`, `cmp edx,0x40` -> `0x41`): paired by ExactInstructions, `modified_funcs_len` = 0. rz-diff flags both (PARTIAL 0.969 and 0.993): the engines are complementary on this class.
- Noise map:
  - renames: SymbolsHash is exact-only, pass 11 hashes the name, name/fullname diff types appear;
  - address shifts: `address` diff type, `i_ratio` falls, ExactBytes fails, masked passes survive;
  - compiler reordering: masked hash fails, multiset passes 11-12 are 1:N;
  - thunks and jump tables: thunks are never hashed nor reported unmatched, the jumptable warning suppresses `code`;
  - inlining: length/called/refcount change, 1:1 only, no split/merge notion; functions < 10 bytes are invisible (#121: lower `--min-func-len`, maintainer warns of false matches).
- Scale [doc]: ntoskrnl 22621.1344 -> .1413: Ghidra analysis 1349 and 1353 s per binary, diff 86 s, 60,664 functions (both), 27,893 SymbolsHash pairs (PDB present), 11 modified.
  Cost is analysis plus decompiling changed pairs; the ladder is seconds. Memory: JVM cap 60% of RAM, no upstream figures.

## 4. rz-diff v0.9.1
- **Modes [src]:**
  - `-t functions`: `aaa` on both files, then every A function is scored against every B function.
  - `-t graphs -0 A -1 B`: analyses only the two functions (unless `-B`), matches blocks, prints DOT (A's CFG; lightgray 1.0 / yellow >= 0.5 / red) or JSON.
  - `-t bytes|lines|symbols|strings|sections|imports|libraries|classes|fields|entries`: Ratcliff/Obershelp hunk diff (difflib family). `-t command`: line diff of command output.
  - `-d myers|leven|lcs-roll|ssdeep`: whole-file `{similarity,distance[,chunk_size]}`; myers/leven truncate inputs to 1 MiB with a warning; ssdeep needs `-i` hash strings **[run]**.
- **Function similarity [src]:** raw bytes of all basic blocks concatenated (no masking). Equal size and memcmp -> 1.0, else 1 - d/max(|a|,|b|), d = unit-cost Levenshtein (prefix/suffix trimmed; O(|a||b|) time, O(min) memory).
  COMPLETE >= 1.0, PARTIAL >= 0.5, UNLIKE < 0.5.
- **Selection [src+run]:** for each A function visit all B in list order (observed ascending address); B bytes are re-read per pair under a mutex. Equal non-empty names not starting `fcn.` pair immediately.
  Otherwise `if (sim < 0.5 && sim <= best) continue; best = sim`: in v0.9.1 any candidate >= 0.5 replaces the current best, so the **last** B with sim >= 0.5 wins, not the argmax. B is never consumed, so pairs are many-to-one.
  `dev` changed the function loop to `||` (argmax; < 0.5 never paired; unreleased, no v0.9.2/v0.10.0 tag); graphs-mode block selection still uses `&&`.
- **Run evidence:**
  - (a) A `f` vs B {g1 sim 0.951 at the lower address, g2 0.805 higher} pairs g2; swapping the layout pairs g1.
  - (b) stripped `f`/`hh`: A.f paired with hh (0.58) while the true B.f (0.97) stays unmatched. (c) graphs: A block paired with the 0.80 block, the near-identical block reported UNLIKE. (d) two A functions share one B.
  - (e) `-0 <fcn>` returns one row per file1 function with original/modified inverted. (f) no functions found: stdout empty, stderr ERROR, **exit 0**. (g) graphs JSON `match` object duplicates `source` (src bug: `fcn_a` passed twice).
- **JSON [run]:** functions = array of {similarity, type, original{name,addr (decimal VA),size}|null, modified{..}|null}; pairs by A address, then unmatched A, then B never chosen; only types FCN/SYM listed.
  graphs = {source{name,offset,ninstr,nargs,nlocals,size,stack,type}, match{=source}, result[{pair{source{address,jump?,fail?,switch[{address,jump}]}|null, match{..}|null}, similarity{type,score}, opcodes}]}; `opcodes` is symbolised disassembly, or a unified diff when >= 0.5 and different.
  Other modes: {from,to,diff[{from[start,len],to[start,len],ops[{op:equal|insert|delete|replace,value}]}]}.
- **Accuracy:** zlib stripped, 4.3 s wall (2.5 s with symbols), 150 rows. Truth pairs by name: 81 byte-identical, 51 address-noise-only (instruction text identical once addresses are masked), 4 text-different (3 genuine + 1 nop-padding variant).
  - rz-diff scored all 46 noise-only pairs found < 1.0 (min 0.80, p10 0.961, median 0.989, max 0.999) and the 4 text-different pairs 0.581 (zError), 0.955 (deflateCopy), 0.961 (nop padding only), 0.997 (inflateSync, the one-instruction fix).
    46 of 50 correct PARTIAL pairs (92%) are pure address noise and the ranges overlap, so no similarity threshold separates noise from a real fix.
  - Stripped: 121 correct, 2 real mispairs (gzoffset->gzoffset64 0.988, gzfread->gzfwrite 0.714), 4 harmless alias pairs, 6 shared B endpoints. With symbols: 123 correct, 0 real mispairs (names, hence PDB, matter).
  - Discovery is reachability-bound: 77 of 138 functions found when nothing called them. Cost O(F_A*F_B*L^2) with no blocking: 90 s for 915 rows (prior doc), 4.3 s for 150 here; kernel-size inputs impractical [inf].
- **CFG export [run]:** `rizin -q -c aaa -c aflj` / `"afbj @fn"` / `"pdfj @fn"` took 0.64 s for 148 functions, 2647 blocks, 3864 edges.
  Per function name, offset, size, nbbs, edges, cc, callrefs[from,to,type], datarefs; per block addr, size, ninstr, jump, fail, switch_op; per instruction bytes, disasm, opcode, type, esil, xrefs_to.
- **PDB [src]:** `pdb.autoload` (false), `pdb.server`, `pdb.symstore`, `pdb.extract`, `bin.dbginfo` (true). rz-diff applies `-e` after `rz_core_bin_load`, so load-time options are probably ineffective [inf].

## 5. Strengths, granularity and common IR
- **Ghidriff strengths:** name-first exactness with pass provenance; seconds-fast monotone ladder; operand-masked hash tolerant of address shifts; call/string/switch signatures; BSim seeding; instruction alignment for implied matches; cached analysis; rich per-function metadata and decompiled diffs.
- **rz-diff strengths:** no JVM, official Windows/Linux/macOS builds, seconds on small binaries, simple auditable formula, raw bytes catch the operand/constant edits the masked ladder hides, `graphs` gives block pairs with CFG edges, separable LGPL process.

| Engine | Unit emitted | Pairing evidence | Exclusivity | Below function level |
|---|---|---|---|---|
| ghidriff | function pair + ordered `match_types`; only changed pairs enriched | pass names; text ratios after pairing | 1:1 except passes 11-12 | none (C text diff) |
| rz-diff functions | function pair | one raw-byte Levenshtein scalar + bucket | non-exclusive, order-dependent | none; `graphs` gives A-centric block pairs |
| BinDiff (`binexport-bindiff.md`) | function pair | similarity, confidence, algorithm | 1:1 | basicblock pairs + algorithm, instruction address pairs |

Proposed IR (extends `FunctionMatch`/`SecondaryMatch`; RVA-based; engine scores of different kinds are never merged):
1. **ProgramIR** per binary, cached once: Function{rva,size,name+provenance(pdb|export|import|auto),thunk_target,blocks,callsites[(rva,target)],string_refs,data_refs}; Block{rva,size,n_insn,succ[(rva,kind)],fp_raw,fp_masked,fp_mnemonic}; Insn{rva,len,mnemonic,operand_tokens,bytes_hash,masked_hash}.
   Fed by Ghidra export (primary), rizin `aflj/afbj/pdfj` (optional, fast), BinExport (specified).
2. **Evidence** atom {level fn|block|insn, a, b, engine, algorithm, ordinal, score_kind(identity|hash|text_ratio|lev_bytes|bindiff_sim|bindiff_conf|vt_cosine|bsim), score|null, cardinality(1:1|1:N|non-exclusive), run_id}.
   Mapping: ghidriff `address_matches` -> one atom per (a,b,type) with ordinal, its ratios only as `text_ratio`; rz-diff row -> `lev_bytes`, non-exclusive when the B endpoint is shared; rz graphs and BinDiff block/instruction tables -> block/insn atoms.
3. **ChangeFacts**, computed by our engine for every accepted pair and never inherited from an engine: raw_equal, masked_equal, mnemonic_equal, cfg_isomorphic, block counts (equal/changed/added/removed), call/string/constant deltas, size delta.
   Class: identical | address-noise-only | operand-or-constant-only | mnemonic-or-CFG | size-only. This is exactly what the two engines disagree on in 3.

## 6. Licences
- ghidriff: GPL-3.0 (`LICENSE`, `setup.cfg`, PyPI). PatchTrace is MIT, so keep it an external process and copy no code. The clean-room engine should be written from sections 1-5, the V-sources and papers, not from ghidriff files.
- Ghidra including VT and BSim: Apache-2.0 (`LICENSE`). Porting is legally possible with NOTICE/attribution; prefer re-deriving from the help text and papers.
- Rizin: per-file SPDX `LGPL-3.0-only` for `rz-diff.c`, `similarity.c`, `diff/distance.c`, `diff/diff.c`; the repo ships `COPYING` (GPL-3) and `COPYING.LESSER`.
  `REUSE.toml`: BSD-2 (magic, jemalloc), MIT (spp), **GPL-2.0-or-later for `librz/arch/p_gnu/**` and `librz/arch/isa_gnu/**`** (binutils-derived ISA plugins). Treat the static release as a GPL-bearing aggregate.
  Running `rz-diff`/`rizin` as a process creates no linking duty; do not link `librz`. The release tarball has no licence texts: ship them with a source offer [inf: needs legal review].

## 7. Recommendation
- **Run as-is:**
  - Ghidra headless as extractor, decompiler and PDB loader, once per binary, output cached as ProgramIR.
  - ghidriff CLI as baseline and regression oracle: consume `matches` + `match_types` as evidence; treat `modified`, `diff_type`, ratios, stats and the markdown as advisory, never as completeness.
  - rizin as optional fast CFG/instruction exporter; `rz-diff -t functions` only as weak evidence (SPEC-11): store engine version, mark shared-B-endpoint and `-0` rows ambiguous, never rank by its similarity, prefer a build with the `||` fix once released.
  - Evaluate Ghidra AutoVT headless as a conservative extra engine (reference correlators and vote-gated implied matches that ghidriff lacks) [inf: not run].
- **Reimplement clean-room (Python on ProgramIR, from V-docs, Halvar Flake 2004, BinDiff docs):**
  1. provenance-recording ladder, matched functions removed per pass, run to a fixpoint, 1:1 gating, and a two-signal rule for weak passes (a structural hash must be corroborated by size and callee/string overlap);
  2. name pass that records name provenance and handles renames and alias groups (identical bodies are N:M, never cross-multiplied);
  3. reference-vector propagation and implied matches with >= 2 votes and 0 conflicts;
  4. in-pair instruction/block alignment (anchored n-gram or patience) on normalised tokens, mutual-best or Hungarian assignment instead of rz-diff's loop;
  5. ChangeFacts on every pair with no size/refcount gate, decompiling only on demand or when fingerprints differ;
  6. thunks as typed nodes, tiny functions via hash-only matching.
- **Drop:**
  - ghidriff `ratio/i_ratio/m_ratio/b_ratio` as similarity or confidence (degenerate `m_ratio`, rounding, autojunk), `stats.*_percent` and `matched_funcs_len`, `StructuralGraphExactHash` as an accepting pass (keep as a feature), `SigCallingCalledHasher` as written, `SwitchSigHasher`, the O(n*m) Decomp loop;
  - rz-diff pairing loop, `graphs` `match` object, raw-byte Levenshtein as a selector, `-d` modes, ssdeep for functions; VT data and similar-symbol correlators for PE patch diffs.

## 8. Open questions
1. Real Windows x64 PE (+PDB): rizin function discovery vs Ghidra on stripped input, effect of `pdb.*` under rz-diff, address-noise rate, MSVC ICF/COMDAT folding (N:1), PGO split chunks, CFG/XFG guard thunks [all inf].
2. Pin a ghidriff commit (API blocked here); 1.0.0 vs main differ in `skip_types` and decompiler locking.
3. Ablation on a labelled Windows corpus (SPEC-27 design): true pairs per pass, wrong pairs admitted by each weak pass, BSim marginal value (1 pair, about 3 s here).
4. Rizin release timeline for the `||` fix, and whether graphs-mode block selection gets fixed.
5. Should SPEC-27 treat ghidriff 1:N groups as N:M explicitly (today "contested")?

## 9. Delta against existing repo docs
- Confirmed [run/src]: `-t functions` always runs `aaa`; JSON keys; thresholds; unmasked bytes; all-core threading; exit 0 on success. Extended: exact formula, name shortcut, non-exclusive and last-wins selection, `-0` inversion, unmatched-B meaning, discovery limits, `-e` ordering, CFG export, GPL-2.0-or-later plugins.
- SPEC-11 section 3: exit 0 also covers "No functions found" (empty stdout, stderr ERROR), which confirms the "empty output is an error" rule. Section 4: keep `flags ()`; derive `alternatives`/ambiguity (secondary/2) from shared B endpoints and record `engine_version`, because pairing semantics differ between 0.9.x and `dev`.
- SPEC-27: `match_types` is the ordinal feature for calibration; pairs found only by StructuralGraphExactHash, BSIM or the Bulk passes deserve a low prior; ghidriff ratios stay out of any confidence. `docs/research.md` pins ghidriff `4f5d895`; `main` today may be newer.
