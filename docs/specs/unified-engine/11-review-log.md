# SPEC-31 / 11 Independent review log (2026-10-14)

Reviewer: independent research-hardening pass over the SPEC-31 set (README, 00-10, plan, backups, troubleshooting) against AGENTS.md, CLAUDE.md, research notes R01-R05, the existing specs and the real code. Base: local integration branch `claude/clever-clarke-s4nhi6` at `ce108cd` (= spec merge `fefa886` + `ffe9ff4` + `ce108cd`); `origin/main` was still `cb25132`. Docs only: no change to `src/` or `tests/`, nothing pushed. Labels as in 00: [src] read in code or upstream source, [own] measured here, [inf] inference, [unv] unverified.

## 1. Method
1. Adversarial read of every file before looking at the author's weak-point list; each claim about code checked with `grep`/reads under `src/patchtrace` (line numbers below are on `ce108cd`).
2. Primary sources only: Ghidra 12.0.4 source zips shipped in the install (`SoftwareModeling-src.zip`, `Base-src.zip`), pyghidra 3.0.2 sources in a venv, the ghidriff pinned copy (`4f5d895`) and `main` copy fetched by the research agents, local copies of google/bindiff, QBinDiff and binkit sources and licences, the DA-01 draft (`origin/docs/diaphora-optional-engine-20261014` @ `b75ac57`, already fetched; GitHub not touched).
3. Cheap measurements in the session scratchpad (s2); nothing was written to the repository except these docs.

## 2. Measurements [own] (scratch scripts, not product code; Linux, 4 vCPU Xeon 2.1 GHz, Python 3.13 for probes)
| ID | What | Setup | Result |
|---|---|---|---|
| M1 | GZF reuse | `GhidraProject.createProject(dir, name, True)`, `importProgram(File(dll))`, `pyghidra.analyze`, `saveAsPackedFile`, fresh project, `importProgram(File(gzf))`; dump of every fact the extractor needs | re-imported program identical in all facts (functions, ranges, bytes, masks, operand types, references, blocks); `getExecutableSHA256()` = file SHA-256 on both; analysed flag kept; GZF import 0.03-0.07 s; GZF 29 KB for a 3 KB DLL |
| M2 | API pitfalls | same | `pyghidra.start()` takes no VM args (use `HeadlessPyGhidraLauncher(...).add_vmargs('-Xmx..')`); `GhidraProject.analyze()` raises NPE in an analyser (no script bundle host) and does not set the analysed flag, `pyghidra.analyze()` does both; `createProject` needs an existing directory |
| M3 | operand facts | clang `--target=x86_64-pc-windows-msvc -O2` + `lld-link /dll /noentry /nodefaultlib` pair; `nasm -f win64` MSVC-style switch | RIP-relative memory operand: `ADDR | DATA`, mask = disp32 only, DATA ref, no scalar; RIP-relative LEA: `ADDR | SCAL`, scalar = absolute VA; `[rdx + rax*4 + 0x2000]` (RVA-form table): `ADDR | DYN`, DATA ref to the table, no scalar, mask = SIB + disp32; stack operands carry `Stack[-0x..]` refs; switch targets appear as COMPUTED_JUMP successors; exports have source IMPORTED |
| M4 | data shift | same pair (one 64-byte global inserted) | `g_counter` 0x3000 -> 0x3040 referenced by 5 functions; `g_table` 0x3010 -> 0x3050 referenced by one function; strings did not move; functions moved by 0x20 |
| M5 | extraction cost through JPype | `/usr/bin/ls` (524 functions, 19,515 instructions) | 18-25 us/instruction (address, length, mnemonic, operand types); 68-70 us with masks, op objects, references, flow, text |
| M6 | decompile cost | same, 80 functions (40 largest + 40 median) | `DecompInterface.openProgram` 0.28 s; per function median 0.013 s, p90 0.16 s, max 2.6 s (8.4 KB function); 80/80 completed |
| M7 | ingest prototype | synthetic 60,000 functions, 2.84 M instructions, 355 MB JSONL; strict JSON with duplicate-key rejection, per-instruction masking, blake2b-64 keys, zlib blobs, one SQLite transaction | 28.9 s wall, 304 MiB peak RSS, 63 MB SQLite (no MD index, text blobs or content digest) |
| M8 | ladder prototype | columnar keys, 9 unique-key passes with drill-down, propagation over a power-law call graph | 0.4 s / 93 MiB at 60k; 2.2 s / 362 MiB at 250k |
| M9 | MD vector | formula read in bindiff `graph_util.h` | diamond = 0.277559753195558 exactly; key 277559753196 |

## 3. Findings and changes (severity: C critical, H high, M medium, L low)
| ID | Sev | Finding (evidence) | Change made |
|---|---|---|---|
| R-01 | C | COS-ADDR/1 unsound: `operand_deltas` skipped every instruction whose L1 bytes were equal, so address operands of masked-equal instructions were never validated; a patch swapping `g_A` for `g_B` with the same instruction shape became `cosmetic` and was hidden by default. Fixing only that would flag every reference to a moved global (M4) as `data-ref`, a semantic class: false `material` at scale | DATA-MAP/1 (strings, leave-one-out votes from masked-equal matched pairs, monotone region shift) and target consistency over EVERY address operand (05 s2.2, s2.7; D-31; `ref` table 02 s3); unmapped = `review` (`address-only`), conflict = semantic |
| R-02 | H | C6 canonicaliser emitted `UNMAPPED_<side>_<rva>`, so any moved global made C6 differ and corroborate `material`; renaming them blindly would instead hide swaps | labels mapped through rows/DATA-MAP, unmapped ones alpha-renamed `U<k>` and counted; any unmapped label forbids COS-PSEUDO (05 s2.4) |
| R-03 | H | `unchanged` = "raw bytes equal" is unsound when the function moved: identical rel32/disp32 bytes reach shifted targets (M4 shows sections shift by different amounts) | UNCH/1 = `h0` equal AND target consistency AND EH-EQ; `unchanged` now carries a proof id (02 s1, 05 s2.5) |
| R-04 | H | COS-LAYOUT/1 used C3 equality (counts, block multiset, MD) as a proof; a then/else successor swap keeps all of them. COS-PSEUDO/1 is decompiler-relative, not a sound proof, yet was hidden by default | COS-LAYOUT needs a polarity-preserving block bijection with a closed jcc-inversion table; COS-PSEUDO rows are listed after `review`, never hidden (U-03, 07 s1) |
| R-05 | H | Independence over-count: Ghidriff ExactMnemonics (K1) and `pt-bytes` P08 (K2) are the same key over the same decoding and, in `gzf` mode, the same function bodies; two tier-B atoms made `matched` | evidence classes; tier-B corroboration needs different components AND classes (05 s1.1, s1.3; D-32; G-U7 per class pair) |
| R-06 | H | Implied matches were accepted inside the worklist with partial vote counts (text said "after drain"): order-dependent results, missed conflicts; conflicts only checked on the older endpoint | deterministic waves: collect, then decide; symmetric conflicts persisted across waves (04 s5, s5.1) |
| R-07 | H | Address detection: RVA-form displacements (MSVC jump tables) have no in-image scalar and no relocation (M3) so they were classed `struct-offset` noise; clearing whole operand masks also clears SIB index/base bits (M3) and would hide an index-register change | operand typing from Ghidra references (`address`, `stack`, `memory`, `scalar`, `register`); only located displacement/immediate fields are cleared; `mask-unlocated` flag (03 s6; D-33) |
| R-08 | H | (g) Constant-only fixes: Ghidriff never examines same-size, same-refcount pairs (R05 s0.1), so C6 is never present and they could not leave `review`; also "second channel differs anywhere" let unrelated differences corroborate | MAT-ANCHOR (the second channel must show the same change; constants need the literal pair in C6) + S3b on-demand decompile of the top L-41 review pairs, cheap per M6 (05 s2.5, s2.8; D-34; U-11) |
| R-09 | M | `ir_key` hashed the whole `limits_digest` (any ladder threshold change would force hours of re-analysis) and `gzf_sha256` (not computable before extraction; GZFs are deleted) | `ingest_limits_digest`; GZF hash and Java version are provenance only; rarity limits applied by the ladder, not stored in IR (02 s5, s6; D-36) |
| R-10 | M | `unified-run` body allowed a 64 KiB stderr tail while every pointer body had to be <= L-31 = 64 KiB | L-31 = 128 KiB, `stderr_tail` <= 32 KiB (02 s4, s6) |
| R-11 | M | Worker spawn re-invented C3's solved problem and required `pip install -e .` in development; memory: no cap for the worker, and a cap must never be applied to the JVM (RLIMIT_AS breaks reservations) | reuse C3 `worker_argv()`/`worker_env()`; L-42 cap with C3 OOM classification on the worker only (01 s4; D-15; U-09; T-37, T-38) |
| R-12 | M | (e) Borrowed thresholds presented as defaults | 02 s6.1: floors only for A/B gates, tier-C-only thresholds never decide, change only via dev lineages, per-pass demotion |
| R-13 | M | Symbol asymmetry: Ghidriff runs without `--no-symbols` when downloads are allowed (backend.py:541-542); `analyze` mode never downloads, so IR names/starts can differ from the primary rows | symbol policy in F1 and `ir_key`; limitation `ir-symbols-differ`; one-sided IR rows never contest (03 s1) |
| R-14 | M | Stack displacements and `sub rsp` sizes classed `struct-offset`/`constant` (semantic): every frame-growth function became a semantic review/material candidate; R04 s5 advice dropped | class `frame`, non-semantic, `review`, never cosmetic (02 s1, 05 s2.2, F18) |
| R-15 | M | DA-01 unverified (`user-attested`) sets capped at C could still contest every row | display-only W atoms that neither support nor contest (06 s5) |
| R-16 | M | `unchanged`/`cosmetic` claimed more than the evidence: SEH scope tables and other unwind data are invisible to bytes and decompiler | EH-EQ precondition from `.pdata`/UNWIND_INFO (03 s7, 05 s2.5) + explicit verdict scope (D-35, UI footer) |
| R-17 | L | P02 export names are symbols in Ghidra's table (exports have source IMPORTED, M3); its own component K3 suggested independence from Ghidriff SymbolsHash | F-PT-PE carries D_symbols; P02/P03 never corroborate each other (05 s1.1, 04 s4) |
| R-18 | L | D-17 said `EXTERNAL:` keys "become import identities", 06 s1 said "skipped and counted" | D-17 aligned with 06 s1 and with the merged N-way rule |
| R-19 | M | SPEC-27/C6 marks "removed(A) vs engine A->B" contested (R01 s3), the unified arbiter does not: same window, two answers | documented deliberate refinement (C-20, A-08); hint `one-sided-by:<source>` |
| R-20 | H | UI seam: `self.unified` was created after `_build_workspace()`, which already calls `self.unified.navigator_stack(...)` (AttributeError at window construction); `current_match()` reads the hidden, possibly filtered navigator (ui.py:1840-1843), so `render_match` could not serve unified rows; writing panes from `ui_unified` left `_hunks`/`_line_maps` stale | controller created before `_build_workspace`; `current_match` override; public `show_external_pair`; seam <= 25 lines (07 s2, A-26) |
| R-21 | M | A-15 asked the live workflow to pass `--md_index`, which SPEC-29 forbids in product argv (bindiff-execution.md:80, `FORBIDDEN_FLAGS`) | dev-only parity tool with its own argv (C-21, A-15) |
| R-22 | M | A-18 claimed "no change to C3 contracts", but `accept_binexport` returns only a summary to the parent | C3 worker mode `ir-export` (A-18, 06 s7, B-23) |
| R-23 | info | (h) Prerequisites already fixed: spawn lock (jobs.py:14-17, 103, 151-157) with `test_concurrent_run_process_calls_do_not_cross_pipes_or_leak_threads`; no other spawn API (`subprocess`, `QProcess`, `os.system`/`startfile`/`spawn*`/`exec*`) under `src/` outside jobs.py; N-way `EXTERNAL:` skip in ce108cd with `test_raw_ghidra_external_locations_are_skipped_not_fatal` (silent skip, not counted). Both tests pass here (Linux, 1 passed each; the spawn-lock test is fully meaningful only on Windows CI) | D-28, A-05, A-06, plan P1/P2 DONE, P2b for the count; T-22/T-23 resolved |
| R-24 | M | GZF seam pseudocode not implementable (`result_ok` unknown in `finally`); Ghidriff saves the GZF in a `finally` even after a failed analysis [src l.993-997] | seam after a successful `run_process`; script refuses non-analysed GZFs (`gzf-not-analyzed`); naming verified (03 s8, T-31) |
| R-25 | M | (f) Extractor API surface [unv] in the draft | 03 s4 rewritten with the calls exercised in M1-M3 and the null-mask case from the source (`SleighInstructionPrototype.cacheInstructionMasks`); FID marker stays [unv] |
| R-26 | L | Stale facts: pins (protobuf 7.36.2 since C3), ui.py:1565 is the definition (call at :1503), build_windows.py notice lines, jobs.py polling lines, calibration/policy.py display_level at :43 | corrected where cited |
| R-27 | L | Windows path length: 64-hex directory names under `runs/<run_id>/unified/` | 16-hex directory names, full ids in manifests (02 s3, s4; 01 s9) |
| R-28 | L | Licence mechanics (h): no NOTICE in google/bindiff (`main` copy); header years differ from `v8`; binkit has no licence file (fetched `LICENSE` = "404: Not Found"); QBinDiff Apache-2.0 | 09 header and s1/s3 (s4 obligations a-d, C3-style notice list, PROVENANCE fields) |
| R-29 | M | Windows-binary noise not covered: WPP/ETW trace-message ids and line numbers change with unrelated edits | F17 `trace-arg` ordering hint (never hides, never changes the verdict) |
| R-30 | L | Fixture byte stability on Windows checkouts | `.gitattributes` lines for `tests/fixtures/unified/` (02 s7.6) |
| R-31 | L | Retention needed private `_delete` | A-04 adds `delete_own(ids, kinds)` |
| R-32 | info | (c) Performance [inf] | M5, M7, M8 recorded in 02 s6 L-35/L-08, 04 s5.2, 08 s6; the JPype dump is the dominant cost |

## 4. Author's weak points W1-W8 (README s5) and resolution
| W | Resolution |
|---|---|
| W1 independence | partly refuted: same-key double counting (R-05) fixed by evidence classes; narrowed A-IND-1 stays, measured per class pair by G-U7 |
| W2 GZF reuse | resolved for the pinned ghidriff code [src] and Ghidra re-import [own M1]; S1 live gate keeps the Windows run with a real Ghidriff GZF |
| W3 speed/memory | measured (M5, M7, M8); budgets hold with margin; JPype dump dominates |
| W4 proof soundness | four unsound rules found and fixed (R-01..R-04), plus R-07, R-14, R-16; flags, memory effects, ABI, reordering and renaming checked per proof in the 05 s2.5 table |
| W5 thresholds | hypotheses rule 02 s6.1 (R-12) |
| W6 Ghidra API | verified except the FID marker (R-25) |
| W7 policy | constant-only promotion via S3b + MAT-ANCHOR (R-08); greedy edge choice inside contested clusters kept (it never hides an against-atom); U-03 refined |
| W8 legal and latent defects | defects fixed upstream (R-23); notice mechanics settled (R-28); patent question stays U-01 |

## 5. Considered and not changed
| Item | Reason |
|---|---|
| Make `D_ghidra_decode` joining for everything (W1 fallback) | would also forbid legitimate cross-class corroboration (E-BODY + E-DATA); evidence classes remove the actual double count |
| Drop COS-PSEUDO entirely | S0 mode would lose its only noise reduction; listed-not-hidden keeps soundness |
| Normalise `mov edi, edi` or `xor r,r` idioms | `mov edi, edi` zero-extends RDI on x64; idioms need measurement first (R04 s5) |
| Bounded SMT equivalence, BSim, embeddings | cost and dependency reasons stand (R05 s5-s6; B-09) |
| Greedy edge choice inside contested clusters | deterministic, never drops an against-atom, rows stay `contested` |
| Plan model tiers and effort bands | plausible; adjusted only where scope changed (S3 +2-3 d, P1/P2 removed) |

## 6. Residual risks (owner and trigger)
| Risk | Owner / trigger |
|---|---|
| MSVC-built binaries behave differently from clang/nasm probes (operand typing, switch patterns, FID) | S1 owner; first live run on the MSVC CI fixture and Tier W |
| DATA-MAP rule (c) maps a renamed single-use global in the same slot (a data-content change) | S3 owner; G-U2 `swap-to-existing-global` must stay non-cosmetic; U-12 / B-21 |
| COS-PSEUDO depends on Ghidra's decompiler (listed, never hidden) | S3 owner; cross-tier check G-U4 |
| EH-EQ covers `__C_specific_handler` scopes only; C++ EH (FH3/FH4) data compared by length and handler | S3 owner; flag `eh` when unsure (review, never cosmetic) |
| Narrowed A-IND-1 | S6 owner; G-U7 per class pair |
| Ghidriff `match_types` naming drift across versions | S0b owner; unknown names map to tier C / E-UNKNOWN |
| Large-GZF import time on kernel-size images [unv] | S1 owner; `bench_extract` in G-U5 |

## 7. Open USER decisions (recommended defaults; full table in 00 s4)
U-01 port BinDiff with attribution (yes; legal/patent review before the first release shipping it) - U-02 transient GZF retention (yes) - U-03 hide UNCH/1, COS-ADDR/1, COS-LAYOUT/1 rows by default, keep COS-PSEUDO visible (yes) - U-04 retire the Evidence tab only after the G-U gates pass - U-05 flag default (off until G-U1..G-U6) - U-06 show tentative (yes) - U-07 Tier R on Windows runners (yes) - U-08 global IR cache (optional) - U-09 worker cap L-42 (yes) - U-10 auto-run after Ghidriff (no) - U-11 automatic S3b (yes, cancellable) - U-12 DATA-MAP region shift (yes, guarded).

## 8. Not verified (and why)
FID library marker API (no FID-matched code in the probe); MSVC-built PEs (no MSVC in the container); Windows behaviour of every [own] fact (Linux only); BinDiff `v8` commit SHA and `v8` header years (GitHub API not used; R02 reports 2011-2023); patent posture of the port (legal question, U-01); GZF import time for kernel-size images.

## 9. Consistency checks run
Script check over the SPEC-31 set and plans (scratch `check_docs.py` from the first author, extended by the review): links and anchors resolve; every file <= 400 lines; every cited code path and line range exists on `ce108cd`; 40 cited code identifiers and the two prerequisite test names exist; every R, M, L, B, T, G-U, D, C, U and A id used is defined and every defined id is used; no TBD/TODO; each "later" names an owner or trigger. Result on the final commit: no problems.
