# SPEC-31 / 00 Decisions, conflicts and open USER questions (unified binary-diff engine)

Status: contract-freeze draft, 2026-10-14, base `main` = `cb25132`. Number check: no `SPEC-31` exists on `cb25132`; SPEC-12..25 are reserved by `../../plans/ghidra-semantic-runtime-roadmap.md`, SPEC-28/29 are each used by several files (left as they are). Inputs (cited, not repeated): research notes `../../research/unified-engine/01..05` (R01..R05), existing specs listed in [README](README.md), Diaphora draft PR files (branch `docs/diaphora-optional-engine-20261014` @ `b75ac57`). Labels: **[src]** read in code or upstream source, **[doc]** stated in a doc, **[inf]** inference, **[unv]** unverified. Only one primary-source fetch was made by this author: `clearbluejar/ghidriff` `main` `ghidra_diff_engine.py` (GZF behaviour, D-05).

## 1. Decisions (ADR-lite; each is binding for SPEC-31 builders unless a USER decision in section 4 overrides it)

| ID | Decision | Rationale (evidence) | Consequence / named test |
|---|---|---|---|
| D-01 | Spec number SPEC-31, folder `docs/specs/unified-engine/`, Python package `patchtrace.unified`, product name "unified diff (derived)"; never "BinDiff" | free number on `cb25132`; Apache-2.0 s6 grants no trademark (R02 s12) | `test_unified_strings_never_say_bindiff_engine` |
| D-02 | Ghidriff stays primary; the unified result is DERIVED, stored apart, never writes `ComparisonProject.matches` | AGENTS.md, SPEC-27, SPEC-28 orchestration s2 | `test_unified_run_never_mutates_project_snapshot` (snapshot SHA before == after) |
| D-03 | Layers (H1 kept, refined): E1 ProgramIR -> E2 PairEvidence from every source -> E3 L1 ladder -> E4 fusion/arbiter -> E5 L2 ChangeFacts -> E6 read model -> one window. L2 never feeds L1; `attention/1` untouched | R01 s0 (L1/L2 separation is a strength), R05 s3 | `test_facts_do_not_change_decisions` (property) |
| D-04 | ProgramIR is extracted once per artifact by a thin, PatchTrace-owned script run by the user's external Python (pyghidra + Ghidra): it dumps facts only; every hash, mask level, MD index and normalisation is computed by pure PatchTrace code | testable without Ghidra; one implementation; no new bundled dependency (R02 s14 step 1, R03 s7) | 03-extraction; `test_ingest_hashes_are_pure_functions_of_records` |
| D-05 | Extraction first tries the analysed GZFs Ghidriff already writes (`saveAsPackedFile` to `--gzfs-path`, name `<gen_proj_bin_name_from_path>.gzf`) [src ghidriff main]; PatchTrace currently deletes them with the scratch dir (backend.py:549). Opt-in `BackendConfig.retain_gzf` moves them into the run dir; fallback = own headless analysis with the same recorded options | halves Ghidra cost (analysis dominates: ntoskrnl 1349 s per side, R03 s3); identical analysis on both sides is the F1 symmetry guard (R05 s4) | pinned ghidriff `4f5d895` behaviour and GZF import via `GhidraProject` are [unv] (reviewer item W2) |
| D-06 | Canonical IR container: one sidecar SQLite file per side, `runs/<run_id>/unified/ir/<ir_key>/ir.sqlite3`, written by PatchTrace after strict validation of the extractor's untrusted JSONL, then opened read-only (`mode=ro`); identity = canonical content digest, not file bytes | random access for L2/drill-down without loading 2 M instructions; stdlib; inside `runs/` so `ProjectStore.backup` copies it (persistence.py:425) | 02 s3; `test_ir_reader_refuses_writable_or_tampered_file` |
| D-07 | Results: sidecar files under `runs/<run_id>/unified/results/<result_id>/` plus tiny pointer rows of NEW enrichment kinds `unified-run`, `unified-result` (added to `KINDS`, NOT to `DERIVED_KINDS`), own retention; no `extension_version` bump | `DERIVED_KINDS` rows not referenced by a `pipeline` row are deleted as orphans (storage.py:312-413) [src]; unknown kinds are invisible to old readers (storage.py:244) [src] | `test_unified_rows_survive_enrichment_retention`, `test_old_reader_ignores_unified_kinds` |
| D-08 | Sources are data-driven: `SourceSpec` registry (id, D-tags, tier map, display name, unit caption); persisted source ids are pattern-validated strings, unknown ids load as "unknown source" | SPEC-28 hard-codes engine ids in ~9 places (R01 s5 row 1) and forced Diaphora into separate kinds; H2 "adding a channel never changes fusion or UI" | `test_new_source_needs_only_adapter_and_registry_entry` |
| D-09 | L1 = ordered, uniqueness-gated pass ladder (BinDiff drill-down semantics + VT-style per-pair provenance) run to a fixpoint with neighbour propagation; tiers M (manual), A, B, C; tier C never auto-accepted | R02 s1/s9, R04 s0.1, s4, R05 R2 | 04-matching-pipeline |
| D-10 | In-house masked-byte comparator (`pt-bytes`) is a first-class source and the L2 C0/C1 channel; it counts as an independent component only when both functions' extents are confirmed by `.pdata` (`extent_src = 1`, 02 s3) | R05 s3.2; rz-diff raw bytes are 92 % address noise (R03 s4) | assumption A-IND-1 (SLEIGH decoding does not join components) is reviewer item W1 |
| D-11 | Fusion = union-find over joining D-tags, max-pool by ordinal tier inside a component, rule-based decision across components; no numeric fusion and no probability until a SPEC-28 calibration artifact passes (display level `'ordinal'`, calibration/policy.py:44) | R05 s0.3, s3; hard rules | 05 s1; `test_fusion_never_emits_numbers` |
| D-12 | `contested` is preserved exactly as SPEC-27 (any source pairing an endpoint differently); new attribute `contest_strength` (`strong`/`weak`) orders rows, never hides them | rz-diff last-wins non-exclusive pairing contests correct pairs (R03 s4, R01 s3 limit 5) | `test_weak_contest_still_contested` |
| D-13 | L2 verdicts by proof tier, first match wins: `unchanged` (raw bytes equal) > `cosmetic` (named proof) > `material` (semantic delta + second channel) > `review` > `unknown`; operand/constant-delta channel built first | R05 s0.4, s3 L2, R1 | 05 s2; leakage gate G-U2 |
| D-14 | Missing, unmatched or unsupported = unknown. One-sided rows are `older-only`/`newer-only`; "added/removed" appears only as a Ghidriff source atom | SPEC-27; R02 s10 ("no unique evidence" is not "removed") | `test_absent_source_is_not_a_vote` |
| D-15 | Processes: extraction = external Python child per side (sequential default); ladder/fusion/facts = PatchTrace worker child `patchtrace unified _worker` through `jobs.run_process` (Job Object / killpg); only the owner thread publishes; cancel = tree kill, partial output discarded | GIL-heavy pure Python must not stall the GUI; SQLite connection is thread-confined (modules.md) | 01 s4; `test_cancel_keeps_previous_result` |
| D-16 | Determinism: inputs sorted by RVA, ties by RVA, no set iteration without sort, integer keys; MD index = plain left-to-right float loop over sorted terms (mirrors BinDiff; Python 3.12 `sum()` is compensated [inf R02 s6]) then `round(x*10**12)` | cross-OS byte-identical results (R04 s7) | `test_result_manifest_identical_linux_windows` (CI) |
| D-17 | Identity of a function across tools = (artifact SHA-256, RVA). VA->RVA via PE `image_base` from `pe_overview`; Ghidriff `EXTERNAL:<hex>` keys become import identities | image-base mismatch silently becomes "absent" today (R01 s3 limit 1); `EXTERNAL:` keys exist [run R03 s2] | `test_external_keys_are_imports_not_errors` |
| D-18 | ONE comparison window: `MainWindow` navigator gains a view switch (Primary | Unified) and the existing Engine evidence dock gains a `Unified` tab; no per-engine window | user requirement R7 | 07-ui-and-cli; `test_no_new_top_level_window` |
| D-19 | CLI first: `patchtrace unified {extract, run, show, explain, status}` + hidden `_worker`; GUI second | R01 s0 | 07 s5 |
| D-20 | No new runtime dependency (stdlib only); feature flag `unified/enabled` default OFF in alpha; frozen build adds one data file (extractor script) | Windows standalone alpha must keep building | plan, packaging section |
| D-21 | Port BinDiff v8 core ideas (MD index, drill-down step semantics, call-reference matching, change flags G I J E L C) with Apache-2.0 attribution; keep SPEC-29 BinDiff as optional oracle/second opinion, never bundled | R02 s14 hybrid recommendation | 09-licensing; parity gate G-U3 |
| D-22 | Ghidra VT reference-vector and implied-match ideas: clean-room from the VT help text; the extractor may CALL Ghidra APIs (runtime use in the external process), nothing is copied | R03 s1, s6 | 09 |
| D-23 | rz-diff = weak L1 evidence (`tier W`), flagged `non-exclusive` when its newer endpoint is shared; its similarity never ranks or decides; rizin as IR producer is a backup only | R03 s4, s7 | 06 s2 |
| D-24 | Diaphora only through the DA-01 import path (its own kinds `diaphora-matches`) plus a unified adapter; no AGPL code, no IDA in PatchTrace | Diaphora spec (PR draft) s"versioning decision" | 06 s5 |
| D-25 | QBinDiff ideas: residual assignment with reject cost and margin on blocked buckets; the belief-propagation solver is NOT built (backup only) | R04 s1 #10-11, R05 R11 | 04 s6 |
| D-26 | radiff2: file-level byte/section/layout diff re-homed to SPEC-26 (pe_overview/raw_view); opcode-vs-operand delta becomes L2 C1/C2; no radiff2 adapter planned | rizin already covers the r2 family under the same LGPL boundary | 10-amendments |
| D-27 | Evaluation before default-on: gates G-U1..G-U8 (08) must pass on Tier R corpora and CI; parity harness against Ghidriff (always) and BinDiff (when installed) | R05 s7, SPEC-28 calibration s12 | 08 |
| D-28 | Prerequisite fixes before parallel spawning or S0: (a) `jobs._windows_process` spawn lock (pipe write ends are inheritable while another thread calls `CreateProcessW(bInheritHandles=True)`, jobs.py:96-111) [src, effect inf: +5 s reader join, parked thread]; (b) tolerant `EXTERNAL:` parsing (nway/graph.py:101 raises PT-NWAY-PAIR) [src + run R03] | both are latent defects found while grounding | plan slices P1, P2; red tests named there |
| D-29 | Analyst control: unified rows offer "Correct match..." which opens the existing `ProjectService.correct_match` flow (service.py:274); manual corrections are tier-M anchors for the next unified run | QB-01 "never silently apply a suggestion" | `test_promote_goes_through_correct_match` |
| D-30 | AI (Ollama/OpenAI-compatible) may receive unified facts only inside the existing explicit context preview; it never decides, filters or suppresses | hard rule | `test_interpretation_has_no_unified_write_path` |

## 2. Starting hypotheses: verdicts

| H | Verdict | Change |
|---|---|---|
| H1 layers | Kept, refined (D-03, D-04, D-05) | fusion sits between all L1 sources and L2; extraction rides on Ghidriff's GZFs when available; IR producers: Ghidra (primary), BinExport2 import (after C3 merges), rizin (backup) |
| H2 external engines as adapters | Kept (D-08, D-21..D-26) | registry-driven; radiff2 dropped as an engine; Ghidra AutoVT as an extra engine deferred (R03 s7 "evaluate", no slice) |
| H3 slices with fallbacks | Kept with two prerequisite slices P1/P2 (D-28) and S0 split into S0a (contracts, store) and S0b (sources + fusion + S0 facts) | see plan |

## 3. Conflicts and resolutions

| ID | Source A | Source B | Resolution | Amended in |
|---|---|---|---|---|
| C-01 | R01 s5 row 2: new derived kind -> add to `KINDS` AND `DERIVED_KINDS` | code: unreferenced `DERIVED_KINDS` rows are orphan-deleted | own kinds outside `DERIVED_KINDS`, own retention (D-07) | 02 s4 |
| C-02 | Diaphora spec s"SQLite safety" item 5 / plan R7: scheduler parses after its temp dir is gone | scheduler.py:134-157 parses INSIDE the `with TemporaryDirectory` block [src] | claim is stale on `cb25132`; no scheduler change needed; Diaphora keeps its own kinds for the Literal reason only | 10 row A-13 |
| C-03 | SPEC-28: `Engine`/`EngineId` Literals | H2: new channels without fusion/UI change | unified contracts use pattern-validated source ids + registry; `secondary/2` Literals untouched (no widening) | D-08 |
| C-04 | SPEC-27 "any disagreement -> contested" | noise from weak engines (R01 limit 5) | keep contested; add `contest_strength` (D-12) | 05 s1.4 |
| C-05 | SPEC-QB-01 `matching/*` package, profiles, BP solver | one engine, token budget | absorbed into `unified/ladder`, `unified/fusion`; solver not built; one conservative config in v1 | section 3.1 |
| C-06 | SPEC-QB-02 new SQLite tables `matching_*` | SPEC-07 additive kinds, single writer | no new tables; enrichment kinds + sidecar files | 10 row A-10 |
| C-07 | SPEC-RD-01/02 `comparison/*` + tables `comparison_*` | SPEC-26 already owns raw/PE layout views | re-home file-level layers to SPEC-26; function-level opcode/operand delta into L2 | section 3.1 |
| C-08 | R02 tier B "accept when a second key or another engine agrees" | R05 s3.3 "hard accept only exact/masked/name" | `matched` = tier A, or tier B confirmed by a second INDEPENDENT component; tier B alone = `tentative` | 05 s1.3 |
| C-09 | R05 s3.4 learned weights + calibration | hard rule: ordinal until validated artifact | rule-based ordinal decisions now; `features/2` family proposal handed to the C9 owner in S6 (A-07) | 05 s1.5 |
| C-10 | SPEC-01 DEC-02 "do not fork matching" | in-house ladder | DEC-02 reworded: never fork Ghidriff; a separate derived engine may match | 10 row A-01 |
| C-11 | SPEC-01 "one active job per window" | extraction + worker jobs | unified run counts as THE analysis job: disabled while Ghidriff runs and vice versa | 10 row A-01 |
| C-12 | R02 s14 "build a BinExport writer in the extractor" | no protobuf in the external env, token budget | no BinExport writer in v1; parity uses the official exporter when present (backup B-04) | 03 s7 |
| C-13 | SPEC-12 roadmap reserves SPEC-13/16/21 (interchange, CFG correspondence, arbitration) | SPEC-31 covers their static PE x64 subset | SPEC-31 is the static subset; those numbers stay reserved for the Ghidra-hosted/runtime track | 10 row A-14 |
| C-14 | SPEC-28 calibration s18 item 9: "PatchTrace-computed body-bytes similarity is a later slice" | D-10 | `pt-bytes` provides it; C9 may adopt it as M0b' | 10 row A-07 |
| C-15 | C6 panel `ENGINE_COLUMNS` fixed to 3 engines (evidence_view.py:22) | D-08 registry | the Unified tab is registry-driven; the Evidence tab is unchanged until USER decision U-04 | 07 s3 |
| C-16 | R04 s7 "quantize or use math.fsum" for MD | R02 s6 "plain loop mirrors C++" | plain loop over sorted terms (parity) then quantize (key stability) (D-16) | 04 s2 |
| C-17 | R01 s4: UI diff header `// name . address` is diffed (ui.py:2080,2103) | L2 noise rule "never diff display text" | unified facts never diff UI text; SPEC-04 amendment to exclude the header from hunks | 10 row A-02 |
| C-18 | R03 s7 "two-signal rule for weak passes" vs R02 "tail steps pair leftovers" | precision first | tail passes produce `candidate` only, and only inside neighbour or blocked sets | 04 s5 |
| C-19 | Diaphora spec "best/partial/unreliable" as scores | D-11 | mapped to tiers B/C/C, `multimatch` -> ambiguous group; ratio kept as native text only | 06 s5 |

### 3.1 ChatGPT-authored specs: item-by-item disposition

| Spec item | Disposition | Where now |
|---|---|---|
| QB-01 goals 1-6 (ranked candidates, explanation, anchors, offline) | incorporated | 04 (ladder provenance), 05 (decisions), 07 (explain), D-29 |
| QB-01 `matching/contracts`, `candidates`, `refinement`, `anchors`, `explain`, `service` | superseded by `unified/{contracts, ladder/blocking, ladder/engine, sources/manual, read_model, pipeline}` | 01 s2 |
| QB-01 `features/registry` with user plugins | rejected: no plugin execution; passes are code + registry | 04 s1 |
| QB-01 similarity distances (cosine/Canberra/...) and weighted aggregation | rejected for decisions (no averaging); cosine kept only inside reference vectors (P16) | 04 s5 |
| QB-01 message-passing solver | backup only (B-07) | backups |
| QB-01 profiles (compiler-drift, data-oriented...) | deferred; one conservative config `ude-default/1` | 02 s6 |
| QB-02 build/CI phases, lazy optional imports, no auto-install | incorporated | plan |
| QB-02 new SQLite tables | superseded (C-06) | 02 s4 |
| RD-01 RD-F01..F03 byte spans, PE layout, offset alignment | re-homed to SPEC-26 B/D (not SPEC-31) | 10 row A-09 |
| RD-01 RD-F05 opcode-only vs full-byte with immediate warnings | incorporated as L2 C1/C2 | 05 s2 |
| RD-01 RD-F06 per-function CFG comparison | incorporated as C3 (from IR); radiff2 `-g` not used | 05 s2 |
| RD-01 RD-F04/F07/F08 radiff2 provider, edit distance, r2 projects | rejected (D-26) | - |
| RD-02 security rules (argv only, no `-c/-e`, bounded streams) | already PatchTrace policy; applied to the extractor | 03 s5 |

## 4. Open USER decisions (each has a safe default used until answered)

| ID | Question | Recommended default |
|---|---|---|
| U-01 | Port BinDiff v8 algorithms with Apache-2.0 attribution (D-21), or clean-room from papers/docs only? | port with attribution; ask for a patent/NOTICE review before the first release that ships the port |
| U-02 | Allow retaining Ghidriff GZFs in the run dir (disk: GZF size [unv], likely a few x the binary) to skip re-analysis? | yes, only when the unified flag is on; deleted after successful ingest |
| U-03 | Default navigator filter hides `cosmetic` and `unchanged` rows (count always visible, one click to show)? | yes |
| U-04 | Retire the C6 Evidence tab once the Unified tab passes G-U gates? | keep both until gates pass, then retire (single drill-down) |
| U-05 | Feature flag default | OFF in alpha; ON only after G-U1..G-U6 pass |
| U-06 | Show tier-B-from-one-component rows as `tentative`? | yes (never counted as matched, never used for an "unchanged" claim) |
| U-07 | Tier R corpus builds on Windows CI runners (clang-cl/mingw/MSVC) for A/A and planted-mutation gates | yes (consistent with spec-decisions O6) |
| U-08 | IR storage: project-local only, or also the global derived cache when a profile `cache_dir` is set? | both; global cache optional |
| U-09 | Memory cap for the unified worker | none in v1 (as SPEC-29 D10) until measured; measure first (G-U5) |
| U-10 | Run unified analysis automatically after each Ghidriff run when the flag is on? | no: explicit action (analyst control); CLI `unified run` |

## 5. Conventions used by all SPEC-31 files
Tier letters: M manual, A auto-accept key, B corroborating key, C candidate, W weak external evidence. "Component" = independence component (05 s1). Numbers live in 02 s6 (single source); other files repeat them only with a pointer. Error codes `PT-UNIFIED-*` in 01 s6.
