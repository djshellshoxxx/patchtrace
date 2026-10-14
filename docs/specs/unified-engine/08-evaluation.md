# SPEC-31 / 08 Evaluation: gates, corpora, parity harness, tests, performance

Rule (AGENTS.md): mocked/fake tests are never live evidence; live and corpus results are recorded in `docs/qa.md` in their own table with OS, tool versions, input hashes and run URL. Gate targets marked [inf] are proposals to preregister before the first locked run (method: `../calibration-corpus-and-model.md` s2, s4, s9: lineage-grouped splits, cluster bootstrap B = 2000). Owner slice S6 (corpus, harness), every slice owns its unit tests.

## 1. Gates (all must pass before the feature flag defaults to ON, U-05)

| Gate | Question | Metric and threshold | Data | First slice able to run it |
|---|---|---|---|---|
| G-U1 A/A null | does the engine invent changes? | X vs X: 100 % `unchanged`, 0 contested, 0 one-sided; P0 (same commit rebuilt): 0 `material`, `review` <= 0.1 % of rows [inf]; P1 nuisance (link order, `/ORDER`, `/OPT:ICF` toggle, timestamp/GUID/path): 0 `material` | Tier R A/A recipes (s2) | S3 (S0b for X vs X) |
| G-U2 planted mutations | does it see real changes, and never hide them? | leakage into `cosmetic`/`unchanged` = 0 (every hit is a normaliser bug and becomes a fixture); recall (`material` or `review`) >= 95 % per class with >= 20 mutants per class [inf] | classes: constant, comparison operator, bound (`<`/`<=`), removed check, swapped callee, struct offset, added block | S3 |
| G-U3 L1 precision and parity | are `matched` pairs right? | Tier R truth: matched-pair precision >= 99.5 %, cluster-CI lower bound >= 99.0 % [inf]; 0 truth-contradicted tier-A pairs on A/A; per-pass precision table (a pass with CI lower < 98 % is demoted one tier); BinDiff oracle when installed: MD index equal to 12 decimals on >= 99.9 % of functions with `n_bb` >= 5 (R02 s14 G1), >= 98 % agreement on BinDiff tier A/B pairs (G2); Ghidriff: every SymbolsHash/ExactBytes pair of an A/A run is `matched` or contested with a recorded reason | Tier R, oracles | S2 |
| G-U4 metamorphic | is it deterministic and symmetric? | byte-identical `manifest.json` (minus `created_utc`) for: two runs, Linux vs Windows CI, input record permutation; swap older/newer -> mirrored rows (older-only <-> newer-only, same matched set); 3-build chain: cosmetic(A,B) and cosmetic(B,C) never with material(A,C) on P1 chains; a cheap-tier semantic delta never coexists with `COS-PSEUDO` | synthetic IR + Tier R | S0b / S3 |
| G-U5 performance | does it fit a 60k-function image on a laptop? | L-35 targets on generated IR (10k, 60k, 250k functions) and on the largest Tier R pair; Windows frozen run included; failures trigger B-05/B-06 | `tools/unified/bench.py` | S2 / S5 |
| G-U6 noise vs legacy | is it worth it? | `material` false leads >= 20 % fewer than the best single legacy output (Ghidriff `modified`, BinDiff flags != 0, rz-diff non-identical) at non-decreasing planted recall (R05 s7) [inf] | Tier R planted + A/A | S3 |
| G-U7 independence assumption | is A-IND-1 safe? | error rate of rows `matched` via B+B with F-PT-BYTES must not exceed the error rate of tier-A rows by more than 2x (cluster CI); else `D_ghidra_decode` becomes joining (config change, no code change) | Tier R | S3 |
| G-U8 integrity and safety | did we break anything? | primary snapshot SHA unchanged by unified runs; old-reader test; schema drift CI; no socket opened during a full unified run (`sys.addaudithook` on `socket.connect` in tests); extractor script AST has no network/subprocess imports; tooltips, accessibility, banned words; frozen smoke | CI | every slice |

## 2. Corpora (no Microsoft binaries in the repository, ever)

| Tier | Content | Truth | Location |
|---|---|---|---|
| Unit | hand-built IR tables (`tests/unified_ir_builder.py`), hand-assembled x86-64 byte snippets with documented encodings (cosmetic: RIP-displacement shift, register rename, block reorder, thunk insertion; material: constant, comparison, callee, struct offset), synthetic Ghidriff JSON and secondary sets | exact by construction | `tests/fixtures/unified/` |
| CI fixture | `tests/fixtures/old.c` / `new.c` built to a DLL pair in CI (MinGW / clang-cl), as for live-rizin | source | CI artifact only |
| Tier R | zlib 1.3 -> 1.3.1 (R03 measured: 138 functions, 81 byte-identical, 51 address-noise-only, 3 genuine changes + 1 padding variant), libpng, sqlite, lua, mbedTLS adjacent tags and CVE-fix commits; clang-cl, mingw-w64, MSVC on Windows runners; PDB kept for truth, engines run symbols-hidden (SPEC-28 calibration s5.2) | debug info + source token diff of each function (L2: edited / induced / unchanged) | recipes + expected SHA-256 in `tools/unified/corpus/`; binaries only as CI artifacts |
| A/A | P0 same commit rebuilt (`/Brepro` where available), P1 nuisance flags, P2 stress (`/O1 /O2 /Ob /GL /Gy`, clang levels) expected `induced`, reported not gated | rebuild = no semantic change | same |
| Tier W (local only) | Winbindex pairs via `acquisition/`; anchors from R05 s1: ntoskrnl 10.0.22621.1344 -> 1413 (CVE-2023-23420), afd.sys 10.0.22621.1028 -> 1415 (CVE-2023-21768) | PDB names (symbols-hidden runs), manual adjudication | `PATCHTRACE_CALIB_ROOT`; results recorded by hash in `docs/qa.md`; corpus guard of `tools/calibration/corpus.py` reused |
Anchor acceptance on Tier W (reported, not CI): the patched function lands in `material` or top-10 `review`; each Ghidriff non-code `modified` row gets a recorded reclassification (R05 s0.2).

## 3. Labels and leakage
Function identity truth per `calibration-corpus-and-model.md` s5 (symbols-hidden rule, ICF/static-name pitfalls from `../../research/phase-c/matching-calibration-ground-truth.md` s3); L2 labels `unchanged-bytes | cosmetic | edited | induced | unknown` (R05 s7). Splits and intervals are by lineage; thresholds (demotions, G-U7 switch) are chosen on dev lineages only and frozen before any locked evaluation.

## 4. Parity harness (`tools/unified/parity.py`, dev only)
Inputs: one project with a unified result, optional `.BinDiff` + `bindiff --md_index` dumps, Ghidriff raw JSON. Output `parity-report.json` (deterministic): per pass: pairs, agreement with each oracle, disagreements listed by RVA pair with both provenances; MD index comparison histogram (exact / differs at 1e-12 / missing); Ghidriff pairs not reproduced, grouped by `match_types`; BinDiff pairs not reproduced, grouped by algorithm. Use: G-U3, and diagnosing parity drift (troubleshooting T-14). Ghidra-parity bonus: the extractor's optional Ghidra hasher values (03 s4) must induce the same equivalence classes as `h0` (ExactBytes) and `h3` (ExactInstructions) on every function (`test_live_h3_matches_ghidra_exact_instructions`, live only).

## 5. Red/green test list per module (unit tests are pure and fast; live tests are separate workflows)

| Module | Tests (red first, then green) |
|---|---|
| contracts / keys / limits | schema round trip and strictness; invalid examples of 02 s8 rejected; `result_key` changes with each input (parametrised over every payload field); swapped orientation -> different key; limits digest stable |
| store | publish requires verified parts; crash between dir move and row publish leaves an orphan removed by the next publish; retention keeps L-32 and never touches other kinds; `test_unified_rows_survive_enrichment_retention`; `test_old_reader_ignores_unified_kinds`; missing sidecar -> U6 not a crash |
| addressing | VA/RVA/auto/mixed; `EXTERNAL:` keys; address outside image dropped and counted |
| extract/runner, ir/* | 03 s10 list |
| sources/* | 06 s9 list |
| ladder/* | 04 s9 list |
| fusion/* | 05 s1.4 list |
| facts/* | 05 s3 table tests; `test_constant_only_patch_is_review_ranked_first`; `test_cos_addr_requires_tier_a_targets`; `test_material_needs_second_channel_from_other_group`; alignment cap -> review |
| pipeline / worker | `test_unified_run_never_mutates_project_snapshot`; `test_cancel_keeps_previous_result`; `test_worker_output_is_validated_before_publish`; `test_asymmetric_ir_falls_back_to_s0`; partial status propagation |
| read_model / ui_unified / cli | 07 s11 list |
| security (01 s9) | `test_no_network_during_unified_run` (audit hook), `test_children_get_absolute_argv_and_private_cwd`, `test_script_copied_to_empty_dir`, `test_paths_to_ghidra_have_no_dot_components`, `test_hostile_names_never_rendered_as_rich_text` |
| prerequisites | P1 `test_concurrent_spawns_do_not_leak_pipe_handles` (Windows CI: two threads spawn, the short child's reader returns in < 1 s while the long child runs); P2 `test_nway_raw_external_keys_are_skipped_not_fatal` |
Parametrised ids stay short (a 64 MiB parameter id once stalled the Windows console for 18 minutes, docs/qa.md).

## 6. Performance harness (`tools/unified/bench.py` + marked tests)
Generated IR at 10k / 60k / 250k functions with realistic degree distributions (power-law callers, 1-5 % changed functions, 0.5 % duplicates) measures: ingest time and RSS (fresh process), ladder time per stage, facts time for N changed pairs, read-model build, `data()` call counts for first paint/sort/filter at 10k and 100k rows. Gate: L-35 with 5x wall-clock slack on CI, exact call-count gates (C6 method). Windows numbers come from the Windows CI runner and the frozen EXE; they are recorded, never extrapolated from Linux.

## 7. CI placement

| Workflow | Runs | Counts as |
|---|---|---|
| `qa-windows.yml` (existing; Linux + Windows) | all unit tests, ruff, schema drift, frozen smoke incl. `unified --help` and `unified _worker --self-check` | automated evidence |
| `live-unified.yml` (new, dispatch + path filter) | extraction on the CI fixture DLL pair with Ghidra 12.0.4 (Windows + Linux), determinism across OSes, parity vs Ghidriff | live evidence (qa.md table) |
| `unified-corpus.yml` (new, dispatch/nightly) | Tier R builds, A/A, planted mutations, G-U1..G-U7 report | corpus evidence (report SHA in qa.md) |
| `live-bindiff.yml` (existing) | adds MD dumps for G-U3 when a pinned BinDiff is provisioned | blocked until the pin exists (qa.md) |
