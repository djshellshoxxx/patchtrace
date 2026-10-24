# Handoff: UNIFIED ENGINE (SPEC-31)

Written 2026-10-15 for an engineer or Claude session with NO chat history. Facts come from the repository at `f38c57e` (tip of `origin/claude/instance-d-gui`, the integration branch, PR #64). Anything not verified by reading a file or running a command is marked `UNVERIFIED`. Policy: `AGENTS.md`, `CLAUDE.md`, `docs/plans/worker-brief.md`. Design: `docs/specs/unified-engine/` (README first). Plan of record: `docs/plans/unified-engine-plan.md`. The plan for what remains is `docs/specs/unified-engine/13-remaining-work-plan.md` (same IDs UE-R1..UE-R13 as below).

## 1. Purpose and current state

The unified engine turns every stored engine output (Ghidriff, BinDiff, rz-diff, analyst corrections) plus a per-binary ProgramIR (Ghidra) into one derived, ordinal, tier-labelled row model with per-row verdicts (`unchanged | cosmetic | material | review | unknown`), shown as a dock tab and through `patchtrace unified ...`. It never replaces the Ghidriff result, never shows a probability, never averages engines (invariants: `docs/plans/worker-brief.md` s2).

State in one sentence: every slice S0a-S6c is built and unit-tested on Linux with synthetic or recorded data; NO gate G-U1..G-U8 has ever run live; the live gate workflow is not on `main` yet; the feature flag is OFF and has no UI switch.

Commands that prove it (run from the repo root; `PYTHONPATH=src:.` is needed for the `tools.*` modules without an editable install):

```bash
git fetch origin && git rev-parse --short origin/main origin/claude/instance-d-gui   # observed 00db4c9 and f38c57e
git ls-tree -r origin/main --name-only | grep -E "unified-live-gates|tools/unified/(live_pairs|rowgates|gates_u)"   # observed: only tools/unified/bench.py and src/patchtrace/ui_unified.py exist on main from this list; the workflow and gate tools are NOT on main
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:. python -m pytest -q -p no:cacheprovider tests/test_unified_gates.py tests/test_unified_row_gates.py tests/test_unified_gate_eval.py tests/test_unified_bindiff_pin.py tests/test_unified_live_workflow.py tests/test_unified_cli.py tests/test_unified_pipeline.py tests/test_unified_fusion.py   # observed: 253 passed in 24.7 s (Linux, CPython 3.13)
PYTHONPATH=src:. python -m tools.unified.bindiff_pin verify --require-verified     # expected exit 3 (pin is trust-on-first-use, verified=false)
ls tests | grep -c "unified"                                                         # about 100 unified test files
```

Known process facts:
- Branches: `origin/claude/instance-d-gui` = integration branch, PR #64 (200 commits ahead of `origin/main` at observation). `origin/chatgpt/unified-fixtures-1` holds a ChatGPT fixture draft (not merged, content UNVERIFIED). `origin/claude/instance-c-research` = label training (instance C), `origin/claude/instance-b-features` = KB/CAP/tools (instance B); neither owns unified files. Status of PR #64 checks: UNVERIFIED (not queried).
- `workflow_dispatch` runs only for workflow files that exist on the default branch. `unified-live-gates.yml` exists only on the integration branch, so it cannot be dispatched until PR #64 (or a smaller PR carrying it) is merged. `live-unified.yml` and `unified-corpus.yml` ARE on main.
- Python in CI is 3.12; local observation was 3.13. Windows: not verified by me.

## 2. What is DONE

| Slice / item | Where | Evidence (test or record) |
|---|---|---|
| P1 Windows spawn lock, P2 nway `EXTERNAL:` skip | `jobs.py`, `nway/graph.py` | `test_concurrent_run_process_calls_do_not_cross_pipes_or_leak_threads`, `test_raw_ghidra_external_locations_are_skipped_not_fatal`. P2b: `test_nway_external_skips_are_counted` exists in `tests/test_nway_graph.py` (code done; the `tasks/todo.md` box is still `[ ]`, tick it in UE-R11; the SPEC-09/SPEC-28 status lines are UNVERIFIED) |
| S0a contracts, limits, keys, registry, store, schemas | `unified/{contracts,limits,keys,registry,store}.py`, `docs/schemas/unified/` | `tests/test_unified_{contracts,keys,store,registry}.py`; audit fixes `98182e5` (qa.md "S0a-FIX") |
| S0b sources, addressing, fusion (components AND evidence classes), S0 facts, verdicts, pipeline, worker, CLI `run/show/explain/status` | `unified/{sources,addressing,fusion,pipeline,worker,cli,compute}.py`, `facts/{channels,pseudo,verdict}.py` | `tests/test_unified_{sources,addressing,fusion,facts,pipeline,worker,cli}.py`; `test_unified_run_never_mutates_project_snapshot` |
| S1 extraction + IR | `unified/extract/{ghidra_script,runner,retain,decomp}.py`, `unified/ir/*` (ingest, reader, features, mdindex = BinDiff v8 port with notices, pe_tables) | `tests/test_unified_{ghidra_script,extract_runner,ir_*,retain_gzf,packaging}.py` (438 tests per qa.md). LIVE: Windows job of `live-unified.yml` passed L0-L4 on MSVC DLLs (PR #49, qa.md "Live, MSVC CI pair"); L5 redefined (amendment A-27); green re-run and Linux L6: UNVERIFIED |
| S2 ladder P00-P15, propagation, groups, parity harness | `unified/ladder/{passes,engine,propagate,groups,state,side,types,ports}.py`, `tools/unified/parity.py` | `tests/test_unified_ladder_*.py`, `test_unified_parity.py`; G-U5 synthetic 10k/60k in qa.md (60k ladder 9.56 s vs L-35 120 s) |
| S5 residual P16-P19 (blocking, reference vectors, block votes, layout gaps, LAP) | `ladder/{blocking,residual,assign}.py` | `tests/test_unified_ladder_{blocking,residual,residual_table,residual_perf,assign}.py` (139 tests); 60k ladder 11.2 s synthetic; worst case dense world 30.6 s |
| S3 IR channels C0-C5, operand classifier, DATA-MAP/1, alignment, UNCH/COS-ADDR/COS-LAYOUT proofs, EH-EQ, MAT-ANCHOR | `unified/facts/{align,operands,datamap,eh,layout,irchannels,anchors,fnview,trace}.py` | `tests/test_unified_{facts_align,datamap,ir_facts,operands,layout_eh,anchors,gu_mutants,verdict_ir}.py`; unit-level G-U1/G-U2/G-U4 per qa.md |
| S3b on-demand decompile (script mode, runner, strict reader, second worker call) | `extract/decomp.py`, `extract/runner.py:decompile_side`, `pipeline._decompile/_judge_again`, `compute.refacts_stage`, `facts/refacts.py` | `tests/test_unified_{ghidra_decompile,decomp_reader,decompile_runner,refacts,refacts_recorded,wire_refacts}.py`; one live Ghidra 12.0.4 run on Linux (qa.md S3b) |
| IR wired into `unified run` (UE-WIRE) | `compute.IrInputs`, `ir/ladder_port.py`, `sources/ladder.py`, `pipeline.PlacedIr` | `tests/test_unified_wire_{cli,compute,pipeline,refacts}.py`; modules.md "UE-WIRE" |
| S4a read model + CLI polish | `unified/{read_model,read_text}.py` | `tests/test_unified_{read_model,cli_show}.py` |
| S4b Qt panel (dock tab with Evidence, Ctrl+Shift+U), tooltips, a11y | `unified/panel.py`, `ui_unified.py` | `tests/test_ui_unified*.py`, `tests/test_unified_panel_spec.py`; `tools/qt_gate.py --repeat 20` 700 passed Linux (qa.md UE-S4b) |
| Code view: decompiled C, IR disassembly gaps, hunks | `unified/pair_text.py`, `UnifiedCodeView` | `tests/test_unified_pair_text.py` (32), `tests/test_ui_unified_code.py` (26), `tests/test_ui_unified_pipeline.py` (real worker child) |
| Explain into AI context preview; remembered column widths | `evidence.build_context(notes=)`, `read_model.parse_column_widths` | `tests/test_context_unified_notes.py`, `tests/test_ui_unified_columns.py` |
| S6a corpus (Tier R recipes zlib/libpng/Lua/mbedTLS +), A/A P0-P2, 12 planted-mutant classes, bench, gate-report skeleton | `tools/unified/{corpus,mutations,bench,gates_u}.py`, `.github/workflows/unified-corpus.yml` | `tests/test_unified_{corpus_*,mutations,bench,gates}.py`; real manifest of 324 pairs (qa.md) |
| S6b/S6c evaluators G-U1..G-U7, outcomes, live driver, cluster intervals, assembler `--inputs` | `tools/unified/{outcomes,evaluators,rowgates,cluster,live_pairs,gates_u}.py`, `unified-live-gates.yml` | `tests/test_unified_{gate_eval,row_gates,live_pairs,live_tool,live_workflow,nuisance}.py` |
| U7 audit fixes (surrogates, invisible chars, thin-lineage gates, G-U8 blocks readiness, BinDiff stub rows demoted) | see `docs/audits/20261015-unified-audit.md` | `tests/test_unified_audit_text.py`, `test_unified_row_gates.py`, `test_unified_fusion.py` |
| BinDiff pin checker + runbook | `tools/unified/bindiff_pin.py`, `docs/runbooks/bindiff-pin.md`, `tools/bindiff_pin.json` | `tests/test_unified_bindiff_pin.py`, `tests/test_provision_bindiff.py` |
| `features/2` proposal text | `docs/specs/unified-engine/12-features2-proposal.md` | text only, deliberately no code |

## 3. What REMAINS (ordered)

Conventions: tests are written FIRST and must be seen failing (`pytest -q` red) before the code. Model tier: haiku = fixtures, docs, log triage; sonnet = implementation/integration; opus only for a named hard blocker. Always run `QT_QPA_PLATFORM=offscreen PYTHONPATH=src:. nice python -m pytest <files> -q -p no:cacheprovider` and `python -m ruff check <files>` (ruff was not installed in my shell; install with `pip install ruff` if needed). Do not run the full suite more than once at the end. Every item appends a `### [UE-Rn:name]` block to `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` (append-only).

### UE-R1. Land PR #64 on main (prerequisite of UE-R2)
- Goal: `unified-live-gates.yml`, `tools/unified/{live_pairs,rowgates,outcomes,evaluators,cluster,gates_u}.py` reachable on `origin/main`.
- Files: none to write. Steps: (1) `git fetch`; compare `origin/main` with `origin/claude/instance-d-gui`; merge main into the integration branch (do not rebase a shared branch); (2) list open PRs and their checks (`gh pr list`, `gh pr checks 64`); (3) fix conflicts keep-both in `docs/modules.md`, `tasks/todo.md`, `docs/qa.md` (append-only blocks); (4) wait for green Linux + Windows `qa-windows.yml`; (5) merge; do NOT claim a GitHub Release.
- If the whole PR is blocked: cherry-pick only the unified commits (`git log --oneline origin/main..origin/claude/instance-d-gui -- tools/unified .github/workflows/unified-live-gates.yml`) into a PR `unified-gates-only` (dependencies: those tools import `patchtrace.unified.*`, `tools.calibration.*` and the SPEC-32 factory; check with `PYTHONPATH=src:. python -m tools.unified.gates_u --help` on the branch).
- Tests/commands: `QT_QPA_PLATFORM=offscreen python -m pytest -q` (full, once), `python -m ruff check src tests tools`, `python tools/generate_schemas.py` then `git diff --exit-code docs/schemas`.
- CI proof: `qa-windows.yml` (Linux + Windows legs, frozen smoke).
- Gate: required checks green on both OS. Size M. Tier sonnet. Depends on: nothing.

### UE-R2. First live gate run, triage, record
- Goal: the first `gate-report/1` on real data; this converts G-U1..G-U8 from `pending` to a verdict or a named fix list.
- Procedure (after UE-R1):
  1. Dispatch: `gh workflow run unified-live-gates.yml --ref main -f pairs=all -f per_class=20` (inputs, from the workflow file: `pairs` default `all`, `per_class` default `'20'`; G-U2 needs >= 20 per class). Smoke first: `-f pairs=zlib...` with a card id from `PYTHONPATH=src:. python -m tools.unified.corpus check` / `tools/unified/corpus/cards.json` (exact id strings UNVERIFIED), and `-f per_class=2`, to avoid a 4-hour failure.
  2. Jobs: `build` (Linux, timeout 180 min; mingw/clang builds, never executes), `pairs` (Linux+Windows, 240 min, runs `live_pairs --roles release,cve-fix,P0,P1`: pass 1 with `--swap`, pass 2 for determinism), `mutants` (12 classes x 2 OS, 240 min each), `integrity` (bench 10k/60k + G-U8 tests, 60 min), `report` (assembles `gate-report.json/.md`). Expected runtime: not measured; the timeouts are upper bounds only (UNVERIFIED). All jobs after `build` are `continue-on-error`.
  3. Download artifact `unified-live-gate-report`; `sha256sum out/gate-report.json`. Artifacts live 3 days.
  4. Record in `docs/qa.md` in its own block `### [UE-R2:first-live-gate-run]`: run URL, date, runner images, Ghidra 12.0.4 (zip sha256 is pinned in the workflow env), pyghidra 3.0.2, Ghidriff pin, report SHA-256, per gate status and numbers (copy the Markdown), corpus manifest SHA (`manifest_sha256`), failures. Mocked or synthetic results are never live evidence (AGENTS.md).
- Expected first-run outcomes (reasoned, not observed): G-U3 oracle part `blocked` (pin unverified); G-U8 `insufficient-data` (frozen-smoke attestation not produced there, see UE-R5); G-U5 `pending` (see UE-R4); G-U7 likely `insufficient-data` (classes under 30 B+B rows); G-U6 compares Ghidriff `modified` only. Real failures will be: MSVC/MinGW operand shapes, a normaliser leak in G-U2 (every leak becomes a fixture and a fix, troubleshooting T-19), Windows vs Linux image-byte differences in G-U4 (T-13).
- For each red gate: open a defect entry in `tasks/todo.md` with the pair id, RVA and the row's `explain` text (`patchtrace unified explain <project> --row <id>`), write a red test from the minimal synthetic reproduction, fix in the owning module (see `unified-engine-troubleshooting.md` T-xx). Do not weaken a gate to pass.
- Size L (CI time + triage). Tier sonnet for harness fixes; haiku to read logs; opus only if a Ghidra/pyghidra or Job Object blocker survives two sonnet attempts. Depends on UE-R1.

### UE-R3. Persist the decompiled C (`decomp.jsonl.gz`)
- Goal: the code view shows decompiled C for real results (today: "Decompiled code is not stored in this result", qa.md UE4, verified in code: no module writes the part; only `contracts.Part.name` allows it and `pair_text.RowCodeSource._read_decomp` reads it).
- Files: `src/patchtrace/unified/store.py` (`write_result` gets an optional `decomp: Iterable[dict] = ()` and adds `write_part(directory, 'decomp.jsonl.gz', ...)` when non-empty; check `_Deep.feed` and `_verify` accept the third part name, `Counts` unaffected); `src/patchtrace/unified/compute.py:refacts_stage` (builds lines `{side, rva, status:'ok', code}` from `texts`, keys must equal `pair_text._DECOMP_KEYS`; sorted by (side, rva) for determinism; bounded by `limits` and `LINE_MAX_BYTES`); `pipeline.py` needs no change if `refacts_stage` writes it (the `publish_result(upgrade=)` path already replaces a same-id directory).
- Tests first (add to `tests/test_unified_wire_refacts.py` and `tests/test_unified_store.py`): `test_refacts_stage_writes_a_decomp_part_that_verifies` (manifest lists the part, `verify_result_dir(deep=True)` passes); `test_decomp_part_is_deterministic_across_runs` (equal sha256); `test_result_id_unchanged_by_decomp_part`; `test_row_code_source_reads_stored_decompiled_c` (extend `tests/test_unified_pair_text.py`); `test_publish_upgrade_replaces_same_id_result_with_decomp` ; `test_old_reader_ignores_new_part` (an older manifest model rejects/ignores unknown parts: check `tests/test_unified_contracts.py` expectation; the `Part.name` Literal already contains the name, so no schema change; confirm `python tools/generate_schemas.py` yields no diff).
- Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=src:. python -m pytest tests/test_unified_store.py tests/test_unified_wire_refacts.py tests/test_unified_pair_text.py tests/test_ui_unified_code.py tests/test_ui_unified_pipeline.py -q -p no:cacheprovider`.
- CI: `qa-windows.yml`; live proof in the UE-R2 run (a project with decompile on shows C in `pair_text`). Untrusted text: use `contracts.strip_unsafe` (U7-02) before writing; never execute the text.
- Acceptance: a real `unified run` with Ghidra configured produces the part and the Code view shows `decompiled` mode. Size M. Tier sonnet. Depends on: nothing (live proof needs UE-R2).

### UE-R4. Close the G-U5 `pending` parts
- Goal: `bench-report/1` measures what `tools/unified/bench.py:PENDING` still lists (facts for 5,000 pairs, read-model build at 10k/100k, exact `data()` call counts) and a Windows report exists; the largest Tier R pair runs through the whole pipeline.
- Files: `tools/unified/bench.py` (new stages `facts`, `read_model`, `ui_calls`; remove them from `PENDING`; `--stages` accepts them; limits `DEFAULT_LIMITS.l35_facts_5000_s`, `l35_first_paint_ms`, `l35_sort_ms`, `l35_filter_ms` exist), `tools/unified/gates_u.py:_g_u5` (the Windows condition is `'windows' in environment.platform`), `GATES['G-U5'].waits`, `.github/workflows/unified-live-gates.yml` job `integrity` (already runs bench on both OS; add the new stages), `tests/test_unified_bench.py`.
- Tests first: `test_bench_facts_stage_reports_counts_and_gate`, `test_bench_read_model_stage_at_10k_and_100k`, `test_bench_ui_calls_exact_data_call_counts` (exact counts, not times; method: C6 call-count gates), `test_g_u5_pending_clears_only_with_windows_report` (gates test).
- Command: `PYTHONPATH=src:. python -m tools.unified.bench --sizes 10000,60000 --stages ladder,ingest,facts,read_model --out /tmp/bench.json` (stage names beyond `ladder,ingest` are what this item adds; today's help lists only those two).
- Known measured numbers (qa.md, Linux, synthetic): ladder 60k 9.8-11.2 s; ingest 60k 116.7 s; `load_unified` 100k rows 17.6 s on a loaded box (check against L-35 UI budgets: first paint <= 200 ms is for the model, load is a worker task).
- Windows frozen EXE bench: needs a frozen-run hook; UNVERIFIED how (no flag exists in `bench.py`; likely run `bench.py` from the Windows runner source tree only and record the frozen EXE as manual). Gate: G-U5 `pass` requires the Windows report and the Tier R pair; otherwise stays `pending`. Size M. Tier sonnet. Depends on UE-R2 for the real-pair part.

### UE-R5. G-U8 frozen-smoke attestation and Windows evidence
- Goal: G-U8 can reach `pass`. Missing: the `frozen-smoke` attestation (the integrity job runs tests only) and Windows CI evidence for unified tests (todo.md S0b/S1 items `[ ]`).
- Files: `.github/workflows/qa-windows.yml` (the job already runs `python tools/frozen_smoke.py dist/PatchTrace/PatchTrace.exe` at line ~44 and prints a result file; surface its result as an artifact `frozen-smoke.txt`), `.github/workflows/unified-live-gates.yml` job `report` (download it and pass `--attest frozen-smoke=pass|fail`; `gates_u --attest NAME=pass|fail`, `ATTESTABLE = ('frozen-smoke',)`), `tests/test_unified_live_workflow.py` (assert the flag is passed).
- Windows CI evidence: confirm the unified test files pass on the Windows leg of `qa-windows.yml` (child spawn via `python -m patchtrace`, `os.replace` retry, CRLF of `docs/schemas/unified/*` examples, Job Object memory cap U7) and CPython 3.12; record in qa.md. Frozen smoke lines: `unified --help` and `unified _worker --self-check` (tools/frozen_smoke.py `unified_checks`, U1 script data file present, U2 CLI).
- Command locally: `python tools/frozen_smoke.py --help` for modes (do not guess flags); Linux build only via `python tools/build_linux.py`; Windows packaging runs on Windows only (AGENTS.md).
- Acceptance: G-U8 `pass` in a gate report: all seven checks of `gates_u.G_U8_CHECKS`. Size S-M. Tier sonnet/haiku. Depends on UE-R1.

### UE-R6. BinDiff: provision the pin, add the MD parity job, wire BinDiff/rz-diff into G-U6
- Goal: G-U3 oracle part leaves `blocked`; G-U6 compares against more than Ghidriff `modified`.
- Part A, owner/network steps (no code): follow `docs/runbooks/bindiff-pin.md` steps 1-4 exactly: independent re-hash of `bindiff_8_amd64.deb`, its `.asc`, `bindiff8.msi` from `https://github.com/google/bindiff/releases/download/v8`; `gpg --verify` against key id `4EB27DB2A3B88B8B` obtained from two channels; executable digest check (`./opt/bindiff/bin/bindiff` inside the .deb); then edit `tools/bindiff_pin.json` (`verified`, `signature.verified`, `signature.signature_verified_by`); update `tests/test_provision_bindiff.py::test_committed_pin_holds_real_v8_values_marked_trust_on_first_use` in the same commit; run `PYTHONPATH=src:. python -m tools.unified.bindiff_pin verify --require-verified` (must exit 0), `pytest tests/test_unified_bindiff_pin.py tests/test_provision_bindiff.py -q`. Dispatch `live-bindiff.yml` (trigger: `workflow_dispatch`, no inputs) and write both run URLs and the `verify` output in qa.md. Never copy digests from docs.
- Part B, code (after A): no workflow runs `tools.unified.parity` today (checked: `live-bindiff.yml` and `unified-live-gates.yml` contain no `md_index` or `parity`; 08-evaluation s7 says `live-bindiff.yml` "adds MD dumps", which is NOT built). Add a job to `unified-live-gates.yml` (or `live-bindiff.yml`) gated by `steps.bindiff_pin.outputs.bindiff_pin_verified == 'true'` (snippet in the runbook s5): provision with `python tools/provision_bindiff.py`, export BinExport for the label pairs, run `python -m tools.unified.parity md-dump ...` then `parity report ...` (read `--help` of both subcommands first), and feed `parity-report.json` to `rowgates.g_u3` (inspect how `gates_u --inputs` finds it; the file name pattern is UNVERIFIED, add it to `expand_inputs` if absent). Tests first: `test_g_u3_oracle_part_passes_only_with_parity_report`, `test_g_u3_oracle_part_blocked_without_verified_pin`.
- Part C, G-U6 legacy flags: `tools/unified/live_pairs.py` fills only Ghidriff `modified`; BinDiff (`flags != 0`) and rz-diff (non-identical) are in `not_supplied`. Implement by running the secondary engines in the corpus pipeline (needs BinExport + a pinned BinDiff, so after A). Tests: extend `tests/test_unified_live_pairs.py`.
- Size M (code) + owner time. Tier sonnet. Depends on: A on owner; B on A and UE-R2.

### UE-R7. Deferred audit findings and harness gaps (low risk, independent)
Each is S, tier sonnet unless noted; red test first; all in `docs/audits/20261015-unified-audit.md`.
- U7-06 (decision needed from the owner, see s4): grace budget for fusion/facts after a ladder deadline. If "grace budget": `compute.py:190,196` use a fresh `Budget` with `limits` grace after `BudgetExhausted` in `ladder/engine.py:66-81`; test `test_partial_ladder_result_survives_a_spent_deadline` (fusion and facts complete, status `partial`, cancel still aborts with `PT-UNIFIED-CANCEL`). If "document only": add the sentence to 04 s8 and test the current `timeout` status.
- U7-07: add a trace-arg mutant class in `tools/unified/mutations/classes.py` + `templates.py` (needs a tracing import in the freestanding profile) or move the sentence in 08 s1 G-U2 to PENDING; test in `tests/test_unified_mutations.py`.
- U7-08: widen G-U4 mirror check in `tools/unified/evaluators.py:143-150` to `tentative/candidate/contested/ambiguous` rows. Needs a decision on `arbiter.strength` tie-breaks (`-edge[0], -edge[1]` is not orientation symmetric); first write a property test over generated rows to see if mirrored rows really differ; if yes, fix the tie-break with a canonical key independent of orientation (this may change `config_digest`, so bump the registry/engine digest deliberately).
- U7-09: replace the remaining narrow control regex copies (`extract/ghidra_script.py:66-67` cannot import patchtrace: copy the ranges and test equality in `tests/test_unified_ghidra_script.py`; `ir/records.py:34`; `secondary/evidence_view.py:101` is outside this area). Changing the script changes `script_sha256` and IR text: regenerate recorded fixtures with their `PROVENANCE.json`.
- U7-10 `sources/__init__.py:233-237` bounded line read; U7-11 `exchange.py:186-193` use `strict_json`; U7-12 `ladder/passes.py:252,286` P15 must treat `'?'` callees as unresolved, not equal tokens (test: unresolved-callee pair stays tier C); U7-13 `tools/unified/bench.py:241` bounded subprocess output.
- Mutant classes `moved-rva-call` and `try-scope` (`classes.PENDING`): `try-scope` needs the MSVC Windows leg (clang-cl with a C runtime handler); `moved-rva-call` needs an acceptance rule on raw caller bytes. Until built G-U2 reports them as `pending`, which blocks a G-U2 `pass`: decide with the owner whether to waive (s4).
- U7-15/U7-16: reconcile the 08 s1 header text ("every gate must pass") with U-05 (G-U1..G-U6, plus a failing G-U8 blocks), and the 05 s1.2 BinDiff-confidence sentence. Docs only, haiku.

### UE-R8. Flag switch in Setup and UI polish
- Goal: an analyst can turn `unified/enabled` on without editing settings. Verified: `ui_unified.py:820` reads `self.settings.get_bool('enabled', False)`; no Setup/settings UI references it (`grep -rn unified src/patchtrace/gui/*.py` found nothing; a toggle elsewhere is UNVERIFIED).
- Files: the Setup dialog module (find it with `grep -rn "restrict_env" src/patchtrace/*.py`, shared file, keep the edit <= 25 lines, inspect open PRs touching it first), `unified/panel.py` (tips), `tests/test_ui_unified.py`, `tests/test_tooltips.py` (shared, `unified.*` ids only).
- Tests first: `test_setup_has_a_unified_checkbox_off_by_default`, `test_toggle_enables_run_button_without_restart`. Wording must carry "experimental, derived, ordinal" and no probability words (`test_unified_banned_strings_never_appear`).
- Spec status: 07 s2 describes a MainWindow view switch with a `ui.py` seam; B-10 (dock tab only) is what was built. `ui.py` has zero `unified` references (grep count 0), so `test_flag_off_ui_unchanged` (plan s5) does not exist and is trivially true. Decide (s4) whether the view switch is still wanted; if not, mark 07 s2 "superseded by B-10" in the spec.
- Manual (owner, Windows): NVDA/Narrator, 125/150/200 % DPI, high contrast pass of the Unified panel (not automatable; record in qa.md as manual). Size S-M. Tier sonnet. Depends on nothing.

### UE-R9. Flag default decision (U-05) and retiring the Evidence tab (U-04)
- U-05: default stays OFF. It may flip ONLY when a gate report (UE-R2 or later) has G-U1..G-U6 all `pass` with the report SHA in qa.md and `flag.decision_ready == true` in `gate-report.json` (code: `gates_u.decision_ready`; a G-U8 `fail` also blocks; G-U7 is advisory but never "assumed safe"). Per-gate needs, from `GATES` in `tools/unified/gates_u.py`:
  - G-U1 (A/A null): outcomes of every manifest A/A pair (P0, P1 variants link order, icf, timestamp, guid, path), X vs X 100 % `unchanged`, 0 `material` on P0/P1. `pending` if a P1 kind has no pair; `insufficient-data` if a pair has no outcome.
  - G-U2 (planted mutants): >= 20 mutants per class with an outcome, zero leakage into `cosmetic/unchanged`, recall >= 95 % per class (`material` or `review`); `pending` while `classes.PENDING` is non-empty.
  - G-U3 (L1 precision): precision >= 99.5 %, lineage-cluster lower bound >= 99.0 % (< 30 lineages: `insufficient-data`), 0 truth-contradicted tier-A pairs, Ghidriff exact pairs matched or contested; oracle part `blocked` until UE-R6A+B.
  - G-U4 (metamorphic): two runs equal, Linux vs Windows equal over the same image bytes, swapped orientation mirrored, 3-build chain; `pending` without a chain in the manifest.
  - G-U5: see UE-R4. G-U6: >= 20 % fewer `material` false leads than the best legacy at non-decreasing planted recall, lineage CI; thin data `insufficient-data`. G-U7: per (component pair, evidence-class pair) B+B error rate <= 2x tier-A rate; classes < 30 rows `insufficient-data`. G-U8: UE-R5.
- U-04 (retire the C6 Evidence tab `ui_evidence.py`, `ENGINE_COLUMNS`): not before U-05 passes; keep both until then (`00-decisions.md` U-04). Then: remove the Evidence tab behind a deprecation release, keep `secondary.evidence_table` for the CLI (check importers with `grep -rn ENGINE_COLUMNS src`), update `unified/panel.py` (`tabbed with evidence` anchor) and `tests/test_gui_host_seam.py`. Owner approval required (s4). Size M. Tier sonnet. Depends on UE-R2..R6.

### UE-R10. `features/2` (calibration vector with unified families U and F)
- Status: proposal only (`12-features2-proposal.md`); no code, intentionally. It belongs to the calibration track owner (SPEC-28 C9, label training instance C). Do not implement until (a) unified results exist on the Tier R corpus (UE-R2), (b) the C9 owner rules on the hazards in 12 s6 (label leakage: `F.c0_equal`/`c1_equal` restate the SPEC-32 labels; second target; claim scope). Next action when unblocked: the C9 owner writes the `features/2` schema spec; this area supplies `unified-match/1` and `change-facts/1` fields as listed (about 41 U columns and 24 F columns [inf]; budget 64 -> 96). Size L. Tier sonnet for the extractor, opus not needed. Depends on UE-R2 and label training.

### UE-R11. Documentation housekeeping (haiku)
- `tasks/todo.md` lines 94-103 still show S0b..S6 as `[ ]` and duplicate the U-01..U-12 lines: tick S0a, S0b, S1, S2, S3, S3b, S4, S5, S6a-c as built, keep live/Windows items `[ ]`.
- Spec status lines still open (10-amendments.md): A-01, A-01b, A-03, A-06, A-09, A-10, A-11, A-14; P2b (count skipped `EXTERNAL:` entries, A-05, A-06). `docs/notices.md` / `docs/reuse-matrix.md` rows (A-24) and the S2 build-notes paragraph in 04 (todo [S2:ladder] integration item): UNVERIFIED whether done.
- `unified-engine-plan.md` section 3 file-ownership is historical; section 1 table lacks status; add a status column pointing here.

### UE-R12. Owner-only acceptance (cannot be automated)
Tier W anchors (local USER corpus, `PATCHTRACE_CALIB_ROOT`): ntoskrnl 10.0.22621.1344 -> 1413 (CVE-2023-23420), afd.sys 10.0.22621.1028 -> 1415 (CVE-2023-21768); acceptance: patched function in `material` or top-10 `review`; record by hash in qa.md, never commit Microsoft binaries or PDBs. Windows manual GUI/DPI/screen-reader passes (UE-R8). Legal/patent review of the BinDiff MD-index port (U-01/O1) before the first public non-prerelease. Decide Ghidra 12.0.4 vs 12.1 (O3: stays 12.0.4; moving changes decompiler output and every recorded run).

### UE-R13. Optional backups already designed (do not build unless a trigger fires)
`docs/plans/unified-engine-backups.md` lists B-00..B-23 with switches (for example B-14 "BinDiff-style" wording when no pin; B-07 `--no-residual`; B-08 `--no-decompile`; B-03 S0 only via `--no-extract`). Use the fallback column when a gate fails twice rather than retrying with a weaker model.

## 4. Decisions only the owner can make (recommendation)

| ID | Decision | Recommendation |
|---|---|---|
| U-05/O2 | When does the flag default ON? | Stay OFF in alpha; flip only with a gate report where G-U1..G-U6 pass and `decision_ready` is true; never earlier |
| U-04 | Retire the Evidence tab? | Keep both until U-05 is met, then retire in a separate release |
| U-01/O1 | BinDiff MD-index port legal/patent review | Licence-only review before the first public non-prerelease; the v8 notice already ships |
| O3 | Ghidra 12.0.4 vs 12.1 | Keep 12.0.4 for the alpha; schedule a comparison run later |
| BinDiff pin | Who runs the independent re-hash and key check (UE-R6A)? | The owner on a workstation not behind the research proxy; about 30 minutes |
| U7-06 | Deadline policy after a partial ladder | Grace budget for fusion/facts (keeps the partial result), cancel still aborts |
| G-U2 waiver | Waive `moved-rva-call` and `try-scope` pending classes for the first U-05 decision? | No: keep G-U2 `pending` honestly; build `try-scope` on the Windows leg; or record an explicit waiver in 08 s1 before the run |
| View switch | Is the MainWindow view switch (07 s2) still wanted, or is the dock tab final (B-10)? | Dock tab is final; mark 07 s2 superseded |
| features/2 | Start? | Not before labelled unified results exist and the C9 owner agrees on hazards |

## 5. Pitfalls and lessons (from qa.md, audits, troubleshooting)

- A workflow can be dispatched only if its file is on the default branch: this is why UE-R1 comes first.
- Windows: `os.replace` of directories fails while an indexer holds a file (T-08, retry exists); `PYTEST_CURRENT_TEST` is limited to 32,767 characters, so parametrised ids must be short (a 64 MiB id stalled the console 18 minutes); the Windows monotonic clock is 15.6 ms, use `>=` on timings; no fixed sleeps; LF fixtures; `.gitattributes` lines for `tests/fixtures/unified/`.
- Never apply a memory cap (RLIMIT_AS) to the JVM child: "Could not reserve enough space for object heap" (T-38). The capped worker never spawns the JVM; the decompile stage runs in the owner thread's process (`pipeline._decompile`).
- Ghidra: `GhidraProject.analyze` needs `GhidraScriptUtil.bundleHost` initialised (T-32); Ghidriff saves a GZF even when analysis failed, so check `isAnalyzed` (T-31); Ghidra's hashers include NOPs that `h3`/`hm` skip, so live check L5 was redefined (amendment A-27).
- Private directories must not have dot-prefixed path elements (T-03).
- Stub rows (imports, thunks, `basicblocks == 0`) must never reach tier A alone (fixed U7-05; keep the test).
- Fusion invariants: corroboration needs two independence components AND two evidence classes; one-sided atoms never contest; manual claims win; never average native numbers.
- Untrusted text: lone surrogates stopped whole runs (U7-01); invisible and bidirectional characters survived three paths (U7-02). Use `contracts.replace_surrogates` and `contracts.strip_unsafe` for any new text path.
- Gates must not pass on thin data: G-U3/G-U6/G-U7 return `insufficient-data` under 30 lineages (U7-03); a skipped or missing input is never a pass; `decision_ready` ignores nothing.
- The Qt abort class: a started `QThread` destroyed on project switch (T-20); run `python tools/qt_gate.py --repeat 20 tests/test_ui_unified.py` after any UI change.
- Persisted contracts change additively only; result ids must not depend on the decompile (a refresh that decompiled replaces the same id with `publish_result(upgrade=)`); regenerate schemas with `python tools/generate_schemas.py` and keep the drift test green (T-24).
- Tests green on Linux, red on Windows (T-28): POSIX path literals, CRLF, replacing an open file, `.cmd` fake interpreter quoting.
- Do not trust the 08 s7 sentence that `live-bindiff.yml` adds MD dumps: it is not built (UE-R6B).

## 6. Verification checklist before calling the area finished

- [ ] PR #64 (or a successor) merged; `qa-windows.yml` green on Linux and Windows; `docs/schemas` drift clean.
- [ ] `unified-live-gates.yml` dispatched; report SHA, run URL, runner images and tool versions in `docs/qa.md`.
- [ ] G-U1..G-U6 each `pass` (not `pending`, `insufficient-data` or `blocked`); G-U8 `pass` with the frozen-smoke attestation; G-U7 reported (advisory) with its class counts.
- [ ] `PYTHONPATH=src:. python -m tools.unified.bindiff_pin verify --require-verified` exits 0; `live-bindiff.yml` run recorded; G-U3 oracle part ran.
- [ ] Linux and Windows `content_digest` and `manifest.json` byte-identity over the same image bytes (G-U4) shown in the report; 10k and 60k bench rows from both OS, plus facts/read-model rows.
- [ ] `decomp.jsonl.gz` written and shown in the Code view on a real result.
- [ ] `PatchTrace.exe unified --help` and `unified _worker --self-check` exit 0 in the frozen build.
- [ ] Flag toggle present in Setup, default OFF; `decision_ready` true only after the above, and the owner approved U-05 in writing.
- [ ] Deferred findings U7-06..U7-18 either fixed with a test or recorded as accepted in the audit file.
- [ ] No Microsoft binary, PDB or Winbindex label committed; no probability words in the UI; `tasks/todo.md`, `docs/modules.md`, `docs/qa.md` updated.

## Continuation 2026-10-16: UE-R7 U7-12 P15 unknown-callee correctness slice

- Isolated branch: `chatgpt/ue-r7-p15-unresolved-20261016-a` from integration head `53f366e8b50ac60a95bdb3734b815daac82cd63d`. No edits to the shared integration branch, main, or active LBL-31/LBL-32 worker branches.
- Spec amended: `docs/specs/unified-engine/04-matching-pipeline.md` P15 rule requires every call site to resolve to an import key, self-reference, or already matched callee. A direct site with unknown callee and no import key cannot prove exact equivalence.
- Red regression tests committed before implementation: `tests/test_unified_p15_unresolved.py` tests unknown/unknown, mixed known/unknown, identified import retained, and unknown versus identified import. On the prior implementation, the first two regressions would emit a P15 tier-A pair because both sides shared `('?', jump)`.
- Implementation: `src/patchtrace/unified/ladder/passes.py` makes P15 abstain for the whole caller on any unknown callee instead of generating a generic token. `LADDER_VERSION` advanced to `ladder/2` so `pass_table_digest` and downstream config identity change; previously computed matches must not be treated as equivalent.
- Verification status: **CI pending**. The new tests use synthetic minimal ladder states and are not live Ghidra corpus acceptance. Before merge run `PYTHONPATH=src:. python -m pytest -q tests/test_unified_p15_unresolved.py tests/test_unified_ladder_core.py tests/test_unified_ladder_properties.py`, full Linux/Windows QA and `python -m ruff check src tests tools`; inspect any changed golden/config digest assertions. G-U1..G-U8 remain unverified live and the unified feature flag stays OFF.
- Follow-up after green checks: merge the isolated PR to `claude/instance-d-gui` with a merge commit and verify target ancestry, then continue UE-R7 remaining findings or UE-R1/UE-R2 integration/live gates without claiming fixture tests are accuracy measurements. Do not merge unrelated draft branches.
