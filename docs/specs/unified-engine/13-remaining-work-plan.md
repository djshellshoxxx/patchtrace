# SPEC-31 / 13 Remaining work plan: slices UE-R1..UE-R13 (integration, live gates, residual features)

Status: plan, 2026-10-15, base `f38c57e` (integration branch `claude/instance-d-gui`, PR #64; `origin/main` was `00db4c9`). S0a-S6c are built (see the README status line and `../../handoff/unified-engine.md` s2). This file is the missing plan for what is left: the live gate run and its harness gaps (S6 residual), G-U5 closing, G-U8 attestation, BinDiff oracle (G-U3), decompile persistence (S3b residual), flag UI and U-04/U-05, `features/2`. Step-by-step HOW, commands and tests per item are in `../../handoff/unified-engine.md` s3 (same ids); this file holds scope, contracts, gates, dependencies and fallbacks. Before EVERY slice re-read AGENTS.md and CLAUDE.md and check the default-branch SHA and open PRs (parallel contributors).

## 1. Verdict and scope
- Goal: reach a signed-off U-05 decision (G-U1..G-U6 pass, G-U8 pass) with the flag still OFF in alpha builds, and leave nothing that only the chat knew.
- In scope: the items below. Out of scope: new engines (Diaphora stays optional, 06 s5), N-way churn (B-12), BSim (B-09), Windows tables (B-11), the `features/2` implementation (belongs to the C9 calibration owner).
- No new runtime dependency; persisted contracts change additively only.

## 2. Slice table

| ID | Scope | Depends on | Tier | Size | Acceptance gate | Fallback |
|---|---|---|---|---|---|---|
| UE-R1 | land PR #64 (or the unified-only cherry-pick) so `unified-live-gates.yml` is on `main` | - | sonnet | M | Linux + Windows `qa-windows.yml` green | unified-only PR |
| UE-R2 | first live gate run on Linux + Windows; record the report SHA; triage reds into red tests and fixes | R1 | sonnet (haiku for logs; opus only for a Ghidra/Job Object blocker after two failed sonnet attempts) | L | a `gate-report/1` SHA and run URL in `docs/qa.md`; every non-pass gate has a named cause | smoke run with `per_class=2` and one case card |
| UE-R3 | persist `decomp.jsonl.gz` after the on-demand decompile | - | sonnet | M | `verify_result_dir(deep=True)` passes with the part; Code view shows `decompiled` for a real result | none (display already says "not stored") |
| UE-R4 | bench stages `facts`, `read_model`, `ui_calls`; Windows report; largest Tier R pair | R2 (real pair) | sonnet | M | G-U5 `pass` or an exact remaining reason | B-05/B-06 if L-35 fails |
| UE-R5 | frozen-smoke attestation in the gate report; Windows unified tests on CI | R1 | sonnet/haiku | S-M | G-U8 `pass` | stays `insufficient-data` |
| UE-R6 | BinDiff pin (owner), MD parity job, BinDiff/rz-diff legacy flags for G-U6 | owner for A; R2 for B | sonnet | M | `bindiff_pin verify --require-verified` exit 0; G-U3 oracle part ran | B-14 (Ghidriff-only oracle, wording "BinDiff-style") |
| UE-R7 | deferred audit findings U7-06..U7-18, mutant classes `try-scope`, `moved-rva-call`, trace-arg | - | sonnet | S each | red test then green per finding; G-U2 `pending` cleared or waived in writing | owner waiver |
| UE-R8 | `unified/enabled` switch in Setup; manual Windows accessibility pass; mark 07 s2 view switch superseded | - | sonnet | S-M | UI tests; qa.md manual rows | CLI-only (B-10b) |
| UE-R9 | U-05 flag default decision; U-04 retire the Evidence tab | R2..R6, owner | sonnet | M | `flag.decision_ready == true` with SHAs in qa.md | flag stays OFF |
| UE-R10 | `features/2` schema spec (C9 owner) | R2, label training | sonnet | L | out of scope until unblocked | none |
| UE-R11 | docs housekeeping (todo.md, 10-amendments status rows, plan status column) | - | haiku | S | docs only | - |
| UE-R12 | owner acceptance: Tier W anchors, Windows manual passes, BinDiff legal review, Ghidra pin | owner | - | - | recorded in qa.md | reported as blocked, never as pass |
| UE-R13 | backups B-xx on a named trigger only | - | - | - | - | - |

Dependency graph:
```text
R1 -> R2 -> R4(real pair) -> R9
R1 -> R5 -> R9
R6A(owner) -> R6B -> R2(second run) -> R9
R3, R7, R8, R11 independent (parallel with R1)
R9 -> U-04 (retire Evidence tab)
```
Critical path: R1 -> R2 -> fixes -> second R2 run -> R9. Parallel safely: R3, R7, R8, R11 (disjoint files: R3 `store.py`/`compute.py`; R7 `ladder/passes.py`, `exchange.py`, `tools/unified/{mutations,evaluators,bench}`; R8 Setup dialog and `unified/panel.py`; R11 docs).

## 3. Contracts and designs

### 3.1 UE-R3 decompile part (additive)
`Part.name` already allows `decomp.jsonl.gz` (`contracts.py`). Line schema (exactly the keys `pair_text._DECOMP_KEYS`): `{"side": "older|newer", "rva": int, "status": "ok|timeout|failed", "code": str|null}` with `code` a string iff `status == "ok"`. Writer: `store.write_result(..., decomp=...)` adds the part after `FACTS` and `ROWS`; lines sorted by (side, rva); text passed through `contracts.strip_unsafe`; sizes bounded by `LINE_MAX_BYTES` and `l30_part_bytes`. `result_id` is unchanged (the part is not a key input); a refresh that decompiled replaces the same-id directory via `publish_result(upgrade=)`. Readers that do not know the part must not fail: `store._verify` compares directory names with `manifest.parts`, so the manifest must list it. Invariants: text is data, never executed; cancel leaves no staged directory.

### 3.2 UE-R4 bench stages
`bench-report/1` gains rows for stages `facts` (5,000 changed pairs, limit `l35_facts_5000_s`), `read_model` (10k and 100k rows, `l35_first_paint_ms`, `l35_sort_ms`, `l35_filter_ms`) and `ui_calls` (exact `data()` call counts, no timing). The three entries leave `bench.PENDING`. G-U5 passes only with a report whose `environment.platform` names Windows and a pipeline run on the largest Tier R pair (`GATES['G-U5'].waits`).

### 3.3 UE-R5 attestation
`gates_u --attest frozen-smoke=pass|fail` already exists (`ATTESTABLE`). The workflow must derive the value from the frozen-smoke result of `qa-windows.yml` (artifact), never hard-code `pass`.

### 3.4 UE-R6 parity inputs
`tools.unified.parity report` writes `parity-report.json`; `rowgates.g_u3` oracle part reads it when `bindiff_pin_verified == 'true'`, else stays `blocked`. Product argv keeps `--md_index` forbidden (C-21); only the dev tool uses it. Legacy flags: `PairOutcome.legacy_tools` gains `bindiff` (`flags != 0`) and `rz-diff` (non-identical) only from real engine output, never inferred.

### 3.5 UE-R7 deadline policy (needs owner decision U7-06)
Option A (recommended): after `BudgetExhausted` in the ladder, fusion and facts run under a fresh bounded grace budget; status `partial`; cancel still raises `PT-UNIFIED-CANCEL`. Option B: document that partial applies to the ladder only and keep `timeout`. Either way a test pins it.

## 4. Gates this plan cannot close by itself
Live runs need GitHub-hosted runners (Ghidra 12.0.4 zip digest pinned in the workflows), the BinDiff pin needs a person with an independent network path and the issuer key, Tier W needs the owner's local corpus, Windows accessibility needs a person with NVDA/Narrator. They are reported as blocked, separately from automated evidence (CLAUDE.md).

## 5. Test and QA plan
Each slice: red test first, focused tests, `ruff`, schema drift (`python tools/generate_schemas.py` + `git diff --exit-code docs/schemas`), Qt repeat gate for UI changes (`python tools/qt_gate.py --repeat 20 tests/test_ui_unified.py`), Linux + Windows CI. Evidence goes to `docs/qa.md` with OS, tool versions, input hashes and run URLs; synthetic or mocked results are never live evidence.

## 6. Open questions (default for each; none blocks UE-R1..R8)
1. U7-06 policy: default Option A.
2. G-U2 pending classes: default keep `pending` (no waiver) until built.
3. MainWindow view switch: default superseded by the dock tab (B-10).
4. Who runs UE-R6A: default the owner.
