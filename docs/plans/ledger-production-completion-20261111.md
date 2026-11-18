# Ledger: production-completion session (2026-11-11)

Session `session_01KtKj8mF3j3dSBSESbfu5Zs`. Branches of this session all start with `claude/sleepy-fermi-`.
Baseline: `main` at `882d1ca0` (push run 42605088788 green). This file is this session's own ledger and progress
record; other sessions do not edit it. Nothing recorded here is live or native evidence unless a row says so.

## 1. Baseline measured in this sandbox

| Check | Result | Notes |
|---|---|---|
| Full suite, `python tools/run_test_suite.py --workers 3` (Linux container, Python 3.12.3, PySide6 6.12.0, offscreen) | 1 failed, 20,809 passed, 56 skipped, 8 xfailed in 480 s | The one failure is `tests/test_research_qualification_cli.py::test_paths_outside_allowed_roots_are_refused`. It fails only under pytest-xdist and passes alone (6 passed in 16 s). CI does not use xdist, so CI is not affected. |
| `python -m ruff check src tests tools` | clean | |
| Native tools (Ghidra, Rizin, BinDiff) | not available | The egress proxy returns 403 for other repositories' GitHub release pages. NVD, MSRC, Winbindex, CISA and FIRST hosts are unreachable. Native and live evidence can only come from the repository's GitHub Actions workflows. |

## 2. Lanes owned by other sessions today (not touched here)

Read from GitHub on 2026-11-11 between 00:40 and 00:55 UTC. Re-read before acting.

| Lane | Owner branch / PR | Files |
|---|---|---|
| Unified-engine soundness: #259 follow-up (swap orientation, IR-only one-sided functions, DATA-MAP vote, reversal asymmetry) | `claude/funny-feynman-d2m0b5` | `src/patchtrace/unified/{sources,ladder,fusion,facts}/**`, `unified/registry.py`, `unified/keys.py`, `docs/specs/unified-engine/**` |
| Unified live gates and native proof (#268, #174, #139 to #141) | `claude/live-proof-20261111`, `claude/live-harness-infra-20261111`, ledger on `claude/autonomous-finish-20261104` | `tools/unified/**`, `src/patchtrace/backend.py`, `.github/workflows/unified-live-gates.yml`, `tools/calibration/tier_r/**` |
| Open-PR consolidation ledger, wave 3 | #179 `claude/patchtrace-multi-worker-consolidate-24ct7v` | `docs/plans/ledger-consolidation-20261104.md`, `tools/dev/branch_inventory.py` |
| Release job naming and action pin | `claude/patchtrace-haiku-agent-motpbx` | `.github/workflows/qa-windows.yml` (release job), `tests/test_release_gate.py` |
| SPEC-53 backend diagnose launcher | #280 `claude/spec53-diagnose-launcher` | `backend.py` diagnose path, `tests/test_backend_cli.py` |
| Analyst accessibility (Codex, 2026-11-09) | `codex/analyst-accessibility-20261109` | `src/patchtrace/ui_export_v2.py`, `src/patchtrace/ui_inspection.py`, `docs/help/**` |
| Codespaces bootstrap | #279 `codex/codespaces-cs1-20261109` | `.devcontainer/**` |
| Rules and call-graph bug fixes (#105 RULE-2, RULE-6, RULE-7, CG-3) | `claude/bugfix-rules-cg-rest-20261111` | `src/patchtrace/rules/**`, `src/patchtrace/callgraph/**` |
| Instance B 12-hour check (older unmerged slices) | `claude/instance-b-features` | `callgraph/layout.py`, `callgraph/limits.py`, `intelligence/tools/capa.py`, `intelligence/tools/runner.py`, `search/saved.py` |
| Instance C: unified bench and parity fixes (UE-B-03, UE-B-07) | #283 `claude/instance-c-research` | `tools/unified/bench.py`, `tools/unified/parity.py` |
| R7 research prototypes | #282 `consolidate/research-r7-20261104` | `tools/research/r7/**` |

## 3. Slices of this session: state at the stop (all file claims released)

The session was stopped by the owner on 2026-11-11 (section 6). No slice is being worked on any more: every file claim
this ledger made earlier is released. "Verified" names the checks that were run in the session's Linux container; none
of it is Windows, native-tool or live evidence. PR numbers are in section 6.

| Slice | What | State at stop | Where |
|---|---|---|---|
| SEC-A | TB-16: deep JSON fails typed at six non-unified parse sites | built; reviewed twice (one major fixed; second round one of two reviewers finished: approve with a nit) | security PR |
| SEC-B | WP-03, SEC-9 residual, PE-4/5: five storage sanitisers on `hostile_text.is_hostile` | built (2 commits); worker stopped before its report; not reviewed | security PR |
| SEC-C | TB-12, TB-10, TB-15 built; TB-09 not built | 3 of 4 items; not reviewed; TB-09 as an unfinished diff | security PR; `wip/SEC-C-item4-TB-09-jobs.patch` |
| SEC-D | PE-2/PE-3 (Tier W copy), PE-6, PE-7, PE-8 | built; review interrupted | security PR |
| K1 | KBA-06, KBA-08, `kb leads` state text | built; not reviewed | KB/CVE PR |
| K2 | KBA-07, report/2 export of the KB context | built; one reviewer of two finished: approve with one minor finding and nits | KB/CVE PR |
| K3 | KB dock loader fails for every open project (KBB-01, high) | unfinished, untested diff | `wip/K3-kb-dock-owner-thread-snapshot.patch` |
| K4 | `kb index sync --help`, `kb products --all`, KEV state in `pilot leads` and `kb search` | not started (card ready) | `cards/K4.md` |
| K5 | L1 advisory-join runner (mechanics only; no accuracy figure) | built; not reviewed | L1 runner PR |
| NA-1 | rz-diff: refuse ambiguous side ownership (Rizin singleton swap); byte-exact stdout and producer provenance | built; worker stopped before its report; not reviewed | rz-diff PR |
| NA-2 | BinDiff importer row cap, typed post-exit failures, `import-bindiff` exit code | not started (card ready) | `cards/NA-2.md` |
| NA-3 | Diaphora SQLite guard refuses views, triggers, virtual tables | not started (card ready) | `cards/NA-3.md` |
| CLI-0 | SPEC-44 brought up to main | unfinished draft | `wip/CLI-0-spec44-refresh.patch` |
| CLI-A | `patchtrace project` (create, info, runs, import-json, backup, swap, sample) and `patchtrace compare` | built; worker stopped before its report; not reviewed; fake backend only | CLI PR |
| CLI-B | `patchtrace corrections` and `patchtrace review`; contract `corrections-exchange/1` | spec drafted, code unfinished and untested | `wip/CLI-B-corrections-review-code.patch` |
| CLI-C | `patchtrace profile`, `patchtrace doctor` built; `patchtrace runtime` specified, not built | 2 of 3 verbs; not reviewed | CLI PR |
| TR-A | Tests that cannot fail or skip silently; PyYAML for the 39 skipped workflow-contract tests; pytest strict config | 1 of 6 items (the xdist-only test) | test-reliability PR; `cards/TR-A.md` |
| TR-B | Skip ledger tool, live-status honesty, base-ref triage, schema drift `--check` | not started (card ready) | `cards/TR-B.md` |
| GUI-A | Changed-row contrast in light themes (high), untrusted text at display, navigator debounce, worker failure, accessible names | not started (card ready) | `cards/GUI-A.md` |
| GUI-B | Palette list, header tooltips, keyboard header sort, lane start failures, failed-panel rebuild, copy refusal | not started (card ready) | `cards/GUI-B.md` |
| GUI-C | State announcements for the evidence and Search panels | not started (card ready) | `cards/GUI-C.md` |
| INT-1 | Withdrawn advisory claims, untested CSAF validation listed, CVSS consistency warnings, redirect refusal | not started (card ready) | `cards/INT-1.md` |
| INT-2 | Typed CVSS/time errors, ASCII-only CVE id contract, KEV provenance never downgrades | not started (card ready) | `cards/INT-2.md` |
| ST | Status roll-up: inventories, generator, drift test | built (36 tests pass); not reviewed | this branch |

`cards/`, `wip/` and `reports/` are under `docs/plans/production-completion-20261111/`.

## 4. Events

| Time (UTC) | Item | State | Evidence |
|---|---|---|---|
| 2026-11-11 00:40 | Discovery | done | `main` `882d1ca0`; 49 open PRs; 284 remote branches, of which 120 change nothing when merged into `main`, 27 merge cleanly with changes and 137 conflict (`git merge-tree --write-tree origin/main <branch>`) |
| 2026-11-11 00:52 | Baseline suite and Ruff | done | section 1 |
| 2026-11-11 00:53 | Inventory analysts (17, read-only) | running | results will land under `docs/status/` |
| 2026-11-11 01:04 to 01:20 | Inventory analysts | 9 of 17 returned (I1 security backlog, D patch correlation, E GUI, K testing and CI, B native adapters, F CLI and parity, C CVE intelligence, T1 tracker part 1) | results held for `docs/status/`; the other 8 were cut off by an account usage-credit limit and re-queued on other models |
| 2026-11-11 01:12 to 01:21 | Account usage-credit limit | recovered with a model fallback chain | interrupted workers left partial commits in their worktrees; each slice is resumed from them, nothing was pushed |
| 2026-11-11 01:22 | Slices in flight | see section 3 | no code pushed yet; first push follows the first reviewed slice |
| 2026-11-11 01:25 | Stop instruction | received and verified | relayed by the owner's shutdown session; the owner's own message in that session (2026-11-11 01:06 UTC): "stop all workers except the ones working on ghostpay and p2p offramp. the others should finish gracefully and update to github" |
| 2026-11-11 01:27 | Inventory analysts | stopped | 9 of 17 complete: B, C, D, E, F, I1, K, T1, T2 under `docs/status/inventory/`; A, G, H, I2, I3, J, L, R not inventoried |
| 2026-11-11 01:37 | Implementation workers | stopped after a bounded window to reach a commit | section 3; unfinished working-tree diffs saved under `docs/plans/production-completion-20261111/wip/` |
| 2026-11-11 01:38 to 01:46 | Focused verification of every committed slice | done | per-slice results in section 3 of each pull request body and in `docs/status/slices.json` |
| 2026-11-11 01:50 | Full suite on the local union of the six code branches (a throwaway merge, not pushed) | 10 failed, 21,331 passed, 48 skipped, 5 xfailed in 468 s | 2 failures: registry rows missing for the two new CLI spec files (added on the CLI branch afterwards; `tests/test_spec_registry.py` 104 passed). 8 failures: the rz-diff refusal branch (#293), left red and documented there |
| 2026-11-11 01:55 | Branches pushed, draft pull requests opened | done | section 6 |

## 5. Findings handed to other lanes (not fixed here)

| Finding | Where | Owner lane |
|---|---|---|
| TB-16 deep-JSON `RecursionError` sites | `unified/extract/runner.py` (277; audit also 252, 468), `unified/ir/reader.py:264`, `unified/pair_text.py`, `unified/pipeline.py:558`, `unified/sources/secondary.py:95`, `unified/sources/diaphora.py:105` | unified soundness lane |
| TB-16, SEC-10, java probe cwd | `backend.py` (341, 609, 675) | live-gate and SPEC-53 lanes |
| PE-2: relocation directory above one read is reported unreadable | `unified/ir/pe_tables.py` | unified soundness lane |
| `rules propose` always exits 2 because the `BACKEND` seam is never assigned (F-D07) | `rules/cli.py:77, 236-238`, `rules/live.py` | rules bug-fix lane |
| `rules show` prints nothing for an empty result (WP-10) | `rules/cli.py` | rules bug-fix lane |
| Copy of the Calls detail cut on a character, not a byte, boundary | `callgraph/panel_qt.py:704` | call-graph lanes |
| rz-diff refusal changes which stored match sets exist for singleton shapes; the unified engine consumes them | `secondary/rzdiff.py` (slice NA-1) | information for the unified soundness lane |

## 6. State at the stop (2026-11-11, about 01:55 UTC)

Nothing was merged to `main`. No pull request of this session is being watched: CI results on these heads were not
read. Every branch is based on `main` `882d1ca0`.

| Pull request | Branch | Head | Content | State |
|---|---|---|---|---|
| #284 | `claude/sleepy-fermi-y3z4yj` | see GitHub | this ledger, `docs/status/` (inventories, generator, drift test, parity matrix), `docs/plans/production-completion-20261111/` (cards, briefs, reports, unfinished diffs, resume steps) | draft; record branch |
| #290 | `claude/sleepy-fermi-security-1` | `aaffd54a` | SEC-A, SEC-B, SEC-C (3 of 4 items), SEC-D | draft; only SEC-A reviewed |
| #291 | `claude/sleepy-fermi-kbc-1` | `53f5dd26` | K1, K2 | draft; K2 half reviewed |
| #292 | `claude/sleepy-fermi-cli-parity-1` | `74718a3e` | CLI-A (`project`, `compare`), CLI-C (`profile`, `doctor`) | draft; not reviewed |
| #293 | `claude/sleepy-fermi-na-rzdiff-ownership` | `7ac011b1` | NA-1 | draft; not reviewed; RED: 8 existing tests fail |
| #294 | `claude/sleepy-fermi-rq-l1-runner` | `ff53dbbc` | K5 | draft; not reviewed |
| #295 | `claude/sleepy-fermi-test-reliability` | `c70ac0bd` | first item of TR-A | draft; small and self-contained |

Known interactions: #290 and #291 both append tests to `tests/test_kbc_products.py` (keep both blocks when the second
one merges). #293 changes which rz-diff match sets are stored for singleton shapes; the Tier R evaluator and the unified
engine consume them.

Local-only branches that were not pushed because they hold nothing beyond what the pull requests and the patch files
carry: the per-slice branches that were merged into #290, #291 and #292, the union-check merge, and the worktrees of
slices that were never started.

To resume, follow `docs/plans/production-completion-20261111/README.md`.
