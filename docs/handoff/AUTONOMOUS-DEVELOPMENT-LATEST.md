# PatchTrace coordinated development — latest verified checkpoint

Date:2026-11-05. Primary review candidate: `integrate/swarm-qualified-20261105`, draft [#205](https://github.com/djshellshoxxx/patchtrace/pull/205). Main remains `5d504ff5`; no main merge or release. Follow-up [#213](https://github.com/djshellshoxxx/patchtrace/pull/213) and current-project [#214](https://github.com/djshellshoxxx/patchtrace/pull/214) were integrated into this candidate; integration-branch ancestry is distinct from main/release acceptance.

[Wave1](archive/20261105-wave1.md) and [wave2](archive/20261105-wave2.md) preserve prior inventories, all source commit receipts and diagnostic history. This document supersedes their current-status sections, not their evidence. All worker code is committed/published; workers are idle. No competing paid automation was enabled.

## Consolidated source and dependency accounting

The candidate includes #191–#199 once, plus #200cache integrity, #201offline investigation, #202verified recovery copies, #203component-support test/spec correction, #204invalid workflow-fragment relocation, #206native input ownership, #207streamed recovery, #208actual unprovisioned-native diagnostics, #209strict release-pin parsing, #210attempt-owned creation rollback, #211linear parity parsing/unchanged-runtime fixture escaping, #212SHA256 source binding/checkout containment, and #214verified current-project inputs. #213 is the collected follow-up integration.

The cumulative #180→#185→#188→#192 stack entered only through #192. It includes report2 and PE signing beyond matching. Preserve original source PRs until full accounting and normal gates; source #174 GT-01/normalizer/fuzz and #176 calibration/replay still have unintegrated work. Historical research #178/#179/#183/#187 is preserved rather than assumed fully merged.

| Subsystem | Status | Verified change | Remaining acceptance / next action |
|---|---|---|---|
| KB/CVE→product→binary investigation | PARTIAL | Offline import/search/explicit product/manual pair preview/create/adopt; current-project verified copies; stale and hash guards | Product-only/binary-only desktop starts, online wizard, live-source qualification; original/derived .bin labels explicitly unsupported by current-pair route |
| Unified matching/evidence/manual corrections | INTEGRATING | Cumulative hardening, option-aware consumers, correction completeness, deterministic support/contradictions | Exact final full/native/Windows gates; G-U1..G-U8 and real precision/calibration gates remain open; opt-in stays off |
| GUI/workspace | PARTIAL | Transactional adoption, stale inspection guard, real KB/current-project journey, tooltip/import boundaries | Native/frozen/high-DPI/accessibility/clean Windows journeys; lock-only-directory wizard retry remains open |
| Persistence/input/security | PARTIAL | Block-verified byte reads; strict cache/pin JSON; exclusive input ownership; bounded recovery; attempt-owned rollback | Rollback assumes cooperative writer lock and retains final pathname race; exclusive artifact publication requires hardlink-capable storage |
| Native adapters/research producer | PARTIAL | Ownership/callback/red controls, preserved evidence, stronger source identity and checkout boundary | Actual pinned-native API/CLI/inventory/IO controls; local headers/libraries/Meson/Ninja unprovisioned, not an unavoidable external blocker; quarantine unchanged |
| QA/CI | INTEGRATING | Real fragment error fixed; focused negative/lifecycle controls; standalone/isolated Python bound correctly in dedicated venvs | Complete single-head full suite, required current-head Linux/Windows/Qt/native/package checks and authorized scanner dispositions |
| Documentation/research | READY for review | Current status consolidated, two historical checkpoints archived, CLI help/specs and evidence retained, stale TOFU instruction corrected | Remaining research/spec branches still need selective reconciliation; no speculative implementation claims |
| Windows/offline release | PARTIAL | Existing beta.751 downloadable; packaging infrastructure retained, strict pin gates improved | Actual relocatable offline payload/disconnected qualification, clean Windows/manual acceptance and release gates; no production release authorized |

## Completed validation (counts overlap)

- Core integrated selection:213passed. Unified/UI/byte/pilot integration:171passed. KB/tooltips/cache:50passed. Recovery/fusion:12passed. CI/tracker:53passed/3existingxfails.
- Independent cumulative unified review:978passed/1Windows-native skip/1old strictxfail. #203 corrected that test's invalid support-vs-corroboration expectation;153focused tests passed, production matching unchanged.
- Integrated follow-ups:649passed/1Windows-onlyskip in70.75s. After current-project journey merge:219passed in78.40s. Independent current-project review:20passed/136deselected; earlier workflow review25passed.
- All source slices passed whole-tree Ruff in their worktrees. Schemas regenerated from candidate source with no drift. Source files/tests/tools/workflows in the final candidate are byte-identical to reviewed/tested follow-up head `c6691ab1` before documentation-only native receipts and checkpoint updates. Do not add overlapping counts as unique coverage.

## Whole-suite status — NOT COMPLETE

Frozen baseline `a33a4405`: first attempt422passed/1environment failure because shared editable CLI differed. Candidate-scoped smoke passed. Source-scoped retry interrupted422passed; isolated Python still resolved global editable source. Dedicated `/tmp/pt-swarm-venv` was installed against `/tmp/pt-swarm2`, with ordinary and -I binding verified.

Dedicated whole-suite attempt:7351passed/13skipped/4existingxfails/1failure in782.08s. It found the omitted named-Qt-adapter import entry; reviewed repair226ac7e5 added precise allowances and seven negative purity controls (159related/44independent passes), preserving all service/UI database/network restrictions.

Remaining-node diagnosis then2096passed/10skipped/1harness failure: inherited coordinator PYTEST_ADDOPTS fail-fast truncated an intentionally failing child pytest. Outer diagnostic flags moved to arguments; no consent guard or assertion changed. A continuation reached88% progress then exited143/SIGTERM without summary; cause not established and no pass inferred. Final overlapping1600-node tail completed1573passed/27skipped/18117deselected in156.89s. These segments are NOT a fresh unsplit full-suite pass, and apply to older snapshot `a60d1dbc`, not the later production follow-ups/current-project feature.

Retained logs: `/tmp/pt-swarm-full.log`, `pt-swarm-full-source.log`, `pt-swarm-full-venv.log`, `pt-swarm-remaining.log`, `pt-swarm-remaining-network.log`, `pt-swarm-final-tail.log`, `pt-followups-focused.log`, `pt-current-integrated.log`. Last-node debug file: `/tmp/pt-diagnostic-last-node.txt`. No local pytest process intentionally remains running.

## Scanner and release boundaries

Sonar205 previously failed main-relative security/reliability ratings. #211/#212 address actual parser/source-boundary findings. Independent operator-counterexample, deterministic synthetic-benchmark and explicit exclusive-output triage is in [scanner receipt](../qa/sonar-205-triage-20261105.md). No suppression, issue status or quality gate was bypassed; no Sonar review credential is configured. #213's earlier green scan was relative to its stacked base, not final main-relative qualification.

Native skips are BLOCKED/NOT RUN, never passed native evidence. #208 retains raw failed compile/package probes, and no native executable ran there. Linux cannot build/qualify Windows standalone; official complete offline bundle remains unqualified. API cost/token/cache-hit telemetry is unavailable and none is invented.

## Restart actions

1. Refresh exact heads, required checks/reviews and branch ownership; main-protection API returned403, so do not infer requirements absent. Inspect final #205 main-relative scanner/CI; never bypass pending/failed gates.
2. Run a fresh complete final-candidate suite in a dedicated source-bound environment, with outer fail-fast options as CLI arguments, not inherited PYTEST_ADDOPTS. If local execution ends, preserve logs and report incomplete; use validated CI/sharding without changing assertions or claiming partial segments as full acceptance.
3. Requalify Windows/native/package and clean-machine/manual gates. Apply normal authorized Sonar project review if remaining false-positive dispositions require it.
4. Merge main only after exact-head required gates/review pass. Then account/close superseded source PRs with preserved commit references; do not blindly merge cumulative stacks.
5. Continue remaining GT-01/calibration/replay and unsupported desktop-start/label-preservation/lock-only retry work. Current-project provenance is preview-only; persisted manual pair hashes remain authoritative and never prove CVE repair.
