# PatchTrace coordinated development — wave three

Date: 2026-11-05. Main remains `5d504ff5`; no main merge or production release. Primary candidate is draft [#205](https://github.com/djshellshoxxx/patchtrace/pull/205), unchanged at `f33e2a0a` while its complete suite runs. Follow-up integration branch: `integrate/swarm-wave3-20261105`, code merge `a84bf6d1`, draft [#218](https://github.com/djshellshoxxx/patchtrace/pull/218). This follow-up is for review, not release qualification.

Previous accounting and full-suite diagnostic history are preserved in [primary checkpoint](archive/20261105-primary-f33e2a0a.md), [wave one](archive/20261105-wave1.md), and [wave two](archive/20261105-wave2.md). PR #205 contains #191–#214 as accounted there; original contributor branches/worktrees remain preserved.

## Published and reviewed changes

- [#215](https://github.com/djshellshoxxx/patchtrace/pull/215), `57f95e09`: isolated #176 preregistration CLI selection. Exact LF protocol identity must match one visible complete QA digest row before corpus access; explicit rehearsal retains unlocked report/key. Original 96 failures/1 pass become 97 passes. Broader training selection:259 passed/1 blocked native-tool skip (overlap); independent review:97 passed. No owner approval/final-evaluation authority is fabricated.
- [#216](https://github.com/djshellshoxxx/patchtrace/pull/216), `7716e2b0`: seeded audit20261107 found raw Windows-version display labels in acquisition metadata. Cleaning/collision warning preserves per-candidate raw hashes and all KB references. Coordinator independently reviewed and ran37 focused tests.
- [#217](https://github.com/djshellshoxxx/patchtrace/pull/217), `f8ed2356`, stacked on #215: remaining #176 report-bound retention/replay and bounded metadata. Foreign-engine output was independently reproduced receiving another provider's score/credit on baseline; repaired path refuses it.239 focused and234 related tests passed (overlap). Independent completion/stat-clock review:44 passed. No actual corpus fit, real labels or production calibration promotion.

All three slices plus reviewed lifecycle [#219](https://github.com/djshellshoxxx/patchtrace/pull/219), `38be184c`, are merged into the follow-up code above. #219 permits lock-only retries through all five real entry checks and preserves committed projects/foreign bytes/persistent locks if acquisition provenance recording fails. It repairs only the crash double signature while retaining actual SIGKILL/recovery assertions. Initial combined acceptance:276 passed in31.34s; expanded lifecycle/KB/calibration integration:475 passed in39.80s (overlap). #219 had228 author-focused and206 independent-focused passes plus second-annotation/interruption preservation probes. Whole-tree Ruff passed. General, calibration, Tier R and report schemas regenerated with no uncommitted drift. Hardlink-capable storage remains necessary for exclusive publication. Managed output cannot receive successful report credit until completion verifies exact bytes; legacy replay remains explicitly warned compatibility.

## Active ownership and dependencies

Runtime supports root plus three concurrent workers, so requested logical swarms execute in waves.

| Owner / subsystem | Status | Current action / dependency |
|---|---|---|
| Coordinator / exact-head QA and integration | INTEGRATING | Frozen f33e2a0a complete suite; source-bound dedicated venv; publish reviewed follow-ups |
| kb_workflow_wave2 / GUI, persistence and acquisition lifecycle | COMPLETE for #219 | Exact38be184c reviewed, published and integrated; real retry and retained-data failure paths validated |
| lifecycle_review_wave3 / independent lifecycle review | COMPLETE for #219 | Exact38be184c approved; independent206 tests plus two preservation probes passed (earlier213 selection overlaps) |
| kb_product_start_wave3 / next KB journey | READY / inspecting contract | Isolated worktree, bounded product-only desktop start using existing services; interface proposal required |
| native_gt_wave3 / next adapter slice | READY / inspecting unique source | Select remaining #174 GT-01/normalizer/fuzz functionality; build tooling owned separately |
| unified_gate_wave2 / pinned native provisioning | INTEGRATING | Exact approved Rizin source fetched/hash checked; isolated Meson/Ninja; actual generated-header oracle compiles; stock native build underway, default PCRE2 link failure retained and supported system-PCRE2 configuration selected |
| random_audit_wave2 / seeded audit and prereg review | COMPLETE for published slice | #216 published and reviewed; #215 reviewed; subsequent turn hit transient API TPM limit, no cost/cache totals inferred |

Native worker independently reviewed #217 while compilation ran. No target binary has been executed, no quarantine removed, no production binary dependency introduced, and no competing API automation enabled.

## Exact-head complete-suite gate — running, not passed

Fresh unsplit command against f33e2a0a:

`env -u PYTEST_ADDOPTS QT_QPA_PLATFORM=offscreen PATCHTRACE_RIZIN_SIMILARITY=/tmp/pt-rizin-similarity.c /tmp/pt-qualified-final-venv/bin/python -m pytest -q`

Ordinary editable install and isolated `python -I` both resolve `/workspaces/patchtrace/src/patchtrace`. Root working tree stays unchanged during this run. Collected19791 nodes. Log `/tmp/pt-205-f33-full.log`; eventual exit receipt `/tmp/pt-205-f33-full.exit`; tool session56905. No final result exists at this checkpoint. One early failure reproduced independently: crash-test double `park(*args)` rejects new `created=` ownership keyword before its intended SIGKILL checkpoint. #219 repairs only the signature, preserving actual kill/recovery assertions; its focused integrated recovery checks pass. Frozen f33 still contains the old double, so its eventual result cannot be green for this known reason. Do not add prior partial/overlapping counts as full qualification.

## Gates and remaining accepted work

- Sonar fresh #205 scan retains three independently reviewed findings (operator condition, deterministic synthetic PRNG, explicit native evidence CLI output path). Prior parser/source-identity findings are absent. Normal authorized project disposition remains required; no scanner bypass or review credential is available.
- Current-head Linux/Windows/Qt/native/package CI remains queued/pending. Branch-protection API returns403, so requirements are not assumed absent. Older #198 Windows QA completed18701 passes/81 skips/6 xfails and only three invalid-workflow-fragment failures already repaired by #204; this is historical evidence, not current-head Windows qualification.
- Unified remains opt-in disabled pending G-U1..G-U8, real precision/native/Windows acceptance. KB online/product-only/binary-only desktop paths and original/derived .bin label preservation remain PARTIAL.
- Native API header compilation is actual pinned-header evidence, not a linked/live producer pass. Full pinned API/CLI/inventory/IO controls and unchanged quarantine remain open.
- Release/offline payload, clean disconnected Windows, frozen application, high-DPI/accessibility and required scanner/review gates remain open. Linux cannot qualify Windows packaging.
- Persistence still assumes cooperative locks; final pathname races are not claimed solved. Current GUI work must never unlink the persistent lock or recursively discard committed project data.
- Historical GT-01/normalizer/fuzz and research/spec branches require selective reconciliation. #176 prereg/replay slices are now accounted separately from prior KB/artifact/GUI integrations.

## Next executable actions

1. Collect complete f33 result and preserve full log/exit; diagnose any further failures without weakening assertions. Requalify the resulting updated candidate, rather than calling baseline evidence final-head acceptance.
2. #219 is now reviewed/published/integrated with475 combined passes. Continue bounded product-only and unique native slices with exclusive ownership and independent review.
3. Complete feasible actual pinned-native controls and retain exact versions/build identity/raw logs; record unavailable gates as BLOCKED, never passed.
4. Publish follow-up integration checkpoints promptly and update #205 after safe source/test reconciliation. Main merge requires exact-head checks, scanner disposition and normal reviews; no release authorized.

API usage/cost/cache telemetry is unavailable. All stated test counts overlap where noted and are never summed into unique coverage.
