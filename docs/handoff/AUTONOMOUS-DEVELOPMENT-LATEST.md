# PatchTrace coordinated swarm checkpoint — 2026-11-05

This is the current coordination record. [Wave-one history](archive/20261105-wave1.md) preserves the earlier recovery, published commits, failures and restart notes without presenting historical worker activity as current.

## Recovery and dependencies

Main remains `5d504ff5`. Existing worktrees, branches and clean working trees were preserved. PRs #191–#199 remain open; source heads match the prior checkpoint. #199 (`e5f9302e`) is required to repair the reproduced verified-byte integrity failure. Its general/Windows checks are pending, not passing. No merges to main, source-PR closures, production releases or competing automation were performed. Branch-protection inspection returns HTTP403, so review requirements cannot be inferred from its absence.

## Current ownership

Runtime supports four concurrent agents including coordinator; roles run in waves.

| Role | Worktree / branch | Exclusive implementation scope | Status |
|---|---|---|---|
| Coordinator / integration, QA, documentation | `/tmp/pt-swarm2`, `integrate/swarm-qualified-20261105` | Integration conflict resolutions, shared specs/schemas, handoff and acceptance record | INTEGRATING |
| A4/C3 offline investigation | `/tmp/pt-investigation2`, `integrate/kb-investigation-20261105` | KB service/dialog/wiring, minimal revision guard and real host hook | PUBLISHED #201; expected_revision guard tested and independently reviewed |
| B5 unified independent verification | `/tmp/pt-unified2`, `integrate/unified-qualified-20261105` | Unified/pilot/report2 focused acceptance; no source edits yet | VERIFIED cumulative stack:978passed/1skip/1oldxfail; #203 corrects that test expectation |
| E4 random audit / independent review | `/tmp/pt-audit2`, `audit/random-boundaries-20261105` | Seeded offline_bundle/enrichment.cache/pe_overview audit; candidate read-only review | PUBLISHED #200/#202; independent integration/KB reviews complete |

## Verified integration work

Candidate combines #194 QA, #199 byte verification, #191 rules/callgraph, #193 KB fixtures/selection, #196 inspection guard, #198 transactional adoption, #197 input preparation, #195 native research controls, and #200 cache fixes. It is a review candidate, not a qualified release. Merge conflicts only involved append-only QA/todo/spec/module records; both sides were retained. UI #196/#198 coexist in distinct methods. Independent source-identity scan confirmed exact source retention for the eight earlier slices. Initial integrated focused selection: **213 passed** in69.76s; whole-tree Ruff passed.

#200 `802b5b1b`: seeded audit(20261105) selected offline_bundle, enrichment.cache and pe_overview from a recorded17-module pool. Two confirmed cache defects: duplicate manifest keys accepted, and >1MiB manifest admission inconsistent with the reader cap. Three original regressions failed before repairs; **173 selected-module tests passed**, Ruff passed. No defect or security qualification claimed for other inspected modules. Coordinator independently reviewed patch and regression tests with no blocker.

## Acceptance and publication

Prior full run stopped on the actual byte-integrity failure:776passed/1skipped/1failed, NOT COMPLETE. #199's580focused passes/1Windows-only skip are not a full-suite result. A fresh combined full suite will run on a frozen integrated candidate after focused dependency checks. Full Windows/native checks remain independent gates. Mocked/compiled-helper controls are not pinned-native acceptance; Rizin quarantine remains.

#192 is cumulative on #188, with report2 and PE signing beyond unified matching. Never merge #180/#185/#188/#192 as independent implementations. KB #176 remaining investigation is now being isolated; calibration/replay portions remain separate. Original PRs must stay open until full accounting/checks/review.

## Next executable actions

1. Finish focused unified and KB GUI/service checks; integrate compatible source once, regenerate schemas if contracts change, and freeze candidate.
2. Run full offscreen pytest and whole-tree Ruff; diagnose actual failures without reducing assertions.
3. Publish candidate immediately after meaningful focused milestone, and inspect current-head CI before any main merge.
4. Continue native GT-01, persistence, offline packaging and remaining calibration work in later waves. Windows builds run only on Windows; actual disconnected bundle and clean Windows GUI acceptance remain open.

API token/cost/cache-hit telemetry is unavailable; no usage or enforced cap is invented.

## Frozen combined qualification candidate

Code freeze after `dfdc1018`: #191–#199, #200cache, #201offlineKB desktop, #202verified recovery copies, #203spec/test correction, and CI fragment repair `1229ca3b`. Main unchanged. Original branches preserved. Final integrated checks:213core passes,171unified/UI/byte/pilot passes,50KB/tooltips/cache passes,12fusion/recovery passes,53workflow/tracker passes+3existingxfails. Counts overlap. WholeRuff passed; `PYTHONPATH=src python tools/generate_schemas.py` regenerated from the candidate with no drift.

Merged unified fixture conflict keeps shared private_tempdir for both cleanup checks and compares the exact private directory contents, preserving source assertions. Source ledger modifications (including completed implementation rows but open release gates) and all independently appended evidence retained. Independent 124-test candidate review found no blockers before the later independently reviewed slices.

GitHub191UbuntuQA actual result:18743passed/47skipped/7xfails and3failures, all invalid openai-agents workflow fragment. Local red3fail/48pass/3xfail; relocation preserves exact fragment bytes as reference outside executable workflow discovery; final49pass/3xfail. #186 runnable automation proposal remains separate and inactive. No additional paid runner enabled.

Fresh full suite starts on the resulting freeze commit with `QT_QPA_PLATFORM=offscreen python -m pytest -q`, plus `PYTEST_ADDOPTS=--maxfail=1` for immediate diagnosis if any test fails. This selects the entire suite; no skips/assertions are changed. Result pending until logged. Cross-OS/native/package gates remain pending.

Supporting subsequent waves remain isolated from frozen source: nativeinput descriptor race and streamed corruptseries recovery followups. Their focused results cannot qualify this candidate until deliberately integrated and retested.
