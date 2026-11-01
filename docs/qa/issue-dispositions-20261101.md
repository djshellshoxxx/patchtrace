# Issue audit reconciliation — November 1 UTC

Source inspected: integrated candidate `f8b2bbbde0548eda3007a047e07bec92401429eb`; later `be598be91f177c743e8901f8c4d76acb09d425c9` changes only frozen-KB journey surfaces, leaving the identity/security findings below unchanged. These are candidate dispositions, not acceptance or issue closure. All five GitHub issues remain open. No thread or issue was changed. Remote active-worker/task tooling is unavailable; activity outside explicit local reservations is **unknown**.

## Retrieval completeness

| Issue | Body fetched | Comments fetched / reported | Evidence |
|---|---|---|---|
| #105 | yes | 35 / 35 | `issue-105-20261101.json` |
| #116 | yes | 1 / 1 | `issue-116-20261101.json` |
| #118 | yes | 1 / 1 | `issue-118-20261101.json` |
| #120 | yes | 0 / 0 | `issue-120-20261101.json` |
| #121 | yes | 0 / 0 | `issue-121-20261101.json` |

The connector's issue-comment endpoint advertises all pages; returned counts equal each issue's reported comment count. Full original prose, author and comment IDs are retained without duplicate HTML.

## Source-backed finding dispositions

| Issue / finding | Current disposition | Source evidence and next action |
|---|---|---|
| #105 KEV-1..3, ACQ-1..4 | Fix source/regressions incorporated; no new acceptance claimed | Main includes #107; `test_kev_bugfixes_20261029.py` and `test_acquisition_hostile_20261029.py` name these cases. The lone-surrogate integration repair is separately retained by #124. |
| #105 STR-1..4, PE-1..3, CODE-1 | Fix source/regressions incorporated; no fresh full reproduction | `test_binary_parsers_bugfixes_20261029.py` covers duplicate strings, scaling, invalid text, chunked directories, RVA zero, section crossing and long block comments; `test_core_review_regressions_20261029.py` covers later duplicate-work/PE-chunk repairs. PE-1 peak-RSS note remains distinct. |
| #105 KBC-1..11 and KBC-13 | Fix source/regressions incorporated; no issue closure | `test_kbc_bugfixes_20261029.py` names each boundary and the scope-count regression. Source inclusion does not certify current Windows/live-provider behavior. |
| #105 KBC-12; PE-1 memory note | Still requires decision/measurement | Superseded-document `not_observed` semantics were explicitly possibly by design; no new owner decision found. Large relocation memory remains unmeasured here. |
| #105 Round-2 RULE/CG findings | Preserve individual reconciliation, do not mark wholesale fixed | `rules/matrix.py` still scores cached cells positionally; `rules/window.py` bounds equal-pair work rather than all comparison work. #146 is a separate candidate for matrix/version/FIFO defects, not proof every Round-2 item is accepted. Current CG/export and remaining rules cases were not exhaustively reproduced in this pass. |
| #116 P1 false save/note feedback | Incorporated fix, candidate acceptance pending | `ui.py:save_note` clears only after `commit_and_report`; `ui_persistence.py` reports success only after writer returns. Historical comment describes #119 as unmerged, superseded by later #124 incorporation. |
| #116 P2 profile changes lost on selection | Source-present, not freshly reproduced | `ProfilesPanel._show_current` calls `_fill` and overwrites `_baseline`; selection handler does not consult dirty state. Reserve GUI ownership before repair. |
| #116 P2 abandoned creation root | Requires targeted re-audit | Current create/import changes touch transaction behavior; avoid claiming either fixed or reproducible from historical source. Active cancellation/import owner reservation applies. |
| #116 P2 export privacy wording | Source-present UI promise mismatch | Export policy still says absolute paths are redacted; report verbatim evidence deliberately preserves paths. Root owns export integration; clarify wording without silently changing evidence fidelity. |
| #116 P3 stale inspection failure | Source-present, deterministic signal repro still needed | `_inspection_failed` writes error/status/log without comparing supplied key with current project key, unlike success. Independent queued-signal regression is an available GUI follow-up. |
| #118 P1 finite search scope widens downstream | Source-present, direct reproduction pending | `_lead_cves` loads stored coverages but calls `lookup_kb` without their `scope`; `_lead_cards` and `_lead_kbs` likewise query cached corpus. New offline journey does not alone establish scope preservation. |
| #118 P1 scope architecture mismatch | Incorporated fix; current pair gates separately retained | #124 incorporates #122 architecture-scope repair; #148 additionally binds captured scope/revision/file bytes. Native acceptance stays independent. |
| #118 P1 card/source-document mismatch | Source-present, direct provenance reproduction pending | `ReverseIndex._lookup` filters edges by product but chooses cards from every active picked document; `_lead_cards` pairs `cards[:1]` with first edge ref. Reserve KB service/index/contracts before repair. |
| #118 P2 acquisition pair identity | Candidate repair included, not accepted by inclusion | #148 binds selected pair scope/revision/bytes and conservative provenance; root's export/import integration and exact-head checks determine adoption. |
| #118 hostile Winbindex entry | Incorporated regression repair | Named `test_acq2_a_lone_surrogate_skips_one_entry_instead_of_failing_the_record`; historical #110 failure is not automatically current. |
| #120 P1 1:1 ambiguous manual correction | **Directly reproduced remaining defect** | `reproduce-issue120-20261101.py/.json`: ManualAdapter→arbiter produces `matched`, `mapped=true` for declared `ambiguous`. Pure synthetic boundary, not full GUI/service run. Assigned to identity worker. |
| #120 P1 manual result identity | **Directly reproduced remaining defect** | Same planned result ID with different manual references and emitted names/atoms. Assigned identity worker; complete content binding and versioned invalidation required. |
| #120 P2 secondary normalized identity | **Directly reproduced remaining defect** | Same planned result ID/raw SHA/current entry with different valid normalized match rows and atoms. Assigned identity worker; preserve upstream raw hash independently. |
| #120 P2 alternative validation | **Directly reproduced remaining defect** | Bindiff set accepts rz-diff candidate with bindiff source and unrelated anchor. Assigned identity worker; validate source/engine/version/anchor consistently. |
| #120 P2 artifact preparation cancellation/deadline | Source-present, not newly timed | Scheduler's private preparation copy uses verified input helper without cancellation/deadline checks. Preserve integrity when adding bounds; not part of identity worker reservation. |
| #121 P1 release dependencies | Partly repaired; native aggregate acceptance open | `qa-windows.yml` release now needs `qt-gate`; separate exact-SHA native/G-U aggregate is still not a release dependency. Do not restate the old Qt omission as current. |
| #121 P1 backup cache | Confirmed source gap; repair assigned | `verified_backup._fingerprint` is `(size,mtime_ns)` and destructive prune uses cached facts. Worker `receipt_fix` owns `wt-backup`; byte verification before destruction and meaningful corruption regression pending. |
| #121 P2 default inherited environment | Source-present / intentional H7 acceptance dependency | `BackendConfig.restrict_env=False`; default flip awaits recorded Windows prerequisite. Evaluate actual approved H7/native evidence before changing policy. No exfiltration claim. |
| #121 P2 Diaphora sliding deadline / memory | Deadline repair assigned; memory separate | `Snapshot.rows` resets each row. `cancel_fix` owns `wt-deadline`, bounded per-query consumption deadline per clarified contract; independent operations may receive new budgets. Memory-capped worker/aggregate RSS remains separate and unverified. |
| #121 P2 Windows artifact-change detection | Documented residual risk still present | `artifact_bytes._stat_key` uses Windows creation time; NTFS change-time helper reuse requires Windows regression. POSIX behavior does not establish Windows fix. |
| #121 P2 native seeded setup evidence | Partly repaired / historical suppression nuance | Workflow first calls deterministic `seed_symbol_cache.py`; subsequent upstream command still clears LASTEXITCODE for intended negative reproduction. Inspect actual seed verification and variants before claiming native acceptance bypass. |
| #121 P2 dependency/toolchain pin completeness | Source-present planning/acceptance gap | Floating dev/build ranges and mutable runner labels remain. No reproducibility/SBOM claim established here. |
| #121 P2 primary process resource caps | Source-present policy gap | Primary backend omits optional memory/output-total caps; realistic native budget selection and failure-preservation tests still needed. |
| #121 P3 four old QA failures | Historical failures superseded by incorporated repairs | Preserve old run as failed. #124 and later candidate checks have different exact SHAs and cannot be substituted silently. |
| #121 P3 ambiguous-candidate iterator work | Source-present, retained-memory-only bound | `NavResult.ambiguous` stores first 20 but exhausts iterable for exact count. Bounded producer contract or total traversal budget requires explicit design; no new exploit claim. |

## Original 41 PRs: collection snapshot

`original41-pr-collections-20261101.json` covers all 41 original PRs, their recorded immutable fetched source SHAs, **9 review submissions**, **10 review threads** and **79 PR-triggered workflow runs**. `original41-pr-workflow-jobs-first-pages-20261101.json` contains **566 child-job summaries** from those 79 run collections. All collection calls returned successfully.

All ten inline threads returned belong to #128: **8 resolved, 2 unresolved** (`PRRT_kwDOVEPRFc6yLs2o`, `PRRT_kwDOVEPRFc6yLs2w`). Resolution is a GitHub observation, not proof the parent or any repair is accepted. #145/#150 receipts are separate candidates; no unresolved thread was changed by this audit.

Coverage limit: combined-status is legacy status contexts, not the GitHub Checks API. Workflow collection is PR-event **first page only**, jobs are latest-attempt **first page only**, and these tools expose no pagination cursor. Review collections expose no pagination arguments; their returned collections are preserved without asserting broader hidden-page completeness. Push/dispatch/native denominators, logs, artifacts and omitted check-runs are not certified by these summaries. Exact-head acceptance remains the integration reviewer's responsibility.

The 100 registry rows were retained earlier; this issue pass is not an exhaustive audit of all accepted requirements, GUI behavior or native compatibility. No DONE/closure inference follows from included source or green workflow parents.
