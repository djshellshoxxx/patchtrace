# Essential PatchTrace integration ledger

This is the coordinator's live delivery record, started 2026-10-29 UTC (October 28 in Vancouver). The owner-authorized scope is reconciliation, unified comparison, KB/CVE/product/binary investigation, adapters, persistence/enrichment, acquisition and their essential GUI. AI interpretation, teaching, DiE/YARA expansion and speculative analysis remain deferred.

## Baselines and ownership

- Initial main: `241a7773dea1d887dfd512adc3225037677a981a`.
- Richest existing implementation: PR #64, `2fa113889d1ffee6b68496993d3b3b6ebb0ba035`. Its source was integrated with current main; the original author branch was not overwritten.
- Designated branch: `codex/essential-integration-20261029`; one coordinator integrates and publishes. Workers use isolated worktrees and do not push.
- Main advanced to `94bd6a41ca309d7110e077c3a3d7a6fca07bdaf2` after independently reviewed PR #106 passed its exact-head Linux/Windows QA, packaging and native workflows and was merged. #76/#80 history is preserved.
- GUI owns `ui.py`, tooltips and Qt panels; unified owns its store/pipeline; KB owns correlation/source adapters; adapters own secondary services; ingestion owns backend/ingestion; independent QA reviews the combined work. Coordinator owns shared indexes and delivery ledgers.

## Reconciliation decisions

| Source | Disposition | Reason |
|---|---|---|
| #64 | Integrated candidate, awaiting combined gates | Broad GUI, extraction, unified, adapter and evidence work |
| #106 / #76 / #80 | Merged into main | Bounded Java probe retry and regression coverage |
| #107 | Integrated candidate | KEV and acquisition hostile-input fixes |
| #108 | Integrated with corrections | Fixed quadratic duplicate-string joins; retained existing complete PE chunk loop and added nonzero-tail coverage |
| #109 | Integrated with corrections | Added UTC overflow protection and explicit ambiguous-pair selection |
| #103 | Integrated with compatibility reconciliation | Preserved existing KEV lookup/anchor contracts while adding real local catalog metadata |
| #101 | Integrated | PatchWatch reuse research and roadmap |
| #83 / #88 / #89 | Integrated candidate | Unknown-callee abstention, strict worker JSON, persisted EXTERNAL limitations |
| #86 | Selectively integrated | Retained cache identity/deep validation; avoided duplicate decompile writer and preserved failed records |
| #67 | Selective essential integration underway | Immutable inputs and isolated launch, preserving current local-symbol launcher |
| #102 | Selective report preservation | Added verified prior-report backups; did not import PR policy that skips Windows PR QA |
| #100 | Existing relevant work retained | Local symbols already present in #64; no new Diaphora expansion |
| #71 / #90 | Superseded | Corrected fixtures already present in #64 |
| #69 / #72 | Review queue | Useful fixtures/specs need current-contract reconciliation |
| #78 / #79 / #82 / #85 | Deferred pending essential calibration need | Overlap; #78 duplicates sort path; #82 stronger planner, #79 distinct A/A failure guard |
| #94 | Measurement required | Timing harness retry does not establish actual performance |

## Verification and limitations

Declared `dev,search,rules` extras are installed. Initial-main full Linux baseline (`pytest -q -n 4 --dist loadfile`): **15,688 passed, 104 skipped, 4 xfailed, 3 failed**. Failures were missing optional modules in subprocesses that resolve the venv interpreter to system Python (yara-x and protobuf), and the executor forbidding AF_UNIX socket creation. The missing wheels were subsequently installed into the Python user site. The AF_UNIX platform restriction is not a product defect and its test has not been removed or weakened.

Focused worker suites and full combined runs are recorded in the final continuation entry below. Mocked engine tests do not establish native compatibility. Native Windows acceptance and exact published-head CI remain mandatory before merging the broad integration. The runtime has working source reads and dependency downloads; Git CLI push has no credential, so publication uses the authorized GitHub connector with exact tree verification.

## Active essential gaps

- Automatic ProgramIR extraction and one-comparison secondary orchestration are being wired; existing extraction functions alone do not establish application completion.
- The real MSRC JSON dialect was absent; official monthly advisory capture established its shape and is guiding the adapter implementation.
- Existing KB panel attempted to reopen a GUI-locked project; immutable capture/render seams are being implemented.
- Offline investigation and explicit pair preview/creation must be exposed in the GUI, with cancellation and no target execution.
- Fresh native BinDiff, rz-diff, Ghidra and Windows evidence must be recorded independently of unit tests.
- Every feature must distinguish implemented, integrated, automated-tested, native-verified, GUI-exposed and merged-to-main states. No overall completion percentage is inferred from file counts.


## 2026-10-30 reconciliation correction

The earlier #67 row was an intention, not a complete integration: private verified input copies, isolated external launches/probes, preview-bound consent and import/diagnostic/PE guards were absent at #123. These are now selectively ported with regressions in the consolidation candidate. Known-client product identity and unified failed-refresh preservation are also repaired. #69 and #72 remain proposed fixture/spec work pending current-contract reconciliation, not silently merged. #102 author work remains preserved; essential parser/checksum changes are selected without its Windows PR-QA restructuring. See `docs/audits/20261030-consolidation-review.md` and the 2026-10-30 QA/todo entries for exact evidence and pending gates.

## 2026-10-31 essential project-safety continuation

Coordinator root; main still `a04f5a2`. PR147 Windows QA failed only on SVG CRLF mismatch; Linux QA (18,446 passed), repeated Qt and all five native Ghidriff jobs passed. Windows packaging never ran. LF checkout repair is independently reproduced and passes 64 unchanged tests; published to PR147 as `50ced35`. Sonar C security rating remains uninspected; do not merge or suppress it. Active PR143/144/146 retained and not duplicated. Source baseline for the separate essential candidate: main `a04f5a2`, branch `codex/essential-project-safety-20261031`; existing copied-interpreter venv and prior main QA are baseline evidence, not new acceptance.

| ID | Outcome/scope/exclusions | Owner/files/workspace | Dependencies/contracts | Required verification | Status/handoff |
|---|---|---|---|---|---|
| PT-EXPORT-GUARD | Prevent report export replacing current project/evidence; preserve external/export-folder reports; exclude report redesign | export worker: service.py/reports.py/ui.py + focused tests; `/workspace/work/patchtrace-export-guard` branch `codex/export-guard-worker-20261031` | Architecture report-destination amendment; service owns root; no wire changes | Red repro against real sample DB/artifacts/raw, refusal side effects/reopen, alias cases, UI integration, existing report tests | IN_PROGRESS; DB overwrite reproduced; independent review requested |
| PT-KB-SCOPE | Bind acquisition to previewed product/revision; exclude GUI expansion and semantic engine work | KB worker: kbcorrelation/service.py + acquisition tests; `/workspace/work/patchtrace-kb-scope`, branch `codex/kb-scope-worker-20261031` | KB workflow amendment; existing consent/lock/history; no lineage promotion | Reproduce AMD64 attachment to ARM64 scope; fresh/unselected/changed selection/stale revision cases; preserved consent and existing acquisition tests | IN_PROGRESS; architecture/scope and concurrent-stage regressions reproduced |
| PT-SAFETY-INTEGRATE | Review both fixes, consolidate and verify | root; shared docs/index/task/QA; essential candidate branch | Both reviewed worker commits | Independent review, full offscreen pytest + Ruff, exact candidate CI; preserve host failures, no unverified merge | READY |

Order: root contracts/index -> isolated red-first workers in parallel -> independent cross-review -> integrate -> complete suite and publish passing source or explicit draft with blockers. Current Linux workspace/venv and three committed worker checkouts retained by root; no paid resource provision. The offline backend payload remains a separate gate; no scope expansion.

PT-KB-SCOPE `0c6df55` independently passed 30 acquire tests and is integrated; 910 worker KB tests passed (fake transports, not live provider evidence). New task PT-KB-GUI, owner GUI worker, workspace `/workspace/work/patchtrace-kb-gui` branch `codex/kb-gui-worker-20261031`: implement indexed offline InvestigationDialog/helper/tests only; root owns ui.py menu/adoption seam. Depends on scope repair and additive import_pair expected_revision contract. Excludes network/acquisition UI, optionalpanel redesign and actualtarget execution. Acceptance: offscreen import/search/explicitscope/preview/new-project/reopen journey, stale preview refusal and cancellation/parent-project preservation, no Qt backend import, existingtooltips tests. Status READY; execute against amended KB workflow spec, root verifies integrated full suite/native gaps.

2026-10-31 integration checkpoint: scope fixes integrated as fc5424e/bf2bbf5/108a9b0; export as265de1c/32c7d51; GUI ascb48070/e660688 and root627b463; new frozen smoke initializer e2727e6. Independent review found/fixed source overwrite, unbounded traversal, noncommitted export, new-only creation race, deferred-close failures and adoption rollback. Product implementation reviewed, acceptance not DONE. PT-EXPORT-GUARD/PT-KB-SCOPE/PT-KB-GUI now IN_REVIEW pending combined acceptance; PT-SAFETY-INTEGRATE INTEGRATING. Authoritative focused counts and environment setup are in the new QA case. Next: freeze complete source, full offscreen suite under validated non-Git temp root, actual Linux build/smoke, publish draft and inspect exact-source Windows/native checks. Main/active PR143/144/146 and author branches retained. No extra VM or credentials used.

Resumed verification after runtime restoration: a394782 fullrun completed14fail (2realGUIseam,12SHMlocation). All12installerfailures pass unchanged/tmp; frameworkextraction repairs2seam failures with3054ui lines and51focused passes. Root retains complete logs and prepares final rerun, no acceptance claim. Automaticapproval review blocked essential commit publication to GitHub; no write workaround attempted, approval remains required after preparation. PR147priorpublished8f4c4a2 has verified Windows/Linux packages/nativeGhidriff but unresolvedSonar; no merge.

Final essential handoff: implementation and independent reviews are integrated locally; product024a00b is frozen and completely tested. Authoritative exact counts, sole host failure/isolated pass, artifact hash and command logs are in the Final essential local verification QA case. PT-SAFETY-INTEGRATE is BLOCKED on publication authorization and subsequent exact-source Windows/native checks, not awaiting local implementation. This final documentation checkpoint leaves src/tests/tools/pyproject unchanged. Root owns retained local branch `codex/essential-project-safety-20261031`, patch/receipt, copied venv, worker source branches and Linux build; no new VM. Next executable action after explicit approval: publish this reviewed tree as a draft PR to djshellshoxxx/patchtrace, verify exact-tree match, inspect current-head CI/reviews and only integrate after required gates pass. Preserve PR143/144/146 and author sources. No approval workaround or unverified merge.
