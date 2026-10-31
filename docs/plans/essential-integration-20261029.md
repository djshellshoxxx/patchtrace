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

## 2026-10-30 fresh continuation and WIN-1 plan

Remote `main` and clean initial local HEAD are `a04f5a299a8d4afef023261e52e08d14678cf1e7` (merged #124). GitHub QA run [41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610) completed successfully for this exact SHA: Linux/Windows QA, repeated Qt, Linux packaging/smoke; release skipped. Linux/Windows package artifacts exist. The native advisory-green summary alone does not prove G-U1–G-U8. New draft stacks #139–#145 are active and remain untouched.

Using the existing ledger as the shared plan; routine implementation choices are delegated by the supplied autonomous brief. Integration owner: root. Workspace branch: `codex/windows-branding-reconcile-20261030`. No cloud resources provisioned. Linux workspace retained for development; disposable worker worktree `/workspace/work/patchtrace-branding`.

| ID | Outcome / scope / exclusions | Owner and owned files | Dependencies / contracts | Acceptance and verification | Status / handoff |
|---|---|---|---|---|---|
| PT-BASE | Verify declared baseline; no product changes | root; `work/` logs | exact main SHA, AGENTS.md | full offscreen pytest, Ruff, pip check; record host failures | DONE; remote exact-main baseline PASS; local partial baseline and venv failure diagnosed, not claimed as a full pass |
| PT-WIN1 | Selectively port #102 metadata/icon; exclude workflow changes and signing | branding worker; app_icon/resources, __main__, pyproject, Windows resource tools/hook/tests in isolated worker branch | SPEC-52 WIN-1 amendment above; module index before implementation | Import source tests, reproduce weak read-back checks, strengthen tests/gate, preserve current build checks, run focused suite | BLOCKED on native acceptance; integrated/reviewed; 310 focused tests PASS |
| PT-WIN1-REVIEW | Independently review then integrate and verify | root/reviewer; shared ledger, QA, todo | PT-WIN1 reviewed commit | Inspect diff, focused/full suite, Ruff, current-source Windows CI before merge | BLOCKED on exact-head Windows/native gates; complete local result in QA case |

Execution order: baseline in parallel with bounded source audit; port indexed modules and targeted build hooks; add regressions for empty/invalid resources; review and integrate; full combined verification and publish a draft candidate if remote native acceptance remains blocked. No author branch is overwritten or closed.

Native gate inspection: run [41063115449](https://github.com/djshellshoxxx/patchtrace/actions/runs/41063115449), report job `124122131077`, is advisory green while native pair/mutant jobs failed. Its report measures 15 A/A pairs missing 15, zero mutant denominators, zero matched rows and zero compared/mirrored pairs; summary: pass 0, fail 0, insufficient-data 7, pending 1. This is not G-U acceptance. Existing #139–#144 repair stacks own these failures; this continuation does not duplicate them.

Exact-main QA log evidence from run 41060959610: Ubuntu job `124080277092` reports **18,382 passed, 47 skipped, 7 xfailed**; Windows job `124080277337` reports **18,349 passed, 81 skipped, 6 xfailed**. Both Ruff checks passed. Windows log explicitly records portable checksum/clean extraction/frozen smoke and installer registration/runtime/self-test/data-preserving uninstall passes. These results validate main `a04f5a2`, not the new WIN-1 candidate. Missing optional native tools are explicitly reported as blocked in those logs.

WIN-1 worker source commits `5617e61` and `676ca38` were independently reviewed and cherry-picked as `5429e84` and `78ff0c7`. Root independently passed the integrated 310-test batch and whole Ruff. The interrupted local baseline is not a completed suite; see QA case. Next: run full frozen-source candidate suite with detailed failure nodes, build/smoke Linux candidate, publish reviewable draft and obtain exact-source Windows CI. No merge/release is authorized by advisory-green native evidence. Worker worktree remains committed/clean and is retained until handoff; root owns integration and final verification.

Final local verification for [PR #147](https://github.com/djshellshoxxx/patchtrace/pull/147): product tree `956487f11e0798909d956ae7f1a91906ed997c2b` (local `7fd095f`, published `015f79c`) is independently reviewed and fully exercised. Authoritative counts/host failure and separate rerun are in the WIN-1 QA case, alongside actual Linux artifact hash/smoke evidence. This checkpoint changes coordination documentation only. Windows QA/native runs are queued; preserve draft and do not merge before required acceptance. Next: inspect the PR's current-head checks, obtain Windows resource/frozen/installer evidence, reconcile any actionable findings, then resume the active essential native-engine stacks. Root retains worker checkout `/workspace/work/patchtrace-branding` (clean committed `676ca38`), development venv and `work/` logs, plus Linux `dist/` candidate; no additional cloud instance was provisioned.
