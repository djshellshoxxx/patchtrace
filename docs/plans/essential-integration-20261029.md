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
