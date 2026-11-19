# Continuation test results — 2026-11-19

The results here are completed slice runs from the continuation based on
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`. Reviewed source is integrated locally
on `codex/patchtrace-completion-20261119-81e4`. **The full combined attempt at
`69fa6b8b` ended with exit 137 before a pytest summary or JUnit report. It is
incomplete; hosted CI of the aggregate remains pending.** A passing slice is
not evidence that the aggregate or a native release passed.

Raw receipt names in the original **Completed runs** table are preserved in the
[focused evidence archive](evidence/continuation-20261119-focused.zip), together
with source-discovery inputs and the full partition plan. Its 94 payloads were
reopened and checked against the included manifest. Archive SHA-256:
`babf10b732007de68adbf265416139bcaf3bd72d13f35916985080055cd5c9df`
(603,406 bytes). Later partition results and Phase 6 receipts are excluded from this focused archive.
Working receipts remain under `/workspace/scratch/81e4938f4a3a/verification`.
Durations are pytest log-summary durations; JUnit suite durations can differ.

## Completed runs

| Source/scope | Actual outcome | Receipt names |
| --- | --- | --- |
| N-way new controls against base | 11 failed in 4.32s | `nway-red.log`, `nway-red.xml` |
| N-way affected selection, `24064cf6` | 85 passed in 21.76s | `nway-green.log`, `nway-green.xml` |
| Installer receipt, source `20b54521` / local port `ef9167d2` | 5 passed in 3.07s | `installer-notes.log`, `installer-notes.xml` |
| Initial parser controls replayed against base | 29 failed, 4 passed in 8.32s | `security-red.log`, `security-red.xml` |
| Parser's initial broader selection | 425 passed, 1 skipped in 68.87s | `security-focused.log`, `security-focused.xml` |
| Independent SQLite-classifier review before correction | 6 failed, 22 passed in 2.31s | `security-review-red.log`, `security-review-red.xml` |
| Corrected parser/boundary selection | 107 passed in 8.62s | `security-review-green.log`, `security-review-green.xml` |
| Final parser affected selection, chain ending `baf95fcd` | 432 passed, 1 skipped in 61.86s | `security-final.log`, `security-final.xml` |
| Cache review regressions before correction | 13 failed, 2 passed | `pe-cache-review-red.log` |
| Concurrent cache-row growth before correction | 1 failed | `pe-cache-growth-red.log` |
| Cache, Qt and announcement final focused selection | 67 passed in 72.23s | `pe-cache-review-green-v2.log`, `pe-cache-review-green-v2.xml` |
| Final deduplicated cache affected selection, `0bc41f6b` | 840 passed, 2 skipped in 60.27s | `pe-cache-final.log`, `pe-cache-final.xml` |
| Independent cache peer controls | 16 passed, 37 deselected in 2.15s | `security-pe-peer.log`, `security-pe-peer.xml` |
| Research facts guard against base | 11 failed, 2 warnings in 1.74s | `facts-gate-red.log`, `facts-gate-red.xml` |
| Research facts guard focused correction | 33 passed in 3.52s | `facts-gate-green.log`, `facts-gate-green.xml` |
| Research facts guard initial caller sweep | 106 passed, 1 failed in 4.05s; authored adapter fixture lacked explicit facts metadata | `facts-gate-callers.log`, `facts-gate-callers.xml` |
| Research facts guard final scoped/caller selection, `d87af037` | 140 passed in 4.59s; fixture metadata corrected, original positive hit assertion retained | `facts-gate-final.log`, `facts-gate-final.xml` |
| BinExport2/rz-diff text controls on unchanged parser base | 35 failed, 16 passed in 4.29s | `adapter-baseline-verified.log`, `adapter-baseline-verified.xml` |
| Final adapter, isolation, scheduler, ownership and property selection | 414 passed in 87.86s | `adapter-boundaries-final.log`, `adapter-boundaries-final.xml` |
| CSAF redirect controls before repair | 4 failed, 6 passed in 1.63s | `static-csaf-red.log`, `static-csaf-red.xml` |
| Final CSAF redirect and existing transport selection | 33 passed in 1.08s | `static-csaf-green-v3.log`, `static-csaf-green-v3.xml` |
| CVE decimal/time boundary controls before repair | 20 failed, 10 passed in 2.44s | `cve-numeric-red.log`, `cve-numeric-red.xml` |
| CVSS exactness controls against the intermediate typing-only correction | 10 failed, 33 passed | `cve-numeric-exact-red.log`, `cve-numeric-exact-red.xml` |
| Final CVE boundary, normalization and caller selection | 124 passed in 6.70s | `cve-numeric-final.log`, `cve-numeric-final.xml` |
| Full combined attempt, `69fa6b8b` | Exit 137/SIGKILL; no summary, no JUnit and no completed-test total | `full-batch1.log`, `full-batch1-result.json` |

These groups overlap. Do not sum their pass counts into a combined or unique-test
total. Earlier cache iteration failures remain in their original receipts,
including a positional test seam corrected without weakening failure assertions
and announcement expectations updated for metadata loading before worker start.
The earlier `pe-cache-expanded` command also repeated PE test-file arguments; it
is not the final deduplicated result.

An execution-environment outage interrupted earlier processes and removed their
temporary environment. No result is inferred from those pending handles. Fresh
restored-environment runs supply the completed receipts above.

## Exact platform skips

| Selection | Test | Reason |
| --- | --- | --- |
| Parser | `tests/test_acquisition_delta.py::test_apply_synthetic_delta_created_with_createdeltab` | `msdelta.dll` is Windows-only. |
| Cache/PE | `tests/test_pe_catalog_win.py::test_real_probe_on_a_system_dll_read_in_place` | Needs Windows CI; blocked native acceptance item. |
| Cache/PE | `tests/test_pe_overview_map_compare.py::test_native_unsigned_file_does_not_raise` | WinVerifyTrust is Windows-only. |

The parser ran on Python 3.12 with SQLite 3.53.1, including an authored
missing-classifier refusal control. Offscreen Qt tests establish the exercised
thread/model/lifecycle behavior; they do not qualify native trust or real desktop
accessibility.

Whole-tree Ruff passed for the final parser and PE slices. The PE slice's schema
regeneration completed without schema changes, and its whitespace check passed.
The installer and facts-guard slices have scoped Ruff and whitespace passes.
The corresponding aggregate checks remain required on the frozen source.

## Aggregate and remote status at handoff

| Gate | State at this checkpoint |
| --- | --- |
| Final facts-guard caller suite and source integration | Completed: `d87af037` integrated locally by `69fa6b8b`; 140 passed. |
| Complete combined offscreen pytest | Incomplete at `69fa6b8b588645a895b3edbdeff3aa4b74856be7`: session 22710 ended 137/SIGKILL. No pytest summary or JUnit exists. |
| Sequential partition diagnostic | Source `a4d6dd9b`, groups1–9 completed: 2,602 passed, 8 skipped, one contextual-digest golden failure; 2,611 collected. Stopped before group10 at the128MiB shared-disk reserve. Remaining45 groups are not covered by this attempt. |
| Historical complete-manifest diagnostic | All 856 original files reached through 59 terminal processes; 23,110 passed, 139 skipped, 6 xfailed, 4 failed, 8 teardown errors. FAILED on frozen source/old Pydantic; not a current-head or unsplit pass. |
| Reviewed digest rebaseline | Sole new plain-data rounding constant explains the digest change; eight fresh-process checks stable. Only the contextual fixture value changes. Complete nine-case golden/cache-identity file passes9/9 in1.85s in the separate candidate checkout; no runtime change. |
| Combined Ruff, dependency and generated-schema checks | Configured whole-tree Ruff and pip check passed at `a4d6dd9b`; schema generation exited 0 with no schema drift. Receipts are in the focused archive. |
| Hosted aggregate Linux/Windows, repeated Qt and package gates | Last observed PR #322 publication `2511301f` equals local `7093ee68`; its five new workflows were queued. Later accepted source still requires publication and its own gates. |
| Existing main CI | Last observed Linux/Windows QA and all five Qt legs green; Linux packaging queued. This does not qualify the aggregate. |
| PR319, head `a56ab13aaf9916fc12bea70ba1494075991b7f09` | Queued at the coordinator's observation; refresh before any action. |
| Broad PR316/318 | Existing holds unchanged. |
| Later PR320 / PR321 | Observed after the frozen census; retained separately. PR320 is a draft broad aggregate with incomplete full-suite evidence; PR321 is a documentation checkpoint atop PR319. Neither qualifies this local source. |
| Main merge / release | Neither performed by this continuation. |

Remote states are the coordinator's observed snapshot, not a new network poll by
the documentation worker. Recheck heads and every required job before promotion.

## Current run and reproducible next commands

The first full process has ended. Its kill cause is not established: shared disk
pressure and low available memory were separately observed, but no causal OOM
event record was available. The later frozen diagnostic reached all original
files across separate processes and FAILED. Its original reserve stops and kill
remain preserved; partitioned coverage is distinct from an unsplit full pass.
Use a new receipt prefix and keep the actual exit status and output for every
command. The interpreter must resolve this root checkout, not a worker worktree.

```bash
cd /workspace/scratch/81e4938f4a3a/PatchTrace
PT_PYTHON=/workspace/scratch/81e4938f4a3a/.venv-main/bin/python
PT_VERIFY=/workspace/scratch/81e4938f4a3a/verification
PT_RUN=full-batch1-rerun1
git rev-parse HEAD > "$PT_VERIFY/$PT_RUN-source.sha"
"$PT_PYTHON" -I -c 'import patchtrace; print(patchtrace.__file__)'
"$PT_PYTHON" -m pip check > "$PT_VERIFY/combined-pip-check.log" 2>&1
QT_QPA_PLATFORM=offscreen "$PT_PYTHON" -m pytest -q \
  --basetemp="/tmp/pt81-$PT_RUN" -o tmp_path_retention_policy=failed \
  --junitxml="$PT_VERIFY/$PT_RUN.xml" \
  > "$PT_VERIFY/$PT_RUN.log" 2>&1
"$PT_PYTHON" -m ruff check src tests tools \
  > "$PT_VERIFY/combined-ruff.log" 2>&1
"$PT_PYTHON" tools/generate_schemas.py \
  > "$PT_VERIFY/combined-schemas.log" 2>&1
git diff --check
git status --short
```

For a focused replay of the final cache selection, the exact file selection is:

```bash
QT_QPA_PLATFORM=offscreen "$PT_PYTHON" -m pytest -q \
  tests/test_pe_*.py tests/test_ui_inspection_signing.py \
  tests/test_gui_host_seam.py tests/test_enrichment_storage.py \
  tests/test_alpha_integration.py tests/test_audit_trust_boundaries_20261107.py \
  tests/test_files_announcements.py
```

The parser's exact broad selection is retained in
[its source receipt](parser-integrity-20261119.md). Focused replays are diagnostic
tools and do not replace the pending full combined run.

## Digest correction and first partition checkpoint

[Supplemental evidence](evidence/algorithm-digest-review-20261119.zip) contains24 manifest-verified payloads, including original partition failures and the corrected digest check. SHA-256 `aaf3f22a9f1b09e8423be01a1667be6afa60b436d6434fe741a0bc852d8ed80a`. The original failed run remains failed. The corrected nine-case replay is separate; no complete 54-group or unsplit result is claimed. The fixture's sole executable consumer is the golden test; production hashing is unchanged.


## Phase 4 — history diagnostics and current qualification

Baseline: 12 failed/8 passed in 19.07s. Recovered slice: 79 passed in 42.63s. Real SQLite post-write controls: 2 failed in 3.59s. Final affected UI/host selection: 81 passed in 37.33s; whole-tree Ruff and whitespace checks pass. Independent source review found no blocker in the recovered diagnostics, scheduler/producer boundary or persistence ownership/refusal contract. Authored offscreen controls do not qualify native comparators or atomic storage.

[History evidence](evidence/history-diagnostic-20261119.zip): 9 verified payloads, 16,801 bytes; SHA-256 `60248a2e1bc603b6dba92451df639d22b7c58cc0d8153262a387242ae4dc5f67`.

The first `a4d6dd9b` partition stopped at disk reserve after 9/54 groups: 2,602 passed, 8 skipped and one contextual-digest pin mismatch. Golden correction `70b82275` follows review of the exact new ROUND constant; 9 digest/cache-identity tests pass in 1.85s. The original failure remains failed. [Algorithm-digest evidence](evidence/algorithm-digest-review-20261119.zip) preserves both outcomes.

The final frozen diagnostic reached all **856 original test files through 59 terminal pytest processes** at runtime/test source `520b524b` (documentation head `3cde10ae`) with unchanged Pydantic 2.13.5. Actual pytest summaries total **23,110 passed, 139 skipped, 6 xfailed, 4 failed and 8 teardown errors**: the diagnostic **FAILED**. Both storage-reserve stops and the original group-51 SIGKILL/-9 without a summary/JUnit remain preserved. Final subpartitions completed the remaining file coverage without rewriting those outcomes. This is not an unsplit pass or qualification of the newer 859-file source and Pydantic 2.14.2.

The earlier 45 unrun groups remain uncovered by that first nine-group attempt.
The later 856-file diagnostic has its own complete manifest and failed outcomes.
No progress dots establish a completed aggregate count.

## Phase 5 — completed corrections and split diagnostic

Historical Phase 5 checkpoint: `bc485a6644bee406fbfd92f4bfa47fdfbb4dbcbd`. The separate 856-file diagnostic retains its earlier source and old dependencies; it does not qualify later changes.

| Scope | Observed result | Evidence |
| --- | --- | --- |
| Contextual stage pin correction | 12 passed in 1.61 seconds; original group 12 remains 510 passed/2 failed. | [Independent stage proof](evidence/contextual-stage-key-review-20261119.zip); nine payloads, SHA-256 `51af1e41cb11765d3191edbdf09c0472b4575a58d6635c4fa01b2e057a161e1e`. |
| Acquisition binding | Baseline 5 failed/2 passed; 255 affected passes in 33.14 seconds; integrated 55 passed in 4.67 seconds. | [Batch 5](RECOVERY_BATCH_5.md), phase 5 archive. |
| Four-file test harness repair | 85 passed/1 existing psutil skip under both failed-only and all retention (11.99 and 8.70 seconds). | [Harness report](TEST_HARNESS_FIXES_20261119.md). |
| Symbol scanner cleanup lifetime | Baseline 1 passed/1 teardown error; corrected 30 passed in 2.42 seconds. | Same harness report and phase 5 archive. |
| Initial 34 candidate groups | Stopped at temporary-storage reserve; JUnit totals 15,971 tests, 4 failures, 4 errors, 86 skips. | [Stopped run archive](evidence/candidate-stopped34-20261119.zip), 71 verified payloads, 364,804 bytes, SHA-256 `608d65b6bcaa51a705b78499b44be4ff83b428de406dbdff89a2e806881dba81`. |
| Later original groups 35–54 | Session 78011 ended at reserve after groups 35–45; tail 46–50 passed, original group 51 was killed without summary/JUnit. Final subpartitions reached all remaining files and exposed three backup-test teardown errors. | Complete frozen diagnostic archive and chained manifests in Phase 6 below. |

The four initial failures were two contextual stage pins, one forbidden AF_UNIX constructor and one path-sensitive preview assertion. The four errors were passed test bodies whose global OS fault patches remained active during fixture cleanup. Group 40 later exposed the same scanner-fixture lifetime issue; its original result remains 519 passed/8 skipped/1 error. The AF_UNIX test is unchanged: bare isolated Python reproduces EPERM before any PatchTrace import, so this runner cannot supply that acceptance result.

The frozen checkout was relocated across filesystems after verifying all 3,946 tracked-file hashes. Its interpreter was repointed and verified using `-I`; source/test/tool fingerprint `9ecd20b2dd0f83047551f8a9f85e28c34a34236f65d77b74e46483eecf33a2b2` is unchanged. Only inactive task-owned environments were removed. No other's workspace or shared dependency environment was modified.

Initial-head hosted gates remain queued. In addition to successful job conclusions, live BinDiff JSON receipts require review because Windows steps can be advisory or report blocked while the job remains green. No full-suite, current-head CI, native, release or main-merge pass is claimed.

## Phase 6 — accepted source and final frozen diagnostic

Accepted source/test checkpoint: `5aebd98f362e7cc5f01a0c96878860b04835cea4`, a
test-only follow-up to runtime/dependency integration `5208c758`. There are
859 tracked test files, with Pydantic 2.14.2/core 2.50.2. Evidence checkpoint
`e430309a` preserves the archives. Later phase receipts below are not members of
the original 94-payload focused archive.

### Complete historical coverage, failed outcome

All 856 original files reached terminal pytest results through 59 processes:
50 original groups, eight final subpartitions and the isolated dense case.
Original sessions 74806/78011 ended at reserve after groups 1–34 and 35–45;
those stopped manifests remain unchanged. Tail groups 46–50 passed 1,373 tests
without skips/failures/errors; original group 51 ended -9 after 40.539s with no
summary/JUnit. That killed attempt supplies no completed-test count.

Final subpartitions reached all remaining files without assertion or fixture
changes. Seven residual-performance cases pass split 6+1; all 1,396 collected
node IDs from original groups 51–54 exactly match the terminal XML node-ID
multiset, with no omitted or duplicated cases. The isolated dense case passed
in 34.19s (35.600625s subprocess time; child maximum RSS 783,708 KiB). Its success
does not establish the original kill's cause.

| Accounting basis | Final recorded totals |
| --- | --- |
| Actual pytest summaries | **23,110 passed; 139 skipped; 6 xfailed; 4 failed; 8 teardown errors** |
| JUnit attributes | 23,259 tests; 4 failures; 8 errors; 145 skipped, including six xfails |

Teardown errors coexist with passing test bodies; do not subtract errors from
pytest passes. The diagnostic **FAILED** on frozen source `520b524b` (documentation
head `3cde10ae`), old Pydantic 2.13.5 and unchanged fingerprint
`9ecd20b2dd0f83047551f8a9f85e28c34a34236f65d77b74e46483eecf33a2b2`.
It is not an unsplit pass or qualification of current 859-file source/dependencies.
The external AF_UNIX constructor EPERM before product imports remains unchanged.

Final subpartition 53-2 reported 346 pytest passes and three teardown errors:
`test_verified_backup_publication_admission.py` kept an `os.scandir` mock alive
into pytest cleanup, where `Path(int_fd)` fails. Root reproduced 3 passes/3
teardown errors on current dependencies; test-only `5aebd98f` scopes the fault
mock to its operation and retains all assertions. Three affected files then
passed **41 tests in 2.62s**. Production code is unchanged and original frozen
errors remain errors. [Harness report](TEST_HARNESS_FIXES_20261119.md).

`candidate-partitioned-summary-20261119.json` has SHA-256
`240385a6e2d9ef19712d00f2f89255ae1e00b9f60a57e3239a4b615860b8ae04` and is
preserved with every original manifest/receipt in the complete diagnostic archive.

### Retention verification

Source `74d5f4bb15a94c6e4f2cb16a5da22a2031d985c7` was integrated by
`153f6cea8289547aa83acf85100e8c162631b77e`. Early 32 setup failures were an
authored fixture algorithm mistake, separately retained and not credited as a
production defect. [Batch 6](RECOVERY_BATCH_6.md) gives exact commands and scope.

| Check | Actual outcome | Receipt |
| --- | --- | --- |
| Meaningful baseline | 26 failed, 6 passed in 2.93s | `attempt-retention-red.{log,xml}` |
| First repaired selection | 123 passed in 20.48s | `attempt-retention-green.{log,xml}` |
| BLOB-ID controls before guard | 2 failed, 2 passed, 32 deselected in 1.59s | `attempt-retention-id-red.{log,xml}` |
| Explicit protection before guard | 2 failed, 40 deselected in 1.52s | `attempt-retention-protect-red.{log,xml}` |
| NULL-cap intermediate selection | 170 passed, 1 failed in 21.11s | `attempt-retention-null-cap-intermediate.{log,xml}` |
| Exact cap/upsert before null-safe sum | 1 failed, 3 passed, 42 deselected in 1.64s | `attempt-retention-null-cap-red.{log,xml}` |
| Final affected selection | **175 passed in 18.92s**, 10 files including 46 new controls; whole-tree Ruff and whitespace pass | `attempt-retention-final.{log,xml}`, `attempt-retention-ruff.log` |
| Independent root SQLite replay | NULL/BLOB metadata each yield zero eviction; every original row preserved | `retention-null-id-peer.log`, `retention-id-peer-green.log` |

Final JUnit SHA-256: `b385d70fb8792b70cac28168b0b9a1d430337e26ebad6944c1d32fc30efdb497`.
Ordinary eviction, valid replacements, read-only history, cap refusal, genuine
storage errors and deliberately injected post-write UI uncertainty remain covered.
This is not atomic-save or universal corrupt-database qualification.

### Pydantic and integrated checks

Source `b28f697162f9edbadbdc860c0358be5feb41f377`, based on `f114eb96`, was
integrated by `5208c7589495cea749142f57599c4382be9caed5`. The source environment
used Linux Python 3.12.14, Pydantic 2.14.2/core 2.50.2 and unchanged Qt 6.12.0.

| Check | Actual outcome | Receipt |
| --- | --- | --- |
| New controls on old versions | 8 failed, 1 passed in 1.24s | `pydantic-security-red.{log,xml}` |
| Identical controls on new versions | 9 passed in 0.96s; included in compatibility total | `pydantic-security-green.{log,xml}` |
| First grouped model attempt | SIGKILL/-9 after 9.573s, no summary/JUnit; cause unestablished | `pydantic-compatibility-results.json` |
| Bounded compatibility | **2,903 passed, 1 existing strict xfail**, no skips/failures/errors; 79 distinct files/28 batches, summed wall time 195.955s | `pydantic-compatibility-summary.json`, `pydantic-compatibility-bounded-results.json` |
| Both-version schema generation | 16 generators complete; all 301 schema files and generated CSAF table byte-identical | `pydantic-schema-compare.{json,log}` |
| Source environment gates | Isolated origins/versions, pip check, whole configured Ruff and whitespace pass | `pydantic-upgrade-versions-after.json`, `pydantic-upgrade-{pip-check,ruff,diff-check}.log` |
| Integrated `5208c758` checks on new versions | **254 passed**, four groups, zero failures/errors/skips: retention/storage 66; secondary attempts/backups 71; acquisition/lifecycle 43; Pydantic/cache/identity 74 | `integrated-phase6-results.json`, four log/JUnit pairs |
| Root integrated gates | Configured Ruff and pip check pass at `5208c758` | `integrated-phase6-{ruff,pip-check}.log` |

The existing strict xfail is `test_codex_pkg_packaging.py::test_linux_package_runs_full_cli_smoke`
(`CODEX-14`); no marker or golden changed. Source/root private environments were
verified on the new versions; original shared/frozen environments retained
2.13.5. [Qualification](PYDANTIC_SECURITY_UPGRADE_20261119.md) binds exact wheels
and source. Overlapping selections are not summed or represented as a full run.

Both actual 15-package Linux runtime/search/rules graphs completed PyPI and OSV
audits: four successful zero-finding results. Direct APIs also omit four upstream
Pydantic advisories affecting the old pin; 2.14.2 clears those ranges. Seven
assessed native Qt findings remain open; official 6.12.1 binding wheels were
unavailable at retrieval, and 6.11.3 is not a complete fix. [Advisory audit](DEPENDENCY_ADVISORY_AUDIT_20261119.md)
retains exact graphs and the demonstrated coverage gap, not a clean-security claim.

Fresh source scan at `5208c758`: 64 findings with no normalized additions/removals
versus `520b524b`. The separate 70-finding tools expansion requires review;
existing source dispositions do not classify all 134 combined results.

### Verified Phase 6 archives

Counts exclude each archive's manifest. Coordinator receipts bind the first
three to source `5208c758`; the separate diagnostic receipt binds frozen source,
and the backup-test report binds the test-only correction `5aebd98f`. CRCs and
payload hashes were verified; archive identities are preserved by `e430309a`
and the separate backup-test commit.

| Archive | Payloads | Bytes | SHA-256 |
| --- | ---: | ---: | --- |
| [Retention and integrated checks](evidence/attempt-retention-20261119.zip) | 41 | 60,901 | `ee765f3dcf38efac9635c944ee1154aba288ea94bec5911c8bee748a95dc1153` |
| [Pydantic qualification](evidence/pydantic-upgrade-20261119.zip) | 82 | 142,996 | `89e2325b53207afcf19b8b143308a08dd4370724a030a5ed726050be8cf2a2fe` |
| [Dependency advisory audit](evidence/dependency-advisory-audit-20261119.zip) | 27 | 57,308 | `e664bd4ef2d5bb9a9eca897cca63986a5fc56701bbfbcf04ad7e570118bee5bd` |
| [Complete frozen diagnostic](evidence/candidate-partitioned-20261119.zip) | 132 | 599,873 | `29a5149bbc2671db26fe260dcc9e94515cd543ac0643f0e74f29f4f0b5720653` |
| [Backup-test lifetime correction](evidence/backup-scandir-harness-20261119.zip) | 6 | 5,316 | `42159a0a7eb93cdb31585d2b4b934262ad3c3e5833592a7bbc34a08e3dd2368c` |

The retention archive also includes integrated checks and fresh source/tools scans.
The advisory archive contains its separate 26-file evidence manifest; its 27
payloads include that manifest. The copied report exactly matches the original
raw report, SHA-256 `370248accabe83d60cfa0f6b153da0c3752b1b3cb90d44d82d444a260acc1bf3`.
The backup archive preserves `backup-scandir-{red,green}.{log,xml}` and both result
JSON files. No full current-head suite, native acceptance, release or main merge
is claimed. Future strings-export and build-tool HTTPS work remains separate.
