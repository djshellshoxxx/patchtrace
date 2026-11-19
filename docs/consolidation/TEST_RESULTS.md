# Continuation test results — 2026-11-19

The results here are completed slice runs from the continuation based on
`fdc2696c23bdbfe7668348f25e3b336ce33039f7`. Reviewed source is integrated locally
on `codex/patchtrace-completion-20261119-81e4`. **The full combined attempt at
`69fa6b8b` ended with exit 137 before a pytest summary or JUnit report. It is
incomplete; hosted CI of the aggregate remains pending.** A passing slice is
not evidence that the aggregate or a native release passed.

Raw receipt names below are preserved in the
[focused evidence archive](evidence/continuation-20261119-focused.zip), together
with source-discovery inputs and the full partition plan. Its 94 payloads were
reopened and checked against the included manifest. Archive SHA-256:
`babf10b732007de68adbf265416139bcaf3bd72d13f35916985080055cd5c9df`
(603,406 bytes). Active partition results are excluded from this focused archive.
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
| Current complete-manifest qualification | Running on `520b524beb0c837b6e50801bd97c88a2447e39fd`: all 856 test files/54 groups, session 74806, `/tmp/pt81-final-results`; no aggregate outcome yet. |
| Reviewed digest rebaseline | Sole new plain-data rounding constant explains the digest change; eight fresh-process checks stable. Only the contextual fixture value changes. Complete nine-case golden/cache-identity file passes9/9 in1.85s in the separate candidate checkout; no runtime change. |
| Combined Ruff, dependency and generated-schema checks | Configured whole-tree Ruff and pip check passed at `a4d6dd9b`; schema generation exited 0 with no schema drift. Receipts are in the focused archive. |
| Hosted aggregate Linux/Windows, repeated Qt and package gates | Not run for this local aggregate. |
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
event record was available. A new sequential qualification is active on `520b524b`; partitioned coverage
remains distinct from an unsplit full pass.
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

The all-856-file, 54-group qualification is running on `520b524beb0c837b6e50801bd97c88a2447e39fd` in coordinator session 74806, with its own `/tmp/pt81-final-venv` environment and results under `/tmp/pt81-final-results`. Source/tests are frozen. No aggregate pass is available yet.

The earlier 45 unrun groups remain uncovered by that attempt; the new qualification starts from the complete 856-file manifest. No progress dots establish a completed aggregate count.
