# PIL current-evidence and report-export repair — 2026-11-18

The CLI, desktop and report/2 adapter now use one current-input check before
treating a stored patch-intent assessment as current. The final affected gate is
**474 passed, zero failures, zero errors and zero skips** on the exact source
commit below. Whole-tree Ruff also passed. This receipt covers authored local
data, persistence and presentation mechanics; it provides no native accuracy,
real CVE attribution, remote consent execution or Windows packaging evidence.

## Source and ownership

| Purpose | Exact commit |
|---|---|
| Original independent flow review | `9e5a5303da6e9a745e604979932f814de8eca4b0` |
| Dedicated implementation baseline | `9002a1f44c6aebcf2c49b29d631aacf20e7ce9e3` |
| PIL specification and tests first | `a2531d390a0e35a5cb4d8c0080767598eaa923e4` |
| PIL source repair | `f47d212a876e0df78e79cb23a4fec2b75b647a54` |
| Report specification and tests first | `2cc95278003942654a3ae5d35a6bf75056d4d91f` |
| Final source, including report hook | `ade0f32a0e18e578516b58482b29212579c524ba` |

Worktree: `/workspace/scratch/c7a9e8d98848/pilot-staleness`, branch
`codex/pilot-staleness-20261118`. It was clean when the final source context was
recorded. All commits carry `[no release]`. The only production files changed are
`pilot/current_inputs.py`, `pilot/store.py`, `pilot/cli.py`, `ui_leads.py` and the
separately authorized `report2/adapters.py`. No persisted contract, schema,
collector, native adapter or frozen research outcome changed.

## Correctness behavior

The shared owner-thread capture checks saved project id/revision, ordered pair
hashes, the completed Ghidriff run/raw identity, verified retained advisory
identities, the local KEV identity and current static rule/origin/tier digests.
It uses the existing connection and never opens another project or passes a
connection into a worker. Advisory comparison follows the collector's universe:
all CVEs through 64, otherwise the assessment's explicit subset. All revisions
of each selected publisher/tracking group participate, including a revision
which withdraws its predecessor's CVE.

An incomplete or corrupt retained source cannot silently restore an old result
to current. The read accounts for every advisory source row; a valid recovery of
missing normalized facts from verified source bytes remains usable. KEV's
verified fallback remains usable, while an unreadable retained catalog is
different from intentionally having no catalog. Missing current run identities
are compared as missing rather than omitted from the check.

Manual function correspondence correction advances the project revision even
when the run and raw hashes do not change. PIL publication, normal save and
append-only reviews do not advance it. Publication therefore checks the saved
revision as well as the production current-input capture. A late older-revision
assessment cannot replace a newer-revision assessment under the same result id.
The existing behavior for a deliberate fresh recomputation under the same id is
retained: the newer derived assessment replaces that same-id copy. This repair
does not add a per-revision assessment archive or change result-id semantics.

Current results still take preference over newer stale results. When only
historical results remain, they stay readable and copyable. Analyst review
events remain append-only and CLI `review` now reports the same stale state as
`why`. Desktop function, evidence-line and outgoing-anchor activation rechecks
current inputs, including evidence changed since the last refresh, and refuses
stale navigation. Report/2 omits stale lead records and records an explicit
`stored pilot result is stale ... leads omitted` unknown. Current report layout
and source history stay intact.

## Evidence retained

The [manifest](pilot-staleness-20261118/manifest.json) records every changed file's
SHA-256, the imported module path, runtime versions, test counts, and hashes for
all 38 members of the [evidence archive](pilot-staleness-20261118/evidence.zip).
The archive was reopened, its member set checked, and every byte count and hash
verified. It is 69,379 bytes, SHA-256
`74cf31afd5b832ee9d7f0fa422d792488869f2a58976bfcda12a4d8112c35301`.

| Run | Actual result and interpretation |
|---|---|
| Original `flow-red` on `9e5a5303` | Seven failures: five staleness cases, the separate CVRF-to-PIL gap, and the separate default child-environment issue. Original source, log, XML and issue #121 snapshot are preserved unchanged. |
| Initial new-test harness | Eight failures and 18 errors. This run patched the socket class before `ssl` imported; the harness was corrected to deny connection methods. A positive review-status value was also corrected before the valid red run. This is retained as a harness failure, not product evidence. |
| Valid PIL red run | 22 failed, five passed in 2.36 s, before production edits. The archived `pilot-red-tests` copies come from `a2531d39`; production remained at `9002a1f4`. |
| Existing UI with evidence-complete fixture | 61 passed in 5.40 s before source changes. The real-store UI helper now imports a real authored advisory rather than claiming a current CVE with no retained advisory. |
| First PIL green | 27 passed in 2.60 s. |
| Action-time review controls | Two failures, four deselected, in 1.02 s: navigation after pairing/advisory change without refresh. This intermediate uncommitted source was not independently snapshotted; its log is preserved and the controls pass at the final exact source. |
| First related gate | 179 passed, one failed in 14.02 s. The assertion expected the old orientation-only warning; the warning now also correctly names the project revision. The assertion was updated to require that complete warning. |
| Subsequent PIL gates | 209 passed in 26.30 s; all 39 new controls then passed in 3.38 s; the affected gate including tooltip and host checks passed 262 tests in 24.49 s. |
| Report red on PIL source | Four failed, one passed in 1.08 s before the report hook. Tests/specification retained at `2cc95278`. |
| Report affected green | 212 passed in 9.12 s. |
| Final combined exact-head gate | **474 passed in 33.37 s** on `ade0f32a`, with zero skips. XML records 33.283 s inside the test suite. |
| Whole-tree Ruff | `All checks passed!` on the final source. |

The original seven-review-control file is evidence of the original baseline,
not a rewritten green test file. Its private CLI `_known` probe was replaced in
production by a shared capture. The new regression tests exercise the actual
CLI stored loader and source-pinned `pilot why`/`review` child processes instead;
the report controls also write and inspect a real report/2 JSON export.

## Exact-head command

The shared virtual environment's editable install points at an older checkout.
The absolute `PYTHONPATH` below pins this source in both pytest and inheriting
children; the new headless control also explicitly constructs its child's
absolute `PYTHONPATH` and checks that no Qt module was imported.

```bash
cd /workspace/scratch/c7a9e8d98848/pilot-staleness
QT_QPA_PLATFORM=offscreen \
PYTHONPATH=/workspace/scratch/c7a9e8d98848/pilot-staleness/src \
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q \
  tests/test_pilot_current_inputs.py tests/test_ui_leads_freshness.py \
  tests/test_pilot_store.py tests/test_pilot_store_durability.py \
  tests/test_pilot_cli.py tests/test_ui_leads.py tests/test_pilot_read_model.py \
  tests/test_tooltips.py tests/test_gui_host_seam.py \
  tests/test_report2_current_leads.py tests/test_report2_adapters.py \
  tests/test_report2_cli.py tests/test_report2_export_vm.py \
  tests/test_report2_export.py tests/test_report2_render.py \
  tests/test_report2_sections.py tests/test_ui_export_v2.py --tb=short \
  --junitxml=/workspace/scratch/c7a9e8d98848/qa/pilot-staleness/exact-head.xml

QT_QPA_PLATFORM=offscreen \
PYTHONPATH=/workspace/scratch/c7a9e8d98848/pilot-staleness/src \
/workspace/scratch/3a6632a6e5ff/venv/bin/python -m ruff check src tests tools
```

## Scope limits and independent review

The low-level `store.load(enrichment, known=...)` API deliberately keeps its
legacy integrity/partial-input semantics. Production CLI, desktop and report/2
reads now supply the complete capture for this repair's inputs. This slice does
not add a new unified/secondary/tool selection policy or collect missing tool
channels. Source I/O uses the existing advisory and KEV verification readers;
this receipt does not qualify total I/O budgets or large-store responsiveness.

The CVRF retained-context bridge is a separate authorized implementation and is
not imported by this standalone source. Its `kb_link_digest` and source-head
freshness need a combined follow-up after that source exists. The historical
issue #121 default Ghidriff environment isolation and primary memory/total-output
caps are separate work; nothing in these tests closes that issue. No target was
downloaded or executed, no paid/native experiment ran, and no frozen corpus or
outcome was modified. Root's independent review and combined integration gates
remain required before publication.
