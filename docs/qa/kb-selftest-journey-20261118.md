# Packaged synthetic KB self-test: source qualification

The bounded authored F8 journey passes at exact source
`316b0f12fd0180a597366bdec80fa768bdc59fe6`: **398 affected checks passed in
74.67 seconds, with zero failures, errors or skips**. A separate current-source
desktop entry completed in 2.76 seconds, returned four authored matches and four
candidate leads, confirmed stale state after reopening, and left no temporary
workspace before printing its success marker. This is source/offscreen evidence;
native Windows/Linux frozen-package, engine and live-source acceptance remain
pending.

## Ownership and source identity

Worktree: `/workspace/scratch/c7a9e8d98848/kb-selftest`.
Branch: `codex/kb-selftest-journey-20261118`.
Baseline: `3faf436a3b11c69220641a167cf424e7f4060839`.
Historical reference: `c13d3257c88140c23fb585a8a59a4dce81e81928`.
The historical helper and its test were read as provenance. Current project
capture, task ownership and candidate-loading contracts were traced separately.
The historical obsolete standalone loader call is not imported or restored.

| Commit | Purpose |
|---|---|
| `ff6851f3` | F8 specification, module index and the original 17 controls before implementation |
| `6a0f6b5e` | Narrow the cleanup fault injection; add active-project early-quit and original-error preservation controls |
| `3e0de93f` | First packaged journey, event-loop/ownership helper and entry hook |
| `0bda6edd` | Stuck-worker retention positive control and baseline tooltip-collision regression |
| `560e6dda` | Preserve the old panel failure-detail requirement; normalize test import order |
| `316b0f12` | Restore panel IDs/error classes, distinguish investigation workspace guidance and align the helper annotation |

The final product change is limited to `gui/qt/kb_selftest.py` (316 lines),
`gui/qt/selftest_loop.py` (173 lines), the existing `__main__.py` self-test branch,
and one tooltip sentence in `kbcorrelation/investigation_qt.py`. The two dedicated
test files contain 22 checks. SPEC-31-F/F8 and the module index describe the seam;
no new standalone spec requires registration. No schema, normal app flow,
workflow, packaging script, native engine or scan-policy change was made.

`ui.py` is unchanged at 3,071 lines, SHA-256
`1b5ea70d275441bd023d2178a8ea7b815add8bb00ff5ddc72014a5f9a92ef74e`.
The existing 3,077-line ceiling and forbidden-API guards pass unchanged.

| Final file | SHA-256 |
|---|---|
| `src/patchtrace/__main__.py` | `49067d51c47b106ee3b6206d00ba08c1c7d5257390a3de226e33d9e6cecdb49e` |
| `src/patchtrace/gui/qt/kb_selftest.py` | `a1f3c175b6a880fdf0c7ea50b8187e5014c6ecce4b414ee650aa93dea96bd46d` |
| `src/patchtrace/gui/qt/selftest_loop.py` | `fe6ac834f2bfea4aed066ef0d1883ed72fc2000c137252bc734c98d57db698b3` |
| `src/patchtrace/kbcorrelation/investigation_qt.py` | `0664dc79a174bcec000f52eee57c5461c368065875a880cb9730092a3c0b6961` |
| `tests/test_ui_kb_selftest.py` | `6bc0eb101fb3dc8548fd6a429cf6bd40965a4babcfa6e5c03907291b050732da` |
| `tests/test_kb_selftest_entry.py` | `b259eca56cd6f065c55a9d3e5ede62c5afd4796dd2fbdfae5d58878884cbd7b7` |

## What the control actually exercises

One real `QApplication.exec()` loop drives timer continuations and the current
desktop TaskRunner. Nested-loop and wrong-thread calls fail before creating a
workspace. The entry preserves the application icon, optional dependency line,
visible sample, panel registry checks and their failure details. The helper is
loaded only by the explicit desktop self-test branch; the source-pinned headless
CLI child still imports no Qt/UI modules.

The actual investigation dialog first searches an empty local workspace, imports
an authored two-product CVRF document, searches both KB and CVE, and requires an
explicit AMD64 selection. It inspects two package-authored 1 KiB PE fixtures as
data, checks their ordered hashes, cancels and retries the pair preview, creates
a normal project and verifies that the host actually adopted that exact root.
Dialog acceptance alone is not treated as adoption.

The current import service admits the authored comparison, the current ranking
pipeline publishes its result, and the actual candidate controller captures
project data on the GUI thread before worker-side loading. The control checks
the expected CVE group and refuses any upgrade of documentary association into
supporting binary applicability. It exports project and advisory context, checks
the exact attached source bytes and content-addressed filename, and reopens the
same project and analysis-run identities. A second authored advisory revision
must disable stale navigation immediately and after another close/reopen while
the original attached source remains readable.

The source fixture captures one UTC date for its two revisions, so the ordinary
current-month lookup is exercised without replacing the service or clock. Its
actual digest is part of the receipt; it is not a permanently fixed native-source
identity. The standalone run recorded
`ba00bf2c68cd2be9d8ad334d54678204b26a6683ccc9023c19e36cecb57ef4ed`.
Unicode filesystem paths are exercised throughout. No repository test fixture
is needed by the packaged helper.

## Failure, cancellation and directory ownership

Per-wait deadlines are ten seconds and the overall deadline is 45 seconds.
They are cooperative around fixed small fixtures and existing bounded calls.
They do not interrupt arbitrary stalled kernel/filesystem I/O; the existing
build/test child-process timeout remains the outer limit.

Failure closes the generator, rejects an owned dialog, checks the shared runner's
shutdown result, closes the window and a captured project-service fallback, and
restores the application quit policy and four environment variables. Original
step failures survive a later cleanup failure; notes identify only exception
classes. If a worker exceeds its finite join budget or cleanup fails, the
temporary workspace is retained and no successful receipt is returned.

A supplied parent retains authored artifacts. The fixed Unicode child is
created exclusively, so a pre-existing child is not reused or removed. Only the
entry removes its own fresh temporary parent. Parent/child identities and
unexpected top-level entries are checked before removal; observed replacements
retain the foreign path and the displaced original. The helper does not claim
an atomic filesystem transaction or resistance to arbitrary same-user namespace
changes during recursive removal.

The entry prints its synthetic marker and structured receipt only after the
temporary context has closed successfully. Injected sample, panel, journey and
directory-cleanup failures keep a nonzero exit and never print those success
lines. The panel failure control preserves the original identifying detail.

## Preserved red and intermediate evidence

All rows below have retained logs/JUnit and command/source receipts. Original
failures have not been replaced by later green output.

| Evidence prefix | Observed result | Disposition |
|---|---|---|
| `initial-red` at `ff6851f3` | 15 failed, 2 passed; 3.90 s | Old real entry exits successfully without F8 receipt; helper/lifecycle controls fail because new modules are absent. Existing sample-failure and headless controls pass. This establishes the implementation gap, not a native security result. |
| `first-implementation` | 1 failed, 16 passed; 9.33 s | Cleanup injection was too broad and intercepted the sample's own temporary cleanup. Corrected to target only the entry-owned directory. |
| `ownership-error-red` | 1 failed, 18 passed; 12.57 s | A changed-child finalizer replaced an earlier step error. Original failure is now preserved and the changed workspace retained. Exact intermediate source/test bytes are included. |
| `focused-green` | 19 passed; 12.24 s | Intermediate focused run before the later tooltip and panel-detail controls; not the final qualification source. |
| `affected-source` at `3e0de93f` | 1 failed, 393 passed; 80.48 s | Existing global tooltip unique-What check exposed an inventory/investigation picker collision. |
| `baseline-tooltip-red` at untouched `3faf436a` | 1 failed; 0.37 s | Independent real-dialog registration reproduces the same collision before the F8 change. |
| `tooltip-and-worker-red` at `0bda6edd` | 2 failed, 1 passed; 1.27 s | Owned and unchanged external collision checks fail; a worker exceeding the join budget correctly retains the workspace. |
| `precommit-affected-source` | 397 passed; 79.80 s | A Ruff test-import-order failure prevented the intended commit while verification started separately. Context honestly records dirty source. Patch and explanation are retained; this is not the exact-source acceptance gate. |
| `panel-detail-red` at `560e6dda` plus retained helper bytes | 1 failed; 1.37 s | The first helper lost offending panel details from the old entry. The final two-line restoration follows this control. |
| `committed-affected-source` at `316b0f12` | **398 passed; 74.67 s; zero skips/errors** | Exact final affected gate, clean before and after; unchanged external controls included. |
| `entry-source` at `316b0f12` | Exit 0; 2.76 s; no leftovers | Separate exact entry with Python-level socket/DNS/child-process calls refused; synthetic receipt retained verbatim. |

The tooltip repair changes only the investigation picker's What text to “Choose
the advisory workspace used by this investigation.” The global uniqueness
assertion and inventory wording remain intact.

## Independent lifecycle evidence and final gate

The inventory reviewer independently traced current source `3faf436a` and ran
two authored controls through the real host runner/dialog and worker-owned
ProjectService stores: **2 passed in 1.23 seconds**. During a pending create,
dialog rejection preserves the commit. Host shutdown can drop its callback and
leave `_pending` set after the worker/store have closed. Cleanup therefore checks
actual shutdown, not that flag. Both controls reopen the committed project,
preserve the original desktop service and leave no live task threads. Their
original bytes are retained, SHA-256
`2166cb89a4fdfa303696828bfb00d215af335e6c6afb06acb204fe85d5cb3110`, and both pass
again within the final 398-check gate. This peer review covers the lifecycle seam;
root review of the final F8 candidate remains separate.

The final gate covers the 22 new controls plus desktop audit, actual investigation
service/dialog, candidate panel, host lifecycle/layout/palette/seam, global
tooltips, GUI import isolation, headless CLI/acceptance, optional dependencies,
Windows resource readers, lead construction, current-project inputs and the
three unchanged external controls. There are no selected exclusions or skips.
Normal Ruff over `src tests tools` and `git diff --check` pass. That normal Ruff
result is not a claim that the separately retained strict security lane is green.

Runtime: Python 3.12.14, PySide6 6.12.0, pytest 9.2.0, pytest-qt 4.5.0,
Ruff 0.17.5 and `QT_QPA_PLATFORM=offscreen`. Every process inherits an absolute
`PYTHONPATH` for this checkout; the new entry child also asserts the actual
imported `__main__.py` path. This avoids the shared venv's older editable checkout.

Raw evidence is under `/workspace/scratch/c7a9e8d98848/qa/kb-selftest`, with the
unchanged peer packet under `qa/f8-lifecycle-independent`. The adjacent manifest
and evidence archive retain exact payload bytes, including source hashes,
commands, stdout/stderr, all red/green JUnit, historical/reference sources and
the external controls. `run_final_gate.py` records and verifies a clean exact
checkout before and after the replay.

The sealed archive contains **88 verified payloads**, occupies **341,337 bytes**,
and has SHA-256
`3ba01184666062fbd8b041e2d20f2463d46d07977ab73a15c5f8430919e77091`.
The [manifest](kb-selftest-journey-20261118.manifest.json) records every payload's
size and digest; the [archive](kb-selftest-journey-20261118.evidence.zip) was read
back and every member verified before this QA commit.

No remote mutation, target download/execution, paid/native experiment, live
provider call, frozen-outcome change or release was performed. This receipt
does not establish real CVE-to-function accuracy, native comparator behavior,
Windows UI/DPI, extracted-package compatibility or OS-level network isolation.
