# Full serial checkpoint verification — f005c66

**The full suite did not pass:** 18,702 passed, 3 failed, 138 skipped, 7 xfailed, 1 warning. No retries, test suppressions, assertion changes or product-source edits were made by this verification worker.

Source: `f005c6674e0d7e7e151668494bb9c5a299f2635b`; tree `e214401ccf5d3187cd9c5c17295f2460d9ae5580`; isolated branch `codex/full-verification-20261101`, worktree `/workspace/scratch/142cb233d750/wt-full`. Tracked/untracked Git status was clean before and after the run. This verifies that checkpoint, not later central changes or native Windows.

A fresh Python 3.12.14 venv was created with `--copies` and installed only from this worktree using `-e '.[dev,search,rules]'`. Isolated `-I` imports resolved to this worktree; the executable resolves to the copied venv executable. Protobuf 7.36.2 uses upb; optional search/rules dependencies are installed. Full package and editable-origin evidence is retained in `environment.json`, `pip-freeze.txt` and `pip-install.log`.

Full invocation:

```sh
QT_QPA_PLATFORM=offscreen /workspace/scratch/142cb233d750/full-venv/bin/python -m pytest -q --junitxml=/workspace/scratch/142cb233d750/full-verification-f005c66-20261101/pytest-junit.xml
```

The runner also directed live-status records into this evidence directory and removed inherited Python/pytest override variables; all effective overrides are recorded in `run-environment.json`. Pytest ran serially, with the sole localhost full/performance slot reserved. Start: **2026-11-01 13:02:50.561322 UTC**. Process end: **13:31:48.377143 UTC**. Pytest reported **1,731.42 s**; outer process elapsed **1,737.806725 s**. Return code: **1**.

## First-run failures

| Test | Observed failure and diagnosis |
| --- | --- |
| `tests/test_gui_host_seam.py::test_new_code_uses_no_forbidden_api[event-pumping]` | The unchanged GUI architecture gate detects seven `processEvents()` calls in `src/patchtrace/gui/qt/kb_selftest.py`, lines 41, 45, 131, 187, 194, 212 and 229. This is not the benchmark tool: the guard scans `src/patchtrace/gui`. Requires an owner-reviewed structural/contract repair; no gate was weakened. |
| `tests/test_network_consent_guard.py::test_a_local_unix_socket_is_not_network` | `_socket.socket.__init__` raises `PermissionError: [Errno 1] Operation not permitted` for AF_UNIX. This matches the documented host-denial baseline. It remains a failed test, not a pass or suppressed skip. |
| `tests/test_unified_worker.py::test_same_id_means_same_content_for_refused_inputs` | Only the final `SourceRef.entry_id == 'foreign'` assertion fails. Earlier partial/refusal, byte-determinism and changed-result-ID assertions passed. SPEC31's identity amendment now defines a derived content identity for this field. The literal expectation appears stale relative to that contract; an owner must verify provenance requirements before changing the assertion. No loss-of-provenance conclusion is inferred solely from this failure. |

Full failure texts are preserved in `failures.json`, the original log and JUnit. The failed worker's temporary manifests were listed after the run, but its pytest temporary directory vanished before the copy attempt; that limitation is recorded in `failure-artifact-retention.json`. No rerun was made to replace the original evidence.

All 138 skip and 7 xfail nodes/reasons remain in `pytest-junit.xml` and `pytest-summary.json`. Live acceptance remains blocked where native engines/toolchains are unavailable; blocked messages are retained, never promoted to passing native evidence. The one warning is the deliberate duplicate-ZIP-entry negative control in `test_offline_bundle.py::test_rejects_duplicate_zip_entries`.

## Other required checks

| Check | Result |
| --- | --- |
| Whole-tree `python -m ruff check src tests tools` | Pass |
| `python -m pip check` | Pass |
| Protobuf runtime/pin checker | Pass |
| General schema regeneration | 72 generated files byte-equal to committed files; zero drift |
| KBC schema generator `--check` | Pass |
| Final `git diff --check`, clean source | Pass |

General schemas were generated in a separate evidence subdirectory and compared to committed files, so verification did not rewrite the source tree. Per-check commands, timestamps, source states, return codes and log hashes are retained in the corresponding JSON receipts. `verification-summary.json` aggregates those records. `host-during-run.json` is explicitly a during-run sample, not a retrospective start-of-run condition.

Original full log SHA-256: `89d914c7f571027a06ead026c37ca3643cf90e0f9fbb795e326181cf1706796e`.
JUnit SHA-256: `e9629e760101020c053b2d574d641b975316c752bc11686e7e669709c6b7a98e`.
