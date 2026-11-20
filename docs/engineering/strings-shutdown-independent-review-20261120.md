# Independent Strings shutdown review — 2026-11-20

## Disposition

**Accept the code for bounded integration. No source blocker found.** One evidence/reporting correction is required: the complete proposed commit fails `git diff --check` because the retained raw baseline log includes trailing whitespace. The coordinator has acknowledged this and will preserve the original bytes in deterministic gzip, update evidence paths and record both the original failure and the subsequent artifact-only correction. No source changes are needed for that finding.

The reviewer is `generation30_receipt_review`, independent of the source author `workflow_repair`. Earlier work by this reviewer concerned the unrelated receipt identity helper. This review does not approve a full qualification, native Windows acceptance, release or merge.

## Exact source and scope

- Worktree: `/workspace/scratch/b1d1356aa953/patchtrace-strings-ui`.
- Reviewed commit: `9997aaa912d484c63c35582f8de547735f6ac0bb`.
- Parent: `5cc3f2a540f2e49e8b86e20decf7d4f62ce89d0a`; matches the requested published base.
- Tree: `23ad5e5230e539df4727f5b2235f107a3f895a98`.
- Worktree was clean before and after verification; recorded HEAD, tree, tracked-file hashes and status were identical.
- Read repository `AGENTS.md`, the Strings module-index entry and the relevant WB3 GUI lifecycle contract. Reviewed the full seven-file diff.
- Production change: two added lines at the start of `StringsController._refilter()` return when `self.closed` is true. The remaining changes are one lifecycle-contract paragraph, two parameterized maintained regressions and authored evidence/reporting.

| File | SHA-256 |
|---|---|
| `src/patchtrace/strings/qt_panel.py` | `134f17a90e0310606b29a29440d727775f2153a6debca4ff0beb30b0f77f55db` |
| `tests/test_ui_strings_panel.py` | `1da0d373593ac91b4827ae339d594c25ea36158a6c04d9e94ac2dba15a0453ed` |
| `docs/specs/program-e/WB3-integration-plan.md` | `5c2da37d38ba51e3043c7609aa3faffff9d349d39758272012161a02c624a06c` |
| `src/patchtrace/gui/qt/tasks.py` | `f94759608980ccc096470ec7efa013f043146579911c680835d346c61a7b4bfe` |

The authored baseline/repaired-source/regression-file hash fields all match independently read bytes. The baseline source hash is `576ae0bf2c9d04b25ba2755ebd5c62d80fc300f0645cea8fa7dba5b12247692f`. The preserved raw baseline log hash is `138912449de8dd57c7178a43292e63608259fec4868de589ae40f30bbf2b3a8c`.

## Reasoning and scope checks

The new check runs before reading the panel's filter widgets, rendering an empty state or submitting `strings-view` work. It therefore ends filter preparation admission when the controller closes, in both shared-runner orderings. Normal open-controller execution follows the same existing code path.

`shutdown()` already sets `closed` and advances the generation while cancelling both Strings channels. `_viewed()` and `_loaded()` retain their generation, project-key and closed-controller checks. TaskRunner also rejects cancelled/superseded deliveries. The fix complements those existing delivery guards by refusing new work after shutdown.

No loader, parser, scanner, matching, persistence, export, provider, subprocess, schema or analysis-capability implementation changed. Tests use synthetic in-memory rows and offscreen Qt. Shared runner ownership remains intact: closing Strings cancels its channels, while an unrelated channel continues to deliver when the runner stays open. The scope does not claim all conceivable post-close widget actions are disabled; it specifically covers filter-preparation task admission and the existing late-result protections.

## Independent verification

One bounded run selected the same three affected maintained files used by the author, together with four reviewer-authored controls:

- `tests/test_ui_strings_panel.py`
- `tests/test_ui_strings_run.py`
- `tests/test_gui_tasks.py`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/test_strings_shutdown_peer.py`

**100 passed in 35.08 seconds**, exit 0. The process wrapper recorded 38.444 seconds including startup/teardown. Exact command, environment, timestamps and before/after source identity are in `strings-shutdown-peer/receipt.json`; raw output and JUnit are preserved beside it. `QT_QPA_PLATFORM=offscreen`; `PYTHONPATH` explicitly names this worktree's `src`, `tests` and root. Interpreter: `/workspace/scratch/b1d1356aa953/patchtrace-venv/bin/python`.

**Overlap:** 96 cases are a fresh replay of the author's same affected selection, not 96 additional unique cases. Four extra reviewer-authored cases are distinct:

1. A queued filter control change before shutdown still submits one `strings-view` request and changes the visible row count.
2. A real completed filter worker's delayed GUI result applies while the controller remains open.
3. The same delayed result is ignored after controller shutdown while the shared runner remains open; a separate channel still completes.
4. The same delayed result is ignored after controller and runner shutdown.

The result-delivery controls retain the actual production callback after a real worker has completed, queue it through Qt and then exercise the requested closure ordering. Closed cases preserve the prepared result and visible rows; all cases preserve loaded source rows, keys, ID mapping and the project object, with no navigation or copy side effects. The positive case demonstrates that the delayed result would otherwise update the model.

The maintained selection separately verifies queued filter input after shutdown with the runner open/closed, ordinary filtering, scan cancellation/idempotent shutdown, stale-project and superseding-scan results, shared TaskRunner lifecycle and ordinary Strings run behavior. No full-suite rerun was performed. The author's baseline failure log was inspected and its source hashes verified; it was not independently replayed, because this review did not modify source.

Scoped Ruff passed for the production file, maintained test file and independent test file. Full commit-range whitespace validation exited 2 at ten lines in the unmodified raw baseline log only; details are recorded in `checks.json`. This is an evidence-format/reporting finding, not a source-test failure.

## Bounded retained-history check

`git log --all --format=%H -- src/patchtrace/strings/qt_panel.py` reported eight file-touching commits. The reviewer extracted each historical `StringsController._refilter` body and source blob. There are exactly two distinct method bodies in that returned history: all seven prior versions share the original unguarded method, and `9997aaa9` adds the guard. The earlier Search debounce repair belongs to a different controller. No retained duplicate of this Strings method fix was found in that bounded history inspection.

The author's `git log -G 'def _refilter|def shutdown|strings-view'` alone is insufficient to discover body-only changes such as the new guard. This review uses the full file-history result and method extraction instead. Full hashes and extracted method bodies are retained in `strings-shutdown-peer/history.json`.

## Evidence files

- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/receipt.json`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/checks.json`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/pytest.log`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/results.xml`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/test_strings_shutdown_peer.py`
- `/workspace/scratch/b1d1356aa953/strings-shutdown-peer/history.json`

These checks establish the ordinary Strings lifecycle fix on the reviewed Linux/offscreen source. They do not close unrelated export ownership, native Windows, external-tool, manual UI, full-suite, packaging or accuracy gates.
