# Generation 4 independent raw-alignment review

Reviewed implementation: `46afcb216ef2b9430ce95b32e00944e7eaaa99ac` on
`codex/raw-alignment-recovery-20261119-4c8d`, based on `afa1af3c`.
Review date: 2026-11-19. Review branch:
`codex/adversarial-20261119-4c8d`.

**Finding:** no new blocking defect found in the recovered paired-window desktop
slice. Six independently authored offscreen controls passed in 3.28 seconds.
This review supports integrating that slice; it does not qualify the later
combined source, native Windows behavior, manual accessibility, or a release.

## Scope and source identity

Read the repository instructions, module index, generation 1 handoff, current
consolidation inventory, and SPEC-26 byte-representation contract. Inspected the
alignment backend, pure row model, verified-reader lifetime, TaskRunner event
delivery, transactional project adoption, and the complete recovered controller
and `ui.py` diff. The patch preserves `make_inspection_thread` and
`publish_metadata_cache`; it does not replace the current inspection path with
the donor's older implementation.

The independent test module asserts both the absolute imported controller path
and the checkout's exact HEAD, then rejects tracked changes to source, tests, or
specifications. This avoids accidentally testing the review worktree's older
code. The final run used the clean implementation checkout above.

## Independent controls

| Boundary | Control and observed result |
| --- | --- |
| Late successful worker from a previous project | Read real verified bytes, block delivery, adopt a replacement project through `MainWindow.set_service`, allow the replacement alignment to complete, then release the old result. The replacement result, displayed text, status, and copied project provenance remain unchanged. |
| Late failed worker from a previous project | Repeat that ordering, then raise from the old worker. Real TaskRunner delivery discards the error; it does not replace the current status or write the old failure into the log. |
| Reader ownership across adoption | In both ordering controls, old borrowed readers return the typed `closed` error after adoption. Replacement readers remain open and return the expected PE signature after stale delivery. |
| Copy from a display containing an insertion gap | Create synthetic PE inputs with different physical overlay bases and an inserted prefix before project ingestion. In Hex and Binary, select all rendered rows, including span headers and the display-only gap, and invoke Ctrl+C. Independently decode the copied byte columns and compare every byte, starting offset, window digest, artifact digest, and project/revision provenance. |
| Context-menu copy | Repeat the same exact-byte check in both representations through actual viewport context-menu events and their actions. |
| Retained stale menu action | After each copy case, change an offset to invalid text, request alignment, then trigger a retained prior menu action. No result remains and the clipboard sentinel is preserved. |

There are two lifecycle cases and four representation/copy-route cases. No donor
test helper is imported. The underlying synthetic artifacts are never executed.

## Evidence and reproduction

- Independent controls: [test_raw_alignment_peer_controls.py](evidence/test_raw_alignment_peer_controls.py).
- Final result: [raw-alignment-peer-result.txt](evidence/raw-alignment-peer-result.txt).
- Implementation author's separate report: `raw-alignment-recovery.md`, in the
  reviewed commit, records its baseline and affected-suite results. Those
  counts were not independently rerun here and must not be added to this review's
  six controls as an aggregate-suite result.

From this review worktree, with the implementation checkout still at the exact
SHA above:

```sh
QT_QPA_PLATFORM=offscreen \
PATCHTRACE_REVIEW_SOURCE=/workspace/scratch/4c8dc848d760/pt-raw-alignment \
PATCHTRACE_REVIEW_SHA=46afcb216ef2b9430ce95b32e00944e7eaaa99ac \
PYTHONPATH=/workspace/scratch/4c8dc848d760/pt-raw-alignment/src \
/workspace/scratch/4c8dc848d760/venv/bin/python -m pytest -q \
  -o pythonpath=/workspace/scratch/4c8dc848d760/pt-raw-alignment/src \
  docs/engineering/evidence/test_raw_alignment_peer_controls.py
```

The explicit pytest `pythonpath` override is necessary because the repository
configuration otherwise prepends the review worktree's own `src`. An initial
invocation exposed that harness mistake at import time. A second preliminary
invocation passed the lifecycle cases but stopped the copy fixtures at the
existing persisted-context hash validator: the fixture had altered sample
artifacts after creating interpretation evidence. The final fixture instead
creates the overlay inputs before ordinary project ingestion and imports
synthetic match records with their correct input hashes. No product correction
or validation bypass was required.

The peer test file passes Ruff; `git diff --check` is clean. No shared QA/task
ledger or implementation-worker file was modified. Existing Linux forced-export
publication and native Qt qualification blockers are unchanged and are outside
this review's findings.
