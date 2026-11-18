# Saved-search delayed Build repair — 2026-11-18

## Finding and correction

Root independently found that an index build started for `old_query` could finish
after recent text had been recalled and submit the newly displayed text without
Enter. The original implementation source was
`e705974b0c8a13be0942a172b93bb1cdfa74895f`; its prior 374-test selection did not
exercise this event order. That historical result is retained unchanged.

Repair source: **`c30c791190abed20ec1424478c13add8133e5929`**. Build captures the
query generation alongside the existing project epoch. Its completion still clears
progress and probes coverage, but automatic query submission requires that captured
generation to remain current. Recent recall already resets the query generation.
An unchanged explicit Build retains its previous automatic query behavior.

The regression blocks a real TaskRunner build using events, recalls recent text,
releases the earlier build, observes coverage completion and no search, then sends
Enter and observes the requested query. Its parameterized positive control leaves
the query unchanged and verifies Build still submits it. No settings, storage,
schema, tooltip or other feature changes accompany this repair.

## Recorded results

| Check | Result |
| --- | --- |
| Original independent reproducer | **1 failed in 0.92 s**, retained verbatim |
| Authored regression before repair | **1 failed, 1 passed in 1.53 s** |
| Expanded affected selection after repair | **376 passed in 16.97 s** |
| Author replay of the unchanged independent reproducer | **1 passed in 0.82 s** |
| Whole repository Ruff / whitespace check | **Passed / passed** |

The affected selection includes saved storage/GUI/CLI, original search UI/query,
tooltip and unchanged host-seam tests. Selections overlap; counts are not additive.
Every subprocess explicitly selected this worktree's source. This is offscreen
Qt and synthetic-project evidence, not native/manual Windows acceptance. Root's
independent recheck and combined publication gates remain separate.

[Manifest](saved-search-build-race-20261118/manifest.json) records the source and
receipt hashes and exact commands. [Raw evidence](saved-search-build-race-20261118/raw-evidence.zip)
retains the original independent source/log/JUnit, authored red run, affected green
run, independent reproducer replay and Ruff output. The original QA archive is
unchanged.
