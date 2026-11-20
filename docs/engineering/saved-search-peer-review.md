# Independent saved-search recovery review — 2026-11-19

Reviewed source: `f632e50655b47a71aff314cdba941641356d16a3`, based on
`c9fd07798fa1cead691776512eb619eb464b768d`. The integrator reviewed the six
changed production modules, the WB1 contract additions, and the donor and
baseline evidence recorded in `saved-search-recovery-20261119.md`.

## Independent controls

`evidence/test_saved_search_peer_controls.py` checks 60 valid query/mode
combinations for preservation of non-text clauses and a saved-store round
trip; a project revision change inside the save-name modal; and save, run,
and delete after controller shutdown. The modal test checks that the same
project ID with a newer revision still refuses the write. Shutdown controls
check both persistence and execution remain inert.

Run from the isolated candidate worktree, with its `src` and `tests` on
`PYTHONPATH`, using the shared Python 3.12 validation environment and Qt
offscreen: **5 passed in 0.67 seconds**. Raw output is retained in
`evidence/saved-search-peer-result.txt`. A worktree-name assertion used to
verify imports during the initial local run was removed so the controls can
be replayed from any checkout.

The first harness run was **1 failed, 4 passed** because the reviewer used
`is:changed`; the actual grammar accepts `is:modified`, `added`, `removed`,
and `unchanged`. This was a test-fixture mistake, not a recovered-product
failure. The original output is retained in
`evidence/saved-search-peer-invalid-fixture.txt`. Only that query fixture and
the path-specific import assertion were corrected before replay.

## Review result

No blocking defect found. Canonical query preparation validates before
rewriting filters, preserves quoted tokens, and reparses the effective
text. Execution reparses stored text with the validated mode rather than
trusting a stored AST. Modal operations capture owner epoch, project,
revision, and service identity. Result/build generation invalidation keeps
recent-text recall inert until submission.

This is independent source and offscreen boundary review. It does not
qualify native Windows, manual accessibility, or the combined full suite.
