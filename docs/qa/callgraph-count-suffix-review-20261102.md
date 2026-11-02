# Independent review: #105 BUG-CG-2 guarded count suffix

No blocking findings within the reviewed bounded slice.

- Source: `424e59dbc800ff7419c2fe47a3eb7f642a5a49b4`
- Tree: `aadafe9d00c9d63fe96ab0c6dda47482073bc437`
- Parent: `ab8476ca5401c0e3f401c59328301192ed57eeb7`
- Clean worktree: `/workspace/scratch/142cb233d750/wt-huge-callee`

## Scope and reasoning

- Count suffix recognition now requires a complete ASCII-decimal suffix. Integer-conversion ValueError returns no inferred suffix, preserving the existing unresolved-label path instead of aborting snapshot construction.
- No digit threshold or production interpreter-policy override was introduced. Existing exact-record resolution precedes the suffix rung, so legitimate long numeric-looking function names still resolve exactly.
- Both caller and callee ingestion preserve their original raw strings, distinct node identities, and edge orientation even when display labels truncate to the same text.
- ALGO changes from callgraph/1 to callgraph/2 so cached derived snapshots cannot reuse the previous resolver policy. The integration specification and inventory match this change.

## Independent validation

- 220 passed in 3.85 seconds, including isolated 4,300-digit runtime guard, actual normalized 5,000-digit caller/callee labels, exact-record precedence, and cache invalidation.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_callgraph_count_suffix_guard.py tests/test_callgraph_labels.py tests/test_callgraph_input.py tests/test_callgraph_pairing.py tests/test_callgraph_snapshot.py tests/test_callgraph_delta.py tests/test_callgraph_dot.py tests/test_callgraph_cli.py tests/test_callgraph_schemas.py`
- Independent child control passed: 10, 200, 639, and 640 digit counts accepted; 641 and 5,000 digits return no suffix; process policy remains 640.
  Command: `PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -X int_max_str_digits=640 /workspace/scratch/142cb233d750/reviews-resume/new_review_controls.py suffix`
- Independent child control passed: even 5,000 digits are accepted when the caller explicitly disables its own conversion guard; implementation leaves that policy unchanged, proving no arbitrary internal cap.
  Command: `PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -X int_max_str_digits=0 /workspace/scratch/142cb233d750/reviews-resume/new_review_controls.py suffix`
- Changed source/test Ruff and diff checks passed; exactly seven changed files.
  Command: `/workspace/scratch/142cb233d750/venv/bin/python -m ruff check src/patchtrace/callgraph/labels.py src/patchtrace/callgraph/snapshot.py tests/test_callgraph_count_suffix_guard.py; git diff --check HEAD^ HEAD`

## Limits and integration

- The two independent boundary controls explicitly configure isolated reviewer child processes only; no application or test-runner interpreter policy is changed.
- Review is restricted to BUG-CG-2; other callgraph findings such as CG-3 remain separate.
- No full suite, performance run, native disassembler execution, or unrelated #105 closure claim.

The sibling JSON binds every changed file and the retained independent control script by SHA-256. No repository source edits, remote mutations, or GitHub approval were performed.
