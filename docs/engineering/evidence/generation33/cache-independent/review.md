# Independent review: native cache diagnostic retention

**Decision: no blocker found within the diagnostics-only scope at frozen commit `8cff43a2fc78c2e150fbdbabc14a977c473811a4`.** The change is suitable for integration subject to the parent task's remaining source-specific qualification. This review does not qualify native cache acceptance or release readiness.

## Source and isolation

| Identity | Value |
|---|---|
| Reviewed commit | `8cff43a2fc78c2e150fbdbabc14a977c473811a4` |
| Reviewed tree | `824f444e89894aee7e951e2708fb2f53b64e9c62` |
| Parent baseline | `71b535cc5c1ca0ccc6762831a5d8a137644d14fc` |
| Reviewer | `/root/ci_qualification` |
| Isolated checkout | `/workspace/scratch/b1d1356aa953/patchtrace-cache-review` |
| Test interval | 2026-11-20 16:58:46–16:58:49 UTC |

The detached reviewer checkout was clean before and after verification. No root or author worktree was edited. The production `src` tree is unchanged from the parent baseline. In particular, the backend, process supervisor, and raw cache blobs remain `001a08b43c78537bf48b2b76d858f92d54e30d54`, `8f559f1b7846019a2eba96408c579a304648ab44`, and `fd8ae260a9a9e40b61db84d2d2940ea0576a68e4`, respectively. Exact hashes for all nine changed files and the quality commands are in [review.json](review.json).

## What was reviewed

The harness now accepts an explicit create-only diagnostics directory, observes existing Java version subprocess calls while a comparison is running, and retains bounded JSON receipts for each attempted run and the final acceptance result. Its temporary observer is restored by the context manager on normal returns and exceptions. The workflow adds the option to the raw-cache step and a JSON glob to the existing `always()` uploader.

The three existing acceptance conditions remain intact: the first analysis must be fresh, the second must be a cache hit, and the raw bytes and normalized matches must agree. The 900-second comparison budget, Java helper's existing 15/30-second retry bounds, cache admission rules, workflow matrix, triggers, gates, and upload condition remain unchanged. The YAML comparison reconstructed the entire previous workflow with only the invocation and artifact-glob changes and matched the new workflow exactly.

## Independent verification

**161 passed in 2.83 seconds, return code 0.** This includes **48 controls authored independently for this review** and a fresh run of the 113 affected repository tests on the frozen checkout. The repository selection comprised 11 new diagnostic tests, 6 Java-version tests, 51 backend-progress tests, and 45 workflow tests.

| Independent control group | Cases | Verified behavior |
|---|---:|---|
| Process observation | 6 | Original argv, positional values, environment and cancellation objects reach the callable; exact result and exception objects are preserved; ordinary errors, interrupts and exit exceptions restore the original callable; non-version calls bypass observation; capped observations do not cap execution; unreadable result diagnostics do not replace the result. |
| Existing Java helper | 7 | With and without the observer, success, timeout then success, two timeouts, cancellation, nonzero exit, launch error and absent Java produce identical outcomes and probe counts. The original 15/30-second budgets and 4096-byte log limit are forwarded. No real subprocess is started. |
| No-option compatibility | 9 | Direct differential execution against the original baseline matches stdout, exception class/message, project lifecycle and comparison configuration for success, first-hit rejection, second miss, byte mismatch, match mismatch, failed run, comparison exception, normalization exception and creation exception. Temporary roots are removed. |
| Failure receipts | 8 | Enabling diagnostics preserves each original failure and records `status: failed`; first and second receipts exist only when their corresponding attempts occur. |
| Destination refusal | 4 | Existing directory, file, directory symlink and dangling symlink are refused before analysis. Existing bytes and links remain unchanged. These filesystem controls ran on Linux. |
| Allowlist, redaction and size | 1 | Unknown settings, origin fields, event fields and raw bodies are omitted; only the last 64 events remain; Unicode tails remain within the character and document-byte caps; credential-shaped event content is redacted. Other observer controls cover credential-shaped probe output. |
| Strict numeric values | 8 | Booleans, nonfinite numbers, oversized integers, strings and null cannot produce invalid numeric JSON. |
| Exclusive bounded writes | 3 | Oversized or nonfinite documents are refused and existing report bytes are preserved. |
| Secondary write failure | 1 | A diagnostic destination error preserves the original comparison exception and reports only the write-error class, without leaking its credential-shaped message. |
| Workflow semantics | 1 | Only the intended command argument and artifact glob change. |

Changed-file Ruff and the complete baseline-to-commit whitespace check pass. The production-source comparison is empty. No native analyzer or target binary was executed; all project/process activity in the review controls was injected.

## Remaining blocker and limits

The earlier native push failure remains a real failure of initial published source `5cc3f2a540f2e49e8b86e20decf7d4f62ce89d0a`: [run 44770501981, job 136406567877](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44770501981/job/136406567877) failed with `second run was not a cache hit; java=unverified`. That attempt did not retain the needed Java probe observation. Its underlying cause remains unresolved, and the passing counterpart does not erase it.

This change repairs diagnostic retention only. It does not alter Java verification, admit an unknown runtime, bypass an assertion, or establish a native pass. Native acceptance and the remaining CI/release gates must be evaluated against the eventually published source. Initial-head CI does not qualify this commit, `71b535cc`, or a later integrated commit.

No workflow was triggered, retried or merged, and no remote state was mutated during this review. The source-specific fake controls are sufficient for the bounded implementation review; no broader scan or additional local test run was performed.

## Evidence

- [Independent controls](test_independent_cache_diagnostics.py)
- [Raw test output](review-tests.log)
- [JUnit results](review-tests.xml)
- [Exact test command and source receipt](review-tests-receipt.json)
- [Source hashes, quality results and review decision](review.json)
- [Original harness used for differential controls](baseline-live-cache-check.py)
- [Original workflow used for the semantic comparison](baseline-live-backend.yml)

The evidence manifest records file byte counts and SHA-256 values. The independent tests live outside the repository, so no contributor source or repository test file was changed to obtain these results.
