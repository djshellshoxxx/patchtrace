# Generation 33 qualification record — 2026-11-20

## Final combined result

Exact clean source **`bbdef5a62482bc6e0709f2f5e842d651a4b91a6b`**, tree **`a8ef4316a88ab58619d966744e26b0067d66ff33`**, passed **606 tests and skipped one native Windows junction test**, with zero failures/errors in 49.33 seconds. The 30-file selection contains 607 unique cases and covers five product repair areas plus native-cache diagnostic retention. Whole-tree Ruff, `pip check`, and complete-range whitespace validation passed. [Final receipt](evidence/generation33/final-combined/receipt.json), [JUnit](evidence/generation33/final-combined/combined.xml), and [output](evidence/generation33/final-combined/pytest.log) preserve commands, source hashes and unchanged clean initial/final state.

The [final source integration review](evidence/generation33/final-source-integration-review-bbdef5a6.md) accepts all 35 blob/mode comparisons and the precise scope. The [cache diagnostics independent review](evidence/generation33/cache-independent/review.md) adds 48 distinct controls to the author's 113-case selection; those 113 maintained cases overlap the final 606. Earlier 397/493-case selections below are historical overlapping checkpoints, not additive coverage.

The diagnostics change fixes loss of acceptance evidence. It preserves original Java probe arguments/results/exceptions and the 15/30-second retry policy, restores its temporary observer, refuses existing output paths, bounds/redacts records, and retains all cache assertions. Workflow conditions, triggers, matrix and budgets remain unchanged; only an explicit diagnostic option and artifact glob were added. The native unknown-Java/cache failure remains open, as does the prior unexplained full-suite SIGKILL. This receipt does not establish native, full-suite, release or empirical accuracy acceptance.

The local/source histories are retained in [verified bundles](evidence/generation33/continuation-history.json), with all 13 local commits through the tested checkpoint and the original worker commit. All changes after this checkpoint must be documentation/evidence only and independently checked against the recorded source hashes before publication.

## Earlier five-area result

Exact clean source `71b535cc5c1ca0ccc6762831a5d8a137644d14fc` / tree `7a30e0a2c15b17def021143bae6c6ad0d69958cb` passed **493 cases and skipped one native Windows junction case**, with no failures or errors, in 44.94 seconds. The deduplicated selection contains 26 files and 494 unique cases. Whole-tree Ruff and complete-candidate whitespace validation passed. [Receipt](evidence/generation33/combined/receipt.json), [JUnit](evidence/generation33/combined/combined.xml), and [output](evidence/generation33/combined/pytest.log) are retained. The newly recovered five acquisition source/spec/test files match independently reviewed donor `ae67122c` exactly. Earlier four-area results below remain separately source-pinned and overlap this run.

The [16:41 hosted snapshot](evidence/generation33/ci-final-1641.zip) records an unresolved initial-head native cache gate failure: `java=unverified`. A same-source counterpart passed, but no cause is established and no failed result is erased. The missing diagnostic artifacts were addressed by the independently reviewed retention repair; this does not repair or qualify Java/cache verification itself.

Four legacy relative links in the historical QA record were already broken before this work. Their actual documents were recovered at retained source commits and their GitHub bytes verified against local Git blobs; the links now point to those immutable original versions. [Independent link review](evidence/generation33/generation33-historical-link-review.md) and [read receipts](evidence/generation33/generation33-historical-links-remote.json) preserve the correction. The first broad link validation failed on these inherited links; final validation is recorded separately after correction.

## Earlier four-area result

The combined reviewed candidate at `ad8916944a697985be3e472cd57f2e15f0a263bc`, complete tree `23ad5e5230e539df4727f5b2235f107a3f895a98`, passed **397 affected tests with zero skips, failures or errors**. Whole-tree Ruff and dependency validation passed. Initial/final tracked source and working-tree status were identical and clean. These are focused integration results, not full-suite, native-platform or release acceptance.

The [combined receipt](evidence/generation32/combined/receipt.json) contains the exact 18-file selection, source/test hashes, commands and environment. [JUnit](evidence/generation32/combined/combined.xml) records 397 unique cases; [pytest output](evidence/generation32/combined/pytest.log) reports 56.67 seconds. Wrapper wall time was 58.514756 seconds. The [Ruff](evidence/generation32/combined/ruff.log) and [dependency](evidence/generation32/combined/dependencies.log) logs remain separate.

The four named repairs are linked-worktree receipt identity, stopping pending Search debounce on Cancel, binding stored Strings evidence to its current source while retaining valid cache origins, and refusing queued Strings filtering after shutdown. The last source is tree-identical to independently reviewed `9997aaa9`. Documentation/evidence changes after qualification do not modify source, tests, tools, dependency pins or workflows; final identity checks must confirm that before publication.

## Full-suite attempt remains incomplete

Earlier frozen source `a024f9ece556daa6e4f095c52fe9a8cc4c31ce28` / tree `1eb4f2197e22c9e46d25bded163ee241835572e6` ran the required unsplit offscreen suite. It ended by SIGKILL after 563.257508 seconds, with child return -9 and launcher exit 137. Its source remained clean and unchanged. No terminal test summary, traceback or JUnit was produced. The partial 3,635 dots and ten skip markers are not a completed test result.

The retained child high-water RSS is 1,113,696 KiB. That statistic does not establish an OOM kill or a host quota. The launcher has no timeout, and postmortem resource readings are not kill-time evidence. Kernel/cgroup termination evidence was unavailable in the exposed environment. Origin of the signal remains unestablished.

One collection-only observation found 23,936 unique node IDs on the same frozen source. It localized the last recorded marker and next expected node to two adjacent display-text cases, without proving which phase was active at termination. One fresh diagnostic ran exactly those two unchanged cases, once. Both passed; no 60-second diagnostic wall limit or 768 MiB sampled process-tree RSS limit triggered. The original three-second operation assertions remained unchanged. Sampled process-tree peak was 83.77 MiB; initial fixture setup was separate from the operation timing.

No source fix, larger input, repeated stress run or weakened gate was justified by that result. The later Strings lifecycle repair is unrelated. Testing for this triage stopped after the two cases.

The [full triage archive](evidence/generation32/full-suite-triage.zip) is self-contained for the 16 manifest-listed artifacts plus its manifest. It preserves original logs/receipts, launchers, ordered node IDs, phase/resource observations and a detailed report with hypotheses distinguished from facts. [Archive verification](evidence/generation32/triage-archive-check.json) confirms every stored payload against its original bytes. Its SHA-256 is `dd89e6d45644e84da06c1d36e1830775bea0f1bb34f65bb3d7ae2d193783d849`.

## Independent review and artifact correction

The [Strings reviewer](strings-shutdown-independent-review-20261120.md) accepted the two-line shutdown guard after 100 passes: 96 maintained cases replayed and four distinct new lifecycle cases. No source blocker was found. The reviewer verified preserved loaded state, ordinary pre-close filtering, stale delivery rejection and unrelated channel service on the shared runner.

The original complete worker commit did fail whitespace validation at ten lines of its raw failure log. The original `baseline.log` bytes are now stored as deterministic gzip, with decompression equality checked against SHA-256 `138912449de8dd57c7178a43292e63608259fec4868de589ae40f30bbf2b3a8c`. The [correction record](evidence/generation32/evidence-log-format-correction.json) and [original diff-check output](evidence/generation32/original-worker-diff-check.log.gz) retain that failure. The worker's original commit is retained in its incremental Git bundle. No failure content or assertion was normalized away.

The earlier independent integration review's overlap/replay findings and the later publication documentation audit are also preserved in the generation32 evidence directory. Corrected facts include six original bundle commits, the actual draft publication mapping, completed bounded g29 input review, and the terminal incomplete local-run state. Historical receipts remain source-specific.

## Hosted and release gates

The [16:13 UTC hosted snapshot](evidence/generation32/patchtrace-ci-pr342-20261120-1614.md) records exact initial PR342 head `5cc3f2a`, its tree-equal proposed merge, queued/running QA/Qt/native jobs and one successful native Windows clean fixture job. Its logs were preserved with compression hashes. This snapshot predates the shutdown fix and cannot qualify its final publication.

The same snapshot records generation29 Linux pytest: 23,808 passed, 51 skipped, six xfailed, followed by Ruff success. Remaining predecessor jobs were still running. Earlier main Linux package failure was an apt transport prerequisite failure. No current-source success is inferred from either predecessor observation.

Main-merge eligibility and release readiness remain false. Resolve live final-head CI and preserve all failures. The next aggregate qualification must retain its source identity and suitable termination/resource telemetry; no additional unchanged local rerun is implied here. The [generation32 handoff](../engineering-handoffs/generation-33-20261120.md) lists the remaining engineering and native gates.

## Final presentation verification

The complete candidate range also exposed extra terminal blank lines in four CI report/JSON presentation copies, including two inherited generation30 files. Their exact original bytes and original manifests are retained in [presentation-eof-originals.zip](evidence/generation32/presentation-eof-originals.zip). Only extra terminal LF characters were removed from the browsable copies; parsed JSON values are identical. [The correction mapping](evidence/generation32/presentation-eof-correction.json) records old/new hashes, and current copy manifests explicitly retain both identities. Earlier source-pinned receipts remain historical records for their original bytes.
