# Independent review: C4 and Windows Intel integration

## Verdict and immutable source

**No blocking findings in the bounded integration delta.** The candidate exactly combines the completed C4 snapshot with the independently reviewed Intel Windows identity repair. Root combined qualification and fresh applicable hosted/native acceptance remain separate gates.

| Identity | Value |
| --- | --- |
| Reviewed merge | `6bf79feffe68a9fdc1293a69900320e12be662bc` |
| Reviewed tree | `dc659c7ef80e317b6c13c120e09f47c5d313f3ca` |
| First parent, reviewed Intel repair | `d628749401f61d3653b5e066ff38245b938c5dcd` |
| Second parent, C4 final records | `39a95c549d48eb523e9efdfda394bb9f184e2b16` |
| C4 final tree | `f53e92d6bc128c929295f6baf3c6241081ee6ed2` |
| C4 reviewed/tested code | `111803d54cfebc1b779f4832a069904b3ee91a7c` |
| C4 reviewed/tested code tree | `d3264bf26f83d039fa212c26b47c094f86691c3f` |
| Common published baseline | `daee337c48c63dda8aeac149c407e900c79dcc86` |

The reviewer used a separate clean checkout, `/workspace/scratch/837fe19aae3a/review-native-c4`, and a dedicated interpreter whose source binding was independently verified with `python -I`. No candidate source, C4 worktree or C4 ref was modified. No remote mutation or workflow dispatch occurred.

## Standards

**0 findings.** The merge makes no resolution edits. Its complete tree is the exact union of two already reviewed inputs. The two ordered parents are verified. C4's 27 changes after its tested code checkpoint contain only documentation/records. Original records, failures, source history and evidence are preserved. The Intel-only whitespace check passes; previously documented raw-evidence whitespace in C4 was retained rather than rewritten.

This review checks integration preservation and narrow runtime boundaries. It does not repeat the completed Build environment, Pages, storage, Action-pin or other feature-internal reviews.

## Specification and source preservation

**0 findings.** The C4 and Intel inputs change 56 and four paths respectively relative to the published baseline, with no overlap. The exact-tree checker compares every path, Git mode and blob in the 4,598-file candidate against C4 plus precisely the four Intel changes. There are **zero missing, extra or differing paths**.

Consequently, the candidate preserves:

- All C4 production files, workflows, locks, tests and specifications outside the intended four-file Intel delta.
- All four Intel repair files exactly, including the Windows fixed synthetic identity and its maintained privacy assertions.
- The complete Pages workflow and dependency lock byte for byte.
- All **385** files under the C4 tree's engineering evidence directory, with their exact modes and blobs.
- The shared BinDiff/Rizin environment policy and POSIX Intel behavior.

`composition.json`, `expected-tree-map.json` and `candidate-tree-map.json` provide the full comparison. `check_composition.py` is the reproducible read-only checker. Selected complete source snapshots are in `reviewed-files/` with SHA-256 receipts in `reviewed-file-hashes.json`.

## Bounded runtime checks

The exact candidate reports **141 passed in 3.26 seconds**, no failures or skips, across six maintained selectors:

1. Dedicated Intel environment regression tests.
2. The existing Windows environment-layout assertion.
3. The actual-host audit that every registered tooltip ID is applied, retaining Strings, Search and Build environment coverage.
4. Pages workflow assertions.
5. Pages dependency-lock assertions.
6. Specification registry checks.

The existing independent identity harness was replayed against this exact merged source. Real `getpass.getuser()` returns `patchtrace` with no `pwd` import attempt; removing the synthetic identity reproduces the missing-`pwd` error. All 432 case combinations of LOGNAME/USER/LNAME/USERNAME remain excluded as caller identities. Explicit extras reject 894 protected-key/invalid-value cases across the two platform branches.

The harness also exercises 24 actual version/help/analysis adapter calls using injected authored fake runners: capa vivisect, capa Ghidra, FLOSS and DIE on POSIX and simulated Windows branches. Private paths, input-copy permissions, cleanup, Java/DIE additions, process arguments and nonzero analysis classification remain intact. No upstream tool or analyzed target binary executes.

Exact commands, source head/tree, timestamps and complete logs are retained in `integration-tests.*`, `identity-controls.*`, `identity-controls-result.json`, `source-binding.*` and `intel-delta-whitespace.*`.

## Pages dispatch boundary

The unchanged Pages workflow has push-to-main path filters and a manual dispatch trigger. It has no PR trigger. Its deploy condition remains:

`github.event_name != 'push' || !contains(github.event.head_commit.message, '[no deploy]')`

Therefore a manual dispatch retains deployment behavior; this review did not invoke one. Byte preservation and local workflow/lock tests do not establish hosted dependency-index resolution or a hosted Pages build. That acceptance gap remains recorded.

## Qualification limits

The 141 passing identities overlap earlier/root selections and must not be added to those counts. C4's prior 580 passes plus one CODEX-5 expected failure belong to its earlier reviewed code checkpoint. Intel's prior 130 passes belong to its separate repair checkpoint. These source-specific records remain intact.

This review did not run the full suite, rerun native tools, establish Windows runtime compatibility, dispatch CI/Pages, resolve broader CODEX-5 lanes, or claim release acceptance. Root must retain its exact-source combined qualification and require all applicable fresh published-head checks. The in-progress final C4 remote-publication mapping is not asserted by this local-source review.

## Retained input evidence

`c4-handoff.md`, `c4-parent-merge-review.md` and `c4-qualification.json` preserve the supplied completed C4 review and qualification records. `c4-from-published.diff`, `intel-reviewed.diff`, `initial-source-map.json` and `lineage-and-workflow.json` bind the original source identities and workflow boundary. `review-report.json` is the machine-readable final disposition; `manifest.json` records all enclosed file sizes and SHA-256 checksums.
