# Independent review: bounded Tier R data integrity (2026-11-03 UTC)

**Disposition: APPROVE the bounded source consolidation for root integration.**
No blocking correctness or integration defect was found in the reviewed delta.
This is source-review approval for the frozen slice below, with the stated
filesystem and evidence limits; it is not approval of the separate research
lane, native acceptance, corpus evaluation, or any PR/issue closure.

## Frozen identities and review scope

| Object | Identity |
|---|---|
| Reviewed commit | `294bccc4886261376fa9cb61c0197c52f3fba315` |
| Reviewed tree | `91aa77f1a23bce2a56a27e2e325a5ab69c3365ac` |
| Exact parent | `2b6a4965cc4e0e1f3822109d8a13ebf236ff9bb0` |
| Read-only checkout | `/tmp/patchtrace-data-integrity-20261103` |

The checkout's actual head/tree/parent match those identities. Its eight-path
delta contains only the three intended source files, three focused regression
files, the appended SPEC-32 amendment and the author's unique QA receipt. Its
working tree remained clean after review. No file in the author's repository
was edited.

Reviewed the complete source delta, relevant `BuildSpec`/`BuildResult` fields,
the build-record assembly and publication call, `Session.side` callers and
`SideData` source lookup, label derivation and case-card aggregation, the new
tests, and the appended specification and author receipt. Also read the prior
`consolidation-receipts-lane-20261102.md` disposition to distinguish these three
preservation fixes from the larger #128 -> #145 -> #150 lineage. The frozen
parent's AGENTS.md, CLAUDE.md and module index had already been read for this
consolidation work; relevant Tier R module-index entries were inspected again.

## Correctness findings

### Full build receipt retention

`persist_build_record` serializes the entire observed record before publication,
uses its exact-byte SHA-256 as the filename, stages complete bytes privately in
the same filesystem, and publishes via exclusive hard link. It cannot overwrite
an existing destination through that publication step. Equal existing regular
receipts are reused without rewriting; mismatched bytes, symlinks and other
nonregular destinations are refused before the legacy view is updated. A hard
link failure becomes `BuildError`, rather than falling back to partial or
overwriting publication. Distinct recipe/source/provenance records remain
discoverable even when the debug artifact hash is equal.

The production call replaces precisely the old final `build.json` write after
the full existing record has been constructed. Compilation, stripping,
loaded-view comparison, artifact/PDB copies, BuildResult construction and all
later orchestration are preserved. The helper is self-contained and adds no
dependency on the absent research CLIs or `receipts.py`.

### Source-bound SideData cache

The revised key includes the frozen build specification, debug hash, recipe
digest, source digest and resolved source root. These are the contexts identified
by the prior lineage audit. `SideData` retains the BuildResult and lazily loads
source spans, so avoiding equal-debug-byte provenance substitution is material
to both emitted build metadata and source/body comparisons. Existing callers
continue supplying their corresponding build result and source root. Same-context
reuse survives, while altered specification/digest/source context is isolated.

This remains an in-session cache. It does not hash mutable source files on each
lookup or verify artifact/PDB contents anew; the appended specification makes
that boundary explicit. No claim of a comprehensive hostile-filesystem cache
or arbitrary manually constructed BuildResult equivalence is needed for this
bounded preservation change.

### Declared unchanged controls

The change is confined to the `check` mapping for already-derived labels:
`unchanged`/`cosmetic` -> `ok`, `changed` -> `disagree`, `ambiguous` ->
`unchecked`. It neither changes the identity join nor promotes a label based on
the case card. Missing-counterpart and ambiguous-identity paths remain intact.
Case-card aggregation continues to count actual `disagree` records separately;
an ambiguous row cannot become verified agreement through this branch.

## Evidence assessed and independent controls

The author's frozen QA receipt reports:

- Original three regression files on unchanged candidate source: 13 failed,
  4 passed.
- After original preservation fixes: 17 passed.
- Final three-file focused command, including four additional boundaries:
  **21 passed in 0.73s**.
- Focused source/test Ruff and diff checks passed.
- Explicit source selection via the isolated Python and PYTHONPATH; synthetic
  records and temporary files only.

The tests were inspected for their assertions, not merely their totals. They
cover multiple receipts for equal artifact identity, idempotent reuse, tampered
existing content, no invented legacy history, unsupported/denied hard links,
complete staged bytes and late collision, legacy-view failure after receipt
retention, each intended cache-key context, same-context reuse, conflicting
source/body controls and missing source spans. I did not repeat the author's
21-test command or transfer it to another tree.

To resolve the concrete uncovered destination-type question, I ran two small
independent synthetic filesystem controls against this checkout's imported
`build.py`, with `PYTHONDONTWRITEBYTECODE=1` and explicit PYTHONPATH. A preexisting
symlink to exactly matching receipt bytes and a preexisting directory at the
receipt name both raised the expected integrity-mismatch BuildError. Both
preserved the prior `build.json` and destination and removed private staging.
**2 independent boundary controls passed.** These used a temporary directory
outside the author checkout and invoked no compiler, native engine or target.

## Integration risks and preserved limits

- Hard-link support is now required for successful receipt publication. Denied
  or unsupported filesystems fail visibly before advancing the compatibility
  view. Linux synthetic controls do not establish native Windows/filesystem
  acceptance. Root should preserve that requirement and its tracked limit.
- `build.json` remains a mutable, direct-write compatibility view. A failure or
  concurrent write can leave it unavailable or inconsistent even after an
  immutable full receipt has been retained. This is not transactional legacy-view
  publication; the immutable receipt must not be deleted to mask a later failure.
- Parent paths are not held through retained directory descriptors, and the
  existence/type/read checks do not provide hostile same-user path-race
  protection. Receipt publication is exclusive at its target path but is not
  the anchored publisher from #150. No power-loss durability is established.
- Existing artifact/PDB publication and mutable source-cache behavior are
  preserved; this helper alone does not verify an entire content-addressed
  store or authenticate past build history.
- The later `live_pairs.py` extraction isolation, completed-primary recovery,
  retained configuration, forced-identical native controls and redaction code
  are outside this delta and remain unchanged. Root combined testing must not
  restore earlier lineage versions over those successors.
- The absent research archive/tools, completed matrix/pilot error-receipt
  recovery and anchored research publisher remain separate. This slice does
  not justify closing #128, #145 or #150.

Root owns combined-tree validation, hosted gates, publication and public
persistence. No remote action, live/locked corpus access, compiler execution,
native engine run, broad suite, stress test, calibration promotion or evaluation
was performed during this independent review.
