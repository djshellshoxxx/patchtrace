# R1 pilot protocol and additive implementation boundary

Status: protocol before execution, 2026-10-30. Existing contracts remain
`suite/1`, `known-answer-labels/1`, `tier-r-report/1` and
`tier-r-engine-output/1`; this document does not authorize changing them.

## Inputs and populations

Use a reviewed freestanding C suite under `corpus/ours/r1-pilot/defined/`, then a
recipe-backed cJSON release pair if acquisition/build succeeds. Fixtures use
defined unsigned arithmetic, explicit pointer-domain assumptions, bounded loops,
separate named functions and authored mutation descriptions. Source edits remain
candidate labels until symbol identity, binary survival and operand behavior are
checked independently of the matching engines.

All pilot cases are **development** observations. No locked test is selected,
read or consumed. A single project/template lineage cannot be split into training
and validation to manufacture independent sample size. Compiler and optimization
derivatives inherit their source lineage.

## Audit extension (not a second corpus factory)

`tools/calibration/tier_r/research_audit.py` is an additive, pure research helper.
It accepts existing validated `KnownAnswerLabels` and engine observations. It
does not build binaries, mutate labels or make production matching decisions.

- `audit_partitions(docs, roles)` requires exactly one role per pair ID from
  `dev`, `validation`, `locked-test`, `shift-test`. It detects cross-role
  intersections in project, lineage, engine/debug artifact digests, source origin
  plus revision, and shared authored mutation/template groups when present.
  Missing/duplicate/extra IDs fail validation. Findings retain deterministic
  evidence keys; passing only covers supplied identifiers, not undetected near
  duplicates or vendored fragments.
- `supplemental_metrics(labels, predictions, *, implicit_unchanged=False)` takes
  actual endpoint observations `(old_rva, new_rva, changed)`, where `changed` is
  `True`, `False` or `None`. It computes explicit correspondence TP/FP/FN,
  precision/recall/F1, unmatched/ambiguous/unknown coverage and unconditional
  material-change detection (correct correspondence AND a positive change verdict,
  divided by all non-ambiguous material truth pairs). A missing or unknown verdict
  never becomes unchanged. Conflicting duplicate change verdicts become unknown
  and are counted. Missing endpoint identities remain unlabelled observations.
- Every denominator is recorded. Correspondence false-positive rate is undefined
  without a declared negative candidate universe; report false discovery rate
  `FP/(TP+FP)` separately. Undefined ratios are JSON null.
- Legacy Ghidriff omission-credit metrics, if requested through the original
  evaluator, remain an upper bound. They never enter this explicit measurement.

The report must attach accepted label record keys, source/binary evidence and
reviewer provenance. `check=ok`, symbol names or a normalized-body hash alone is
not an acceptance certificate. Structural ambiguity remains unresolved;
many-to-many accuracy needs a later extension because `/1` intentionally
projects unique RVAs and ambiguous records.

## Execution and performance

The additive `research_build` wrapper varies only existing factory profile and
optimization fields; it introduces no automatic discovery aids or changed flags.
The `research_pilot` wrapper accepts existing labels and a private work directory.
It can resume an already completed, identity-verified primary project. It records
Ghidriff observations from the raw address-match table, after the production raw
identity check, with separate old/new bases. A pair without an explicit change
verdict stays unknown. Ambiguous table multiplicity fails observation extraction.
Unified metrics use only `matched` one-to-one decisions and explicit one-sided
decisions; tentative, contested and structural rows remain counted abstentions.
Primary and unified work remain derived projects, never corpus truth inputs.
Scoring defaults to exploratory candidate labels. An externally reviewed selection
must identify the exact label digest and stable function keys; an acceptance note
is not inferred from factory success. The original label document is preserved.
These experimental receipts are research notes, not a new persisted product
contract. Unit substitutes prove orchestration invariants only.

The pilot CLI receipt must be a new `.json` file directly inside the explicitly
selected absolute private work directory, outside the repository. Reject relative
paths, `..` components, symlinked path components and existing destinations before
starting engines. Recheck containment at publication and use exclusive creation
so a destination created during analysis cannot be overwritten. This boundary
protects existing files and snapshots from a mistaken output argument; it is not
a sandbox against another local process that can replace the user's private
directory while the command is running. Historical receipts retain their original
locations; new invocations use `--output "$R1_RUNS/case/receipt.json"` alongside
`--work "$R1_RUNS/case"`.

Build with the existing Tier R factory; record actual compiler/tool versions,
recipe digests, commands, source hashes and artifacts. Rebuild in distinct scratch
directories. Compare hidden-symbol images first; visible-symbol results are a
separate experiment. Run pinned Ghidriff first, then rz-diff and compatible
unified/BinDiff adapters. No target DLL/EXE is executed.

Record process status, wall time, binary sizes and labelled function counts. Peak
memory is measured only where a process-tree method is available; otherwise it
is unavailable. Warm/cold cache definitions and repeat runs must be explicit.
Installation success is not an engine pass. Preserve failed commands and raw logs
outside git; commit bounded summaries and hashes. No release-flag or calibration
change is implied.

## Demonstrated existing live-harness failures

The pilot also reproduced a build-provenance collision: Clang O2 and O3 can emit
the same debug image, while `images/<debug_sha>/build.json` retains only the last
recipe. Artifact identity is many-to-one with build provenance. Preserve that
legacy last-build file for compatibility, and additionally persist every complete
`tier-r-build/1` receipt as `images/<debug_sha>/builds/<receipt_sha256>.json`, where
the filename hashes the exact serialized receipt bytes. Repeated identical
receipts are idempotent; pre-existing bytes that disagree with the content key
must fail. There is no label-schema or `BuildResult` interface change. Rebuild the
affected configurations to recover actual receipts; do not reconstruct historical
execution by guessing flags from the labels. Tests cover distinct recipes sharing
one artifact, repeat writes and integrity failures.

The same experiment exposed `Session.side` reusing a `SideData` object, including
its older `BuildResult`, based only on equal debug bytes. Three O3 endpoint
records consequently carried O2 configuration metadata. Preserve the first
receipts as failed provenance evidence; then bind the cache to full build/source
context and rerun the matrix. This changes metadata correctness and cache scope,
not source labels or matching decisions.

The prior live gate run is linked in the README. Fix only defects with regression
evidence in the dev-only harness. A backend `identical` shortcut is not genuine
Ghidriff execution; absent outcomes cannot satisfy A/A acceptance. Persist a real
successful primary run through `ProjectService.apply_analysis` before unified
consumption. Fabricated primary output and ground-truth-derived engine answers
are prohibited. Preserve failure diagnostics without rewriting prior evidence.

Full Linux pytest/Ruff, schema checks, independent review, Windows CI and relevant
native checks remain merge gates. Substituted-engine tests are unit evidence only.
Unavailable and not-run cases remain distinct from passed checks.
