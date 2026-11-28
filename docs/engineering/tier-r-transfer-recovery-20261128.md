# LBL-31 managed artifact handoff recovery

Base: published card-control PR #371, commit
`b96e9ae8aee215db1aa9ea93739c3b4a432139f5`, tree
`ce6b5ba4eca3639adc0eb398b976eb3895ab11e1`.

The retained PR #78 tip `2019a37fa65fc37f4758469143c2daadc07e0098`
contains earlier transport/workflow intent. Its old file copying and flat output
layout do not satisfy current managed credit contracts; they will not replace
the current producer, completion, replay or failure propagation code.

## Plan

1. Specify and index the bounded transport module, then add failing controls for
   exact evaluator-to-artifact-to-training-reader replay, refusals and ownership.
2. Implement the exporter/verifier with the current owned-file and output-store
   primitives. Add the generated transport schema.
3. Wire explicit shard export before scratch cleanup and complete-set merge into
   a fresh managed output directory; retain per-shard roots and outcome semantics.
4. Wire pinned CI artifacts and dispatch-only, default-false unlocked smoke
   training. Test the actual reader/report route with authored outputs.
5. Commit each verified slice and request independent exact-head review. Root owns
   combined full/platform/hosted qualification and remote publication.

## Evidence

Environment: existing shared Python environment imports pytest, Pydantic and YAML;
no editable-install rebinding. No source fetch, target execution or native/live
acceptance has been performed for this slice. Red/green records follow below.

### Slice 1: bounded managed export and verification

- Initial baseline: 22 failed controls; current evaluator production worked, but
  the transfer module was absent (`../transfer-slice1-red.log`).
- First implementation: 22 passed. Additional admission/publication controls
  exposed 3 failures: changed destination label acceptance, late manifest budget
  refusal after destination creation, and missing generated schema; 27 passed
  (`../transfer-slice1-controls-red.log`).
- A valid but foreign report-credit replacement control then failed while the
  changed-label control passed (`../transfer-slice1-owner-red.log`). The writer
  now checks original report ownership and exact admitted data/metadata bytes
  before publishing its final transport manifest.
- Final slice selection: **170 passed, zero skipped**, 2.95 seconds. Three expected
  `LegacyOutputWarning` warnings come from existing explicit legacy-negative
  tests; new transport replay requires `allow_legacy=False` and issues no such
  warning (`../transfer-slice1-green.log`). Targeted Ruff and whitespace passed.
- Tests use authored normalized responses through the actual evaluator, managed
  writer and training reader. This proves transfer/replay only. Shard integration,
  merge consolidation and CI/training execution remain the next slices.

### Slice 2: shard collection and complete-set managed merge

- Specification amendment preceded the runtime changes. Initial baseline:
  **29 failed** handoff controls (`../transfer-slice2-red.log`); exporter fixtures
  already produced valid managed runs. The missing seams were shard collection,
  complete-set consolidation, consumer verification and CLI failure propagation.
- First implementation: **60 passed** across both new transport modules. Further
  controls exposed **4 failures**: another engine's report hid an empty successful
  process response, and the shard importer accepted duplicate JSON members,
  oversized documents and linked files (`../transfer-slice2-coverage-red.log`).
- Final focused/adjacent selection: **383 passed, zero skipped**, 6.81 seconds,
  including existing card controls, shard outcome propagation, completion,
  credited replay, output persistence and contracts (`../transfer-slice2-green.log`).
  The same three existing explicit legacy-negative tests issue their documented
  warnings; the new artifact paths require managed credit. Ruff and whitespace
  passed.
- The actual evaluator CLI is exercised through an authored provider. Shard export
  happens before temporary scratch cleanup; ordinary findings remain findings,
  blocked cases remain blocked, and collection failures become a failed
  `evaluate:artifact-transfer` case. Merge first validates every separate root's
  metadata/budget, then rechecks exact bytes during semantic credit admission and
  finalizes a fresh managed directory from original reports. A second merge is
  byte-identical. The consumer reconstructs the aggregate before exposing training
  paths. No native or hosted producer claim follows from these controls.
- Workflow transport and the unlocked training/report command journey remain the
  next slice. The existing evaluator, output store and training implementation
  remain unchanged.

### Slice 3: pinned artifacts and the actual unlocked training/report journey

- Spec amendment preceded tests and implementation. **21 baseline failures**
  established missing dispatch/upload/download/result-check wiring
  (`../transfer-slice3-red.log`). The first implementation passed all 21 controls,
  including the actual Ubuntu Bash command bodies against authored evaluator
  artifacts and a missing-marker case that stopped before training.
- A wider selection found **448 passed, 1 failed**, 73.46 seconds. The failure
  was the old CI-summary test's exact list of upload paths. Its replacement checks
  every job/artifact name and restricted path, retaining MSVC probe/status limits
  and explicitly covering managed data versus aggregate/result files. The wiring
  lane then passed **82 tests**, including an additional actual zero-exit smoke
  with enough natural lineages but too few samples to fit.
- The complete affected selection passed **496 tests, zero skipped**, 56.78
  seconds (`../transfer-slice3-final-green.log`). Six expected legacy warnings
  belong to existing explicitly unverified-reader fixtures, not the new managed
  transport or workflow journey. New code did not alter the evaluator, output
  store or training implementation.
- A final static destination-ancestor control exposed **1 failure**: a parent
  link was refused after an empty directory had already been created through it
  (`../transfer-slice3-destination-red.log`). The writer now anchors existing
  ancestry before any directory creation. The final-source transport/shard/CI
  selection passed **149 tests, zero skipped**, 9.11 seconds
  (`../transfer-slice3-final-controls.log`). Whole-tree Ruff and whitespace passed.
- The workflow's boolean `train` input defaults false and requires explicit
  dispatch plus successful shard and merge jobs. Downloads retain separate shard
  roots; uploads retain the validated hidden marker. Merge checks both aggregate
  and transport determinism. Training first re-verifies consolidated ownership,
  creates a fresh result directory and retains its actual exit code and summary.
  It supplies no protocol or final-lock option. The strict result check accepts
  exit 1 only for the existing minimum-natural-lineage halt with matching report
  identity, exact smoke config and insufficient-data gates. Other failures remain
  failures. `train report` independently verifies/renders the result.
- Both Bash journey controls execute Linux workflow commands; on Windows only
  those two controls are explicitly inapplicable. Portable schema, ownership,
  workflow topology and result controls still run there. No Windows/native/hosted
  acceptance is inferred from this local Linux result.

## Artifact action contracts checked

Read the exact pinned [upload-artifact README](https://github.com/actions/upload-artifact/blob/ea165f8d65b6e75b540449e92b4886f43607fa02/README.md)
and [download-artifact README](https://github.com/actions/download-artifact/blob/d3f86a106a0bac45b974a628896c90dbdf5c8093/README.md).
The upload pin excludes hidden files unless explicitly enabled and places multiple
paths under their common ancestor. The download pin retains separate artifact-name
directories when `merge-multiple` is false. The workflow relies on those documented
semantics; an actual hosted archive round trip remains a separate gate.

## Preserved boundaries and remaining qualification

- `evaluate.py`, `output_store.py` and `train.py` remain byte-identical to published
  base `b96e9ae8`. Their managed sentinel, exact-byte credit, no-overwrite and
  current feature/fit/report behavior are preserved.
- Transport copies exact existing label bytes. This includes bounded mutation
  before/after provenance already inside the label schema and digest; it excludes
  source-tree files, target images, binaries, PDBs and Tier W data. It does not
  remove provenance snippets and then claim the original label digest still holds.
- No live source fetch, target execution, native engine acceptance, final-lock
  consumption or remote mutation occurred. Authored providers prove transport and
  consumer plumbing only; their insufficient-data reports are not accuracy gates.
- Independent review, parent-owned full/platform qualification, and an actual
  hosted smoke dispatch (`subset=smoke`, `engines=rz-diff`, `train=true`) with
  downloaded verified report remain required. Existing training adapter limits
  (including feature engines and statistical sample guards) are unchanged.
- Budgets bound serialized evidence and membership, with explicit preflight and
  strict refusal. This is not a signature/authenticity scheme or protection against
  arbitrary concurrent same-user filesystem changes, and maximum-cap performance
  was not benchmarked.

## Independent source and consumer review, November 27 (America/Vancouver)

Root reviewed runtime head `ee2210bbf051783de3e7cab8d1881c0b83087f2b`, tree
`38ce6ea2c763a8cd147a6b0e0c3ffb4059480176`, including exact byte admission,
manifest budgets, ownership, complete-set merge, consumer reconstruction and
actual process-result validation. No blocking defect was found.

Ten additional authored controls verify consumption from a fresh Unicode/spaced
path after removal of the original production directory; immutable retained bytes
through the actual unlocked training/report result; refusal of output reformatting
even after recomputing the transport digest; linked root/ancestor refusal; and
unexpected or non-integer process outcomes. They exercise the actual evaluator,
managed transport and training reader without target execution. The independent
controls plus six relevant transport/shard/workflow/CI modules passed **198 tests,
zero skipped**, in 111.74 seconds. Execution was slow across unrelated local
commands during this run; no cause or product hang is inferred. This was one
completed run, not a retry count.

The independent controls now remain in
`tests/test_tier_r_training_independent.py`. Author red/green logs and root's final
log/XML are retained under `docs/engineering/evidence/tier-r-transfer-20261128/`.
The runtime is unchanged by this evidence commit. Exact-head hosted full/platform
qualification and the explicitly enabled hosted training artifact/report journey
remain pending; local authored transport checks do not establish native accuracy.

After retaining the controls in the repository, explicit fixture re-export imports
resolved five Ruff F811 import/style findings without changing assertions. The
retained independent module passed all **10 tests, zero skipped**, in 3.07 seconds.
The complete required Ruff selection (`src tests tools`) and whitespace check pass.


## Parent workflow census correction, November 27 (America/Vancouver)

The source census in `test_codex5_command_audit_20261121.py` still expected
19 run scalars and six pip invocations after this branch added its training
handoff. The actual parent workflow has 23 run scalars, seven pip invocations
and seven outside the three protected install invocations. The unchanged test
failed once against publication tree `3e0bdaaa9da6e91b1643850c4950a3fd1d3aa000`.
Only this explicit census tuple was corrected. Protected-invocation assertions
and strict dependency-closure expected failures remain unchanged.

The affected audit, CI-summary and training-workflow lane passed **139 tests,
one existing strict expected failure**, in 5.80 seconds; required Ruff passed.
Original failure and final log/XML remain in the evidence folder. This changes
no runtime or workflow command, and does not replace the pending exact-head
hosted full/platform and explicitly enabled training-journey gates.
