# Development corpus research runners

## Scope and provenance

This specification recovers the R1 development workflow from
`2fdac2ea9042985ac3c98545d38ac3461d00f4cc`, including the receipt-preservation work
merged into the historical research branch by PR #145. It adds usable development
entry points while retaining the current factory, build, primary, secondary and
unified interfaces. It grants no new native compatibility or release credit.

The recovered modules are `tools/calibration/tier_r/research_audit.py` (pure
partition and explicit-observation metrics), `research_observers.py` (strict
Ghidriff image-address projection), `research_build.py` (stock-profile build
matrix), `research_pilot.py` (explicit primary/secondary/unified pilot), and
`receipts.py` (exclusive anchored receipt publication). The default authored
development suite is `corpus/ours/r1-pilot/defined`.

## Development commands

From the repository root, use the environment that already provides PatchTrace
and its development dependencies. Build artifacts and receipts go in an
absolute private directory outside the checkout. For example:

```sh
python -m tools.calibration.tier_r.research_build \
  --store /absolute/private/corpus-store \
  --output /absolute/private/build-receipt.json \
  --profiles msvc-free --opts O2
```

The receipt lists each produced label path and its exact digest. A blocked
toolchain leaves a blocked entry; it does not silently substitute a compiler.
Select one produced label document for an explicit pilot:

```sh
python -m tools.calibration.tier_r.research_pilot \
  --labels /absolute/private/corpus-store/labels/selected-pair.json \
  --store /absolute/private/corpus-store \
  --work /absolute/private/pilot-work \
  --output /absolute/private/pilot-work/receipt.json \
  --ghidra-dir /absolute/path/to/ghidra
```

The label filename above is a placeholder for a path from the build receipt.
Supply `--rz-diff` to select that secondary executable and `--unified` to request
unified extraction and comparison. `--primary-project` reuses a completed,
hash-bound primary project and reports persisted provenance. `--review` selects
an exact-digest review document under the contract below. The build runner exits
0 for built, 1 for findings or partial work, 2 for a command/publication error,
and 3 when every matrix cell is blocked. The pilot exits 1 for a failed engine,
cleanup or warm-cache step, 2 for a command/publication error, 3 when no selected
engine produces an observation result, and otherwise 0. These statuses describe
the development run; they do not grant corpus acceptance.

## Inputs and ownership

Both command-line entry points admit their receipt destination before native
work. Receipt names are absolute `.json` paths without traversal, symlink or
reparse components. Build receipts must be outside the repository. Pilot
receipts must be directly inside the selected private work directory, also
outside the repository. Existing or racing destinations are preserved.

Labels, optional review metadata and retained raw engine JSON use the current
bounded regular-file reader. Labels retain the existing 64 MiB contract limit;
reviews are limited to 8 MiB; raw Ghidriff JSON retains its existing import
limit. Duplicate JSON keys, nonfinite numbers and malformed/deep documents are
structured failures. A review binds the exact pair and label digest, has
nonempty bounded reviewer and review-kind strings, and classifies each supplied
function exactly once. Function keys use exact string/optional-uint32 types;
booleans cannot stand in for addresses. The review is an explicit user-supplied
selection receipt, not evidence that the identity of a reviewer was authenticated.

The build matrix admits at most 64 suite versions, 512 matrix cells and 4096
source-tree entries, with at most 16 MiB of C source text in each suite version.
Suite JSON is bounded by the existing 8 MiB contract. Source discovery refuses
symlink/reparse and special entries; only `.c` files become compiler inputs.
Versions name child directories; dot and parent aliases are refused. All pair
endpoints must name declared versions. Duplicate or truncated pair IDs
are refused before tool probing. Completed labels use exclusive anchored
publication rather than replacing an existing label document.

The current factory retains its build provenance, source-directory identity and
bounded receipt behavior. Current primary project creation owns its copied
artifacts; their ordered hashes must match the supplied labels before running
the primary backend. Unified extraction independently checks the opened artifact
bytes against these same hashes. Secondary execution continues through the current
production adapter scheduler and verified-input preparation. Targets are never
executed. Artifact stores and suite source trees remain caller-owned during
native compilation; this recovery does not replace the existing compiler or
artifact-store contract.

## Scoring and execution provenance

No review means exploratory candidate scoring. A selected review may mark
records ambiguous without rewriting the original labels. Unknown change
verdicts remain unknown; tentative, contested and one-to-many unified identities
cannot be converted into unique correspondence credit. Observation ingestion
counts raw rows, including duplicates, and refuses more than the existing
`MAX_PREDICTIONS` budget. Partition checks cover the identities provided by the
caller, not undetected near duplicates.

Ghidriff observations retain the raw digest and ordered artifact binding.
Consumed function and address-edge row budgets are checked before invoking the
production normalizer, so over-budget input cannot first allocate normalized
function objects.
Validated EXTERNAL-to-EXTERNAL address-table edges are explicitly unscored;
cross-namespace, unknown-namespace, ambiguous paired and paired/unpaired
conflicts are refusals. Image bases are side-specific. The legacy rz-diff reducer
is blocked for unequal image bases. Cached, imported or resumed primary runs
are never described as execution in this invocation. Missing optional engines
remain blocked or not run.

## Publication and failures

On POSIX, receipt publication walks and retains no-follow directory descriptors,
exclusively opens the leaf relative to its held parent, and checks named ancestor
identities before reporting success. Both platforms verify the newly opened
receipt's exact bytes and retained named identity before reporting success;
short writes, same-inode mutation and leaf replacement are failures. On Windows, every parent is held without
write/delete sharing and all reparse/device/stream aliases are refused. A host
without the required primitives fails explicitly.

A write or ordinary cleanup error preserves completed work. If publication fails after a
matrix or pilot completes, the CLI emits an error containing the complete
receipt; it does not overwrite another receipt, delete a replacement path or
claim rollback. Ordinary primary/unified cleanup errors are recorded without discarding
the completed engine result or preventing other requested engines from being
attempted. Receipts describe authored cross-checks and observations; they do not
promote candidates to accepted corpus truth.

An optional warm-cache comparison failure is recorded alongside the successful
first unified outcome and makes the command fail without discarding that outcome.

Every owned unified side is offered cleanup even if an earlier close raises a
cancellation or process-exit exception. A pre-existing primary failure remains
the surfaced cause. Without an earlier failure, cancellation propagates after
the remaining closes; this interrupted invocation does not claim a final CLI
receipt or completion of later engine work.
The primary exception is captured from the owned operation itself; an unrelated
active exception in its caller cannot suppress cleanup cancellation.

## Qualification

Pure and substituted orchestration tests establish input, ownership, scoring and
publication contracts only. Native Windows directory-sharing tests and actual
primary/secondary/unified compatibility remain separate gates. Historical pilot
notes accompanying the restored suite describe their original source and
environment; they do not qualify the current integration head.
