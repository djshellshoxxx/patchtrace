# R2 matching evidence retention and analyst attribution — 2026-11-18

## Result and exact source

Source **`8f0864277d29d3d77a22ee8b30cede7146aa0c9b`** passes the affected gate:
**764 passed, zero failures/errors/skips, 36.38 seconds** (37.13 seconds wall).
The gate includes the five unchanged external product-surface controls, current
fusion/mirror policies, strict persistence, registry/key behavior, shared desktop
detail, CLI, worker/wiring and Qt controller neighbors. Full configured Ruff over
`src tests tools` and `git diff --check` pass. Source and test hashes were equal
before and after the clean committed-source run.

This is authored local evidence for evidence retention, attribution and cache
identity. No target binary, analyzer, network endpoint or frozen native outcome
was run or modified. Native accuracy and packaged-platform qualification are not
established by this packet.

| Role | Commit |
|---|---|
| Current-contract baseline | `3faf436a3b11c69220641a167cf424e7f4060839` |
| Spec and failing controls | `27e2c5409c558de76d11bf93bb5cc4d2150d7d91` |
| Correct the registry-digest test expectation | `5c8998b8a8ae7ce34efc2aaf395527b2fb585a0a` |
| Product source | `8f0864277d29d3d77a22ee8b30cede7146aa0c9b` |

The worktree is `r2-evidence-retention`, branch
`codex/r2-evidence-retention-20261118`. The baseline arbiter, read text, registry,
contracts and limits bytes were verified equal to published PR316 source
`55f3d0742f7d4cf32357a42b8b1cc76d85875e71`; see `source-comparison.json` in the
archive. Root owns independent review and integration.

## Confirmed defects and repair

At the default L-39 cap of 64, repeated correlated observations can displace the
cross-class atom used by the B+B matching rule. The row stays `matched`, or
`contested` with `uncontested:matched`, but its persisted atoms can contain only
E-BODY evidence. The external authored probe reaches the arbiter, strict result
writer/verifier and desktop detail. The repair reserves a deterministic chosen
tier-B pair with different independence components and non-unknown evidence
classes when that base decision needs it. Representatives are selected in the
existing orientation-free order; repeated observations of one component/class
do not enlarge the pair search. The entire mirror-key groups join the existing
strongest-per-component reservation. The strongest opposing group is also kept.

`Support` still names the strongest chosen atom of each component. Its two
indices may both identify E-BODY atoms even though the retained atom list holds
the cross-class witness. This is the current max-pool contract, not a defect.
The repair does not change native confidence handling, component admission,
greedy choice, persisted atom ordering, mapping eligibility or strict CFG
policies. B+B acceptance remains ineligible for proof target mapping.

The non-matched dependency is explicit: a contested row with
`uncontested:matched` needs the witness along with the opposition. Tentative and
candidate bases, one-sided rows, inferred groups and analyst groups do not use
this witness reservation. Chosen M/A evidence already supports acceptance under
the existing strongest-component rule. A custom in-process cap smaller than
the union of mandatory groups raises `PT-UNIFIED-LIMIT` / `atoms-cap` in either
orientation. This happens in fusion before `compute_stage` reaches result
writing. There is no new CLI cap option and the default cap stays 64.

Manual split, merged and ambiguous groups intentionally have no 1:1 Support
inventory. Previously the shared Decision line described B+B evidence or generic
inferred ambiguity. It now identifies the analyst correction and exact category
only when the existing single recognized group hint agrees with the decision
and retained on-group manual M/E-MANUAL evidence is present. Unsupported hints
and inferred groups do not acquire analyst attribution. The tests exercise
`ProjectService.correct_match`, manual-only S0 publication, strict verification,
desktop `row_detail`, project close and reopened `unified explain`.

Only the existing arbiter channel version changes, **2 to 3**. Current `ude/2`,
other channel/proof versions and the orientation policy introduced by arbiter 2
remain intact. New current identities differ; a verified version-2 historical
record stays readable and byte-identical through stale loading, a source-pinned
Qt-free CLI child and publication of a current result.

## Red/green chronology

All logs, XML, commands, source hashes and dirty-state patches below are retained.
No failed run was replaced by a green log.

| Run | Source/state | Observed result |
|---|---|---|
| Peer original complete historical R2 probe set | `55f3d074`; original historical tests from `b3ceb8b3` | 74 failed / 6 passed; not 74 product findings |
| Selected unchanged historical controls | clean `3faf436a` | 7 failed / 1 passed / 8 explicitly deselected, 0.48 s |
| Unchanged external product-surface v3 probe | clean `3faf436a` | 4 failed / 1 passed, 0.68 s |
| New specification controls and registry neighbors | clean `27e2c540`, product bytes unchanged | 13 failed / 40 passed, 1.08 s; no setup errors |
| First implementation plus mirror properties | draft source on `27e2c540`; patch retained | 58 passed / 1 test-expectation failure, 3.95 s |
| Corrected focused controls | draft source on `5c8998b8`; patch retained | 59 passed, 3.53 s |
| Final affected gate and original external v3 probe | clean exact `8f086427` | 764 passed, 36.38 s; zero skips |
| Selected unchanged historical controls after repair | clean exact `8f086427` | 6 passed / 2 historical contract mismatches / 8 explicitly deselected, 0.31 s; process exit 1 preserved |

The first implementation's single failure was in the new registry test: it
incorrectly expected `Registry.digest()` to exclude channel versions. That
digest already includes them. The correction requires the digest to change,
while proof versions and the pass table stay equal. The original 13-red run
and the intermediate 58/1 run are both preserved; neither is called a passing
qualification result.

The two post-repair historical failures are:

- `test_support_indexes_identify_the_actual_corroborating_classes`.
- `test_cap_preserves_acceptance_witness_and_strong_contest_together`, at its
  final Support-index assertion; its contest checks already pass.

Both require Support itself to select the corroborating classes, contrary to
SPEC-31/02 section 4 and SPEC-31/05 section 1.1. They remain unchanged. The new
current-contract controls inspect **all retained atoms** and independently
check that Support stays max-pool. The historical CFG entry-boundary and old
cache-policy expectations are outside this repair. The complete 74-failure
disposition is retained by the peer in docs-only commit
`4f71b811dbd1555ce5cb6cffe062dddc3bb801e5`, archive
`semantic-disposition-batch4-20261118.zip`, SHA-256
`7b7951f095362015f3df825500dcbf31c23c12d1299181bc0faeaf62d02e60d3`.

The relocated historical hash-seed child test is explicitly excluded: it
constructs a nonexistent `src` path relative to its relocated file and could
otherwise import the older shared editable checkout. Current source mirror and
permutation controls run in the affected gate. No historical test was edited
to repair that relocated harness.

## Reproduction and ownership of receipts

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, with absolute
`PYTHONPATH=<exact checkout>/src:<exact checkout>/tests` and
`QT_QPA_PLATFORM=offscreen`. The final command additionally places the external
QA plugin directory last on `PYTHONPATH`; it never supplies product modules.
The complete command and before/after hashes are in
`committed-affected-context.json` and `committed-affected-exit.json`.
`run_checks.py` refuses to reuse a receipt label and can require a clean
checkout. The headless history child overrides its own `PYTHONPATH` with the
exact source path and asserts the imported package location and absence of Qt
modules.

The external v3 probe contains a fixed observation destination. The two small
replay plugins change only that destination after collection: baseline and
post-repair observations use separate folders. Assertions and original source
bytes remain unchanged. `original-observations-unchanged.json` and
`green-observations-integrity.json` retain before/after hashes of the peer's
original observations and this review's baseline observations.

Original external probe SHA-256:
`37fa19d6c288b1892d9567ddeee7cae35d74c721a73a01247629db6e373b30c4`.
Original historical fusion file SHA-256:
`b545602a001c206f608800c034412023abfe79a79d84d8a59e34b6b5b22cab68`.
The peer's earlier v1/v2 harness corrections are explained in the retained
`r2-product-surfaces-correction.md`; v3 is the unchanged final external probe
used for acceptance here.

The adjacent manifest lists every evidence payload's byte size and SHA-256;
the adjacent ZIP contains the complete selected receipts, original probes,
historical raw results, source/test snapshots and patch. Original mutable-work
receipts remain under `qa/r2-evidence-retention`; the durable archive is the
review handoff. No remote mutation, scanner suppression, contract/schema
migration, frozen-outcome update or native accuracy claim accompanies this
repair.
