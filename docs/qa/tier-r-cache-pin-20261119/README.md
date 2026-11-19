# Tier R approved cache-pin assertion repair — 2026-11-19

This is a test-only correction for the sole failure in the completed PR #319
Linux QA job. It accepts the exact immutable cache action already present in the
reviewed workflow. No workflow, product source, case selection, elapsed budget,
packaging step, or release gate changes.

## Source and failure binding

| Item | Exact source or observation |
| --- | --- |
| Hosted PR #319 head | `a56ab13aaf9916fc12bea70ba1494075991b7f09` |
| Hosted checkout merge | `d7da9458256b398945f129f78331fbbe9629410b` |
| Hosted merge tree, equal to the PR head tree | `e99ba4a6573fea1d546be9f549d78e3f5df24714` |
| Main parent named in the hosted log | `fdc2696c23bdbfe7668348f25e3b336ce33039f7` |
| Workflow run / Linux job | `44502009773` / `135483923306` |
| Isolated repair base | `2ff86a96752bde9718460206c5e4b679bdad9cd4` |
| Test-only repair | `5575af797dfaabdce6a3ee4081d680054d0a2d8f` |
| Repair tree | `e7324bcbb709702e688fb77c53db5c3c614b4a18` |
| Original test blob, equal at hosted head and isolated base | `9c0214db46e69506be4b34efa50ee1b7bbb82655` |
| Repaired test blob | `41d36b118f24ac98194393123e078eb18542bba4` |
| Unchanged workflow blob, equal at hosted head and isolated base | `4f92ef38ddb48dcc06481e130ae5190094ae9e02` |
| Frozen assembled runtime | `9335e7dcadc6d0337243f894e8f234ccc74bc62e` |

The retained [Git commit REST response](https://api.github.com/repos/djshellshoxxx/PatchTrace/git/commits/d7da9458256b398945f129f78331fbbe9629410b)
binds the hosted merge to its tree and ordered parents: main `fdc2696c` followed
by PR head `a56ab13a`. Root retrieved that response; its exact bytes are included
in the archive. The local test imports at core
`91349d28093f24f46c025161794ff98da3277eaa` and assembled candidate
`81842b8df3d5bc5339bd516505611cdd7daabaf7` were independently compared: each changes
only this test file and retains the repaired blob shown above.

The [hosted job](https://github.com/djshellshoxxx/PatchTrace/actions/runs/44502009773/job/135483923306)
completed with **1 failed, 23,268 passed, 50 skipped, 6 xfailed, 21 warnings in
2316.05 seconds**. Its only failure was
`tests/test_tier_r_shard.py::test_workflow_structure_and_pins`, at the assertion
requiring `@v` in every non-MSVC action reference. The actual workflow includes
`actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830`, so that stale assertion
rejects an approved immutable pin. This was not an elapsed-budget failure.

Step 9, the full pytest invocation, failed. Step 10, ordinary Ruff, was skipped
in that hosted job. The earlier Linux pair-publication boundary step separately
reported **108 passed, 2 skipped in 2.69 seconds**. Neither that step nor this
test repair establishes native Windows or release acceptance.

## Minimal correction

The exact MSVC assertion remains unchanged. The original `@v` rule remains for
all other existing action references, with one explicit equality exception for
the approved cache SHA. This preserves the two existing `actions/cache@v4`
entries while refusing unrelated immutable references. It does not introduce a
generic 40-character-SHA allowance. All workflow structure, environment, job,
dependency, and permissions assertions remain unchanged.

The relevant module index and SPEC-32 sections 13–15 and Windows advisory
prerequisites were read. This corrects a test's description of the existing
workflow; it changes no specification contract and needs no schema regeneration.

PR #318 at `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` is unaffected by this
specific assertion. Its test blob is
`3fd76162a0dd6e8dd330608bf2c3dd97c322f9cf` and already checks immutable action
references with a 40-hex regular expression. Both remote test files and the
PR #319 workflow were retrieved at their exact source pins and retained.

## Local verification

The following bounded selection ran in the isolated worktree, with
`PYTHONPATH=src:tests` and `QT_QPA_PLATFORM=offscreen`, using
`/workspace/scratch/80dddc5347b2/patchtrace-followup-venv/bin/python`:

```text
python -m pytest -q \
  tests/test_tier_r_shard.py::test_workflow_structure_and_pins \
  tests/test_ci_summary.py \
  tests/test_tier_r_windows_dependencies.py \
  tests/test_workflow_contract_dependencies.py \
  --junitxml=/workspace/scratch/80dddc5347b2/ci319-cache-pin-failure-20261119/local-after.xml
```

- Before correction: the exact failing test reproduced **1 failed in 1.83s**.
- After correction: the displayed selection reported **21 passed in 1.99s**,
  with no skips.
- Ordinary `python -m ruff check src tests tools`: passed.
- `git diff --check`: passed.
- A source comparison verified no changes to `src`, `tools`, `.github`, or
  `pyproject.toml`; the source commit changes only the one test assertion.

The exact executable, argument arrays, environment overrides, pre-edit source,
post-edit test blob, output, return codes, and JUnit reports are in the evidence
archive. The initial failing test and hosted full failure remain retained.
This scoped local result does not replace a fresh required hosted QA run.
The 21 controls overlap earlier CI configuration checks and are not an additional
full-suite run.

## Independent review

The independent security reviewer approved the scoped test-only source at
`5575af797dfaabdce6a3ee4081d680054d0a2d8f`, confirming the sole one-line change,
unchanged exact MSVC branch, and the pinned test/workflow blobs. Their six
separately authored controls reported **6 passed in 1.25s**: the exact approved
cache reference and existing version-tagged entries pass; a different 40-hex
cache reference, the same SHA under checkout, a suffixed SHA, and an MSVC version
tag fail. Their source probe, log, JUnit, and source proof are retained unchanged
in the archive. This is an independent assertion/configuration review, with no
full-suite, native-tool, or Windows qualification claim.

## Evidence

`evidence.zip` retains the decoded REST job log encoded as UTF-8, REST job steps
and run metadata, exact remote file snapshots, local red/green logs and JUnit,
source identities, and static-check receipts. `manifest.json` records archive
and member SHA-256 hashes and byte lengths. The raw job log is **86,706 bytes**,
SHA-256 `481a596f7ecfcbff7d2f724507780062ef6b58fa9b1ee011b872573fa855a72e`.

The hosted `qa-Linux` artifact (`14524901998`) was reported as uploaded; this
receipt does not claim that its ZIP was downloaded or independently inspected.
All retained local results are portable test/configuration evidence, not native
tool qualification, a full-suite green result, or permission to merge with open
required gates.
