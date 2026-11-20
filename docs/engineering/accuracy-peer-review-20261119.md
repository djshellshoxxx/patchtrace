# Independent accuracy report-boundary review — 2026-11-19

## Verdict and exact scope

**No remaining blocking finding in the reviewed correction.** The independent
reviewer examined candidate `776695170bc0a526951075e3744bcc684035cfcc` and
ran 48 authored boundary controls: **48 passed in 0.60 seconds**. Whole-tree
Ruff plus lint of both independent control files passed. The subsequent
`eed3ddbbd69f5675c2f0ebf0bdabe01cea868db8` commit only clarifies the author's
skip reasons; reviewed source and tests are unchanged.

The review covers `tools/research_qualification/scoring.py`, `parity.py`,
`scorerun.py`, their existing CLI dispatch and case validation, the accuracy
plan amendment, the new implementation regressions, and the adapter test
fixture adjustment. It does not claim a repository-wide test pass or native
engine compatibility. No target binaries or native analysis engines ran.

## Separate controls and baseline

The reviewer authored the first 35 controls before running the candidate.
On the unchanged integration baseline
`ef6f7a332872910277917a51ce9991bd56f0e298`, they produced **28 failures and
7 passes in 0.59 seconds**. These parameterized failures demonstrate aggregate
boundary gaps; they are not 28 distinct product defects. The exact original
control-file hash and output are retained in
`evidence/accuracy-peer-baseline-manifest.json` and
`evidence/accuracy-peer-baseline.txt`. That first control file was unchanged
between the baseline and candidate runs.

Those controls challenge:

- Mixed layer, stratum, and development/holdout cohorts through both generic
  Python APIs and their CLI commands; the corrected CLI refuses with exit 2
  and emits no misleading aggregate JSON.
- Missing cohort fields; repeated projects at two and 29 cases; absent, null,
  empty, whitespace-only, and non-string project identities.
- Preservation of hit, miss, false-positive, top-k overlap and blocked counts.
  Unverified and missing-report cases cannot increase the confidence
  denominator, and blocked duplicate projects do not suppress a valid
  one-project, one-case conditional bound.
- Empty results and unchanged input manifests; exact all-success conditional
  bounds for one, two, and 29 distinct project labels, checked with the
  closed-form `alpha ** (1 / n)` rather than the implementation's bound helper.
- L3 pooled-stratum and repeated-project refusal, independent development and
  holdout outputs, and exclusion of blocked non-L3 cases.

Thirteen additional controls were written during source review, in a separate
file so the initial red/green control set remains attributable. They check
malformed metadata types, L3 typed refusal, the missing-project fix described
below, separate stratum results, Markdown label escaping, persisted JSON and
receipt consistency, and preservation of the original manifest bytes.

## Finding corrected during independent review

The first implementation routed project validation through the new bound
helper, but L3 `_row` still indexed `case['project']`. A direct API caller
missing that field encountered `KeyError` before the promised withholding
logic. The CLI already rejects such malformed manifests during validation;
the gap concerned the direct API and its stated new contract.

The reviewer reported the exact location to the implementation owner. The
owner retained a failing reproduction and changed the row builder to preserve
the absent field as null. The independent final control verifies the case
verdict remains available while `lower_bound` is null and `bound_reason` is
`missing_project`. No reviewer edited the implementation worktree.

## Output and statistical interpretation

The generic aggregate names one explicit `(layer, stratum, holdout)` cohort.
L3 keeps separate development, holdout, and stratum outputs. Unsupported bounds
are withheld with machine-readable reasons while descriptive case counts and
individual verdicts remain visible. The implementation does not invent a
project-level success rule for several correlated case outcomes.

A `PASS` scoring receipt still means the admitted authored cases met their
ranking criteria; it is not a certification of a population accuracy bound.
The persisted result retains null bounds and their reasons, including when the
receipt's case verdicts pass. Distinct project strings alone cannot establish
independence, detect aliases, or prove that a held-out project was never used
for tuning. The report explicitly leaves those requirements with the frozen
sampling protocol and curated ground truth. All fixtures in this review are
synthetic mechanics, not empirical L1/L2/L3 accuracy evidence.

## Reproduction and artifacts

From the reviewed checkout, with repository dependencies available:

```sh
PYTHONPATH=. python -m pytest -q -c pyproject.toml \
  docs/engineering/evidence/test_accuracy_peer_controls.py \
  docs/engineering/evidence/test_accuracy_peer_extra_controls.py
python -m ruff check src tests tools \
  docs/engineering/evidence/test_accuracy_peer_controls.py \
  docs/engineering/evidence/test_accuracy_peer_extra_controls.py
```

The raw terminal output, JUnit XML, quality result and hashes are adjacent under
`evidence/accuracy-peer-*`. The author's complete research selection passed
495 tests with three skips: two native Windows publication controls and an
optional psutil CPU/RSS measurement. Those are the author's affected-suite
receipts, not additional independent runs by this reviewer, and the selections
must not be summed as distinct coverage.

Root remains responsible for final integrated source qualification, current
hosted checks and the wider release gates.
