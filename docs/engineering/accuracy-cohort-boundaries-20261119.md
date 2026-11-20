# Accuracy cohort and confidence-bound correction

## Scope and baseline

This fresh-generation review started at
`f4503de37bb94b1449118f23709e647ea55dd944`. It inspected
`tools/research_qualification/{cases,scoring,parity,scorerun,l1_run}.py`, their CLI
entry points, the accuracy plan and the existing facts-gate tests. All examples
and test cases below are authored mechanical controls. No binary engine ran,
no real case facts were promoted, and no actual accuracy estimate was obtained.

Two reporting defects reproduced on unchanged source:

1. A valid manifest with one L2 and one L3 hit produced a combined generic
   `score` result with two hits, a single `lower_bound: 0.224`, and no layer
   identity. Generic `parity` similarly produced one combined comparison.
2. Twenty-nine hits from the same project produced `lower_bound: 0.902`, despite
   the manifest summary correctly identifying just one distinct project. The
   L3 orchestrator used the same case-count denominator, while its per-set
   aggregation also pooled different strata.

The previous facts admission repair remains effective: `facts: unverified`
cases receive no rank, score or parity credit. The defect is in aggregate
admission and statistical reporting, not in that gate or the binary matcher.

## Uniqueness evidence

The frozen donor scan covers **325 origin refs, including the HEAD alias**.
It found four `scoring.py` blobs, one `parity.py` blob and one `scorerun.py` blob.
All four historical `score_run` function ASTs have the same SHA-256; the
variation concerns per-case ranking and the already-recovered facts gate.
The exact blob sets also equal those found through `git rev-list --objects
--all` for these paths, including the fetched PR history. No alternative
aggregate repair existed in that reachable inventory. The broader branch
inventory remains the parent's separate frozen discovery snapshot.

The evidence archive contains the ref-to-head map, file blobs, function AST
hashes and historical blob comparison. This is a newly implemented correction,
not a wholesale donor merge.

## Resulting contract

The accuracy plan was updated before implementation.

- Generic `score` and `parity` require one explicit `(layer, stratum, holdout)`
  cohort and identify it in successful output. Mixed or invalid cohort metadata
  is a `ValueError` at the API boundary and exit 2 through the CLI. An empty
  manifest retains empty results and null cohort fields. Frozen manifests must
  remain intact; separate experimental cohorts must be defined before a run.
- Scorers retain every admitted per-case result and descriptive count. They
  withhold `lower_bound` for missing or repeated scored project identities and
  emit `scored_projects` plus `bound_reason`. No synthetic rule for combining
  several case results into a project-level Bernoulli trial is introduced.
- Blocked and unverified rows do not affect bound admission. Distinct project
  labels still do **not** prove independence; valid bounds remain explicitly
  conditional on the frozen sampling protocol.
- L3 retains development/holdout separation, non-L3 blocking and case verdicts.
  It exposes per-stratum summaries, withholds mixed-stratum pooled bounds and
  displays bound reasons in markdown. Direct API calls reject malformed cohort
  values before hashing/grouping. A missing direct-API project is retained as
  null in the row and withholds the bound rather than raising `KeyError`.
- Existing CLI input validators still reject malformed manifest records. The
  adapter-to-scorer test fixture now supplies explicit authored cohort/project
  metadata; its original hit/top-one/blocked assertions are unchanged.

Only the three research report modules, one existing adapter test fixture, the
new boundary regression file, the module index and the relevant accuracy plan
changed. These reports have no generated Pydantic schema; no application model,
stored project schema or production binary-analysis algorithm changed.

## Verification and preserved failures

| Source stage | Check | Observed result |
|---|---|---|
| Unchanged baseline | First 22 authored boundary controls | **22 failed**, 0.88 s |
| Initial correction | Scoring, parity, facts gate, scorerun, adapter and new controls | **144 passed**, 2.09 s |
| Initial correction | Four direct-API malformed cohort controls | **4 failed**, 22 deselected, 0.66 s |
| After direct-API cohort guard | Entire research-qualification selection | **494 passed, 3 skipped**, 10.10 s |
| Reviewer follow-up | Missing L3 project control | **1 failed**, 26 deselected, 0.82 s; preserved `KeyError` |
| Final correction | Entire research-qualification selection | **495 passed, 3 skipped**, 10.68 s |
| Final correction | `python -m ruff check src tests tools` | Passed |
| Final correction | `git diff --check` | Passed |

The failures are parameterized demonstrations of these boundaries, not 27
independent product defects. The final test file contains 27 controls. The broad
selection includes CLI/receipt integration and existing facts-gate, L1 and
adapter controls. Two native Windows publication controls were skipped. The
third skip was `test_resource_peaks_are_measured` because optional `psutil` was
absent; this run provides no CPU/RSS measurement qualification from that test.
Commands used the dedicated Python 3.12 environment with
`QT_QPA_PLATFORM=offscreen`; the exact outputs and JUnit XML are archived.

Independent review was started by a fresh worker before this commit. Its own
unchanged-baseline controls and candidate assessment belong in its separate
review record. Repository-wide tests and hosted qualification on the integrated
candidate remain the parent's gate; this report does not claim either passed.

## Evidence

- `evidence/accuracy-cohort-20261119.zip`: original red/green logs, JUnit XML,
  donor scan and Ruff outputs.
- `evidence/accuracy-cohort-20261119-manifest.json`: archive and member hashes,
  source/test fingerprints and the starting commit.

Remaining accuracy work includes independently established real ground truth,
frozen sampling protocols, adequate distinct projects and native/live engine
receipts. These safeguards do not fill those gaps or certify a release.
