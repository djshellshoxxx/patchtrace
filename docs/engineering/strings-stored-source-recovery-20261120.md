# Generation 31: recover current Strings source admission

## Result and scope

Recovered a retained defensive stored-result repair and connected it to the
existing Strings CLI. The source commit is
`cf71c457665092b11448c6515c33360f68a590dd`, based on generation-30 integration
`9fdb518f2b322f784fe389b7856a299023f1d901`.

The change preserves current project/artifact/side binding and legitimate
cache-origin provenance. It does not add comparison, cue, ranking, function
linking, Search, GUI, export-publication or network functionality. The existing
legacy `ToolStore` readers remain unchanged.

## Why the recovery is unique

The current candidate has no `intelligence/tools/admission.py` and its
`strings.cli._floss_source` selects `ToolStore.latest('floss', artifact.side)`
without passing the current artifact SHA. It also requires a raw sidecar on the
latest run itself. The older retained branch already solves both omissions.

The broad donor is
`2042e24dc7f3eac265e0eb183c738527852b22cf`, retained by
`consolidation/patchtrace-continuation-20261119` / PR #321. Two files are recovered
byte-for-byte:

| File | Retained donor and recovered Git blob |
| --- | --- |
| `src/patchtrace/intelligence/tools/admission.py` | `ae64016dc65d575d649aafae1264d15d6d434e3c` |
| `tests/test_intel_tools_admission.py` | `626e95da8297eea959d7c9b0344e1e32eecc3e4d` |

The donor's historical report attributes the helper to private intermediate
commit `41af7c7e3f3bd5e50c49b86bc061fdef834b4daf`, which is unavailable in this
clone. This recovery identifies the available retained commit and exact blobs;
it does not claim a cherry-pick of the unavailable intermediate.

Only the existing CLI source selector is adapted from the donor's caller
behavior. The donor's broader Strings composition, GUI Source selector,
Search wiring, inventory and older export implementation are excluded.
The contract and module index were updated before adding runtime code.

## Original defects and repaired behavior

An authored fake FLOSS producer stores results through the real runner and
project store using synthetic PE fixtures. No analyzed binary is executed.

- After `ProjectService.swap_orientation()`, the original CLI returned the
  pre-swap artifact hashes under the new side labels. Current-source admission
  now refuses those stored results. Auto uses the verified built-in scan;
  explicit FLOSS selection refuses. Restoring orientation makes the original
  correctly bound evidence usable again.
- A legitimate second runner invocation produces cache hits with no new raw
  sidecar. The original CLI discarded the valid stored source or refused
  explicit FLOSS. The recovered helper admits the original evidence owner and
  preserves its recorded raw digest, executable and options provenance.
- Stale or foreign selected run/evidence metadata formerly remained usable.
  It now makes the stored source unavailable without silently selecting an
  older produced run. Auto fallback and explicit FLOSS refusal remain distinct.

The helper validates original strict JSON, row ownership/status, content-derived
evidence identity, run/evidence binding and cache origin. It uses the existing
normalized-sidecar loader. Recorded raw provenance does not assert that raw
bytes were reread or that native tools were rerun.

## Verification

| Selection | Result |
| --- | --- |
| Eight new caller regressions on unchanged baseline | **8 failed**, 2.90 s |
| Same eight caller regressions plus 33 recovered helper tests | **41 passed**, 3.30 s |
| Existing Strings CLI/source/basis and tool-runner integration | **61 passed**, 7.79 s |
| Scoped Ruff and `git diff --check` | Passed |

The two green selections contain 102 distinct cases with no overlap,
failures, errors, skips or xfails. The frozen baseline failures are retained.
Exact source hashes, node names, commands, JUnit results and evidence hashes
are in [the manifest](evidence/generation31-strings-admission/manifest.json).

This is focused Linux verification with synthetic data and an authored producer.
Independent review and combined source qualification are separate gates.
Native FLOSS, Windows, GUI and release acceptance are not claimed. There are
no schema or dependency changes. The Linux forced-export source-name race is
unchanged and remains open.
