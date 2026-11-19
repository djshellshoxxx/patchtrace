# Consolidation verification

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Current recorded source: `7dfba50f`; first remote source: `188b4962`.
Counts below overlap and must not be added as distinct test coverage.

## Focused results

| Selection / source | Observed result | Scope |
|---|---|---|
| #318 `c4ace208` core/adapter/portable native diagnostic selection | 742 passed, 1 skipped, 76.52 s | Held-input, publication, adapter identity and portable diagnostics; no live-engine compatibility claim. |
| Initial recovered Tier-W CLI | 97 passed | Offline fixtures; no network or target execution. |
| Combined CLI, runner, Calls layout and current graph-cap selection at `edb6f20f` | 214 passed, 14.79 s | Actual combined source before the later security fixes. |
| SQLite constructor repair | Baseline 18 failed / 2 passed; focused final 26 passed | Actual SQLite ownership/failure paths. Expanded surrounding selections also ran; those counts overlap. |
| Schema rollback preservation | 24 demonstrated baseline failures; combined constructor/rollback selection 142 passed, 1 skipped | Failure precedence and connection ownership; native platform skip remains unverified. |
| Transaction rollback preservation `644f4ab6` | Baseline 16 failed / 2 passed; combined 160 passed, 1 skipped, 5.80 s | Write/commit/rollback failure paths. Independent immutable-source review and 18-case replay also passed. |
| Forced export/content verification/cleanup precedence | Final 86 passed, 1 native-Windows skip; independent replay also 86 passed, 1 skipped | Includes negative ownership and receipt tests. It does not prove the open Linux source-name race is impossible. Adjacent advisory/storage selection: 21 passed. |
| Tier-W input/byte-bound admission `811713a9` | Initial 16 red failures; two additional late-input publication regressions failed; final 145 passed, 2 expected failures, 8.32 s | CLI, regular-file byte bounds, corpus/symbol ownership, existing corpus/symbol/runner controls and generated schema drift. Expected failures remain explicit in the log. |
| Runner provenance/output admission `d3fe7f65` | 12 demonstrated red controls; 33 runner/admission tests passed | Backend/input/symbol-policy ownership, duplicate IDs and output aliases. Cancellation/publication follow-up is separate. |

Normal `python -m ruff check src tests tools` passes through the Tier-W admission
commit. Initial merged code also passed compileall. Regenerated calibration
schemas are checked against committed bytes. One intermediate schema-drift test
failed because its expected schema-name set lacked newly generated RunRecord;
the set was updated to include the new public contract and the test then passed.

## Broad suite and resource failures

The first combined `QT_QPA_PLATFORM=offscreen python -m pytest -q` process on
`a9e40d27` was killed with exit 137 before producing a test summary. Its log was
empty. The execution host then became unavailable and recovered later. This is
an aborted verification attempt, not a pass and not an identified product defect.
An earlier focused command named nonexistent `tests/test_ui_graph_inspect.py`;
it collected no tests. The corrected `test_ui_graph_inspection.py` selection
produced the 214-pass result above.

A fresh frozen worktree at **`7dfba50f`** is running every matching test file in
sequential bounded groups. Each process uses offscreen Qt and `PYTHONPATH=src`,
at most 20 test files or 220 KB of test source per group, distinct temporary
directories and a JUnit result. Source is frozen during the run. The manifest
and per-group results are under the task checkpoint directory
`bounded-qa-7dfba50f/summary.json`; final durable results must be copied into this
record before claiming suite completion. Added or changed functionality after
that SHA needs its own affected-suite rerun.

## CI and acceptance

The first remote checkpoint exposed 31 check runs. At the recorded observation,
26 were queued, 3 were skipped, and the Linux BinDiff and intel-tool workflow
jobs reported success. A workflow status alone is not evidence that an optional
native branch actually ran; its actual receipt must be inspected before native
acceptance is credited. This checkpoint is not a green overall CI gate.

Native Windows, complete Qt repeats, real Ghidra/Ghidriff/rz-diff/BinDiff/capa
acceptance, real-data accuracy, dependency audit and Windows standalone package
qualification remain separate required checks. Skips, mocked engines, fixtures
and historical receipts are never promoted to those claims.

## Reproduction

From a disposable checkout of the named source, install project dev/search/rules
extras, then run:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q
python -m ruff check src tests tools
PYTHONPATH=src python -m tools.calibration.schemas
git diff --exit-code -- docs/schemas/calibration
```

When memory requires bounded groups, retain the exact complete file manifest,
commands, source SHA, JUnit results, exits and any omissions. Do not describe a
partially completed group run as a complete passing suite.
