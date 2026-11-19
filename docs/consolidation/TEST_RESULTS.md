# Consolidation verification

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Current recorded source: `eb595b82`; latest verified remote source: `bc7eb632` (local tree equivalent `11bc7014`).
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

## New integrated results

- Tier-R managed transfer: 370 passed, two native-platform skips, 18.66 s; independent immutable-source review.
- Tier-W paired runner publication: 61 author tests passed; independent 28 publication controls passed in 2.48 s.
- Combined transfer, runner and admission at `0f0e44d7`: 161 passed, 17.95 s.
- GUI accessibility at `153581e7`: 145 passed, 62.37 s, following five baseline failures and two newly exposed current controls.
- Research recovery author: 173 passed, 14 native skips, 5.70 s; independent 52 passed/14 skips and six final cancellation controls. Integrated research plus transfer at `eb595b82`: **189 passed, 14 skipped, 11.60 s**.
- Normal Ruff over `src tests tools` passed at `eb595b82`.
- Current Linux development environment: 32 installed distributions audited after exact-hash pip bootstrap upgrade from 25.0.1 to repository-pinned 26.3; zero advisory findings. This does not qualify fresh profile/platform dependency gates.
- Strict security Ruff at `3c6f5905`: 80 findings with existing triage categories; gate remains non-green. Raw JSON is retained.

## Broad suite and resource failures

The first combined `QT_QPA_PLATFORM=offscreen python -m pytest -q` process on
`a9e40d27` was killed with exit 137 before producing a test summary. Its log was
empty. The execution host then became unavailable and recovered later. This is
an aborted verification attempt, not a pass and not an identified product defect.
An earlier focused command named nonexistent `tests/test_ui_graph_inspect.py`;
it collected no tests. The corrected `test_ui_graph_inspection.py` selection
produced the 214-pass result above.

The first bounded run at frozen **`7dfba50f`** attempted 17 groups before another
executor outage. Several child processes exited -9 without JUnit results. The
uncapped 384 MiB allocation control also exited -9 under pressure, then passed
unchanged in 2.76 s after recovery. Resource-aborted groups receive no pass credit.

The restored run retains the prior successful coverage of 160 files and runs the
remaining files in 121 groups, at most eight files or 90 KB of test source per
process. It uses the persistent task virtualenv, offscreen Qt, `PYTHONPATH=src`,
distinct temporary directories and JUnit results. The complete union manifest is
953 matching test files. At this recorded observation **65/121 groups**
finished; JUnit totals were 13181 cases, 1 failure,
9 setup errors and 84 skips. Groups [39, 44] were
nonzero; this is an incomplete run, not a passing suite.

Group 39 exposes nine KEV setup errors: a fixture replaces the socket type with a
function before a lazy SSL import subclasses it. Group 44 has one Unix-socket
creation refusal from the host's execution policy. Preserve both raw failures;
repair the fixture without weakening its network guard, and leave actual socket
platform acceptance unqualified here. No test was skipped to hide this restriction.

The live record is `bounded-qa-restored-7dfba50f/summary.json`; this checkpoint's
snapshot and compressed failed-group logs are under `evidence/`. Do not edit the
frozen QA checkout. Added or changed functionality after `7dfba50f` requires its
own affected-suite run; a final candidate still needs complete qualification.

## CI and acceptance

The first remote checkpoint exposed 31 check runs. At the recorded observation,
26 were queued, 3 were skipped, and the Linux BinDiff and intel-tool workflow
jobs reported success. A workflow status alone is not evidence that an optional
native branch actually ran; its actual receipt must be inspected before native
acceptance is credited. This checkpoint is not a green overall CI gate. At remote `bc7eb632`, a later observation had 28 queued and three skipped checks.

Native Windows, complete Qt repeats, real Ghidra/Ghidriff/rz-diff/BinDiff/capa
acceptance, real-data accuracy, fresh-profile dependency audits and Windows standalone package
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
