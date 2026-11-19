# Consolidation verification

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Current recorded code: `7e610c03`; prior verified remote source: `1341dc21`
(local tree equivalent `65043fe8`).
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

The restored run completed all 121 groups after retaining the original successful
coverage of 160 files. The exact union is 953 test files. Group 111 was killed
without JUnit; its smaller files then passed 168 tests, its 10k benchmark cases
passed 3, and its separate dense 60k control passed 1. The other three 60k cases
were killed again (shell exit 137) before a result and remain unverified.

The disjoint completed-case ledger contains **25,943 passed, 150 skipped,
3 expected failures, 9 errors and 1 failure** (26,106 cases; zero duplicate IDs).
It excludes the earlier killed group's otherwise-present XML from credited
coverage. Original attempts, failures, harness, manifests, command lines and
retry receipts are retained in `evidence/bounded-qa-7dfba50f-all-attempts.zip`;
selection rules, hashes and exact unverified node IDs are in
`evidence/bounded-qa-7dfba50f-complete-summary.json`.

The nine errors are the cold SSL import/KEV socket fixture failure, subsequently
repaired at `c970080c` with 333 focused passes and independent review. The one
failure is actual AF_UNIX creation denied by this host policy; it remains an
unqualified platform control and was not skipped to hide the restriction.
These are results of frozen `7dfba50f`, not a claim that the newer integration
candidate passed the complete suite.

## Current affected-source results

| Change/source | Observed result | Qualification |
|---|---|---|
| Tier-W offline review/run `c6d15e04` | Author 214; integrated 147 passed 12.87s | Offline fixtures and explicit local runtime admission; single-writer/race scope retained. |
| Shared stored sources `9e559383` | Author 176; independent 49 passed 18.26s | Five demonstrated identity failures repaired; no native tool execution. |
| Strings completion `ecfd5960` | Integrated 1464 passed 97.89s; independent 49 passed 6.95s | Complete affected Strings/Search/shared-source selection; no skips; counts overlap. |
| Streaming publication/transport `04df9ede` | Author 188 passed/two native skips; independent 120 passed/one skip, 4.40 s | Held ranged reads and publication; platform qualification remains separate. |
| Combined schema/CLI/stream/version boundaries | 209 passed/one native skip, 13.55 s | Current integration after schema conflict resolution, before version filter follow-up. |
| Version `7bce4d02` then `3be22028` | 220 passed/one opt-in frozen-smoke skip; independent filter failure; corrected 27 passed 4.25s and independent 27 passed 3.64s | Real same-size tracked edit proves configured filter no longer runs. Source dirty is explicitly unknown. |
| Project lifecycle `fbf95d94`/`950da8f1` | 189 author passes, 123 cleanup author passes, 15 + 15 scoped independent controls; integrated 57 passed 8.25s | Current SQLite/Qt/cancellation/primary-error boundaries; these overlapping selections do not certify phase 2 retry. |

Normal full Ruff passes at `cb1b508c`. Strict security Ruff at `ecfd5960` exits 1
with 81 findings (one additional constant SQL construction relative to the earlier
80). Raw findings are retained; no suppression or threshold relaxation was made.

## CI and acceptance

Latest inspected check snapshot for remote `087f50aa`: 31 checks, 23 queued,
3 skipped, 1 running, 3 successful and 1 failed. The successful jobs are Ubuntu
packaging dependency audit, Linux live rz-diff and the Ubuntu probe. The probe
receipt has not been inspected; job status alone receives no native credit. The
failed job is security-scan.
The inspected security and rz-diff jobs checked out GitHub merge commit `001b8372`, whose tree
`bf90c3f862d144fc11adc471a84a51076987ba2f` exactly equals remote `087f50aa`.

The downloaded security artifact verifies a completed, non-timeout Ruff command
with exit 1 and the original 80 findings. The downloaded Linux rz-diff receipt
records real Rizin 0.9.1, the pinned archive digest, `mocked:false`, engine status
ok, 30 matches, distinct fixture digests and output digest. The ZIP hashes match
the hosted upload logs. This establishes that historical native control on that
source; it is not a final-candidate/native-all-platform or accuracy gate. Artifacts
are retained as `evidence/hosted087f-{security-static,rzdiff}.zip`. The check
snapshot and artifact identities are in `evidence/hosted087f-observation.json`.

Native Windows, complete Qt repeats, real Ghidra/Ghidriff/rz-diff/BinDiff/capa
acceptance, real-data accuracy, fresh-profile dependency audits and Windows standalone package
qualification remain separate required checks. Skips, mocked engines, fixtures
and historical receipts are never promoted to those claims.

## Additional reviewed integration results

| Change/source | Observed result | Scope |
|---|---|---|
| Retry `72255922` plus stage cleanup `fd6861d2` | Author 255 initial and 74 correction controls; independent 57 plus two correction controls; root 74 passed 9.78 s | Counts overlap. Real stage replacement and garbage-collection negatives retained; cooperative final-check interval remains explicit. |
| Saved executor `f60424fc` / root `189edc47` | Author 204 passed/one native skip 9.54 s; independent 57 passed 3.04 s; root 179 passed 9.08 s | Binary/PDB plan, byte-receipt, publication, schema and offline CLI controls. No live network or native Windows credit. |
| Build producer `4af75c62` | Author 233 passed 7.98 s; independent 39 passed 1.77 s, with a separate actual Git-root provenance blocker | Original negative JSON and regression retained; this initial result alone is not approval. |
| Git-root correction `442e3961` | Author 70 passed 5.55 s; independent 43 passed 2.85 s | Real unrelated parent repository, valid detached worktree, changed top-level and replaced root; approved scoped correction. |
| Linux frozen consumer at `7e610c03` | Actual PyInstaller 6.22.3 round-trip and modified-record refusal, 7.99 s | Qt/UI excluded. Exact entry/command/source/tree/digests retained; not a full desktop/Windows package or release receipt. |
| PE cache `e59e9fce` / root `6d0f1509` | Author 214 disjoint passes; independent read review; root 85 passed 14.55 s | Real SQLite, authored PE and offscreen Qt; no native trust claim. An interrupted broader author attempt remains uncredited. |
| Parser slice `03c120e4` / root `7e610c03` | Author 602 disjoint passes; independent read reviews; root 191 passed 6.64 s | Includes current saved-executor interaction; original 89 failures and seven later rz-diff failures are retained. |

Normal full Ruff passes at `7e610c03`. Strict source scan at the same source exits
1 with 80 findings: S310=6, S101=9, S608=37, S105=14, S603=1, S110=10, S314=2,
S108=1. This differs from the earlier 80/81 finding sets and remains a failed
gate. Raw JSON is retained as `evidence/security-ruff-7e610c03.json`.

Latest inspected hosted snapshot on `1341dc21`: 31 checks, 28 queued and three
skipped. It supplies no new passing acceptance evidence. Historical `087f50aa`
Rizin/static artifacts above remain bound to their original tree. A third
executor interruption occurred during the schema cherry-pick; persistent Git
and evidence survived, and only the interrupted reads were retried after recovery.

## Reproduction commands

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
