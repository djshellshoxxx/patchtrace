# Search selected-row admission — 2026-11-19

Local scoped controls pass on **b5aace25a36809ae7e4ab044e692c12015772a7d**. Independent source review and the
exact combined candidate's hosted/platform gates remain separate. This packet
supersedes the selected-row blocker for this local source; it does not retroactively
qualify stage-one source `c14c836fd9fee3e054ae2294122f818ce45b1062` or any broader product release.

## Scope and source

The Search bridge now calls the shared opt-in `latest_admitted` boundary once per
engine/current artifact side. It stores the admitted run/evidence values in the
existing owner-thread snapshot. Rejected selected records produce explicit
unavailable coverage and cannot establish comparability. The current metadata
key still invalidates cached snapshots when stale/guard/body-hash fields change.
Normal queries exclude unavailable sources even when an old index segment exists.

The caller runtime delta after c14 is only `src/patchtrace/search/wiring.py`.
The shared helper is byte-identical to the author's source
`41af7c7e3f3bd5e50c49b86bc061fdef834b4daf`. CLI dispatch, saved-query semantics,
Qt generation guards, owner-thread capture, advisory reader limits and the 10,000
optional metadata-row boundary are unchanged by this correction. The existing
real-note control still proves normal base search with optional sources refused.

| Layer | Commits |
| --- | --- |
| Existing selective production binding | Spec f96b2c3a; runtime c14c836f; stage-one QA efcc2462 |
| Shared dependency, original author sequence | 9bdde026 → 8eae07d3 → 41af7c7e |
| Shared dependency, local cherry-picks | 61bc3064 → 847c8e19 → de0943f0 |
| Caller spec and initial controls | 01611af60e886ffb53e3e4d097698c03933be198 |
| Real stored-row controls and persistence correction | ebdb8cd044f3296291f6ab236e9920d1d8826980 |
| Caller implementation and existing spy adaptation | b5aace25a36809ae7e4ab044e692c12015772a7d |

An assembly must include the shared dependency once, then the caller-only
sequence. `receipt.json` contains full IDs; `source-manifest.json` contains exact
Git blobs and SHA-256 values. `caller-source.patch.gz` records the caller-only
delta after the shared dependency. The earlier external prepared patch was
partially applied, then reconciled with the corrected real-store controls; the
committed sequence is authoritative.

## Historical fixture correction

The original independent probe changed row metadata on an open SQLite connection,
captured a source snapshot, and then closed without committing. The in-owner
snapshot showed a real admission defect. **Its later reopened CLI call did not
prove admission of the changed row:** close rolled back that fixture mutation.
The stage-one QA and checkpoint wording that treated that CLI output as proof
were too broad. `probe_original.py/json` are retained byte-for-byte and are now
qualified to their valid in-owner scope; they are not erased or relabeled as green.

The first four new caller controls copied the same fixture error: four failures
before adaptation, then four failures alongside 56 passes after adaptation.
Those reopened-CLI failures were test-fixture failures, not four additional
product defects. Both complete attempts are retained. No assertion or runtime
budget was weakened.

The correction explicitly commits the authored mutation, reopens the actual
project, and asserts the stored value before invoking Search. The minimal change
is in `probe-fixture-correction.patch`. The corrected tests also check normal
automatic-build queries without `--rebuild`; the corrected standalone probe keeps
the original `--rebuild` route. Both use real project stores and authored fake
capa output on synthetic PE inputs, never target execution.

## Corrected red and green evidence

The frozen baseline **ebdb8cd044f3296291f6ab236e9920d1d8826980** contains the new tests and shared helper, but
its Search wiring is unchanged from c14: blob
`929389a31f4d864303ddf02c59622ab3b5586459`. The helper is not called by that baseline
bridge. Its four committed/reopened mutation cases fail in **3.94 seconds**.
The corrected independent probe confirms persisted mutations and still returns
one newer capa hit after both stale and foreign-project changes.

On the repaired source, the same corrected probe confirms each mutation persists,
then returns **zero** newer capa hits, explicit `PT-TOOL-STALE` unavailable coverage,
and `comparable=False`. The opposite valid tool side remains buildable in the
normal-query regression controls.

| Observation | Result | Interpretation |
| --- | --- | --- |
| Initial uncommitted-mutation controls | 4 failed in 4.53 s | Fixture did not persist across CLI reopen; retained, not valid CLI red proof |
| First adapted focused selection, same fixture error | 56 passed, 4 failed in 13.87 s | Four persistence-fixture failures retained |
| Corrected baseline normal CLI controls | 4 failed in 3.94 s | Real guard admission defect; persisted values asserted after reopen |
| Current-source, wiring and shared-admission controls | 60 passed in 36.51 s | Real body/metadata refusal, cache origin, optional limit, owner-thread/Qt custody |
| Adjacent CLI/saved/Qt/source/help selection | 418 passed in 29.89 s | Existing surrounding workflow contracts retained |
| Corrected standalone probe | 2 red cases → 2 green cases | Persisted metadata, actual CLI rebuild, coverage/comparability receipt |
| Ordinary Ruff and whitespace | Passed | No suppression added |

The 60 focused cases ran on the working source immediately before the b5aace25
commit; there was no source/test edit between their success and that commit.
The 418 adjacent cases and green standalone probe ran on the exact committed
source. These selections overlap earlier stage-one/helper-author receipts and
must not be added to historical pass totals. All raw logs/XML are preserved using
deterministic gzip; original uncompressed hashes are in the receipt.

The nine prior run/evidence identity controls now mutate real stored JSON and its
checksum instead of mocking `ToolStore.latest`, which the repaired caller no
longer uses. A changed engine/side can affect source attribution, so the old mock's
assumption that the opposite group remains buildable was removed from those
body-mutation cases. Independent per-group failure controls remain, and all four
metadata guard cases explicitly require the opposite valid side to remain usable.
The metadata-budget control observes the actual `EnrichmentStore.entries` seam and
confirms no source body reads on metadata admission refusal.

## Replay and limits

Use the existing reviewed environment with `PYTHONPATH=src`,
`PYTHONDONTWRITEBYTECODE=1` and `QT_QPA_PLATFORM=offscreen`:

```sh
python -m pytest -q -p no:cacheprovider tests/test_search_current_sources.py tests/test_search_wiring.py tests/test_intel_tools_admission.py
python -m pytest -q -p no:cacheprovider tests/test_search_cli.py tests/test_search_saved.py tests/test_search_saved_workflow.py tests/test_ui_search_saved.py tests/test_ui_search_panel.py tests/test_search_sources_tools.py tests/test_help_docs.py
python -m ruff check src tests tools
PYTHONPATH=src:tests python docs/qa/search-admission-20261119/probe_persisted.py
```

The recorded focused/red/probe commands used 60-second outer supervision and
adjacent controls used 90 seconds, with five-second termination grace. None reached
that bound. No product timeout or performance threshold changed.

This is portable source/storage/offscreen Qt evidence. Public `ToolStore`, the
existing normalized-sidecar I/O contract and broader resource budgets are unchanged.
Raw origin fields are recorded provenance, not newly verified current raw-file bytes.
No persisted schema/model changed. Full hosted Linux/Windows, native tool, frozen
package, actual accessibility and exact combined-candidate gates are not closed here.
The previous exit-137 full-suite records remain incomplete and unattributed.
