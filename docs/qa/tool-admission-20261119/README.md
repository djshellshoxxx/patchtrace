# Opt-in stored-tool admission — 2026-11-19

## Source and disposition

Source: `41af7c7e3f3bd5e50c49b86bc061fdef834b4daf`.
Tree: `3e2e48e4fd7fd159d84eefb3b9f3acf5b78d7e8d`.
Base: core319 `ac3a98150bd17bbbd973c7e7dcadb7edcf551934`.

Apply the three commits in order:

1. `9bdde026ea6b3be1d79a04284c402d2e9c9e70df` — T14 contract and module index.
2. `8eae07d390c3ab74e1f90f863793ea4ab521e14d` — side-aware cache selection, lazy group admission, recorded raw provenance.
3. `41af7c7e3f3bd5e50c49b86bc061fdef834b4daf` — shared helper and 33 controls.

The focused helper controls pass and independent helper review is scoped
approved. The Search/Strings caller adaptations, exact combined CI, and
native/package gates are separate; this receipt does not mark them passed. No
remote mutation or target-binary execution occurred in this work.

The runtime addition is `intelligence/tools/admission.py`. Its opt-in API returns
`AdmittedToolEvidence(run, evidence, evidence_run)` or no produced match; invalid
selected records raise a fixed-message `ToolError`. Existing public ToolStore,
EnrichmentStore, common contracts, normalization, persistence and dependencies
are unchanged; `source-proof.json` records equal Git blobs.

## Confirmed defects and repair

The retained in-owner Search snapshot and Strings composition probes show that
selected stale or foreign-project run metadata could remain usable evidence.
The original reopened Search CLI output has the fixture limitation recorded
in the correction below; it is not proof of persisted invalid-row admission.
The legacy ToolStore read returned body models without their Entry metadata.
The 21-case author probe returned evidence in 20 invalid-metadata cases
(including an older-run fallback) and silently returned no match in one case.

The helper retains and admits selected row metadata, exact current guards,
row/body status and IDs, body engine/side/artifact/cache/configuration bindings,
and evidence count/status consistency. It uses original `body_json` for strict
row parsing so duplicate keys cannot disappear in a parsed dictionary.

Actual producer cache hits have `raw_sidecar=None` and `stdout_digest=None`;
their normalized evidence retains its original run ID. The helper fully admits
that originating run and returns it for recorded provenance. The production
helper does not reread raw files. Existing normalized-sidecar loading and its
I/O policy are reused, without a new global store byte/row policy.

Cache evidence selection includes engine, side and cache key. An authored,
coherent retained orientation-history record exercises the fact that the key
does not include side, while the selected cache run itself comes from the real
runner's fresh-to-cache path. This is not an invalid A/A runner request.

Independent review also reproduced a typed-error gap in the draft: replacing
TEXT body storage with an identical UTF-8 BLOB retained its content digest but
raised AttributeError inside EnrichmentStore before strict row admission. The
opt-in boundary now converts that read failure into ToolError; public readers
are unchanged. The original independent red proof remains in the archive.

## Completed checks

| Check | Result | Source scope |
|---|---|---|
| Legacy metadata probe | 20 nonempty returns, one silent no-match across 21 invalid-metadata cases | Original public reader at spec-only 9bdde026 |
| Resumed draft metadata probe | 21 typed refusals | Earlier uncommitted helper; historical result only |
| Initial helper controls | 24 passed in 16.94 seconds | Before side-selection/lazy-admission/BLOB refinements |
| Final changed helper controls | **33 passed in 3.54 seconds**, exit 0 | Source 41af7c7e |
| Independent original BLOB probe | Healthy baseline; two typed OUTPUT refusals | Source 41af7c7e |
| Independent original metadata probe | 21 typed STALE refusals, zero accepted | Source 41af7c7e |
| Independent selected controls | Seven passed in 1.96 seconds | Source 41af7c7e; overlaps author selection |
| Ruff on new helper and tests | Passed, exit 0 | Source 41af7c7e |
| Working/staged whitespace checks | Passed | Source 41af7c7e |

The final 33 comprise: two real producer fresh/cache provenance cases, 21
selected-run/evidence/origin metadata cases, one public-reader compatibility
case, two BLOB cases, three original-JSON duplicate-key cases, two missing
evidence/origin cases, one side-aware cache-history case and one unrelated-side
model case. Refusal controls check database preservation. These selections
overlap earlier checks; their counts must not be added as unique coverage.

The independent review confirmed the helper/test source matches 41af7c7e. The
helper SHA-256 is
`7a06f5087927e263b2433e820ed1b1f5c3c80a6c517d445a342523685c77c373`.

The producer uses an authored fake FLOSS executable and synthetic PE inputs.
The production runner, stores, models and helper are real. This establishes
orchestration and admission behavior, not live FLOSS/native compatibility.

Final command, from the isolated worktree:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=src:tests \
  /workspace/scratch/80dddc5347b2/patchtrace-tool-admission-venv/bin/python \
  -m pytest -q tests/test_intel_tools_admission.py \
  --junitxml=/workspace/scratch/80dddc5347b2/tool-admission-focused-final.xml
```

The dedicated interpreter imports this worktree's source, followed by prepared
dependencies; it does not mutate the shared venv. Source import, Python,
SQLite and platform details are in `source-proof.json`.

## Interrupted checks retained as history

Session25304 was interrupted during workspace unavailability. No initial green
artifact was found; that operation never earned a pass.

Later cell g5:33 attempted two additional test edits and a dependent focused
run during another outage. The orchestration was terminated without a result.
On restoration, both additional tests and the intended final log/XML were
absent. They were then added and the fresh 33-case run completed. The final
result does not retroactively qualify either interrupted operation.

## Evidence and limits

`evidence.zip` contains 20 verbatim members: red/resumed/final logs and probes,
the independently reported BLOB defect, original Search/Strings guard and cache
probes, and the exact source patch. `manifest.json` supplies member sizes and
SHA-256 digests; archive CRC and every member digest were verified.

Archive SHA-256:
`950394cc84b96616fc9286fa4f021a91882bc44a6699b497a853141fe210e011`.

This helper inherits EnrichmentStore's existing materialized read and the
existing normalized-sidecar loader. It makes no new whole-store resource bound,
raw-file freshness or live-native claim. Native absence/unrun gates remain
BLOCKED. Final caller behavior must still be checked on the integrated source:
Search unavailable coverage; Strings Auto verified built-in fallback; explicit
FLOSS refusal; valid real-cache recorded-origin provenance retention.

## Historical evidence correction: original Search CLI probe

The original `search-stale-guard-independent.py` mutated SQLite rows and checked
the Search snapshot while the owning service remained open. It then closed that
service without committing the mutation before reopening the project through
the CLI. The close rolled back those changes. Therefore its `admission_after`
snapshot establishes the in-owner defect, but its reopened CLI `after` result
does not establish admission of persisted invalid metadata. Any earlier wording
that credited that CLI output as such proof is withdrawn.

The original script and JSON remain unchanged in `evidence.zip`; the archive
hash above is retained. The helper's 21-case metadata and independent BLOB
probes admit rows before closing the owner and are unaffected by this fixture
correction. No helper runtime or test result is changed by this addendum.

The corrected `search-stale-guard-persisted.py` adds an explicit commit, a
reopened SELECT/assertion proving the exact changed value persisted, and a
`persisted_after_close` receipt field. The Search owner ran that same corrected
probe against both sources:

| Source | Both persisted mutations | Reopened CLI result |
|---|---|---|
| Red `ebdb8cd044f3296291f6ab236e9920d1d8826980` | Confirmed | Affected newer capa hit remains one; indexed and comparable |
| Green `b5aace25a36809ae7e4ab044e692c12015772a7d` | Confirmed | Affected hit becomes zero; group unavailable with PT-TOOL-STALE and incomparable |

The red wiring blob is `929389a31f4d864303ddf02c59622ab3b5586459`, exactly
matching original Search source `c14c836fd9fee3e054ae2294122f818ce45b1062`.
The green caller replaces duplicated body-only checks with `latest_admitted`
per current artifact/engine/side, retaining per-group refusal and detached
worker values. Independent source review found no blocker in that caller diff.
It inspected the minimal corrected probe, source equality and red/green
receipts; it did not claim a separate execution of those corrected probes.

`search-cli-correction.zip` retains the corrected probe, both receipts and the
exact caller patch. `search-cli-correction.json` records pins and member digests.
The original 20-member archive is unchanged. The four-member correction archive
passed CRC and per-member SHA-256 verification; its SHA-256 is
`26749b06c2574889dedfa1732a84f0384ca8a3bd989f99f5663cdc514b4409c5`.
