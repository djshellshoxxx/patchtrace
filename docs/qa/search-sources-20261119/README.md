# Production search source recovery — preserved stage-one evidence

**Status: BLOCKED pending selected-row guard admission.** Source
`c14c836fd9fee3e054ae2294122f818ce45b1062` connects production sources and
passes its affected controls, but independent review then demonstrated that a
stale or foreign-project selected tool row can still be indexed. A shared opt-in
admission seam is being prepared for Search and Strings. Do not treat this
stage-one source as approved for assembly.

## Source and scope

Base: `ac3a98150bd17bbbd973c7e7dcadb7edcf551934` (core PR319 local tree).
Spec first: `f96b2c3a4f8c77e8f7c0bbec419775ad4e601c83`.
Original bounded slice: `33e7e33805e68b03665ab860fc19c83fd11fc5d8`
from `claude/autonomous-finish-20261104`.

Only search CLI, panel declaration, Qt controller and the new `search/wiring.py`
change at runtime. The original patch did not apply intact across the current
saved-query CLI/Qt seams; reconciliation retains named/recent storage actions,
canonical filters, captured query generations and the saved-run plan. Existing
injected source ports retain their path.

The bridge reads existing stores on the owning thread and sends copied project
state plus frozen source values to workers. It checks current artifact/side,
engine, configuration/cache and non-cache run identity. Valid cache reuse may
retain the evidence's original run ID. Its metadata memo includes body hashes,
guard/stale fields and current artifact identities. Admission above10,000 relevant
metadata rows gives explicit unavailable optional groups; ordinary note search
still works. This new bridge limit changes no shared reader/body cap.

Shared ToolStore, EnrichmentStore, bounded advisory storage, owned publication,
and saved-query storage/adapters are byte-identical to the base; receipt.json
records their Git blobs. This is also why selected guard/stale metadata still
requires a separate admission check: memo invalidation alone cannot provide it.

## Observed tests

| Observation | Result | Meaning |
|---|---|---|
| Independent baseline missing-behavior probe on core319 | Exit0,1.82s | One imported advisory yields0 production hits; existing adapter injection yields1. Same probe separately records the Strings cue gap. |
| Original source slice plus current-artifact controls |13 failed,9 passed in8.78s | Actual orientation/identity, stale memo, metadata limit and shared project-object failures. |
| Affected search/saved/Qt/advisory controls after repairs |927 passed in59.24s | Before import ordering, source-limit copy and the extra general-group control. |
| First added general-group control |236 passed,1 failed in10.81s | Test fixture supplied function rows without a completed raw analysis, so the existing fn source correctly stayed not-applicable. This is preserved. |
| Corrected real note control plus current-source/Qt/help checks |237 passed in9.59s | A real persisted note is searchable before and after optional-source refusal; final runtime/tests match the pinned source. |
| Full Ruff / whitespace |PASS | Initial Ruff import-order failure is retained separately. |
| Independent selected-row guard probe on pinned source |2 reproduced cases | After stale=1 or foreign project_id, snapshot rebuilt but newer capa stayed indexed/comparable and returned a CLI hit. This blocks assembly. |

The test-fixture correction did not weaken the product's raw-analysis requirement.
It uses an actual persisted analyst note as an independently searchable base
group, demonstrates a successful ordinary query first, then changes only the
optional-source limit and repeats that query. All eight optional groups report
unavailable with their reason.

The red patch/hashes and raw logs/JUnit are preserved; `.gz` files are deterministic
lossless gzip. The receipt records original and stored hashes. Counts overlap
between commands and must not be added as unique-test coverage.

## Limits and next step

Security review owns a small shared admission helper/spec/tests; Search and
Strings will opt in. Re-run the independent stale/foreign real-store probe and
focused caller controls after integration. Preserve this failing stage-one record.

No target image was executed. Tool-route fixtures use authored fake tools and
inert synthetic PE bytes. No live provider, real native compatibility, Windows
GUI/frozen package, repeated20-session Qt or full-repository qualification is
claimed. The two unrelated local full-suite exit137 attempts remain blocked and
unattributed; these focused passes do not qualify them.
