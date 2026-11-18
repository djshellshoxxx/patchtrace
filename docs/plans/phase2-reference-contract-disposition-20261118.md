# Phase 2 reference contracts: current-source disposition

Comparison source: **`068513a72e8a1412ce3960d3024c462d68d51376`**, tree
`2183dcf3b9cfee268c3ebb163ad9f3e9e928e10f`.
Historical reference: **`4522030ff3ff76d720a5efc33953aaa5e5837398`**,
`haiku/phase2-handoff-import-20261027`.

This is a read-only follow-up to semantic batch seven. It reconciles the nine
reference record families with actual producers, validators and consumers. It
does not import a replacement schema, change existing records, alter scoring or
close the historical branch. The original 131-tip focal denominator remains
unchanged; broader residues from that inventory remain open.

[Machine-readable disposition](phase2-reference-contract-disposition-20261118.json)
and [sealed source and QA receipt](../qa/phase2-reference-contract-disposition-20261118.md)
retain the exact reference files, current source and caller proofs.

## Decision

Keep `enrichment/1` and `pilot/1` as their existing, distinct runtime contracts.
The reference `schema_version=1` objects are not compatible wire aliases. The
current implementation distributes their responsibilities across more records,
uses different identity recipes and has later explicit policy decisions. A
renamed field cannot supply missing ownership, source provenance or typed code
evidence. A future interchange adapter would require its own version, explicit
source context and loss/unknown rules before it could import or export these
objects.

One small production gap is confirmed: the desktop's signal navigation bypasses
the existing live location validator. This is the same UI-owner obligation
already called out in `enrichment-hardening-backlog.md`; it is not newly inferred
from a historical name match. An actual persisted-row/reopen/window probe gives
three failures with four positive controls. A separate, narrow navigation repair
can reuse the validator without changing scores, confidence, stored evidence,
schema or detector behavior.

## Reference authority and preservation

The historical extension document identifies itself as a proposal grounded in
the October 11 repository. Its import provenance explicitly says that the nine
schemas need runtime checks for arithmetic, identity, ownership and store
invariants. The import added documentation, synthetic examples and schema-only
tests; it added no runtime implementation. All 20 `$ref` values are local
fragments. The reference documents and test file are retained byte for byte in
this packet:

| Original file | SHA-256 |
| --- | --- |
| `PatchTrace-Extension-Specification-2026-10-11.md` | `cdd94117ee9a4e847a9ffe2dcf14c21e1a9c68c9ce250751ccb5d4ccacc9209d` |
| `PatchTrace-Phase2-Contracts-v1.schema.json` | `e903f4a604bcef4d7a8728317198a99b8e49bd1cfb5b9725dc8d6b647472522c` |
| `PatchTrace-Phase2-Synthetic-Examples-v1.json` | `9a579d01bdb0ec771f83e8f83ef2a9ad1a715c9b76938e0dd8de394593c3b0eb` |
| `test_phase2_contract_examples.py` | `5d38fee13be891eb5f83637ead9354268091f5463e4b0b74b6758285dbb5b0e7` |

The unchanged provenance document is retained too. Existing batch-seven results
remain attributed to their old comparison window, including its initial
missing-`jsonschema` collection error and later 23-pass reference-only run. The
new run used dependencies already installed in the primary runtime and the
product test environment; it installed nothing. Original sources and old
outcomes were not corrected or rewritten.

Current `enrichment.md` explains that the implementing session did not receive
the package and requires explicit reconciliation before any version change.
That historical statement is compatible with this later import. It does not
make the original schema the machine format of today's stored records. A search
of the pinned `src/` and `tools/` finds no consumer of the reference package or
its proposed record names. Actual public `parse_snapshots` rejects its CVE wire
object with `PT-ENRICH-INPUT`.

## Nine record families and current boundaries

The machine-readable file includes each record's actual producers, consumers,
retained behavior, incompatible fields and remaining obligation. The following
table states the consequential differences; none of its rows asserts complete
semantic equivalence.

| Reference | Current projection and callers | Disposition |
| --- | --- | --- |
| `EvidenceRefV1` | `SourceLocation`, `FunctionView`, `RunView` and storage `Guard`; produced by `views.FunctionView.location`, checked on derived-cache reads by `pipeline._locations_owned`, consumed by desktop navigation and the pilot B1 adapter | The current locator carries run/artifact/function IDs, side, inclusive lines, excerpt hash and optional address. Outer objects supply project/raw identity. The reference also combines artifact SHA, diff/occurrence IDs, pointer, source kind, address kind and quality. Current and reference IDs have different recipes. The live validator exists, but desktop `jump_signal` omits it. |
| `FeatureGateV1` | `FeatureSite` and `FeatureTransition`; `wil.analyze` → pipeline/`flags`/signal display | Numeric IDs, locations, lexical enclosure, adjacent-only uncertainty and transitions exist. Explicit parent feature IDs, friendly-name mapping provenance and resolved-symbol hashes are not interchangeable current fields. The pipeline does not feed an authenticated PDB-name map to `analyze`; its default symbol status is absent. Nested enclosure tests do not establish typed dominance. |
| `ChangeSignalV1` | `ChangeSignal`, `SignalSet`, `DetectorOutcome`, `StageResult`; detectors → attention ranking and pilot `B1Evidence` | The eight detectors, grouping, uncertainty and exact locations exist. Category, weights, stage status and diagnostics are distributed across records instead of repeated on each signal. A schema import supplies no typed IR. Missing/truncated evidence remains distinct from complete zero findings. |
| `RankingConfigV1` | `RankingConfig`; CLI/profile configuration → `ranking.score_signals` | The default weights and exact `attention/1` arithmetic agree: group cap 40, raw cap 80, integer multipliers 100/70/35/0. The reference serializes caps and multipliers; current caps/multipliers are algorithm constants. Its schema's configurable multiplier shape does not authorize a current calibration change. |
| `FunctionRankingV1` | `RankingEntry` plus `RankingResult`; `ranking.rank` → CLI, desktop, report adapter | Base score, raw/group subtotals, deterministic ordering, match certainty and evidence state exist. Proposed `missing_reasons`, `tie_key` and common per-row provenance are not current fields; diagnostics live elsewhere. Existing report/GUI agreement applies to the current base ranking, not every proposed field. |
| `CVEContextV1` | `CveSnapshot`, attributed fields and CVSS records; normalization/import/latest-provider selection → contextual rank | Provider digests, attribution, conflicts and conservative freshness exist. The reference's modified timestamp, richer affected predicates and availability envelope are not all represented in B3. Snapshot identity recipes and CVE bounds differ. The reference prose has a length cap its schema does not express. Richer intelligence/CSAF records are separate contracts, not automatically equivalent B3 snapshots. |
| `ContextualRankingV1` | `ContextContribution`, `ContextualEntry`, `ContextualRanking`; CLI `correlate` → pipeline → stored contextual row | Base values stay intact; the +30 cap and binary-support/conflict guards exist. The current contribution stores a source label, binary reference and detail rather than every proposed field-digest/token/rule field. Desktop `rank_changes` supplies no snapshots; its report adapter emits base ranking. Leads is not proof of the proposed B3 desktop/report projection. |
| `CacheManifestV1` | `CacheManifest`, `CacheConfig`, `RuntimeFingerprint`; derived cache and backend raw-cache callers | Current one-payload manifests, strict hash/size checks, private staging, runtime eligibility and input keys implement the current cache design. Reference multi-file/state/access/provenance fields do not map by renaming. Native locking, power-loss behavior and performance acceptance are not established by this reconciliation. |
| `PipelineExecutionV1` | `PipelineStatus`, `StageResult`, options/result objects and stored entries; worker execution → owner-thread publication → consumers | Guarded publication, stage statuses, cancellation refusal and version/config metadata exist. Operational offline/cache policy lives in options/profile/adapters. Currency deliberately ignores note-only project revision changes under the later contract. A reference import must not restore the older broad revision rule or silently alter persisted rows. |

Ten new wire-boundary controls pass: each of the nine reference-valid objects
is rejected by its current projection, and the actual snapshot parser rejects
the reference CVE object. These are expected refusals. They demonstrate why an
automatic rename/import would be wrong; they do not qualify a future adapter.

## Actual product paths

`cli.cmd_rank`, `cmd_flags` and `cmd_correlate` use `_run_pipeline` to open one
project, run the shared pipeline and publish through the owner-thread store.
`correlate` obtains snapshots only from the explicit file/fetch path, removes
file-loaded feature-ID claims and labels those files unverified. Its online
path constructs and prints exact provider requests before consenting transport.
This inspection did not execute that transport or claim current live endpoints.

The desktop `rank_changes` captures a project snapshot for worker computation,
then publishes and reloads on completion. `_load_enrichment` selects the default
or named profile and checks current input/algorithm identity. `_render_signals`
displays detector, confidence and original line ranges. The base ranking goes
through `_enrichment_export` and `reports._ranking_section`; it does not become
a CVE localization score. The preserved current UI tests exercise real worker
completion, reopen/staleness, navigation and Markdown/HTML/JSON base values.

The cache path's `_locations_owned` checks each cached signal/site against live
function ownership, address, line bounds and excerpt hash. `views.validate_location`
also exists as a public semantic validator and has explicit mismatch tests.
The desktop method currently proceeds directly to `reveal_lines`, which only
uses the function's display offset and requested lines. This is the concrete
missing call, rather than a missing validation primitive.

### Pilot consumes observations, not B3 numbers

`pilot.collect._signal_sets` loads current B1 sets or computes them in memory.
`pilot.sources.code.B1Evidence` maps their detector kinds, rationale and locations
to `tool-reported` code-shape observations with Ghidra origin. It reads neither
the attention score nor contextual adjustment. `pilot.collect.collect` obtains
current advisory contexts separately, retaining CSAF/CVRF source admission and
the same-origin vendor-text policy already implemented on this baseline.

`pilot/1` has ordinal mechanism and lead classes, explicit applicability and
quality gates, source-component independence and tie groups. `STRONG_REACHABLE`
is false; `AssignedMechanism` excludes `strong`. `tiers.derive` cannot assign
it. `pilot.ranking` uses integer order keys and candidate-key tie ordering; it
documents that the earlier plan's attention-rank tie preference has no supplying
source yet. Nothing in this packet adds that source or changes the order.
Current fusion tests check missing channels, source dependence, disputed
identity, confounded windows and the limits of lexical evidence. Their success
is not a corpus calibration result or evidence of CVE truth.

## Confirmed boundary: P2-NAV-1

The original external probe is
`test_phase2_navigation_boundary.py`, SHA-256
`61b5d7c21778e12ba71bc6d32a0779f7d1d457656955bf2bfdab64c8c5953688`.
It creates an authored sample project, computes real signal records and alters
only one location field to make a schema-valid but semantically invalid derived
record. The real pipeline/store writes the row with its ordinary checksum; the
project is closed and reopened before a real offscreen `MainWindow` loads it.
The probe then calls the real signal action and records actual cursor selection.

| Case | Current observed result | Required boundary |
| --- | --- | --- |
| Valid location | Current code selected; positive passes | Preserve navigation |
| Different excerpt hash | Current code selected with no diagnosis | Refuse stale location |
| Wrong side with same function ID | Current newer code selected despite older-side metadata | Refuse ownership mismatch |
| Different run ID | Current code selected despite the foreign run claim | Refuse ownership mismatch |
| Existing validator on all three invalid locations | Correct typed refusal; three positives pass | Reuse this validator |

The exact run is **3 failed / 4 passed in 1.67 seconds**, with no skips. Four
observation JSON documents record the original/stored locator, actionable item,
real reveal call, selected text and diagnostics. The probe prohibits network and
child execution. It does not claim ordinary detectors produce malformed rows,
that a checksum authenticates an origin, or that the stored row can currently
be imported through the reference schema.

### Approved narrow next slice

On a separate branch from this exact baseline, amend the current navigation
contract and add regression coverage before source changes. In the actual
signal-navigation method, call `views.validate_location` on the live project
before changing display mode or revealing text. Refuse an invalid/stale
run/artifact/side/address/excerpt with a bounded diagnosis and preserve valid
selection behavior. Keep original evidence and all score/confidence outputs
unchanged. The existing validator's current function/line/ownership checks are
the authority; avoid another competing validator.

The approved slice does not broaden into publication validation, cache policy,
report arithmetic or richer reference-format support. The malformed-row
publication in this reproducer is a fixture route, not permission to change
storage semantics. Root will independently replay the unchanged probe using
an observation-only redirection plugin so the original red observations remain
untouched.

## Required behavior, deferred capability and qualification

Current implementation obligations include strict/current identities, bounded
input parsing, explicit unavailable/partial state, exact attention arithmetic,
no contextual score without binary support, no automatic CVE egress and guarded
navigation. The confirmed next repair is the last of those at the actual
desktop call site. The focused 11-file current gate passed **697 cases in
8.29 seconds**, with no failures or skips. It covers authored enrichment,
storage, offscreen UI and pilot contracts/adapters/fusion; its children are
source-only Python import/schema checks.

The **23 original reference tests passed in 0.12 seconds**. They check only
schema shape, nine valid/nine invalid labels and provenance hashes. The
**10 wire-boundary controls passed in 0.21 seconds**. These gates have distinct
purposes and overlap in facts they check; their counts are not a completion
percentage or an additive feature-coverage score.

Typed IR dominance/dataflow, authenticated WIL private-wrapper/friendly-name
mapping, broader affected-product predicates, full proposed B3 desktop/report
presentation and any reference interchange adapter remain explicit design or
qualification work. Phase 3/4 acquisition, secondary-engine, AI and calibration
proposals in the historical document are outside this Phase 2 reconciliation.
They are not evidence to change pilot tiers or to port a superseded runtime.

No live CVE fetch, native engine, compiler, target, package, frozen executable,
Windows run, calibration experiment or manual desktop acceptance occurred.
Historical performance results and remaining release gates keep their original
attribution. No source change, remote mutation, merge or branch closure is
included in this disposition.
