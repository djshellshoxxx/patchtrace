# Pilot: retained CVRF context fallback

Status: approved implementation scope, 2026-11-18. Parent: PIL-integration-plan.md
sections 4, 7 and 8; KB source and field-provenance contracts remain authoritative.
This amendment changes an internal advisory port, not a persisted schema.

## Problem and scope

The real `kb import-pair` route attaches a source-bound `kb-context` to its project.
After comparison and ranking, `kb leads` can use that CVRF context, but pilot only
reads the CSAF store. A named CVRF-only CVE consequently returns no stored advisory.
Pilot shall consume eligible retained CVRF context through the existing owner-thread
project service, without opening another project or consulting a workspace cache.

The fallback is documentary candidate context. It does not establish binary product
membership, a fix boundary, or a changed function's relationship to a CVE. The project
bundle contains recorded import-time field bindings, not raw source objects or full
retrieval provenance. Every fallback context states that raw bytes and upstream
freshness were not reverified. Imported authenticity remains unestablished.

## Interfaces and ownership

`pilot/sources/kb_context.py` owns bounded capture and a pure adapter:

- `capture(service, enrichment, project=None, budget=...) -> ContextSnapshot`: reads only the
  already-owned project store. The result contains immutable validated current heads,
  plain warnings, and `digest: str | None` for the retained context state.
- `ContextSnapshot.cves`: sorted eligible CVRF CVEs. An unavailable snapshot supplies
  none; unavailable evidence is unknown, never a negative assertion.
- `fallback_facts_ids(snapshot, csaf_cves, selected)`: exact recorded source SHA-256
  values behind selected CVRF fallback cards. CSAF overlap contributes no CVRF vote.
- `available_cves(snapshot, csaf_cves, csaf_readable=...)`: shared pure universe for
  collection and stored-result comparison. Both helpers accept `csaf_readable=False`
  to suppress fallback when the CSAF universe could not be fully read.
- `ProjectAdvisorySource`: composes the existing `StoredAdvisorySource` with the
  captured fallback; offers `context(cve, assume_applies=False)`, the existing source
  methods, and optional `kb_link_digest` for the localization identity.

`pilot/ports.py` describes the non-persisted `AdvisoryRuleView` (hypotheses and anchors).
An existing `IntelligenceReport` satisfies this structural view. CVRF uses an honest
small view; it never fabricates CSAF schema, publisher, tracking or raw-path metadata.
`collect.py` combines the CVE universe and contexts. `service.py` records the adapter's
optional digest in the existing `PilotInputs.kb_link_digest`, defaulting to `None`.

The separate current-input qualification work owns `pilot/current_inputs.py`,
`pilot/store.py`, `pilot/cli.py` and `ui_leads.py`. Its follow-up must consume this same
capture/identity seam before the combined feature is qualified as fresh on read.

## Admission, revision and integrity

Capture checks the row's verified canonical body, project guard, `kb` run marker,
kind, `kb-context:<context_key>` ID/input key, successful status and explicit stale
flag. The original guard's raw digest was made over a different serialization and
must not be compared with the canonical storage-body digest. Each retained context
must match its context-key formula and source document IDs. Fields used as evidence
must have complete `CardFactRef` bindings to the same CVE, source SHA, document,
field value and supported original JSON field location.

Select maximum `base_revision` **within each investigation before CVE or pair
filtering**. Revisions of separate investigations are not comparable. A newer empty
context withdraws earlier cards; a newer invalid, stale or differently oriented head
cannot cause fallback to an older head. Divergent heads at the same revision,
conflicting retained monthly source revisions, or different current card values for
the same CVE are ambiguous and withheld. A withdrawn CVE is not revived by an older
retained copy in another investigation. Where corruption prevents safe grouping,
withhold the CVRF channel and retain a plain reason; valid CSAF remains usable.
An explicitly named withdrawn CVE keeps the existing not-found exit code but says
that a newer context withdrew the card and the older records remain historical.

Legacy contexts without exact field bindings remain readable elsewhere but cannot
be promoted into pilot source evidence. Recompute CWE profiles and hypotheses using
the current `IntelligenceRules.interpret` over admitted fields; never trust persisted
derived profiles as executable rule input. Preserve native pointer casing, e.g.
`/Vulnerability/0/Title/Value` and `/Vulnerability/0/CWE/0/ID`.

## Combination, uncertainty and identity

CSAF takes precedence whenever its retained document universe lists the CVE,
including a superseded revision whose later revision withdrew it. Its applicability,
negative/conflict gates, hypotheses and observations stay authoritative for this
adapter. A retained CVRF overlap is disclosed; it cannot override CSAF or supply
extra independent support. An unreadable CSAF store leaves its overlap universe
unknown and cannot authorize CVRF fallback; independently usable CSAF results remain
available. CVRF-only cards have unknown mapping and applicability on both sides,
no code-locality anchors, and gate `unverified`. The existing explicit
analyst assumption may produce `asserted`, with its normal recorded limitation.

Every CVRF observation is vendor text (`D_vendor_text`, `E-TEXT`, context role),
with the actual recorded source SHA and field pointer. Duplicate agreeing bindings
retain provenance but do not add a rule, origin component or tier. Missing title/CWE
does not invent one. Current classification disagreement and unknowns remain visible.

The context digest is domain separated and covers retained head identity, pair and
unavailable/ambiguous state. It changes on replacement, withdrawal, removal or loss
of integrity. No rows means `None`. Current source SHA values join
`advisory_facts_ids`; the existing 64-source maximum is enforced, never truncated.
Global context invalidation is deliberately conservative in this first slice.

## Budgets and lifecycle

Before body loading, cap the metadata scan at 1,001 rows and refuse more than 1,000
retained rows or 16 MiB total body bytes. Bound decoded structure to 100,000 nodes,
depth 32, 4,096 cards and 16,384 field refs across the captured rows. These bounds
limit admission, not completeness claims. Exceeding them leaves CVRF unavailable
with a limit reason; it does not select a convenient prefix. Check cooperative
cancellation before reads and throughout loops. Pure adaptation accepts immutable
snapshots and reaches no SQLite connection, Qt object, network or target process.

## Acceptance and evidence

Red-first controls cover the actual authored KB import/pair/analysis/rank/pilot
journey, exact native field references, rule recomputation, unknown applicability,
duplicate invariance, CSAF negative/conflict/withdrawal precedence, old row
compatibility, corrupt/missing/forged bindings, wrong ownership, swapped pairs,
newest invalid/withdrawn heads, independent investigations, bounded/cancelled
capture, source identity drift, and no extra project open or external execution.
Current-source subprocess CLI output and desktop stored-result reading are checked
separately. No fixture or offscreen test is native/manual or live-provider acceptance.
Retain failed runs and qualification receipts; independent combined review precedes
remote publication.
