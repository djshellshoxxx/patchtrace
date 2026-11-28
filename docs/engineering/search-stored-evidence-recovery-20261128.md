# Production stored-evidence Search recovery — 2026-11-28

Base: published Pilot `72de37b02cf51eb8be8cb4b6281897a827eabf48`.
Selective reference: unmerged consolidation donor
`6096e64d4e7b8f0ecc6af884f7d220e07790d85a` (PR #320).

The existing tool/advisory source adapters are implemented, but ordinary Search
CLI and desktop construction never supplies them. This work completes that
production path while preserving current admission, ownership, filesystem and
Pilot protections. An absent filename alone was not used as evidence of a gap.

## Incremental plan

1. Specify and implement a shared bounded owner-thread capture helper over the
   current `latest_admitted` seam. Prove strict metadata/body admission, retained
   cache origin, sidecar quotas and independence from the store. Send the stable
   foundation commit to the parallel Strings implementation.
2. Bind the existing S8 source adapters to ordinary CLI search/build/coverage,
   with conservative advisory/CVE completeness and current comparability.
3. Capture desktop inputs before worker submission; preserve saved workflows,
   request generations and current navigation checks. Verify actual default
   desktop behavior and row/filesystem freshness.

## Evidence and remaining gates

Specification and module registration precede implementation. Runtime and
test dependencies were verified from the existing Python 3.12 environment;
the shared editable installation was not rebound. The completed Pilot worktree
was reused on the new Search branch because workspace capacity is limited.

Red/green evidence and exact committed source identities will be appended as
each slice finishes. Full combined, independent, Windows and frozen acceptance
remain with the integration owner. Tests use authored stored data and synthetic
PE files; no native provider, analyzed artifact or live service is executed.

### Slice 1: shared bounded stored-tool capture

The new test module first failed collection because the production snapshot
module did not exist. After implementation, its 47 authored-record controls and
the existing admission/Strings stored-source regressions passed together:
**88 passed**, no skips (4.14 seconds). Ruff and whitespace checks passed.

The helper reuses current `latest_admitted`, adds bounded SQLite projections and
a read savepoint, and checks producer/configuration/sidecar identity without
changing `admission.py`, `store.py`, `EnrichmentStore` or held-file primitives.
Tests cover valid opposite-side preservation, foreign/stale/future rows,
duplicate original JSON, BLOB bodies, metadata classes, cache origin, aggregate
row/body/sidecar limits, failed-read charging, sidecar links and replaced roots.
Returned values are usable after the owner store closes and on another thread.

The stable consumer API is `capture_tool_sources(service, engines=('floss',))`
on the owner thread, then `.admitted('floss', side)` or `.latest(...)` on any
thread. The former retains `evidence_run`; no I/O occurs in either value lookup.
Normal Search CLI/desktop binding is still pending in subsequent slices.

Foundation follow-up: the parallel Strings integration needs to distinguish
global capture refusal from its existing per-side auto fallback. A new failing
control preceded `capture_error` / `require_capture()` and sidecar-budget
exhaustion reporting. The combined foundation lane now passes **89 tests**, no
skips. A classified stale/foreign side still preserves the valid opposite side;
the global accessor reports bounded row/body or aggregate sidecar capture loss.

### Slice 2: production CLI, source coverage and freshness

The initial 25 wiring controls failed against the normal source path. In
particular, existing advisory/CVE text returned exit 4 (complete no results),
and existing stored strings returned exit 3 without hits. The production
`search/wiring.py` now supplies all six tool groups plus advisory and CVE groups
for ordinary search, build, status, saved-query execution and advisory anchors.

Advisory pointers retain their existing publication identities; all normalized
and raw reads use the shared anchored budget and original strict JSON. Any
advisory/CVE capture loss makes that group unavailable. Explicitly requested
unavailable coverage produces a partial result, never complete absence.
Counterpart absence requires two complete admitted comparable tool sources.
Segment input identities include retained content, so changed output under the
same tool configuration cannot silently reuse a prior segment.

Inline captures may reuse the same owner/database modification identity.
File-dependent and unsuccessful captures always revalidate. A further red
control showed that SQLite `total_changes` does not detect rollback of a
successful provisional capture; captures inside an owner transaction therefore
never qualify for reuse. External commits, replaced evidence, sidecar damage,
cache identity, saved-query/anchor paths, secret redaction and source ownership
are covered by the 33 maintained wiring tests, all passing (1.97 seconds).

Before the final three boundary controls were added, the complete existing
`test_search*.py` selection plus the then-current wiring cases passed **881
tests**, no skips (21.57 seconds). The final 33-case wiring selection and Ruff
passed afterward. Desktop default wiring remains the next slice.

### Slice 3: desktop capture and displayed-result freshness

The first twelve desktop boundary controls failed before integration: ordinary
build/search did not supply stored sources, a live service was reachable from
workers, pending results and displayed navigation ignored changed inputs, and
project-copy bounds were missing. The desktop now captures independent project,
root and source values on the owner thread before query/build/coverage tasks.
Results and navigation revalidate their own captured receipts. Visible rows keep
their original receipt while a replacement task is pending. Project copies are
bounded before allocation, and no store or SQLite connection reaches workers.

A deterministic late-build callback then reproduced a second ordering defect:
an old completed build could overwrite a newer successful query with a stale
message. Generation checks now discard those old success/error completions,
including coverage callbacks, without replacing the newer state. A separate
typed-truncation control reproduced an invalid comparable pair when only
`truncated_types` was populated; either truncation representation now prevents
absence claims and carries the existing source warning.

At this checkpoint the complete affected selection passed **1,030 tests, zero
skips** in 39.96 seconds. Whole-tree Ruff and all **22** GUI/core isolation
controls passed. The common intelligence admission/store, enrichment storage
and owned-publication implementations remain unchanged from the base.

Independent pre-freeze review raised an overall-status gap: a default query
could report complete absence despite a corrupt retained advisory or refused
tool row. Four new controls failed (one explicit-kind control already passed).
The captured source list now supplies known failed groups to the generic
service's coverage calculation. Unqualified queries report partial coverage
when those groups are relevant, with or without other hits. Explicit kind
filters remain scoped. Optional tools that have never produced output keep
their existing separate coverage; this does not turn them into empty evidence
or change the generic core-only/injected population.

The first expanded run passed 1,032 tests and failed two new scope assertions:
their fixture had no applicable function population. Those checks now use its
valid empty CVE population, and an additional control preserves never-produced
optional-tool behavior. The final affected run passed **1,035 tests, zero skips**
in **35.65 seconds**. Whole-tree Ruff and whitespace checks also pass.

Final verification command:

```sh
PYTHONPATH=src QT_QPA_PLATFORM=offscreen /workspace/scratch/e3f205d85f15/.venv/bin/python -m pytest -q tests/test_search*.py tests/test_ui_search_panel.py tests/test_ui_search_saved.py tests/test_intel_tools_snapshot.py tests/test_intel_tools_admission.py tests/test_strings_stored_source_admission.py --basetemp=/tmp/patchtrace-search-affected-final-coverage-2
```

The worktree excludes only historical `docs/engineering/evidence/` files using
worktree-local sparse checkout to respect shared disk capacity; their Git
objects and all current specifications, sources and this record remain present.
No provider, target, native tool or remote publication was executed. Independent
review of the final source, combined integration, hosted Windows/Qt and packaged
acceptance remain separate open gates.

## Independent exact-source approval — November 27 (America/Vancouver)

Runtime `c4898ffb57297cae08eb3fc05afa05f96bb55d1f`, tree
`72df3ad65708cedd6b29dd55584e90f2239d518b`, remained clean during independent review.
**13 authored independent controls** and **229 maintained integration controls**
passed with zero skips. Required Ruff and whitespace passed. No remaining scoped
blocking finding was identified. The final author's affected lane passed 1,035
tests without skips; counts overlap and are not additive.

Controls exercise real top-level CLI/default MainWindow stored sources,
failed-capture coverage, changed-output invalidation, saved query reruns,
owner-thread capture, post-close independent values, displayed-row receipts,
unannounced revision changes and stale navigation/results. Common admission,
store, persistence, enrichment storage and publication modules remain base-identical.
The pre-freeze default-query coverage issue is independently verified fixed.

Exact review JSON, XML and control source are retained under
`docs/engineering/evidence/search-stored-evidence-20261127/`. This follow-up changes
only evidence/documentation. Authored/offscreen results do not qualify native
providers or Windows packaged UI. Exact-head hosted/full/combined and packaged/native
acceptance remain open; no target or live provider was executed.
