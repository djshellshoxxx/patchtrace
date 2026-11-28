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
