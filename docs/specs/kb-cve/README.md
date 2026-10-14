# SPEC-31 Implementation Addenda: Developer Handoff Index

**Status:** Documentation only; no runtime implementation claimed. **Base design:** [SPEC-31](../kb-cve-correlation-and-acquisition.md). **Branch:** docs/spec-31-kb-cve-correlation-20261014. **Frozen contract target:** kbcorrelation/1.

## Reading order, ownership and gates

| Sub-spec | Expanded scope | Primary owner | Depends on | Ready when |
| --- | --- | --- | --- | --- |
| [31-A Contracts](31-A-contracts-identity.md) | Pydantic schemas, identity, provenance, error/outcome model, foreign keys and migration | Contracts | existing identity + ProjectStore audit | versioned schemas and negative contract tests green |
| [31-B MSRC reverse index](31-B-msrc-reverse-index.md) | Official release discovery, parser semantics, durable coverage/resume, conflicts | Source connectors | A | KB/CVE/product mapped with exact source pointer; incomplete searches never false negatives |
| [31-C Product/build pairs](31-C-product-build-pairs.md) | Scope normalization, directed servicing/checkpoint graph, hard pair blockers, deterministic selection | Lineage | A/B | no false automatic product/arch/build match |
| [31-G Component discovery](31-G-components-discovery.md) | Explicit official filename claims vs package/Winbindex/user hints, no speculative filenames | Component resolver | A/B/C | no hallucinated module; documented source tier/unknown state |
| [31-D Acquisition/package](31-D-acquisition-packages.md) | Reuse SPEC-08, source consent, final SHA, PA30/31 base, optional package inventory and signing | Acquisition | A/C/G + existing SPEC-08 | atomic verified two-file promotion, partial remains partial |
| [31-F Workflow/UI/storage](31-F-workflow-ui-persistence.md) | Reducer, persistence, first-class CLI, existing AcquisitionDialog reuse, Qt workers, project attachment | Integrator / UX | A/B/C/D/G | offline and consented metadata→project workflow; no regression |
| [31-E Evidence/intent](31-E-evidence-intent.md) | Documentary context, optional SPEC-28/30, provenance graph, no false CVE-fix claims, calibration | Correlation | A/B/C/F | E0 context works without optional engines, E1 capability gated |
| [31-H Test/release](31-H-tests-release.md) | TDD fixtures, negative cases, Windows smoke, PR gates, reproducible handoff | QA/integrator | all | full frozen Windows acceptance and report/reopen passed |

Addenda use these letter labels as the canonical 31-A..31-H implementation work packages. The base spec's originally proposed staff-slice letters were descriptive; apply the updated mapping in its §15. **31-I** denotes the integration owner running cross-module acceptance and merging, not a ninth new product subsystem. Advanced package reconstruction is an independently gated follow-up under 31-D.

## Non-negotiable design decisions

- Treat the KB->CVE->product relation as scoped documentary evidence; it does not identify the changed DLL or vulnerable function.
- An incomplete KB source index must never claim no vulnerabilities. A zero-row result includes measured coverage and 'not observed'.
- Filename selection is evidence-tiered; 'Windows networking' does not automatically imply tcpip.sys.
- Pair orientation is established by same-lineage product/build evidence; not KB number or PE timestamp.
- A hashed Winbindex candidate has index consistency, not authenticated Microsoft signer identity. Windows files can use catalogs as well as embedded signatures.
- User consent is operation-and-URL specific; no automatic download, execution of a target binary or project creation before both final PE files pass verification.
- Reuse existing enrichment, Winbindex, acquisition and ProjectService plus the *existing* ui.py AcquisitionDialog. Do not introduce a parallel downloader or CVE normalization layer.
- SPEC-28 and SPEC-30 are planned optional capabilities. E0 documentary context must work when they are absent. E1 advanced mechanism localization requires its own verification.
- Raw bytes and exact provenance are immutable; derived interpretations may become stale with revised sources/builds/runs.
- Separate source/provider, package, domain, persistence, CLI and Qt layers. Strict typed interfaces, negative fixtures and red/green/refactor before adding behavior.

## Repository integration order

1. Contract freeze: commit 31-A models/schemas/tests and minimal empty package with import checks.
2. Land 31-B offline official-source ingestion and testable exact KB reverse lookup with coverage state.
3. Land 31-C product/update graphs and 31-G component candidates as pure code, sequential/shared read-only interface.
4. Land 31-D SPEC-08 adapter for verified local/direct PE; separate experimental package/delta work.
5. Land 31-F storage and CLI metadata-first end-to-end path; re-use existing UI acquisition logic with clean controller seams.
6. Land 31-E E0 documentary context and optional capability probes. Build E1 later after SPEC-28/30 runtime modules exist.
7. Run 31-H tests continuously. Integrator 31-I owns shared CLI/UI/service/database migrator edits, CI, merge order, module index, docs/QA updates.

Do not launch multiple workers modifying src/patchtrace/cli.py, src/patchtrace/ui.py, src/patchtrace/persistence.py or src/patchtrace/service.py concurrently. Freeze and publish shared types first; workers should use owned subdirectories and tests. Rebase, review, merge or explicitly close every PR.

## Existing code dependencies (checked 2026-10-14)

- src/patchtrace/enrichment/cve.py and intelligence.py: NVD/MSRC per-CVE context with opt-in consent. Current 'correlate' is a contextual re-ranking, not patch attribution.
- src/patchtrace/acquisition/{contracts,winbindex,transport,quarantine,delta}.py: x64 build candidates, Winbindex digest and symbol server, optional Windows reconstruction.
- src/patchtrace/ui.py: **AcquisitionDialog already exists** with filename entry, consent, older/newer selection, worker-driven download, GUI-owned project creation.
- src/patchtrace/service.py: ProjectService.create/open/backup/swap_orientation; src/patchtrace/persistence.py: ProjectStore single writer.
- src/patchtrace/enrichment/storage.py: guarded additive derived persistence patterns; do not duplicate uncoordinated connections.
- src/patchtrace/tooltips.py and ui_evidence.py: existing UI controls and evidence semantics.
- src/patchtrace/intelligence/ not present in checked main; SPEC-28/30 are NOT automatically ready.

## Research notes and sources

Microsoft's published MSRC Security Updates API sample code covers Get-MsrcSecurityUpdate and Get-MsrcCvrfDocument; does not establish a universal stable KB query API. Discover exact supported URLs and record fixtures before using release indexing:
https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API

Checkpoint cumulative updates can require prior checkpoint content for Catalog/offline servicing:
https://learn.microsoft.com/windows/deployment/update/catalog-checkpoint-cumulative-updates

Catalog files can sign member files that have no embedded Authenticode signature:
https://learn.microsoft.com/windows-hardware/drivers/install/catalog-files

## Definition of complete

All relevant base-spec §19 acceptance plus independently tested source coverage, correct product/build pair identity, verified final PE bytes, explicit source lineage/unknown states, regression-safe Qt/CLI/SQLite behavior, and native Windows frozen-build smoke. Documentation-only PR is not an implemented feature.
