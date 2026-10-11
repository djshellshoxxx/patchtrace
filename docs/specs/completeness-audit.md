# Specification and implementation completeness audit

Audit scope: the supplied brief plus subsequent authorization for modular implementation, full code audit, QA and Windows standalone. The original stop-after-specification instruction is superseded. This audit distinguishes written contracts, implemented behavior and empirical acceptance.

| Package area | Normative source | Implementation evidence | Remaining empirical gate |
|---|---|---|---|
| Product/scope/platform/assumptions | architecture.md, verification.md | Static PE AMD64, local desktop, explicit orientation, synthetic walkthrough | Real patch corpus |
| Research/reuse/licenses | ../research.md, ../reuse-matrix.md, ../notices.md | Inspected exact upstream revisions, supported CLI, staged interpretation adaptation | Artifact notice audit |
| Architecture/modules/APIs | architecture.md, ../modules.md | Pure domain/adapters/services, Qt consumes contracts | Portability beyond target deferred |
| Schemas/examples/migrations | schemas.md, ../schemas/ | 15 generated strict schemas, aggregate ownership/digests/citations | Legacy migration not applicable v1; future versions rejected |
| Ingestion/persistence/recovery | architecture.md | Immutable copies, transactions/history, lock, backup/relocation, integrity, interrupted jobs | Windows metadata acceptance |
| Backend/jobs/normalization | architecture.md, research.md | Safe argv, Job Object, quarantine, hash identity, missing assembly honest | Native Ghidriff fixture workflow |
| Interface/journeys | ui.md | New/Open/Sample, paired modes, filters, evidence/reviews/notes, correction/undo, preview, settings, backup/export | Clean interactive Windows QA |
| Interpretation/context/evidence | architecture.md | Budget, exact preview+system prompt, omissions, optional providers, strict output | Live local/remote models unconfigured |
| Security/privacy | verification.md | Static-only, safe paths, no tools, HTML escaping, scoped references, credentials excluded | Held-out adversarial corpus |
| Quality/test/benchmark/traceability | verification.md, ../qa.md | Adversarial unit/integration and Qt checks | Resource targets and accuracy unmeasured |
| Packaging/update/support | ../windows.md, ../notices.md | Windows onedir build, frozen sample self-test, licenses/help | Actual Windows artifact and user test |
| Milestones/tasks/risks/glossary | ../../tasks/plan.md, ../../tasks/todo.md, architecture.md, verification.md | Tracked gates, explicit failure/retry/status | Unverified checks stay open |

## Resolved contradictions
Desktop standalone bundles Python and Qt but analysis runtime remains external. Subprocess use is not claimed to remove upstream licensing obligations or provide an OS security sandbox. Confidence/match similarity is qualitative/uncalibrated. No synthetic test establishes vulnerability truth. Recorded evidence is traceable, not proof of a model claim. Cancelled remote requests cannot recall already transmitted bytes. Unknown schema/output fails visibly instead of returning no changes. Large alignment has an explicit bounded heuristic strategy and preserves exact equal regions, not invented machine-instruction mapping.

## Deliberate first-beta boundaries
Symbols are handled by external Ghidra configuration; analyst notes can record supporting material. Bulk document ingestion, automated split/merge detection, Docker backend, detached windows, graphs, interactive chat, light theme, auto-updater and additional CPU/file formats are deferred. Manual split/merge/ambiguous relationships are available. Known CLI instruction-hash output cannot supply assembly; unavailable assembly is labeled. Adjacent unchanged caller code absent from diff is explicitly unavailable. Endpoint/model configuration is analyst-owned; no mandatory cloud account or model subscription.

Every R01–R14 requirement in verification.md maps to a responsible module and acceptance procedure. Core workflows have test fixtures; no failing or missing live acceptance is counted as passed. A Windows testable beta may be distributed with these limitations, but whole-project verified completion requires the remaining live gates. Responsibility for implementation defects is the developer; backend/model/clean-machine evidence is recorded as it becomes available. See ../qa.md for actual results.
