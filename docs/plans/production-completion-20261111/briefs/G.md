# WORKSTREAM G - Persistence and application architecture
Scope: src/patchtrace/persistence.py (ProjectStore), ui_persistence.py, verified_backup.py, jobs.py, service.py, models.py,
evidence.py, raw_cleanup.py, artifact_bytes.py, src/patchtrace/unified/store.py (read-only: L1 lane), kbcorrelation stores,
enrichment/storage.py, kev storage, search/ (FTS5 index), fabric/ (anchor fabric), nway/, docs/schemas/** and
tools/generate_*schemas.py.
Specs: architecture.md, schemas.md, verification.md, nway.md, series-window.md, anchor-fabric.md, app-settings.md,
report-export-contract-v2.md.
QA/audits: docs/qa/persistence-security-20261105.md, storage-*.md, backup-*.md, docs/audits/20261015-core-app.md,
20261015-qa-cli-persistence.md, 20261015-fabric-audit.md; trust-boundary TB-07 (views/triggers refusal).

Assess each directive item: analysis run persistence; binary metadata storage; comparison result storage; CVE
relationships; patch relationships; evidence provenance; manual corrections; historical analysis retrieval (can a user list
and reopen past runs - GUI and CLI?); database migrations (is there an explicit schema version and migration path? what
happens when opening an older or a newer project?); transaction safety; concurrent operations (two processes on one project;
locks); data integrity (hash-on-read); recovery from interrupted operations (crash mid-write, staging sweep); API contracts
(pydantic models; schema drift is enforced how? read the tests - do NOT run a generator inside the checkout); backward
compatibility; upgrade and rollback tests.
Hunt for partial-write corruption risks: non-atomic writes (`grep -rn "write_text\|write_bytes\|open(.*'w" src` without
temp-file + os.replace), missing fsync where durability is claimed, multi-file updates without a journal, SQLite usage
without transactions - each with file:line and a concrete crash scenario.
