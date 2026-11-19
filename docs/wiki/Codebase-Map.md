# Codebase Map: where to find what

The full module table is `docs/modules.md`. Quick map:

| I want to... | Look in |
|---|---|
| Start the app / CLI entry | `src/patchtrace/__main__.py`, `src/patchtrace/cli.py`, `cli_commands/` |
| Desktop windows and wizard | `src/patchtrace/ui.py`, `ui_*.py`, `gui/` (Qt code only) |
| Data models and schemas | `src/patchtrace/models.py`, `docs/schemas/` |
| Ingest a PE and validate it | `ingestion.py`, `artifact_inspection.py`, `artifact_bytes.py` |
| Project storage, locks, backups | `persistence.py`, `verified_backup.py` |
| Run Ghidriff and manage processes | `backend.py`, `jobs.py`, `backend_cli.py` |
| Normalise Ghidriff output | `normalization.py` |
| Line/hunk alignment | `alignment.py` |
| Review, matches, notes (service layer) | `service.py` |
| Evidence and AI interpretation | `evidence.py`, `interpretation.py`, `providers.py` |
| Enrichment, ranking, CVE context | `enrichment/`, `kev/`, `kbcorrelation/` |
| Call graph views | `callgraph/` |
| Reports (JSON/Markdown/HTML) | `reports.py` |
| Diagnostics and redaction | `diagnostics.py` |
| Offline backend bundle | `offline_bundle.py`, `backend_bundle.py`, `tools/build_backend_bundle.py` |
| Packaging | `tools/build_windows.py`, `tools/build_linux.py`, `tools/frozen_smoke.py` |
| Tests | `tests/` (about 530 files, including fixtures in `tests/fixtures/`) |
| Corpus used for tests | `corpus/` |
| Specs | `docs/specs/`; QA record `docs/qa.md` |
| CI | `.github/workflows/` |
