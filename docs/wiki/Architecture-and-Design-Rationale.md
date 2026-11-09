# Architecture and Design Rationale

Source: `docs/specs/architecture.md` (SPEC-01, schema v1). Items marked *(inferred)* are conclusions from the code.

## Decisions recorded in the spec

- **DEC-01: no Java in the GUI.** Ghidra and Ghidriff run as external processes; the desktop does not embed a JVM.
- **DEC-02: use the supported CLI and keep raw outputs.** Matching is not forked from Ghidriff; raw output is preserved so results can be audited.
- **DEC-03: bounded interpretation flow.** Inspired by Diffalayze; exact reuse was pending source investigation at the time of writing.
- **DEC-04: AI is optional, session-only credentials.** Ollama on localhost, or HTTPS OpenAI-compatible endpoints, through the standard library; credentials are never persisted.
- **DEC-05: traceability over claims.** Requirements stay listed even when runtime verification is blocked; unverified paths are not called complete.

## Structure

- Python 3.12 domain layer, PySide6 desktop, Ghidriff as an external CLI process.
- SQLite stores validated JSON snapshots and append-only revisions in transactions; immutable copies of
  inputs and raw outputs sit beside the database in the project folder.
- JSON schemas are generated from strict Pydantic models; upstream schemas are accepted only through an adapter.
- One writer per project through a lock file; one active job per window.
- Cancellation is cooperative for AI providers and process-tree termination for analysis.
- Logs omit credentials and are size-capped.

## Why the module boundaries look like this (inferred)

Domain modules (`models.py`, `alignment.py`, `normalization.py`, `enrichment/`, `callgraph/`) are kept
pure so they can be tested with synthetic inputs and without Qt. `ui.py` and `ui_*.py` are the only
Qt-facing code. The large number of sub-packages (`callgraph`, `enrichment`, `kbcorrelation`,
`unified`, `buildenv`, `fabric`, `pilot`, `rules`, `kev`) suggests feature areas added on top of the
beta core; `docs/modules.md` gives each module's seam and status.

## Known boundaries

Stated in `docs/specs/completeness-audit.md` and `docs/qa.md`: the beta targets Windows 11 x64 only,
and live acceptance items remain listed in `tasks/todo.md`.
