# Developer Guide

## Setup and checks (Windows, from the repository root)

```powershell
py -3.12 -m pip install -e '.[dev]'
py -3.12 -m patchtrace
$env:QT_QPA_PLATFORM = 'offscreen'
py -3.12 -m pytest -q
py -3.12 -m ruff check src tests tools
py -3.12 tools/generate_schemas.py
```

Linux needs Qt's system libraries first; then `QT_QPA_PLATFORM=offscreen python -m pytest -q`. The
README states which checks were run for the published beta and which Windows-only tests are skipped
on Linux.

## Build the Windows package (on Windows)

```powershell
py -3.12 tools/build_windows.py
```

Creates an onedir executable, collects help/licence files, checks notices, runs the frozen sample
self-test and produces `dist/PatchTrace-*.zip`. Other entry points live in `tools/` (for example
`build_linux.py`, `build_backend_bundle.py`, `frozen_smoke.py`). Schema generation scripts are
`tools/generate_*_schemas.py`.

## Rules for contributors

Read `AGENTS.md` and `CLAUDE.md` first. Summary from the architecture spec:

- UI code stays separate from ingestion, backend lifecycle, persistence, evidence, providers and reports.
- Only the UI imports Qt; domain modules stay usable without Qt.
- Workers return results to the UI thread through queued signals; only service transactions change project state.
- Record new substantial modules in `docs/modules.md` and the applicable spec.
- Do not claim a path is verified unless a test or live check was run; `docs/qa.md` holds evidence.
