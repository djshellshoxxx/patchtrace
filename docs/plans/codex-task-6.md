# Task for ChatGPT Codex: YARA-X panel view model and documentation conformance sweep

Branch `codex/rules-view-and-docs`. Same rules as `codex-task-1.md` (read it first): own branch, draft PR to `main`, product rules from `AGENTS.md`, no `[skip ci]`/`[release]` markers in commit messages, no network access in tests, no secrets, secret-shaped literals built from fragments, `.gitattributes` LF rule for any new fixture directory is listed in the allow-list. Keep Qt out of pure modules. Run focused tests and `ruff check` + `ruff format --check` on touched files before every push; CI is the full gate (only minimal QA locally, owner order 2026-10-15). One commit per work package; PR description lists test counts, open items, and anything not verified (Windows, frozen build). Do not edit files outside the allow-list; if a shared file needs a change, write it under "Integrator asks" in the PR description.

## Read first
`AGENTS.md`, `docs/specs/program-e/YRX-integration-plan.md` (sections 7-10, slice R6a), `docs/modules.md` [R5:rules-store], `docs/cli-reference.md`, `docs/user-guide.md`.

## Work packages
1. **R6a** pure view model and service: `src/patchtrace/rules/{view,panel_service}.py`, `tests/test_rules_view.py`. All states of the plan's state table (R0-R8 strings verbatim), banned-string check, hostile rule text sanitised, no Qt import (subprocess test), read-only over the R5 store. No `ui_rules.py`.
2. **Docs conformance test** `tests/test_docs_conformance.py`: every CLI verb in the registry appears in `docs/cli-reference.md`; every exit code documented; every spec in `docs/specs/INDEX.md` exists and has a REGISTRY row; every `docs/modules.md` path exists; links in `docs/*.md` resolve. Failures that are plain doc gaps: fix the docs in your PR (allow-listed below); code gaps are xfail strict.
3. **Doc fixes** for gaps found in 2, in `docs/cli-reference.md`, `docs/user-guide.md`, `docs/specs/INDEX.md` only.

## Allow-list
`src/patchtrace/rules/view.py`, `src/patchtrace/rules/panel_service.py`, `tests/test_rules_view.py`, `tests/test_docs_conformance.py`, the three docs above.
