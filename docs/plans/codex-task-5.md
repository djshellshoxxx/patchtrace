# Task for ChatGPT Codex: independent code and bug audit of merged Program E modules (E-4)

Branch `codex/audit-3`. Same rules as `codex-task-1.md` (read it first): own branch, draft PR to `main`, product rules from `AGENTS.md`, no `[skip ci]`/`[release]` markers in commit messages, no network access in tests, no secrets, secret-shaped literals built from fragments, `.gitattributes` LF rule for any new fixture directory is listed in the allow-list. Keep Qt out of pure modules. Run focused tests and `ruff check` + `ruff format --check` on touched files before every push; CI is the full gate (only minimal QA locally, owner order 2026-10-15). One commit per work package; PR description lists test counts, open items, and anything not verified (Windows, frozen build). Do not edit files outside the allow-list; if a shared file needs a change, write it under "Integrator asks" in the PR description.

## Read first
`AGENTS.md`, `docs/plans/e4-audit-and-qa-plan.md`, `docs/migration-readiness.md`, `docs/plans/codex-task-1.md` (report format), existing `docs/audits/*.md` (do not repeat findings).

## Work packages (one report each, `docs/audits/codex-<area>-1.md`)
1. **kev**: `src/patchtrace/kev/**`, `cli_commands/kev.py`.
2. **rules (YARA-X)**: `src/patchtrace/rules/**`, worker limits, hostile rule text, golden stability.
3. **pilot (patch-intent)**: `src/patchtrace/pilot/**`, ranking/fusion determinism, store.
4. **fabric**: `src/patchtrace/fabric/**` store, pins, CLI, owner-thread rules.
5. **unified engine**: `src/patchtrace/unified/**` stages S3/S4a/S5/S6a, proofs, residual.

For each: read every module line by line; list defects as ID, severity (High/Medium/Low), `file:line`, a reproducing input or a statically proven path, proposed fix. Hunt specifically: unbounded reads or loops, path traversal and Windows names, SQL built from text, non-determinism (dict order, hash seed, clock), exceptions that escape the CLI exit-code contract, secrets in logs, banned words in user-facing strings, schema/model drift, missing tooltips or accessible names, tests that assert nothing. Add regression tests as NEW files `tests/test_codex_<area>_*.py`; failing ones are `xfail(strict=True, reason="CODEX-<area>-n")`.

## Allow-list
`docs/audits/codex-*-1.md` (the five above), `tests/test_codex_<area>_*.py`. No `src/` edits.
