# Task for ChatGPT Codex: privacy, offline and contract test gaps (SPEC-41/42/43)

Branch `codex/test-gaps`. Same rules as `codex-task-1.md` (read it first): own branch, draft PR to `main`, product rules from `AGENTS.md`, no `[skip ci]`/`[release]` markers in commit messages, no network access in tests, no secrets, secret-shaped literals built from fragments, `.gitattributes` LF rule for any new fixture directory is listed in the allow-list. Keep Qt out of pure modules. Run focused tests and `ruff check` + `ruff format --check` on touched files before every push; CI is the full gate (only minimal QA locally, owner order 2026-10-15). One commit per work package; PR description lists test counts, open items, and anything not verified (Windows, frozen build). Do not edit files outside the allow-list; if a shared file needs a change, write it under "Integrator asks" in the PR description.

## Read first
`AGENTS.md`, `docs/specs/network-egress-privacy.md` (SPEC-42), the SPEC-41 and SPEC-43 documents in `docs/specs/INDEX.md`, `tests/network_guard.py`, `tests/test_network_consent_*.py` (model), `docs/audits/random-audit-1-20261014.md`.

## Work packages (NEW test files only; a test that fails today on a real defect is `xfail(strict=True, reason="CODEX-n")` and listed, never fixed in `src/`)
1. SPEC-42 section 7 still open: `tests/test_network_census.py` (every outbound host in code is a row of the spec table), `tests/test_offline_switch.py` (offline mode blocks every transport), F4 (blob host printed before any CLI request), F5 (an accepted LLM send transmits exactly `context.payload`).
2. SPEC-43 G1/G2: secret-shaped Model and endpoint text refused before save (provider settings), as xfail if the code does not yet refuse.
3. SPEC-41 open rules R12, R15, R25, R26, R28, R34-R37, G11, G13-G16, G18-G20: one parametrized test module `tests/test_spec41_open_rules.py` stating each rule as a check on real code paths.
4. Audit gaps: the missing tests 2, 3 and 5 of `random-audit-1-20261014.md`.
5. Report `docs/audits/codex-tests-1.md`: table of rule id, test id, pass/xfail, evidence.

## Allow-list
`tests/test_network_census.py`, `tests/test_offline_switch.py`, `tests/test_spec41_open_rules.py`, `tests/test_codex_gaps_*.py`, `docs/audits/codex-tests-1.md`.
