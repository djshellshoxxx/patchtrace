# Task for ChatGPT Codex: independent audit and hostile-input tests (batch 1)

Owner order 2026-10-14: give Codex bounded work that does not collide with the Claude workers. Codex works on its own branch `codex/audit-1` and opens a draft PR to `main`. It never pushes to another branch and never edits a file outside the allow-list below.

## Read first
`AGENTS.md`, `CLAUDE.md`, `docs/modules.md`, `docs/plans/e4-audit-and-qa-plan.md`, `docs/specs/non-goals.md` if present, the SPEC for each package you audit (`docs/specs/INDEX.md`).

## Product rules (a violation is a defect)
Never execute a target binary; no silent upload (network only with operation-specific consent, offline by default); never fabricate disassembly or evidence; an uncalibrated number is never shown as vulnerability confidence; never average engine scores; unknown is not negative; no Microsoft binaries, PDBs or Winbindex data in the repo; no GPL/AGPL code copied.

## Work packages (do them in order; one commit each)
1. **Audit report** `docs/audits/codex-audit-1.md`: read and attack these packages in `src/patchtrace/`: `kev/`, `fabric/`, `pilot/` (not `pilot/rules` data), `rules/`, `gui/`, `pe_overview/resources.py`, `version_info.py`, `manifest.py`, `codetext/`. For every finding: severity (High/Medium/Low), `file:line`, a minimal reproduction you actually ran (command and output), the product rule or spec line it breaks, a proposed fix. Only reproduced findings count. Look for: hostile input (huge, nested, cyclic, malformed, bidi/control characters), Windows paths (reserved names, long paths, case), resource exhaustion, race conditions, consent bypass, secrets in logs, unknown treated as negative.
2. **Hostile-input tests** in NEW files only: `tests/test_codex_hostile_kev.py`, `test_codex_hostile_resources.py`, `test_codex_hostile_manifest.py`, `test_codex_hostile_codetext.py`. Use `hypothesis` (already a dev dependency). Each test must be fast (under 2 s), deterministic (fixed seeds or `derandomize=True`), and must fail on the unfixed code for a real defect, otherwise it is a regression guard. If a test exposes a defect, mark it `pytest.mark.xfail(strict=True, reason="CODEX-n")` and list it in the audit report; do not fix source files.
3. **Spec-versus-code drift list** `docs/audits/codex-spec-drift-1.md`: for SPEC-41 to SPEC-54 in `docs/specs/`, list each requirement that the code contradicts or does not implement, with `file:line` on both sides.

## Allow-list (the only files you may add or change)
`docs/audits/codex-*.md`, `tests/test_codex_*.py`. Nothing else: no source, no workflows, no `.gitattributes`, no registry, no `docs/modules.md`.

## Rules
- Run `python -m pytest tests/test_codex_*.py -q` and `ruff check tests/test_codex_*.py` before every push; both must pass (xfail counts as pass).
- Commit messages must not contain the text `[skip ci]`, `[ci skip]` or `[release]`.
- No secrets, no network access in tests, no Microsoft data.
- Finish with a PR description: counts of findings by severity, list of xfail ids, commands to reproduce.
