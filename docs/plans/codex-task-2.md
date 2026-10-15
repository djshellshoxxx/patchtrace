# Task for ChatGPT Codex: packaging, workflow and licence audit (batch 2)

Same rules as `codex-task-1.md` (own branch `codex/audit-2`, draft PR to `main`, product rules, no skip or release markers in commit messages). Independent of batch 1.

## Read first
`AGENTS.md`, `docs/release-process.md`, `docs/install.md`, `docs/notices.md`, `docs/specs/windows-release-signing-policy.md`, `docs/specs/network-egress-privacy.md`, `docs/plans/e4-audit-and-qa-plan.md`.

## Work packages (one commit each)
1. **Workflow audit** `docs/audits/codex-workflows-1.md`: read every file in `.github/workflows/` and `tools/release_gate.py`. Report reproduced or statically proven problems: untrusted input in `run:` steps (injection), over-broad `permissions`, unpinned or mutable action references and downloads without a pinned digest, secrets exposure, `[skip ci]`-style marker hazards in squash messages, jobs that can hang (no `timeout-minutes`), cache poisoning, publish steps that can run on a pull request, Windows-versus-Linux differences. Severity, `file:line`, evidence, proposed fix for each.
2. **Packaging and licence audit** `docs/audits/codex-packaging-1.md`: `tools/build_windows.py`, `tools/build_linux.py`, `tools/pyinstaller_hooks/`, `tools/frozen_smoke.py`, `pyproject.toml`, `third_party/notices/`, `docs/notices.md`. Check that every runtime dependency has a pinned version, a licence text and a notice row; that no GPL/AGPL code is bundled except Ghidriff as a separate unmodified component; that hidden imports used at runtime are covered by hooks; that the smoke list covers every CLI verb. List gaps with evidence and a proposed fix.
3. **Regression tests** in NEW files only: `tests/test_codex_pkg_*.py`, static checks that fail on the problems of packages 1 and 2 that are plain facts about files (for example every workflow job has `timeout-minutes`, no `pull_request` job has a publish step, every dependency in `pyproject.toml` has an exact pin or an upper bound). A check that fails today must be `xfail(strict=True, reason="CODEX-n")` and listed in the report; do not edit workflows or build scripts.

## Allow-list
`docs/audits/codex-*.md`, `tests/test_codex_pkg_*.py`. Nothing else.

## Rules
Run `python -m pytest tests/test_codex_pkg_*.py -q` and `ruff check tests/test_codex_pkg_*.py` before every push. No network access in tests, no secrets. PR description: finding counts by severity, xfail ids, reproduction commands.
