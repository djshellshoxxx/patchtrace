# COMMON RULES (every implementation worker of session sleepy-fermi)

You build ONE bounded slice of PatchTrace (repo djshellshoxxx/patchtrace; Python 3.12, PySide6) in a git worktree that the
orchestrator created for you. Your prompt names the worktree, the branch and your slice card.

## Read first, in this order
1. `<worktree>/AGENTS.md` and `<worktree>/docs/plans/worker-brief.md` - the repository's own policy and worker protocol.
   They are binding (product invariants, frozen shared files, tests-first, Windows pitfalls, report format), except where
   this file is stricter.
2. This file.
3. Your slice card (path in your prompt) and every spec/file it names. Read the code before changing it.

## Environment
- Work ONLY inside your worktree (absolute paths; your shell cwd is another repository, so always `cd <worktree> && ...`).
- Python: python. Tests:
  `cd <worktree> && QT_QPA_PLATFORM=offscreen PYTHONPATH=<worktree>/src nice -n 10 python -m pytest -q -p no:cacheprovider <test files>`
  (PYTHONPATH must point at YOUR worktree's src). Lint: `cd <worktree> && python -m ruff check src tests tools`.
  Schemas after any contract edit: run the matching `tools/generate_*schemas.py` from your worktree with the same PYTHONPATH
  and commit the regenerated files; the suite has regenerate-and-compare tests.
- 4 CPU cores are shared by several workers: run focused test files only, never the whole suite (the orchestrator does).
  `-n 4` (pytest-xdist) is available for a larger focused selection.
- No network. No native tools (Ghidra, Rizin, BinDiff). Never fetch, pull, push, rebase, merge, switch branches, create
  branches or worktrees, or touch GitHub. Commit locally on the branch you were given.
- Temporary files go under <scratch>/work/<slice id>/ ,
  never into the repository. `git status` must show only intended files before you commit.

## Rules that are stricter than worker-brief.md
- Red first: write the failing test, run it and SEE it fail for the right reason, then fix, then see it pass. Keep the red
  output (a few lines) for your report. A fix without a test that failed before it is not accepted.
- Exclusive files: edit only the files your card lists under "Owned files" (new files inside the listed directories are
  fine). Frozen shared files (ui.py, tooltips.py, tests/test_tooltips.py, panel_manifest.py, cli.py,
  tools/frozen_smoke.py, tests/test_acceptance_smoke.py, pyproject.toml, optional_deps.py, backend.py,
  enrichment/storage.py KINDS, .gitattributes, tools/build_*.py) and the shared trackers (tasks/todo.md, docs/qa.md,
  docs/modules.md) are edited only by the orchestrator unless your card explicitly grants one. Put the exact text you
  need there under "Integrator asks".
- Files of other sessions' lanes are off limits (the single exception: when your card assigns you numbered NEW help
  pages, you may add those new files under docs/help/ and one index line per page in docs/help/README.md - never edit an
  existing help page): src/patchtrace/unified/{sources,ladder,fusion,facts}/**,
  unified/registry.py, unified/keys.py, docs/specs/unified-engine/**, tools/unified/**, src/patchtrace/backend.py,
  .github/workflows/unified-live-gates.yml, .github/workflows/qa-windows.yml, tools/calibration/tier_r/**,
  src/patchtrace/ui_export_v2.py, src/patchtrace/ui_inspection.py, docs/help/**, .devcontainer/**,
  tests/test_release_gate.py, tests/test_backend_cli.py, docs/plans/ledger-consolidation-20261104.md, tools/dev/**.
- Spec first: when behaviour or a persisted/CLI contract changes, amend the governing spec in the same commit series
  (status line or a dated amendment row) BEFORE the code. Persisted contracts change additively only.
- Never weaken, delete, skip or xfail an existing assertion to get green. If a rule change invalidates a test's premise,
  rewrite the test so its purpose survives and say so.
- No new runtime dependency. Pure domain code stays free of Qt. Deterministic output (sorted iteration, no clock, no
  unseeded randomness). Bound every loop over untrusted input.
- Portability: code must also be correct on Windows (pathlib, explicit encoding='utf-8', newline handling, no POSIX-only
  calls in src; tests that truly need POSIX use skipif with a reason).
- Honesty: synthetic or fixture tests are never live evidence; say which class your evidence is. Do not claim what you did
  not run.
- Commit messages: imperative subject (<= 72 chars) naming the finding id if any, a body explaining why, and exactly these
  trailers:
  `Co-Authored-By: Claude <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01KtKj8mF3j3dSBSESbfu5Zs`
- If blocked after two serious attempts on one problem, stop and report precisely. Do not loop, do not widen scope.

## Report (structured output; the orchestrator reads only this)
Branch, commit SHAs, files changed, tests added, the red evidence (test id + the failing assertion line), focused test
commands with pass counts, ruff result, schema regeneration (yes/no/not needed), spec amendments, deviations from the card,
"Integrator asks", tracker rows to append (ready-to-paste text for tasks/todo.md and docs/qa.md under a heading
`### [sleepy-fermi:<slice id>]`), open risks, and what you could not verify.

## Resuming an interrupted attempt
An earlier worker on this same slice may have been interrupted. Before anything else run
`git -C <worktree> log --oneline origin/main..HEAD` and `git -C <worktree> status --porcelain`. If commits or uncommitted
changes exist, they are that earlier attempt: review them critically against the card (do not trust them), keep what is
correct, fix or discard what is not (`git -C <worktree> checkout -- <file>` for a file you decide to redo), then continue
with the items that are still missing. Never amend or rewrite existing commits; add new ones. Your report covers the
whole slice (earlier commits included), and you must have run the tests for everything you report as done.

## Commit trailer
End every commit message with the two trailer lines given above. If a harness reminder tells you to name a model in the
Co-Authored-By line, do not argue about it: the orchestrator normalises trailers before anything is pushed.
