# COMMON RULES (independent reviewers of session sleepy-fermi)

You review ONE slice built by a different agent. You did not write it; your job is to find what is wrong with it. Default
to distrust: a claim in the author's report is a hypothesis until you reproduce it.

- Worktree and branch are named in your prompt. READ-ONLY for you: never edit, commit, stash, reset or checkout in it.
  Write your own probe scripts/tests only under
  <scratch>/reviews/<slice id>/ and run them with
  `cd <worktree> && QT_QPA_PLATFORM=offscreen PYTHONPATH=<worktree>/src nice -n 10 python -m pytest -q -p no:cacheprovider <path>`
  or `python -c`. (pytest may be pointed at a test file outside the repo; add `--rootdir <worktree>` and `-c <worktree>/pyproject.toml`.)
- Read `<worktree>/AGENTS.md`, `<worktree>/docs/plans/worker-brief.md` section 2 (product invariants) and the slice card.
- The diff under review: `git -C <worktree> diff origin/main...HEAD` (and `git -C <worktree> log --oneline origin/main..HEAD`).
- Check, in this order: (1) does the red test really fail on origin/main for the stated reason? The main checkout
  <main checkout> is pristine origin/main: for changes under src/ run the NEW test files from the slice worktree
  against the base sources with `-o pythonpath=<main checkout>/src` (this overrides the ini `pythonpath = ["src"]`;
  do not rely on PYTHONPATH, the ini entry wins); for changes under tools/ copy the base version with
  `git -C <worktree> show origin/main:<path>` into your scratch directory and exercise it there. Never stash, reset or
  checkout in any worktree; (2) correctness of the fix on edge cases the author did not test -
  write and run adversarial inputs; (3) regressions: run the existing test files of every module the diff touches;
  (4) security and data integrity: untrusted input, path handling, partial writes, error paths, resource bounds;
  (5) contract/spec consistency: spec amended, schemas regenerated, persisted contracts additive, CLI envelope and exit
  codes; (6) portability to Windows; (7) scope: files outside the card's ownership, frozen shared files, other sessions'
  lanes; (8) test quality: real assertions, hermetic, deterministic, no weakened or deleted assertions, no fixed sleeps;
  (9) ruff clean.
- Report findings with severity (blocker | major | minor | nit), file:line, a concrete reproduction (command + observed
  output) and the smallest fix. A finding without a reproduction or a precise code reference is a nit at most.
  Verdict: approve | approve-with-nits | changes-required. Use changes-required only for blocker/major findings.
