# Paste this into ChatGPT (or Codex) to continue PatchTrace

Works best with Codex or any agent that can run shell commands in a checkout of the repo with `gh` authenticated. Plain ChatGPT chat can only advise, so paste command output back into it.

---

You are continuing work on the PatchTrace repository (github.com/djshellshoxxx/patchtrace). The owner is Sheldon, a systems administrator. He wants short answers, numbered steps for anything he must do himself, and no filler.

Before doing anything:
1. Read `AGENTS.md`, then `docs/plans/accuracy-program-handoff-20261107.md`, then `tasks/todo.md`.
2. Run `tools/handoff_status.sh` and treat its output as the truth. The handoff doc may be out of date.

Your job, in order: land the open PRs per the merge order in the handoff doc, then build the Winbindex pair fetch and ghidriff diff-and-score workflows into a first scored result, as described under "Next three tasks".

Rules you must follow:
- Merge a PR only when every test job is green and nothing blocking is open. Use the REST API with the head sha: `gh api -X PUT repos/djshellshoxxx/patchtrace/pulls/N/merge -f sha=HEAD_SHA -f merge_method=merge`.
- GraphQL is blocked, so use `gh api` REST calls only.
- Never force-push or rebase someone else's branch. Resolve conflicts by merging main into the branch.
- Never skip or weaken a failing test. Never claim something ran when it did not.
- Accuracy claims are per layer (L1 join, L2 open-source pairs, L3 Windows pairs) and are never blended. Never score a case marked `facts: unverified`. Unrun cases are BLOCKED and left out of the score, not counted as misses.
- Do not commit Microsoft binaries. Commit hashes and reports only.
- Do not guess version pins, URLs or API shapes. Check them against the real source and say so when you could not.
- Keep changes small and mergeable. Add a test for every behaviour change. Run `python -m ruff check src tests tools` and the focused tests before pushing.
- When something needs the owner (a decision, a secret, a Windows machine), stop and say exactly what you need.

Finish each session by updating the handoff doc's PR table and "Next three tasks", so the next tool can pick up cleanly.
