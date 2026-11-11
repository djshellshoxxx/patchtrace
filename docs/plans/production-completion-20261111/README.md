# Production-completion session of 2026-11-11: handoff

This directory is the working record of one autonomous session (`sleepy-fermi`, session
`session_01KtKj8mF3j3dSBSESbfu5Zs`) that started on `main` `882d1ca0` and was stopped by the owner about one hour in
("stop all workers except the ones working on ghostpay and p2p offramp; the others should finish gracefully and update
to github", 2026-11-11 01:06 UTC). Nothing was merged to `main`. The state of every slice, with branch, pull request and
the checks that were actually run, is in `docs/plans/ledger-production-completion-20261111.md` sections 3 and 6 and,
machine-readable, in `docs/status/slices.json`. Pull requests: #284 (this record), #290 (security), #291 (KB/CVE
correlation), #292 (CLI verbs), #293 (rz-diff ownership, red), #294 (L1 runner), #295 (test reliability).

## What is here

| Path | Content |
|---|---|
| `cards/*.md` | One card per slice: goal, evidence pointers, owned files, required tests, acceptance. 24 cards; 9 were never started and are ready to run as written. |
| `briefs/COMMON.md`, `briefs/<KEY>.md` | The rules and the per-workstream briefs of the 17 read-only inventory analysts. Nine returned (results in `docs/status/inventory/`); the briefs for A, G, H, I2, I3, J, L and R were not completed and can be re-run as written. |
| `briefs/IMPL-COMMON.md`, `briefs/REVIEW-COMMON.md` | Rules every implementation worker and every independent reviewer followed (they extend `docs/plans/worker-brief.md`). |
| `workflows/slice-pipeline.js`, `workflows/inventory-readers.js` | The two orchestration scripts: implement or resume a slice in a pre-created worktree, two independent reviewers, bounded fix rounds, model fallback; and the analyst fan-out. |
| `wip/*.patch` | Unfinished working-tree diffs saved at the stop. They are NOT tested and NOT reviewed. |
| `reports/*.json` | The structured reports of the workers and reviewers that finished: commits, red evidence, focused tests, deviations from the card, open risks, what they could not verify, and reviewer findings with reproductions. Workers that were stopped mid-slice left no report. |

Paths written as `<worktrees>/…`, `<main checkout>` and `<scratch>/…` in the cards were local to the session's container:
a worktree per slice, a pristine checkout of `main`, and a scratch directory. Create your own.

## Unfinished diffs (`wip/`)

| Patch | Applies on | What it is | State |
|---|---|---|---|
| `SEC-C-item4-TB-09-jobs.patch` | branch `claude/sleepy-fermi-security-1` | TB-09 / WP-09: never signal a process group whose leader has been reaped (`jobs.py`, `tests/test_jobs.py`) | incomplete, untested; the supervision loop is shared by every engine, so finish it only with the repeat runs the card asks for |
| `K3-kb-dock-owner-thread-snapshot.patch` | `main` `882d1ca0` | KBB-01: the KB and CVE dock reads the open project through an owner-thread snapshot | incomplete, untested |
| `CLI-B-corrections-review-code.patch` | `main` `882d1ca0` | `corrections-exchange/1` spec plus first code for `patchtrace corrections` and `patchtrace review` | spec complete as a draft; code incomplete, untested |
| `CLI-0-spec44-refresh.patch` | `main` `882d1ca0` | SPEC-44 (CLI umbrella) rewritten to describe `main` | incomplete draft, not checked against the code |

Apply with `git apply --index docs/plans/production-completion-20261111/wip/<name>.patch` on the stated base. The files
are stored byte-exact (`-text` in `.gitattributes`).

## How to resume

1. Read `AGENTS.md`, `CLAUDE.md`, `docs/plans/worker-brief.md`, then the ledger named above. Re-read GitHub first: other
   sessions were active in this repository on the same day (ledger section 2) and may have moved.
2. Review and finish the draft pull requests listed in the ledger, in this order: security, KB/CVE correlation, rz-diff
   ownership, CLI verbs, L1 runner, test reliability. Each pull request body says which slices in it were reviewed and
   which were not. No slice in them has been through a full independent review round except SEC-A (one reviewer of two
   in the second round).
3. Run the cards that were never started: `NA-2`, `NA-3`, `TR-B`, `GUI-A`, `GUI-B`, `GUI-C`, `INT-1`, `INT-2`, and the
   remaining items of `TR-A`, `K4`, `CLI-C` (the `runtime` verb), then the slices whose patches are listed above.
4. Complete the inventory: workstreams A (matching engine), G (persistence), H (accuracy), I2 and I3 (fresh security
   review), J (performance), L (documentation) and R (specification registry) were not inventoried. After adding their
   files to `docs/status/inventory/`, run `python tools/status/build_status.py`.
5. Keep `docs/status/slices.json` current and regenerate; `python tools/status/build_status.py --check` must pass.

## Limits of what was verified

Everything in this session was verified in a Linux container with focused test selections named in each pull request.
No native tool (Ghidra, Rizin, BinDiff) and no live data host was reachable, and nothing ran on Windows. No accuracy
figure was produced. The full suite was run twice: on `main` `882d1ca0` (20,809 passed, 56 skipped, 8 xfailed, and one
failure that occurs only under pytest-xdist and is fixed in #295), and once on a local union of the six code branches,
a throwaway merge that was not pushed (21,331 passed, 48 skipped, 5 xfailed, 10 failed: two were registry rows since
added on #292, eight belong to #293 and are listed in its body). No pull request was run through the full suite on its
own, and GitHub's CI results, including every Windows result, had not been read when the session stopped.
