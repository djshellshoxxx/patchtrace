# Accuracy program handoff (tool-neutral)

State as of 2026-11-07 ~07:10 UTC. Re-check GitHub before acting: default-branch SHA, open PRs, check runs. Anything below marked "open PR" may have merged since.

## Quick start for a new tool
1. Run `tools/handoff_status.sh` (read-only; needs `gh` and `jq`) for live PR and CI state.
2. A ready-to-paste prompt for ChatGPT or Codex is in `docs/plans/chatgpt-continue-prompt.md`.

## Goal
Owner priority: the KB/CVE correlation feature, then a defensible accuracy claim for it. Claims are made per layer and never blended:
- L1: advisory join (CVE to KB to product and file), oracle = MSRC data cross-checked with Winbindex and KB articles.
- L2: open-source pair diff (about 29 independent projects, not yet listed).
- L3: real Windows binary pairs (changed-function ranking, top k=5).
Report bounds with Clopper-Pearson over independent projects, not raw case counts.

## Where things are
- Research tooling: `tools/research_qualification/` (stdlib only; pathguard `confine` on every file argument; exit 0 ok, 1 differs, 2 blocked/usage).
- Case manifests: `docs/research/accuracy-cases/` (`rq-case-manifest/1`, freeze hash; `facts: unverified` cases are never scored; `expected.accept` = up to 8 extra accepted names).
- Findings and triage: `docs/qa/accuracy-program-findings-20261107.md`, `tasks/todo.md`, `docs/qa.md`.
- Receipts convention: PASS/FAIL/BLOCKED/CANCELLED. Unrun cases are BLOCKED and excluded, never counted as misses.

## Open PRs at time of writing (check each; merge order matters)
| PR | What | Note |
|----|------|------|
| 235 | integration branch retargeted to main | merge on green CI, sha-guarded; then close the PRs in #180-#240 it contains (keep branches, add a comment) |
| 258 | live probe result record | |
| 260 | `accept` validation + scoring, 14 L3 cases | merge BEFORE 264 and 266 (their manifests use `accept`) |
| 262 | findings doc | |
| 263 | parity comparator | conflicts with 265 in `__main__.py`: merge main into the branch |
| 264 | 5 ZDI cases | HOLD: owner must decide on one curl fetch of the phreedom PDF recorded in its sources log |
| 265 | engine output adapters (ghidriff, BinDiff, rizin) | BinDiff and radiff2 layouts unverified against real exports |
| 266 | 12 GitHub-sourced L3 candidates | follow-up: mark `Ipv6pProcessOptions` (contradicted label) and the csc case (single source) as excluded from scoring |
| 269 | L1 join corpus, 87 candidates (79 verified, 8 unverified) | validator `tools/research_qualification/l1_check.py` |
| (new) | Winbindex pair-fetch workflow | `workflow_dispatch` only; first real run is only possible after it is on main |

## Merge and GitHub rules
- Owner's standing rule: merge when every test job is green and nothing blocking is open. The code-review bots (Qodo, CodeRabbit) were disabled by the owner on 2026-11-06; go by CI alone.
- REST only: `gh api repos/djshellshoxxx/patchtrace/...`. GraphQL is blocked. Merge with `PUT /pulls/{n}/merge`, pass the head `sha`, `merge_method=merge`.
- Never force-push or rebase another worker's branch. Resolve conflicts by merging main into the branch.
- Do not weaken or skip a failing test. Do not claim a release succeeded when the token lacks permission.
- A stop hook may falsely report unpushed commits; confirm with `git ls-remote`.

## Next three tasks, in order
1. Land the merge queue above, then #235 and the cleanup of superseded PRs.
2. Run the Winbindex pair workflow to confirm before/after files exist for the Windows candidates, then run ghidriff in CI and score with the adapters and parity comparator. Record unavailable pairs as BLOCKED.
3. Get one real BinDiff export and one real rizin JSON export to verify the adapters, then freeze a first scored manifest of at least 20 verified pairs from at least 10 independent binaries and publish a clearly labelled first result.

## Owner-side items
- Timeout measurement (PT-TIMEOUT-3/4): update to main, set timeout 14400, rerun the pair, run `python -m tools.research_qualification stages <ghidriff.log>`, send the log and `backend-execution.json`.
- Mark the Sonar finding at `tools/check_windows_package.py:149` as a false positive (tool only reads the operator-named archive; member paths are checked and tested).
- Decide on #264's curl fetch.

## Known gaps
No valid candidates yet for ksecdd, NTLM/Kerberos beyond one case, RDP beyond one, modern win32k with a named patched function, DNS, or non-ZDI print spooler. Several diff-corpus repos returned 403 from this environment and were not worked around.

## Cost discipline
Cheapest model that can do the job; one capable model for integration. Agents get exclusive file ownership and a self-contained brief. Do not poll: wait for CI and event notifications.
