# PatchTrace dev prompt: next major milestone, then handoff (2026-10-30)

Paste this whole file as the task for a coding agent. Written against snapshot `main` = `5214720716c7afb7952bacbc9afd4b8255574ae8` (#111 merged; main QA run 41004639343 success) and open #124 head `95e09548a82202ae4cfd9380522f36513da87a66` (QA run 41041471026 success). Snapshot only. Step 1 re-verifies everything.

---

## 0. Role and hard rules

You are the **integration coordinator** for `djshellshoxxx/patchtrace`. Owner authorized: repair, reconcile, commit, push, and merge reviewed passing work. Work until the milestone in §2 is met or a real hard limit or blocker stops you. Do not stop after a plan or one small fix.

Rules:
- Re-fetch GitHub state first (default-branch SHA, open PR heads, check runs, review threads). Live state beats any doc.
- Parallel contributors exist. Do not force-push, delete, rewrite, or reset any branch you did not create this session. Do not touch `claude/awesome-ramanujan-o3pxx3-*` (active Windows/hostile-input work) or PR #102 author work except through its owner or an explicit reconciliation step.
- No target binary execution. No implicit downloads. No credential persistence. No unpreviewed remote transmission. No model-suggested command execution.
- Never weaken a test, skip a gate, disable Windows PR QA, or relabel a failure as success. Environment limits (for example AF_UNIX denied in the executor) are recorded as environment limits, not product passes.
- Mocked/fake-engine tests are never native compatibility evidence. Label them.
- Use the repo's own environment and credentials only. If auth or a setting is missing, record the exact missing item and continue on the rest.
- Do not add a model name, session URL, or attribution beyond what the harness requires to commit messages and PR bodies.

Read in this order, then treat the newest dated doc as authoritative where it conflicts with older ones:
1. `AGENTS.md`, `CLAUDE.md`, `docs/modules.md`
2. `docs/plans/essential-integration-20261029.md` and `docs/audits/20261030-consolidation-review.md` (on #124 until merged; then on main)
3. `docs/handoff/autonomous-continuation-20261030.md` (on #124 until merged)
4. `docs/qa.md`, `tasks/todo.md`, the relevant `docs/specs/*` sections before any contract change
5. `docs/plans/chatgpt-merge-first-handoff-20261016.md` and `docs/plans/claude-autonomous-alpha-handoff-20261013.md` are **stale historical snapshots**. Use them for context only. The 1013 handoff's base SHA, PR #19 state, and B1–B4 are superseded.

Known stale doc: `tasks/todo.md` carries old `[planned]` / unchecked statuses that contradict merged work (handoff B4). Reconcile it from code and CI, not from memory.

---

## 1. Step 0: reality check (required before any edit)

1. `git fetch origin --prune`. Record `origin/main` SHA and `git log -8 --oneline origin/main`.
2. List all open PRs with head SHA, base, draft flag, and last update. Expected at snapshot: #124 (ready, consolidation), #123 (draft, superseded by #124), #110 (draft, superseded), #112–#115, #117, #119, #122 (repair stack, superseded), #113/#114 (ready/draft repair alternatives), #109/#108/#103/#102/#101/#100/#98/#94/#90/#89 (verify each), #95 and #19 if still open.
3. For each open PR: check runs at head, review threads (unresolved count), mergeability. Note any PR whose head moved since this snapshot.
4. List remote branches by last commit. Note any branch touched in the last 24 hours and its PR owner. This is your ownership map.
5. Write a short working note to `docs/plans/milestone-ledger-20261030.md` on your branch (see §6). Do not reuse snapshot facts without re-checking.

Stop only if step 1–4 show a conflicting active coordinator (someone pushing to the same PR head in the last hour). In that case, report and wait for the owner.

---

## 2. Milestone to complete: "Integrated essential alpha"

Milestone is met only when **every** item below has evidence recorded in `docs/qa.md` with exact SHA, run URL, and counts.

**M-A. Consolidation landed.** #124 (or a successor PR with the same content) is merged to `main` with preserved ancestry, and the exact `main` head passes the full QA workflow: Linux full suite, Windows full suite, Ruff, repeated Qt acceptance, Windows standalone + portable + installer, Linux package + 22.04/24.04 smoke, and native Windows Ghidriff (five jobs). If #124's threads or checks are red at the current head, repair them first.

**M-B. Superseded PRs closed honestly.** For each of #110, #112–#115, #117, #119, #122, #123: verify its unique content is present in `main` (diff or tree check, not guesswork), then close with a comment that names the replacing PR. Leave #67, #69, #72, #78, #79, #82, #85, #102, and the calibration branches open unless their disposition in the audit doc says otherwise. Do not close a PR merely because files overlap.

**M-C. Windows standalone alpha built from `main`.** On `windows-latest` CI, build from the exact merged `main` head:
- PyInstaller onedir, portable ZIP, and NSIS per-user Setup
- SHA-256 sidecars verified (Setup sidecar included)
- frozen smoke A1–A5 and A10 passing (`tools/frozen_smoke.py`, `tests/test_acceptance_smoke.py`)
- Qt offscreen `--self-test` passing on the frozen binary
- dependency notices copied; Qt DLLs replaceable
- Artifact URL recorded.
Do not cross-compile Windows from Linux. Windows packaging must run on Windows.

**M-D. Release publication.** Attempt publication only through the existing workflow. If it returns 403 `Resource not accessible by integration` (handoff B1), do not patch Python code to work around it. Record the exact permission setting needed and mark publication **blocked**, separate from the build being green. Keep the Actions artifact downloadable.

**M-E. Essential flows reach "GUI-exposed + automated-tested + merged" on main.** Each needs a spec section, red/green regressions, and a GUI path or an explicit CLI-only label:
1. **Unified comparison (G-U1–G-U8).** Automatic ProgramIR extraction, sound matching with abstention, materiality, explainable evidence, safe decompile refresh, deterministic results. Gate evidence from real corpus runs is recorded separately from synthetic tests. Any gate without real evidence is marked `not run`, not `pass`.
2. **KB → CVE → product → binary correlation and patch search.** Real advisory parsing, freshness and provenance, generation/architecture separation, explicit ambiguous-pair selection. Legacy scope IDs need refresh/reselection. Do not reinterpret old contexts silently.
3. **Extraction, persistence, run history.** Immutable ingestion, previous-result preservation on failure, cancellation and recovery, enrichment ranking, Winbindex acquisition with verified pairing.
4. **Secondary engines.** BinExport2 / BinDiff / rz-diff adapters with unified orchestration. Preserve engine attribution and disagreements. Live BinDiff stays `blocked` if no licence is installed. Live rizin is `not run` until the workflow has a green run on both OSes.
5. **Offline investigation.** Explicit pair preview and creation in the GUI, with cancellation and no target execution.

**M-F. Issue #105 tracker reconciled.** KBC-12 and KBC-13 are open per the #105 record. Confirm the state of each finding and record it. Do not close #105 without per-finding evidence.

**Not in this milestone (defer, record as deferred):** AI interpretation expansion, guided teaching, DiE/YARA feature expansion, calibration claims (#78/#79/#82/#85 reconciliation), SPEC-26 E incremental panel, msdelta on Windows, real relocatable offline Ghidra/JDK bundle, live provider acceptance, clean interactive Windows GUI acceptance by a human.

**Acceptance wording rule.** Do not write "complete", "production ready", or "done" anywhere except when M-A through M-F each have the evidence above. Use the status ladder in §5 for every feature.

---

## 3. Work order

Run in this order. Parallel work is allowed only with isolated worktrees and disjoint file ownership. `src/patchtrace/ui.py`, `docs/qa.md`, and `tasks/todo.md` have a single integration owner: you.

**Phase 1 (gate, first):** M-A and M-B. Land #124 after its threads and checks are green at the exact head. Fix any regression with a focused failing test first. Re-run the full combined suite on the merged main head.

**Phase 2 (gate):** M-C and M-D. Confirm Windows artifacts on the merged head. Record exact run URLs, sizes, and hashes. Record the B1 release-permission state.

**Phase 3 (feature):** M-E in this order, one coherent PR per slice:
1. Unified G-U evidence: run the gates on the real corpus under `tools/unified` and record `pass`/`fail`/`not run` per gate. Fix only the gaps the evidence shows.
2. KB/CVE pair search and explicit selection in the GUI, with legacy-scope refresh prompts.
3. Secondary-engine orchestration (adapter outputs into unified), with disagreement display.
4. Offline investigation and cancellation/result-preservation paths.
5. Persistence, run history, and enrichment ranking polish.

**Phase 4 (parallel stream, optional, owned by a GUI worker):** SPEC-26 inspection slices from `tasks/todo.md`: PE trust (signed/revoked Windows acceptance), raw view async page reads and verified function extents, tooltip registry completeness. Do not block the milestone on these.

**Phase 5:** M-F, then the handoff in §7.

---

## 4. Engineering loop (each slice)

1. Spec first if an interface or persisted contract changes. Update `docs/specs/*` and `docs/modules.md`. Regenerate schemas after contract edits.
2. Red test: reproduce the defect or the missing behaviour. Keep it focused. Show it failing.
3. Minimal fix at the root cause. Keep pure domain and adapters free of Qt.
4. Green: focused tests, then `python -m ruff check src tests tools`, then `QT_QPA_PLATFORM=offscreen python -m pytest -q` (or the parallel form the repo uses).
5. Commit and push every verified slice, and at least every 15–30 minutes of productive work. Use `git push -u origin <branch>`. Retry network failures only (2s, 4s, 8s, 16s).
6. Open a **draft** PR for every pushed branch that lacks one. Subscribe to its PR activity. Respond to review threads with evidence. Post a comment only when asked or when a review point must be explained, and end it with the required footer.
7. Merge only when the head's exact-SHA checks are green and threads are resolved or answered. Use a merge commit to preserve ancestry unless the repo rule says otherwise. Verify `main` after each merge.

Test discipline:
- Red/green for every confirmed bug. Run the regression on the parent commit and show it fails.
- Count tests from actual output. Do not add overlapping counts from different legs.
- A failing check is diagnosed from its job log. Do not rerun repeatedly to hope it passes. Classify each as product defect, test defect, or environment limit, and record the classification.

Token discipline:
- Cheapest capable model for grep, inventory, docs, and log triage.
- Capable mid-tier model for module implementation, Qt, packaging, and merge resolution.
- Highest tier only for a demonstrated hard blocker: subtle PE/Authenticode trust, a security invariant, or a repeated failed approach.
- Use `rg` and targeted line ranges. Do not dump whole logs or whole modules.

---

## 5. Status ladder (use for every feature in the handoff)

Each feature gets one value per rung, with evidence:
1. **Implemented** — code exists
2. **Integrated** — on an integration branch with its dependencies
3. **Automated-tested** — focused and full suite pass at a named SHA
4. **Native-verified** — run on the real OS/tool (Windows native, real Ghidra, real rizin); give the run URL
5. **GUI-exposed** — reachable from the desktop UI, with tooltip and cancel path where relevant
6. **On-main** — merged, and the exact main head passed its gates

Never infer a percentage from file counts. A feature without rung 4 is not called verified. A feature without rung 5 is labelled CLI-only.

---

## 6. Ledger

Keep one ledger at `docs/plans/milestone-ledger-20261030.md`, updated every time you push or merge:
- branch, PR number and link, head SHA, merge SHA
- decisions, with the reason
- run URL and counts per leg, labelled as environment or product failures where they occur
- ownership of each open branch
- next executable step

Keep `docs/qa.md` as the single authoritative test record. Keep `tasks/todo.md` as the delivery checklist, reconciled to code and CI.

---

## 7. Final deliverable: the handoff

When M-A through M-F are complete, or a hard limit or blocker is reached, write:

`docs/handoff/milestone-handoff-<YYYYMMDD>.md`

Required sections:
1. **Snapshot**: `main` SHA, every open PR with head SHA and draft/ready state, every run URL cited.
2. **Merged this milestone**: PR, merge SHA, reason.
3. **Closed as superseded**: PR, replacing PR, verification that the content is present.
4. **Preserved, not closed, and why**: #102, #67, #69, #72, #78/#79/#82/#85, and any other.
5. **Artifacts**: Windows ZIP, Setup, sizes, SHA-256, run URL, and the release status with the exact permission state for B1.
6. **Feature status matrix**: every essential flow, with the §5 ladder values and evidence links.
7. **Test record**: per-leg counts, environment limits named as such, Ruff result, schema regeneration result.
8. **Open gates and blockers**: each with the exact human action required (permission, credential, setting, licence, or hardware). Do not describe a blocked item as a failure of the code.
9. **Known stale docs** that were corrected, and those still stale.
10. **Next three slices**, in order, each with its spec path, owner, and acceptance check.
11. **Resume instructions**: the first three commands a new session should run, starting from `git fetch origin --prune`.

Also:
- Add a pointer from `docs/plans/claude-autonomous-alpha-handoff-20261013.md` to the new handoff, marked superseded.
- Update `CLAUDE.md`'s pointer to the current handoff only if it names a stale doc as current.
- Commit the handoff on the working branch and open or update a draft PR.

Final chat reply: one compact status report. Current `main` SHA, PR links, what merged, artifact URL, milestone result (met or not, with the unmet item), the blocked items with required actions, and the handoff PR link.

---

## 8. Stop conditions and what to report

Stop and report, without guessing, when:
- A GitHub setting, token scope, or secret is needed (B1 release permission, a missing connector, a licence).
- A destructive or outward-facing action is needed (force push, deleting a branch, closing a PR without a verified replacement, publishing a release).
- Owner intent is genuinely unclear for a product choice, not a routine implementation choice.

For each stop: say what is blocked, what you verified, what remains open, and the exact next executable step. Finished parts still get pushed and recorded.

---

## 9. Orientation facts (verify before use)

| Item | Snapshot |
|---|---|
| `main` | `5214720` (#111 merged) |
| #124 | ready, head `95e0954`, QA run `41041471026` success |
| #123 | draft, `99f8328`, superseded by #124 |
| #110 | draft, `5ed624e`, superseded |
| #102 | draft, Windows exe version/icon, release integrity, author work — preserve |
| `claude/awesome-ramanujan-o3pxx3-*` | active 10-30 branches (`-ci`, `-hostile`, `-win1`) — owner-only |
| Release publication | 403 on `v0.1.0-beta.100` per earlier handoff B1 — re-check |
| Known open gates | clean interactive Windows GUI acceptance, real offline Ghidra/JDK bundle, live BinDiff (no licence), live rizin (awaiting green run), live provider acceptance, calibration reconciliation |

Commands for the verification pass (run from the repo root):

```bash
git fetch origin --prune
git log -8 --oneline origin/main
QT_QPA_PLATFORM=offscreen python -m pytest -q
python -m ruff check src tests tools
```
