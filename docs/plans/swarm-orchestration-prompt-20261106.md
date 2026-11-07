# PatchTrace swarm prompt (paste into each VM's first message)

Owner: Sheldon Davidson (djshellshoxxx/patchtrace). Written 2026-11-06. Owner is away and will return to review.
The owner granted broad permission to get the project done and accepts credit spend if it is spent intelligently.

## 0. How to run it (owner reads this part, workers skip to section 1)

| Role | Model | Effort | Why |
|---|---|---|---|
| Lane orchestrator (one per VM, 3 total) | Opus 5.5 | high | plans, splits work, integrates, resolves conflicts, owns merges |
| Implementation worker (features, tests, CI, adapters) | Sonnet 5.5 | medium | the workhorse; best cost/quality for nontrivial code |
| Mechanical worker (triage, lint, docs, searches, fixtures, status files) | Haiku 5.5 | low | bounded tasks with a checkable result |
| Hard-problem escalation (concurrency, security invariants, correlator design, a task that failed twice on Sonnet) | Opus 5.5 | high (max only for a demonstrated blocker) | do not repeat retries on a weaker model |
| Do NOT use | Fable 5.1 / Mythos tier | n/a | extra cybersecurity safeguards may refuse binary-diff work, and it costs more with no benefit here |

"Ultracode": I cannot verify what this setting is, so nothing here depends on it. If it is an extended-effort or
longer-thinking mode, do not enable it for the swarm. At most enable it for one orchestrator planning pass per lane.

Three VMs, one per lane, each a separate session on its own branches. Expect roughly 3 orchestrators plus up to 5
concurrent workers per VM (more parallel workers on one repo means more merge conflicts, not more speed).
Start all three together. Lane 1 is the owner's top priority.

## 1. Mission and priorities

1. **Finish the KB/CVE correlation feature (SPEC-31, `src/patchtrace/kbcorrelation`)**: the owner's top priority.
2. Land the open PR stack safely: #205 -> #250 -> #218 -> #235, with CI and SonarCloud green.
3. Build the accuracy-validation program (`docs/plans/accuracy-validation-plan-20261106.md`).
4. Keep the Windows standalone alpha and the P1 timeout work moving (`tasks/todo.md`).
Never trade correctness, security or user data for speed. Report blocked external acceptance separately from automated evidence.

## 2. Facts every worker must know (verified in earlier sessions)

- Repo: Python >= 3.12, PySide6, pydantic, protobuf. Tools in `tools/` (no `__init__.py`; `tools/calibration` and
  `tools/research_qualification` are packages), tests in `tests/`.
- Test: `QT_QPA_PLATFORM=offscreen python -m pytest -q <focused tests>`. Lint: `python -m ruff check src tests tools` (line length 110).
- Read first: `CLAUDE.md`, `AGENTS.md`, `docs/modules.md`, `tasks/todo.md`, the relevant `docs/specs`, `docs/plans/accuracy-validation-plan-20261106.md`.
- Active parallel contributors exist. Before starting, read the default-branch SHA, all open PRs and their checks. Never overwrite another worker's branch.
- GitHub access from the sandbox: repo-scoped REST only (`gh api repos/djshellshoxxx/patchtrace/...`). GraphQL is blocked,
  the Codespace API is blocked, `gh auth status` shows an invalid token yet repo REST calls work. Do not "fix" auth.
- Network: shell is allowlisted (package registries, GitHub). WebFetch refuses api.msrc.microsoft.com and GitHub source pages.
  Anything needing MSRC, Winbindex, vendor downloads or Windows must run in GitHub Actions (`workflow_dispatch`), not the sandbox.
- A stop hook reports "unpushed commits" falsely because clones track only `main`. Verify with
  `git ls-remote origin <branch>` against `git rev-parse HEAD`; if equal, nothing is unpushed.
- Receipts convention: one immutable atomic JSON per attempt, statuses PASS/FAIL/BLOCKED/CANCELLED. BLOCKED never counts as success.
  Live-status JSON: `engine`, `status` in passed|failed|blocked, `reason`; blocked exits 0 loudly, failed exits 1.
- Already built on branch `research/qualification-tools-rq00-rq01-20261106` (131d47e): receipts, perf harness, stage parser,
  sample-size table, Ghidriff call-count model (a MODEL; per-call counts unverified), self-compiled fixture pairs + scorer,
  case manifest validator with freeze hash, top-k scorer. Probe branch `research/kbc-live-probe-20261106` (b74f95d3): live MSRC/Winbindex
  probe + manual workflow, never run live. No PR is open for either branch.
- PR state at last check: #205 (base main, head 4e9f1d5d) all required checks green except two Windows jobs still running;
  #250 resolves a ledger conflict into the #205 branch (mergeability unknown); #218 (draft) must be retargeted to main after #205 lands;
  #235 (draft) has conflicts and Sonar failures; about 67 old PRs (#61-#190), mostly drafts, many contained in #235.
- Ghidriff timeout hypothesis (PT-TIMEOUT-2) is unverified against upstream source; keep it labeled unverified until a measurement exists.

## 3. Rules (hard)

1. Spec first for interface changes; red/green regression tests for behavior; small mergeable slices; preserve persisted contracts.
2. Never claim something was run, built, tested or published unless it was. Report exact results. Mark unverified facts `unverified`.
3. Do not invent CVE ids, URLs, versions, API signatures or benchmark numbers. A fetch that fails is reported, not guessed.
4. No secrets in code, logs, commits or CI output. If one leaks, stop and report it.
5. Never force-push, rewrite shared history, delete branches, close PRs or issues, or overwrite another worker's branch.
   Close/delete candidates are written to `docs/swarm/closure-candidates.md` with evidence, for the owner.
6. Never disable or weaken a test, assertion, warning or gate to get green. Never remove the Windows lock safeguard.
7. Never publish a release, enable a paid API-agent workflow, or add third-party GitHub Actions. First-party actions only; pin versions.
8. Merging is allowed ONLY when: PR is not draft, targets the correct base, every required check is success (not pending, not skipped
   where it should run), SonarCloud gate passes, `mergeable` is true, and the merge is logged in the lane status file. Merge the stack in order.
   If any condition is unclear, do not merge; record the blocker.
9. Third-party code: check the licence first (MIT/BSD/Apache/ISC ok with attribution; GPL/AGPL/LGPL, unlicensed: do not copy, record in the log).
10. Do not download or commit third-party binaries; fetch them only in Actions and keep them out of the repo.

## 4. Credit discipline

- Orchestrators plan once, write briefs, then delegate; they do not do bulk reading or editing themselves.
- Search before reading, read ranges not whole files, put bulk output in files, never re-read a file just written, run independent calls in parallel.
- Each worker: at most 2 attempts on the same failure with new evidence between them; then escalate one tier once; then record BLOCKED and move on.
- No polling loops. Use background runs and wait for notifications; a CI wait is one scheduled check, not repeated sleeps.
- Reuse before writing: sibling files, existing probes (`tools/live_kev_probe.py`, `tools/live_kbc_probe.py`), workflows (`live-kev.yml`).
- Stop-loss: if a lane has spent roughly its share (about one third of what the owner would consider reasonable for a few hours) with no
  merged or tested output in the last 90 minutes, the orchestrator stops spawning workers, writes the handoff, and ends.
- Final integration review of each lane may use one Opus worker that did not write the code.

## 5. Worker brief format (compressed; keep exact identifiers, paths, commands, errors)

```
TASK | one outcome
SCOPE | files/dirs owned exclusively by this worker (no one else edits them)
CONSTRAINTS | rules from section 3 that bite here, model/effort, attempt cap
RESULT | exact deliverable, branch, tests that must pass
EVIDENCE | commands run and their real output summary, commit SHA, receipt path
BLOCKERS | precise blocker and the smallest action to unblock
```
Workers report in this format, short. Orchestrators integrate and verify the combined result with the full relevant test set before reporting.

## 6. Lane 1 (VM 1): KB/CVE correlation and the PR stack  [highest priority]

Orchestrator: Opus 5.5 high.
Workers:
- L1-A CI watcher/merger (Haiku low, merges only per rule 8): check #205 checks; when green and Sonar passes, merge; then check #250
  mergeability (`gh api repos/.../pulls/250`), resolve if trivial through a PR, never force-push; retarget #218 to main (REST PATCH base) after #205 lands.
- L1-B correlator completion (Sonnet medium, escalate Opus for design): read SPEC-31 and `kbcorrelation`, list unimplemented acceptance items,
  implement the smallest remaining slices test-first (CLI `patchtrace kb ...`, consent flags `--consent-hosts`, `--consent-plan`),
  keep offline paths network-free; unverified MSRC CVRF URL shape stays unverified until the live probe passes.
- L1-C live probe (Sonnet medium): open a PR for `research/kbc-live-probe-20261106`; ensure the workflow can be dispatched (it likely must exist
  on the default branch: add the minimal change needed); dispatch it once available and record the real result (PASS/FAIL/BLOCKED) in `docs/qa/`.
  On FAIL, fix the parser/URL with a regression test using the real response shape (saved sanitized fixture).
- L1-D #235 rebase (Sonnet medium): after #218 retargets, resolve #235 conflicts on a NEW branch (never overwrite), fix Sonar issues, open PR.
- L1-E Sonar and coverage triage (Haiku low): list open Sonar issues on each PR via REST/Checks output; fix trivial ones (Sonnet), report the rest.
Done when: #205 merged, #250/#218/#235 each merged or with a precise blocker, the correlator's remaining acceptance list is empty or blocked with reasons,
live probe has a real recorded result.

## 7. Lane 2 (VM 2): accuracy validation and research tools

Orchestrator: Opus 5.5 high. Follow `docs/plans/accuracy-validation-plan-20261106.md`.
Workers:
- L2-A open PRs for `research/qualification-tools-rq00-rq01-20261106` (Haiku low) and keep CI green (ruff, tests, no new warnings).
- L2-B AV-2 candidate list (Sonnet medium, web research): per project (7-Zip, Notepad++, PuTTY, WinSCP, KeePass; MinGW stratum VLC/FileZilla;
  Windows-shipped components curl, zlib, libarchive, OpenSSH), find real CVEs with fix commits and old/new release pairs. Verify each fact by
  fetching from at least two sources (project advisory, NVD/GitHub advisory, commit page). Write `docs/research/accuracy-cases/candidates.json`
  in `rq-case-manifest/1` with `facts: unverified` until Actions confirms hashes. Target 40 candidate cases across at least 20 projects. Choose
  cases BEFORE running any engine; reserve a holdout. If a source host is unreachable, mark it unverified, do not guess.
- L2-C AV-3 Actions workflow (Sonnet medium): `workflow_dispatch` workflow on the Windows runner that fetches pairs, hashes, optionally builds
  MSVC before/after at fix commits with identical flags, strips, and emits receipts; first-party actions only; `permissions: contents: read`;
  upload hashes as an artifact. Unit-test the pure parts with fakes. Never commit binaries.
- L2-D engine adapters + parity comparator (Sonnet medium): convert Ghidriff, BinDiff and Rizin outputs into `{case_id: [functions]}` for
  `scoring.py`; compare engines on the same pairs; record disagreement. Use captured sample outputs; label unverified fields.
- L2-E harness hardening (Sonnet medium): Windows Actions job exercising the perf harness kill path (`taskkill /T`), currently untested.
- L2-F measurement (after L2-D/E): run the harness on the self-compiled fixtures and one real pair in Actions; record per-stage timings
  and calls/second to turn the call-count model into a time estimate. Do not claim a Ghidriff fix from the model alone.
- L2-G L1 join evaluation (Sonnet medium): after the live probe passes, run the automated advisory-join evaluation over several MSRC months
  and report the one-sided lower bound with n and errors.
Done when: manifests frozen (hash recorded), workflows dispatchable, adapters tested, and a stratified report skeleton filled with whatever real
numbers exist. Do not publish an accuracy percentage without its n, errors, and stratum.

## 8. Lane 3 (VM 3): backlog, Windows alpha, timeout, hardening

Orchestrator: Opus 5.5 high.
Workers:
- L3-A old-PR triage (Haiku low): the 67 PRs #61-#190 and the 5 "no-files" PRs (#128, #131, #152, #163, #183). Comment-free analysis only:
  write `docs/swarm/closure-candidates.md` with evidence (contained in which merged PR/branch, file-level equality). Do not close anything.
- L3-B PT-TIMEOUT-3/4 (Sonnet medium): diagnose the per-function decompiler timeout and missing PDB handling; verify cache reuse; write
  specs/tests; keep failure logs and prior results. No untested speed fixes.
- L3-C Windows alpha (Sonnet medium): installer/portable smoke tests and docs per `tasks/todo.md` (PR #95 track), verifying only what can be
  verified; GUI acceptance stays an owner item.
- L3-D security review (Opus high, one pass): review the changed code in the correlator, harness and workflows for injection, path traversal,
  secret handling, supply chain, sensitive logging; findings file with severity, evidence, remediation, verification status. Fix material findings
  within scope; label it an AI-assisted review, not an audit.
- L3-E docs and `.devcontainer` (Haiku low): `.devcontainer` for Codespaces (Python, ruff, offscreen Qt deps), README research quickstart.
Done when: closure-candidates written, timeout items each have tests or a precise blocker, security findings recorded.

## 9. Status, handoff, and ending

- Each lane keeps `docs/swarm/lane-N-status.md` on its own branch: done, in progress, blocked, unverified, PR links, exact test results, merges made.
- Commit with these trailers on every commit:
  `Co-Authored-By: Claude <model> <noreply@anthropic.com>` and `Claude-Session: <this session url>`.
- Before ending, the orchestrator verifies: branches pushed (`git ls-remote`), tests and ruff pass on the final head, status file complete,
  scheduled follow-ups (CI checks) created for anything still running. Then it writes a short final report: completed, verified, incomplete, blockers.
- If blocked on something only the owner can do (GitHub UI, Windows interactive acceptance, secrets, paid-service decisions), finish all independent
  work first, then list exactly what is needed.
