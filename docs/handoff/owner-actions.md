# Owner actions (only the owner can do these)

Sources: `docs/plans/master-todo-d.md` ([OWNER], [EXT] items), `docs/plans/ledger-D.md` open owner questions, `docs/plans/owner-decisions-20261015.md`, `docs/runbooks/tier-w-local-run.md`, `docs/specs/windows-acceptance-and-milestone-builds.md`, `docs/windows.md`, `docs/plans/c9-preregistration-v1.md`. Written 2026-10-15. UNVERIFIED marks anything not confirmed in the repository.

## 1. Purpose and current state

Claude sessions cannot do these: they need the owner's Windows machine, the owner's GitHub settings rights, an application in the owner's name, or a policy decision. Each item says what blocks on it. Items O1 to O4 unblock the most work.

Already done by the owner (decisions file, verified in git): bundle pins recorded (commit 8fb3521, decision 1); C's branch restored (tip `393d09b` is a merge named "Merge restored research branch", decision 2); JDK approval recorded (commit c9a01b6 "Record owner approval to ship the Temurin JDK"). Decision 11 (close PRs #40, #41, #43): they are not in the open list read on 2026-10-15.

## 2. What is DONE by the owner

| Item | Evidence |
|---|---|
| Record the two verified pins | `tools/backend_pin.json`, commit 8fb3521 |
| Restore `claude/instance-c-research` | `git log origin/claude/instance-c-research`, tip 393d09b |
| Approve Temurin JDK shipping | commit c9a01b6 on the C branch and PR #65 on `main` |
| Close docs PRs #40/#41/#43 | absent from the open PR list (final state not re-read, UNVERIFIED) |

## 3. What REMAINS (owner checklist, ordered by what it unblocks)

Each item: goal, steps, what to send back, blocks, size, dependencies. Claude tier is not applicable.

### O1. Windows desktop acceptance pass (decisions 13)
- Goal: first real evidence for the manual gates M01-M28.
- Steps:
  1. Pick a Windows 11 x64 machine or VM with a clean user profile (no Python, Ghidra or Java for M01-M13; install them only for M14-M15).
  2. Download the newest prerelease from the GitHub Releases page (currently `v0.1.0-beta.281`, built from commit 21a005e; a newer one appears after PR #64 and a following merge). Download the `.zip` and its `.sha256`.
  3. In PowerShell: `Get-FileHash .\PatchTrace-0.1.0-windows-x64.zip -Algorithm SHA256` and compare to the `.sha256` text. If different, stop and report.
  4. Extract the whole ZIP into a folder you can write to (for example `C:\Users\<you>\PatchTrace`). Double-click `PatchTrace.exe`. SmartScreen or antivirus may warn: the alpha is unsigned by design.
  5. Open `docs/specs/windows-acceptance-and-milestone-builds.md` section 3 and walk the table row by row (M01 launch, M02 sample, M03 new project with a space in the folder name, M04 file overview, M05 raw views, M06/M07 tooltips, M08-M10 display scale 100/150/200 percent, M11 high contrast, M12 resize and keyboard, M13 export, M14 cancel analysis, M15 close during analysis, M16 file lock, M17 restart persistence, M18 Unicode path). M14 and M15 need a configured Ghidra, Java and Ghidriff (`docs/windows.md`).
  6. Accessibility rows M19-M28 (NVDA, Narrator, keyboard only, contrast themes, layout persistence on two monitors, DPI moves, Accessibility Insights, 100k-row table under Narrator, floating panel shortcuts, frozen style plugin) need NVDA (free download), Narrator (Win+Ctrl+Enter) and Accessibility Insights for Windows. Background: `docs/research/qt-accessibility-windows.md`.
  7. For each row write pass or fail plus one line of what you saw and a screenshot name. Do not paste screenshots that contain Microsoft binaries' contents.
- Send back: the filled table (rows M01-M28) in chat or as a PR to `docs/qa.md`. Claude then records it in `docs/qa.md` and files each failure as a defect with a red test.
- Blocks: releasing the alpha to outside testers; signing decision; G1 in `master-todo-d.md`. Size: a few hours. Depends on: a published prerelease with the PR #64 panels (do it after PR #64 is merged and a prerelease published, else you test the older beta.281 UI).

### O2. Tier W local runs (decision 14; Microsoft data stays on your machine)
- Goal: score engines on real Windows binaries without any Microsoft data leaving the machine.
- Steps: follow `docs/runbooks/tier-w-local-run.md` exactly.
  1. Prepare a short directory outside the repository with no dot-prefixed component (for example `D:\ptcal`).
  2. Install the repository (`pip install -e .`), plus a Python with `pyghidra` and `ghidriff`, a Ghidra install and Java (see `docs/windows.md`).
  3. PowerShell: set `PATCHTRACE_CALIB_ROOT` and `PYTHONPATH=src`, then run `python -m tools.calibration.tier_w.run_local --corpus-id tier-w-2026q4 --consent-hosts winbindex.m417z.com,msdl.microsoft.com --python <venv python> --ghidra-dir <ghidra> --timeout 3600` (flags taken from the runbook; use `--dry-run` first).
  4. When it finishes: confirm the last line says nothing was uploaded and the `guard` stage is `ok`; `git status` must show no new files.
- Send back: aggregate numbers only (precision/recall and intervals per condition). Never paste file names, pair ids, hashes, KB numbers, paths or function names.
- Exit codes: 0 ok, 1 partial or guard findings, 2 configuration or consent error, 3 BLOCKED (tool, network or CLI missing), 5 cancelled. Report any non-zero exit with the aggregate output only.
- Blocks: Tier W part of label training (`01-label-training.md`). Size: hours of compute. Depends on: the SPEC-33 s11 CLI being present in the checkout (otherwise `run_local` exits 3; whether every stage exists on `main` today is UNVERIFIED).

### O3. Sign off the C9 preregistration lock (decision 5)
- Goal: freeze `docs/plans/c9-preregistration-v1.md` before the single locked run.
- Preconditions: the pre-lock audit `docs/audits/20261015-lbl26-pre-lock-audit.md` has no open High; PR #66 merged; the corpus grown to the needed size (decision 4: about 38 lineages now, about 48 needed; ChatGPT draft PR #68 holds 24 unverified candidates).
- Steps: read the preregistration sections 6 (gates) and 8 (lock procedure); state in chat "lock C9 preregistration v1" or list the targets you want changed (product-owner sign-off on targets is still marked pending in its status line). Claude then makes the lock commit and records the SHA-256 in `docs/qa.md` row `C9-PREREG-v1` (procedure in section 8.2). After the lock the file is never edited; a change is v2.
- Blocks: the single locked Tier R run (`corpus-tier-r.yml`, about 150-250 runner-hours, approved in decision 6). Size: a short decision. Depends on: corpus growth and LBL-26 closure.

### O4. GitHub settings
- Pages: Settings, Pages, Source = "GitHub Actions" (so `pages.yml` can deploy). Then also supply a logo file and a Monero address if you want the donation block; otherwise the page shows a text wordmark and hides it. Blocks: the project page. Size: minutes.
- Workflow permissions: Settings, Actions, General, Workflow permissions = "Read and write" (needed for `publish_prerelease=true` in `backend-bundle.yml`, which "needs contents write on the token"); if the token lacks it the job must say so rather than claim a release. Size: minutes.
- Branch protection on `main` (optional): require `qa (ubuntu-latest)`, `qa (windows-latest)`, `qt-gate` jobs and `linux-smoke`. Size: minutes. Recommendation in `qa-and-release.md` section 4.
- Environment `github-pages`: created automatically on first deploy; UNVERIFIED whether approval rules are set.

### O5. Review and decide PR #61 (agent skills, SPEC-56)
- It adds skills and edits `AGENTS.md` and `CLAUDE.md`. Read the diff on GitHub; either close it or ask Claude to merge `main` into it and run CI. Blocks: nothing. Size: 15 minutes.

### O6. Code signing application (decision 9)
- Goal: start the lead time for a signed beta; the alpha stays unsigned.
- Steps: apply to SignPath Foundation's open-source programme (their site was unreachable from the sandbox; the offer's current conditions are UNVERIFIED, read them yourself). Needs the repository URL, the MIT licence, and a statement that CI builds the binary. The policy is `docs/specs/windows-release-signing-policy.md`: no private key on a developer machine, a Claude worker, a PR job or a repository secret file; RFC 3161 timestamp required. Send the outcome to Claude, which then adds the signing step under owner review. Blocks: signed releases only. Size: an hour plus waiting.

### O7. Restoring and housekeeping of branches
- C's branch is restored. For other branches: after PR #64 and #66 merge, `claude/instance-d-gui` is reset to `main` by Claude. Old branches (list in `README.md`) can be deleted only after `git diff --shortstat origin/main origin/<branch>` shows nothing unique. If any shared branch is ever force-pushed by accident again, restore it from the reflog of the machine that pushed, or from the GitHub PR's "head" commit shown on the closed PR page, then merge the restored tip (as was done at `393d09b`). Size: minutes per branch.

### O8. Open owner questions still unanswered in ledger D
- LBL corpus: how far to grow beyond 38 lineages and who verifies licences (recommendation: Claude workers verify every SHA and licence from primary sources; you approve the final register).
- CORE-3 (second import behaviour): decided "keep both"; implemented by a worker, no further action unless problems show.
- Symbol-server downloads: decided "explicit consent per operation".
- Unified engine O1 (licence-only review of the BinDiff port before the first public non-prerelease), O2 (flag OFF until G-U1..G-U6 pass), O3 (stay on Ghidra 12.0.4 through beta): adopted; O1 needs a person to read the licence (a lawyer if you plan commercial distribution). Size: variable.

### O9. Final release (never automatic)
- Only you can decide a non-prerelease. Precondition list in `qa-and-release.md` section 7. Claude will not create it.

## 4. Decisions only the owner can make (recommendation)

| Decision | Recommendation |
|---|---|
| When to lock the prereg | After corpus reaches the target and LBL-26 findings are closed; do not rush |
| Alpha to outsiders | After O1 has no unexplained failure in M01-M18 |
| Sign or not | Unsigned alpha, apply now, switch on after M01-M18 pass |
| Which ChatGPT drafts to accept | Docs (#70, #72) after a claims check; fixtures (#69, #71) after the tests run; code (#67) only through a worker with red tests |
| Delete old branches | Yes after the diff check, not before |

## 5. Pitfalls and lessons

- Never paste Microsoft-derived names, hashes, paths, KB numbers or function names into chat, issues or PRs.
- A Windows pass on an old prerelease does not test the newer panels. Note the prerelease tag in every result.
- The auto-mode classifier refuses supply-chain pin changes and similar steps from Claude; the owner approving in chat is the unblock (that is how decision 1 happened). Say it plainly and name the file.
- The tooling cannot reach `learn.microsoft.com`, `signpath.org`, `msrc.microsoft.com`: any fact from them needs your own check.
- Do not run Tier W in CI or inside the repository tree; the runner refuses (CI env vars, root inside the work tree, dotted root).

## 6. Verification checklist before calling this area finished

- [ ] O1 table returned, recorded in `docs/qa.md`, failures filed.
- [ ] O2 aggregate numbers recorded; `git status` clean on the owner machine.
- [ ] O3 decision made; if locked, `C9-PREREG-v1` SHA row exists.
- [ ] O4 settings done; `pages.yml` ran once.
- [ ] O6 application sent.
- [ ] No final release without an explicit owner statement.

## Owner decisions recorded 2026-10-15 ("accept all")

| Item | Decision | Applied |
|---|---|---|
| QA-CLI-3 | `cache verify` / `cache status` on a `--cache-dir` that is not a directory exit 2 (environment/config) | `cli.py cmd_cache`; `tests/test_cli.py`; strict xfail removed in `tests/stress/test_cli_stress_paths.py` |
| QA-S2-2 | The project store is owner-thread-only; workers hand results to the owner thread, a foreign-thread write fails with `sqlite3.ProgrammingError` and writes nothing | `tests/stress/test_stress2_enrichment_store.py::test_the_store_is_owner_thread_only_and_a_foreign_writer_changes_nothing` |
| Label-training pre-registration lock | Lock as drafted, but only after the LBL-26 pre-lock audit items (D-01..D-12, C-1..C-8) are closed; then the real Tier R run | NOT yet applied: waiting on those items (see `docs/handoff/label-training.md`) |
| Card-audit licence items | pcre2 recipe/releases/checker use `BSD-3-Clause WITH PCRE2-exception`; postgresql-libpq card excluded (moved to `corpus/excluded/` with its reason; `PostgreSQL` removed from the checker allow-list); brotli (MIT) and zstd (BSD-3-Clause elected over GPL-2.0) rows added to `docs/plans/calibration-licences.md` | done; `AUDITED_CVE_IDS` is now 32 |
| Windows-scope field on CVE cards | Accepted in principle; no field is added until the CVEs to annotate are chosen (additive-only contract) | open: needs the CVE list |
| FAB-A03, remaining U7 items | Handled as short yes/no lists in this file when reached | open |
