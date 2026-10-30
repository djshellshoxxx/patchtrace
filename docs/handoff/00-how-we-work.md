# How we work (the method)

Sources: `CLAUDE.md`, `AGENTS.md`, `docs/plans/worker-brief.md`, `docs/plans/multi-instance-coordination.md`, `docs/plans/ledger-{A,B,C,D}.md`, `docs/plans/owner-decisions-20261015.md`, `docs/release-process.md`, `.github/workflows/*.yml`. Tags: UNVERIFIED means not confirmed in the repository.

## 1. Purpose and current state

The project is a spec-first, evidence-first Windows/Linux desktop tool (PySide6) that compares patched and unpatched PE files and ranks functions. Policy lives in `AGENTS.md` (authoritative) and `CLAUDE.md`. State proof commands:

```
git fetch origin
git log -1 --format='%h %ad %s' --date=short origin/main                  # 00db4c9 on 2026-10-15
git rev-list --left-right --count origin/main...origin/claude/instance-d-gui   # 0 240 on 2026-10-15
git log --oneline origin/main..origin/claude/instance-c-research          # 5 commits, PR #66
```
Plus the GitHub reads: open PRs, and the check runs of each PR head (see section 6).

## 2. Instances and who owns what

Owner-approved layout (`multi-instance-coordination.md`). Each instance pushes only to its own branch and keeps its own ledger.

| Instance | Branch | Owns | Ledger |
|---|---|---|---|
| A | `claude/clever-clarke-s4nhi6` (old; its work is merged) | Integration owner: unified engine, intelligence, `ui.py`, workflows, release gate, GUI F0/F1 | `docs/plans/ledger-A.md` |
| B | `claude/instance-b-features` | Feature services, CLI, view-models: KB, CAP, DIE, WB1-WB3, KEV, YARA-X, acquisition, tools-core. Stops at pure view-models and messages D | `ledger-B.md` |
| C | `claude/instance-c-research` | Label training (LBL, Tier R, Tier W), specs, audits, backend bundle | `ledger-C.md` |
| D | `claude/instance-d-gui` | GUI framework F2-F9, all Qt panels (`ui_<feature>.py`), audits, migration readiness, QA suites, master plan | `ledger-D.md` |

The ledgers are append-only logs; the newest block is at the bottom. Read the last two blocks of each before acting. Today only one session (D, `session_01Mr844cQDLwXi9iMUoGmBXk`) is known to be active; A, B and C are idle or finished (UNVERIFIED which sessions still run).

## 3. Worktrees, workers and the merge flow

1. A worker gets a git worktree (`.claude/worktrees/<name>`), branch `worktree-agent-<id>` or `worktree-<id>`, starting from `origin/main` (a harness fact in ledger A). The prompt's first line is `git merge --ff-only claude/instance-d-gui` (or the instance branch) so it starts from the integration branch.
2. The worker commits locally with the trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (or `Claude Haiku 5.5`). It never pushes and never switches branches (`worker-brief.md` section 3).
3. The integrator (the orchestrator session) cherry-picks or merges the worker branch into the instance branch, runs focused tests, then the full gate twice before a PR.
4. PR to `main`: draft first, ready when every check on the CURRENT head is green. Squash-merge with `expectedHeadSha`. Then reset the instance branch to `main`: `git fetch origin main && git checkout -B <branch> origin/main`, and `git push --force-with-lease` only when the remote branch holds merged history only.
5. Docs-only PRs: put `[skip ci]` in the squash commit message (no build, no prerelease). Code merges must not contain any skip marker anywhere in the message or body (`docs/release-process.md`, skip-marker hazard).

Before every PR: fetch `main`, merge it into your branch, resolve, run the gate. Before any implementation: check GitHub's current default-branch SHA, all open PRs and their checks (`CLAUDE.md`). Do not overwrite another worker's branch.

### Doc-conflict rule
Append-only shared docs: `docs/modules.md`, `tasks/todo.md`, `docs/qa.md`. On conflict keep both sides, never reflow. Each slice appends a block under a unique heading `### [<slice id>:<name>]`. In `cli.py` `COMMANDS` take the union. Spec files get their status line updated by whoever builds from them.

### Frozen shared files (workers must not edit; integrator only)
`ui.py`, `tooltips.py`, `tests/test_tooltips.py`, `panel_manifest.py`, `cli.py`, `tools/frozen_smoke.py`, `tests/test_acceptance_smoke.py`, `pyproject.toml`, `optional_deps.py`, `backend.py`, `enrichment/storage.py` (`KINDS`), `.gitattributes`, `tools/build_*.py`. A worker that needs a change lists it under "Integrator asks". New UI is a dock or tab through the panel registry, never an edit of `ui.py`.

## 4. CI workflows and what each proves

All under `.github/workflows/`. Inputs are read from the files.

| Workflow | Trigger | Proves | Dispatch inputs |
|---|---|---|---|
| `qa-windows.yml` (QA and Windows standalone) | push to `main`, tags `v*`, every PR, manual | Jobs: `qa` (ubuntu + windows: `pytest -q`, `ruff check src tests tools`, protobuf runtime check; windows also builds with `tools/build_windows.py` and runs `tools/frozen_smoke.py dist/PatchTrace/PatchTrace.exe`), `qt-gate` (repeat GUI files: 20 on Linux, 5 on Windows, via `tools/qt_gate.py --repeat N`), `linux-package`, `linux-smoke` (22.04 and 24.04), `release-gate`, `release` (prerelease only) | none |
| `backend-bundle.yml` | manual, workflow_call, push (filters in file) | Zero-download bundle build and offline acceptance; `pin_report_only` and `pin_verify` modes | `version`, `platforms` (both/windows/linux), `publish_prerelease`, `pin_report_only`, `pin_verify`, `sigstore_identity`, `sigstore_issuer`, `gpg_fingerprint` |
| `corpus-tier-r.yml` | manual, nightly cron 03:17 and 03:47 UTC, push main, PR | Sharded Tier R synthetic corpus builds and scoring (plan, shard matrix, merge, windows/msvc advisory) | `shards` (1-256, default 4), `seed` (default 1), `engines` (rz-diff, ghidriff, bindiff; default rz-diff), `subset` (smoke, suites, cards, mutations, noise, full; default smoke) |
| `unified-live-gates.yml` | manual only (added by PR #64; not on `main` yet) | G-U1..G-U7 live runs with Ghidriff pairs, mutants, integrity, report. Advisory | `pairs` (case card ids or `all`), `per_class` (default 20) |
| `unified-corpus.yml` | manual | Unified corpus gates and Windows bench (advisory) | see file (UNVERIFIED inputs) |
| `live-backend.yml` | manual, push main and `codex/**`, PR | Native Windows Ghidriff acceptance matrix (5 variants) | none |
| `live-rizin.yml`, `live-bindiff.yml`, `live-capa.yml`, `live-intel-tools.yml`, `live-kev.yml`, `live-nvd.yml`, `live-unified.yml` | see files (UNVERIFIED triggers except `live-unified.yml`: manual, push main and `codex/**`, PR) | Live tool or feed compatibility, real binaries/feeds, not mocks | UNVERIFIED |
| `pilot-eval.yml` | manual | Patch-intent pilot evaluation (advisory) | none |
| `nightly-fuzz.yml` | cron 03:17 UTC, manual | BinExport2 fuzz, non-gating | none |
| `optional-deps.yml` | PR, manual | Wheels-only probe of optional extras | none |
| `pages.yml` | push to `main` under `site/**`, `tools/site/**`, the workflow; manual | Builds and deploys the project page; first run waits for the owner to enable Pages | none |

Mocked or synthetic tests are never live compatibility evidence (`AGENTS.md`).

## 5. Push rules

- Push only to your own instance branch. Never push to `main` directly. Never force-push except `--force-with-lease` after a merged-history-only reset of your own branch. A past accidental force-push by instance C was repaired by merging a restored branch (tip `393d09b`).
- Never delete or overwrite another worker's branch. ChatGPT drafts are `chatgpt/*`: read them, do not push to them.
- Commit trailers: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and `Claude-Session:` line when the session reminder provides it; PR bodies end with the Claude Code attribution line.
- A ledger-only commit on a PR branch must not carry a skip marker, because GitHub scans the head commit message (ledger B note).

## 6. Reading CI correctly (stale-head events)

A PR's check list can contain runs for earlier head commits, and a run can be queued, skipped or cancelled because a newer push superseded it. A green tick on an old head proves nothing about the current head. Procedure:
1. Read the PR head SHA (`pull_request_read` method `get`, or `gh pr view <n> --json headRefOid`).
2. List check runs for that exact SHA; open each run URL and confirm `head_sha` equals the PR head.
3. `skipped` jobs (for example `release-gate` on a PR, the live jobs on a branch without the trigger) are expected on PRs and are not green evidence.
4. Required evidence for a merge: `qa (ubuntu-latest)`, `qa (windows-latest)`, `qt-gate (ubuntu-latest, 20)`, `qt-gate (windows-latest, 5)`, linux package/smoke, and the advisory live jobs reported as such. Record exact counts (the prerelease notes show them, e.g. beta.281: Linux 13214 passed, 62 skipped; Windows 13189 passed, 87 skipped).
5. A job that never started is not a failure and not a pass: wait, or re-run. Use `get_job_logs` for failures. Do not retry a flake blindly: ledger A records one real flake (`raw-cache-hit`, `_java_version` timeout) that was a defect (task T10 in `master-todo-d.md`).
At the last read (2026-10-15 05:58Z) PR #64's 21 check runs were almost all `queued`. The "stale-head" lesson itself comes from the harness task text and is not written down in the repository docs (UNVERIFIED as repo doctrine); the procedure above is the safe reading.

## 7. Windows alpha scope

A usable Windows standalone alpha, not a final release (`CLAUDE.md`, `docs/windows.md`, `docs/release-process.md`):
- Python and Qt are bundled in a one-folder PyInstaller build (`tools/build_windows.py`), unsigned, no installer. Built on Windows CI only; PyInstaller cannot cross-compile (`AGENTS.md`).
- Ghidra, Java and Ghidriff stay external and clearly documented, unless the offline bundle (`backend-bundle.yml`) is attached: the "full" archives are not published yet.
- Qt DLLs stay replaceable; dependency notices are copied.
- The included synthetic sample works without a backend or AI provider.
- Windows desktop acceptance (M01-M28 in `docs/specs/windows-acceptance-and-milestone-builds.md`) is manual and reported separately. Nothing is called complete while acceptance gates are unverified.

## 8. Token-cost rules (from CLAUDE.md, binding)

- Lowest-cost reliable model per task: Haiku for narrow searches, docs, fixtures, lint; Sonnet for integration, architecture, nontrivial builds; the highest tier only for a demonstrated hard blocker, a nuanced security invariant, or a failed lower-cost attempt. Never retry with an underpowered model. Fable is never used (coordination doc).
- Delegate only bounded independent work; no agents for single-file edits.
- Workers read only their card; reports at most 250 words; focused tests while developing (`nice -n 10 python -m pytest <files> -q -p no:cacheprovider`, `QT_QPA_PLATFORM=offscreen`), the full suite once per worker at most, the integrator runs the full gate twice. At most 12 workers per 4-CPU container.
- Budget governor: before launching a wave read the session `rate_limit_info`; if status is not `allowed` or `allowed_warning`, launch nothing. No Opus while `allowed_warning`.
- Compute-heavy runs (compiling corpora, Ghidra, evaluation) go to GitHub Actions matrices, not agent loops.
- Be patient with workers: stop one only when demonstrably looping, and say why in the ledger.

## 9. Product invariants (violating one is a defect)

From `worker-brief.md` section 2: never execute a target binary; never upload content silently (network only with operation-specific consent, exact preview); never fabricate disassembly or evidence; never show an uncalibrated number as vulnerability confidence (display stays `ordinal` until a calibration artifact passes); never average different engines' or channels' scores; keep conflicting evidence; unknown or missing is not a negative vote; shared-origin evidence counts once; older/newer orientation explicit; provenance on everything; advisory, string and code text is untrusted data; one main window; pure domain models and adapters separate from Qt; persisted contracts change additively only; Microsoft-derived binaries, PDBs and Winbindex-derived labels are never committed; no GPL/AGPL code copied (Ghidriff stays a separate unmodified component; Diaphora, PatchDiff2, Turbodiff are references only). Credentials are session-only (`AGENTS.md`).

Test rules: red then green; hermetic (no network, no Microsoft binaries, no target execution); deterministic; short explicit `parametrize(ids=[...])`; `>=` on timings; no fixed sleeps; LF fixtures (`.gitattributes` lines go to the integrator); YAML plain scalars never contain `: `; installs with `pip --only-binary=:all:`; `open(..., encoding='utf-8', newline='\n')`; `pathlib`.

## 10. Owner decisions file

`docs/plans/owner-decisions-20261015.md` holds 14 numbered decisions. Do not re-ask them. Summary of those that steer work: pins recorded (1, done in 8fb3521); CORE-3 keep both (3); grow the label corpus (4); lock prereg after the pre-lock audit LBL-26 (5); Tier R compute approved (6); CLI exit codes unified per the recommendation (7); unified engine O1/O2/O3 recommendations adopted (8); unsigned alpha plus SignPath application (9); symbol-server downloads only with per-operation consent (10); docs PRs #40/#41/#43 closed (11); qbindiff/radiff2/Diaphora are v2, not dropped (12); owner does the Windows pass and Tier W runs (13, 14). Append new decisions to a new dated file; do not edit this one.

## 11. Tool and sandbox limits learned (read `docs/plans/ledger-D.md`)

- Auto-mode classifier: it refused to write supply-chain pins (digests into `tools/backend_pin.json`) as a trust-on-first-use action; the owner had to approve explicitly (decision 1). Expect the same for any change that adds a downloaded-artifact digest, a dependency pin from an unverified source, a force-push, or a destructive branch operation. Do not work around it; ask the owner, record the answer in the ledger.
- Sandbox egress: the agent proxy returned 403 / DNS failure for `learn.microsoft.com`, `signpath.org`, `msrc.microsoft.com` (`docs/research/windows-signing-options.md`) and the GitHub release API for BinDiff (`tools/bindiff_pin.json` trust note). Facts from such hosts must be tagged snippet-only or unverified, and live acquisition runs need a GitHub Actions runner or the owner's machine. Check `/root/.ccr/README.md` and `curl -sS "$HTTPS_PROXY/__agentproxy/status"` for proxy state (environment text of the cloud container, not repo docs).
- GitHub tools in a session are limited to the configured repository `djshellshoxxx/patchtrace`.
- `GITHUB_TOKEN` refuses to publish when the head commit changes files under `.github/workflows/` (403). Plan a following non-workflow merge.
- Shiboken segfault when a `TaskRunner` is dropped on a worker thread: hardened in `gui/qt/tasks.py` (T15); keep the runner owned by the host until shutdown.
- A worktree-isolated agent cannot run compound `git` shell lines; use plain separate commands.
- Module `patchtrace` is not importable by `python -m tools.calibration...` unless `PYTHONPATH=src` (observed: `ModuleNotFoundError`).

## 12. Verification checklist before calling this area finished

- [ ] `git fetch` then re-read `origin/main`, open PRs and the current head's check runs.
- [ ] Every ledger's last block is read; contradictions are resolved by re-reading code, not by trusting prose.
- [ ] No branch of another worker was overwritten.
- [ ] Each merge to `main` produced the expected prerelease (or the workflow-file hazard is documented in the PR).
- [ ] No claim of "signed", "air-gapped", "accurate" or "complete" without a linked evidence row in `docs/qa.md`.
