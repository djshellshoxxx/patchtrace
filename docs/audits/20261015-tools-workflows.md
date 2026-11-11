# Audit: CI workflows and release/build tools (2026-10-15)

Snapshot: `main` at `21a005e` (fast-forward checked at start). Read-only static audit. No workflow was run, no
script was executed, no secret or network resource was touched. `backend-bundle.yml` is owned by another
instance and is excluded. Repeats of findings in `codex-workflows-1.md` and `codex-packaging-1.md` are marked
**known** with their CODEX id; their evidence was re-checked against this snapshot where a location changed.

Totals: **0 High, 3 Medium, 17 Low** new findings (OPS-1 to OPS-20 in the table; none of OPS-1 to OPS-20 is a
repeat), plus 12 known repeats.

## Findings

| ID | Sev | Status | file:line | Evidence | Fix |
|---|---|---|---|---|---|
| OPS-1 | Medium | new | `tools/qt_gate.py:3`; `.github/workflows/qa-windows.yml` (absent) | The docstring says the gate runs in a "Linux PR job and nightly". No workflow references `qt_gate` (grep of `.github/` is empty). `docs/qa.md:546-550` supplies a YAML snippet "for the integration owner" that was never added, yet `docs/qa.md:319` cites the gate as evidence. | Add the step to the `qa` job (ubuntu `--repeat 20`, windows `--repeat 5`, per the docs), or correct the docstring and docs so no CI claim is made. |
| OPS-2 | Medium | new | `.github/workflows/qa-windows.yml:181-182`; `tools/milestone_notes.py:110-116` | Both `qa-ubuntu` and `qa-windows` receive `needs.qa.result`, the aggregate of the matrix. One failing leg marks both rows FAIL, and a Linux pass is reported as FAIL when only Windows failed. The release notes are the alpha's evidence record. | Export each matrix leg's own result (job outputs keyed by `runner.os`, or the jobs API), and pass those per leg. |
| OPS-3 | Medium | new (policy unverified) | `.github/workflows/pages.yml:9` (`workflow_dispatch`), `:36-44` (deploy) | `workflow_dispatch` can run from any branch. Neither `build` nor `deploy` has a `ref == main` guard, so a branch with write access can dispatch a build of its own content and deploy it to the public Pages site without review. The `github-pages` environment's deployment-branch policy is not in the repository and was not queried. | Add `if: github.ref == 'refs/heads/main'` to build and deploy, and restrict the environment to `main` in settings. |
| OPS-4 | Low | new | `tools/milestone_notes.py:32` | Release notes state "A1 help for all 7 commands". `frozen_smoke.py:49` takes `names()`, and `docs/qa.md:336` records 11 built-in verbs. The stated coverage is wrong and will drift as verbs are added. | Derive the count from `frozen_smoke.COMMANDS`, or drop the number. |
| OPS-5 | Low | new | `.github/workflows/qa-windows.yml:5` (`tags: v*`), `:186` (`prerelease: true`), `:189` (name) | A `v*` tag push, which the release is meant to publish as a stable tag, is published as a prerelease titled "PatchTrace beta <run_number>". | Derive `prerelease` and the title from the ref kind (tag vs main). |
| OPS-6 | Low | new | `.github/workflows/qa-windows.yml:133-134` | `release` has no `always()`. For a tag push, if `release-gate` fails for infrastructure reasons (checkout, setup-python), the release is skipped silently, although the gate itself is designed to fail open. | Use `always()` with explicit `needs.*.result == 'success'` checks, and keep the tag path independent of gate outputs. |
| OPS-7 | Low | new | `.github/workflows/qa-windows.yml:109-119` | No `concurrency` group. Two quick pushes to main read the same anchor and can both publish, breaking the every-third-merge cadence. Tags are unique by run number, so no collision, only extra prereleases. | Add `concurrency: { group: release-gate, cancel-in-progress: false }`. |
| OPS-8 | Low | new | `.github/workflows/qa-windows.yml:96-100` | The bundled-library check is vacuous. A glob that matches nothing passes `ldd` on a literal path, the error goes to stderr unrecorded, and the only output is `::warning::`. It can never fail, so the check proves nothing. | Assert each path exists and at least one glob matched; fail on `not found`. |
| OPS-9 | Low | new | `.github/workflows/qa-windows.yml:55-56, 75-76, 93-94`; `tools/milestone_notes.py:29`; `tools/build_linux.py:24` | `0.1.0` is hard-coded in five places. A version bump in `build_linux.VERSION` breaks the upload late, in the release job. | Read the version from one source, or pass `--version` from the workflow. |
| OPS-10 | Low | new | `tools/build_linux.py:288`; `tools/build_windows.py:63` | `copytree(root/'docs')` ships the whole `docs/` tree in every end-user archive, including `docs/audits`, `docs/plans`, and worker briefs. | Copy a curated user-facing doc set and exclude internal audit and planning material. |
| OPS-11 | Low | new (partly CODEX-12) | `tools/build_windows.py:85-87`, `:119`; `tools/build_linux.py:27-29`, `:325`; `:15` vs `build_linux.py:40`; `:17-20` vs `:42-46` | The Windows script needs `PySide6_WebEngine` and `PySide6_Pdf` metadata unconditionally (`distribution()` raises if absent). Linux does not list them. The protobuf pin and notice lists are duplicated in both scripts, and self-test timeouts differ (60 s vs 120 s). | Move shared pins, notice lists, and timeouts into the shared helper module, and make the distribution list the same on both platforms. |
| OPS-12 | Low | new | `.github/workflows/live-backend.yml:50-52` | Line 52 sets `$global:LASTEXITCODE = 0` unconditionally after the seeding Ghidriff run, so a failed seed run is discarded. Only `live_backend_check.py` can detect it. | Check the seed run's exit code, or assert the seeded store exists before continuing. |
| OPS-13 | Low | new | `.github/workflows/live-rizin.yml:49`; `.github/workflows/corpus-tier-r.yml:101` | `RZ_DIFF` is set to `rizin/bin/rz-diff` with no existence check on Linux. The Windows leg searches the archive and throws if absent (`live-rizin.yml:60-61`). A layout change fails later, with a less clear message. | Add `test -x "$RZ_DIFF"` with an `::error::`, or locate the binary as the Windows leg does. |
| OPS-14 | Low | new | `.github/workflows/live-unified.yml:85` | `$(echo "$PWD"/ghidra-runtime/*/)` expands an unquoted glob. Zero or several matches write a literal glob or a space-joined list into `GITHUB_ENV`. `corpus-tier-r.yml:127` uses `find ... \| head -n 1`, which is correct. | Use the `find` form. |
| OPS-15 | Low | new | `.github/workflows/corpus-tier-r.yml:10` (dispatch default `'4'`), `:35` (env fallback `'2'`); `tools/calibration/tier_r/shard.py:656` (default 4) | Three different shard-count defaults. Push and PR runs silently use 2 shards. | Use one default, defined in one place. |
| OPS-16 | Low | new | `.github/workflows/unified-corpus.yml:41-42`, `:69` | The comment says "exit 3 means BLOCKED", but the step has no handling, so BLOCKED fails the job before the build and bench run. `cp` on line 69 fails the job when no label files exist. | Capture the exit code and record BLOCKED in the gate report; make the label copy tolerate zero matches. |
| OPS-17 | Low | new | `.github/workflows/nightly-fuzz.yml:12, 20`; `tools/fuzz_binexport.py:94-95`; `pyproject.toml` dev extra (no `atheris`) | The job is titled BinExport2 fuzz and its comment implies atheris coverage on Linux. `atheris` is not in the dev extras, so only the random-mutation loop runs. `docs/qa.md:168` confirms atheris was not installed. | Install `atheris` in the job with a pin, or relabel the job as random-mutation. |
| OPS-18 | Low | new | `.github/workflows/pilot-eval.yml:30`, `:35` | The uploaded report carries placeholder digests, `corpus_sha256` of 64 zeros and `tool_sha` of 40 zeros, with an empty arm set. Readers can take these for real identifiers. The invariant forbids fabricated evidence. | Write `null` or `not-run` for unavailable digests, or do not upload the placeholder. |
| OPS-19 | Low | new | `.github/workflows/qa-windows.yml:45-56, 71-76`; `live-backend.yml:74-81`; all other `upload-artifact` steps | None of the 20 `upload-artifact` steps sets `retention-days`. The default is 90 days, applied to per-push Windows and Linux packages and raw native run outputs. | Set explicit retention (for example 14 days for CI packages, 30 for evidence). |
| OPS-20 | Low | new | `.github/workflows/qa-windows.yml:21, 61`; `optional-deps.yml:17`; `nightly-fuzz.yml:16`; `pilot-eval.yml:15`; `unified-corpus.yml:32, 85, 108`; `corpus-tier-r.yml:74` | Only four `checkout` steps set `persist-credentials: false`. The test jobs, which run pull-request code, persist the token in `.git/config`. | Default to `persist-credentials: false` in every job that does not push. |

### Known repeats

| Id | Where it still applies in this snapshot |
|---|---|
| CODEX-1 (mutable action tags) | `qa-windows.yml:21, 22, 184`; `pages.yml:32-33, 44`; `ilammy/msvc-dev-cmd@v1` in `live-backend.yml:30`, `live-rizin.yml:72`, `live-unified.yml:30`; `softprops/action-gh-release@v2` at `qa-windows.yml:184` |
| CODEX-2 (no job timeout) | `pages.yml:36-44` deploy; `qa-windows.yml:59` linux-package; `qa-windows.yml:132-135` release |
| CODEX-3 (Pages build privileges) | `pages.yml:10-13` |
| CODEX-4 (nightly fuzz permissions) | `nightly-fuzz.yml` (no `permissions:` block) |
| CODEX-5 (unhashed pip, moving runtimes) | `pages.yml:27` (`pytest` unpinned); `pilot-eval.yml:19` (`pytest hypothesis` unpinned, `-e .` without `--only-binary`); `qa-windows.yml:27, 66` |
| CODEX-6 (restored extracted tools bypass verification) | `corpus-tier-r.yml:83-100`. `live-intel-tools.yml:46-49` restores a cache too; its provisioner was not reviewed, so the same gap is not claimed there. |
| CODEX-7 (parse error publishes) | `tools/release_gate.py:221-237`, fail-open at `:232-233` |
| CODEX-8 (skip-check trailers, bracket markers in bodies) | `tools/release_gate.py:35, 65-73` |
| CODEX-10 (unbounded dev deps) | `pilot-eval.yml:19`; `pages.yml:27` |
| CODEX-11, CODEX-12 (optional notices; empty license copy) | `tools/build_linux.py:296-305`; `tools/build_windows.py:90-96` |
| CODEX-13 (full attach without validation) | `tools/build_linux.py:201-225`; `tools/build_windows.py:129-131` |
| CODEX-14 (Linux release lacks full CLI smoke) | `qa-windows.yml:68` (build), `:101-106` (smoke) |
| CODEX-15 (GPL components in full bundle) | `tools/build_linux.py:213` (copies the whole payload) |

## What I reviewed

- Workflows, in full: `qa-windows.yml`, `pages.yml`, `nightly-fuzz.yml`, `optional-deps.yml`, `pilot-eval.yml`,
  `live-backend.yml`, `live-bindiff.yml`, `live-intel-tools.yml`, `live-kev.yml`, `live-nvd.yml`,
  `live-rizin.yml`, `live-unified.yml`, `unified-corpus.yml`, `corpus-tier-r.yml`. All 14 parse as YAML and
  have a top-level `permissions:` block except `nightly-fuzz.yml`.
- Tools, in full: `tools/release_gate.py`, `tools/build_linux.py`, `tools/build_windows.py`,
  `tools/frozen_smoke.py`, `tools/milestone_notes.py`, `tools/qt_gate.py`, `tools/corpus_check.py`, and the
  corpus CLI `tools/unified/corpus/cli.py`. Site tools checked: `tools/site/build_site.py` (outbound URL
  allow-list and config validation), `tools/site/requirements.txt`, and reachability of `tools/site/*.py`.
- Checks run: grep for untrusted expressions in `run:` and `env:`. Every `${{ inputs.* }}` and
  `github.event.inputs.*` is routed through `env:` (clean). The only inline matrix expressions in `run:` are
  controlled constants (`live-bindiff.yml:52, 60`, `live-intel-tools.yml:52`). Grep for `retention-days`,
  `continue-on-error`, `concurrency`, `persist-credentials`, and `uses:` tags. A colon-space scan of plain
  scalars found none. Every file referenced by an in-scope workflow exists (`docs/linux.md`, `docs/qa.md`,
  `docs/plans/pilot-preregistration-v1.md`, `tests/test_site_*.py`, the CSAF fixture, the pilot tests).
- Positive controls: `release_gate` runs `git` and `gh` via argv lists with no shell. Its output is reduced
  to printable ASCII before `$GITHUB_OUTPUT`. `milestone_notes` receives `GATE_REASON` as a `printf` argument,
  not in the format string. The `release` job uses `persist-credentials: false` on its source checkout. The
  Ghidra and rizin downloads in `live-backend`, `live-rizin`, `live-unified`, and `unified-corpus` are
  digest-checked before extraction. `unified-corpus`'s `fetch` compares each source tree to `pins.json` and
  fails closed. `frozen_smoke` treats `SKIP` as neither pass nor fail, as documented. `release_gate` publishes
  on `push` only.

## Not reviewed

- `.github/workflows/backend-bundle.yml` (owned by another instance).
- Tools outside the listed scope: `tools/provision_*.py`, `tools/live_*.py`, `tools/check_*.py`,
  `tools/verify_backend_pins.py`, `tools/bundle_acceptance.py`, `tools/qa_binexport_memcap.py`,
  `tools/fuzz_binexport.py` (only its exit path was read), `tools/calibration/**`, and
  `tools/unified/gates_u.py` and `bench.py` (only argument and output paths were read). Their cache and
  verification behaviour (for example the intel and BinDiff provisioners behind the cache restores) was
  not verified.
- Repository settings that this audit could not query: the `github-pages` environment's branch policy,
  default workflow token permissions, runner image contents, and whether `ilammy/msvc-dev-cmd` or any
  other action has been compromised.
- No workflow was executed, no GitHub API was called, and no artifact was built or inspected. Every
  finding is a statement about source text at this snapshot, not about a failed run.
