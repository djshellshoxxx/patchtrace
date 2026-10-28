# Working notes: Windows alpha run (2026-10-28)

Short record of decisions and pitfalls for the next worker. Status lives in `SPEC_STATUS.md`, evidence in `docs/qa.md`,
security findings in `SECURITY_REVIEW.md`, the session handoff in `docs/plans/claude-autonomous-alpha-handoff-20261013.md`.

## Decisions

- **Alpha naming follows the repo's own spec**, not a new scheme: `v0.1.0-alpha.<n>` is the annotated acceptance tag
  (`docs/specs/windows-acceptance-and-milestone-builds.md` 1.2); `v0.1.0-beta.<run>` stays the automatic main build.
  The release name now derives from the tag (the spec's precondition for the first alpha).
- **Exe icon = the owner's mark** `site/assets/cdl-mark.svg` (already the site favicon), copied byte-identically to
  `src/patchtrace/resources/patchtrace-mark.svg`; a test keeps the copies equal. Swap the SVG to rebrand.
- **No CompanyName in the version resource**: SPEC-52 forbids publisher wording for unsigned builds. Comments names
  the commit, which is how a downloaded exe is matched to its source (`tools/check_windows_exe.py`).
- **Manifest skipped** (SPEC-52 WIN-1 fallback): PyInstaller's default asInvoker manifest stays; `longPathAware` is
  not set.
- **CI**: pull requests run only Linux QA + Linux package/smoke; Windows QA, build and validation run on main, `v*`
  tags and manual dispatch. Check names `qa (ubuntu-latest)` / `qa (windows-latest)` are kept (job `name:`), so
  branch-protection rules and the acceptance spec still match. To test Windows on a branch, dispatch the workflow.
- **paths-ignore covers images only**: 80+ tests read markdown under `docs/` and the package ships `docs/`, so
  ignoring markdown would silently skip real checks.
- **Native Ghidriff matrix (`live-backend.yml`) left as is** (PRs touching `src/**`): it is the acceptance gate
  the milestone spec requires for backend changes, not a build.
- **Dev tools exact-pinned** to what CI resolved on 2026-10-28; `calibration-dev` (never installed in CI) keeps its
  range. Transitive dependencies are not hash-locked (see `SECURITY_REVIEW.md`).
- **Enrichment 500 ms hit objective not attempted further**: profiling shows the spec-mandated re-validation alone
  costs about 0.65 to 0.8 s at 10,000 pairs; the remaining options change the storage contract or need the owner to
  relax SPEC-07. Baseline output hashes for any future change: `scratchpad/perf/hash_output.py` (local only).

## Pitfalls

- `ui.py` is capped at 3077 lines (`tests/test_gui_host_seam.py`, a migration ratchet). Move helpers out instead of
  growing it; never raise the ceiling.
- The frozen package keeps only Qt platform plugins (`tools/pyinstaller_hooks/hook-PySide6.QtGui.py`):
  `QIcon('x.svg')`, JPEG, GIF and ICO decoding silently do nothing there. Render SVG with QtSvg; PNG is built in.
- PyInstaller's version-file loader `eval()`s the file; validate and `repr()` every value.
- `PyInstaller.utils.win32.versioninfo` imports `win32api` (absent off Windows) and packs native `13L` structs (8-byte
  longs on Linux). Tests stub the import and use little-endian standard sizes; on Windows the real path runs.
- PySide: a `QBuffer(QByteArray(...))` temporary is freed under the buffer; keep the `QByteArray` referenced.
- Local test environment: `apt-get install libegl1`; `pip install -e '.[dev,search,rules]'` (CI's extras); the venv
  interpreter must be a real file, not a symlink, because `tests/test_rules_worker.py` resolves `sys.executable`.
- A commit that changes `.github/workflows/*` and is then tagged by the release action may get HTTP 403 when the
  action creates the tag (SPEC-52 WIN-4 note). Push the `v*` tag yourself on a commit whose own diff does not touch
  workflows.
- Cloud agent sessions cannot push tags: `git push origin refs/tags/...` gets HTTP 403 (only the session branch
  is writable). The owner pushes `v*` tags; the tag run then builds, re-validates and publishes.
- `gh` has no valid token in these sessions; use the GitHub MCP tools for runs, jobs, logs and releases.
