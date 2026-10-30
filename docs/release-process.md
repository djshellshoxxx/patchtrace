# Release process

How a PatchTrace prerelease is produced and published. Sources: `tools/release_gate.py`, `.github/workflows/qa-windows.yml`, `docs/specs/windows-release-signing-policy.md` (SPEC-52). Everything published so far is a prerelease `v0.1.0-beta.N`. See [version-history.md](version-history.md).

## Pipeline

A push to `main` (or a `v*` tag) runs `qa-windows.yml`:

1. `qa (ubuntu-latest)` and `qa (windows-latest)` (jobs `qa` and `qa-windows`): the test suite and Ruff, plus the `qt-gate` repeat legs. `windows-package` builds the one-folder package once with `tools/build_windows.py` (which checks the exe's version resource and icon, SPEC-52 WIN-1) and the NSIS 3.13 per-user installer, and uploads the Windows ZIP, Setup.exe and both LF-only `.sha256` sidecars. `windows-validate` downloads exactly those bytes, verifies both sidecars with `sha256sum -c`, and runs the frozen-app smoke (`tools/frozen_smoke.py dist/PatchTrace/PatchTrace.exe`, includes the self-test), the clean portable ZIP extraction under a Unicode path and the install/frozen startup/uninstall check (user-created project files retained). All of these run on pull requests as well. `linux-package` needs only Linux QA and uploads `PatchTrace-0.1.0-linux-x86_64.tar.gz` and its `.sha256`.
2. `linux-smoke` downloads the Linux artifact, checks `sha256sum -c`, extracts it and runs the offscreen self-test on Ubuntu 22.04 and 24.04.
3. `release-gate` runs `tools/release_gate.py` and decides whether to publish.
4. `release` runs only if the ref is a `v*` tag or the gate says `publish=true`, and only after `qa`, `qa-windows`, `windows-validate`, `linux-smoke` and `release-gate` succeeded. It re-verifies the Windows ZIP and Setup.exe sidecars before attaching them. It generates evidence notes (`tools/milestone_notes.py`; if that fails, a static preamble is used and the release is neither blocked nor faked), then creates a GitHub **prerelease** named `PatchTrace beta <run number>` tagged `v0.1.0-beta.<run number>` (a pushed `v*` tag names its own release `PatchTrace <tag>`) at the run's commit, with the Windows ZIP, Windows Setup.exe, Linux tar.gz, and their SHA-256 checksum files attached.

Pull-request and other non-push events never publish. Pull-request runs are cancelled by a newer push to the same pull request; push, tag and manual runs have their own concurrency group and are never cancelled. The release action is pinned to a commit (`softprops/action-gh-release` v2.6.2 `3bb1273`) and the dev tool chain to exact versions in `pyproject.toml`. A push to any ref other than `main` or a tag never publishes.

## The release gate

A **milestone** is a first-parent commit on `main` after the commit of the latest published `v0.1.0-beta.*` prerelease, the head included. Publish when any of these holds:

| Condition | Meaning |
|---|---|
| ref is a tag | Explicit tag push |
| head commit message contains `[release]` | Manual override: put it in the merge commit message |
| no earlier prerelease exists, or the latest one is not on the head's first-parent history | Bootstrap and recovery |
| 3 milestones have accumulated | The normal cadence: every third counted merge |
| the gate itself fails | It fails open and prints why, so a broken gate never withholds the Windows alpha |

The gate prints `publish=`, `milestones=` and `reason=`; the reason and the counted merges are copied into the release notes.

### Skip-marker hazard

A commit whose whole message (subject and body) contains a marker GitHub honours (`[skip ci]`, `[ci skip]`, `[no ci]`, `[skip actions]`, `[actions skip]`) produces no CI run, hence no build, so the gate does not count it. The head commit is always counted because its run exists. Hazards:

- Docs-only merges marked `[skip ci]` never advance the count, by design.
- The marker anywhere in a squash-merge body also suppresses the run. If you want a release, never include a skip marker in that message, and do not write the marker text when quoting it in a message.
- `[release]` on a commit that also holds a skip marker cannot publish: no run starts.

### Workflow-file hazard

GitHub refuses `GITHUB_TOKEN` publication when the head commit adds or changes files under `.github/workflows/` (HTTP 403 "Resource not accessible by integration"). The build still succeeds and the zip stays an Actions artifact. Publish by merging any later commit that does not touch workflows (use `[release]` if the count is short). No settings change is needed (docs/qa.md, release publication note).

## Packages

| Package | Built on | Smoke test |
|---|---|---|
| Windows x64 zip, one-folder PyInstaller build | Windows CI | Frozen EXE headless smoke, self-test and clean ZIP extraction outside checkout |
| Windows x64 installer, per-user NSIS 3.13 | Windows CI | Install to Unicode/spaces path, verify frozen startup, Start Menu, Apps registration, uninstall and data retention |
| Windows x64 per-user Setup installer | Windows CI with build-only Inno Setup | Install, Qt/runtime checks, frozen self-test, uninstall |
| Linux x86-64 tar.gz (executable bit preserved) | Ubuntu 22.04, older glibc baseline | Offscreen and Xvfb on 22.04 and 24.04 |
| Full zero-download bundle (`-full` archives) | `backend-bundle.yml`, manual dispatch or tag | Not published yet. A tag push builds and runs acceptance but never publishes; only `publish_prerelease=true` attaches assets, and only to a prerelease |

## Signing policy (SPEC-52)

Alpha and beta prereleases stay **unsigned**, and release notes say so, including that SmartScreen and antivirus may warn. Integrity comes from the `.sha256` sidecars. A combined `SHA256SUMS` asset and a build-provenance attestation are specified but need owner approval and workflow permission, so they are not part of the current assets. A hash or attestation shows a file came from the workflow run; it does not make a publisher trusted. A signing path is specified for later (no private key on a developer machine, a Claude worker, a PR job or a repository secret file). No signing is performed today.

## Verify assets before announcing

1. Download the Windows ZIP, Windows Setup.exe, Linux tar.gz and each corresponding `.sha256` file from the release page.
2. `sha256sum -c` (Linux) or `Get-FileHash ... -Algorithm SHA256` (Windows) must equal the sidecar and the hashes in the notes.
3. Check the release is marked **Pre-release** and its tag commit is the intended `main` commit.
4. Read the notes: they list job results (`qa-ubuntu`, `qa-windows`, `linux-smoke`), test counts and which acceptance gates are still open. Do not copy a claim that the notes do not make.
5. Windows desktop acceptance (display scaling, screen readers) is manual and reported separately from automated evidence.

## Rules

- Never create a final (non-prerelease) release, a draft, or auto-update without the owner's decision.
- Never bypass a failing test to get a release, and never describe a release as published if the token lacked permission.
- No claim of "air-gapped" or "signed" without linked evidence.
