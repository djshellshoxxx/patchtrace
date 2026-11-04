# Release process

How a PatchTrace prerelease is produced and published. Sources: `tools/release_gate.py`, `tools/verify_release.py`, `.github/workflows/qa-windows.yml`, `docs/specs/windows-release-signing-policy.md` (SPEC-52). Everything published so far is a prerelease `v0.1.0-beta.N`. See [version-history.md](version-history.md).

## Pipeline

A push to `main` (or a `v*` tag) runs `qa-windows.yml`:

1. `qa` on Ubuntu and Windows: the test suite and Ruff. The Windows job also builds the one-folder package with `tools/build_windows.py`, runs the frozen-app smoke (`tools/frozen_smoke.py dist/PatchTrace/PatchTrace.exe`, includes the self-test) and checks a clean portable ZIP extraction under a Unicode path, builds the NSIS 3.13 per-user installer, verifies installation/frozen startup/uninstallation while retaining user-created project files, and uploads the Windows ZIP, Setup.exe, and both `.sha256` sidecars. The Linux build job uploads `PatchTrace-0.1.0-linux-x86_64.tar.gz` and its `.sha256`.
2. `linux-smoke` downloads the Linux artifact, checks `sha256sum -c`, extracts it and runs the offscreen self-test on Ubuntu 22.04 and 24.04.
3. `release-gate` runs `tools/release_gate.py` and decides whether to publish.
4. `release` runs only if the ref is a `v*` tag or the gate says `publish=true`, and only after `qa`, `linux-smoke` and `release-gate` succeeded. It generates evidence notes (`tools/milestone_notes.py`; if that fails, a static preamble is used and the release is neither blocked nor faked), then creates a GitHub **prerelease** named `PatchTrace beta <run number>` tagged `v0.1.0-beta.<run number>` (or the pushed tag) at the run's commit, with the Windows ZIP, Windows Setup.exe, Linux tar.gz, and their SHA-256 checksum files attached.

Pull-request and other non-push events never publish. A push to any ref other than `main` or a tag never publishes.

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
| Linux x86-64 tar.gz (executable bit preserved) | Ubuntu 22.04, older glibc baseline | Offscreen and Xvfb on 22.04 and 24.04 |
| Full zero-download bundle (`-full` archives) | `backend-bundle.yml`, manual dispatch or tag | Not published yet. A tag push builds and runs acceptance but never publishes; only `publish_prerelease=true` attaches assets, and only to a prerelease |

## Signing policy (SPEC-52)

Alpha and beta prereleases stay **unsigned**, and release notes say so, including that SmartScreen and antivirus may warn. Integrity comes from the `.sha256` sidecars. A combined `SHA256SUMS` asset and a build-provenance attestation are specified but need owner approval and workflow permission, so they are not part of the current assets. A hash or attestation shows a file came from the workflow run; it does not make a publisher trusted. A signing path is specified for later (no private key on a developer machine, a Claude worker, a PR job or a repository secret file). No signing is performed today.

## Verify assets before announcing

1. From a clone of the repository, with `TAG` the release tag, `SHA` the intended `main` commit and an empty directory `DIR`, fetch the inputs, then run the offline verifier (`tools/verify_release.py`, stdlib only; it never uses the network, never extracts an archive and never runs a downloaded file):

   ```bash
   gh release view "$TAG" --json tagName,isPrerelease,isDraft,targetCommitish,assets,body > release.json
   git ls-remote --tags origin "refs/tags/$TAG" "refs/tags/$TAG^{}" > peeled.txt
   gh release download "$TAG" --dir "$DIR"
   python tools/verify_release.py --tag "$TAG" --sha "$SHA" --release-json release.json --peeled peeled.txt \
     --dir "$DIR" --record record.md
   ```

   It checks: the tag name; **Pre-release** set and not a draft; `targetCommitish`, the peeled tag (the plain ref of a lightweight tag) and the Windows ZIP's `PatchTrace/dependency-versions.json` `PatchTrace commit` all equal `SHA`, and its `PatchTrace` label is the tag without the leading `v`; the eight assets (Windows ZIP, Portable.zip, Setup.exe, Linux tar.gz and their four `.sha256` sidecars) are listed and downloaded with equal sizes; each sidecar is exactly `<64 lowercase hex>  <name>` and one LF (a CRLF sidecar fails); each file's SHA-256 equals its sidecar, the listed `sha256:` digest and every hash the notes print for that name, and Portable.zip is byte-identical to the Windows ZIP; the ZIP holds `PatchTrace/PatchTrace.exe`, `file-inventory.json` and `dependency-versions.json`, the tar holds `PatchTrace/PatchTrace` with an executable bit, each required member a regular file and not a link, and neither has an absolute, `..`, duplicate or escaping-link member (a tar symlink or hard link, or a ZIP Unix symlink entry, whose target is absolute or leaves the archive). Failures carry `PT-REL-TAG-MISMATCH`, `PT-REL-NOT-PRERELEASE`, `PT-REL-COMMIT-MISMATCH`, `PT-REL-ASSET-MISSING`, `PT-REL-SIDECAR-FORMAT`, `PT-REL-HASH-MISMATCH` or `PT-REL-ARCHIVE-CONTENT`. The Linux package records no commit yet, so that check reports `not-checked`, which is never a pass. `--json` prints one object with `{id, status, code, detail}` per check; `--notes FILE` replaces the release body as the notes source.
2. Exit codes: `0` no check failed, `2` usage error or unreadable input, including a downloaded asset that cannot be read (nothing is reported), `3` at least one check failed. Do not announce on `2` or `3`.
3. Paste `record.md` (tag, peeled SHA, bytes and SHA-256 per asset, failed and not-checked checks) into `docs/qa.md`, and add what the tool cannot see: the run URL and number, and the comparison with the Actions artifact of the same run (windows-acceptance spec section 1.3).
4. Read the notes: they list job results (`qa-ubuntu`, `qa-windows`, `linux-smoke`), test counts and which acceptance gates are still open. Do not copy a claim that the notes do not make.
5. Windows desktop acceptance (display scaling, screen readers) is manual and reported separately from automated evidence. Without the tool, `sha256sum -c` (Linux) or `Get-FileHash ... -Algorithm SHA256` (Windows) against each sidecar and the hashes in the notes is the manual fallback.

## Rules

- Never create a final (non-prerelease) release, a draft, or auto-update without the owner's decision.
- Never bypass a failing test to get a release, and never describe a release as published if the token lacked permission.
- No claim of "air-gapped" or "signed" without linked evidence.
