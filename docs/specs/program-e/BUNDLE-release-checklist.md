# BUNDLE release checklist: Windows alpha acceptance and prerelease rules

Status: plan, written 2026-10-15. Documents only. Extends `docs/specs/program-e/BUNDLE-integration-plan.md` (sections 9, 10.2, 10.3 and QA rows BUNDLE-1 to BUNDLE-7) and uses the manual matrix M01 to M18 from `docs/specs/windows-acceptance-and-milestone-builds.md`. Signing policy: `docs/specs/windows-release-signing-policy.md` (SPEC-52); research: `docs/research/windows-signing-options.md`. Operational state and remaining work: `docs/handoff/backend-bundle.md`.

Rule that governs everything here: automated evidence and owner/external acceptance are reported in separate lists. A gate that only the owner or Windows hardware can close is reported as BLOCKED external, never as done.

## 1. Release rules (binding)

1. Only `.github/workflows/backend-bundle.yml` publishes bundle assets, and only when started by `workflow_dispatch` or `workflow_call` with `publish_prerelease=true`. A pushed `v*` tag builds and runs acceptance but never publishes.
2. The release created is always a PRERELEASE (`gh release create --prerelease`), never a draft, never final. The job refuses to touch an existing release that is not a published prerelease.
3. A final (non-prerelease) release needs the owner's explicit say-so in the conversation or a recorded decision in this repository, after sections 3 and 4 are complete and plan open questions 1 and 2 (Ghidriff GPL-3.0 and JDK source offer) have an owner answer.
4. If the token lacks `contents: write` or the upload fails, report "build green, release not published" with the run link. Do not retry in a loop, do not use another credential, do not claim a release exists.
5. Publication requires the pin gate without `--allow-unapproved-licenses` (`python tools/check_backend_pin.py --release` exit 0).
6. Release notes state: unsigned, SmartScreen and antivirus may warn, integrity is the `.sha256` sidecar only, Linux is experimental, and the list of open gates from section 4. No claim of "air-gapped" or "verified offline" without a linked acceptance run.
7. Never commit Microsoft binaries, PDBs or Winbindex-derived labels; never add GPL code to the repository.

## 2. Asset list (names exact, from plan 7.7)

`PatchTrace-<ver>-windows-x64-full.zip` + `.sha256`; `PatchTrace-<ver>-linux-x86_64-full.tar.gz` + `.sha256`; `PatchTrace-<ver>-backend-windows-amd64.zip` + `.sha256` (importer ZIP); `ghidriff-4f5d895-source.tar.gz` + `.sha256`; `THIRD-PARTY.json` (Windows) and `THIRD-PARTY-linux.json`; existing lite assets unchanged. Any single asset above 1.9 GiB fails the build (`ASSET_LIMIT`); `--split` produces parts and `join_parts` documents rejoining (both build steps in `backend-bundle.yml` pass `--split`; how split parts are published is UNVERIFIED).

## 3. Automated acceptance (CI evidence)

All rows are produced by one `backend-bundle.yml` dispatch with `platforms=both` on the commit to be released. Record the run URL in `docs/qa.md`.

| Id | Check | Proof | Where it is evidenced |
|---|---|---|---|
| A1 | Pin file valid, no placeholder, licences approved | `python tools/check_backend_pin.py --release` exit 0 | job `pin-resolves-and-plan` |
| A2 | Windows full build produced and sidecars verify | `sha256sum -c` on both `.zip.sha256` | job `build-windows-full-bundle` |
| A3 | Windows acceptance | positive-control probe connects before firewall rules, fails after; tree digest of `backend/` equal before/after on a read-only tree extracted to a path with a space and a non-ASCII name; `backend verify --full` ok; `backend selftest --expect-function read_item` exit 0; zero non-loopback connections sampled | job `accept-windows-no-network-readonly`, artifact `acceptance-windows` |
| A4 | Linux full build and sidecars | `sha256sum -c` | job `build-linux-full-bundle` (blocked today by the Ghidriff tarball mismatch, handoff R1) |
| A5 | Linux acceptance on 22.04 and 24.04 | same as A3 with `unshare --net` | jobs `accept-linux-no-network-readonly (ubuntu-22.04|ubuntu-24.04)` |
| A6 | Licence completeness | every `THIRD-PARTY.json` component has licence files, Ghidriff `modified: false`, `process_boundary: separate-process`, `source.kind: in-bundle` | artifact `evidence-windows` / `evidence-linux` |
| A7 | Size recorded | sizes of each asset in the run summary | `docs/qa.md` row BUNDLE-5 |
| A8 | Unit and integration tests | the pytest list in `docs/handoff/backend-bundle.md` section 1, plus the Linux and Windows QA jobs of the PR | PR checks |

## 4. Windows alpha acceptance (owner-only, BLOCKED external until recorded)

Machine: a clean Windows 11 VM or PC (no Python, Java, Ghidra on PATH; Defender on), with the network adapter disabled for the offline part. Use the exact prerelease zip downloaded from the release page, not a CI artifact.

Steps and expected results (record pass/fail, Windows build number, date, zip SHA-256 in `docs/qa.md` row BUNDLE-7 and in the M-table of `windows-acceptance-and-milestone-builds.md`):

| Id | Step | Expected |
|---|---|---|
| W1 | `Get-FileHash <zip> -Algorithm SHA256` vs the `.sha256` sidecar and release notes | equal |
| W2 | Right-click zip, Properties, Unblock (or `Unblock-File`), extract to `%USERPROFILE%\Downloads\PatchTrace` (and once to a OneDrive-synced folder if available) | extraction completes; no path-length error |
| W3 | Record SmartScreen/Defender behaviour on double-click `PatchTrace.exe` (Edge download and `curl` download, per SPEC-52 gate) | behaviour noted; unsigned warning is expected and not a failure |
| W4 | M01 launch, then the rest of M02 to M18 from the milestone matrix, including DPI (M08 to M10), high contrast (M11), cancel (M14), close during analysis (M15), Unicode path (M18) | per that matrix |
| W5 | Disable the network adapter. Setup shows "Bundled runtime: ok (fast check)"; press "Verify bundle files" | verification finishes, Cancel leaves settings unchanged |
| W6 | Compare the owner's own old/new PE pair offline (or the repository pair `tests/fixtures/old.c`/`new.c` compiled with MSVC) | results appear; no network use; Task Manager shows no residual `java.exe` or Ghidriff process after finish or cancel |
| W7 | First start duration with Defender real-time scan on (first-run hash pass over about 40,000 files) | time recorded (research open question 6) |
| W8 | JPype `_jpype` import on a machine without the VC++ redistributable, if such a VM is available | works, or the failure is recorded (research open question 7) |
| W9 | Antivirus scan of the exact zip (VirusTotal only with the owner's upload consent, per the no-silent-upload rule) | result recorded |

## 5. Signing (owner application, not part of the alpha)

The alpha stays unsigned. Parallel owner task: apply to SignPath Foundation (or choose Azure Artifact Signing / OV certificate) per `docs/research/windows-signing-options.md` sections 7 and 11. Enable signing only after W4 has a recorded pass and SPEC-52 workflow steps exist (protected GitHub Environment `release-signing`, tag-only trigger, timestamp RFC 3161 SHA-256, sign `PatchTrace.exe` only, hash after signing). Never sign third-party DLLs. Record the provider decision as an owner decision; Claude workers do not apply on the owner's behalf.

## 6. Order of work to the first prerelease

1. Fix Linux tarball mismatch (handoff R1). 2. Green Windows build and acceptance (R2). 3. Green Linux build and acceptance (R3). 4. Dispatch with `publish_prerelease=true` (R5). 5. Verify assets (section 2 list, `gh release view <tag> --json isPrerelease,isDraft,assets`, sidecars). 6. Update docs (R6) with run links. 7. Hand W1 to W9 to the owner. 8. Final release only on explicit owner say-so (section 1, rule 3).

## 7. Definition of done for the Windows alpha

Automated: A1 to A3 and A8 green on one run for the release commit, prerelease published by the workflow, docs updated. External (reported separately): W1 to W9 recorded by the owner. The alpha is "usable" when both lists are complete; until W is recorded the notes say "owner clean-machine test pending".
