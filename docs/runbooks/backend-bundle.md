# Backend bundle runbook

Scope: how a maintainer builds, verifies and publishes a prerelease of the zero-download backend bundle, and how a user installs it offline.

Sources: `tools/build_backend_bundle.py`, `tools/backend_pin.json`, `.github/workflows/backend-bundle.yml`, `docs/specs/program-e/BUNDLE-integration-plan.md`. Anything not stated in those files is marked **UNVERIFIED**.

## 1. Concepts

- `tools/backend_pin.json` pins every component (Python, Ghidra, JDK, wheels, ghidriff source tarball) by URL, size and SHA-256. Each digest names its `digest_source`.
- A component with status `placeholder` (SHA-256 `PLACEHOLDER-UNRESOLVED`) blocks release builds. `tools/check_backend_pin.py --release` and the build refuse placeholders.
- Platforms: `windows` and `linux` (the builder's `PLATFORMS`).
- Asset size gate: `ASSET_LIMIT` is 1.9 GiB, below GitHub's 2 GiB release-asset limit. `SIZE_WARN` is 1.2 GB (investigate before shipping).
- Release asset names (from the plan and workflow): `PatchTrace-<ver>-windows-x64-full.zip` (+ `.sha256`), `PatchTrace-<ver>-linux-x86_64-full.tar.gz` (+ `.sha256`), `PatchTrace-<ver>-backend-windows-amd64.zip` (+ `.sha256`), `ghidriff-4f5d895-source.tar.gz` (+ `.sha256`), `THIRD-PARTY.json`.

## 2. Build with the builder

The builder imports `patchtrace`, so put `src` on the import path. Without it the script fails with `ModuleNotFoundError: No module named 'patchtrace'` (observed).

Dry-run an extracted tree against the path policy (read-only):

```bash
PYTHONPATH=src python tools/build_backend_bundle.py check <extracted-tree> [--prefix ghidra|jdk|python] [--json] [--limit N]
```

Full build (needs network; downloads happen only here):

```bash
PYTHONPATH=src python tools/build_backend_bundle.py build --platform windows --out <new-or-empty-dir> [--cache-dir DIR] [--version VERSION] [--split] [--asset-limit BYTES] [--release] [--no-compile] [--json]
PYTHONPATH=src python tools/build_backend_bundle.py build --platform linux --out <new-or-empty-dir> [--cache-dir DIR] [--version VERSION] [--split] [--asset-limit BYTES] [--release] [--no-compile] [--json]
```

- `--out` must be a new or empty directory.
- `--pin` defaults to `tools/backend_pin.json`.
- `--split` splits the archive when it is above the asset limit.
- `--release` refuses while any `license_policy` component lacks owner approval.
- `--no-compile` skips bytecode precompilation.
- The builder's only subprocesses are its own `python -m pip` calls with `--no-index` (per the module docstring).

The builder writes the payload under `backend/payload/{python,ghidra,jdk,LICENSES,SOURCES}`, the importer ZIP, the ghidriff source tarball, notices and `THIRD-PARTY.json`. The exact output file list beyond the names in section 1 is **UNVERIFIED**.

Before a release build, resolve all placeholders in `tools/backend_pin.json`. Per the pin file, a placeholder is resolved only from a networked run, and it is marked `digest_source: tofu` when the vendor publishes no digest. Do not use `tofu` where a `vendor-file`, `vendor-listing`, `pypi-json` or `sigstore-verified` source exists.

## 3. Verify in CI (`backend-bundle.yml`)

Trigger: `workflow_dispatch`, release tags `v*`, or `workflow_call`.

Dispatch inputs (names from the workflow): `version`, `platforms` (`both`, `windows` or `linux`; default `both`), `publish_prerelease`, `pin_report_only`, `pin_verify`, `sigstore_identity`, `sigstore_issuer`, `gpg_fingerprint`.

Job order, from the workflow job names:

1. `pin-resolves-and-plan`: validates inputs, plans the tag, runs the pin release gate and prints a pin report (placeholders only, no build).
2. `pin-verify-signatures-and-rebuild`: installs `sigstore==4.5.0`, verifies pins with network access, writes `pin-verify.json`.
3. `build-windows-full-bundle` and `build-linux-full-bundle`: run the builder, then `tools/build_windows.py --full` on Windows. The Windows job runs the builder with `--split` and `--version "$VERSION"`.
4. Acceptance jobs, including `accept-windows-no-network-readonly`: verify the sidecar, extract to a hostile path and run acceptance with a firewall block and a positive control. The benign sample pair is compiled and never executed.

A tag push builds and runs acceptance but does not publish.

## 4. Publish a prerelease

Publishing happens only when `publish_prerelease` is true (or the dispatch input is set). The publish step:

- creates the tag as a prerelease with `gh release create <tag> --prerelease --target <sha>` if it does not exist;
- refuses to touch an existing release unless it is a published prerelease (`isPrerelease=true`, `isDraft=false`);
- uploads with `gh release upload <tag> release/* --clobber`;
- compares remote asset names with the local `release/` listing.

Manual tag form when the tag is not a release tag: `v<version>-bundle.<run number>` (from the workflow).

The job needs `contents: write` on the token. If it lacks that permission, the step fails and nothing is published. Acceptance evidence is attached to the workflow run, not to the release.

## 5. Install offline (user side)

Full bundle, per the plan:

1. Download the full ZIP (or tar.gz on Linux) and its `.sha256`, and verify the checksum with your own tool.
2. Extract the release artifact (not `dist/`) to a folder. The bundle `backend/` sits next to the executable.
3. Check the bundle with the backend CLI. The verb names in the plan are `patchtrace backend status` and `patchtrace backend verify [--full]`, with `--bundle-dir DIR` and `--work-dir DIR`. **UNVERIFIED** against the CLI entry point; the verb names are not in the four named sources.
4. Per-user writable data goes to `%LOCALAPPDATA%\PatchTrace\work` (Windows) or `~/.local/state/patchtrace/work` (Linux), per the plan.

The plan states that `backend/` is read-only at install and that analysis must not write into it. The exact procedure for the SPEC-06 importer ZIP (Setup dialog, "Install offline backend ZIP…") is **UNVERIFIED** here.

The SHA-256 sidecar is a self-consistency check. It is not an independent publisher signature (plan, Risks: "Self-consistent bundle is not authentic"). Signing is a separate WIN track.

## 6. Open gates

- Placeholders in `tools/backend_pin.json`: the pin file records resolved Windows Python and Ghidra digests, but some entries carry notes dated 2026-10-14/15. Re-check the file before any release build.
- `ghidra-GPL-dir` is not owner-approved and is stripped (`GPL/**`). Non-PE GNU demangling is lost.
- Temurin JDK 21 is owner-approved for shipping (recorded in the pin file). JDK 25 is the fallback only after a failing acceptance.
- Live acceptance on both OS is not claimed by this runbook. Check the run links in the workflow evidence before reporting any result.
