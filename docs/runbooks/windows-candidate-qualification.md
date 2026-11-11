# Clean Windows candidate qualification

Use the exact candidate commit, downloadable Actions artifact or prerelease URL, and
independently recorded archive SHA-256. Keep each attempt in a new evidence directory.
Do not begin exploratory testing before the package is downloadable. Desktop ZIPs
include Python and Qt; Ghidra, Java and Ghidriff remain external unless an explicitly
qualified full offline bundle supplies them. No result below was run on Windows by
the Linux development session that added this checklist.

1. Record candidate commit, build/run URL, download URL, archive byte count and
   SHA-256 before extraction. Compare against both the run evidence and sidecar.
   Preserve raw logs from every failed attempt; never reuse an evidence directory.
2. With a source-bound development Python, run
   `python tools/check_windows_package.py ARCHIVE --sha256 DIGEST --commit SHA --label LABEL`.
   Save its one JSON document and exit code. This read-only preflight may run on
   Linux; `verified-structure` does not satisfy any Windows execution gate.
3. On Windows, run the existing `tools/build_windows.py` pipeline when building the
   candidate, `tools/check_windows_exe.py` for embedded resource identity, and
   `tools/frozen_smoke.py` against the downloaded/extracted candidate. Retain the
   Windows/Python/PyInstaller versions and command, stdout, stderr and exit for each.
   A Linux PyInstaller build cannot substitute for this step.
4. Run `tools/test_windows_portable.ps1 -Archive ARCHIVE` on Windows, outside the
   checkout. It checks the archive hash, Unicode/spaces extraction, replaceable Qt
   Windows plugin, dependency manifest/notices, frozen self-test and CLI startup.
   Run the existing installer smoke separately; record its Setup.exe digest and
   verify user project retention during uninstall. Source Python tests are not
   evidence that the frozen package works.
5. In a clean Windows 11 x64 profile, record OS build, filesystem, Defender state,
   absence of developer runtimes, display scale and tester. Follow M01–M18 and the
   automated A-gates in the [acceptance specification](../specs/windows-acceptance-and-milestone-builds.md).
   Include 100/150/200% DPI, keyboard-only investigation, Narrator/NVDA, cancellation,
   reopen/recovery and file-lock failure behavior. Keep unavailable checks `not-run`.
6. Offline acceptance uses the existing [backend-bundle runbook](backend-bundle.md):
   verify pinned component digests, licenses/approvals, backend inventory and exact
   launcher identity; move the complete downloadable package to a disconnected clean
   Windows machine and run real analysis on permitted authored inputs. Record network
   disconnection and actual native outputs. A mocked backend, desktop-only ZIP or
   successful bundle parser does not qualify disconnected analysis.

Copy this evidence skeleton for each candidate; replace values only from observations:

```json
{
  "candidate_commit": "REQUIRED_EXACT_SHA",
  "build_run_url": "REQUIRED_URL",
  "artifact_download_url": "REQUIRED_URL",
  "archive_sha256": "REQUIRED_DIGEST",
  "archive_bytes": null,
  "windows_build": null,
  "tester": null,
  "checks": {
    "archive_preflight": {"status": "not-run", "evidence": []},
    "windows_resource_identity": {"status": "not-run", "evidence": []},
    "frozen_smoke": {"status": "not-run", "evidence": []},
    "portable_extraction": {"status": "not-run", "evidence": []},
    "installer_retention": {"status": "not-run", "evidence": []},
    "native_analysis": {"status": "not-run", "evidence": []},
    "disconnected_full_bundle": {"status": "not-run", "evidence": []},
    "manual_M01_M18": {"status": "not-run", "evidence": []}
  }
}
```

Each evidence item should name a retained raw log or artifact, its SHA-256/byte count,
and the exact checked commit. Record failures alongside later successful retries.
Dependency manifest and license checks establish package contents; they do not
replace component licensing decisions or native compatibility evidence. This
runbook adds no workflow dispatch, release publication or gate bypass.
