# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub private vulnerability reporting on https://github.com/djshellshoxxx/patchtrace (Security tab, "Report a vulnerability"). Known gap: whether private reporting is enabled for the repository has not been verified. If the button is missing, open a minimal public issue asking for a private contact, without details. Include the version or tag, the platform and steps to reproduce; send only synthetic or public samples, never malware or proprietary binaries. There is no bug bounty and no guaranteed response time; PatchTrace is a prerelease.

## Supported versions

Only the latest prerelease is supported (tags `v0.1.0-beta.N`; see `docs/version-history.md`). No final release exists. Fixes land on the default branch and ship in the next prerelease; older tags are not patched.

## Trust model

PatchTrace analyses hostile input: Windows binaries, symbols, vendor advisories and model output are all untrusted.

- Targets are never executed. Downloaded files stay in quarantine; identification reads headers only, and only a verified AMD64 PE can become a project input through the normal ingestion path (`src/patchtrace/acquisition/quarantine.py`, `src/patchtrace/ingestion.py`, artifact cap 1 GiB). Analysis is static: Ghidra/Ghidriff and the optional engines run as separate child processes that read the file. Model-suggested commands are never executed (README).
- Hostile text is data. Advisory, string, symbol, code and model text is bounded and escaped before display or export; model output is schema-validated, citations are checked, and invalid output is kept as a failed attempt rather than accepted findings (`docs/specs/ai-provider-interpretation.md`). Stronger export escaping is planned, not built (`docs/specs/report-export-contract-v2.md`).
- Offline by default, no silent upload, no telemetry, credentials session-only. See `docs/privacy.md`, including its known gaps.
- Child processes: Ghidriff runs unmodified as a separate component. A restricted child environment is used in bundle mode or when enabled; with an external install and default settings the child inherits the parent environment (known gap, `docs/qa.md` [CONSENT]).

## Supply chain and verified downloads

- Pinned tools: `tools/backend_pin.json`, `tools/bindiff_pin.json` and `tools/intel_tools_pin.json` record URL, size and SHA-256 per component with the source of each digest. A pin without values is never downloaded (`tools/provision_*.py`). The bundle builder fails hard on a size or hash mismatch, accepts HTTPS only and keeps redirects on HTTPS (`tools/build_backend_bundle.py`). Known gap: some components in `tools/backend_pin.json` are still `PLACEHOLDER-UNRESOLVED`, so the offline runtime payload is incomplete (`docs/specs/offline-backend-installer.md`).
- Acquired builds are checked against the Winbindex size and SHA-256 before promotion.
- The offline bundle verifier checks every file by hash and rejects unsafe manifest paths (`src/patchtrace/offline_bundle.py`).
- Dependencies install with `pip --only-binary=:all:`. No GPL/AGPL code is copied; Ghidriff (GPL-3.0) stays a separate unmodified component. Microsoft binaries and PDBs are never committed.
- Release packages are unsigned prereleases; checksums were published for the beta.225 Windows and Linux packages (`docs/version-history.md`). A signing policy is only planned (`docs/specs/program-e/WIN-release-signing-policy.md`). Verify checksums yourself.

## Out of scope

Findings that require running a target binary, trusting a malicious Ghidra or Java installation you selected in Setup, or a compromised pinned upstream release are beyond what PatchTrace can defend against, although reports about missing verification are welcome.
