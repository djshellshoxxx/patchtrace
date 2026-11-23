# Release qualification and authorization

**Decision: hold release.** Main `ea16019601486c831941f9bc1a7ba5862a170317` passed its desktop QA. These receipts qualify that source. The documentation candidate `259ada8634e5cebf80632f83320902c21e22e464` has focused local verification only. Apply all release decisions to the final combined candidate.

| Gate | Evidence on main | Required before closure |
|---|---|---|
| Full regression and Qt | Run 44919714193. Ubuntu logged 24,336 passed, 53 skipped, 4 expected failures. Windows logged 24,205 passed, 185 skipped, 3 expected failures. Five Qt jobs passed. | Review skipped/expected cases by release criterion and bind new runs to the final commit SHA. |
| Windows artifact, Linux package | Windows validation job 136910859852 verified the downloaded ZIP and installer, clean extraction, Qt/frozen smoke, install and non-destructive uninstall. Linux smoke passed on Ubuntu 22.04 and 24.04. | Record the digest of each final asset, clean-machine install, pristine user profile, manual accessibility evidence and support boundary. |
| Backend compatibility | Native Ghidriff passed on hosted Windows. BinDiff passed on hosted Linux and explicitly recorded a network-behavior block on Windows despite green Actions status. | Attach the supported adapter/OS receipts, including blocked or missing rows in the feature matrix. |
| Full offline runtime | The pin check passed. The newest inspected published prerelease, beta.1035, targets `1836eb120571bb3c3a09fd3014447498621e2103`. Its eight assets cover desktop packages and SHA-256 sidecars only. | Identify the complete archive by digest, validate actual payload/notice inventory, verify installation without elevation, third-party runtime startup, replacement, rollback and disconnected use. Record isolation controls and untouched global settings. |
| Project data | Local focused CLI, GUI adoption, history-bound, backup-sidecar and report/backup tests passed. | Run preservation and historic schema acceptance on the combined source, including interruption and restore. |
| Documentation and licensing | Developer packaging guide candidate now matches current installer, extras, Windows Python pin and release controls. Pin metadata includes project owner-approved Ghidriff and JDK exceptions. | Verify actual notices, SBOM, pinned dependency closure and source obligations for the distributed bytes. Retain license records and complete corresponding-source evidence. |
| Source reconciliation and review | Repository has historical per-scope ledgers. A new census and local implementation candidates exist. | Attach the current exhaustive ledger, review source-equivalent and unique changes, and document remaining blockers. Independent reviewer must qualify the assembled candidate. |
| Authorization | Main QA's release job was skipped. Focused work has no publication receipt. | Verify head, required CI and reviews. Record owner authorization for tags or releases separately from integration and deployment. |

### Current artifact identities

| Baseline artifact | Hosted SHA-256 from downloaded-artifact verification |
|---|---|
| PatchTrace-0.1.0-windows-x64.zip | `ab6e6d5c0a7b4feed004118ec7ab2294fcdc0e2c1e8131f3ad9157600bf596d1` |
| PatchTrace-Windows-x64-Setup.exe | `c7b3ffd7063c5662de8c0f9d6f3bfb2aa975ca96ffc5e6ab254a07e73015739a` |

### Build and validation entry points

Use the repository’s [Windows build and artifact procedure](https://github.com/djshellshoxxx/PatchTrace/blob/ea16019601486c831941f9bc1a7ba5862a170317/docs/windows.md), [Linux build and smoke procedure](https://github.com/djshellshoxxx/PatchTrace/blob/ea16019601486c831941f9bc1a7ba5862a170317/docs/linux.md), and [release process](https://github.com/djshellshoxxx/PatchTrace/blob/ea16019601486c831941f9bc1a7ba5862a170317/docs/release-process.md). The platform sources identify build commands, compiler and runtime requirements, frozen binary checks and expected outputs. The developer documentation amendment describes the unsigned per-user NSIS installer alongside the portable ZIP. Hosted build evidence establishes the recorded outputs for that run. Independent byte-for-byte rebuild evidence was not obtained in this review.
