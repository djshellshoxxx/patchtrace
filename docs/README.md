# PatchTrace documentation index

PatchTrace compares two builds of a Windows x64 binary and helps you find what a patch changed. It never executes the binaries it inspects, sends nothing without your explicit consent, and works offline by default. Features that are not built yet are marked "planned" in these pages.

## Start here (user documents)

| Document | What it covers |
|---|---|
| [install.md](install.md) | Windows zip and Linux tar.gz, bundled versus external Ghidra/Java/Python, offline use, verifying downloads, uninstall |
| [RUN.md](RUN.md) | First-run walkthrough (GUI and CLI), project files, where data lives |
| [user-guide.md](user-guide.md) | Task guide: compare two builds, read evidence, CVE context, exports, privacy settings, troubleshooting, FAQ |
| [concepts.md](concepts.md) | Pair, match, evidence, attention, calibration, tiers, and what a result does and does not mean |
| [version-history.md](version-history.md) | What each prerelease added |
| [../README.md](../README.md) | Project overview, GUI control reference and upstream comparison |

## Platform and runtime notes

| Document | What it covers |
|---|---|
| [windows.md](windows.md) | Windows setup, source build, clean-machine QA procedure |
| [linux.md](linux.md) | Linux x86-64 package and Qt host libraries |
| [offline-backend.md](offline-backend.md) | Offline backend ZIP: install procedure and maintainer assembly |
| [notices.md](notices.md) | Third-party notices |

## Engineering references

| Document | What it covers |
|---|---|
| [modules.md](modules.md) | Module map |
| [qa.md](qa.md) | Recorded test and acceptance evidence |
| [cli-reference.md](cli-reference.md) | Every CLI verb and sub-verb with flags, exit codes and an example |
| [specs/REGISTRY.md](specs/REGISTRY.md) | Index of all numbered specifications (SPEC-nn) |
| [specs/network-egress-privacy.md](specs/network-egress-privacy.md) | Every network use, its consent rule and caps |
| [plans/](plans/) | Plans, ledgers and handoffs |
| [audits/](audits/) | Audit reports |
| [research.md](research.md), [reuse-matrix.md](reuse-matrix.md), [package-audit.md](package-audit.md) | Upstream research, reuse and licence decisions, packaging audit |
| [schemas/](schemas/) | Generated JSON schemas of persisted contracts |

## Product invariants

- PatchTrace never executes a target binary, driver or installer. It reads bytes and runs static analysis tools only.
- Nothing is uploaded silently. Each network operation needs its own consent naming the host.
- The default is offline.
- Unknown or missing evidence is not a negative vote.
- Scores order your reading list. They are not vulnerability confidence.
