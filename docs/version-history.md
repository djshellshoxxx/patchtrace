# Version history

All releases so far are **prereleases** of `0.1.0` (tags `v0.1.0-beta.N`). The number N is the CI run counter, so it rises by more than one between tags and some numbers have no tag. No final release exists. Packages are unsigned. Sources: `git tag` subjects (dates are tag dates), `docs/plans/ledger-A.md`, `docs/qa.md`. Entries list what the tag's change set added, not a promise that every item was hands-on accepted; acceptance evidence is in `docs/qa.md`.

Only these tags carry published packages that were recorded in the ledgers: beta.8 (first), beta.101 and beta.103 (publication after a token problem, see qa.md), and beta.225 (Windows zip and Linux tar.gz with checksums). For other tags a package may exist only as a CI artifact.

## 2026-10-11 Foundation

| Tag | Added |
|---|---|
| beta.8 | First desktop beta: Qt workspace, project store, Ghidriff import and run, findings and review, reports, Windows zip |
| beta.13 | Fix for dot-prefixed Ghidra analysis paths |
| beta.21 | Isolated temporary Ghidra workspace; backend hardening notes |
| beta.29 | Ghidriff symbol-server lookups became explicit opt-in (off by default) |
| beta.36 | Safe local runtime discovery in Setup (read-only, bounded, nothing executed) |
| beta.62, beta.63 | CI permission probes only; no user-visible change |
| beta.70 | Fix for a cached-PDB error under `--no-symbols`; first Linux x86-64 build |
| beta.72 | Verified offline backend ZIP installer (importer side only; no official runtime ZIP) |
| beta.80 | Phase 2 enrichment: change signals, `attention/1` ranking, WIL feature flags, CVE context, derived cache, CLI verbs `rank flags correlate cache` |
| beta.82 | Full code audit and repairs; specifications; headless acquisition (Winbindex, symbol server) |
| beta.85 | Analysis profiles and raw-output cache |

## 2026-10-12 Multi-build and second opinions

| Tag | Added |
|---|---|
| beta.90 | N-way series (3 to 8 builds), acquisition dialog, BinDiff import and rz-diff secondary engines |
| beta.95 to beta.97 | Planning: Ghidra semantic tracing roadmap, cross-engine evidence and calibration design, CSAF and three-tool intelligence specification |
| beta.98 | Dedicated feature-audit agent (process change only) |

## 2026-10-13 Alpha inspection

| Tag | Added |
|---|---|
| beta.101 | Atomic offline-bundle publication fix |
| beta.103 | Better diff navigation; GUI inspection requirements |
| beta.109 | Handoff and CI triage notes |
| beta.110 | Preliminary file overview that works without any analysis backend |
| beta.112 | Verified bounded artifact byte reader |
| beta.116, beta.117 | PE overview (section map, comparison, Authenticode probe); Hex, Binary and Base64 raw views |
| beta.118 | Semantic tooltip registry across the GUI |
| beta.120 | PE comparison, raw views and Authenticode row in File overview |
| beta.127 | Hardened PE row tooltips |
| beta.129 | rz-diff stdout and stderr captured separately so diagnostics cannot corrupt JSON |
| beta.131 | Byte-level download progress for acquisition |
| beta.142 | Phase C specifications and decisions; inspection thread teardown fix |

## 2026-10-14 Evidence engines, specs and unified engine

| Tag | Added |
|---|---|
| beta.144 | Engine scheduler and runs registry (SPEC-28); one-set-per-engine reconcile fix; enrichment hardening |
| beta.146 | Series window; core hardening; live rizin and frozen-app smoke CI |
| beta.148 | SPEC-28 leftovers (alternatives, per-outcome persistence); Windows acceptance automation |
| beta.158, beta.162, beta.163 | Specifications only: QBinDiff-inspired matcher, radiff2-inspired comparison |
| beta.167 | Engine evidence panel, BinDiff execution, calibration tooling, second audit fixes |
| beta.176 | BinExport2 support, real BinDiff 8 run, CI runtime guards, unified-engine specification |
| beta.177 | Research and plan for optional Diaphora engine (docs only) |
| beta.202 | Phase D wave 0: CSAF core, capa, FLOSS and Detect It Easy adapters, BinDiff GUI setup, unified contracts, known-answer corpus |
| beta.211 | Optional dependency extras, KB correlation contracts and fixtures |
| beta.220 | KB phase 1, intel-tools runner, store, CLI and provisioning, FLOSS fixes |
| beta.222 | Program E plans and specs; unified pass ladder; Pages site tooling |
| beta.225 | Unified engine (registry, adapters, fusion, pipeline, `unified` CLI, Ghidra extractor); CSAF reports and `intelligence` CLI. Windows zip 60,640,443 bytes, sha256 `05138b1fe480361d1b6d812de76635c6ae9cf39931e5a5da07f178449e191473`; Linux tar.gz 89,535,839 bytes, sha256 `2fdb5ece075b63c32c9ec9d673d9f4171c5fd3fb8b201d526736f068956f15ae` (ledger A). CI: Windows pytest 4884 passed, Linux 4891 passed, frozen and Linux smoke on Ubuntu 22.04 and 24.04 |

## After beta.225 (merged, not yet in a tag)

Merged on the main line by 2026-10-14, from the ledger and git history: the zero-download backend bundle builder, discovery, `backend` CLI, acceptance harness and workflow (PR #48, not yet built into a published package); release gate, CLI command registry and GUI foundation (PR #52); SPEC-41 to SPEC-45 drafts (AI provider, network egress and privacy, settings, CLI umbrella, accessibility). More work is on integration branches awaiting merge.

## Open items before a final release

- A full bundle package must be built, published and accepted on a disconnected machine; some pins are unresolved.
- Windows desktop acceptance (DPI, screen readers) is not done.
- No calibrated confidence exists; none is shown.
- Packages are unsigned.
