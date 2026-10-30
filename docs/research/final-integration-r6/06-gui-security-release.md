# 06 — Unified Qt workflow, persistence resilience, security audit and Windows release

**Scope:** existing Qt MainWindow, project service/persistence, adversarial PE/SQLite/network handling, native Windows 11 x64 release. Source: `AGENTS.md`, `SECURITY.md`, `docs/specs/{ui,gui-framework,windows-acceptance-and-milestone-builds,report-export-contract-v2,network-egress-privacy}.md`, current `ui*.py`, `verified_backup.py`, `backend.py`, release workflows. **Release label at 2026-10-30: NOT READY**, even though a Windows prerelease exists.

## 1. Canonical analyst workflow, with no competing windows

Expected single-window user journey and state transitions:

```text
New project / Open project
  -> Select valid older and newer PE x64 OR choose verified acquisition pair
  -> Check SHA, provenance, PE/metadata and dependency readiness
  -> Select primary/secondary sources and limits
  -> Run / Cancel / Re-run (child process; GUI stays responsive)
  -> Review primary matches / unified L1 correspondence and ambiguity
  -> Inspect paired code, raw bytes, metadata, function callgraph and deltas
  -> Inspect source atoms, proof rule, evidence limits and source conflicts
  -> Search CVE/KB -> product scope -> verified candidate file/version
  -> Link approved source and binary pair to existing run
  -> Rank attention, inspect alternatives, correct correspondences, add notes
  -> Save, close and reopen history
  -> Export reproducible JSON/Markdown/other supported reports
```

The existing `MainWindow` is authoritative. `unified/read_model.py` and `ui_unified.py` should be views over immutable results; `secondary/evidence_panel.py`, `kbcorrelation/panel_qt.py` and existing report UI supply cross-navigation. A view switch Primary/Unified and one evidence dock or existing panel tab is preferable to separate per-engine windows. No duplicated project store or Qt-thread-outside SQLite connection.

**State contract:**
- `no-project`: safe startup, nothing downloaded, correct visible dependency state.
- `project-ready`: input SHA and PE metadata accessible without Ghidra, provenance orientation clear.
- `analysis-pending/running`: immutable request, progress and job ID; cancel available; previous committed result still visible.
- `completed`: load verified pointers, exact raw/native results, function correspondence + semantic facts, alternatives/unknowns and source update age.
- `failed/cancelled/unsupported`: typed status and recovery steps, no “analysis complete” chip, no partial result falsely promoted.
- `stale/corrupted`: report invalid sidecar/cache and offer safe revalidation/rebuild, preserving original run/notes.
- `offline`: all open/search/export operations local; explicit consent preview required for source update or acquisition.

## 2. Essential UI panels and acceptance obligations

| Surface | Required content | Acceptance regression |
|---|---|---|
| Project/source chooser | Name/path, exact older/newer SHA and arch, approved file/fix boundary and data-origin status | Invalid PE or identical/foreign SHA rejected with clear message; no unintentional directory mutation |
| Setup/preflight | Ghidriff/Ghidra/JDK version, BinExport2 producer, BinDiff/rz-diff status and installation paths; offline mode | Unconfigured/licensed tool explicitly unsupported; UI does not offer fake success |
| Run/progress | Per-stage progress, real worker cancellation, elapsed/resource status, persisted error code and source run ID | GUI event loop remains live and descendant processes terminate on cancel/close |
| Unified function list | L1 decision (matched/tentative/contested/ambiguous/one-sided/unknown), tier, source class and evidence availability | 10k/100k rows virtualized, sorting/filter deterministic; no auto-hide of weak conflicts |
| Paired code and raw views | True Ghidra code/decompiler source, bytes, RVA/image base, side identity, missing-data reason | Mismatched RVA or unavailable code must not fabricate disassembly or show the other side's code |
| Semantic detail | C0–C8 channel states, typed operand/control/data deltas, EH-EQ, DATA-MAP, named L2 proof/MAT-ANCHOR, caps, unknown | `COS-PSEUDO/1` remains reviewable; changed-target negative cases never grouped benign |
| Source evidence | Ghidriff, BinDiff, rz-diff and manual atom source/version/independence, raw scores as raw | B+B proof shows two independent class/component witnesses; native scores not labeled “confidence %” |
| CVE/KB search | Exact source authority/coverage/revision, product/build scope, contradictions, candidate vs verified pair | No source data shows “not observed in checked scope,” not no-CVE; source-linked drill-down |
| Ranking/findings | WIL/attention lead and why, analyst-vetted explanation separated from observed data | Changed non-attributed functions visible; rank is not a causal or exploited verdict |
| Notes/corrections | Reviewer, timestamp, original/corrected match, reversible history and scope | Source run immutable; correction reflected in new derived result without lost notes |
| History/export | Old run list, source SHA and manifest, JSON/Markdown evidence chain with exclusions | Close/reopen stable; export identical aggregate with input digests and exact limitation list |

**Accessibility and Windows platform:** test 100%, 150% and 200% DPI; resize to 800×600 and full screen; dock/splitter saved/restored, high contrast and dark/light theme; Tab/focus order/F6, screen-reader descriptive accessible names/NVDA/Narrator; keyboard-only navigation including search and reports. Huge results must not block UI thread. Disabled controls need actionable plain-language reasons. A test screenshot may show correct layout but **not** prove screen-reader semantics; have an actual human or accessibility harness verify.

**Hostile strings:** project names, PE metadata, decompiler/assembly, CVE advisory text, error stderr and imported source labels are hostile input. Render as plain text/escaped Markdown, not arbitrary HTML. Avoid executing hyperlinks, embedding remote images, shell/interpreter markup or prompting an AI model to follow source text instructions.

## 3. Project and persistence reliability design

Main `src/patchtrace/persistence.py` and `verified_backup.py` already implement typed project snapshots, historical data and verification; test their failure boundaries rather than replace them. Preserve a clean distinction between original `ComparisonProject`, imported raw secondary data, derived unified sidecars, contextual KB source snapshots, analyst corrections, and transient scratch or cache. A cache may be deleted; committed evidence must remain valid or explicitly damaged.

**Failure scenarios to exercise in real isolated projects:**
- restart immediately after successful analyze/persist; same SHA, match counts, history and notes;
- kill child mid-Ghidra extraction or during BinDiff SQLite output; old project and completed original run untouched;
- cancel at each stage (download, native delta, Ghidra, normalized matching, decompile, export) without zombie descendants;
- tamper derived sidecar or raw PE after ingestion; detect mismatched hashes and refuse stale results;
- intentionally corrupt temporary export/SQLite import; reject with bounded resources, never promote a half-written `.BinDiff`;
- stale cache/policy update/engine version change; recompute derived result with provenance, do not alter original run;
- migrations and old-project reader: additive schema, verified backup, actual rollback, original file recoverable;
- application termination while Qt DB writer holds transaction; journal recoverable, backup present;
- file-system lock, low disk, antivirus scan, OneDrive sync path, Unicode/trailing dot/reserved Windows file name and long path; actionable error, no half-write;
- project backup and restore on clean profile; hashes for original PE, run and notes unchanged;
- repeated same project creation and analysis idempotent or explicit no-op, never silent overwrite.

**Verified data-durability audit candidate — prioritize before destructive pruning:** `verified_backup.py::_fingerprint` on current main caches based only on file `(size, mtime_ns)`; `trusted_backup` can reuse a cached “good” verdict. Audit [#121](https://github.com/djshellshoxxx/patchtrace/issues/121) notes that tampering a backup in place while restoring size/mtime may retain the cached trust verdict before `persistence.py` discards history. Reproduction must mutate valid SQLite pages to invalid but same-length bytes, restore mtime with `os.utime`, test both `trusted_backup` and destructive prune path, on Windows/NTFS and Linux. A fix should perform robust content validation/digest recheck (particularly before any irreversible prune) with race-safe file-identity handling. Merely using a stronger timestamp without validating content is not a universal corruption guarantee. Preserve the pre-fix failing test and release-visible backup status.

## 4. Security threat model: target files are hostile data

**Adversary-controlled surfaces:** PE headers/sections/imports/dwarf/pdb hints; direct and indirect relative references; ZIP, CAB/delta and download paths; Protobuf BinExport2; SQLite BinDiff/Diaphora/project files; user-entered source URLs and redirects; GitHub/MSRC/NVD/CSAF metadata; advisory/decompiler strings; local file paths; environment variables and subprocess configuration. **Protected assets:** analyst workstation and credentials, source binaries/private PDBs, original project evidence, network privacy, toolchain integrity, reliable Windows package.

| Category | Existing boundary / observed concern | Test + required mitigation |
|---|---|---|
| Binary ingestion | PE validity, AMD64 type, file size, image layout, non-execution | Malformed DOS/NT headers, section overlap, RVA overflow, huge exports/imports, unexpected data directories, wrong machine; no process ever runs the target |
| Protobuf | `binexport_prescan`, upb parser/worker and bounded deserializer | Huge nesting/unknown groups, amplification, invalid indices, duplicate function addresses; fail within measured CPU/RSS limit; no pure-Python parser fallback |
| SQLite imports | strict `.BinDiff` read-only schema and `diaphora/sqlite_guard.py` | Malicious tables/triggers/virtual tables, huge rows, hot journal, time bomb; use read-only defensive mode, fixed total deadline and bounded worker; audit old issue #121 for current state |
| Subprocess | `jobs.run_process` Windows Job Object / POSIX process group, private cwd | Cancellation, dead children/grandchildren, timeouts, log bounds and no shell command injection; test real Windows kill-on-close |
| Child environment | **Live main `backend.BackendConfig.restrict_env=False`** and default `os.environ.copy()` path | Seed `GH_TOKEN`, `NVD_API_KEY`, proxy vars in parent and assert external Ghidriff/Ghidra child does not receive them in offline default. Consider restricted-by-default migration with compatibility tests |
| Network | Consent-scoped source plan, offline search and local-only analysis | Socket audit on open/search/run/export; refuse redirected new host, stale/surprising content, keys from env; no silent symbols or AI uploads |
| Archive/delta | Quarantine, safe extraction, hash and PE guard | Symlink/hardlink/`../` and absolute extraction, ZIP bomb, MSDelta wrong base/CRC/memory, cancel, no partially promoted file |
| Signer/catalog | SHA vs Authenticode/catalog/trust/revocation separate | Embedded and catalog-signed PE, untrusted, missing, revoked/expired and offline verification, never “Microsoft signed” based solely on source host |
| Evidence DB/backups | Versioned, atomic store, verified backup guard | Same-size/mtime backup tamper, thread-bound SQLite, interrupted migration/commit, malformed imported rows |
| Reports/GUI | Plain-text hostile strings, bounded Markdown/JSON, no remote assets | HTML/script/Markdown escape, format string, newlines/control characters, path/URL information leak |
| Optional AI | Explanation only, untrusted advice/source content and explicit network consent | Prompt-injection in advisory/code comments cannot change match/KB or run commands; no implicit provider call or private code upload |
| Dependency supply chain | Pinned Ghidra/JDK/Ghidriff/BinExport/BinDiff, license notices and manifest | Verify archive/file SHA, upstream release authenticity/signature where available, fail on placeholder/unknown; SBOM and reproducible artifact list |

Security findings above vary in confidence: backend default environment inheritance and backup fingerprint are **source-observed**; exploitability and actual attack preconditions require reproductions. Do not assign an external vulnerability severity or claim an exploit occurred from static inspection alone. Protect proprietary Windows PEs/PDBs and internal paths in CI artifacts and public reports.

## 5. Exact child-environment hardening slice

Main `backend.py` has a `restrict_env` option but currently defaults **false** for external mode; bundle mode is separately restricted. Since external Python/Ghidriff/JVM may inherit parent secrets, implement using TDD:
1. Red tests: seed mock `GH_TOKEN=NOCONNECT`, `NVD_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `HTTPS_PROXY`, `PYTHONPATH`; make a child print safe *presence flags only*, no secret content. Verify offline default does not inherit credentials, network proxy or Python injection.
2. Enumerate necessary platform PATH/TEMP/SystemRoot/USERPROFILE, locale and Java/Ghidra variables for Windows/Unix. Vendor-specific vars must be an explicit user opt-in and recorded as a capability condition.
3. Change default to restricted allowlist with a documented compatibility switch for trusted custom runtimes only; ensure bundle and normal external mode agree on symbol-server consent.
4. Repeat native Ghidriff Windows and Linux, frozen EXE in fresh profile, offline socket-audit and existing symbols-disabled pipeline. Record legitimate prior environment dependence and migration notes.
5. Never log secret values, full contents of external environment or user code in diagnostic records.

This is an engineering proposal; do not claim the default was corrected until regression and CI prove it.

## 6. Windows standalone release: what exists and what R6 still needs

The actual 2026-10-29 [v0.1.0-beta.543](https://github.com/djshellshoxxx/patchtrace/releases/tag/v0.1.0-beta.543) includes Windows portable ZIP and NSIS installer, plus Linux archive and checksum files. Main's [QA workflow 41060959610](https://github.com/djshellshoxxx/patchtrace/actions/runs/41060959610) completed successfully with Windows portable/installer smoke; **there is no published R6 release from current main**. This is an integration beta, not an accepted complete Windows reverse-engineering workflow.

**Live release job:** `.github/workflows/qa-windows.yml` on main has `needs: [qa, qt-gate, linux-smoke, release-gate]`. This repairs an older audit issue which claimed Qt-gate was omitted; it does **not** hard-gate all native extraction/secondary engine/unified corpus/real KB acceptance workflows to the same SHA. An advisory `unified-live-gates.yml` can be overall green with failed/blocked child jobs. Define an explicit required **R6 aggregator** that consumes exact run/artifact status for real native and G-U coverage, and fail closed on missing/failed/blocked mandatory evidence. Preserve existing beta cadence for development, but distinguish public beta from a specifically release-ready/accepted tag.

**Portable vs installer:** test both from release assets, not just from local `dist/`. Frozen PyInstaller should have full Qt dependencies, private worker entrypoint, extractor script exactly once, schema/notices; it should not assume developer Python is installed. NSIS per-user Setup must install under Unicode/space path, register Start Menu/app entry, uninstaller, and leave user-created project data intact. Test checksum of exact binary as downloaded, and compare release SHA to Actions produced asset.

**Backend installer/offline bundle:** `tools/backend_pin.json` includes Ghidra 12.0.4, Temurin JDK 21, Python 3.12.10 embed and pinned Ghidriff revision/pyghidra. This is not automatically in the 64 MB standalone desktop ZIP. Provide accurate documentation: “desktop GUI runs without an analysis backend; real native comparisons require a separately configured local Ghidra/Java/Ghidriff or a separately verified offline bundle if provided.” For a truly offline acceptance test, transfer/install approved tool archives in a disconnected VM, verify pin manifests and licences, configure local paths, run the known pair without network and capture process+socket evidence. No official claim of fully air-gapped analysis until that exact test passes.

**Signing:** prerelease assets are **unsigned** per `docs/release-process.md`. SHA-256 verifies file integrity relative to the published trusted digest; it does not establish an authenticated publisher identity. A future code-signing process must keep keys outside PR/developer sessions and be separately authorized. Do not silently sign, deploy or publish as a release-ready alpha.

## 7. Clean Windows 11 x64 acceptance matrix

| ID | Operator action / environment | Pass condition |
|---|---|---|
| W-01 | Fresh local Windows 11 x64 user, Python/Ghidra absent, extract portable ZIP and launch | Qt app opens; version/portable checksum correct; missing tool shown, no crash |
| W-02 | Same clean profile, install Setup in Unicode/space path | Start Menu/Apps entry, frozen CLI/self-test and clean uninstall preserving project data |
| W-03 | DPI 100/150/200%, high contrast, 800×600, maximized, keyboard | Main panes accessible, no hidden critical control, Qt responsive, NVDA/Narrator labels and focus |
| W-04 | New x64 project with approved PE pair under spaced/Unicode/OneDrive-style folder | SHA/PE overview, raw hex and metadata available offline, save/reopen |
| W-05 | Configure approved pinned Ghidra/Java/Ghidriff externally | Native x64 analysis produces real run, GZF/IR and full unified read model |
| W-06 | Native optional BinExport2/BinDiff/rz-diff where installed | Proper capability, raw input/output hash, source and conflict, missing tool handled |
| W-07 | Search exact CVE/KB against local permitted source snapshot | Scoped results, incomplete coverage and candidate/verified distinction, zero network |
| W-08 | Correct function match and write notes; restart | Original source run hash preserved, notes/history attached and correct derived result |
| W-09 | Export JSON/Markdown and inspect malicious text fixture | All input/provenance/proofs/limits included; safe escaping; exported file hash verified |
| W-10 | Cancel and close while Ghidra or BinDiff runs | No residual Java/Python/child after specified deadline; persisted valid run intact |
| W-11 | Offline VM with local runtime package but NIC disconnected | Full known pair analysis completes without network or silent vendor service |
| W-12 | Bad/locked project, malformed PE, invalid BinExport, corrupt sidecar | Clear error, bounded work, no data loss or incorrectly completed status |
| W-13 | Program from published ZIP and installed Setup on two machines | Same accepted side/result hashes and deterministic semantic outcomes |
| W-14 | Verify released asset ZIP/Setup after download, compare build artifact | Exact same SHA as published, target commit and release notes truthful; license/manifest present |

Record each as **PASS/FAIL/BLOCKED/NOT RUN** with tester, `winver`/OS build, date UTC, current commit/ref, release asset SHA, toolchain, PE hashes, steps, screenshot/event log/reference, actual result. Do not default a manual QA checklist to “pass”.

## 8. Packaging verification commands (operator, not run here)

```powershell
# Replace these paths/names after downloading the actual release.
$zip = 'PatchTrace-0.1.0-windows-x64.zip'
$sidecar = "$zip.sha256"
$expected = (Get-Content $sidecar -Raw).Trim().Split(' ')[0].ToLowerInvariant()
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "ZIP digest mismatch" }
Expand-Archive $zip -DestinationPath .\r6-extract -Force
Get-ChildItem .\r6-extract -Recurse -Filter 'PatchTrace.exe'
# Then run the built-in self-test/help from the actual discovered frozen executable.
# Validate installed runtime and native Ghidriff separately (not inferred from self-test).
```

For final R6 handoff attach exported licence inventory, Windows release manifest and hashes, shell/Qt/raw backend logs (scrubbed), and proof that no private internal PE/PDB data was published.

## 9. Release decisions and blockers

**READY:** all essential native and scenarios A–J (including W-11 offline and W-14 published package) pass, real CVE/KB/source-paired case works, G-U and security/recovery gates accepted and no P0/P1 blocking defect.

**CONDITIONALLY READY:** accepted essential workflow and all required security/native gates pass, with expressly noncritical optional BinDiff/AI or UI limitations documented; no misleading claim that unsupported optional tool is included. If an explicitly required essential native engine is unavailable, this label is **not** available.

**NOT READY (current):** real unified corpus gates have zero measured outcomes; real MSRC CVRF compatibility/pair evidence missing; R5 not accepted; full clean Windows search→analysis→reopen→export and offline runtime acceptance absent; backup/env findings require exact test/repair; no R6 release artifact published at audited SHA.

Do not trade accuracy or protectable project data for a green CI badge. Every release readiness decision must link the exact passing evidence and list unsupported/blocked functionality.
