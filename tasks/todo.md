# PatchTrace delivery tracker
- [x] M1 Research, contracts, schemas, ingestion, normalization
- [x] M2 Backend and cancellation
- [x] M3 Persistence, service and desktop
- [x] M4 Context and optional providers
- [x] M5 Reports and diagnostics
- [x] M6 Code audit, automated QA, Windows standalone (release publication follows merge)
- [x] Live Ghidriff known-patch acceptance
- [ ] Live local and remote provider acceptance
- [ ] Clean Windows GUI acceptance
- [ ] Confirm dot-free quarantine fix with a real Ghidriff analysis from a Windows OneDrive-backed project and verify the rebuilt executable
- [ ] Confirm external Ghidra scratch/GZF isolation with Windows native fixture and a Windows OneDrive-backed user case
- [ ] Verify Windows real fixture under default `--no-symbols` and optional online-symbol mode; retain airgap verification as a separate system-network test
- [x] Cached-PDB `FileExistsError` under `--no-symbols`: per-run isolated Ghidra settings (PR #9). Native Windows CI 2026-10-12: plain Ghidriff reproduces; PatchTrace passes with persisted store (with/without PDB at embedded path) and clean. User clfs.sys binaries not supplied/tested.
- [x] Linux x86-64 onedir build (`tools/build_linux.py`, CI `linux-package`/`linux-smoke`); local offscreen + Xvfb self-test pass
- [ ] Verify live Ghidriff analysis from frozen Linux build
- [ ] Local-only symbol policy: needs PatchTrace-owned Ghidriff launcher (CLI cannot set empty symbol URLs)
- [x] Phase 2 B1-B4, storage, pipeline, CLI (rank/flags/correlate/cache), desktop Rank changes, report export (SPEC-07, PatchTrace-authored)
- [ ] Reconcile SPEC-07 with the supplied handoff package and validate its 9 valid / 9 invalid examples (package not supplied)
- [ ] Derived-cache hit objective 500 ms at 10,000 pairs (measured 3.1 s); UI responsiveness at 10,000 pairs unmeasured
- [x] Analysis profiles (SPEC-07 §12): Setup Profiles tab, CLI --profile, exports record profile
- [x] Raw Ghidriff output cache reuse (SPEC-07 §13), opt-in via profile cache_dir; native Windows hit verified (CI raw-cache-hit)
- [ ] Live NVD/MSRC fetch through the CLI recorded as a separate probe
- [x] Phase 3 contracts: SPEC-08 acquisition, SPEC-09 N-way, SPEC-10 BinExport/BinDiff, SPEC-11 rz-diff (tool research in docs/research/phase3)
- [x] 3a acquisition: headless + CLI + desktop dialog (live afd.sys probe matched); [ ] msdelta on Windows; [x] per-byte progress (Transport.download progress callback → desktop dialog bar; CLI unchanged)
- [x] 3b N-way series + CLI, unchanged hops from preserved address_matches; [ ] Series window; [ ] native three-build CI; [ ] per-hop attention
- [x] 3c/3d BinDiff import, rz-diff runner/parser, reconciliation, CLI; [ ] GUI reconciliation view; [ ] protobuf BinExport bindings; [x] separate stdout/stderr capture for rz-diff (`run_process(separate_streams=True)`, bounded per stream; Windows CreatePipe path covered only by CI, no native rizin run); [ ] live BinDiff/rizin runs (SPEC-28 C2 workflow still open)
- [x] 3b N-way series + CLI, unchanged hops from preserved address_matches; [x] Series window (read-only, SPEC-09b; offscreen tests, no manual DPI pass yet); [x] per-hop attention from stored default-profile ranking; [ ] native three-build CI/frozen-EXE smoke of the window; [ ] Open-pair live-project (locked) path
- [x] 3c/3d BinDiff import, rz-diff runner/parser, reconciliation, CLI; [ ] GUI reconciliation view; [ ] protobuf BinExport bindings; [x] separate stdout/stderr capture for rz-diff (`run_process(separate_streams=True)`, bounded per stream; Windows CreatePipe path covered only by CI, no native rizin run); [ ] live BinDiff/rizin runs
- [x] 3c/3d BinDiff import, rz-diff runner/parser, reconciliation, CLI; [ ] GUI reconciliation view; [ ] protobuf BinExport bindings; [x] separate stdout/stderr capture for rz-diff (`run_process(separate_streams=True)`, bounded per stream; Windows CreatePipe path covered only by CI, no native rizin run); [ ] live BinDiff/rizin runs (rizin: `live-rizin.yml` + `tools/live_rzdiff_check.py` written, awaiting first green run on both OSes and qa.md rows; BinDiff blocked, no licensed install; pinned hashes are trust-on-first-use)
- [ ] Phase 4 deferred
- [x] Full code audit (5 areas, 2026-10-12): see docs/qa.md
- [ ] Assemble, license-audit and publish a **real relocatable offline Python 3.12 / ghidriff / pyghidra / Ghidra / JDK** payload. Validate from fully disconnected Windows 11 and known-patch fixture; currently only synthetic archive/import tests exist.
- [ ] Add clean Windows disk-space, user-profile path-length, antivirus-lock and full-stack offline smoke checks before claiming no-setup beta.
- [x] SPEC-26 A tooltip registry (#24): 143 entries + templates, enumeration tests; [ ] static QMessageBox helpers, per-row item templates, theme/DPI tests
- [x] SPEC-26 B raw views: Hex/Binary/Base64 of verified original bytes, whole-file and from-function-entry scopes, paging, go-to offset, diff-line highlight (#23 + integration); [ ] verified function extents, async page reads, persisted per-hash results
- [x] SPEC-26 C diff navigation crossing functions (#15); raw modes explain absence of text hunks
- [x] SPEC-26 D preliminary PE inspection (#22 + integration): headers, sections, imports/exports, entropy, overlay, certificate table, RSDS, checksum, field comparison in File overview; Authenticode probe (embedded, no revocation) shown; [ ] signed/trusted/revoked Windows acceptance, catalog signatures, version info/manifest, dock/tab presentation, persistence keyed by artifact hash
- [x] SPEC-28 P1-P5: EngineRun/cache key, adapter registry, scheduler (cap 2), `secondary/2` + `current_sets()` (C5 duplicate-set reconcile crash fixed, regression `test_reconcile_never_raises_with_duplicate_engines`), `secondary run` CLI (partial success exits 3); [ ] P6 live-rizin workflow; [ ] BinDiff execution (C4); [x] reconcile-level alternatives rows (`matches-alternative-rank-N`); [x] per-outcome persistence on Ctrl+C; [x] portable (Windows-capable) fake-engine CLI/rz-diff tests; [ ] Windows CI evidence for scheduler cancel/timeout and `.cmd` fake-engine tests; [ ] adapters emitting alternatives
- [ ] SPEC-26 E incremental multi-engine panel (unchanged; BinDiff/rz-diff remain CLI/opt-in)
- [ ] Clean Windows interactive GUI acceptance of the alpha ZIP (File overview, raw views, tooltips, DPI)
- [x] SPEC-07h correctness slice (docs/specs/enrichment-hardening-backlog.md): H1 retention + cap fallback, H3 WIL/partial status, H4 contextual binary evidence, H5 SIZE/BND false positives, H6 `_TEMP`, H11 stale => partial, H12 CVSS cross-provider conflicts, H13 merged `select_latest` (oldest `retrieved_at`); [ ] H2 history bound, H7 child env allowlist (native Windows gate), H8 raw output stored twice, H9 cancel latency, H10 NVD pacing/403 (not started); re-baseline note: signals/wil/ranking/contextual stage versions bumped, so derived caches and stored rows are recomputed

## Enrichment hardening follow-up (2026-10-14)
- [x] H2 history bound, H8 single raw copy, H9 cancel latency, H10 NVD pacing (local evidence; CI pending)
- [x] H7 builder + opt-in `restrict_env`/`env_passthrough`; [ ] native Windows `raw-cache-hit` with restriction, then flip default; [ ] wire rz-diff CLI to `for_tool='rizin'`
- [ ] H2 pre-prune verified backup; [ ] H8 legacy duplicate cleanup on open; [ ] H10 live NVD probe fixture
- [ ] Frozen EXE headless smoke A1-A5, A10, A6s (`tools/frozen_smoke.py`, `tests/test_acceptance_smoke.py`, `tools/milestone_notes.py` wired into the release body): awaiting Windows CI run; A6 native `--run`, A7-A9, A11, A12 of windows-acceptance spec section 2 still open

## Second audit (2026-10-14)
- [x] Items 3-11, 13 (see docs/qa.md); [ ] CI/Windows confirmation of restricted-env JAVA_HOME and background backup; [ ] move the publish rows themselves off the GUI thread (needs a worker-owned connection)
## C6 multi-engine evidence panel (2026-10-14)
- [x] C6-1 pure view-model + service (`secondary/evidence_view.py`, `secondary/evidence_panel_service.py`); `assess_reports` pre-indexed
- [x] C6-2 `ui_evidence.py` Evidence tab, states E0-E8, 26 `evidence.*` tooltips + 4 templates, 8-line MainWindow seam
- [x] C6-3 Engines tab on the SPEC-28 scheduler (probe, run, cancel, per-engine failure, GUI-thread persistence, .BinDiff import)
- [x] C6-4 accessibility names/status rule, contrast test, font-metric row height, 10k/100k data()-call gates, QSettings persistence (local Linux evidence only)
- [ ] C6 CI evidence on Linux + Windows runners (not run from the builder worktree)
- [ ] C8 manual gates: NVDA/Narrator announcement of the status label, 125/150/200% DPI and glyph fonts on Windows, live-palette contrast, frozen-EXE dock smoke
- [ ] Product decision D5 (evidence status in exported reports) - later slice
## C4 BinDiff execution (SPEC-29, 2026-10-14)
- [x] P1 contracts: `EngineRun.provenance`, `cache_key(extra=)`, `SecondaryError.kind`; schema regenerated
- [x] P2/P3 inputs, probe, run, adapter, CLI `secondary run --engine bindiff` (fake executables only); [ ] swap to real C3 `AcceptedBinExport` at integration (no signature change)
- [x] P4 importer hardening (trigger/view/virtual table rejection, authorizer, trusted_schema=OFF, defensive) + discovery pre-fill
- [x] P5 pin/provisioning/live harness/workflow; [ ] verified v8 asset names, sizes, SHA-256 in `tools/bindiff_pin.json` (blocked: release asset names not obtainable from the authoring session)
- [ ] P6 live run on Linux + Windows, real v8 golden `.BinDiff`, committed repo-owned `.BinExport` pair, `unshare -rn` check, answers to SPEC-29 §12 U1-U11
- [ ] Windows CI evidence for the BinDiff fake-executable tests (`.cmd` launcher with `=`-joined flags) and the BinDiff env on Windows
