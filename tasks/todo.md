# PatchTrace delivery tracker
- [x] Fixed the two locally reproducible full-suite issues recorded in `docs/qa.md`: site screenshot renderer follows the Files panel; Tier R rejects an unknown mutation operator before toolchain probing. Focused rerun: 27 passed, 2 skipped.
- [x] Linux-container-only full-suite failures documented in `docs/qa.md` are environment limitations (`python -I` excludes the editable install; AF_UNIX sockets are denied; timing budgets are load-sensitive); full pytest and Ruff passed on Windows and Ubuntu CI (run 39456546905).

## Windows Setup release track (PR #95, 2026-10-17)
- [x] Implement pinned NSIS per-user Windows installer on existing PyInstaller onedir runtime.
- [x] Add portable extracted-ZIP and installed-frozen-executable smoke tests, checksums, and data-preserving uninstall logic.
- [ ] Verify PR #95 on Windows CI, merge only after all release gates pass, and publish a new GitHub prerelease including Setup.exe + portable ZIP.
- [ ] Verify actual published installer and ZIP assets, checksums and release commit SHA; complete clean Windows interactive GUI acceptance separately.

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
- [x] Local-only symbol policy (SPEC-53 GHR-1..3 + CLI flags): PatchTrace-owned launcher forces an empty server list in `local` mode (hermetic fake-ghidriff tests); [x] Setup checkbox + folder field (`backend/symbol_mode`); [ ] radio group/list widget, Profiles `local` value, diagnose launcher lines; [ ] GHR-5 native air-gap matrix (real Ghidriff/Ghidra, OS network block) - until then "no servers" is configuration, not an air-gap claim
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
### C4 follow-up after measuring the real BinDiff 8 (2026-10-14; supersedes the pin and P6 lines above where they overlap)
- [x] Plan section 4 items 1-9 applied to SPEC-29, code and tests (probe/argv, `--config` isolation incl. machine config, journal, usage exit 0, non-clean stop, importer layers, 250-char output path, MSI/redist facts, D1)
- [x] `tools/bindiff_pin.json` real v8 values (deb 62,663,460 B, msi 72,237,056 B; re-hashed by a second download, identical), trust-on-first-use
- [x] Stdlib `.deb` provisioning (byte-identical to `dpkg-deb -x`); Windows `--advisory` leg with `redist` preflight
- [x] Linux live run, local only (uid 65534): probe, pinned version, end-to-end via C3 `accept_binexport` + `run_engines` + `BinDiffAdapter`, cancel at first output, 0.5 s timeout, `unshare -rn`; real v8 golden on the SYNTHETIC pair committed
- [ ] First green `live-bindiff` run on GitHub (Linux required leg) and the advisory Windows record (msiexec /a layout, bindiff.exe start, VC++ runtime on windows-latest)
- [ ] Real-driver `.BinExport` pair (Ghidra/IDA) for U8 runtime/memory and U9 `executable_id` formats; zero-match behaviour on a real pair
- [ ] Independent re-hash of the pinned assets from a second network path and `.asc` verification (key id `4EB27DB2A3B88B8B`) before beta
- [ ] Importer per-table row caps (plan S6/D5); `live-bindiff` promotion to required after 10 green runs (product owner)
## C9 calibration build (2026-10-14)
- [x] C9-1/2/4/5/6/7/8/9 code on synthetic data: contracts + schemas, corpus guard/verify/fetch, lineage + identity grouping, sampling, labelling log (terminal mode), kappa, features/1, stdlib fitters (+ optional sklearn cross-check), grouped nested CV, metrics, lineage bootstrap, fixed-sequence LTT tau, null-simulated ECE gate, OOD validation, ablations, M0b raw-bytes baseline, gates, report, locked-test runner, shipped artifact/predict/ood/policy (`display_level()` stays 'ordinal')
- [ ] C9-0 ratify spec section 18 amendments; citation check (all sources "verify before ratification"); draft `docs/plans/c9-preregistration-v1.md`
- [ ] C9-3 Tier R recipes (patch-tag builds, clang-cl/mingw; Microsoft open-source MSVC builds) and the end-to-end Tier R run (< 60 s); read every licence first (BinKit, BinaryCorp, REFuSe-Bench, Assemblage, Winbindex: UNCONFIRMED)
- [ ] Labelling HTML front-end on 127.0.0.1 (terminal mode exists); C9-10 labelling campaign blocked on USER decisions O1, O2, O4
- [ ] Cross-platform report determinism (Linux vs Windows byte-identical report SHA) - only verifiable in CI; package-data + PyInstaller datas entry when the first artifact ships
- [ ] C9-12 GUI L1/L2 via C6 only after a locked-test pass (C6 imports `display_level()` guarded; currently always 'ordinal')
## C3 BinExport2 (SPEC-10b, 2026-10-14)
- [x] C3-1..C3-6 and C3-8 built: pinned protobuf 7.36.2 (upb only), descriptor + golden field table, pre-scan, checker, identity, snapshot, pipeline, capped worker with `accept_binexport`/`accept_pair`, `jobs.run_process(memory_limit_bytes=)` plus the Windows spawn-handle lock, `secondary binexport-check`, notices, build-script guards, frozen smoke B1/B2, hypothesis/fuzz, synthetic goldens with provenance.
- [ ] Windows CI: U7 behaviour at the Job Object memory limit (`tools/qa_binexport_memcap.py`), frozen `PatchTrace.exe` B1/B2, size delta and AV result for `_message.pyd`.
- [ ] CI workflow steps (integration owner): `--only-binary=:all:` install, `pip check`, pin + upb assertion, Linux-only nightly `tools/fuzz_binexport.py`.
- [ ] C3-7 real Ghidra/IDA goldens (human); live rows U1/U3/U5/U6/U9/U12.
- [ ] C4: swap the `bindiff_inputs` Protocol for the real `AcceptedBinExport`. GUI wiring of BinExport selection.
## SPEC-31 unified diff engine (planned 2026-10-14; docs/specs/unified-engine, docs/plans/unified-engine-plan.md)
- [x] Spec + plan + backups + troubleshooting (docs only; this PR)
- [x] Independent review of the spec (docs/specs/unified-engine/11-review-log.md): 30 findings fixed in place (R-01..R-32), residual risks and USER decisions U-11/U-12 added
- [x] P1 Windows spawn lock in `jobs._windows_process` (merged with C3; `test_concurrent_run_process_calls_do_not_cross_pipes_or_leak_threads`)
- [x] P2 nway raw `address_matches`: skip `EXTERNAL:<hex>` entries instead of `PT-NWAY-PAIR` (ce108cd)
- [ ] P2b count the skipped `EXTERNAL:` entries in the series limitations; SPEC-09/SPEC-28 status lines (A-05, A-06)
- [ ] S0a contracts/limits/keys/registry/store + schemas + doc status lines (10-amendments rows marked S0a)
- [ ] S0b sources, fusion, S0 facts, pipeline, worker, CLI `unified run/show/explain/status --no-extract`
- [ ] S1 extraction (GZF reuse + analyze fallback), ingest, MD index port with notices, live-unified workflow (Windows + Linux)
- [ ] S2 ladder MVP + parity harness; S5 residual (blocking, vectors, votes, LAP)
- [ ] S3 IR change channels, DATA-MAP/1 target consistency, proofs UNCH/COS-ADDR/COS-LAYOUT with EH-EQ, MAT-ANCHOR, S3b on-demand decompile
- [ ] S4 read model + `ui_unified.py` (single window: view switch + dock tab), tooltips, accessibility
- [ ] S6 Tier R / A/A / planted-mutation corpus, gates G-U1..G-U8, flag default decision (USER U-05)
- [ ] USER decisions U-01..U-12 (defaults in docs/specs/unified-engine/00-decisions.md s4)
- [ ] USER decisions U-01..U-10 (defaults in docs/specs/unified-engine/00-decisions.md s4)

### [K:28a-28b] CSAF engine (track K, 2026-10-14)
- [x] SPEC-28a: contracts + generated schemas/examples, discovery, transport, stdlib validator, normalization, storage (synthetic fixtures; fake opener)
- [x] SPEC-28b: CWE lexicon (negation/scopes), hypothesis rules, anchors, verified-bytes identity, OLD/NEW applicability with contradictions and explicit unknowns
- [ ] Deferred: `intelligence/reports.py` (JSON/MD, escaping), `intelligence/cli.py` + `cli.py` hook + `tools/frozen_smoke.py` entry (spec section J)
- [ ] Live (BLOCKED here): MSRC provider-metadata location and directory layout, real Microsoft CSAF documents through the validator (policy if they fail mandatory tests), `.sha256` availability, consented fetch on Linux/Windows; re-verify OASIS schema hashes on docs.oasis-open.org and CWE names on cwe.mitre.org
### [W:tier-w-w1] Tier W local-only corpus (SPEC-33, 2026-10-14)
- [x] Spec; layout/contracts; Winbindex catalogue + resolve + pair/manifest builder; stdlib MSF reader; PE tables + masked body hash; repository guard (O1) with self-made PDB allow-list; reproducible self-made fixtures
- [ ] Next wave: `fetch` (binaries via quarantine.acquire, PDBs via a Transport subclass, throttle/resume/disk/cancel), Ghidra/PyGhidra exporter + `symbol-map/1` writer + optional llvm-pdbutil adapter, labels + N2/N3/N9/N10 tags, audit queue + error rate, runner (symbols hidden/visible), `evaluate`, CLI, the Tier W runbook (to be written with LBL-25)
- [ ] Owner machine only: Winbindex/msdl access (BLOCKED here: proxy CONNECT 403), real Microsoft PE/PDB parsing (OMAP, stripped publics), Ghidra time per family, symbol-label error rate
### [T:core] SPEC-29 tools capa/FLOSS/diec (2026-10-14)
- [x] Spec T1-T10 (`tool-evidence/1`); pinned capa 9.4.0, FLOSS 3.1.1, diec 3.21 verified from upstream source + real Linux runs
- [x] Contracts, strict parsers/probes, scratch/env helpers, normalize (RVA, verified offsets, attribution, pairing), delta (newly-introduced vs newly-detectable, unlocalized, flags, value gate unvalidated); real goldens on SYNTHETIC pairs
- [ ] Runner/scheduler + store (draft exists outside the repo, untested), CLI `intel-tools` + 6-line hook, schema generator + regenerate test
- [ ] Fake-executable tests (missing exe, timeout, cancel, oversize, stderr noise, stale cache, Windows paths, airgap)
- [ ] Provisioning + `tools/intel_tools_pin.json` (asset SHA-256 measured, see qa.md), live test, `live-intel-tools.yml`; Windows runs; Ghidra-backend fixture; DiE value-gate benchmark
### [D:known-answer-factory] SPEC-32 known-answer corpus factory (builder D, 2026-10-14)
- [x] Spec `docs/specs/known-answer-corpus.md`; label contract + schemas/examples; C locator; reproducible msvc-free/mingw builds; PDB/DWARF inventory; masked hashes; decision-table labeller; authored-suite cross-check (I4); case cards (I2/I3); A/A rebuild + layout and toolchain-noise pairs (M4); pinned fetch; zlib v1.3 -> v1.3.1 card verified by a real build
- [ ] M1 catalogue to >= 14 projects x 3 consecutive pairs (only zlib, 1 pair, committed); M2 >= 15 CVE cases + >= 3 bounds/constant-only + >= 3 controls (sources: CVE List V5 raw records, oss-fuzz-vulns; NVD/OSV hosts blocked here)
- [ ] M3 planted mutations (`tools/calibration/mutations/`, 16 operators designed in spec s8; not built)
- [ ] M5 `tier_r/evaluate.py` (rz-diff via registry/scheduler, BinDiff/Ghidriff import, per-stratum metrics, report) and `annotate.py`/`manifest.py` conversions
- [ ] CLI (`python -m tools.calibration.tier_r`), `corpus.py known-answer` hook, `.github/workflows/corpus-tier-r.yml` (Linux + advisory Windows); optional manifest-only `public-datasets` importer (DeepHistory pins, oss-fuzz-vulns, CVE List V5)
### [B:hardening] Phase D track B (2026-10-14, builder worktree; local Linux evidence, CI pending)
- [x] H2 pre-prune verified backup: no history prune, retention, `make_room` or engine-run deletion without a re-opened, integrity-checked backup (`verified_backup.py`); failure keeps every row (supersedes the "[ ] H2 pre-prune verified backup" line above)
- [x] H8 legacy duplicate raw cleanup on open: journalled (`backups/raw-duplicates.jsonl`), hash-verified, reversible (`raw_cleanup.restore_raw_duplicates`), series readers never clean (supersedes "[ ] H8 legacy duplicate cleanup on open")
- [x] rz-diff CLI allow-list: already wired via `engine_env` (C4); now pinned end to end by `tests/test_rzdiff_cli_env.py` (supersedes "[ ] wire rz-diff CLI to for_tool='rizin'")
- [x] H3 gaps: truncated pairings are `partial` in B1 and WIL even without a visible edit; [x] SPEC-07 §4 `views.validate_location` (GUI navigation wiring left to the UI owner)
- [x] Derived-cache algorithm digests in stage ids and pipeline rows (older rows recomputed once); [x] P2 WIL gate-scan performance; [ ] derived-cache hit 500 ms at 10,000 pairs: improved, still NOT met (see docs/qa.md [B:hardening])
- [x] H10 live probe tool + advisory workflow + recorded-fixture tests; [ ] first live run on GitHub (`live-nvd` workflow; this container has no direct egress: recorded BLOCKED)
- [ ] Deferred to the next wave: P2 `nondeterministic now` (injectable clock in `PipelineOptions`), `function_rva` reader identity, offline bundle ratio (outside track B files), GUI use of `validate_location`
### [G:bindiff-gui-setup] Phase D track G: BinDiff + BinExport GUI setup (2026-10-14)
- [x] Engines-tab "BinDiff setup" section (`ui_engine_setup.py`): executable field + Browse + Probe (discovery prefill, never PATH, never run by discovery), pin status, older/newer `.BinExport` pickers, validation through the CLI's C3 acceptor on a worker with progress/cancel, plain-language SPEC-29/SPEC-10b messages with technical details on demand, explicit unbound confirmation recorded in provenance as the CLI does, run through the C6 scheduler flow with `cli_bindiff.adapter_from_args`; 15 `engine_setup.*` tooltip ids; C6 regression baseline test
- [ ] Windows desktop: real BinDiff 8 `bindiff.exe` through the GUI, native file dialogs, 125/150/200% DPI layout of the section, NVDA/Narrator announcement of the two status lines, keyboard-only walk (manual, C8)
- [ ] Real Ghidra/IDA `.BinExport` pair through the GUI (only synthetic fixtures so far; C3-7)
- [ ] Optional: remember `.BinExport` paths per project; auto-probe a previously configured executable (both deliberately not done: explicit actions only)
### [S0a:contracts-store] SPEC-31 S0a (2026-10-14)
- [x] limits, contracts, keys, store, `docs/schemas/unified/` + examples via tools/generate_schemas.py, drift test; 02 s9 freeze notes
- [ ] DEFERRED: `unified/registry.py`, `place_ir`/`find_ir`, orphan result-dir sweep, spec status lines A-01/A-01b/A-03/A-06/A-08/A-09/A-10/A-11/A-14, `.gitattributes` for tests/fixtures/unified
- [ ] Windows CI: unified tests (paths, os.replace retry, CRLF checkout of docs/schemas/unified examples) and Python 3.12
### [AM1:kb-amendments] KB integration plan amendments A-5, A-6, A-10, A-12 (2026-10-14, local worktree commit; not pushed)
- [x] A-5 (+ KEV plan A4, + integration owner AM1): `kb-investigation`, `kb-context`, `kev-context`, `search-saved`, `rule-candidate`, `rule-decision`, `rule-version`, `rule-test`, `rule-export` added to `enrichment.storage.KINDS`, not to `DERIVED_KINDS`; rows survive `apply_retention`, `prune_runs` and `make_room` (`tests/test_enrichment_kb_kinds.py`)
- [x] A-6: `ProjectStore.backup()` also copies `kb/` and `intelligence/` (repairs the CSAF advisory sidecar gap); byte-identical by SHA-256 after opening the backup, symlink refusal inherited, layout unchanged for projects without them (`tests/test_backup_sidecars.py`)
- [x] A-10: public `intelligence.anchors.text_anchors()`; `Anchor.source` gains `cvrf-title`, `cvrf-note`, `cvrf-tag`; `docs/schemas/intelligence/` regenerated (only `AnchorSet.json` and `IntelligenceReport.json`, three enum values each); regenerate-and-compare green (`tests/test_intel_text_anchors.py`)
- [x] A-12 (part): `.gitattributes` LF for `tests/fixtures/kbcorrelation/**` and `docs/schemas/kbcorrelation/**`
- [ ] Left to the owning slices: the rest of A-12 (`tools/frozen_smoke.py` import of `kbcorrelation`, pytest marker `live_kbc`, tooltip-registry roots), K2's writers for `kb/` sidecars with their own hash-on-read, the writers of the saved-search and rule rows, the `intelligence.anchors` consumer in K8
- [ ] Windows CI for the new tests (not run here); the symlink test skips on a host that cannot create symlinks
- Unblocks K2 (store, reducer, recovery), which waited on A-5 and A-6

## GitHub Pages site (2026-10-14; site/, tools/site/; local Linux evidence, GitHub run pending)
- [x] Single-page site in the Circuit Drift Labs style: honest status (alpha, vibe coded, no calibrated confidence), works-today list with cited evidence, five real GUI screenshots of the synthetic sample, ten labelled design previews, features and integrations table with Working / In progress / Planned, Program E game plan; no external requests (gate in `tools/site/checks.py`)
- [x] `tools/site/{build_site,make_logo_assets,render_screenshots,xmr_address,donate,checks}.py`, `tests/test_site_*.py`, `tests/site_claims.md`, `.github/workflows/pages.yml`, `site/README.md`
- [ ] OWNER: Settings -> Pages -> Source: GitHub Actions; add `site/assets/source/logo-original.png`; add `monero_address` to `site/site-config.json` (the donation block stays hidden until then)
- [ ] First `pages.yml` run on GitHub (never run); Windows and Safari rendering; keyboard and screen-reader pass on the live page
- [ ] Re-render `site/assets/screens` when the GUI changes (`QT_QPA_PLATFORM=offscreen python tools/site/render_screenshots.py`); update `site/content.json` and run `python tools/site/build_site.py --write-claims` when a feature's status changes
### [K0:kbcorrelation-contracts] KB-CVE correlator K0 (2026-10-14)
- [x] contracts, limits, ids, errors, ports, `tools/generate_kbc_schemas.py` + `docs/schemas/kbcorrelation/` (+ examples), regenerate-and-compare test, KB syntax matrix, Coverage `complete_in_scope` invariant
- [ ] DEFERRED to later slices: K0f fixtures, A-5/A-6 (KINDS, backup), A-8 `cli.py` hook, A-12 (`.gitattributes` LF for docs/schemas/kbcorrelation, frozen smoke import, `live_kbc` marker); live probe L1 confirms provisional `KbcLimits`
### [K-FIX:audit-C] Audit C of intelligence and CVE enrichment (2026-10-14)
- [x] Fixed, each with a red test first: C-01, C-02, C-03, C-04, C-05, C-06, C-07, C-08, C-09 (all Medium), C-10, C-12, C-13, C-21, C-22 (cache write failure and per-kind cap); plus crash classes the audit's fuzzer missed (version strings beyond 4300 digits, over-long or unpaired-surrogate property names breaking the `Finding` contract); additive CWE-134 and CWE-193 lexicon terms and rules
- [ ] Not built, reason recorded: C-14 to C-20 (`intelligence/tools/`, owned by instance B); C-11 and C-24 (dropping or marking an over-bound provider element needs an additive `CveSnapshot` marker field in enrichment/contracts.py; today an over-long element fails the whole provider response closed, and the 64-item truncation cannot affect ranking because references are not used and products only lose matches); C-23 (an NVD superset only blocks the extra CWE through the intersection in `contextual_rank`, by design of SPEC-07 section 8); C-22 URL-map lock (a lost update costs a refetch); C-25 to C-27 (information only: numbering is the registry's job, other builders own the missing modules, Windows unverified)
- [ ] `intelligence explain` (not built yet) must pass every stored document to `resolve`, or call `AdvisoryStore.applicability(cve, older, newer)`, so a withdrawn CVE is reported; `for_cve` alone cannot show it
### [S2:ladder] SPEC-31 S2 (2026-10-14, builder worktree)
- [x] Ladder MVP P00-P15 (uniqueness-gated, BinDiff-style drill-down, tier cap along the chain), propagation to a fixpoint (neighbour cascade, hubs, thunk targets, implied matches with symmetric persistent conflicts), groups (duplicate, ICF, inline/outline), leftover reasons, `partial` on budget exhaustion; `src/patchtrace/unified/ladder/`
- [x] Parity harness `tools/unified/parity.py` (Ghidriff, BinDiff rows, MD histogram, dev-only `--md_index` argv) and synthetic IR builder `tests/unified_ir_builder.py`
- [x] Acceptance: every 04 s9 test of the S2 scope by its name (the S5 residual tests are not in scope; the three MD tests run against the builder's stand-in), the four properties (permutation, side swap, unrelated function, budget prefix), G-U5 at 10k and 60k (`tests/test_unified_ladder_perf.py`), 31 mutants of the ladder killed
- [ ] S1: adapter `IrReader -> IrSide` (ports.py docstring has the column mapping); `ir/mdindex.py` must ship `test_md_index_diamond_vector`, `test_md_index_plain_loop_not_compensated_sum`, `test_md_null_below_min_blocks` against the real module (S2 has them against the builder's stand-in); the ported modules' header years are R02's `2011-2023` and must be checked against the pinned files when `third_party/notices/bindiff-v8-<sha7>/` lands
- [ ] S0b: registry rows for P01-P15 (family, evidence class) plus a cross-check against `ladder.passes.PASSES` (the table in tests/test_unified_ladder_core.py::SPEC_TABLE is the spec transcription); consume `Correspondence`; `PASS_TABLE_DIGEST` into `config_digest`
- [ ] Integration owner: spec amendment rows A-15 (bindiff-execution.md wording for the dev-only parity tool) and A-24 (docs/notices.md, docs/reuse-matrix.md rows) and a short "S2 build notes" paragraph in 04 (deviations above); register a `perf` pytest marker if G-U5 tests should be deselectable (pyproject.toml is not S2's); extend `test_ported_modules_carry_attribution_header` to `ir/mdindex.py`
- [ ] BLOCKED (live): G-U3 parity against a real BinDiff (`--md_index` dump layout unverified; no pin yet), G-U5 on the Windows runner and the frozen EXE, real MSVC-built IR, Ghidriff `address_matches` of a real run through the harness
- [ ] S5 seam is ready (`PassSpec.run`, `State`); blocking, P16-P19 and LAP are not started
### [S0a-FIX:audit-c] SPEC-31 S0a-FIX (2026-10-14; independent audit C, docs/audits/20261014-C-unified-s0a.md)
- [x] F-01..F-26 fixed, or recorded as deliberately unchanged with the traced reason in 02 s9.1: pointer `unified-result-ptr/2` with a version-gated reader (`/1` stays readable), pair-aware retention, strict and deep verification, ownership, result-drift refusal, text/time/path rules, golden key vectors with the content/operational limit split, orphan sweep (closes that item of the DEFERRED line above)
- [ ] Open: `.gitattributes` lines (first fixture), Windows CI run of the new tests (device names, CRLF checkout, 240-character path budget), ownership of non-Ghidriff `SourceRef.entry_id` rows (S0b adapters), S0b/S1/S2 integration (display text is sanitised, identifiers are rejected; `publish_result` needs a saved project owning the run and artifacts)
### [K:K1-K2] CSAF remainders (PIL-K1/PIL-K2, 2026-10-14; supersedes the "Deferred" reports/cli line in the K block above)
- [x] K1 `intelligence/explain.py` (`build_report`) and `intelligence/reports.py` (canonical JSON, escaped Markdown, `escape_md`, atomic export); injection fixture, byte-identical goldens (`tests/fixtures/csaf/expected/`, LF via `.gitattributes`)
- [x] K2 `intelligence/cli.py` (`import`, `fetch`, `explain`, `ACTIONS`), 6-line `cli.py` hook, `tools/frozen_smoke.py` A1 + C1-C4, `test_every_cli_command_is_covered_by_the_smoke_list` green
- [ ] Windows CI: goldens byte-identical on Windows, the frozen `PatchTrace.exe intelligence --help` and C1-C4, Python 3.12
- [ ] Live (BLOCKED): a consented fetch from msrc.microsoft.com on Linux and Windows (tests use a fake opener only); real Microsoft documents through import/explain; the default provider-metadata location is still unverified
- [ ] Next: PIL-A1 (pilot contracts) can reuse `reports.escape_md`; `ACTIONS.update` is the hook for `intelligence leads|why|review`
### [PIL-A1:contracts] Patch-intent localization contract freeze (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s7, s9)
- [x] `pilot/{limits,contracts,keys,origins,ports}`, `tools/generate_pilot_schemas.py`, `docs/schemas/pilot/` (7 schemas, 10 valid + 40 invalid examples), `.gitattributes` LF lines, `PT-PILOT-*`, `tests/test_pilot_{contracts,keys}.py` (359 tests; gates: regenerate-and-compare, invalid examples, `test_strong_is_unreachable`, `test_assessment_has_no_floats`, `test_old_reader_ignores_patch_intent`); persisted contracts frozen additive-only
- [ ] Owner: plan s10 amendments still open (this slice edits no spec): 1 SPEC-30 status, `pilot/1`, ledger instead of graph, tiers, CVE gate, 30d gate; 2 CSAF spec; 3 implementation plan; 4 rows for the remaining `pilot/*` and `ui_leads.py`; 5 `phase-d-build-coordination.md` s2 (`patch-intent` is not derived, list `PT-PILOT-*`); 6 public `backup_once`/`delete_own` in `enrichment/storage.py`; 7 `cli.py` EXTENSIONS; 8 `ui.py`/`tooltips.py` seam; 9 LBL consumer note; 10 unified A-22 and KB 31-E
- [ ] Next slices: PIL-A2/A3 adapters, PIL-B1 rule table, PIL-T oracle (`tests/fixtures/pilot/` is already pinned to LF), then B2, C1, C2, D1; `ports.py` signatures are provisional until A2/A3/B2 land
- [ ] Windows and Python 3.12 CI for the pilot tests (3.12 verified locally in a venv); frozen smoke import of `patchtrace.pilot` once a consumer exists (nothing imports it yet)
- [ ] Pre-existing on work/a 8fcdd3d, not PIL: `tests/test_algorithm_digests.py::test_algorithm_digests_are_pinned` fails since `enrichment/cve.py` `CVE_PATTERN` gained `re.ASCII`; re-baseline `tests/fixtures/algorithm_digests.json` and record it in docs/qa.md
### [S0b:unified-s0] SPEC-31 S0b (2026-10-14)
- [x] sources (Ghidriff + raw `address_matches`, BinDiff, rz-diff, analyst corrections), addressing (C3 `detect_address_basis`), fusion/arbiter with independence components AND evidence classes, S0 facts (canon/1, C4n/C5t/C6/C8) and verdicts, pipeline (prepare/cached/execute/publish), hidden worker (C3 `worker_argv`, L-42 cap, C3 OOM rule), CLI `unified run/show/explain/status`; `registry.py` delivered here (S0a deferred it); spec notes 02 s10, 05 s6, 06 s10, 07 s12
- [ ] Windows CI: the unified tests on Windows (child spawn through `python -m patchtrace`, Job Object memory cap and OOM classification U7, `os.replace` of staged result directories, CRLF), Python 3.12; frozen `PatchTrace.exe unified --help` and `unified _worker --self-check` (A-20, smoke lines belong to S1)
- [ ] BLOCKED, live evidence: a real Ghidriff/Ghidra raw output with the PDiff `address_matches` table on a real MSVC pair; real BinDiff 8 and rz-diff sets in a project (adapters and facts were tested on synthetic data only, decompiler text is imitated); whether real BinExport sets carry import vertices outside the image (C3's strict basis rule would refuse such a whole set and say so)
- [x] After the S0a-FIX merge: identity now covers refused sets and the raw failure kind (store `result-drift`, 02 s10 item 13), the owner-side `zlib.error` mapping is gone (fixed in the store), the hostile-name and limit tests follow s9.1 (U+FFFD replacement, content limits only)
- [ ] OPEN for other owners: `secondary/2` needs a basic-block count to identify BinDiff stub rows (A-16, 02 s10 item 8a); C3 `secondary --help` prints `==SUPPRESS==` for `_binexport-worker`; `tools/frozen_smoke.py` `COMMANDS` was touched by S0b (owner S1); open S0a status lines A-01/A-01b/A-03/A-06/A-09/A-10/A-11/A-14
- [ ] Not built here (later slices): IR channels C0-C3 and C7, UNCH/1, COS-ADDR/1, COS-LAYOUT/1 (S3); CLI `extract` (S1); ladder passes (S2); Diaphora adapter and its two named tests (DA-01); read model and GUI (S4)
### [S1:extraction-ir] SPEC-31 S1 (2026-10-14)
- [x] Extractor script (`gzf`/`analyze`), runner, ingest with operand typing and located fields, features, MD index (BinDiff v8 port + notices), pe_tables incl. EH signature, IR reader and placement, backend `retain_gzf` seam, PyInstaller data-file hook, build and frozen-smoke gates, live tool + `live-unified.yml`, recorded fixtures with `PROVENANCE.json`
- [x] Linux live evidence on real Ghidra 12.0.4 (own analysis, real Ghidriff with retention, 4,060-function pair, Ghidra hasher classes): docs/qa.md [S1:extraction-ir]
- [ ] Windows: first `live-unified` run (MSVC-built fixtures, real Ghidriff GZFs through `retain_gzf`, cross-OS `content_digest` equality on the same DLL bytes); expected to expose MSVC-specific operand shapes (RVA-form switches), none were available here. 2026-10-14 (PR #49): the Windows job passed L0-L4 on MSVC DLLs; L5 failed because Ghidra's hashers include NOPs that h3 / hm skip, so L5 was redefined (amendment A-27); the green re-run and the Linux job (L6) are still to be seen
- [ ] Windows frozen smoke U1 (script data file, BinDiff notice); U2 switches on when S0b's `unified/cli.py` exists; the frozen `importlib.resources` read is verified on Linux only
- [ ] Open or not built: BinDiff `--md_index` parity (G-U3, S2 harness; no pinned BinDiff here), FID `lib` marker, global derived-cache stage `program-ir` (A-04b), S3b `decompile` mode of the script (S3)
- [ ] Observation for the backend owner (not changed here): `backend._probe_backend` resolves the interpreter path, so a POSIX venv interpreter (a symlink) is probed without its site-packages; Windows launchers are unaffected
### [K1:kbcorrelation-sources] KB-CVE correlator K1 (2026-10-14)
- [x] cvrf/csaf_bridge/scope/importer/net_plan, products + alias catalog, index, `kb index` verbs (import/status/verify/plan); S01-S10, S11, S12-S14, S16, S19 and NEG-01/02/03/04/05/06/07/08/24/25/26 covered by synthetic tests; reorder-invariance property; 32 MiB cap + gzip bomb; two-axis coverage; product status disputes
- [ ] NOT done / open: K3 hook of `cli_index` into `kb` and `cli.py` (A-8); K2 replaces the interim workspace files; S15 timeline UI; S17/S18 end-to-end in K3; cross-document status disputes (only in-document); real MSRC CVRF dialect + URL shape (live probe L1) and CSAF KB location (L4) BLOCKED; S20 needs a captured official response (live)
### [T:core] tools-core builder (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] Audit TA-1..TA-12 and TA-16 fixed with red tests first (`tests/test_intel_tools_audit.py`); WB3-S1b FLOSS amendments (consent v2, `-n`/`-L`, memory cap, `PT-TOOL-LIMIT`, per-type quotas, `data_rva`/`site_rva`); TC-R runner + store; TC-C `intel-tools` CLI (5-line `cli.py` hook); TC-P schemas, pin file (all six assets MEASURED, none UNMEASURED), provisioning, advisory `live-intel-tools.yml`
- [x] Real pinned capa 9.4.0 and FLOSS 3.1.1 (Linux) probed pinned, run through the runner on the SYNTHETIC pairs and equal to the goldens (`tests/test_live_intel_tools.py`)
- [ ] BLOCKED: diec live leg (no Qt5 Core/Script libs in this container), all Windows legs, first GitHub run of `live-intel-tools.yml`, Ghidra backend, independent re-hash of the pins from a second network path, executable-swap window between re-hash and spawn is narrowed not closed
- [ ] Not done: `intel-tools pairs` (CAP), capa `memory_limit_bytes` option and `contained-in-function` (CAP-1), DiE vocabulary (DIE D1), `tools/frozen_smoke.py`/`build_windows.py` pin packaging, docs/qa.md rows (integrator)

### [WB3-S0:strings-core] WB3-S0 contracts and table
- [x] `patchtrace.strings` limits, contracts, keys, columnar table; schemas under `docs/schemas/strings/`; gate measured: two 200k-row sides (unique display values) load in about 0.3 s, tracemalloc peak about 52 MiB
- [ ] Next: S1 sources, S2 regions/cues, S3 scan (need S0 only)
### [WB3-S1-S3:strings-sources-scan]
- [x] WB3-S1 sources, WB3-S2 regions/cues/look-alike, WB3-S3 built-in scan (parity with the FLOSS 3.1.1 static goldens, property tests against a whole-buffer regex oracle)
- [ ] Open: S0 contracts/table (`strings/__init__.py`, limits, columnar table) not on this base; `SourceRow` maps 1:1 onto the planned table columns; advisory-text/advisory-api/lookalike cues are set by the delta layer (S5/S6)
### [G1:callgraph-kernel]
- [x] Kernel (limits, text, labels, CSR, algo) with NetworkX 3.7 differential oracle (dev only, skipped when absent) and PYTHONHASHSEED 0/1 determinism test
- [ ] Next: G2 contracts, input, pairing, resolver, snapshot, query
### [G0:fixtures] WB2 G0 synthetic call-graph fixtures (2026-10-14, Haiku 5.5, worktree)
- [x] Red tests first (`tests/test_callgraph_fixtures.py`), then builder `tests/callgraph_fixtures.py` and six committed fixtures in `tests/fixtures/callgraph/`; 24 focused tests pass; ruff clean
- [ ] Integrator: add `.gitattributes` line `tests/fixtures/callgraph/** text eol=lf`
- [ ] Live gate (WB2 section 5): confirm the real Ghidriff `matches` label forms against one real synthetic-PE JSON before trusting hub registry and import keys; the fixture's `name_matches`/`address_matches` shape is an assumption until then
### [WB1-S0:search-foundation]
- [x] S0 capability probe, limits, errors, cache paths, bench and runtime-check tools (focused tests green on Linux)
- [ ] Open gate: probe on `windows-latest` and the frozen Windows build (`check_search_runtime.py` and later `search --probe`)

### [WB1-S1:search-query]
- [x] S1 grammar, safe MATCH builders (hypothesis: no input raises OperationalError), 40+ name goldens, hostile list, frozen contracts
- [ ] Integrator: add `tests/fixtures/search/*.json eol=lf` to `.gitattributes`

### [WB1-S2:search-segment]
- [x] S2 segment store (crash-point, corruption, authorizer allow-list, replace-over-open-file tests; Linux green)
- [ ] Open gate: the replace-over-open-file and URI-open tests on `windows-latest`
### [K2:kbcorrelation-store] KB-CVE correlator K2 (2026-10-14)
- [x] workspace store, two-phase attach, reducer, recovery; subprocess hard-kill (SIGKILL) at `index_after_doc`, `index_before_commit`, `after_project_create`, `before_cas` (x2), `after_sidecar_write`, `attach_before_row` (x2) leaves a valid project and workspace; repair idempotent; newer store fails closed; project backup keeps the `kb` sidecars
- [ ] NOT done / open: K3 binds `ProjectPort` (`create_project` must return the existing project for the same bytes; `put_row` has no directory, so the binding needs a project registry) and replaces the interim `cli_index` files with `WorkspaceStore`; `kb attach --repair` verb; workspace object eviction (only `unreferenced_objects()` lists candidates); `tests/test_kbc_contracts.py` must exempt `store.py` from its sqlite3 ban; Windows run of the kill tests (CI) not yet seen
### [CAP-0:capa-docs] CAP-0 spec amendments and documentation rows (2026-10-14, builder worktree; docs only, no code)
- [x] `docs/specs/three-tool-evidence-adapters.md`: status line, tool-selection wording on localization, new T13.1-T13.6 amendments (CAP section 10); `docs/specs/patch-intent-localization-engine.md`: CAP scoring amendment (context only, lineage, `observation_key`)
- [x] `docs/modules.md`, `docs/qa.md`, this file: append-only CAP blocks (module rows, evidence rows 19-21, slice status)
- [ ] NOT done (later slices, per CAP section 9): T0 shared SPEC-29 core prerequisite (not CAP-owned; CAP-0 did not verify its completion); CAP-1 contracts and parser v2; CAP-2 pair delta; CAP-3 view-model; CAP-4 raw-first cache; CAP-5 `intel-tools pairs`; CAP-6a/6b Capabilities dock and run tab; CAP-7 hints; CAP-8 live capa acceptance (L1 Linux required, Windows advisory); CAP-9 extent attribution (deferred on SPEC-31 S1); CAP-10 BinExport2 (deferred); CAP-11 consented download (owner decision)
- [ ] Integrator asks: none from CAP-0; the T13 amendments change no shared file. Shared-file changes listed in CAP section 10 (`tools/frozen_smoke.py`, `tools/build_windows.py`, `pyproject.toml` marker `live_capa`, `.gitattributes` fixtures) belong to the slices that need them.
### [CAP-1:capa-parser-v2]
- [x] Contracts and parser: coverage, features, labels, exit 11/13, Ghidra >= 12.0 probe, memory-cap option, in-memory re-parse (`tests/test_capa_parser_v2.py`)
- [ ] Integrator: `runner.py` passes `CapaConfig.effective_memory_limit()` for capa (today only FLOSS); `intel-tools probe` rules label and `PT-TOOL-PAIRING` exit mapping (CAP-5)

### [CAP-2:capa-pairs]
- [x] Pair groups, pair delta, synergy golden `tests/fixtures/intel_tools/expected-pairs-capa-api.json`, properties, 20,000-item bound, no-Qt import test
- [ ] Not done: `tests/capa_pairs_pe.py` and REAL `capa-move-*` goldens need the pinned capa (not in this container); the DERIVED `capa-move-derived-newer.json` stands in (labelled in `MANIFEST.capa-v2.json`)
- [ ] Integrator: generate a `capa-pairs/1` JSON Schema in `tools/generate_intel_tools_schemas.py` (its test pins 9 outputs); hypothesis-context leg of the synergy test is CAP-7

### [CAP-3:capa-view]
- [x] View-model, banned-wording sweep, 100,000-row build and re-arrange budget, no-Qt import test (`tests/test_capa_view.py`)
- [ ] Not done here (CAP-6a, needs the GUI registry): Qt model/view with the `data()`-call budgets, tooltips, offscreen state tests, 20x repeat

### [D1:diec-hardening]
- Done: adapter hardening (nested, empty result, heuristic marks, 57-name table, installer flag, memory cap function). Open: runner wiring of the diec memory cap (integrator), live goldens replace the hand-authored fixtures (G-L1).
### [D2:pe-build-facts] PE build facts (2026-10-14, Sonnet 5.5, worktree)
- [x] Rich (stdlib, bounded, equals pefile 2024.8.26 on generated headers), header version fields, debug entry types, LoadConfig GuardFlags/cookie, CLR header, runtime families, `collect_build_facts`; hypothesis never-raise
- [ ] Not done: 2 s per-side wall-clock budget (reads are small and bounded; cancel is polled per stage); `docs/specs/pe-overview.md` "Build facts" section and "Not done" update (D-amendments, integrator); WBQ S3 consumers
### [SPEC-07-hit:derived-cache-hit]
- [x] Hit path 1.92 s -> 1.44 s at 10,000 pairs (lean cache payload via exclude_defaults + cached TypeAdapter; inlined scalar canonical-JSON fast path). [ ] 500 ms objective still open: build_views ~0.75 s, rank ~0.6 s, input_digest/_locations_owned ~0.35 s remain (see docs/qa.md).

### [CAP-4:capa-cache]
- [x] `intelligence/tools/capa_cache.py` (lookup, store, fetch_or_run) with tests. [ ] Runner wiring (profile `cache_dir`, `capa_cache.fetch_or_run` around the spawn) is an integrator ask.
### [CAP-5:capa-cli]
- [x] `intel-tools pairs` (--engine, --change, --namespace, --include-noise, --include-library, --show-features, --show-secrets, --json), probe rules label, `PT-TOOL-PAIRING` exit mapping, `capa-pairs/1` schema entry.
- [ ] Not done: `--hypothesis CVE-ID` (needs CAP-7 `capa_hints`); `cli_commands/pairs.py` adapter and `frozen_smoke.py` import (integrator).
### [WB1:S3:sources-build]
- [x] Sources v1 (`fn`, `raw`, `pe:<side>`, `ann`, `fnd`) and build orchestration; determinism under permutation and incremental == from-scratch tested. [ ] Live gate: the `strings`/`symbols` shape of a real Ghidriff JSON (the `raw` reader fails closed on any other shape); `name_matches` of unchanged functions stay unindexed until then.
### [WB3-S4:strings-links]
- [x] WB3-S4 L1/L4/L5 links and literal segmentation (`strings/{clit,links}.py`); synthetic Ghidriff-shaped fixture `tests/fixtures/strings/pdiff/`
- [ ] Not built here: edited-pair detection (belongs with the S5 delta), L2/L3/L6 tiers (need IR or capa), Ghidriff `strings` loader wiring in the service layer
### [G2:callgraph-snapshot]
- [x] Contracts, project input, raw matches, resolver, pair map, snapshot (GL-01 enforced), bounded queries; G0 fixtures moved to the repo's list-of-targets `matches` shape. [ ] Live gate: one real Ghidriff JSON must confirm `name_matches` (only `address_matches` is read by other repo code). [ ] G3 deltas, noise, hints; G4 CLI/DOT.
### [G7:callgraph-evolution]
- [x] Pure evolution model, pair view and lineage builder. [ ] CLI `graph series`, composition (read pair projects read-only via nway PairReader, close each) and `ui_calls_evolution.py` tab wait for G4 and the GUI panel registry.
### [D3:buildenv-core] Build-environment core (2026-10-14, Sonnet 5.5, worktree)
- [x] Contracts, fingerprint, delta, pre-flight, `noise-map/1`, anchors, copy deck, view model, schemas in `docs/schemas/build-environment/`, synergy test on the committed real diec 3.21 goldens, `quality_flags` parity.
- [ ] Not done: store, CLI, report (D4); card, controller, tooltips (D5); overlay wiring (D6, reuses `noise_map.row_effect`/`order_rows`); timeline (D7); DiE golden for the UPX image (live gate D8); G-DIE-1 (D9). `buildenv/auto_diec` and `confirm_before_run` settings belong to D5.
### [WB3-S5:strings-delta]
- [x] WB3-S5 basis rules, delta, edited pairs, review tiers (`strings/{basis,delta,edits,rank}.py`); `SYN-WB3-1` on SYNTHETIC inputs (`tests/fixtures/strings/synergy/`)
- [ ] Not built here: anchor join (`StringsDelta.anchors`, S6), `format-spec` as an `EditRef.kind` value (reported as a reason instead; needs a contracts addition), real FLOSS/Ghidriff goldens (S9)

### [D6:overlay]
- [x] Pure overlay and tests (100k rows). [ ] S4 wiring: `build_tag` on `UnifiedRowView`, partition, navigator notice.
### [G3:callgraph-deltas]
- [x] Deltas, hub registry, API hints, groups, blast/entry, paths, leads; section 5 known answer reproduced (P first, L hub-only, 3 of 5 `called` flags cleared). [ ] Live gate: real Ghidriff label forms (`name_matches`, import labels) still unconfirmed; fixtures are synthetic. [ ] G4 CLI/JSON/DOT and a composition-root `EntryPort`/hint source.
### [K3:kbcorrelation-service] KB-CVE correlator K3 (2026-10-14)
- [x] components (tier D/E), manual pairs (grade B/X, KB9 copy), local plan, documentary context (stated CWE -> curated hypothesis, unknowns, limitations), JSON/Markdown export, `KbService`, production `ProjectPort`, `kb` dispatcher (`index`, `search`, `products`, `components`, `pairs`, `import-pair`, `plan`, `attach --repair`, `explain`, `export`); `cli_index` moved onto `WorkspaceStore`; offline E0 script steps 1-4 and 6 incl. SIGKILL at five crash points then idempotent repair; banned-word sweep
- [ ] NOT done / open: step 5 (`rank` then `kb leads`, slice K4a); the 6-line `patchtrace/cli.py` hook (integrator); CSAF applicability report in the context; `kb attach` to a foreign project (W3); `kb plan`/`kb pairs` need K5; KEV adapter (K8); `ContextBundle` JSON schema; Windows CI run of the new tests (subprocess kill uses `os._exit(137)` there)
### [WB1:S4:service-rank]
- [x] Query engine, ranking, pair expansion, fuzzy and `SearchService`; synergy test (`test_container_size_beats_each_channel`), permutation-stable order, 100k-document and 100k-name timeout gates, cursor bound to index key and plan, too-broad cap. [ ] Not done: tool/advisory/IR sources (S8/S9) feed the service through `extra_specs`; `Evidence.seen_by` lists one origin (no cross-group corroboration); no `representation changed` change class 1 signal; unified summary, tool delta and series stay empty with a stated limitation.
### [D4:buildenv-store-cli-report] (2026-10-14, Sonnet 5.5, worktree)
- [x] `build-env` store with `test_old_reader_ignores_build_env_kind`; CLI `show`, `delta`, `timeline` (mounted on a local parser in tests); report section with injection fixtures.
- [ ] Not done, integrator seams: `KINDS += 'build-env'`, the <= 6 line `cli.py` hook and `_command_name`, `reports.py` extras parameter that calls `buildenv.report`, `artifact_inspection.py` side-inspector seam. CLI does not persist fingerprints (the GUI card writes them, D5). Timeline verb reports per-hop toolchain only; the strip model is D7.

### [WB3-S7a:strings-view-model]
- [x] View-model, copy and tooltip entries with tests. [ ] S7b Qt panel (needs the GUI registry); [ ] `tooltips.register_entries()` hook (A7).

### [G5:view-model]
- [x] Pure view models and tests (`tests/test_callgraph_view_model.py`).
- [ ] `ui_calls.py`, `ui_calls_tips.py`, `tests/test_ui_calls.py` after F5.

### [WB3-S6:anchors-export-cli]
- [x] Anchors, search rows, export, CLI dispatcher and tests (synthetic pair, built-in scan). [ ] Integrator: 6-line `cli.py` hook, `frozen_smoke` check of `strings scan --builtin --json` (A8, A13). [ ] Not built: derived-cache storage of tables and deltas (recomputed per call), Ghidriff `strings` input to the CLI (L1 links need it), review-order boost from anchor hits (by design none).

### [K6:kbcorrelation-cvrf-fetch] KB-CVE correlator K6 (2026-10-14)
- [x] `cvrf_fetch.py` and `cli_online.py` with 49 hermetic tests (fake opener, sockets denied): consent equality and `plan_sha`, offline refusal, 429/5xx/Retry-After, 32 MiB cap, cancel (between months, mid-read, in a retry wait), hostile redirects, wrong-month document, partial coverage exit 3.
- [ ] Integrator: route `kb index sync` to `cli_online.main` in `kbcorrelation/cli.py` (hook text in the `cli_online` docstring); the live MSRC URL shape, document size and rate limits stay unverified until probe L1.

### [WB1:S5S6:search-cli-view]
[x] S5 search CLI and S6 view model (no widgets). [ ] Open: integrator hooks (cli.py, frozen_smoke COMMANDS, tooltips merge); Qt panel `ui_search.py` and `test_search_{ui,perf}.py` (instance D); `HitDelegate` highlight uses `ResultRowView.spans`.
### [G4:callgraph-cli]
- [x] CLI dispatcher, DOT and JSON export, schemas and drift test; G7 `graph series` verb (read-only pair projects, missing pair = unknown, exit 3). [ ] `cli.py` hook (`COMMANDS`, `_command_name`, `register` call) and a `cli_commands/graph.py` adapter once F1b lands. [ ] Live gate: DOT opened in a real Graphviz (never executed here); real Ghidriff label forms.

### [K5:kbc-lineage-resolver] KB-CVE correlator K5 (2026-10-14)
- [x] additive `winbindex.parse_rows` (md5-only and shared-KB rows kept, BASE, heading class), `kbcorrelation/{lineage,resolver}.py`, synthetic fixtures, tests incl. the grade property
- [ ] open: wiring `IndexPort` and `kb pairs`/`kb plan` to `resolve` (integrator, K7); live check of the heading classes and `otherWindowsVersions` on a fresh record (needs the Winbindex host)

### [K4a:kbcorrelation-leads] KB-CVE correlator K4a (2026-10-14)
- [x] `leads`, `cli_leads` (`kb leads PROJECT [--cve] [--limit]`), `view_model`; E0 synergy golden `tests/fixtures/kbcorrelation/expected/synergy-leads.json` (baseline scores 26/25, 36/25, 36/35 reproduced); KEV never reorders functions; contested stays contested; stale on swapped orientation; lineage counts once.
- [ ] NOT done / open: `patchtrace/cli.py` `kb` hook (integrator, see K3); run id in the stale fingerprint (needs the context row to record it); KEV, unified and secondary adapters (K8: `RealEngine` moves to `adapters/engine.py`); unified MAT-ANCHOR and anchor-coincidence membership; `.gitattributes` line for `tests/fixtures/kbcorrelation/expected/*.json`.
### [K5w:pairs-plan-glue]
- [x] K3/K5 glue: `kb pairs` / `kb plan` over the offline file index; tests `tests/test_kbc_pairs_index.py`.
- [ ] `kb index import` accepting a Winbindex record (today the file is placed in `<workspace>/winbindex/` by hand); E1 network `PairPlan`.

### [CAP-7:capa-hints]
- [x] Hint table + `capability_context`; inventory extractor; tests `tests/test_capa_hints.py`.
- [ ] Open: `rules-inventory-9.4.0.json` is DERIVED/UNVERIFIED (7 matched rules from the real goldens). Regenerate from the pinned capa-rules 9.4.0 with `--rules-dir`, then re-resolve the removed candidates (process-launch, privilege-identity, crypto-primitive, `load-code/*`) and restore only those that resolve.
- [ ] Open: `--hypothesis CVE-ID` in `intel-tools pairs` (not on the CAP-7 card; integrator or CAP-5 follow-up) can call `capability_context`.
### [K7:acquire-workflow]
- [x] Non-UI K7: `acquisition/workflow.py`, `kbcorrelation/acquire.py`, `tests/test_acquisition_workflow.py`.
- [ ] K7 UI (instance D): `ui_kb_online.py`, `tooltips_kb_online.py`; `kb acquire` CLI verb and `wiring` binding of `Acquirer` (integrator); dialog refactor onto the workflow (last).
### [S8:search-tool-advisory-sources]
- [x] WB1 S8: `search/sources/{tools,advisory}.py` (tool, advisory, CVE groups behind ports) with tests.
- [ ] Integrator: bind `extra_specs`, `comparable`, and a `cve-snapshot` reader to the real stores.
### [K7v:kb-acquire-cli]
- [x] `kb acquire` verb, `Acquirer` binding in `wiring`, `kb index import --winbindex`. Integrator: hook `kb` in `patchtrace/cli.py` (see `kbcorrelation/cli.py`) if not yet applied.
### [K1a:kev-core]
- [x] K0 fixtures and vendored schema; K1a pure core, tests `tests/test_kev_{contracts,parse,join,view_model,boundaries,schemas}.py`.
- [ ] K1b store, K2 transport/service/CLI, K3 GUI, K4 KB adapter, K5 project row/report, K6 live probe; A0 spec, A1-A12 integrator amendments (plan section 10).

### [K4:kev-kb-adapter]
- [x] `kev/kb_adapter.py`, `tests/test_kev_synergy.py` (items 1-8), `tests/test_kev_kb_integration.py` (fake edges).
- [ ] Open until KB K8: item 9 (`test_three_lanes_stay_separate_for_cve_2024_38063`), real KB view-model run, contextual_rank byte-identity.
### [F2:qt-runtime]
- [x] F2 Qt runtime built (tasks, settings, announce, metrics, runtime, qt_support, qt_gate); 20x gate green on Linux
- [ ] F2 open: Windows 5x gate and the integrator full-suite runs; `gui/__init__.py` is F1-owned (F2 relies on a namespace package until F1 lands)
### [GUI:framework] GUI framework plan amendments (2026-10-14; GUI-F0, documentation only)
- [x] GUI-F0: section 10 amendments applied to the docs it names (multi-engine-evidence-panel 1.8, 5.3.6, 8, 15 and new 17; unified-engine 07 sections 2, 8, 9, 10 and 01 line; ui.md paragraph; series-window and gui-preflight M3; workbench README and KB contract; modules, qa and acceptance rows; roadmap 5; phase-d 1; CLI lines of unified, KB and workbench-floss; the eleven sibling plans' CLI hooks, accessibility, shortcuts and placement). Code rows of section 10 are not in F0.
- [ ] GUI F1 to F9 not started. Order from GUI plan section 9: F0 and F1 (with F1b in parallel), then F2, then F3 and F4 with F2, then F5 (single owner of `ui.py`, `tooltips.py`, `tests/test_tooltips.py`, `panel_manifest.py`), then F6a, F6b, F7 and F8 in parallel, then F9.
- [ ] Manual gates M19 to M28 are `not-run`; the owner decides who records them (GUI plan open question 12). Not run here.
- [ ] Merge risk: open PRs #41 and #43 also edit `docs/specs/kb-patch-search-ui-cli-contract.md`, `docs/specs/workbench/README.md` and `docs/plans/workbench-search-graph-floss-implementation.md`; rebase these amendments onto whichever merges second.
- [ ] Open for the owner: the GUI plan status line was not changed by F0 (outside the section 10 exclusive list); per-track `ui.py` seam mentions not named in section 10 are flagged in the GUI-F0 report.
### [RG:release-gate] Release gate (2026-10-14)
- [x] `tools/release_gate.py` and the `release-gate` job: a prerelease at every third counted merge, `[release]`, a tag, no earlier prerelease; fail open; skip markers read from the whole message; the release notes carry the count and the reason
- [ ] Open, only GitHub can show it: the first real `main` push through the gate (`gh api` with the job token, the output hand-over, a skipped gate on pull requests skipping `release`, the notes line), the Windows run of `tests/test_release_gate.py`, and whether the merge that carries this workflow edit hits the known publish 403 (spec 1.1) if it is a publishing merge
### [F1b:cli-registry] GUI slice F1b, CLI-extension registry (2026-10-14, builder worktree; Linux evidence only)
- [x] `cli_commands` registry (89 lines), `cli.py` seam (net +3), collect hook, derived smoke and no-Qt `--help` lists, `tests/test_cli_registry.py` (57 tests, 1 opt-in); red first, then mutation-checked (24 one-line breakages, all caught)
- [x] Linux, Python 3.13.16 and 3.12.3: registry plus acceptance smoke 70 passed, 1 skipped; the 20 CLI-related test files 415 passed, 1 skipped (355 before the seam, +4 `--help` parametrizations, +56 registry); `ruff check` clean on the touched files
- [x] Opt-in real freeze, Linux (PyInstaller 6.22.3, Python 3.12.3 and 3.13.16): `patchtrace.cli` frozen from a tree copy with two fake verbs and this hook lists, runs and `--help`s the verb, shows the broken one as unavailable and exits 3; the same build without the hook answers `invalid choice` (exit 2)
- [ ] Windows CI, NOT verified here: `python tools/build_windows.py` with the new hook, `python tools/frozen_smoke.py` A1 over `names()`, `pkgutil.iter_modules` over the frozen PYZ on Windows (plan F19 marks it [U]). Until the first adapter file exists (F1 `cli_commands/panels.py`) A1 covers only the 11 built-ins, so frozen discovery of a real adapter is first exercised when one lands
- [ ] Integrator: nightly step `PATCHTRACE_TOY_FREEZE=1 python -m pytest tests/test_cli_registry.py -k frozen_cli -q` (about 25 s); `CLI_BASELINE_LINES = 869` in `test_cli_seam_budget` must equal the line count of `cli.py` before the seam when this merges; section 10 doc amendments incl. `docs/qa.md` L111 "all seven commands" (F0)
- [ ] Not built (plan 8.12): entry-point or third-party plugins, a `hidden` flag, migration of the built-in verbs (open question 16), a shared `--json` helper for adapters (not on the card)
### [WBQ-S4:pe-exports-api] WBQ slice S4 pe-exports-api (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] `pe_overview/exports_table.py` (`parse_export_entries`) and `pe_overview/api_delta.py` (`compute_api_delta`) with hostile-input tests first (forwarders, ordinal gaps, name-table loops, out-of-range RVAs, oversize counts); pefile oracle behind `importorskip`; 36 mutants all killed
- [ ] S5 (integration, not done here): call `parse_export_entries(ctx, smap, exp.rva, exp.size)` from `inspect.py`, add `ExportsInfo.entries` (default `()`) and OR its `truncated` into `ExportsInfo.truncated`; call `compute_api_delta` from `compare.py` for the row `Imports: APIs added or removed (n)` (status and reason map one to one, provenance is `PROVENANCE`); put the two warning codes `export_table_over_cap`, `export_name_table_loop`, `export_ordinal_out_of_range` into `docs/specs/pe-overview.md`; either move `ExportEntry` and `ApiChange` into `models.py` or import them under `TYPE_CHECKING` (importing at module level would be circular through `_common`); move the shared RVA-span helpers (`_readable`, `_read_span`, `_name_at`) from `imports_exports.py` to `_common.py`
- [ ] Observation for S5: the existing `parse_exports` still warns `export_count_implausible` for a valid alias table (more names than addresses) and reads a null name pointer as the DOS header text `MZ`; `parse_export_entries` does neither. Not changed here (frozen until S5)
- [ ] Integrator: `dev` extra needs `pefile==2024.8.26` for the two oracle tests (they skip without it); Windows CI run, Python 3.12 and real MSVC-built PEs are not covered
### [WBQ-S10:symbols-decoration] WBQ S10 symbols-decoration (2026-10-14, Sonnet 5.5, worktree; Linux)
- [x] `symbols/{__init__,kinds,decoration}.py`, `tests/test_symbols_decoration.py` (180 tests plus one optional decoder oracle) and `tests/fixtures/wbq/ms_kat.{tsv,NOTICE,LICENSE.TXT}` (59 pairs from the LLVM Demangle tests); focused tests and ruff green, 18 of 18 deliberate defects caught
- [x] Checked against LLVM's own demangler (pydemumble 0.1.3, scratch venv): 59 of 59 outputs identical and no disagreement on 1,083 corpus names, 300,000 mutations and 250,000 generated back-reference chains (docs/qa.md)
- [ ] Integrator: `.gitattributes` line `tests/fixtures/wbq/** text eol=lf` (the test refuses a CRLF `ms_kat.tsv` and compares the licence copy by SHA-256); optionally `pydemumble==0.1.3` in a `dev` or `symbols` extra so the oracle test runs in CI instead of skipping
- [ ] Not built (other slices): S11 readable names behind the capped worker, S12 dbghelp, S13 `SignatureChange` with its toolchain flag, Itanium, Rust and RTTI qualified names, a Pydantic contract once FAB exists
- [ ] Not run here: Windows (LF handling of the fixtures) and the Linux-versus-Windows decoder equality on the known answers (S11)
### [PIL-B1:rules] Patch-intent rule table (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s7, s9)
- [x] `pilot/rules/{contracts,data,evaluate}.py` and `tests/test_pilot_rules.py` (261 tests): closed leaf vocabulary, validation with `PT-PILOT-RULES` reasons, versioned digest (`pilot_rules_digest()`), 22 rows for all K rules, three-valued evaluation of expected changes; gates `test_every_k_rule_has_expected_changes`, per-family positive and negative fixtures (ids = family names), `test_cwe_detector_map_consistent_with_rules`
- [ ] Open for PIL-A3 and PIL-B2: the carrier of `Evidence.level` (B1 signal confidence) and `Evidence.subject` (API name, capability namespace) on an `Observation` (A1 has no field for either); the 14 rows with `PilotRule.detectors == ()` are the ones plan s7 holds at tentative unless two components agree; B2 reads `Evaluation.conflict_ids` to force `contested`
- [ ] Owner: the plan s9 PIL-B1 card still says "20 K rules" and asks for K edits that audit C already made (CWE-193 lives in its own family `off-by-one`, not under `bounds`); the two extra rows (R-FORMAT-STRING, R-OFF-BY-ONE) and INPUT's `BND` leaf are decisions beyond the draft table; `next_step` sentences are not part of the table (read model, C2); A1's `keys.DOMAINS` does not list `pilot-rules`
- [ ] Not done: capa namespace rows (empty in v1 until CAP validates its tags; a later additive revision changes the digest and makes stored results stale); Windows and Python 3.12 CI for `tests/test_pilot_rules.py` (3.12.3 verified locally in a venv)
### [K1b:kev-store]
- [x] K1b snapshot store `kev/store.py`, tests `tests/test_kev_store.py`.
### [K2:kev-transport-cli]
- [x] K2 transport, service and Qt-free CLI `kev/{transport,service,cli}.py`, tests `tests/test_kev_{transport,service,cli}.py`.
- [ ] Integrator: `kev` hook in `cli.py` (see docstring of `kev/cli.py`); K6 live gate must verify the canonical CISA URL and User-Agent acceptance before it is called verified.

### [PIL-A2:advisory-sources] Patch-intent localization advisory-side adapters (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s9)
- [x] `pilot/sources/{advisory,identity,kev,window,snapshot}.py` and `tests/test_pilot_sources_advisory.py` (K report adapter, CVE gate, KEV port with absence as context, confounded window, pairing verdict map, B3 snapshot and excerpt as K facts); gates `test_cve_gate_table` (35 rows plus a 1,350-combination oracle), `test_kev_absence_is_unknown_context`, `test_unified_beats_secondary_for_identity`, `test_confounding_counts_cves_fixed_on_newer`, every `detail` passes `sanitize_text`
- [ ] Integrator: `pilot/sources/__init__.py` is created by PIL-A2 and PIL-A3 alike (keep one, a docstring only); add `status(self) -> ChannelStatus` to `ports.AdvisorySource` (`StoredAdvisorySource.status()` already provides it, so a partial advisory load is not read as complete); decide whether `KbWindowSource` moves into `ports.py`
- [ ] Next: PIL-B2 consumes `AdvisoryContext`, `kev_context`, `confounding` and `cve_context`; PIL-A3's pairing adapter calls `identity.pairing_identity(unified=..., secondary=..., unified_current=...)`; PIL-T builds its CSAF fixture through `StoredAdvisorySource` or `context_from_report`
- [ ] Open: the KEV track implements `ports.KevSource` (or fills `CatalogKev` with a snapshot id and `{cve: date_added}`) and the KB track `KbWindowSource` (both ports only, fakes in the tests); KEV `cwes` as one more vendor-text repetition needs an additive port field; real MSRC CSAF and NVD/MSRC snapshots through the adapters (BLOCKED as K, no live data here); Windows CI for the new tests
### [WBQ-S7:codetext-core] WBQ slice S7 codetext-core (2026-10-14, builder worktree, Sonnet 5.5; Linux only)
- [x] `codetext/{__init__,tokens,names,palette}.py` and `tests/test_codetext_{tokens,palette}.py` (306 tests): lossless and total on any text (hypothesis, 5 seeds), Pygments dev oracle, every text role >= 4.5:1 and every mark >= 3:1 on the three backgrounds, the printed colour-blind distances reproduced with the validated Machado matrices, 200 KB in 57 ms (gate 150), hostile corpus, windows of lines equal the document scan
- [ ] Next in the WBQ chain: S8 (`operands`, `intraline`, `model`, `oracle`: `OperandClass`, `Mark`, `FormatSpan`, SYN-WBQ-1), then S9 (highlighter, `compose_selections()`, the `ui.py` seam, F8, tooltip ids, Setup rows). The model must convert offsets to UTF-16 for Qt and feed `QTextBlock.text()` (docs/modules.md [WBQ-S7:codetext-core])
- [ ] Integrator: amendment 4 (`facts/pseudo.py` imports its patterns from `codetext.names`; `TEMP_NAME` equals its locals pattern, `AUTO_NAME` is a superset, run `test_algorithm_digests.py` after the swap), the WBQ rows of docs/modules.md, optional dev dependency `colorspacious==1.1.2` (MIT) so the one test that proves the colour-vision simulation runs in CI instead of skipping, a `patchtrace.codetext` import check in `tools/frozen_smoke.py` (frozen for this slice)
- [ ] BLOCKED, owner and CI only: Windows CI (this slice ran on Linux, CPython 3.13.16 and 3.12.3 in a throwaway venv), the 200 KB budget on the Windows runner, NVDA and Narrator announcement of the "Line changes" label, 125/150/200 % DPI, Windows high contrast, bold advance width in Consolas, `ShowDefaultIgnorables` glyphs, the assembly path on real SPEC-31 `insns.text` (name and register forms were checked against Ghidra's `SymbolUtilities` source, not against a real listing)
### [PIL-T:oracle] Patch-intent oracle (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s5, s9)
- [x] `tests/fixtures/pilot/synergy-1/` (generator, two CSAF, ledger, expected, README), `tests/pilot_synergy_support.py`, `tests/test_pilot_synergy.py`, `tests/test_pilot_sample_e2e.py`: 40 pass today (fixtures are valid pilot/1 and K input, tables equal plan s5 verbatim, byte-stable LF goldens, fake ports obey the A1 Protocols) and 22 are `xfail(strict=True, reason='PIL-B2', raises=EngineMissing)`; no shared file touched (`.gitattributes` already pins `tests/fixtures/pilot/**` to LF)
- [x] Executed against an uncommitted reference engine (one reading of plan s7, not part of the repository): all 22 engine tests pass with the markers ignored and report XPASS(strict) with them; 12 injected defects (repeated advisory counted as independent, B1 and ChangeFacts as two witnesses, call labels as a third witness, no window cap, no toolchain cap, KEV ordering functions, RVA as tie-break, nuisance ignored, contested pairing not last, a tool that did not run read as a negative vote, two tier-raising behaviours) each fail at least one test
- [ ] PIL-B2 owner: land `patchtrace.pilot.service.localize`, adapt `localize()` in the support module if the input bundle differs, then remove the `PIL_B2` marker (one constant); a plain assertion failure is a real divergence from plan s5/s7: fix the engine, or amend the plan and `generate.py` together (a test compares the committed cells with the plan text)
- [ ] Not asserted because the plan is silent: the order inside a rank block (partial, queue), `fits` and mechanism of queue rows, the rendering of the "why" text (needs `pilot/why.py`; its facts are in `expected.json`), the `limitations` of contexts, the exact `unknown_ids`
- [ ] Open until B2 is green: the PIL-T gate "section 5 tables reproduced exactly" (plan s9); Windows CI for the two files (LF, short ids and the subprocess hash-seed check were written for it, not run there)
### [PIL-A3:code-adapters] Patch-intent localization code-side adapters (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s9)
- [x] `pilot/sources/{pe,code,calls,tools,unified}.py` (+ docstring-only `__init__.py`), `tests/test_pilot_sources_code.py` (159 tests; gates `test_cosmetic_proof_becomes_conflict`, `test_capa_unlocalized_never_attaches`, `test_floss_static_string_never_attributed`, `test_label_only_calls_cap_verification`); no shared file, schema, dependency or persisted contract touched
- [x] Ports implemented: `PairingSource` (`GhidriffPairing` with secondary-engine identity, `UnifiedPairing`), `ChangeEvidenceSource` (`B1Evidence`, `UnifiedFacts`, `CodeEvidence` with the "text evidence only" ceiling when typed facts are absent), `CallDeltaSource` (`GhidriffCalls` + PE import delta), `ToolEvidenceSource` (`ToolDeltas` over T's `ToolDelta`/`ToolRun`, `not-run` until a result is supplied); vocabulary table in docs/modules.md
- [ ] PIL-B2 wiring: choose the universe (`UnifiedPairing` only for a `current` unified result, else `GhidriffPairing` with the secondary sets; never both), always build `GhidriffRows` (B1 signal sets and call labels find their candidate through it), pass `pe.address_map` from the two verified artifacts, load tool results/unified result/secondary sets on the owner thread (nothing here opens the project database)
- [ ] PIL-B1/B2: B1 confidence is not on the observation (it is the detector's, `enrichment.signals.DETECTORS`); a `review` row's shape observations carry obligation `second-channel`, a `material` row's none (use it for the "no anchored second channel" order key); `cf:` observations of an S0 unified result are decompiler- and name-relative (the code channel says so)
- [ ] Overlap with PIL-A2 to reconcile at integration: its `identity.py` "pairing verdict map" and this slice's `IDENTITY_OF_DECISION` (`sources/unified.py`) / `IDENTITY_OF_VERDICT` (`sources/code.py`) are the same s7 table; keep one. The shared helpers `build_observation`, `channel_status`, `settle`, `lookup` live in `sources/code.py` (the card names five files only); a shared module is the cleaner home
- [ ] Not built (card fallbacks and non-goals): IR call keys (typed calls); loading from the store; `loc:names` (locality is computed by B2); capa namespace rows (empty in v1, so capa stays context); SPEC-30 status line and the s10 amendments are owner items and were left untouched to avoid a four-way conflict between A2, A3, B1 and T
- [ ] BLOCKED, live evidence: real Ghidriff callee labels (namespaces, thunks, EXTERNAL names), real capa/FLOSS/DiE deltas and a real unified result with ProgramIR; everything here was tested on synthetic data and T's/unified's own code on synthetic inputs
- [ ] Windows CI for `tests/test_pilot_sources_code.py` (it spawns one Python child for the import-purity check and writes unified result directories with `os.replace`); Python 3.12.3 was run locally and passes
### [R0:rules-contracts] YARA-X rules R0 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] limits, errors, contracts, ports, 26 schemas with valid and invalid examples, `tests/test_rules_contracts.py` (card numbers and codes pinned, hostile text, cross-field rules, ports, purity); the card's contracts are validated for internal consistency (rule hash, `PT_<lineage12>_<dir>`, metrics, separation, cells row-major), so a record cannot lie about its own numbers
- [x] Decisions beyond the card: the port `PairSource` is `PairLookup` (the record keeps the name); features carry `kind` and `included`; `MatrixRun` gains `rules` (columns) and `finished_at` (the export header's "Tested <UTC>"); `CellResult.hits` is `None` for any file without a scan result; worker `LintResult`, `Diagnostic`, `WorkerLimits` and `WorkerError` records
- [ ] Open: id derivations (`candidate_id`, `lineage_id`, `version_id`, `cache_key`) are shape-checked only; the producing slices (R3, R5) own them. Readers that must ignore unknown fields of a newer client (plan s7) need a tolerant-reader step in R5's store because the models forbid extra fields. `ports` signatures are provisional until R3-R6a land
### [R2:rules-engine] YARA-X rules R2 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] Engine facade, hidden worker, runner; the grid of 12 targets (readable, rebuilt at another layout, not a PE, missing, too large, changed hash, changed size, a directory, empty, truncated) against 3 rules (bytes, import-only, a rule that fails its lint) through a REAL worker child equals a golden table; `test_parent_never_imports_yara_x` and `test_worker_baseexception_exit_23` and `test_worker_timeout_kills_child_tree` pass; 422 passed in 21 s (294 contracts, 42 engine, 86 worker)
- [x] Measured on Linux: worker start from source about 0.5 s (probe 0.68 s, lint 0.51 s, 3-target scan 0.51 s; mostly pydantic and the contract models); RLIMIT_AS with a 32 MiB target: 64 MiB ends as a Rust allocation abort, 128 MiB as an ENOMEM panic caught as BaseException, 192 and 256 MiB as MemoryError, 384 MiB scans; a 120 MiB target scans at 512 MiB, so the 1 GiB default leaves room for the 128 MiB file limit. YARA-X's timeout ticks once a second on its own grid: a limit of T seconds aborts a scan between T-1 and T seconds after it starts (the plan's "1.00 s" was measured at an aligned start)
- [ ] BLOCKED / open (CI or the owner): all Windows legs (the Job Object memory limit counts commit, so the OOM failure mode is a measured unknown U7; start-up time; Defender, EDR or Arbitrary Code Guard against the engine's JIT, which `probe` reports as state R1); the frozen build (hook, `rules _rules-worker` verb, `frozen_smoke`); `iced_x86` is not installed here, so the probe's decoder stamp is tested with a stand-in module only (R4 owns the real adapter)
- [ ] Integrator asks: see the R2 report (pin `yara-x==1.21.0`; `rules _rules-worker` CLI adapter; hook-patchtrace.rules.engine.py; frozen_smoke R1/R2 checks; `optional_deps.py` imports `yara_x` eagerly, which would load the extension in any process that imports it)
### [WBQ-S1:pe-rsrc] WBQ S1 PE resources and version info (2026-10-14)
- [x] `pe_overview/resources.py`, `version_info.py`, `tests/pe_rsrc_builder.py`, 109 tests; equal to pefile on builder PEs and on 16 real third-party PEs; primary block equal to `csaf.identity`; every listed hostile case at least 5x under 250 ms; 30 of 30 mutations killed
- [ ] Not wired: S5 owns `models.py`, `inspect.py`, `compare.py`, `__init__.py` (new `PeOverview` fields, stages, comparison rows, exports); `csaf/identity.py::read_version_info` moves onto `version_info` after S5 (amendment 7)
- [ ] Open: an entry is a name or an id by the high bit of its first dword (as pefile and `csaf.identity` decide); the Windows loader may decide by the declared name/id counts, so a lying directory could show different resources to the loader. Not verified against Windows. Real Microsoft PEs were not exercised here
### [WBQ-S2:pe-manifest] WBQ S2 PE manifest (2026-10-14)
- [x] `pe_overview/manifest.py`, 141 tests; DTD and entity payloads refused in all six encodings; caps (2 MiB per manifest, 16 MiB read in total, 16 manifests, 256 list items); 34 of 34 mutations killed
- [ ] Not wired: S5 (`PeOverview` field, `inspect.py` stage, `compare.py` rows, exports). Rows for S6/S13 come from `ManifestObservation`
- [ ] To confirm with the owner: only braced GUIDs count as supportedOS; a DTD token inside a comment or CDATA also refuses the manifest (conservative); leading whitespace before the XML declaration is invalid; trailing NUL padding is dropped. Windows' own tolerance for these was not verified
- [ ] Open: the frozen Windows bundle's libexpat version is unrecorded; the refusal of DTDs does not depend on it
### [FAB-0:fabric-core] Anchor fabric pure core (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s7, s9)
- [x] `docs/specs/program-e/FAB-integration-plan.md` (156 lines, tables pinned to the code by `tests/test_fabric_plan.py`); `fabric/{limits,contracts,ids,origins,ports,memory}.py`; `tests/test_fabric_{contracts,ids,origins,memory,synergy,plan}.py` and `tests/fabric_support.py` (331 tests; gates: independent oracle and pinned goldens for the identity formulas, `pair_key` parity with `unified.keys.row_id` and `pilot.keys.candidate_key`, `components` parity with `pilot.origins`, the synergy scenario, a 71-mutation check); contract `fabric/1` frozen additive-only
- [ ] Integrator asks: add `anchor-batch` to `enrichment/storage.py` `KINDS` for FAB-1 and `anchor-pin` for FAB-4 (neither in `DERIVED_KINDS`, no `extension_version` bump); apply the plan s10 amendments (GUI `AnchorRef` row and Q1, GDE s7.6, KB s4 and Q9, PIL s4, CAP s4, DIE s7, WB1 s4, YRX `Anchor.kind` row, KEV Q15, `multi-instance-coordination.md` s4); registry data additions (CAP lineage, KEV, WBQ, WB3) as one FAB PR each; no `.gitattributes` line (no fixtures)
- [ ] Next slices: FAB-1 store and schemas, FAB-2 converters (K `Anchor`, `PilotAnchor`, DIE `BuildFactAnchor`), FAB-3 PIL rebinding of `pilot/origins.py` and `pilot/ports.py`, FAB-4 `PinPort`, FAB-5 `fabric` verbs (after GUI F1b), FAB-6 `related` panel (after GUI F5)
- [ ] Not verified: Windows and CI; the frozen smoke (nothing imports `patchtrace.fabric` yet); the 20,000-anchor timings on Windows
### [K1a:kev-core] KEV K0 fixtures and K1a pure core (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K0: `tests/fixtures/kev/` (12 real CC0 entries of catalog 2026.10.13 copied verbatim and pinned by SHA-256, the synthetic 2099 catalog of plan section 5), `docs/schemas/kev/upstream/` (CISA's draft-07 schema, byte for byte, pinned)
- [x] K1a: `kev/{contracts,limits,parse,join,view_model,ports,teach,tooltip_entries}`, `tools/generate_kev_schemas.py` with `docs/schemas/kev/*.json`, six test files plus `tests/kev_helpers.py`: the ten gate tests of plan section 9 and the hostile-input, golden, identity, property and boundary tests (415 tests, mutation-checked)
- [ ] OPEN for the integrator (shared files): `.gitattributes` lines for `tests/fixtures/kev/**` and `docs/schemas/kev/**`; the A0 spec `docs/specs/kev-exploitation-context.md` is not on the base (the plan was the card); A2 tooltip registration (a module-level `REGISTRY.update(KEV_TOOLTIPS)` at the end of `tooltips.py` would be circular because `kev.tooltip_entries` imports `TooltipEntry` from `tooltips`: register through the F5 `PanelSpec.tips` or a lazy hook); A5 ASCII-only CVE patterns in `intelligence.py`, `cve.py` and `contracts.py` (plan F18, still on the base); A10 notice (CC0, "not endorsed by CISA or DHS"); the `kev.action` tooltip names Ctrl+Shift+X (GUI plan 8.2) where the KEV plan said Ctrl+Shift+K
- [ ] NOT built here: K1b store (next), K2 transport, service and CLI, K3 GUI, K4 KB adapter and synergy test, K5 project row and report, K6 live probe. The canonical `www.cisa.gov` feed URL stays unverified until K6 (this sandbox reaches only the GitHub mirror)
### [K1b:kev-store] KEV K1b snapshot store (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K1b: `kev/store.py` and `tests/test_kev_store.py` (56 tests): the five gate tests of plan section 9 (`test_install_crash_points_keep_previous_current` with six crash points, `test_older_mirror_never_replaces_newer_current`, `test_damaged_current_falls_back_and_says_so`, `test_replace_retries_on_permission_error`, `test_prune_only_when_asked`), install order, hash before parse, gzip bomb, shrink guard, pointer disagreement, status, location and a Hypothesis interleaving property; 27 one-line mutations killed
- [ ] OPEN for K2 (service and CLI): install from one process at a time (no lock, see `docs/modules.md` `[K1b:kev-store]`); pass a UTC `now` such as `2099-03-02T08:00:00Z`; show `InstallResult.outcome` (`kept-newer`: the mirror was older, the newer catalog stays in use) and `Loaded.notes` as they are; `kev prune --keep N --yes` calls `prune(keep, yes=True)` (the status warning already names that command); map `KevError.code` through `EXIT_CODES`
- [ ] NOT built here: K2 transport, service and CLI (next), K3 GUI, K4 KB adapter and synergy test, K5 project row and report, K6 live probe

### [FAB-2:converters] Anchor converters and registry rows (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s9, s10)
- [x] `src/patchtrace/fabric/convert.py` (`from_k_anchor`, `from_pilot_anchor`); `fabric/origins.py` FAB-2 rows (`kev-catalog`, `pe-self-report`, WB3 `emulation` and `ir`) and tags `D_kev`, `D_pe_self_report`, `D_emulation`; `tests/test_fabric_convert.py` (27 tests); the golden digest and the module list in `tests/test_fabric_{origins,contracts}.py`; the status line of the FAB plan.
- [ ] Owner decisions to confirm: the WB3 `ir` row takes Ghidra's origin until IR producers are recorded per key; K hypothesis-rule hints count as `advisory-text`; DiE's Rich facts join `pe-self-report` only through a DiE row when `BuildFactAnchor` lands; CAP lineage (`capa` keeps `D_vivisect`) waits for CAP-7 (plan s11, question 3).
- [ ] Integrator asks: none. No shared file was touched (`KINDS`, `.gitattributes`, `cli.py`, `ui.py` and the rest of the frozen list are unchanged); the golden digest moves with the four rows, as plan s10 requires.
- [ ] Next: FAB-3 (PIL rebinding of `pilot/origins.py` and `pilot/ports.py`, PIL owner) and FAB-1 (store over `anchor-batch`; the integrator edits `KINDS`).
- [ ] Not verified: Windows and CI; the full suite (the integrator runs it); the DiE `BuildFactAnchor` (not built).
### [GUI-F1:core] GUI framework F1: pure core (2026-10-14)
- [x] gui text, theme_math, shortcuts, capabilities, state, projection, anchors, ports, registry with lint and loader, cli; panel_manifest with the 14 slots; 13 test files, 507 tests (hypothesis on `sanitize_text`, ids and manifest; no-Qt subprocess; exits 0/2/3/4/5): docs/qa.md [GUI-F1:core]
- [ ] Integrator: add `cli_commands/panels.py` (about 12 lines, adapter text in the F1 report) once F1b is merged; then `patchtrace panels check` joins the feature-PR gate (it exits 4 until the first panel is built)
- [ ] Open for the next slices: F8 re-exports `ui_evidence.contrast_ratio` from `gui.theme_math` and moves the `evidence.*` tips into `PANEL.tips`; F4 and F6 give `ColumnSpec`, `TableSpec`, `PreparedTable`, `PairText`, `GraphNodeView`, `GraphEdgeView` pure homes; the panel module paths for the slots the plan does not name may need a one-line manifest edit each
- [ ] Not verified: Windows CI, the frozen build (PyInstaller sees 14 function-level imports of modules that do not exist yet and will warn "missing module", not fail), the full suite twice
### [AI-FIX:ai-provider-fixes] AI provider and interpretation fixes (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] SPEC-41 R11: every IPv4-mapped IPv6 endpoint literal is refused on CPython 3.12 and 3.13 (it was rejected on 3.12 and accepted on 3.13); R18 and audit RA-7: a key that is not printable ASCII (a euro sign, an accented letter, a no-break space) is rejected by the constructor with fixed text instead of failing after connecting
- [x] SPEC-41 R33: `BadStatusLine` and every other transport exception now come back as `PT-PROVIDER` with fixed text from `request_completion` and `interpret()` (HTTP status, TLS, `http.client` errors, OSError and timeouts, malformed envelope, anything else by class name)
- [x] SPEC-41 R14 and R7: the 120 s deadline and Cancel now end a blocked connect or body read. Found while testing: Cancel during a stalled body read waited for the whole socket timeout (4.07 s of 4 s in a scaled real-stack run, so up to 120 s in the app)
- [x] SPEC-41 R29: a finding that names a CVE, CWE or CVSS claim absent from the context is quarantined, not the run; all findings quarantined makes the run `failed`
- [x] Tests for SPEC-41 G1 to G10, G12 and G17 in `tests/test_providers_endpoint.py`, `tests/test_providers_transport.py` and `tests/test_interpretation.py`
- [ ] Open in SPEC-41: R12 unknown-kind message, R15 request-body cap, R25 prompt and response version digests, R26 alternatives need support, R28 CWE catalogue (format only, Q6), R34 to R37 export rules, G11, G13 to G16, G18 to G20. Live Ollama and OpenAI-compatible acceptance (line 9) is untouched and still open
- [ ] Observed, not changed: a non-ASCII character in the path of an endpoint passes `validate_endpoint` and fails at send as `transport failed unexpectedly (UnicodeEncodeError)` (classified and safe, but cryptic); a non-ASCII host fails as a connection error
- [ ] Integrator asks: `ui.py` shows `run.error` only for failed runs, so the note on a completed run that dropped some findings is visible only in the raw-response dialog and the JSON export; the SPEC-41 sections 2, 4, 6, 7 and 8 and `docs/specs/architecture.md` lines 43 and 45 still describe the earlier behaviour
### [S5:residual] SPEC-31 S5 (2026-10-14, builder worktree)
- [x] Residual stage `src/patchtrace/unified/ladder/{blocking,assign,residual}.py`: blocking (tokens, MinHash bands, split-or-abstain buckets, top L-22 per direction), P16 reference vectors, P17 block votes, P18 layout gaps, P19 assignment with rejection (pure-Python LAP), `pass_table(residual=False)` = backup B-07, `table_digest()`; stages 5 and 6 through `PassSpec.run`, no file of the S2 ladder changed
- [x] Acceptance: `test_blocking_never_builds_full_matrix` (counters <= L-22 x pool, on a 300-per-side world and at 10k / 60k), G-U5 at 10k, at 60k and for an all-residual 60k world (`tests/test_unified_ladder_residual_perf.py`), precision per pass and tier reported (docs/qa.md), the 04 s9 residual tests by name (`test_refvector_mutual_best_with_margin`, `test_lap_reject_cost_leaves_function_unmatched`), the four properties with the stage on (permutation, side swap, never removes a tier M/A/B pair, budget prefix), hash-seed determinism, 73-mutant sweep (70 killed, 2 equivalent, 1 redundant line removed)
- [ ] Integration owner: (a) adapter `IrReader -> MnemonicSource` and `run_ladder(..., passes=pass_table(older=..., newer=...))` in the pipeline, with `table_digest()` as the `pass_table_digest` input of `config_digest`; (b) the policy that picks `residual=False` (B-07); (c) `worker.MODULES` and the frozen smoke list when the pipeline imports the stage; (d) 01 s2 says "L-31" for `ladder/assign.py`, the number is L-24; (e) a `perf` pytest marker if G-U5 files should be deselectable (the S5 file takes about 50 s); (f) the S5 deviations of docs/modules.md [S5:residual] into a short build-notes paragraph in 04
- [ ] BLOCKED (live): residual precision and recall on real Ghidra IR and Tier R (the G-U3 per-pass table for P16-P19 is S6's), the real cost of decoding `ins` blobs for the unmatched functions (the synthetic double costs about 25 us per function), G-U5 on the Windows runner and the frozen EXE, the L-24 / L-20 / L-25 / L-26 numbers are the spec's and are not tuned on real data
- [ ] Known limits: the LAP time cap (L-24, 30 s) reads the wall clock, so on a very slow machine the same input can abstain where a fast one does not (recorded as `assign-time-cap`); `SideData.blocks` collapses a block repeated inside one function, so P17 counts it once

### [F4:virtual-table] VirtualTable
- [x] `gui/table_spec.py` (pure) and `gui/qt/table.py`; 10k and 100k `data()` and time gates, selection, sort, filter, keyboard, copy cap (`tests/test_gui_table.py`, `tests/test_gui_table_spec.py`).
- [ ] Integrator: re-measure the time ceilings on Windows CI; add a panel-level sort command and a status announcement from `counts_changed` and `copied`; chips delegate (F3) reads `CHIP_ROLE`.
### [GUI-F3:widgets] GUI framework F3: shared widgets (2026-10-14)
- [x] labels, state_view (StateView, NoticeStrip), chips, theme (dark tokens, stylesheet equal to DARK_STYLE), gui/tips.py with tests/test_gui_{labels,state_view,chips,theme,tips}.py; qt_gate repeat 10: 1,770 passed.
- [ ] Integrator (F5): call register_gui_tips() in the host and in the test fixture; wrap the central widget with NoticeStrip; have tooltips.py delegate apply_tooltip(accessible=) to gui.tips.apply_tip or adopt it.
- [ ] F7: high-contrast chip drawing, system variant, ThemeTokens from QPalette.
- [ ] BLOCKED (manual): real Narrator or NVDA output for the status strip and notice strip, Windows rendering of chip shapes at 100-200 percent DPI.
### [F6b:graph-canvas]
- [x] GraphCanvas and gui/graph_view.py with focused tests.
- [ ] BLOCKED (manual): Windows timings of the 500/2,000 and 2,000/8,000 budgets, real screen reader output for node announcements.

### [F6a:codediff]
- [ ] Integrator (M4): move the four ui.py setExtraSelections sites (render_match, _highlight_hunks, raw view, raw clear) to compose_selections; adopt CodeDiffView in ui.py when M4 lands.
- [ ] WBQ S9: attach the windowed CodeHighlighter through CodeDiffView.attach_highlighter before set_pair.
- [x] F7: hunk tints are ThemeTokens (hunk_replace, hunk_other) with system and high-contrast variants.

### [GUI-F5:host] GUI framework F5: panel host and seam (2026-10-14)
- [x] PanelHost, docks, layout persistence, View menu, command palette, F6 cycle, anchors, MainWindowPort, ui.py seam, tooltips delegation, `--self-test` panel check, seam budget and forbidden-API tests; AI-FIX: completed interpretation runs show `run.error`.
- [ ] Integrator: add the repeat job to `.github/workflows/qa-windows.yml` (text in docs/qa.md [GUI-F5:host]); run the full suite twice and `tools/qt_gate.py --repeat 20` on Linux.
- [ ] F8: evidence migration (`secondary/evidence_panel.py`; remove the `hasattr(self, 'evidence')` hooks and the menu lookup by 'Analysis'); then lower `UI_TRANSITIONAL_CEILING` in tests/test_gui_host_seam.py to the final +15.
- [ ] F7: Theme submenu, `theme_changed` on palette change, reduced motion.
- [ ] BLOCKED (manual): palette, F6 order, dock tab names and notice strip with real Narrator or NVDA on Windows; layout restore across DPI changes.

### [F8:evidence-migration] Evidence and engine setup on the host (2026-10-14)
- [x] M1 and M2 done; `UI_TRANSITIONAL_CEILING` lowered 25 -> 17 (ui.py 3,159 lines).
- [ ] Reach the plan's +15 (3,157): two more ui.py lines go with F9 (series and files docks).
- [ ] Integrator: move the evidence status messages to `StatusAnnouncer` and the load/run/probe threads to `TaskRunner` (needs the C6 thread tests rewritten); M4 stays open.
- [ ] BLOCKED (manual): M19 NVDA walk and M21 keyboard walk of the migrated panel on Windows.
### [F7:theme]
- [x] system variant, automatic high contrast, chip HC drawing, reduced motion (Qt animation effects), View > Theme, hunk tints as ThemeTokens, focused tests.
- [ ] Integrator: a tip id for the Theme submenu (tooltips.py is frozen for F7); panels with their own painting should handle `theme_changed` and use `tokens.high_contrast`; legacy ui.py widget-level stylesheets (code font size) are unaffected.
- [ ] BLOCKED (manual M22): real Windows high-contrast themes (Aquatic, Desert, Dusk, Night sky), Settings > Accessibility > Visual effects (animations off), light/dark OS switch with the System variant, chip and hunk legibility at 100-200 percent DPI.

### [F9:series-files-docks] Series and files docks (2026-10-14)
- [x] M3 done: both former exceptions to "one main window" are docks; ui.py 3,092 lines, `UI_TRANSITIONAL_CEILING` lowered 17 -> -50.
- [ ] Integrator: `tooltips.py` still says "Opens a non-modal Series window" in `action.series` and describes `series.window` as a window; reword when F7 releases the file.
- [ ] BLOCKED (manual): keyboard and screen-reader walk of the tab close buttons and both docks on Windows.
### [RA-FIX-1:audit-fixes] Random audit 1 fixes (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] RA-1 per-file entropy budget (4 x `entropy_cap`, `entropy_budget_exhausted`) and `headers.read_image_layout` for `unified.addressing.layout_from_reader`; the audit recipe (96 sections over one 8 MiB range, 8.4 MB file) takes 1.4 s instead of 34.3 s, the honest one-section file stays at 0.5 s
- [x] RA-4 offline cache index sharded over `urls/<xx>.json`, an unreadable index file is never rewritten (`PT-INTEL-CONFIG`), a full shard is refused (`PT-INTEL-LIMIT`), the first version's `urls.json` stays readable and untouched
- [x] RA-8 one hostile-character rule (`hostile_text.is_hostile`) for `process.sanitize` and `pe_overview.clean_text`; no existing golden changed (the dependent test files were run, see `docs/qa.md`)
- [x] RA-9 entropy of constant data is `0.0`; RA-10 `bench_enrichment` prints `peak_rss_mib: null` without `resource`
- [ ] Open, not in this slice: RA-2, RA-5, RA-6 (KB CVRF, K1), RA-3 (slow-drip reads, one shared bounded-read helper, SPEC-28 / SPEC-07 / acquisition), RA-7 (provider credential charset), and the audit's missing tests 2, 3 and 5
- [ ] Open: the other full `inspect_pe` callers (`unified/ir/pe_tables.read_pe_tables`, `intelligence/tools/normalize.PeMap.from_reader`) need the section table but not entropy; passing `Limits(entropy_cap=0)` would skip the entropy pass (not done: files outside this slice)
- [ ] Open: two `put` calls from different processes can still lose an update inside one shard (C-22 lock), the damage is a refetch; the E6 plan's Windows RSS cell for the enrichment bench is now `null` (unmeasured) until `GetProcessMemoryInfo` is used
### [CONSENT:network-consent-tests] Network consent tests (2026-10-14; SPEC-42 sections 3 and 7, SPEC-43 section 7)
- [x] `tests/network_guard.py` and `tests/test_network_consent_{guard,symbols,fetch,openers,secrets}.py`: 119 tests; closes SPEC-42 gaps F1 (symbol lookups), F2 (calibration download), F3 (tier-R fetch) for what a process can observe, plus the R3 and R7 gaps (key and tokens out of QSettings, project files, `analysis.log`, events, error text); `redact_log` extended for `AWS_SECRET_ACCESS_KEY=`-style assignments and `github_pat_` tokens
- [ ] BLOCKED, external: whether Ghidriff `--no-symbols` stops all symbol-server traffic (SPEC-42 E5) needs a native run that records the hosts contacted; the child is a process and no in-process guard can see its sockets
- [ ] Windows CI for the five files (run on Linux, CPython 3.13.16 only); the guard test starts one pytest subprocess
- [ ] Still open in SPEC-42 section 7: `test_network_census.py`, `test_offline_switch.py`, F4 (blob host printed before any CLI request), F5 (accepted LLM send transmits exactly `context.payload`); SPEC-43 G1 and G2 (secret-shaped Model and endpoint text refused before a save) belong to the provider owner
- [ ] Owner decisions the tests surfaced: `restrict_env` is off by default, so the SPEC-42 row 9 sentence "proxy and CA variables passed only when on" holds for restricted and bundle mode only (an unrestricted child inherits every proxy variable and token); `cli.main` prints `{type(exc).__name__}: {exc}` for an unexpected exception without redaction (no path that carries a key was found); `redact_log` stays pattern-based and leaves Cookie and `Set-Cookie` values, SAS `sig=`, Slack and JWT tokens and `--password value` visible
### [PIL-B2:engine] Patch-intent localization fusion, tiers, ranking and the service (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s9)
- [x] `pilot/{quality,tiers,ranking,fusion,why,service}.py`, `tests/test_pilot_{fusion,ranking,properties}.py`, `tests/pilot_localize_support.py`: `localize(inputs, config, cancel) -> PilotAssessment`; the PIL-T oracle is green (22 strict xfails now pass; only the markers were removed, no assertion touched; `localize()` in `tests/pilot_synergy_support.py` needed no change because `LocalizeInputs` is structural); gates `test_synergy_*` (all), properties (permutation, repetition, idempotence, removing support and adding doubt never raise a class, unknown never "not seen"), the 5 s target (`test_5000_pairs_by_8_cves_localize_within_the_5_second_target`, CPU time)
- [x] Invariants guarded by tests: no float, division or rounding in the six modules (AST scan), order keys are integer tuples, the tier derivation never returns `strong` and every flag is monotone over its whole fact space (15,360 combinations), shared origin counts once, cancel before and during a run, the deadline, P-01 and P-03
- [ ] Owner decision, plan s7 "Rows without a B1 detector stay tentative unless two components agree": built as two independent origins among the CODE observations (the advisory does not count). If the plan meant the advisory to count, `fusion._fit` loses one condition and those 14 rows reach moderate with one ChangeFacts or call origin; `test_rows_without_a_b1_detector_need_two_independent_code_origins` states the current reading
- [ ] PIL-A3/A1 follow-up, B1 confidence: the observation does not carry it, so `fusion.B1_LEVEL` reads every detector at its default (`INT` weak); `R-OFF-BY-ONE` `bound-adjusted` (leaf `b1:INT@moderate`) is therefore met only through `b1:BND`, `cf:comparison` or `cf:constant`. An additive optional field on `Observation` (or `b1:` kinds per level) fixes it without touching B2's rule logic
- [ ] Integrator: add `status() -> ChannelStatus` to `ports.AdvisorySource` (`StoredAdvisorySource` has it; `localize` reads it when offered, else derives `available`/`not-run` from the contexts); delete the now vestigial `PIL_B2`, `EngineMissing`, `engine_available`, `assert_strictly_pending` and the two guard tests in the PIL-T support module (left in place because the brief allowed removing the markers only)
- [ ] PIL-C1 (store, report, CLI): build `LocalizeInputs` from `GhidriffPairing`/`UnifiedPairing` + `CodeEvidence` + `GhidriffCalls` + `ToolDeltas` + `CatalogKev` + `confounding`/`cve_context` (counts zero) + the `adv:*` entries; use `why.Explainer(assessment)` for `why[]` and `intelligence why`; `PilotAssessment.queue_count` means queue rows left out of `leads` over all contexts (A1 did not define it); the pool holds only referenced observations
- [ ] Not built: quoted advisory strings as locality (T's `value_hash` is case exact, no source supplies an IR function's string references), the attention/1 rank inside a tie (no source), the KB window (contexts carry the CSAF-derived count), publication of anchors to an `AnchorSink`
- [ ] BLOCKED, owner and CI: Windows CI for the three test files (the hash-seed test spawns Python; Linux only so far: CPython 3.13.16, and 3.12.3 in a throwaway venv without Qt, 175 passed in both), live evidence (real Ghidriff labels, capa/FLOSS/DiE, a unified result with ProgramIR), SPEC-30 amendments of plan s10 (still open)
### [S3:ir-facts] SPEC-31 S3 (2026-10-14, builder worktree)
- [x] IR channels C0-C5 (`facts/irchannels.py`), operand classifier with target consistency (`operands.py`), DATA-MAP/1 (`datamap.py`), alignment (`align.py`), CFG logic (`layout.py`), EH-EQ (`eh.py`), MAT-ANCHOR (`anchors.py`), F17 (`trace.py`), UNCH/1 + COS-ADDR/1 + COS-LAYOUT/1 in `verdict.py`; spec notes in 05 s7
- [x] Acceptance by name: the 05 s2.7 / s3 and 08 s1 tests of the S3 scope (`test_moved_global_is_cosmetic_via_other_function_votes`, `test_swapped_global_same_shape_is_not_cosmetic`, `test_innocent_functions_keep_mapping_beside_a_dissenter`, `test_single_use_global_needs_region_shift`, `test_function_never_votes_for_itself`, `test_two_way_tie_is_unmapped`, `test_unmapped_target_blocks_cosmetic`, `test_wrapper_with_logic_not_collapsed`, `test_unmatched_callee_is_material_candidate`, `test_block_reorder_is_cos_layout`, `test_then_else_swap_not_cosmetic`, `test_tiny_change_is_review_not_hidden`, `test_small_constant_bound_change_detected`, `test_hub_call_change_still_reported`, `test_trace_arg_constant_ordered_last_not_hidden`, `test_frame_only_change_is_review_not_material`, `test_constant_only_patch_is_review_ranked_first`, `test_constant_only_patch_promoted_only_with_anchored_c6`, `test_cos_addr_requires_tier_a_targets`, `test_unchanged_requires_target_consistency`, `test_material_needs_anchored_second_channel`, `test_scope_table_change_blocks_unchanged`)
- [x] Gates at unit level: G-U1 X versus X is 100 % `unchanged` on REAL Ghidra 12.0.4 output (recorded probe image 7/7, MinGW image 61/61) and on hand-assembled images; G-U2 every mutant of the 08 s1 table including R-01..R-04, R-07, R-16 (13 classes x 20 random members + the named cases) lands in `material` or `review`, leakage into `cosmetic` / `unchanged` = 0, frame-only and trace-arg in `review`; G-U4 swap property (verdict and proof independent of the direction); every ordered pair of the 61 real MinGW functions (3,721 pairs) judged without error and never `unchanged` unless the bytes are equal
- [x] Live, Linux, real Ghidra 12.0.4 (docs/qa.md [S3:ir-facts]): a 61-function MinGW pair (the one real source edit is `material`, 15 `unchanged`, 38 `cosmetic`, 7 `review`) and a 4,060-function pair (236 planted edits all `review`, 3,797 + 21 of 3,824 untouched functions `cosmetic` / `unchanged`, 6 `review`, 0 hidden), 1.4 ms per pair
- [ ] Integration owner (S3 does not edit `compute.py`, `worker.py`, `fusion/arbiter.py`): pass `ir_sides=IrSides(...)` and `budget=` from `compute.py` (sections from `PeTables.sections`, `identical = older_sha256 == newer_sha256`), fill `ir_older` / `ir_newer`, drop the `ir-not-extracted` limitation when IR is present; `arbiter.to_match(..., flags=judged.flags)`; `worker.MODULES` entries; the `IrReader -> IrSide` adapter of the S2 seam
- [ ] Open design question (owner / USER): single-use data with no confirmed neighbour stays `unmapped` (spec rules a-c), so a small rebuild-shaped pair leaves rows in `review` (the real MinGW pair: 7 of 61 CRT functions, class `address-only`, never material). A candidate rule "no datum of the section moved and the section tables are equal -> equal addresses map" would clear them but is outside DATA-MAP/1 as specified; G-U1 P0 (`review` <= 0.1 %) is measured on the S6 corpus
- [ ] Not built or known gaps: switch-table permutation with an unchanged target set is invisible to the IR; block pairing has no similarity fallback (an entry guard leaves many `unknown` deltas, still `review` or `material`); equal-`h1` pairs are not fast-pathed on the `ref` rows (about 8 microseconds per instruction decode, 1.4 ms per small real pair)
- [ ] BLOCKED / unverified: Windows and MSVC-built IR (RVA-form switches, CFG dispatch, /GS), Python 3.12, G-U1 P0/P1 and G-U2 recall at >= 20 mutants per class on the real Tier R corpus (S6), G-U6 / G-U7 (S6)
- [ ] S3b (`decompile` mode of the extractor script, worker `refacts`): see its own block
### [S3b:decompile] SPEC-31 S3b (2026-10-14, builder worktree)
- [x] `decompile` mode of the extractor script, `decompile_side` in the runner, the strict `decomp.jsonl` reader (`extract/decomp.py`), `FactsContext.build(decompiled=)` and the row selection `facts/refacts.py`; spec notes 03 s12.9 and 05 s7 (status lines updated)
- [x] Live, Linux, real Ghidra 12.0.4 (docs/qa.md [S3b:decompile]): own analysis of the two MinGW probe DLLs, the facts selected `add_clamped` and `dispatch` (constant-only edits, `review`), the real `decompile` mode decompiled them on both sides in 22.7 s, and the facts with that C text made both `material` (second channel C6); a function-less RVA came back `failed`
- [x] Tests: 82 new (script mode with fakes, reader, runner with fake interpreters and tree kill, selection, C6 seam, recorded real decompiler text); the S1 script and runner tests stay green; a 38-mutant check of the new code: 36 killed, 2 equivalent (`parse_float` and the L-41 bound are enforced a second time by the type check and the S0a request model)
- [ ] Integration owner: the `refacts` worker mode and stage (select -> `decompile_side` per side over the retained GZFs -> `FactsContext.build(decompiled=)` -> judge those rows -> publish), the `--no-decompile` flag, `tools/live_unified_check.py` leg L7 (decompile two functions of the fixture pair)
- [ ] BLOCKED / unverified: Windows (the JVM, the native decompiler process and the Job Object on `windows-latest`), MSVC-built GZFs, a decompiler timeout and a decompiler crash on a real program (only fakes provoke them), the 64-pair / 600 s bounds at scale (2 pairs measured), Python 3.12
### [S4a:read-model] SPEC-31 S4a (2026-10-14)
- [x] Qt-free read model (`unified/read_model.py`, `read_text.py`): states U0-U6 plus the U7 notice, default order (contested, material, review, ... 07 s7) with library (F16) and trace-argument (F17) rows last, filter with the U-03 collapse count, per-source cells that never combine, columns / `cell_text` / `rows_tsv`, lazy detail / provenance / context text, evidence-class counts and one-line summary, edit groups (F10), tooltip ids and chips as data; CLI `unified show` / `explain` polish (`--source`, `--search`, `--all`); spec 07 s13. 59 new tests (read model 51, CLI show 8), 36 of 36 scratch mutants killed, filter 14-17 ms and sort 39-68 ms at 100,000 synthetic rows
- [ ] S4b (instance D, after the GUI host exists): `ui_unified.py` (`PANEL = PanelSpec(id='unified', tabify_with='evidence')`), table model over `filter_rows` / `sort_rows` / `cell_text`, Unified tab from `row_detail`, copy from `provenance_block`, view switch, Run / Cancel / progress through `TaskRunner`, tooltip registration from `TOOLTIP_IDS` / `TOOLTIP_TEMPLATE_IDS` / `source_tooltip_ids()`, accessible names, the `data()` call gates at 10,000 and 100,000 rows, 20x Qt repeat, `test_flag_off_ui_unchanged`, Windows DPI and screen-reader passes (manual)
- [ ] Integrator asks: add `read_model` and `read_text` to `worker.MODULES` (frozen self-check) and to the layer map of `tests/test_unified_import_dag.py`; a public line reader in `unified/store.py` for `SidecarRecords` (it uses `store._lines` and `store._parse` today); a `cli_commands/unified.py` adapter when the S0b `COMMANDS` hook moves
- [ ] Open: Windows CI for the new tests (timings with the 15.6 ms clock, `copytree` of a project); real Ghidriff / BinDiff / rz-diff data (every row here is synthetic); IR-mode cells (pt-ladder, pt-bytes, structural proofs, the collapsed rows) on real S2 / S3 output; an attention/1 map built from the enrichment store (the request accepts it, nothing builds it yet); the size-argument context of 05 s2.6 needs call-site facts from S3; loading 100,000 rows takes about 18 s on the shared box (two thirds is the store's strict validation), so the panel must load in the background with progress and cancel
### [S6a:corpus-gates] SPEC-31 S6a (2026-10-14, builder worktree; Linux only)
- [x] Tier R catalogue `tools/unified/corpus`: recipes for libpng, Lua and mbedTLS beside SPEC-32's zlib, four release cards with the fixes the pinned changelogs attest (libpng 1.6.44 overflow hardening, mbedTLS 3.6.1 CVE-2024-45158), `pins.json` source digests, offline `problems()`; CLI `toolchain, check, fetch, build, aa, mutate, manifest`; A/A P0, P1, P2 under the gate's names; `unified-corpus-manifest/1`
- [x] Planted mutants `tools/unified/mutations`: 12 G-U2 classes, 288 of 288 accepted at 24 per class; symbol-reference proof for the two classes whose masked body is equal by design
- [x] G-U5 bench `tools/unified/bench.py` (ladder, ingest at 3 M instructions, informational extract rows from the live tool); gate-report skeleton `tools/unified/gates_u.py` (`gate-report/1`; G-U5 and G-U8 evaluated, the rest pending with what they wait for); advisory dispatch-only `.github/workflows/unified-corpus.yml`; `features/2` proposal text (`12-features2-proposal.md`, A-07); A-19 applied to `verification.md`
- [x] Acceptance: 166 new tests (7 files) and 215 neighbouring existing tests green on Linux, and the new files plus the workflow and registry guards (267 tests) green on an extract of the integration branch `work/a` at 5f18f26; real runs recorded in docs/qa.md (fetch with digest check, four builds, A/A, mutants, live Ghidra extraction of the recipe-built zlib pair, bench at 10k and 60k)
- [ ] BLOCKED / not run: the first dispatch of `unified-corpus.yml` (static checks only), every Windows leg (bench RSS branch via `K32GetProcessMemoryInfo`, mingw and clang on the runner), the MSVC leg, the frozen EXE, Python 3.12 (the CI pin; local is 3.13)
- [ ] S6b (after S3): evaluators for G-U1, G-U2, G-U4, G-U6 and G-U7 on `unified-result/1` rows joined to the manifest labels; G-U3 additionally needs the IR-to-ladder adapter (`IrReader` to `IrSide`, not on the base) and a pinned BinDiff for its oracle part; G-U4 chain checks need a third consecutive version per project; G-U8 `ui-policy` needs S4 test names; report SHAs into docs/qa.md for U-05
- [ ] Not built: P1 nuisance variants ICF toggle, timestamp, GUID, path (need a link-flag field on the SPEC-32 `BuildSpec`); mutant classes `moved-rva-call` and `try-scope`; sqlite (SPEC-32 exclusion stands); single-commit CVE-fix pairs (the REST API is not available to the session, so parent commits cannot be verified); the informational 250k-function bench size (not run here)
- [ ] Integrator: `.gitattributes` line `tools/unified/corpus/*.json text eol=lf`; reconcile with the LBL plan proposal to drop `tools/unified/{corpus,mutations}/*` and `unified-corpus.yml` (docs/modules.md [S6a:corpus-gates] notes what moves where)
### [K4:kev-kb-adapter] KEV K4 KB adapter and synergy (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K4: `kev/kb_adapter.py`, `tests/test_kev_synergy.py` (16 tests: plan section 5 items 1 to 8 over a real `rank` result and a real `contextual_rank`, with the five gate tests of plan section 9) and `tests/test_kev_kb_integration.py` (68 tests: Protocol surface, reading-order property, timeline table, candidate order, abstention, hostile input, limits); 41 one-line mutations killed
- [ ] OPEN for the KB wave merge (reported open, not done): plan section 5 item 9 (`test_three_lanes_stay_separate_for_cve_2024_38063`: the MSRC lane "Exploited: No; Exploitation More Likely" and the SSVC lane "exploitation poc (2024-08-29)" are read by the KB view model, which is not on this base; only the KEV lane "Not listed" is checked, in `test_the_kev_lane_of_cve_2024_38063_is_not_listed_in_the_real_trimmed_catalog`) and the real KB view-model test. The KB view fills the adapter inputs: edges (`kb`, `cve`), `candidates`, `cwes`, `release_dates` (the base's `KbCveEdge` has no day-level `released_at`), `orientation_verified` and `detector_cwes=enrichment.cve.CWE_DETECTORS`
- [ ] NOT built here: K2 transport, service and CLI, K3 GUI, K5 project row and report (next), K6 live probe
### [K5:kev-project-context] KEV K5 project row, drift and report block (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K5: `kev/project_context.py`, `kev/report.py`, `tests/test_kev_project_context.py` (32 tests) and `tests/test_kev_report.py` (58 tests): the three gate tests of plan section 9 (`test_context_row_roundtrip_and_v1_client_ignores_it`, `test_flip_not_listed_to_listed_is_reported`, `test_report_block_escapes_hostile_text`) and, through a real sample project, the round trip, no extension-version bump, a stale row when another catalog is loaded at publication, survival of retention and pruning, damaged rows skipped with a warning, typed storage errors, drift order, the report golden, hostile file names and versions; 36 and 53 one-line mutations killed (one behaviour-equivalent mutant remains)
- [x] A4 (`kev-context` in `enrichment.storage.KINDS`, not in `DERIVED_KINDS`) was already on the base (A-5 and AM1): no shared-file commit was needed
- [ ] OPEN for the integrator: the report hook (plan A6, decided with the FAB report contract) should call `report_block(context, meta, drift=drift_lines(context, kev))`, with `meta=None` when the recorded snapshot is gone from the KEV store (`kev prune`); the dock and the CLI call `build_context` and `publish_context` on the owner thread after a lookup (pass `loaded_snapshot_id`), and `load_contexts` with `drift_lines` to mark a project's KEV answers "changed since recorded"
- [ ] NOT built here: K2 transport, service and CLI, K3 GUI, K6 live probe, K7
### [FAB-1:fabric-store] Anchor fabric store and schemas (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s7 "Store as built", s9)
- [x] `fabric/store.py`, `tools/generate_fabric_schemas.py`, `docs/schemas/fabric/` (5 schemas and `examples.json`), `tests/test_fabric_{store,schemas}.py` and `tests/fabric_store_support.py` (109 new tests; gates: round trip through a second store, a step-by-step and a random-sequence differential against `MemoryAnchorStore`, stale flag by moved origin table and by stored guard, retention and old reader untouched, per-anchor skip-and-count, orientation across a real `swap_orientation`, regenerate-and-compare, 65 mutations); `KINDS` += `anchor-batch` (own commit)
- [ ] Integrator asks: none for shared files beyond the committed `KINDS` line (no `.gitattributes` line: `docs/schemas/**/*.json` already covers the schemas); optional: add the `fabric-batch` domain to `ids.DOMAINS` and scan `store.py` in `test_every_identity_domain_in_use_is_listed`, and update the `fabric/__init__.py` docstring ("pure core": `store.py` is an adapter); a frozen-smoke import line once a consumer imports `patchtrace.fabric.store`
- [ ] Open risk for FAB-6: the store uses the project connection, so it must be used on the owner thread; the panel's worker-thread `find` pages need a hand-off (an immutable loaded view) or a read-only connection, to be decided with the GUI panel framework
- [ ] Open: rows are not atomic across several batches of one call (a crash between two rows is completed by repeating the call); an unreadable or newer row is only listed, never repaired
- [ ] Not verified: Windows and CI; timings on Windows (Linux numbers in `docs/qa.md`); behaviour with a real producer, the GUI and the CLI (later slices)
### [FAB-4:fabric-pins] Anchor fabric analyst pins (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s7 "Pins as built", s9)
- [x] `fabric/pins.py` (`PinPort`, `EnrichmentPinStore`, `PinEvent`), `PinEvent` in the generator and `docs/schemas/fabric/`, `tests/test_fabric_pins.py` (54 tests; gates: pins survive batch replacement, retraction, a retraction of the `analyst` producer and enrichment retention with their rows untouched, a model-based random sequence, skip-and-count, orientation, notes, old reader, 42 mutations); `KINDS` += `anchor-pin` (own commit); `store.py` exports the shared project access
- [ ] Integrator asks: none for shared files beyond the committed `KINDS` line; WB1 amends s4 as plan s10 says (pin becomes `PinPort.pin(project_key, anchor, note, via)`, with `via` standing for the provenance); the "Pin as lead" button is WB1's and stays absent until it calls the port
- [ ] Open: pins are read whole on every call (about 27 ms at 1,000 events, a new pin about 50 ms), which is fine for an analyst's pins; a compaction of old events is not built; the same owner-thread limit as the batch store for FAB-6
- [ ] Not verified: Windows and CI; a real WB1 or GUI caller
### [R1:rules-synth] YARA-X rules R1 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] `rules/synth.py`, `tests/test_rules_synth.py` (333 tests, about 30 s) and six goldens in `tests/fixtures/rules/golden/`; hostile strings (quotes, backslashes, NUL, newlines, bidi, star-slash, braces, keyword text) in every value position stay inside their literal (an engine-free lexical oracle), compile under R2's policy with no warning, are read back exactly by the real YARA-X and are `Formatter` fixed points; every byte value and ASCII character round-trips; a 60 KB rule with every value at its cap compiles clean; call pins, import gates (named, ordinal, delay-load), text patterns and the PE/machine/executable gates are checked on synthetic PE images; 61 of 61 one-line mutations of `synth.py` killed (one real gap, the default of `include_names`, found and pinned)
- [x] Decisions beyond the card: multi-line condition (one top-level clause per line) where the R0 example text has one line (both are fixed points; the example is unchanged); list-valued meta keys repeat once per value; delay-load imports are a loop over `pe.delayed_import_details` and ordinal imports are `pe.imports(dll, n) > 0` (YARA-X 1.21.0 has no `pe.delayed_imports`, and the bare ordinal form warns `non_bool_expr`); a rule needs a pattern or an import gate besides the PE gate; a `StringFeature.text` that is not the canonical spelling of its bytes is refused (R3 builds it with `synth.escape_bytes`); text patterns exactly as the grammar says (at most four, `ascii`/`wide`), and the card's fallback of hex and imports only is `TEXT_PATTERNS = 0`
- [ ] BLOCKED / open (CI or the owner): the Windows leg of `tests/test_rules_synth.py` and of the goldens (byte for byte needs LF checkouts, see Integrator asks); the layout is pinned to YARA-X 1.21.0 by `test_synth_is_formatter_fixed_point`, so a bump PR regenerates the goldens (`PYTHONPATH=src python tests/test_rules_synth.py`) after reading the diff; R4 still has to confirm the Section 5 grid with real masks (the pin and import semantics are proven here on synthetic images only)
- [ ] Integrator asks: `.gitattributes` += `tests/fixtures/rules/** text eol=lf` and `*.yar text eol=lf` (plan s10); nothing else (no dependency, KINDS, CLI, hook or shared-file change); no file of this slice contains the export marker line (R5 writes it; the goldens and tests use plain header lines)
### [K2:kev-fetch] KEV K2 transport, service and CLI (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K2: `kev/{transport,service,cli}.py`, the 17-line adapter `cli_commands/kev.py` and `tests/test_kev_{transport,service,cli}.py` (247 tests): the six gate tests of plan section 9 and the RA-3 real-socket regression (`test_a_slow_drip_server_cannot_hold_the_download_past_its_deadline`: a loopback server sends one byte every 0.5 s, the deadline is 2 s, the fetch returns in 2.0 s; the audit measured 12 s on the CSAF transport); 68 one-line mutations killed
- [x] Live check from this sandbox (not CI, not Windows): `kev fetch --source cisa-github` installed catalog 2026.10.14 (1,745 entries, 1,787,354 bytes, no unknown fields, no warnings) through the production transport; `--source cisa-site` fails with `PT-KEV-NETWORK` here (the host is blocked), so the canonical URL stays unverified until the K6 workflow runs on GitHub
- [ ] OPEN for the integrator (shared files): `tools/frozen_smoke.py` smoke steps `kev import`, `kev lookup`, `kev status` on `tests/fixtures/kev/kev-synthetic-2099.json` (A1; the derived `names()` lists need no edit); rows for `www.cisa.gov` and `raw.githubusercontent.com` (both through `kev/transport.py`, consent `--consent-hosts`) in `docs/specs/network-egress-privacy.md` section 1; the subprocess tests of `tests/test_acceptance_smoke.py` import the main checkout's `patchtrace` unless `PYTHONPATH` points at the tree under test
- [ ] OPEN, not K2: RA-3 (a slow-drip server bypasses the deadline) still stands in `intelligence/csaf/transport.py`, `enrichment/intelligence.py` and `acquisition/transport.py`; one shared bounded-read helper in `netutil` with the loopback test of `tests/test_kev_transport.py` as the model would close all four
- [ ] NOT built here: K3 GUI, K4 KB adapter and synergy test, K5 project row and report, K6 live probe (next in this chain), K7
### [K6:kev-live-probe] KEV K6 live probe and workflow (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] K6: `tools/live_kev_probe.py`, `.github/workflows/live-kev.yml`, `tests/test_live_kev_probe.py` (63 tests): the gate tests `test_probe_classifies_blocked_vs_failed` (16 cases) and `test_probe_detects_schema_drift` (13 cases), the one-release-one-content rule, the 72 h limit, the mirror-only fallback, the status-file convention, the CLI subprocess and the workflow guards; 37 one-line mutations killed
- [x] Run from this sandbox (not CI, 2026-10-14): `--sources cisa-github` PASSED (catalog 2026.10.14 fetched through the CLI, live schema byte-identical to the vendored copy, SHA-256 0d5865c9...); the default two-source run is BLOCKED because `www.cisa.gov` does not resolve here (`gaierror`)
- [ ] OPEN, closes only on GitHub: the first `live-kev` run (the canonical `www.cisa.gov` address with the fixed User-Agent, content equality of the two sources, schema drift). Until it has passed `cisa-site` must not become the GUI default (plan question 1); record its table in `docs/qa.md`
- [ ] OPEN for the integrator: no shared file needs a change (`tools/check_live_status.py` has no engine list); the workflow is new and unrequired, so do not add it to any branch protection
- [ ] NOT built here: K3 GUI, K4, K5, K7

### [FAB-5:fabric-cli] Fabric CLI verbs (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s8, s9)
- [x] `src/patchtrace/fabric/cli.py` (Qt-free `list`, `show`, `resolve`, `stats`), `src/patchtrace/cli_commands/fabric.py` (20-line registry entry; `cli.py` is untouched, the registry discovers the file) and `tests/test_fabric_cli.py` (38 tests: the envelope, exit codes 0, 2, 3, 4 and 5, partial reads, child processes, no Qt import, the adapter's size and lazy loading); the import-hygiene guard in `tests/test_fabric_contracts.py` admits the CLI adapter
- [ ] Integrator asks: none for shared files. The launch prompt named `list/find/resolve/pin/unpin`; the card's section 8 is read-only `list/show/resolve/stats`, which is what is built. A CLI pin verb would need a card amendment first, since a pin is an analyst write
- [ ] Open: `--offset` for paging past 500 anchors; the FAB-6 `related` panel reads the same store on the owner thread; the frozen smoke sees the new verb after the merge (in a worktree the editable install points at the main checkout, so `tests/test_acceptance_smoke.py` fails there until then)
- [ ] Not verified: Windows CI (the child-process tests set `PYTHONPATH`); the full suite (the integrator runs it)
### [FAB-3:adoption] PIL adopts the fabric's origin table and anchor seams (2026-10-14; plan `docs/specs/program-e/FAB-integration-plan.md` s9 FAB-3, s10)
- [x] `pilot/origins.py` and `pilot/ports.py` rebound to the fabric (no copy of the table, the calculus, `OriginRegistry` or `AnchorSink`); `DefaultOriginRegistry.payload()` in the fabric; `tests/test_fabric_adopt.py` (15 tests); the PIL parity tests of `tests/test_fabric_origins.py` replaced by a reference-oracle property and a `payload()` test; pilot schema examples regenerated (the origins digest and the ids derived from it only); FAB plan status line (the duplicated status line is one again) and the note in PIL plan s4.
- [ ] Integrator asks: none for shared files. A textual conflict is possible only in the append-only docs and, if A41 edits the same lines, in the `RUNTIME_ALLOWED` table of `tests/test_pilot_contracts.py` and the ports inventory of `tests/test_pilot_keys.py`.
- [ ] Open: no PIL code publishes anchors yet (the publisher calls `fabric.convert.from_pilot_anchor`, which needs the pair record for a candidate); `Navigator` is still PIL's own port (the GUI `NavigationPort` replaces it only by a separate decision); a row added to the shared table moves the PIL origins digest and stales stored pilot results, so the golden is re-pinned with the row.
- [ ] Not verified: Windows and CI; the full suite (the integrator runs it); the frozen build (nothing imports `patchtrace.pilot` at runtime yet).
### [R3:rules-candidates] YARA-X rules R3 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] `rules/{features,gates,candidates}.py`, `rules/adapters/{tools_delta,pe_imports}.py`, `tests/rules_fixtures.py`, `tests/test_rules_candidates.py` (140 tests; real YARA-X in-process, real capa 9.4.0 and FLOSS 3.1.1 goldens): string candidates on `floss-static` (older: debug dump; newer: index/length), import and capability candidates on `capa-api` for `term` (older: TerminateProcess), `log` (newer: WriteFile; older: nothing), `env` (newer: GetEnvironmentVariableA); gates unit-tested on their boundaries; 45 of 45 one-line mutations killed; no shared file, schema or dependency touched
- [x] Decisions beyond the card: the closed-grammar `synth` (R1) is not built, so `propose` takes a `RuleRenderer` and tests use a reference renderer from `tests/rules_fixtures.py`; the normalised capa evidence keeps call sites but not API names, so `api_gates` come from the stored raw capa document, resolved against the build's own import table (exact name, else exactly one of the `A` and `W` variants; R4 pins are exact); an import that merely differs between the files is offered unticked (it may belong to another function); a build that was not scanned makes `sep` `unknown` and unknown blocks
- [ ] Integrator: wire `synth` as the `RuleRenderer` (`RuleSpec` carries source, direction, lineage, INCLUDED features, version) and re-run `tests/test_rules_candidates.py` with it in place of `rules_fixtures.render_rule`; rule texts may differ cosmetically, the gates must not
- [ ] Open (R4/R5): bytes windows, pins and `xref`-linked strings (the decoder); `Sources` and the seams live in `candidates.py` because `ports.py` is R0's; the store, CLI and `propose --direction` plumbing are R5's
- [ ] BLOCKED, live evidence: real Ghidriff pairing and real capa/FLOSS output on real binaries (everything here is synthetic); Windows CI for the new tests
### [R4:rules-bytes] YARA-X rules R4 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] `pe_overview/tables.py` (`.pdata`/`.reloc` readers copied from the dev-only module, plus `import_slots`, `read_backed`, `executable_sections`), `rules/{masks,window}.py`, `rules/adapters/mask_iced.py`, `tests/test_rules_masks.py` (98), `tests/test_rules_synergy.py` (20), `tests/fixtures/rules/synergy-matrix.json`; `propose` now takes `Sources.bytes`. The grid of plan s5 (5 rules x 11 builds) equals the plan's table (a test parses the table) with the REAL YARA-X in this process and through the hidden worker child; the windows of the three capa pairs are the card's measured ones (term 24 B / 20 literal, log 38 B, env 35 B); 87 of 89 one-line mutations killed in the final run (the 2 survivors are equivalent guards), no shared file, schema, dependency or other-slice module touched
- [x] Decisions beyond the card: a window is the changed range of the rule's own side plus one instruction of context each side, grown after-then-before until its checks pass or 128 B (the card's numbers fall out of this policy); `uniq`/`sep` of a window are counted by byte regex over the executable sections and the finished rule is scanned again by the engine, which decides; file-level strings only anchor a rule when there is no window, a string the changed code reads (`xref`) is ticked beside the window; a body without a verified `.pdata` extent (a leaf function) gets no pattern (`PT-RULE-MASK no-extent`) and the other channels still speak; a packed or protected build (DiE flag) gets no byte windows; `import_slots` gives no slot for a cut-short import table (a wrong slot would pin a call to the wrong API); `gates.absent_elsewhere` added (the window's own `sep`); the plan's `difflib.SequenceMatcher(autojunk=False)` is unbounded on bodies with many alike instructions (measured 14 to 32 s at 12,000 instructions), so the shared head and tail are cut off first and a middle over `MAX_DIFF_PAIRS` (1,000,000 equal-instruction pairs, provisional) is not compared but taken as one changed range, which `uniq` and `sep` then police
- [ ] Integrator: pin `iced-x86==1.21.0` (and `yara-x==1.21.0`, R2's ask) in `pyproject.toml`, `optional_deps.py`, the PyInstaller hook and `frozen_smoke` (R2 asks too); the 10 iced tests skip until then, and `test_decoder_pin_and_install_agree` (itself a skip now) fails a CI run once the pin is declared but the wheel is missing; add `.gitattributes` lines `tests/fixtures/rules/** text eol=lf` and `*.yar text eol=lf`; wire R1 `synth` as the `RuleRenderer` and re-run `tests/test_rules_synergy.py` (the grid must not change); move the unified-IR table readers onto `pe_overview/tables.py` as the plan intends (nothing was moved or deleted here)
- [ ] Open: the decoder used by every test is the stand-in `rules_fixtures.SubsetDecoder`; it is equal to the real iced-x86 1.21.0 on all six fixture images and on the decoder unit cases (checked with a scratch `pip install --target`, not committed), but no real-binary body was decoded; the synthetic images have no `.pdata` (real `.pdata` is covered by `pe_builder` images and the extent cross-check, not by the grid); window policy thresholds stay provisional until Tier R
- [ ] BLOCKED, live evidence: real compiler output (jump tables, thunks, alignment padding, SEH funclets, hot-patch NOPs), real Ghidriff pairs and Windows CI for the new tests (CRLF checkout of the golden, `difflib` timing on a cold runner)
### [REDACT-2:redaction-coverage] redact_log coverage (2026-10-14; SPEC-42 R7)
- [x] `redact_log` hides Cookie and Set-Cookie values, SAS `sig=`, Slack tokens, JWTs and `--password x`-style arguments, closing the last decision above; `cli.main` redacts the exception text of its catch-all on stderr and in the `--json` `error` (exit 3 unchanged); `tests/test_redaction_coverage.py`, 57 tests
- [x] Found and fixed on the way: the URL userinfo rule was quadratic (`redact_log('a' * 40000)` took 15 s); every pattern is now linear and a 1 MiB hostile corpus guards it
- [ ] Windows CI and CPython 3.12 for `tests/test_redaction_coverage.py` (Linux, CPython 3.13.16 only); its timing test starts one `python -c` child with `PYTHONPATH` set to the module under test
- [ ] Owner decision: the `except CliError` branch of `cli.main` still prints `str(exc)` unredacted (messages written by the CLI, some wrapping `str(SecondaryError)` or `str(EnrichmentError)`); route it through `redact_log` too?
- [ ] Not covered, add if logs show them: short flags (`-p x`, `curl -u user:pass`), Azure `AccountKey=` connection strings, `X-Amz-Signature=`, Slack `xapp-` tokens; a quoted value directly followed by more text is re-redacted on a second pass by the old assignment rule
### [WBQ-S8:codetext-marks] WBQ slice S8 codetext-marks (2026-10-14, builder worktree, Sonnet 5.5; Linux only)
- [x] `codetext/{marks,operands,oracle,intraline,model}.py` and `tests/test_codetext_marks.py` (337 tests): operand classes from positive evidence, `diff_row` with address and temporary masking, the 0.8 gate with the single-edit exception, an alignment that is the exhaustive-search optimum, the bit-parallel gate and exact-distance band (at most 8,192 cells per pair, 250,000 per refresh), the UTF-16 `FormatSpan` model with bounded `refresh` and `find_change`; SYN-WBQ-1 counts (1 changed pair, 1 address-only, 4 rename-maybe, rows 10 and 11 skipped), the mutation property, named symbols never masked, shift-only controls with 0 `changed`; 165 of 165 scratch mutants killed
- [ ] Next in the WBQ chain: S9 (`ui_codetext.py`: `CodeHighlighter` over `CodeTextModel.spans`, merged formats per `(role, mark)` and theme, `compose_selections()`, F8 on `find_change`, the "Line changes" label from `summary`, tooltip ids, Setup rows, the `ui.py` seam; a `chrome` style for the header and truncation rows, which the model leaves without spans) and, if the owner decides U-WBQ-1, S9b (`codetext/align.py`). S13 can import `SYN_OLD`, `SYN_NEW`, `SYN_ROWS`, `ASM_OLD` from `tests/test_codetext_marks.py`
- [ ] Integrator: the S7 asks stand (amendment 4, `colorspacious` dev dependency, a `patchtrace.codetext` check in `tools/frozen_smoke.py`); the WBQ rows of docs/modules.md; amendment 2 (`04-quickwins.md` QW6: "consume displayed row pairs, similarity gate, labels from `ChangeClass`"); a `MatchPairOracle` feed (matched pairs as Ghidra addresses) and an `ImageRange` (PE headers) when S9 builds the model
- [ ] Owner decision, not blocking: whether the single-edit exception to the 0.8 gate (`SMALL_EDIT`, deviation 1 in docs/modules.md) stays; whether short assembly lines with two edited operands should be marked (they are skipped, as the plan's gate says)
- [ ] BLOCKED, owner and CI only: Windows CI (this slice ran on Linux, CPython 3.13.16 and 3.12.3), the timing gates on the Windows runner (they are loose on purpose: the deterministic guarantee is the cell cap), real SPEC-31 `insns.text` and real decompiler output through the operand rules, everything Qt (S9)
### [PIL-C1:store-report-cli] Patch-intent localization store, report and CLI (2026-10-14; plan `docs/specs/program-e/PIL-integration-plan.md` s9)
- [x] `pilot/{store,review,report,collect,cli}.py`, the adapter `cli_commands/pilot.py`, `tests/test_pilot_{store,report,cli}.py` (122 tests), four report goldens; gates `test_store_roundtrip_and_stale`, `test_retention_keeps_three_and_reviews`, `test_cli_leads_exit_codes` (real processes: 0, 2, 3, 4; 5 by an interrupted process), `test_review_events_append_only` (store and CLI), `test_report_banned_strings` (every synergy arm); JSON export is the fallback and is complete
- [x] No `KINDS` change was needed: `patch-intent` is already reserved and not in `DERIVED_KINDS`, and review events and results are told apart by their id prefix
- [ ] Integrator: the verb is `patchtrace pilot ...` (the card's adapter), the plan wrote `intelligence leads|why|review`; if the nested form is wanted, a 6-line alias in `cli_commands/intelligence.py` or K2's `ACTIONS` can call `pilot.cli.run`
- [ ] Integrator (A1/B2 follow-up): `PilotInputs` has no field for the CVE selection, the B1 algorithm digests or the unified/tool results beyond their ids, so `result_id` cannot tell two selections or two B1 versions apart; the store replaces the older copy of an id, which is safe because results are derived, but an additive optional field (for example `cves`) would make the identity exact. `PilotManifest` has no CVE list either (retention reads the advisory documents instead)
- [ ] Integrator: amendment 6 (promote `backup_once`/`delete_own` to `EnrichmentStore`) is still open; `store.py` uses `verified_backup` and public attributes only and is the second copy of that pattern (unified has the first)
- [ ] PIL-C2 reuses `collect.collect` for the Leads dock request (it is Qt-free and owner-thread) and `store.stage`/`store.read_sidecar` for the worker; `store.publish` is the owner-thread half
- [ ] Not built: stored capa/FLOSS/DiE deltas, CISA KEV and KB window as inputs, B3 snapshot CVEs, `--tools`; `tests/test_pilot_cli.py` pins that their channels say "not run"
- [ ] BLOCKED, owner and CI: Windows CI for the three test files (path and retry behaviour is exercised on Linux only; the symlink test skips without the privilege), live evidence (real Ghidriff, capa/FLOSS/DiE, a unified result with ProgramIR), the frozen `PatchTrace.exe pilot leads` on the sample project

### [R5:rules-store] YARA-X rules YRX-wire and R5 (2026-10-14, Sonnet 5.5, worktree; Linux only)
- [x] YRX-wire: `candidates.synth_renderer` is the default renderer; the reference renderer is an oracle; the section 5 grid is unchanged.
- [x] `rules/{store,matrix,export,cli}.py`, `cli_commands/rules.py`, `tests/test_rules_{store,matrix,export,cli}.py` (14, 34, 20, 28), `tests/rules_store_support.py`, golden `tests/fixtures/rules/export/export-term-v1.yar`.
- [ ] Integrator: the live `PairBackend` for `rules propose` (match to `PairSource`, strings, imports, capabilities, bytes and DiE flags from the project stores; track T) is not built, so `propose` exits 2 without it; `ui_rules`/R6a can use `matrix`, `store` and `export` as they are; pins for `yara-x`/`iced-x86` in `pyproject.toml`, `optional_deps.py`, the PyInstaller hook and `frozen_smoke` (R2 and R4 asks); `.gitattributes` lines `tests/fixtures/rules/** text eol=lf` and `*.yar text eol=lf` (the new golden is LF-only); the repo guard of plan s10 (the marker `patchtrace-rule-export/1` is in the new golden, under `tests/fixtures/rules/`).
- [ ] BLOCKED, live evidence: Windows CI for the new tests (CRLF checkout of the golden, file locking of the sidecar), a real series through `rules test`, and the frozen `rules _rules-worker` path.

### [PIL-D1:eval-core]
- [x] metrics, ablation, gate, report (tests/test_pilot_eval_*.py)
- [ ] arm runner over localize(), case/advisory loader, CLI: needs LBL M2/M5 pair labels and tools/calibration/pilot/advisories/<CVE>.json

### [PIL-C2:read-model]
- [x] pilot/read_model.py (tests/test_pilot_read_model.py)
- [ ] ui_leads.py, leads.* tooltips, PANEL registration, reveal_location, storage prepare/commit split (GUI track)
### [WBQ-S6-S9:qt-modules]
- [x] S6 `pemeta_view.py`, `ui_pemeta.py`, `tests/test_ui_pemeta.py` (39 tests); S9 `codetext_view.py`, `ui_codetext.py`, `tests/test_ui_codetext.py` (34 tests); qt_gate x5 green (365 passed).
- [ ] Integrator: Files panel hosts `PeMetaWidget` as a "Build facts" tab and feeds it a `PeMetaSnapshot` (needs WBQ S5 in `inspect.py`; S3 Rich header rows are not built); `ui.py` seam: `CodeTextController(self.old_view, self.new_view, announce=ctx.announce, live_base=...)`, `begin(...)` before and `finish()` after the `setPlainText` calls in `render_match`, `configure(colors, marks)` from QSettings `desktop/code_colors` and `desktop/token_marks` (default off), F8 and Shift+F8 actions calling `step_change(+1/-1)`, the label under the hunk selector, Setup rows; tooltip ids from `TIPS` in both UI modules move into `tooltips.py` or the panel specs.
- [ ] BLOCKED, live evidence: NVDA and Narrator reading of the "Line changes" label, 125/150/200% DPI, Windows high contrast, bold advance in Consolas, pixel probe of syntax foreground on a hunk row.
### [UE-S4b:ui-unified]
- [x] Unified panel (`unified/panel.py`, `ui_unified.py`) on the GUI host, built against `read_model.py`; 39 focused tests, qt_gate x20 green.
- [ ] Integrator: tests/test_tooltips.py needs `unified.dock`, `unified.tab`, `unified.source.unknown` in the `names` set of `test_every_registry_id_is_applied_somewhere` (no focusable control carries them); the Explain text should feed `build_context`/`ContextDialog` (ui.py) instead of the preview-only dialog.
- [ ] Open: reader for stored IR disassembly / decompiled pair text (`pair_texts` hook) to fill the code panes for rows without a Ghidriff match; persist `unified/columns`.
### [PIL-C2:leads]
- [x] `pilot/read_model.py`, `pilot/panel.py`, `ui_leads.py`, `tests/test_pilot_read_model.py`, `tests/test_ui_leads.py`, `tests/leads_support.py`; qt_gate repeat 6 of `test_ui_leads.py`: 366 passed.
- [ ] Integrator: add `leads` to `built` in `tests/test_gui_host_seam.py::test_the_shipped_manifest_builds_only_the_migrated_panels_and_has_no_problem` and to the dock list of `tests/test_tooltips.py::test_every_registry_id_is_applied_somewhere` (both fail on any new built panel until then). Decide `default_visible` for the dock (the plan wants it visible with a project; GUI open question 13).
- [ ] A: a worker-safe `collect` (snapshot in, evidence out) so that Prepare leads does not hold the GUI thread while evidence is collected; public `collect.overview` (the dock imports `_overview`); a snapshot date in `Kev(not-in-snapshot)`; `store.load` split into pointer rows (GUI thread) and sidecar read (worker).
- [ ] BLOCKED, live evidence: real UIA/NVDA/Narrator announcement of the status lines, high-contrast and 200 percent DPI look of the chips, Windows CI of the new tests.

### [D:master-plan]
- Master plan and categorized to-do list for finishing the project: `docs/plans/master-plan-d.md`, `docs/plans/master-todo-d.md`; panel specs prompt for ChatGPT: `docs/plans/chatgpt-panel-specs-prompt.md`.


### [UE2-S6b:live-gates]
- [x] G-U1, G-U2, G-U4 evaluators over `unified-outcomes/1`; G-U8 `ui-policy` tests named; live driver and workflow written; focused tests green on Linux
- [ ] BLOCKED / not run: the first dispatch of `unified-live-gates.yml` (static checks only), the Windows leg, `live_pairs` against a real Ghidra (its pure parts are tested), mutant runs at 20 per class (about 240 Ghidriff runs, one job per class)
- [x] superseded by [UE3-S6c:gates] below (G-U3, G-U6, G-U7, G-U4 chains, G-U1 P1 variants have evaluators; only the BinDiff oracle part of G-U3 stays blocked)


### [UE3-S6c:gates]
- [x] G-U1 P1 nuisance variants (generator and evaluator coverage); built only on the next live `unified-live-gates.yml` run (not dispatched here)
- [x] G-U4 3-build chain (P1 chains) and COS-PSEUDO cross-tier check
- [x] G-U3, G-U6, G-U7 evaluators (pure, synthetic fixtures); G-U3 stays `blocked` on the BinDiff pin even when its data pass
- [x] `gates_u --inputs` assembler with numbers and decision line; workflow: mutants on both systems, integrity job (bench, G-U8 tests)
- [ ] BLOCKED / not run: every live part; whether lld honours each nuisance as intended is known only from the first Tier R build


### [UE2-U3U5:explain-columns]
- [x] Explain fragment in `build_context` / the existing ContextDialog flow (rows with a Ghidriff match); `unified/columns` persisted; qt_gate x5 green on the Unified, columns, host-seam and tooltip tests
- [ ] Open: rows without a Ghidriff match still use the own preview (build_context needs a stored match); Windows DPI and screen-reader passes


### [UE2-U4U6:ir-text-real-gui]
- [x] U6 IR text reader (`IrPairTexts`); U4 hermetic real-pipeline GUI test; qt_gate x5 green (Unified, columns, pipeline, host seam)
- [ ] Open: decompiled C of S3b rows (`decomp.jsonl.gz`) is not yet read for the code panes; alignment gaps from `facts/align.py` are not drawn (the diff pane aligns the two texts itself); Windows (the worker child, DPI)


### [UE4:code-panes]
- [x] Decompiled-C side by side in `CodeDiffView` (stored part, honest unavailable), alignment gaps from the stored IR, hunk navigation, provenance per side, copy with provenance, all states, tooltips, accessible names; 100,000-line cap test
- [ ] Integrator: write `decomp.jsonl.gz` (parts of the manifest, same line shape as `extract/decomp.py`) when the on-demand decompile ran; until then the C mode reports "not stored"

### [LBL-14:ci-summary]
- [x] ci_summary.py, nightly smoke+noise on ubuntu-24.04, determinism and status steps in the merge job (hermetic tests only).
- [ ] First green scheduled run on Actions (not verified here).

### [LBL-prereg:tools]
- [x] P-1 prereg hash tool, P-2 constants test, vendoring scan (PREREG 8.5 i and ii closed; 8.5 iii open).
- [ ] Before the lock: run the vendoring scan over the Tier R per-lineage masked body hashes and apply merge proposals.

### [LBL-13:channels]
- [x] Channel pack scorers with hand-computed goldens (synthetic inputs). Open: real inputs need FLOSS/capa runners (T track) and YARA-X for `rules`.


### [U3-U8:cli-pin]
- [x] U3 S4 CLI polish (early usage errors, exit codes in help); Explain fragment path already built.
- [x] U8 prep: pin checker and runbook. Open (owner, network): run docs/runbooks/bindiff-pin.md, flip `verified`; wire `bindiff_pin verify` into `unified-live-gates.yml`; first dispatch of that workflow.

### [LBL-08:msvc-leg]
- [x] `msvc` profile, probing, host gating, nuisance variants, noise pairs, hermetic tests with fake `cl`/`link` (`tests/test_tier_r_msvc.py`)
- [ ] Owner/CI: run the dispatch-only `msvc-advisory` job of `corpus-tier-r.yml` on windows-2022 (set repository variable TIER_R_MSVC=1) and check the recorded `cl` version, the `/d1trimfile` source-path normalisation and A/A byte identity; advisory until 10 green runs

### [LBL-06:mutations-source]
- [x] Nine added source operators with goldens, compile checks, determinism, recorded rejections, masked-body rule, profile gate
- [ ] Open: the `locate/cases/cli` split of row 06 (the 25 operators are usable through `engine.apply_case`); `buf-resize` must land `review` in the evaluation (frame-only), checked by the evalcore row, not here

### [U7:audit]
- [x] Audit written, 4 Medium fixed with red tests
- [ ] U7-05 BinDiff stub rows reach tier A alone (additive `SecondaryMatch.basicblocks` or IR-aware demotion before fusion)
- [ ] U7-06 decide the budget policy for fusion and facts after a ladder deadline (partial result is lost today)
- [ ] U7-07 trace-arg mutant class for G-U2

### [LBL-07:mutations-ir-opt]
- [x] LBL-07 IR layer + opt layer (`mutations/ir.py`, `mutations/opt_transforms.py`)
- [ ] LBL-07 follow-up: add `opt` to `tier_r/toolchain.CANDIDATES` so `probe()` reports it; wire `agreement_by_operator` into the farm report; IR counterparts for the remaining semantic operators

### [LBL-26:audit]
- [x] Pre-lock audit docs/audits/20261015-lbl26-pre-lock-audit.md; 2 High and 4 Medium fixed with red tests
- [ ] LBL-26 for C: wire guards.audit_identity_roles, natural-only rows, indeterminate worst-case bound, nested tau (audit C-1..C-8)
- [ ] LBL-26 deferred D-01..D-12 (audit doc)

### [WB2-G8:whole-program-sources]
- [x] G8 sources built and tested (synthetic graphs, networkx oracle). Open: snapshot.py must merge `source.limitations`; G9 glue is integrator-owned (frozen files).

### [WB3-S8:strings-run] (2026-10-15, Sonnet 5.5, worktree; Linux)
- [x] `strings/run_service.py`, `ui_strings_run.py`, `tests/test_ui_strings_run.py`.
- [ ] Wire `StringsRunController` into the Strings dock (needs S7b `ui_strings.py`); `ToolStore` built on the GUI thread.
- [ ] Integrator: add `tests/test_live_strings.py` and `tests/fixtures/strings/goldens/**` to `.github/workflows/live-intel-tools.yml` paths and pytest list.

- [x] D7 buildenv/timeline.py (pure) with tests
- [ ] D7 seams: `PairSnapshot.build_env`, `BuildTimelineStrip` in `ui_series.py` (integrator)
- [x] D9 tools/buildenv_value_gate.py with hand-computed goldens (synthetic)
- [ ] D9 run on real Tier R M4 outcomes (needs UE S2/S3 outcomes and the known-answer factory)
- [ ] D8 first dispatch of `live-buildenv` (Actions) and golden confirmation; stays BLOCKED locally without PATCHTRACE_DIEC

### [WB1-S7:search-panel]
- [x] Search dock on the panel framework (states Q0-Q12, paged rows, navigation, cancel, shutdown).
- [ ] Kinds menu, saved searches, suggestion popup, hit-span delegate, F3/Shift+F3, feature-owned paged model (see commit notes).

### [WB2-G5G6:calls-panel]
- [ ] Calls panel follow-ups: graph.export_dot, graph.callsite, graph/* settings, Tree as a lazy model, entry paths.

### [WB3-S7b:strings-panel]

- [ ] Strings panel: wire function pairing and stored observations into the loader; FLOSS run/probe/consent, export, settings (`strings/*`), column tips.

### [CAP-6:capabilities-panel]
- [x] Capabilities dock (CAP-6a changes, CAP-6b setup, probe, preview, run) on the panel framework.
- [ ] Integrator: no `ui.py` change needed; host Open-setup and Run-comparison remedies are not wired.
- [ ] Not built: grouped tree model (flat table with a Group column), commands, C13 reparse refresh, reported-match count for C12.

### [K3:kev-panel]
Done: dock with state matrix, consent, import, changes, copy, go to CVE. Open: replace-anyway after a shrink refusal (needs a staged-install service API), kev/filter and kev/sort settings, network policy port.

### [FAB-6:related]
- [x] Related evidence panel, table-only first release. Open for the integrator: manifest slot, leads area, host wiring of `show_anchor`.

### [LBL-20:fetch-transport] / [LBL-21:symbols]
- [x] Fixture-tested `tier_w/fetch.py`, `transport.py`, `symbols.py`, `symbols_llvm.py`, `ghidra_export_symbols.py`, `symbols_ghidra.py` (`tests/test_tier_w_fetch.py`, `tests/test_tier_w_symbols.py`).
- [ ] BLOCKED, owner/Windows runner: live msdl fetch, live Ghidra 12.0.4 export (`PATCHTRACE_GHIDRA_DIR`), `pyghidra` mode, PDB-forcing pre-script, adapter text for `fetch-plan`/`fetch`/`symbols` (LBL-25).

### [LBL-22:tier-w-labels]
- [x] LBL-22 labels.py and audit.py with synthetic goldens
- [ ] LBL-22 wire to the runner (LBL-23) and real symbol maps (owner machine)

### [LBL-24:tier-w-aggregate]
- [x] LBL-24 evaluate.py and aggregate.py with goldens, guard contract list
- [ ] LBL-24 run on a real Tier W evaluation (owner only, O1)
## Windows per-user installer delivery (2026-10-17)

- [x] Add Inno Setup definition, compiler wrapper and portable-bundle dependency preflights on codex/windows-setup-installer-20261017.
- [x] Add Windows CI install/self-test/uninstall acceptance and include installer plus SHA-256 sidecar in the Windows artifact.
- [ ] Confirm current-head Linux and Windows pytest/Ruff, Windows frozen smoke, installer build and installer lifecycle test.
- [ ] Merge through the established PR checks and publish a new beta release containing the installer. The installer workflow change must be followed by a later non-workflow release-triggering commit per docs/release-process.md workflow-file hazard.

### Codex continuation (2026-10-22)
- [x] Select the newest broad integration baseline (`claude/instance-d-gui`), update it with current `main`, and port PR #100's eight commits on an isolated branch.
- [x] Install declared `dev`, `search`, and `rules` extras; verify the six PR #100 search failures disappear with pinned RapidFuzz installed.
- [x] Reproduce and fix quoted-symbol normalization and COFF function/data boundaries in masked-body acceptance; local synthetic regression tests pass.
- [x] Run combined PR #100 and COFF regression batch: 314 passed, 24 skipped in 63.91 s; compiler-backed cases skipped without Clang.
- [x] Run Ruff on the combined tree before the COFF fix; [ ] rerun after the fix and docs checkpoint.
- [ ] Validate the fix on current-head Windows CI with real Clang; confirm `string-literal-shout` and `callee-swap-dispatch` both pass. PR #64 now points to the published Setup slice (`f625ff63f1c0bb5e1666a24d0cc7284b5c04ddec`), but no Actions run exists for this head; only an owner-side authenticated push or workflow dispatch can start the required checks from this workspace.
- [ ] Run full Linux pytest, Ruff, and current-head Linux/Windows QA, GUI repetition, frozen smoke, portable ZIP and installer lifecycle on the combined branch. Local full pytest and collection attempts remained CPU-bound for 10+ and 2+ minutes respectively and were interrupted; no complete local result is claimed.
- [x] SPEC-53 Setup three-radio mode group and accessible PDB folder list with Add/Remove, empty-list guidance, and legacy online migration.
- [ ] Complete remaining feasible SPEC-53 work: Profiles `local` digest semantics, diagnostics, GHR-5 native air-gap evidence, and decide whether GHR-6 is in release scope.
- [ ] Continue SPEC-DA-01 by dependency order: validate real Diaphora 3.4.3 output before relying on guessed schema details; then implement export import, bounded signals/context, GUI, Mode B, and only pursue Mode C after licensed Windows and distribution review.
- [ ] Inspect open PRs and handoffs for independent unmerged work; deduplicate overlapping LBL-31/LBL-32 and Java/UE changes before porting. Merge only after their current-head checks pass.
- [ ] Generate and validate Windows x64 release artifacts only from the tested combined source state; record hashes and CI run URLs. Do not claim real Ghidriff/Diaphora or owner-only UI evidence from synthetic tests.

### [DA-A] Optional Diaphora result import (SPEC-DA-01 Mode A, 2026-10-21)
- [x] Contracts, hostile-input sqlite guard, result import, address map, provenance binding, Ghidriff bridge, store kind `diaphora-matches`, CLI `diaphora inspect|import|show`, generated schemas (synthetic fixtures only)
- [ ] Verify against a real Diaphora 3.4.3 `.diaphora` result (EA text encoding, ratio range, `type` strings are assumptions); pinned release SHA
- [ ] Export-DB import (functions, blocks, CFG, compilation units), `signals`, `context`, `ui_diaphora.py`, HTML-safe report namespace; Mode B runner/probe (external Python + Diaphora, `jobs.run_process`, cache key per spec); Mode C licensed IDA export; license review before any distribution
