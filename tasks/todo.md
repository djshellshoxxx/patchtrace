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
- [ ] Next wave: `fetch` (binaries via quarantine.acquire, PDBs via a Transport subclass, throttle/resume/disk/cancel), Ghidra/PyGhidra exporter + `symbol-map/1` writer + optional llvm-pdbutil adapter, labels + N2/N3/N9/N10 tags, audit queue + error rate, runner (symbols hidden/visible), `evaluate`, CLI, docs/plans/tier-w-runbook.md
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
