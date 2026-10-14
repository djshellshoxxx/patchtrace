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
