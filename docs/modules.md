# Module index

Stable IDs are independent of filenames. Public interfaces in SPEC-01 and schemas in SPEC-02 are source of truth. Module implementations remain independently usable without Qt.

| ID | File | Responsibility and public interface | Dependencies | Ownership / test seam |
|---|---|---|---|---|
| contracts | models.py | Versioned validated artifact/project/run/function/match/evidence/context/finding/job/export records | pydantic | Pure data; schema and invariant tests |
| ingestion | ingestion.py | inspect_artifact and immutable copies; PE AMD64 validation | contracts | Disk staging; synthetic PE fixtures |
| persistence | persistence.py | create/load/save project, lock, backups, revision history | contracts | SQLite connection confined to its creating thread; temp roots |
| normalization | normalization.py | normalize_ghidriff, preserve unavailable fields | contracts | Pure conversion; upstream JSON fixtures |
| alignment | alignment.py | Bounded line alignment and hunks; large-input fallback | contracts | Pure lines; unequal/empty fixtures |
| offline bundle | offline_bundle.py | Strict inventory verifier, checksum-bounded ZIP inspection, transactional per-user extraction and deterministic producer | stdlib | Synthetic ZIP, traversal, tampering, cancel, rollback, Qt import tests |
| runtime discovery | runtime_discovery.py | Bounded read-only local Python/Ghidra path candidate discovery (no execution or network) | stdlib | Injected filesystem/env and Qt setup prefill tests |
| backend | backend.py | Discover configured dependencies; construct verified argv | contracts | External runtime config; fake executable |
| jobs | jobs.py | Child lifecycle, log bounds, timeout/cancellation | backend | Job Object/process group; fake children |
| evidence | evidence.py | Context selection, digest, evidence resolution | contracts | Pure exact references; forged IDs |
| interpretation | interpretation.py | Prompt, strict responses, citation validation | evidence/providers | Result only, no project writes; fake responses |
| providers | providers.py | Loopback Ollama and HTTPS OpenAI-compatible transports | stdlib | Session-only credentials; HTTP fixtures |
| findings | service.py | Reviews, manual matches, notes, stale invalidation | contracts/persistence | Service owns project aggregate; transaction tests |
| desktop | ui.py | Wizard/workspace/settings/context preview/evidence navigation | service/jobs | Main thread Qt; pytest-qt |
| reports | reports.py | JSON/Markdown/self-contained HTML and manifests | contracts | Atomic exports; injection fixtures |
| diagnostics | diagnostics.py | Dependency status, bounded redacted logs and pure fixed-text Ghidriff exit classification | stdlib | No credentials; redaction tests |
| samples | sample.py | Representative synthetic ordinary fix with explicit sample identity | contracts | Never masquerades as real analysis |

| enrichment.contracts | enrichment/contracts.py | Strict frozen enrichment/1 records, statuses, typed EnrichmentError (SPEC-07) | pydantic | Pure; contract tests |
| enrichment.identity | enrichment/identity.py | Canonical JSON, domain-separated SHA-256 diff/occurrence/pairing/signal/stage IDs | stdlib | Pure; property tests |
| enrichment.views | enrichment/views.py | Ownership-checked immutable run/match/function views with bounded code | contracts/alignment/models | Pure; forged-ownership tests |
| enrichment.signals | enrichment/signals.py | B1 deterministic detectors BND/INT/OVF/VAL/ERR/SIZE/SCRUB | views/contracts | Pure; positive/negative fixtures |
| enrichment.ranking | enrichment/ranking.py | Exact integer attention/1 scoring, grouping and ordering | contracts/identity | Pure; golden arithmetic |
| enrichment.wil | enrichment/wil.py | B2 Feature_<uint32> sites, transitions and WIL signals | views/contracts | Pure; recognition/negative fixtures |
| enrichment.cve | enrichment/cve.py | B3 pure CVE normalization, snapshots and contextual reranking | contracts/identity | Pure; redacted provider fixtures |
| enrichment.intelligence | enrichment/intelligence.py | B3 consented, bounded HTTPS MSRC/NVD transport | stdlib urllib | Injected opener; no live calls in tests |
| enrichment.cache | enrichment/cache.py | B4 content-addressed derived/raw cache, locks, leases, eviction | contracts/identity | Temp roots; crash-point tests |
| enrichment.pipeline | enrichment/pipeline.py | Stage orchestration, cancellation, partial status | above (not transport) | Injected adapters |
| enrichment.storage | enrichment/storage.py | Additive enrichment tables through ProjectStore/Service | persistence | v1 compatibility tests |
| cli | cli.py | Headless commands rank/flags/correlate/cache; never imports Qt | enrichment/service | Subprocess import test; exit-code contract |
| acquisition (planned) | acquisition/*.py | SPEC-08 Winbindex metadata, consented msdl download, quarantine, PE/PA30 identification, optional Windows msdelta | stdlib/ingestion/ctypes | Fake opener; live probe recorded separately |
| nway (planned) | nway/*.py | SPEC-09 series of adjacent pair projects, 1:1 chain hypotheses | service/models | Synthetic pair fixtures |
| secondary matches | secondary/*.py | SPEC-10 BinExport/BinDiff validation and import; SPEC-11 rz-diff runner/parser; reconciliation | protobuf (optional), jobs | Handcrafted files; optional live tools |
| secondary orchestration | secondary/{runs,registry,scheduler,store,cli_run}.py | SPEC-28 C1/C5: `EngineRun` records + cache key, adapter registry (rz-diff, bindiff=unsupported until C4, ghidriff-baseline provenance), `run_engines` (max 2 parallel, shared cancel, deadlines, failure isolation), `current_sets()` one set per engine (`secondary/2`), `secondary run` CLI | jobs.run_process, enrichment storage | Portable `sys.executable -c` fake engines; fake rz-diff scripts (POSIX); no live rizin evidence |
| nway | nway/contracts.py, graph.py, series.py | SPEC-09 series of adjacent pair projects, 1:1 chain hypotheses; tolerant discovery, recoverable `series.json` (`--replace-corrupt`), classified staleness (SPEC-09b s4) | service/models | Synthetic pair fixtures |
| nway.pair_access | nway/pair_access.py | SPEC-09b read-only open-read-close of one pair project into a `PairSnapshot` (state, stored default-profile ranking, names); never writes, never raises per-pair | service, enrichment | Real pair fixtures plus fake readers |
| nway.view_model | nway/view_model.py | SPEC-09b pure `load_view`/`apply_query` producing `SeriesView` rows, per-hop scores, filters, sorting, `chain_text` | nway, pair_access | Pure tests with injected fake reader |
| secondary matches (planned) | secondary/*.py | SPEC-10 BinExport/BinDiff validation and import; SPEC-11 rz-diff runner/parser; reconciliation | protobuf (optional), jobs | Handcrafted files; optional live tools |
| secondary orchestration | secondary/{runs,registry,scheduler,store,cli_run}.py | SPEC-28 C1/C5: `EngineRun` records + cache key, adapter registry (rz-diff, bindiff=unsupported until C4, ghidriff-baseline provenance), `run_engines` (max 2 parallel, shared cancel, deadlines, failure isolation, `on_outcome` per-engine delivery so Ctrl+C keeps finished engines), reconcile rows carry `alternatives` + `matches-alternative-rank-N`, `current_sets()` one set per engine (`secondary/2`), `secondary run` CLI | jobs.run_process, enrichment storage | Portable fake engines (`tests/fake_exe.py`: shebang on POSIX, `.cmd` on Windows; heartbeat tree-kill assertion); Windows runs of these not yet seen on CI; no live rizin evidence |
| artifact bytes | artifact_bytes.py | SPEC-26 shared seam: `VerifiedArtifactReader.open_artifact/open_path`, bounded `read(offset,length,clip)` on a SHA-256-verified handle; change detection; `ArtifactBytesError.code` | ingestion/contracts | Pure IO, no Qt; tmp-file tests |
| pe overview (alpha) | pe_overview/*.py | SPEC-26 D: bounded stdlib PE header/section/directory/import/export/entropy/overlay/certificate-table parsing, field-level old/new comparison; `inspect(reader) -> PeOverview`; Authenticode trust isolated in Windows-only `authenticode.py` | artifact bytes | Pure; synthetic/hostile PE fixtures; native Windows trust tests skip elsewhere |
| byte representations (alpha) | representations/*.py | SPEC-26 B: paged Hex/Binary/Base64 rendering of exact verified bytes; whole-file/file-range/function-RVA scopes via injected section map | artifact bytes | Pure; boundary fixtures |
| tooltip registry (alpha) | tooltips.py | SPEC-26 A: semantic-ID tooltip registry, safe templates, `apply_tooltips`; New/Open exempt | Qt (apply only) | Registry tests + widget enumeration test |
| artifact inspection (alpha) | artifact_inspection.py | SPEC-26 D orchestration: `inspect_project_artifacts(project_id, artifacts, root, cancel) -> ProjectInspection` (per-side verified reader + `PeOverview` + `compare_overviews`); per-side failure codes never hide the other side; owner closes readers | artifact bytes/pe overview | Pure; tampered/missing/cancel tests |
| raw view (alpha) | raw_view.py | SPEC-26 B composition: whole-file and from-function-entry scopes (entry RVA via section map, extent never claimed), `build_side`, `differing_lines` | pe overview/representations | Pure; mapping and diff tests |
| series UI | ui_series.py | `SeriesWindow` and `SeriesLoadThread`: renders a `SeriesView`, plain-text cells, Open-pair signal; hook in ui.py is one action | Qt, nway.view_model | pytest-qt offscreen, tooltip audit |
| inspection UI (alpha) | ui_inspection.py | `InspectionThread` independent of analysis jobs; PE comparison table rendering | Qt, artifact inspection | pytest-qt via MainWindow |
| packaging | tools/build_windows.py; tools/build_linux.py; tools/pyinstaller_hooks/ | Frozen Windows/Linux runtimes, curated Qt desktop plugins, licenses, inventory and checksum | PyInstaller | Windows/Linux Actions and archive inspection |

Every substantial future module must be added here before implementation. UI must not own analysis logic; provider must not own project state.

## Phase C6 evidence panel modules (SPEC-28 evidence panel, owner C6)

| Module | Files | Responsibility | Depends on | Tests |
|---|---|---|---|---|
| evidence view | secondary/evidence_view.py | Pure typed view-model (`EvidenceViewModel`, `EvidenceRow`, `EngineCell`, `EngineInfo`, `Alternative`), verdict mapping Agree/Contested/Single engine/Unknown, per-engine native cell text (never combined), `sanitize_text`, `filter_rows`, `format_provenance_block`, state precedence E0-E8 | secondary.reconcile/evidence | Pure table-driven tests, banned-string sweep, no-Qt subprocess import |
| evidence panel service | secondary/evidence_panel_service.py | Pure orchestration: immutable `EvidenceRequest` -> `load_evidence` (newest set per engine, reconcile, assess, build), `detect_stale`, `EngineOutcomeView` adapter over SPEC-28 `EngineOutcome`, `RunRequest` + `execute_run` over `scheduler.run_engines` | evidence view, secondary scheduler | Pure tests with injected fake registry |
| evidence UI | ui_evidence.py | Qt adapter: `EvidenceController` (dock, generation counter, GUI-thread persistence), `EvidencePanel`, table/filter-proxy/engine-status models, badge delegate, `EvidenceLoadThread`/`EngineRunThread` (workers see immutable requests only) | Qt, evidence panel service | pytest-qt offscreen per state E0-E8, hostile strings, thread tests, tooltip audit |
## C4 BinDiff execution (SPEC-29, 2026-10-14)
| Module | File | Responsibility | Depends on | Tests |
|---|---|---|---|---|
| bindiff probe | secondary/bindiff_probe.py | `--version`/`--help` capability probe (major >= 8, required options, untested newer majors, `bindiff_ui`/`bindiff_cli` refused, never PATH), cached per (path, mtime, size); `sanitize` | jobs.run_process, engine_env | `tests/test_bindiff_probe.py` (fake `bindiff`) |
| bindiff inputs | secondary/bindiff_inputs.py | `AcceptedBinExportLike` Protocol (C3 seam), `bind_pair` (SHA-256 `executable_id` binding, orientation, explicit asserted override), `copy_and_hash` | contracts | `tests/test_bindiff_inputs.py` |
| bindiff run | secondary/bindiff_run.py | private workdir, fixed argv, output guard, success = exit 0 + one `older_vs_newer.BinDiff`, raw preserved before hardened import, §6 kinds | bindiff_probe, bindiff_inputs, bindiff | `tests/test_bindiff_run.py` |
| engine env | secondary/engine_env.py | single child-env allow-list for secondary engines (rz-diff via `backend.build_child_env`, BinDiff from scratch) | backend | `tests/test_engine_env.py`, `tests/test_live_rzdiff_check.py` |
| bindiff CLI | secondary/cli_bindiff.py | `--older/--newer-binexport`, `--accept-unbound-binexport`, `PATCHTRACE_BINDIFF`, C3 acceptor wrapper | registry | `tests/test_cli_bindiff.py` |
| live harness | tests/conftest.py, tests/test_live_bindiff.py, tools/{provision_bindiff,check_live_status,make_bindiff_fixtures}.py, tools/bindiff_pin.json, .github/workflows/live-bindiff.yml | never-silent live status (`passed/failed/blocked`), fail-closed pinned provisioning, synthetic goldens | - | `tests/test_live_harness.py`, `tests/test_bindiff_golden.py` |
| live pair + real golden (C4 follow-up) | tests/bindiff_live_pair.py, tests/fixtures/secondary/bindiff-v8-real-on-synthetic.* , bindiff-8-help.txt | stdlib BinExport2 encoder for the SYNTHETIC live pair; real v8 output/help used as goldens; provisioning now extracts the `.deb` with stdlib ar+tar and verifies the pinned executable | patchtrace.sample | `tests/test_bindiff_live_pair.py`, `tests/test_bindiff_real_golden.py`, `tests/test_provision_bindiff.py` |
### C9 calibration (2026-10-14; synthetic validation only)
| Module | Files | Responsibility | Depends on | Verification |
|---|---|---|---|---|
| calibration runtime (ships, pure) | src/patchtrace/calibration/{features,artifact,predict,ood,policy}.py | `features/1` extraction from stored Ghidriff + `Reconciliation` rows (families G,B,R,S,P,X, dependency table, profiles); strict `patchtrace-calibration-model/1` loader (size cap, strict JSON, digest, schema/semantic checks, no pickle) that degrades to no-model; predict + provenance; OOD flags; policy order; `display_level()` = 'ordinal' unless a valid artifact carries passing gates | models, secondary.reconcile (read-only) | tests/test_calibration_runtime.py (golden vectors, loader negatives, policy table, no forbidden imports) |
| calibration dev pipeline (never ships) | tools/calibration/*.py, tools/calibration/guidelines/g1.md | contracts (corpus/labels/report), corpus verify/fetch + no-PE/Tier-W guard, lineage union-find + identity grouping + roles, sampling, blind labelling log, kappa, stdlib IRLS/Platt/PAV, grouped nested CV, metrics, lineage bootstrap, Learn-then-Test thresholds, null-simulated ECE, OOD validation, ablations, baselines (M0, M0b raw bytes, M1, M2), gates, deterministic report, single-use locked test, synthetic worlds, schema generation | patchtrace.calibration, acquisition.contracts | tests/test_calibration_{math,metrics,cv,tools}.py; optional scikit-learn cross-check (`calibration-dev` extra) |
## C3 BinExport2 support (2026-10-14, SPEC-10b `binexport2-support.md`)
| Module | Files | Responsibility | Depends on | Verification |
|---|---|---|---|---|
| BinExport2 acceptance | secondary/binexport_{limits,descriptor,proto,prescan,check,identity,snapshot,models,pipeline,worker,run,producer}.py; secondary/binexport.py (facade); secondary/cli_binexport.py | Upb-only runtime from a checked-in descriptor set (private pool). Wire pre-scan before parse, the §6.5 structural checker, identity/orientation/address basis, a TOCTOU-safe snapshot, and a memory/time-capped worker. Public seam: `accept_binexport` -> `AcceptedBinExport(snapshot_path, summary)` plus `accept_pair`. CLI: `secondary binexport-check` and a hidden `_binexport-worker`. | jobs.run_process (`memory_limit_bytes`), contracts, protobuf==7.36.2 | Synthetic messages and goldens, mutation oracle, hypothesis never-crash, real worker and fake-worker isolation tests, Linux frozen smoke B1/B2. Windows CI and real Ghidra/IDA goldens are still open. |
## SPEC-31 unified diff engine (planned, 2026-10-14; spec `docs/specs/unified-engine/`, plan `docs/plans/unified-engine-plan.md`)
| Module | Files | Responsibility | Depends on | Status / slice |
|---|---|---|---|---|
| unified contracts | src/patchtrace/unified/{contracts,limits,keys,registry}.py | strict `unified-*`/`program-ir`/`change-facts` records, `UnifiedLimits` (L-xx), identities and cache keys, data-driven source/pass/channel registry | pydantic, enrichment.identity | planned, S0a |
| unified store | src/patchtrace/unified/store.py | sidecar dirs under `runs/<run_id>/unified/`, pointer rows (`unified-run`, `unified-result`; KINDS only, not DERIVED_KINDS), own retention | enrichment.storage | planned, S0a |
| unified sources | src/patchtrace/unified/{addressing.py,sources/*} | Ghidriff (normalized + verified raw), secondary sets, manual corrections (later Diaphora) -> evidence atoms; VA/RVA and `EXTERNAL:` handling | models, secondary.store, pe_overview | planned, S0b |
| unified fusion | src/patchtrace/unified/fusion/{components,arbiter}.py | independence components, rule-based decisions, contest strength; never averages | registry | planned, S0b |
| unified facts | src/patchtrace/unified/facts/{pseudo,channels,verdict,align,operands}.py | L2 channels C0-C8, proof tiers, operand-delta classifier | ir.reader | planned, S0b/S3 |
| unified IR | src/patchtrace/unified/ir/{schema,ingest,features,mdindex,pe_tables,reader}.py | strict ingest of extractor JSONL into a read-only sidecar SQLite, masks L0-L3, BinDiff-style MD index (Apache-2.0 attribution), .pdata/.reloc | artifact_bytes, pe_overview | planned, S1 |
| unified extraction | src/patchtrace/unified/extract/{ghidra_script,runner}.py | thin Ghidra fact dumper run by the external Python (never imports patchtrace); runner via jobs.run_process | jobs, backend env builders | planned, S1 |
| unified ladder | src/patchtrace/unified/ladder/{passes,engine,propagate,groups,blocking,residual,assign}.py | uniqueness-gated pass ladder, propagation with votes/conflicts, groups, residual assignment with rejection | ir.reader | planned, S2/S5 |
| unified pipeline | src/patchtrace/unified/{pipeline,worker,cli,read_model}.py | stage orchestration, hidden `_worker`, `unified` CLI verbs, Qt-free view model | all unified modules | planned, S0b/S4 |
| unified UI | src/patchtrace/ui_unified.py | navigator view switch + dock tab in the single MainWindow; threads per C6 rules | Qt, read_model | planned, S4 |
| prerequisites | jobs.py (spawn lock), nway/graph.py (`EXTERNAL:` keys) | latent defects found while grounding SPEC-31 | - | planned, P1/P2 |
## Phase D track B hardening (2026-10-14)
| Module | File | Responsibility | Depends on | Tests |
|---|---|---|---|---|
| verified backup | verified_backup.py | SPEC-07h H1/H2 amendment: `write_verified_backup` (backup API -> `.part` -> close -> read-only re-open -> `integrity_check` + identity queries -> rename), `find_verified_backup`/`trusted_backup` (read-only `quick_check`, project id, required table; verdict cached per process by path+size+mtime), `ensure_verified_backup`; used before every history prune and enrichment retention/`make_room`/engine-run deletion | stdlib, ingestion.safe_path | `tests/test_prune_backup.py` |
| raw cleanup | raw_cleanup.py | SPEC-07h H8 amendment: `cleanup_legacy_raw_duplicates(root, project)` on `ProjectService.open(maintenance=True)` removes `runs/<id>/raw/json/*.ghidriff.json` only when the run's `raw_path` is the legacy copy and both hash to `raw_sha256`; journal `backups/raw-duplicates.jsonl` written (fsync) before each removal; `restore_raw_duplicates(root)` reverses it; never raises; N-way readers open with `maintenance=False` | ingestion.safe_path | `tests/test_raw_legacy_cleanup.py` |
