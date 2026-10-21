# Spec registry

Canonical alias for every spec file under `docs/specs/`: the number each file's own text declares, its canonical alias, its status, and the code that owns it. Read this before you cite a spec number. Source files are not edited here. Where a title or prose uses another number, the alias in this file wins.

**Status refresh, 2026-10-14 (branch `work/a`, 430d690).** Statuses and basis columns of Tables A and B were re-checked against code for SPEC-07h, 10, 10b, 11, 30, 31 (README and parts 02 to 08), 34, 35, 36 and the Table B rows (ledger findings F2 to F5 and F10 in `docs/specs/program-e/OUTSTANDING-specs-ledger.md`); SPEC-37 is not started. File lists and PR numbers in the snapshot below are historical.

**Snapshot, 2026-10-14.** `main` = `1560531c7522b10fa5d18ef744ac5a068936ef31`. Its checks (qa on ubuntu and windows, linux-smoke on 22.04 and 24.04, linux-package, release) all succeeded. Open PRs: #40 (SPEC-34, KB/CVE; checks green), #41 (SPEC-37, KB patch search; checks green), #42 (draft, Phase D wave 0 with SPEC-32 and SPEC-33; linux-smoke queued, one native check in progress), #43 (PT-WB workbench; checks green). Table B lists files that exist only on those branches. Re-check GitHub before relying on any row.

## 1. Citation rule

Cite a spec as **repository path plus canonical alias**, for example `docs/specs/three-tool-evidence-adapters.md` (SPEC-36). Never cite a bare number that another document also uses.

1. The alias in this file wins over the number in a document's title or prose. A retired number is never reused.
2. Sub-specs and annexes keep the parent number plus a suffix: `SPEC-07h`, `SPEC-09b`, `SPEC-10b`, SPEC-26 parts B and D, `SPEC-31/00` to `SPEC-31/10`, `KBC-A` to `KBC-H` (SPEC-34 slices), `KPS-A` to `KPS-E` (SPEC-37 annexes), `PT-WB-01` to `PT-WB-04`.
3. Non-numeric families keep their prefix: `SPEC-DA-01`, `SPEC-QB-01/02`, `SPEC-RD-01/02`.
4. A new spec file takes the next free number, currently **SPEC-56** (SPEC-41 to SPEC-55 are allocated: 46 KEV, 47 YARA-X, 49 BinExport/Ghidra-host decision and 55 non-goals come from instance C), and is added to this file in the same change. SPEC-12 to SPEC-25 are reserved for the planning package in `docs/plans/ghidra-semantic-runtime-roadmap.md`; no spec file may use them.
5. Status. **draft**: a proposal or methodology not yet approved to build. **approved**: developer-ready, with no functional code on main. **partial**: some functional scope is built on main and some is open. **built**: functional scope is on main and only external acceptance (native Windows, live tools, manual GUI) is open. The basis is the file's own Status line, checked against `tasks/todo.md` at the snapshot.
6. Numbers marked *proposed* are recommendations for the owner to confirm. Until confirmed, cite the file by path.
7. `tests/test_spec_registry.py` fails when a file under `docs/specs/` (recursive, `program-e/` excluded) is not cited here by its backticked path.

## 2. Table A: spec files on main (1560531)

| File | Number declared in its own text | Canonical alias | Status | Owner (code package) | Basis and open items |
|---|---|---|---|---|---|
| `docs/specs/REGISTRY.md` | none (this index) | REGISTRY | n/a | none | Index of this table |
| `docs/specs/INDEX.md` | none (listing) | INDEX | n/a | none | Generated file listing with SPEC and status; this registry wins on conflict |
| `docs/specs/architecture.md` | SPEC-01 (title) | SPEC-01 | built | ingestion.py, backend.py, jobs.py, persistence.py, service.py, models.py | Core pipeline is on main |
| `docs/specs/schemas.md` | SPEC-02 (title) | SPEC-02 | built | models.py; generated schemas (tools/generate_schemas.py) | Contracts and schema generation on main |
| `docs/specs/verification.md` | SPEC-03 (title) | SPEC-03 | built | tests/ and docs/qa.md (process) | Requirements and audit record; full code audit done 2026-10-12 |
| `docs/specs/ui.md` | SPEC-04 (title) | SPEC-04 | built | ui.py | Clean Windows GUI acceptance still open (external) |
| `docs/specs/runtime-discovery.md` | SPEC-05 (title) | SPEC-05 | built | runtime_discovery.py | Read-only discovery; pre-fills paths only |
| `docs/specs/offline-backend-installer.md` | SPEC-06 (title) | SPEC-06 | partial | offline_bundle.py; packaging tools | Verifier built; no real relocatable payload yet (tasks/todo.md) |
| `docs/specs/enrichment.md` | SPEC-07 (title) | SPEC-07 | partial | enrichment/ (contracts, identity, views, signals, ranking, wil, cve, intelligence, cache, pipeline, storage, profiles) | Phase 2 built; open: 500 ms cache-hit objective (measured 3.1 s), 10k-pair UI gate, handoff-package validation |
| `docs/specs/enrichment-hardening-backlog.md` | SPEC-07h (title) | SPEC-07h | partial | enrichment/cache.py, storage.py, intelligence.py, cve.py | H1-H6, H8, H9, H11-H13 built; H2 pre-prune verified backup (verified_backup.py), H8 legacy cleanup (raw_cleanup.py) and H10 live NVD probe (tools/live_nvd_probe.py, live-nvd workflow) are built; open: first live run and the H7 default flip after Windows CI |
| `docs/specs/acquisition.md` | SPEC-08 (title) | SPEC-08 | partial | acquisition/ (contracts, winbindex, transport, quarantine, delta); ui.py AcquisitionDialog | Open: msdelta on Windows |
| `docs/specs/nway.md` | SPEC-09 (title) | SPEC-09 | built | nway/ (contracts, graph, series) | 3b built; native three-build CI is acceptance only |
| `docs/specs/series-window.md` | SPEC-09b (title) | SPEC-09b | partial | nway/view_model.py, nway/pair_access.py, ui_series.py | Read-only window built; open: open-pair live-project path |
| `docs/specs/bindiff-adapter.md` | SPEC-10 (title) | SPEC-10 | partial | secondary/bindiff.py, bindiff_probe.py, bindiff_inputs.py, bindiff_run.py | Import, probe, run and reconciliation display built (secondary/evidence_view.py, ui_evidence.py, ui_engine_setup.py); open: external acceptance only (live BinDiff run, human goldens) |
| `docs/specs/binexport2-support.md` | SPEC-10b (title); cites SPEC-10 | SPEC-10b | built | secondary/binexport*.py, cli_binexport.py, tools/fuzz_binexport.py | All functional slices built; open: CI/human acceptance only (nightly fuzz evidence, Windows memory-cap run, human goldens) |
| `docs/specs/secondary-engine.md` | SPEC-11 (title) | SPEC-11 | partial | secondary/rzdiff.py, registry.py, engine_env.py | rz-diff runner, parser and reconciliation display built (live-rizin workflow and tools/live_rzdiff_check.py exist); open: first live rizin evidence and external acceptance |
| `docs/specs/multi-engine-orchestration.md` | SPEC-28 (title) | SPEC-28 | partial | secondary/runs.py, registry.py, scheduler.py, store.py, cli_run.py | P1-P5 built; open: C2 live workflow, adapters emitting alternatives |
| `docs/specs/bindiff-execution.md` | SPEC-29 (title); cites SPEC-28, SPEC-10 | SPEC-29 | partial | secondary/bindiff_probe.py, bindiff_inputs.py, bindiff_run.py, cli_bindiff.py; tools/provision_bindiff.py | P1-P5 built; open: P6 live Linux and Windows run, real-driver pair |
| `docs/specs/multi-engine-evidence-calibration.md` | SPEC-27 (title) | SPEC-27 | partial | secondary/reconcile.py, evidence.py; calibration/ (runtime) | Self-declared "experimental"; index not calibrated |
| `docs/specs/multi-engine-evidence-panel.md` | SPEC-28 (title) | SPEC-38 (proposed; collision) | partial | secondary/evidence_view.py, evidence_panel_service.py; ui_evidence.py | C6-1 to C6-4 built; open: C8 manual gates, D5 export status |
| `docs/specs/gui-preflight-inspection.md` | SPEC-26 (title, "proposal") | SPEC-26 (parent; parts A, C, E) | partial | ui.py, tooltips.py, ui_inspection.py, preflight.py, artifact_inspection.py | Self-declared "IN PROGRESS"; part E open |
| `docs/specs/byte-representations.md` | SPEC-26 requirement B (title) | SPEC-26-B | partial | representations/, raw_view.py, artifact_bytes.py | Hex, Binary and Base64 built; open: verified function extents, async paging, persisted results |
| `docs/specs/pe-overview.md` | SPEC-26 requirement D (title) | SPEC-26-D | partial | pe_overview/ (authenticode.py is Windows-only); artifact_inspection.py | Preliminary PE inspection built; open: signed and trusted Windows acceptance, version info, persistence keyed by hash |
| `docs/specs/patch-intent-localization-engine.md` | SPEC-30 (title); cites SPEC-28, SPEC-29 | SPEC-30 | partial | pilot/ (contracts, sources, rules, fusion, quality, tiers, ranking, why, service) | PIL-A1/A2/A3/B1/B2 built as pilot/1 (docs/modules.md); advisory side uses intelligence/; open: GUI, calibration gate, reports |
| `docs/specs/csaf-cve-interpretation-engine.md` | SPEC-28 (title) | SPEC-35 (renamed) | partial | intelligence/ (anchors, explain, hypotheses, lexicon, reports, storage, cli); intelligence/csaf/ (contracts, discovery, transport, validate, normalize, applicability, identity) | 28a/28b contract built in intelligence/csaf/; other modules under intelligence/ present; open: items the spec defers |
| `docs/specs/three-tool-evidence-adapters.md` | SPEC-29 (title) | SPEC-36 (renamed) | partial | intelligence/tools/ (common, capa, floss, diec, normalize, delta, process, runner, store, cli, pins); tools/provision_intel_tools.py | tool-evidence/1: contracts, parsers, normalize, delta, runner, store, CLI and provisioning built; open: live runs, DiE value gate (no false-lead-reduction claim) |
| `docs/specs/calibration-corpus-and-model.md` | "SPEC-28 (proposed number)" (title) | SPEC-39 (proposed; collision) | draft | calibration/ (runtime, ships); tools/calibration/ (dev, never ships) | "DRAFT methodology"; C9-0 ratification open |
| `docs/specs/diaphora-optional-engine.md` | SPEC-DA-01 | SPEC-DA-01 | approved | none on main; planned per docs/plans/diaphora-integration.md | "Developer-ready design; no code" |
| `docs/specs/program-e/GDE-integration-plan.md` | none (plan; spec id unassigned) | GDE (unnumbered) | deferred | none; planned guide/ (contract guide-lesson/1) | Guided RE teacher: authored lessons, closed predicate vocabulary, static hint ladder; no code; deferred until the GUI panel registry and anchor work land; listed as a non-goal for the alpha |
| `docs/specs/qbindiff-inspired-matching.md` | SPEC-QB-01 | SPEC-QB-01 | draft | none on main; planned matching/ | "Proposed; not implemented" |
| `docs/specs/qbindiff-modular-integration.md` | SPEC-QB-02 | SPEC-QB-02 | draft | none on main | Proposed companion to SPEC-QB-01 |
| `docs/specs/radiff2-inspired-comparison.md` | SPEC-RD-01 | SPEC-RD-01 | draft | none on main; planned comparison/ | "Proposed; no feature claimed implemented" |
| `docs/specs/radiff2-modular-integration.md` | SPEC-RD-02 | SPEC-RD-02 | draft | none on main | Proposed companion to SPEC-RD-01 |
| `docs/specs/windows-acceptance-and-milestone-builds.md` | none (self-described "draft spec") | SPEC-40 (proposed; unnumbered) | draft | packaging: tools/build_windows.py, tools/build_linux.py, tools/frozen_smoke.py | Sections marked (new) not implemented |
| `docs/specs/completeness-audit.md` | none (cites SPEC-05, SPEC-07) | none (audit; cite by path) | n/a | none | Audit; its per-row statuses are stale (handoff B4) |
| `docs/specs/kev-exploitation-context.md` | SPEC-46 (title) | SPEC-46 | draft | planned enrichment/kev (KEV-integration-plan) | Draft written 2026-10-14; nothing implemented |
| `docs/specs/yara-x-rule-workflow.md` | SPEC-47 (title) | SPEC-47 | draft | planned rules/ (YRX-integration-plan) | Draft written 2026-10-14; nothing implemented |
| `docs/specs/binexport-producer-ghidra-host.md` | SPEC-49 (title) | SPEC-49 | draft | src/patchtrace/unified/extract/ (S1 extractor), secondary/binexport*.py | ADR draft: who produces BinExport2 |
| `docs/specs/non-goals.md` | SPEC-55 (title) | SPEC-55 | draft | none (decision record) | Non-goals and deferred decisions; ratification by the owner open |
| `docs/specs/unified-engine/README.md` | SPEC-31 (title) | SPEC-31 | partial | unified/ (contracts, keys, limits, store, extract, ir, facts, ladder, fusion, sources, pipeline, worker, cli, read_model, registry); tools/unified/ | Built so far (docs/modules.md): S0a, S0b, S1, S2, S3/S3b, S4a, S5, S6a; open: remaining slices, ui_unified.py, USER decisions |
| `docs/specs/unified-engine/00-decisions.md` | SPEC-31 / 00 | SPEC-31/00 | draft | planned unified/ | Contract-freeze draft; base cb25132 |
| `docs/specs/unified-engine/01-architecture.md` | SPEC-31 / 01 | SPEC-31/01 | draft | planned unified/ (layers, import DAG) | Nothing implemented |
| `docs/specs/unified-engine/02-data-model.md` | SPEC-31 / 02 | SPEC-31/02 | draft | planned unified/ (contracts, limits, keys, registry, store) | S0a built (unified/contracts.py, keys.py, limits.py, store.py); registry.py present |
| `docs/specs/unified-engine/03-extraction.md` | SPEC-31 / 03 | SPEC-31/03 | draft | planned unified/extract/, unified/ir/ | S1 and S3b built (unified/extract/, unified/ir/); remainder planned |
| `docs/specs/unified-engine/04-matching-pipeline.md` | SPEC-31 / 04 | SPEC-31/04 | draft | planned unified/ladder/ | S2 and S5 built (unified/ladder/ incl. residual.py); remainder planned |
| `docs/specs/unified-engine/05-fusion-and-noise.md` | SPEC-31 / 05 | SPEC-31/05 | draft | planned unified/fusion/, unified/facts/ | S0b fusion and S3 facts built (unified/fusion/, unified/facts/) |
| `docs/specs/unified-engine/06-adapters.md` | SPEC-31 / 06 | SPEC-31/06 | draft | planned unified/sources/ | Sources built (unified/sources/ghidriff.py, manual.py, secondary.py) |
| `docs/specs/unified-engine/07-ui-and-cli.md` | SPEC-31 / 07 | SPEC-31/07 | draft | planned ui_unified.py, unified/cli.py | unified/cli.py and S4a read model built; ui_unified.py not built |
| `docs/specs/unified-engine/08-evaluation.md` | SPEC-31 / 08 | SPEC-31/08 | draft | planned tools/unified/ | S6a corpus and gates built (tools/unified/corpus, gates_u.py, bench.py, parity.py, mutations); remainder planned |
| `docs/specs/unified-engine/09-licensing.md` | SPEC-31 / 09 | SPEC-31/09 | draft | none (licence notices) | Notices per technique source |
| `docs/specs/unified-engine/10-amendments.md` | SPEC-31 / 10 | SPEC-31/10 | draft | none (edits to other specs, per slice) | Each amendment applies in its slice's PR |
| `docs/specs/ai-provider-interpretation.md` | none (SPEC-41 assigned) | SPEC-41 | draft | providers.py, interpretation.py, evidence.py | Documents loopback Ollama and HTTPS OpenAI-compatible transports, validation and AI-text rules; findings: loopback check differs on CPython 3.12 vs 3.13, 'no new claims' is prompt-only, transport errors escape unclassified (Haiku draft, probes run) |
| `docs/specs/network-egress-privacy.md` | none (SPEC-42 assigned) | SPEC-42 | draft | acquisition/transport.py, enrichment/intelligence.py, intelligence/csaf/transport.py, providers.py, netutil.py, tools/provision_*.py | 18-row network inventory (hosts, consent, caps), explicit no-telemetry and no-auto-update statements, user-facing privacy text; consent-test gaps listed (Haiku draft) |
| `docs/specs/app-settings.md` | none (SPEC-43 requested) | SPEC-43 | draft | ui.py, ui_evidence.py, ui_series.py, ui_engine_setup.py, enrichment/profiles.py | 27 QSettings keys and profile fields inventoried (Haiku draft, code-checked); section 8 proposals pending owner approval |
| `docs/specs/accessibility-baseline.md` | none (SPEC-45 proposed) | SPEC-45 | draft | ui.py, ui_evidence.py, ui_series.py, ui_engine_setup.py, tooltips.py | Application-wide accessibility, keyboard, DPI and English-only localization baseline; 54 controls without accessible names inventoried; AX-M1..M6 are owner/Windows gates (Haiku draft) |
| `docs/specs/cli-umbrella.md` | none (SPEC-44 proposed) | SPEC-44 | draft | cli.py, backend_cli.py, secondary/cli_*.py, intelligence/cli.py, intelligence/tools/cli.py, unified/cli.py | Umbrella CLI rules, per-verb flag tables and flag registry; doctor, export, import, show, project proposed not in the alpha (Haiku draft, flags checked against --help) |
| `docs/specs/anchor-fabric.md` | none (SPEC-48 assigned) | SPEC-48 | partial | fabric/ (contracts, ids, origins, ports, memory, store, pins, convert) | FAB-0, FAB-1, FAB-2, FAB-4 built; open: FAB-3 PIL adoption, FAB-5 CLI, FAB-6 related panel, Windows CI |
| `docs/specs/report-export-contract-v2.md` | none (SPEC-50 assigned; was RPT2) | SPEC-50 | draft | reports.py (v1 only); v2 not built | Promoted from program-e; draft for build, v2 opt-in |
| `docs/specs/unified-engine/12-features2-proposal.md` | SPEC-31 / 12 | SPEC-31/12 | proposal | none (text for the C9 owner, amendment A-07) | Proposal only; nothing built |
| `docs/specs/unified-engine/13-remaining-work-plan.md` | SPEC-31 / 13 | SPEC-31/13 | plan | none (plan only) | Slices UE-R1..UE-R13; how-to steps in `docs/handoff/unified-engine.md` |
| `docs/specs/panels/README.md` | none (index) | SPEC-54 (panels) | n/a | none | Index of per-panel specs, not a spec itself |
| `docs/specs/panels/related.md` | none (SPEC-54 panel) | SPEC-54 | proposed | fabric/panel.py, fabric/related.py, ui_related.py | FAB-6 `related` panel contract, written from the code |
| `docs/specs/panels/graph-inspection.md` | none (SPEC-47 panel) | SPEC-47 | proposed | callgraph/minimap.py, callgraph/minimap_qt.py, callgraph panel_data | Calls panel DOT export, call-site reveal, minimap |
| `docs/specs/kb/adapter-binding-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | KB adapters bound to the correlation port; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/advisory-revision-and-snapshot-identity-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | Advisory revision and snapshot identity; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/beta-budgets-help-and-acceptance-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | KB beta budgets, help and acceptance; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/cve-to-function-matching-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | CVE-to-function matching; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/leads-dock-lifecycle-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | Leads dock lifecycle; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/live-acquisition-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | Live KB acquisition; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/search-anchors-bridge-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | Search anchors bridge; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/store-threading-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | KB store threading; written by the KB gameplan worker, not yet built |
| `docs/specs/kb/vendor-feeds-and-source-matrix-spec.md` | none (KB gameplan) | SPEC-KB | proposed | kbcorrelation/, kb adapters | Vendor feeds and source matrix; written by the KB gameplan worker, not yet built |
| `docs/specs/pe-version-authenticode.md` | none (SPEC-51 assigned); part D2 of SPEC-26 | SPEC-51 | partial | pe_overview/ (resources.py, version_info.py, manifest.py built; authenticode.py Windows-only) | D2-1 and D2-2 built; open: DER and embedded-signature digest, catalog check, compare rows, CLI and GUI tab |
| `docs/specs/windows-release-signing-policy.md` | none (SPEC-52 assigned) | SPEC-52 | draft | none (policy); tools/build_windows.py, release workflow | Nothing is signed; owner decisions on a signing service are open |
| `docs/specs/ghidriff-launcher-symbols.md` | none (SPEC-53 assigned) | SPEC-53 | draft | planned backend.py launcher; enrichment/cache.py | Not built; closes the local-only symbol policy item in tasks/todo.md |
| `docs/specs/gui-framework.md` | none (SPEC-54 assigned) | SPEC-54 | partial | gui/ (registry, anchors, projection, capabilities, state, text, shortcuts, theme_math, ports, cli); cli_commands/; panel_manifest.py; tooltips.py | Pure core built; Qt host layer, panels and accessibility audit not built |

PR #42 also modifies these main files: `bindiff-execution.md`, `binexport2-support.md`, `csaf-cve-interpretation-engine.md`, `enrichment.md`, `enrichment-hardening-backlog.md`, `multi-engine-evidence-panel.md`, `three-tool-evidence-adapters.md`, and every file under `unified-engine/`. The rows above describe main; PR #42 may change their status when it merges.

## 3. Collisions and decisions

| Number | Claimed by (declared text) | Decision | Canonical aliases |
|---|---|---|---|
| SPEC-28 | `multi-engine-orchestration.md` (title); `multi-engine-evidence-panel.md` (title); `csaf-cve-interpretation-engine.md` (title); `calibration-corpus-and-model.md` ("proposed number") | SPEC-28 stays multi-engine orchestration. CSAF moves to SPEC-35. The evidence panel gets SPEC-38 (proposed). Calibration gets SPEC-39 (proposed). | SPEC-28, SPEC-35, SPEC-38, SPEC-39 |
| SPEC-29 | `bindiff-execution.md` (title, C4); `three-tool-evidence-adapters.md` (title) | SPEC-29 stays BinDiff execution, the number used by the code, the tracker and `docs/modules.md`. The three-tool suite moves to SPEC-36. | SPEC-29, SPEC-36 |
| SPEC-31 | `unified-engine/` (main; unified diff engine); `kb-cve-correlation-and-acquisition.md` and `kb-cve/` (PR #40, title "SPEC-31") | SPEC-31 is the unified diff engine. KB/CVE correlation moves to SPEC-34, with slices KBC-A to KBC-H. | SPEC-31, SPEC-34 |
| SPEC-32 | `known-answer-corpus.md` (PR #42, title); `kb-patch-search-and-pair-resolution.md` and annexes 32A to 32E (PR #41, title) | SPEC-32 is the known-answer corpus. KB patch search moves to SPEC-37, with annexes KPS-A to KPS-E. | SPEC-32, SPEC-37 |
| SPEC-33 | `tier-w-local-corpus.md` (PR #42) only | Not a collision. SPEC-33 is the Tier W local-only corpus. | SPEC-33 |
| SPEC-26 | `gui-preflight-inspection.md` (parent); `byte-representations.md` (part B); `pe-overview.md` (part D) | Not a collision: parts of one requirement set. | SPEC-26, SPEC-26-B, SPEC-26-D |
| SPEC-07, SPEC-09, SPEC-10 | `enrichment-hardening-backlog.md`, `series-window.md`, `binexport2-support.md` | Sub-specs of a parent number. Not collisions. | SPEC-07h, SPEC-09b, SPEC-10b |
| SPEC-12 to SPEC-25 | `docs/plans/ghidra-semantic-runtime-roadmap.md` (planning package for SPEC-12; reserves 13 to 25) | Reserved. No spec file uses them. | reserved |
| none | `windows-acceptance-and-milestone-builds.md` | Unnumbered. Proposed SPEC-40. | SPEC-40 (proposed) |
| SPEC-38, SPEC-39, SPEC-40 | Unused in docs/ on main, and in the docs/specs and docs/plans trees of every open PR branch, at the snapshot | Proposed in order of need: 38 evidence panel (built), 39 calibration (draft), 40 Windows acceptance (draft). Next free: SPEC-41. | proposed |

Renames (the number in the old title is replaced by the canonical alias): the CSAF spec, titled SPEC-28, becomes SPEC-35; SPEC-29 three-tool becomes SPEC-36; SPEC-31 KB/CVE becomes SPEC-34; SPEC-32 KB patch search becomes SPEC-37. Plan slices follow their parent: in `docs/plans/csaf-patch-intelligence-implementation.md`, SPEC-28a and SPEC-28b are SPEC-35a and SPEC-35b; SPEC-29a, 29b and 29c are SPEC-36a, 36b and 36c; SPEC-30a to 30d keep their numbers.

## 4. Read-through map for old numbers

Specs, plans and research written before this registry use the old numbers. This registry does not edit them. Read a number by its context:

| Old text | Context marker | Read as |
|---|---|---|
| SPEC-28 | Engine-run records, secondary/registry, scheduler, run_engines, C0, C1, C2, C5, P1-P5, max_parallel, exit codes, failure isolation | SPEC-28 |
| SPEC-28 | Evidence panel: C6, evidence dock and view, ui_evidence, "SPEC-28 panel" | SPEC-38 |
| SPEC-28 | Calibration: C9, locked test, calibration gates, display level, "numbers before SPEC-28 gates" | SPEC-39 |
| SPEC-28 | CSAF: advisories, VEX, CSAF 2.0, normative parser, product applicability | SPEC-35 |
| SPEC-29 | BinDiff execution: C4, bindiff_*.py, pinned BinDiff | SPEC-29 |
| SPEC-29 | Three-tool suite: capa, FLOSS, DiE, intelligence/tools/ | SPEC-36 (slices 29a to 29c = SPEC-36a to 36c) |
| SPEC-31 | Unified diff engine: unified-engine/, unified/, slices S0a to S6, U-01 to U-10 | SPEC-31 |
| SPEC-31 | KB/CVE correlation: MSRC reverse index, acquisition packages, slices 31-A to 31-H | SPEC-34 (31-A to 31-H = KBC-A to KBC-H) |
| SPEC-32 | Known-answer corpus: Tier R, A-A, planted mutations | SPEC-32 |
| SPEC-32 | KB patch search: annexes 32A to 32E, pair resolution | SPEC-37 (32A to 32E = KPS-A to KPS-E) |

Examples. `docs/specs/patch-intent-localization-engine.md` line 6, "validated advisory facts (SPEC-28)", reads as SPEC-35. `docs/specs/unified-engine/05-fusion-and-noise.md`, "SPEC-28 owns calibration and display levels", reads as SPEC-39. `docs/specs/tier-w-local-corpus.md`, "calibration-corpus-and-model.md (SPEC-28/C9)", reads as SPEC-39. `docs/specs/unified-engine/10-amendments.md`, "multi-engine-evidence-panel.md (SPEC-28 panel)", reads as SPEC-38.

## 5. Table B: spec files that were on open PR branches at the 1560531 snapshot

These files were not on `main` at 1560531. As of 2026-10-14 (branch `work/a`, 430d690) they are in the tree and the test requires them; statuses were re-checked against code on that branch. They are listed so that the aliases in sections 3 and 4 have a registered target. Rows stay here to preserve the snapshot grouping.

| File | Number declared in its own text | Canonical alias | Status | Owner (code package) | Basis and open items |
|---|---|---|---|---|---|
| `docs/specs/kb-cve-correlation-and-acquisition.md` (PR #40) | SPEC-31 (title) | SPEC-34 | partial | kbcorrelation/ (contracts, ids, products, alias_catalog, index, cli_index, sources/) | K0 contracts, K1 sources and K1-K2 index built (docs/modules.md); open: acquisition packages, UI, workflow |
| `docs/specs/kb-cve/README.md` (PR #40) | SPEC-31 addenda index | SPEC-34 (index) | approved | none | Documentation only |
| `docs/specs/kb-cve/31-A-contracts-identity.md` (PR #40) | SPEC-31-A | KBC-A (SPEC-34) | approved | planned acquisition/ | Design only; contract kbcorrelation/1 |
| `docs/specs/kb-cve/31-B-msrc-reverse-index.md` (PR #40) | SPEC-31-B | KBC-B (SPEC-34) | approved | planned | Provider research required |
| `docs/specs/kb-cve/31-C-product-build-pairs.md` (PR #40) | SPEC-31-C | KBC-C (SPEC-34) | approved | planned | Implementation pending |
| `docs/specs/kb-cve/31-D-acquisition-packages.md` (PR #40) | SPEC-31-D | KBC-D (SPEC-34) | approved | planned acquisition/ | Optional advanced package support |
| `docs/specs/kb-cve/31-E-evidence-intent.md` (PR #40) | SPEC-31-E | KBC-E (SPEC-34) | approved | planned | Optional semantic mechanisms cite "SPEC-28/30"; read them per section 4 |
| `docs/specs/kb-cve/31-F-workflow-ui-persistence.md` (PR #40) | SPEC-31-F | KBC-F (SPEC-34) | approved | planned cli.py and ui.py seams | Depends on 31-A to 31-D |
| `docs/specs/kb-cve/31-G-components-discovery.md` (PR #40) | SPEC-31-G | KBC-G (SPEC-34) | approved | planned | Developer-ready |
| `docs/specs/kb-cve/31-H-tests-release.md` (PR #40) | SPEC-31-H | KBC-H (SPEC-34) | approved | planned test corpus | Developer-ready |
| `docs/specs/kb-patch-search-and-pair-resolution.md` (PR #41) | SPEC-32 (title) | SPEC-37 | approved | planned patch_search/service.py facade | Implementation not started; no patch_search package in the tree |
| `docs/specs/kb-patch-search-source-adapters.md` (PR #41) | SPEC-32A | KPS-A (SPEC-37) | approved | planned | Docs only |
| `docs/specs/kb-patch-search-pair-lifecycle.md` (PR #41) | SPEC-32B | KPS-B (SPEC-37) | approved | planned | Docs only |
| `docs/specs/kb-patch-search-ui-cli-contract.md` (PR #41) | SPEC-32C | KPS-C (SPEC-37) | approved | planned | Docs only |
| `docs/specs/kb-patch-search-qa-and-fixtures.md` (PR #41) | SPEC-32D | KPS-D (SPEC-37) | approved | planned | Docs only |
| `docs/specs/kb-patch-search-contract-blueprint.md` (PR #41) | SPEC-32E | KPS-E (SPEC-37) | approved | none (examples, not runtime code) | Examples for implementers |
| `docs/specs/known-answer-corpus.md` (PR #42) | SPEC-32 (title) | SPEC-32 | partial | corpus/ and docs/schemas/corpus/ (PR #42) | Partially built (tools/calibration/tier_r, tools/unified/corpus) |
| `docs/specs/tier-w-local-corpus.md` (PR #42) | SPEC-33 (title); refines "SPEC-28/C9" | SPEC-33 | partial | tools/calibration/ (dev only, never ships) | W1 built (tools/calibration/tier_w); exporters, labels, runner and CLI deferred |
| `docs/specs/unified-engine/11-review-log.md` (PR #42) | SPEC-31 review log | SPEC-31/11 | n/a | none | Review log, not a spec |
| `docs/specs/workbench/README.md` (PR #43) | PT-WB index (cites SPEC-29, SPEC-31) | PT-WB (index) | approved | none | Developer-ready design; no implementation |
| `docs/specs/workbench/01-search-fts5-rapidfuzz.md` (PR #43) | PT-WB-01 | PT-WB-01 | approved | none (planned search index) | Not implemented |
| `docs/specs/workbench/02-networkx-callgraph.md` (PR #43) | PT-WB-02 | PT-WB-02 | approved | none (planned) | Not implemented |
| `docs/specs/workbench/03-floss-strings.md` (PR #43) | PT-WB-03; "SPEC-29" means the three-tool suite | PT-WB-03 | approved | planned intelligence/tools/floss.py (SPEC-36) | Reuses the SPEC-36 FLOSS adapter |
| `docs/specs/workbench/04-quickwins.md` (PR #43) | PT-WB-QW | PT-WB-04 | draft | none | "Ranked proposals, not implementation" |
