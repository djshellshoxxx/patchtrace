# PatchTrace internals

A short map of how the code is organised. The per-module table is `docs/modules.md`; engineering policy is `AGENTS.md`; interfaces are specified in `docs/specs/`.

## Layers
1. **Contracts and pure domain** (`models.py`, `evidence.py`, `alignment.py`, `normalization.py`, `enrichment/contracts.py`, `*/contracts.py`): strict, frozen pydantic records, canonical-JSON identity, no I/O, no Qt.
2. **Adapters** (stdlib or optional-dependency, no Qt): file and format readers (`ingestion.py`, `artifact_bytes.py`, `pe_overview/`, `representations/`, `secondary/` BinExport, BinDiff and rz-diff), network transports behind injected openers (`acquisition/`, `enrichment/intelligence.py`, `providers.py`), tool adapters (`intelligence/` capa, FLOSS, diec, CSAF), process control (`jobs.run_process`, `backend.py`).
3. **Services and feature engines** (Qt-free): `service.py` owns the project aggregate; `enrichment/` (signals, ranking, cache, pipeline), `unified/` (unified diff engine), `nway/` (series), `pilot/` (patch-intent leads), `kbcorrelation/`, `kev/`, `rules/`, `fabric/` (anchors), `codetext/`, `symbols/`, `calibration/` (shipped runtime only; fitting stays in `tools/calibration/`).
4. **Presentation**: `ui*.py` and `gui/` (Qt, main thread; `gui/` holds the pure panel registry, projection, anchors and capabilities, with Qt widgets behind it) and `cli.py` plus `cli_commands/` (headless, never imports Qt). `tooltips.py` and `panel_manifest.py` are shared seams with a single owner.

Rule: a lower layer never imports a higher one. UI owns no analysis logic and a provider owns no project state. A new panel is a dock or tab in the single main window, built from a pure view-model.

## Data flow
Two PE artifacts are ingested into immutable verified copies (`ingestion`, `artifact_bytes`) and a `ComparisonProject`. The Ghidriff backend runs as a child process (`jobs`), its JSON is normalised (`normalization`) and persisted (`persistence`, SQLite). Enrichment derives signals, attention ranking and CVE context from those records (`enrichment`), keyed by content-addressed identities (older/newer SHA-256 plus sorted RVAs), cached in `enrichment/cache`. Secondary engines add `EngineRun` match sets that `secondary/reconcile` compares and never averages; disagreements are kept as `contested`. The unified engine, PE overview, tool evidence, KB, KEV and CSAF produce further per-candidate observations. `pilot/` fuses advisory-side and code-side observations in an origin-aware ledger into ordinal tiers and a tie-aware order (no numbers). Reports (`reports.py`) and the UI read stored results; they do not recompute them.

## Process boundaries
- The GUI process never executes a target binary. Analysis tools (Ghidra, Ghidriff, rz-diff, BinDiff, capa, FLOSS, diec) run as bounded child processes through `jobs.run_process` (absolute executable, `shell=False`, allow-listed environment, timeout, output bound, Windows Job Object or POSIX process group so grandchildren die on cancel).
- Network access exists only in explicit consented operations (acquisition, CVE and advisory fetch, bundle acquisition); tests use injected openers.
- Qt work stays on the main thread; background work uses worker threads that own their SQLite connections. Cancellation is cooperative with a hard kill after the deadline.
- Optional heavy dependencies (protobuf for BinExport, scikit-learn for `calibration-dev`) are loaded lazily through `optional_deps.py`; `tools/` is dev-only and excluded from packaging.
- Frozen builds (`tools/build_windows.py`, `tools/build_linux.py`) are checked by `tools/frozen_smoke.py`.

## Persisted contracts
All contracts are versioned (`name/N`) and change additively only; readers ignore unknown additive fields and refuse unknown versions.
- Project: SQLite snapshots with `PRAGMA user_version = SCHEMA_VERSION` (1), writer ownership, bounded revision history and verified backups (`persistence.py`, `verified_backup.py`).
- Enrichment tables are additive records in `enrichment/storage.py`; `KINDS` is the closed set of kinds and derived kinds are cache-invalidated by identity.
- JSON contracts with generated schemas in `docs/schemas/` (enrichment, secondary, intelligence, unified, kbcorrelation, kev, fabric, pilot, rules, calibration, corpus, intel-tools, profile) and a regenerate-and-compare drift test. `pilot/1` results carry a `result_id` over all input digests, so staleness is derived and never mutates evidence.
- Calibration artifacts (`patchtrace-calibration-model/1`) ship read-only with a digest; no artifact ships today, so `display_level()` stays ordinal.
- CLI output uses the `enrichment-cli/1` envelope with exit codes 0, 2, 3, 4 and 5.

## Invariants that shape the design
Never execute a target; never upload silently; never fabricate evidence; never show an uncalibrated number as confidence; keep conflicts; unknown is not a negative; shared-origin evidence counts once; explicit orientation; provenance everywhere; untrusted text is bounded and escaped. Full list: `docs/plans/worker-brief.md` section 2.
