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
| packaging | tools/build_windows.py; tools/build_linux.py; tools/pyinstaller_hooks/ | Frozen Windows/Linux runtimes, curated Qt desktop plugins, licenses, inventory and checksum | PyInstaller | Windows/Linux Actions and archive inspection |

Every substantial future module must be added here before implementation. UI must not own analysis logic; provider must not own project state.
