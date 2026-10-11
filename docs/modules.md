# Module index

Stable IDs are independent of filenames. Public interfaces in SPEC-01 and schemas in SPEC-02 are source of truth. Module implementations remain independently usable without Qt.

| ID | File | Responsibility and public interface | Dependencies | Ownership / test seam |
|---|---|---|---|---|
| contracts | models.py | Versioned validated artifact/project/run/function/match/evidence/context/finding/job/export records | pydantic | Pure data; schema and invariant tests |
| ingestion | ingestion.py | inspect_artifact and immutable copies; PE AMD64 validation | contracts | Disk staging; synthetic PE fixtures |
| persistence | persistence.py | create/load/save project, lock, backups, revision history | contracts | SQLite connection confined to its creating thread; temp roots |
| normalization | normalization.py | normalize_ghidriff, preserve unavailable fields | contracts | Pure conversion; upstream JSON fixtures |
| alignment | alignment.py | Bounded line alignment and hunks; large-input fallback | contracts | Pure lines; unequal/empty fixtures |
| backend | backend.py | Discover configured dependencies; construct verified argv | contracts | External runtime config; fake executable |
| jobs | jobs.py | Child lifecycle, log bounds, timeout/cancellation | backend | Job Object/process group; fake children |
| evidence | evidence.py | Context selection, digest, evidence resolution | contracts | Pure exact references; forged IDs |
| interpretation | interpretation.py | Prompt, strict responses, citation validation | evidence/providers | Result only, no project writes; fake responses |
| providers | providers.py | Loopback Ollama and HTTPS OpenAI-compatible transports | stdlib | Session-only credentials; HTTP fixtures |
| findings | service.py | Reviews, manual matches, notes, stale invalidation | contracts/persistence | Service owns project aggregate; transaction tests |
| desktop | ui.py | Wizard/workspace/settings/context preview/evidence navigation | service/jobs | Main thread Qt; pytest-qt |
| reports | reports.py | JSON/Markdown/self-contained HTML and manifests | contracts | Atomic exports; injection fixtures |
| diagnostics | diagnostics.py | Dependency status and bounded redacted logs | stdlib | No credentials; redaction tests |
| samples | sample.py | Representative synthetic ordinary fix with explicit sample identity | contracts | Never masquerades as real analysis |
| workspace | workspace.py (planned, SPEC-05) | Ghidra-safe local workspace: path validation (GP-* rules), staged input names, publish/quarantine, stale cleanup | ingestion | Pure paths; fake-Ghidra path rule fixture |
| config | config.py (planned, SPEC-05) | Strict versioned PatchTraceConfig shared by GUI and CLI; precedence/provenance; QSettings migration | contracts/persistence | Pure JSON; temp config roots |
| analysis | analysis.py (planned, SPEC-05) | Headless execute/commit orchestration extracted from desktop | backend/service/workspace | Thread-confined commit; fake backend |
| cli | cli.py (planned, SPEC-05) | Subcommands, flag-to-ghidriff mapping, exit codes, run report; never imports Qt | config/analysis/reports | Subprocess and golden-help tests |
| packaging | tools/build_windows.py; tools/pyinstaller_hooks/ | Frozen Windows runtime, curated Qt desktop plugins, licenses, inventory and checksum | PyInstaller | Windows Actions and archive inspection |

Every substantial future module must be added here before implementation. UI must not own analysis logic; provider must not own project state.
