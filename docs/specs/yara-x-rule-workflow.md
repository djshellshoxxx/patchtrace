# YARA-X rule workflow (SPEC-47)

Status: draft, 2026-10-14. Owner: unassigned (the integration owner assigns the build). Documents: no `src/patchtrace/rules/` package exists on this checkout; the existing code this spec builds on is listed in section 2. Derived from `docs/specs/program-e/YRX-integration-plan.md` (E-1 research, 2026-10-14). Items marked `[proposal]` are the recommended design; nothing marked `[proposal]` is built or approved.

## 1. Scope and non-goals

In scope: one analyst-driven workflow from ONE accepted changed-function pair to a tested, provenance-carrying YARA-X rule version:

1. Select an accepted pair (`review=accepted`).
2. Propose at most 3 older-build and 3 newer-build rule candidates from verified evidence (bytes, strings, imports, capabilities).
3. Review the candidates side by side with their evidence.
4. Accept one candidate explicitly. This stores an immutable rule version in the project.
5. Test the version (YARA-X, in a capped worker) against the series builds, extra builds and a local clean set. Results are a tri-state grid with raw counts.
6. Export a local `.yar` file with a provenance header, on an explicit action.

Non-goals (each is a defect if added without a new spec):

- a free-text YARA editor, a generic rule scanner, or a rule library shared across projects;
- any "all functions" or bulk mode; CLI and GUI take exactly one pair;
- publish, upload, share, or clipboard-to-network;
- flaw or fix verdicts, and any reading of a match as "affected" or "fixed";
- rule hits as triage votes or as corroboration (rules derive from the same bytes as the match; SPEC-36 classes YARA-X as derived evidence, see section 2);
- process or memory scanning; regex, `include`, or any module other than `pe` in generated rules;
- AI-written rules; delete (only archive).

## 2. Existing code this spec builds on

Verified on this checkout (`worktree-agent-aefb4df19292844c0`, HEAD `fd6cdba`).

| Area | Location | What this spec uses it for |
|---|---|---|
| Optional capability probe | `src/patchtrace/optional_deps.py:20-29` | `yara_x` is imported behind a guard and registered as `'yara-x': ('rules', ...)`. Source of the blocked state R1 (section 8). |
| Dependency declaration | `pyproject.toml:15` `rules = ["yara-x>=1.0,<2"]` | A version range. R-18 requires an exact pin; the change is an integrator ask (section 9). |
| Process supervision | `src/patchtrace/jobs.py:233` `run_process(argv, cwd, env, cancel, timeout_seconds, ..., memory_limit_bytes, max_output_bytes)`; docstring: terminates descendants on every exit | The rule worker (R-08) runs through it. Existing exercise: `tests/test_secondary_scheduler.py`, `tests/fake_exe.py`. |
| Reserved row kinds | `src/patchtrace/enrichment/storage.py:39-55`: `rule-candidate`, `rule-decision`, `rule-version`, `rule-test`, `rule-export` are in `KINDS`; `DERIVED_KINDS` is at line 55 and lists none of them | The kinds exist already, so retention never deletes them. The plan's storage amendment (YRX plan section 10) is therefore already applied; the integrator verifies it once. |
| Sidecar pattern | `src/patchtrace/intelligence/tools/store.py:1-6` (inline <= 1 MiB, else `<project>/intel-tools/<sha256>.json`); atomic content-addressed writes at `store.py:38` and `:55` | Matrix runs over 1 MiB (section 4) follow the same pattern. |
| Text bounding and secrets | `src/patchtrace/intelligence/tools/common.py:40` `sanitize(text, limit=200)`; `:434` `secret_kind(value)`; `:443` `redacted_display(display, kind)` | Untrusted string text is bounded and escaped; secret-looking strings are excluded (R-10). |
| String evidence | `src/patchtrace/intelligence/tools/delta.py:55-58` `StringChange` (`display_value` max 256, `secret_kind`); `:250` redacts unless `show_secrets` | Source of string candidates. The display form is escaped, so it never seeds a byte pattern; exact bytes are re-read from the artifact (R-10). |
| Pair and series contracts | `src/patchtrace/nway/contracts.py:34-47` `BuildRef`, `PairRef` (`project_id`, `revision`, `run_id`); `:17` `Ordinal` bounded by `MAX_BUILDS` | Grid rows and provenance keys. |
| Function records | `src/patchtrace/models.py:52` `FunctionRecord` | The plan reports that it holds decompiler and assembly text only, with no bytes or extents. This writer did not re-read its fields: `[unverified]`. Bytes therefore need an extent source (R-12). |
| Derived-evidence class | `docs/specs/three-tool-evidence-adapters.md:11` (canonical alias SPEC-36; its own title says SPEC-29) | YARA-X "counts as derived, not independent evidence". Basis of R-11. |
| Guard tests | `tests/test_enrichment_core.py:193` (pure modules import no Qt, network or subprocess); `tests/test_kbc_contracts.py:384`; `tests/test_intel_cli.py:3` (`enrichment-cli/1` envelope, exit codes 0/2/3/4/5, no Qt in CLI paths) | Patterns the `rules/` guards copy (R-06, section 6). |
| Synthetic PE fixtures | `tests/test_intel_tools_pe.py` | Only fixture source for the known-answer scenario (section 7). |

Not present on this checkout: `src/patchtrace/rules/`, `src/patchtrace/pe_overview/tables.py`, `tests/rules_fixtures.py`, `tests/test_rules_*.py`, `tests/test_spec_registry.py` (cited by `docs/specs/REGISTRY.md` section 1, item 7; not found in `tests/` here).

Derived-evidence and Qt-free rules are inherited from `docs/specs/program-e/YRX-integration-plan.md` section 3 (charter check).

## 3. Product invariants applied

These restate the repository invariants for this feature. Violating one is a defect.

- Offline by default: no network import in `rules/`; no upload, publish, share or clipboard transfer.
- No target execution: YARA-X and the decoder read bytes of hash-verified files. Nothing is run, loaded as a module, or deserialized from untrusted input.
- Unknown is not a negative: an unscanned or unreadable file is never counted as "No match" and never as clean.
- Uncalibrated numbers are never shown as confidence: no score, percent, or accuracy. Counts per state only.
- Advisory, string and code text is untrusted: bounded, escaped, never executed, never a pattern source.
- One main window: the Rules page is a dock or tab, never a separate window.
- Pure domain and adapters stay separate from Qt; persisted contracts change additively only.
- Microsoft-derived bytes, PDBs and Winbindex-derived labels are never committed. Fixtures are synthetic.

## 4. Normative requirements

Each requirement is `[proposal]` unless it cites existing code in section 2.

**Input and analyst control**

- R-01 (MUST) A proposal takes exactly one function pair with `review=accepted`. Verdict `material` is required; otherwise the analyst confirms it and the candidate is flagged `unvetted`. DIE `packed` or `protected` flags block byte features.
- R-02 (MUST) No bulk mode. No `--all`, `--yes` or equivalent flag exists on any CLI verb or GUI action.
- R-03 (MUST) Propose writes candidate rows only. Nothing is accepted, tested or exported automatically.
- R-04 (MUST) Accept requires an analyst label (1..120 characters). It stores an immutable rule version and does not publish or export anything. Accept and export are separate actions.
- R-05 (MUST) Export is an explicit action to an analyst-chosen path. It writes a local `.yar` file with the header in section 6. If the path is inside a Git working tree, the export refuses unless the analyst sets an explicit acknowledgement.
- R-06 (MUST) No network import in `rules/` (AST test, pattern of `tests/test_enrichment_core.py:193`).
- R-07 (MUST) Nothing executes a target. Scans run over bytes read from a hash-verified artifact. Process and memory scanning are out of scope.

**Isolation and rule safety**

- R-08 (MUST) Every `yara_x` call runs in a child worker started through `jobs.run_process` (`src/patchtrace/jobs.py:233`) with a timeout, a memory cap and cooperative cancel. The parent process never imports `yara_x`. The worker catches `BaseException` (YARA-X panics derive from it) and exits with code 23.
- R-09 (MUST) Rule text comes only from the closed serializer. Generated rules contain no `include`, no regex, and only `import "pe"`. Compilation uses `error_on_slow_pattern=True` and `includes_enabled=False`, with `allowed_metadata`, `allowed_rule_name` and `allowed_tags`. A candidate passes compile only with zero warnings, except the style warning `text_as_hex`. Rules are never loaded through `deserialize_from`.
- R-10 (MUST) Untrusted text is data. Rule text, advisory text and string values are escaped or whitelisted. Strings for which `secret_kind` (`common.py:434`) is set are never used. Only `static` strings are used. Exact bytes are re-read at the recorded offset, never taken from the escaped display form.
- R-11 (MUST) Results are cells, not scores: `Match`, `No match`, `Not scanned: <reason>`, `Timed out`, `Error`. `No match` is never a negative vote. A rule hit never enters the attention or evidence-panel corroboration, and never raises the match's channel count. The series flip (the build where a rule starts or stops matching) is the only new observation and counts once, as channel `series bytes`.
- R-12 (MUST) Byte features come from decoded instructions, not raw text. Masks cover RIP-relative displacements and out-of-function branch displacements, and operand fields covered by a base relocation. Immediates are kept. Function extents come from `.pdata` or the unified IR; when neither gives an extent, the candidate fails with `PT-RULE-MASK`. Decoder: `MaskSource` port, default `iced-x86`, unified-IR adapter later.
- R-13 (MUST) Byte-window eligibility requires the gates in section 5. Thresholds are provisional until calibrated on Tier R (R8 of the plan).

**Provenance and state**

- R-14 (MUST) Every rule version records `EngineStamp` (engine `yara-x`, version, version source, decoder and version, grammar `yrx-gen/1`, worker `rules-worker/1`), the pair identity (project, revision, run, both SHA-256 values, match id, RVAs) and the label.
- R-15 (MUST) Storage is append-only. A revision is a new version with `supersedes` set. Versions are archived, never deleted.
- R-16 (MUST) Staleness is derived on read: artifact hash mismatch is a hard stale; a run id change is a notice; an engine or grammar bump marks the grid stale and keeps the rule text unchanged.
- R-17 (MUST) Determinism: canonical feature order, content-addressed ids, LF-only ASCII rule text, and no timestamps in the hashed body. Dates appear only in header comments.
- R-18 (MUST) Pins: `yara-x==1.21.0` and `iced-x86==1.21.0`, exact, wheels only (`--only-binary=:all:`). A version bump is a dedicated change that re-runs the grid. Both licences (BSD-3-Clause and MIT) ship in the notices.
- R-19 (MUST) If the engine or decoder is unavailable, the Rules page shows state R1 and saved rules stay readable. Nothing else is blocked.
- R-20 (SHOULD) Function names are omitted from rules and exports by default, because they may come from symbol files. `--include-names` is an explicit opt-in.

## 5. Candidate generation and gates

Generation runs only after R-01 holds.

1. Strings: `StringChange` added or removed on the side, with exact bytes re-read at `offset`. `linked_by=xref` when a decoded RIP target equals the string RVA.
2. Imports: differing `pe_overview` imports, and API gates from capa `api` features. One call pin per masked `call [rip+disp]` whose target is an IAT slot (`pe.import_details[].functions[].rva` equals the slot RVA, per the plan's measurement).
3. Capabilities: metadata and gates only (never a condition alone). Only `newly-introduced` and `removed-with-code` count; `newly-detectable` and `unlocalized` are ignored.
4. Bytes: take the changed range from a `difflib.SequenceMatcher(autojunk=False)` over masked instruction tokens. Grow the window over context instructions until the gates pass, capped at 128 bytes. Keep up to 3 windows per direction, ranked by literal bytes, unique in the source build and absent from the other.
5. Compose per direction: the default included set is the bytes window, its pins, its linked strings and the import gates. Other features are offered unticked. Toggling re-runs the checks; it is a revision, never free text.
6. In the worker: compile with the linters, then scan the pair. `sep` requires a hit at the expected RVA in its own build and no hit in the other.

Gates (`gate_id`, state `pass fail unknown waived`):

| Gate | Rule | Measured value shown |
|---|---|---|
| `elig` | accepted review, material verdict or confirmed | verdict and review |
| `len` | literal (unmasked) bytes >= 16 and longest literal run >= 6 | literal bytes, longest run |
| `wild` | wildcards <= 40 % of window bytes | ratio |
| `uniq` | exactly one hit in the source build; grow to <= 128 B otherwise reject | hit count |
| `sep` | hit at the expected RVA in its own build, no hit in the other build | hit counts per build |
| `compile` | zero warnings except `text_as_hex` | warning codes |
| `secret` | no `secret_kind` string | count |
| `dist` | builds share one toolchain (DIE `toolchain-changed` otherwise) | flag |

Metrics are raw and never combined into a score. The engine's slow-pattern warning is not a sufficient gate on its own; the own metrics above are required (the plan measured that `slow_pattern` does not fire for `{ ?? ?? ?? ?? }`).

## 6. Contracts (proposed; package `src/patchtrace/rules/`, contract `yara-rules/1`)

Models are Pydantic v2, `extra='forbid'`, strict, frozen (pattern of `tool-evidence/1`). Field lists are the plan's section 7, condensed.

| Model | Fields |
|---|---|
| `EngineStamp` | `engine='yara-x'`, `version`, `version_source` (`metadata`/`pin`), `decoder`, `decoder_version`, `grammar='yrx-gen/1'`, `worker='rules-worker/1'` |
| `PairSource` | `project_id`, `revision`, `run_id`, `older_sha256`, `newer_sha256`, `match_id`, `category` (modified/added/removed), `review`, `materiality`, `analyst_confirmed_material`, `finding_id`, `cwe`, `older`/`newer` as `FunctionRef{name, rva, size, extent}` |
| `BytesFeature` | `side`, `window_rva`, `length` (16..512), `pattern` (hex tokens, `??` wildcards), `literal`, `longest_run`, `mask` (subset of `rip-disp`, `branch-ext`, `reloc`, `addr-ref`), `mask_source`, `pins` (<= 4 `CallPin`), `source_hits`, `other_hits`, `separation` |
| `StringFeature` | `side`, `value_sha256`, `length`, `text` (escaped), `encoding` (`ascii`/`wide`/`ascii-wide`), `offset`, `evidence_run_id`, `linked_by`, `separation` |
| `ImportFeature`, `CapabilityFeature` | `dll`, `name` or `ordinal`, `delay`, `origin`, `separation`; for capabilities also `rule_id`, `namespace`, `attack`, `classification` |
| `Gate` | `gate_id`, `state`, `measured`, `detail` |
| `RuleCandidate` | `candidate_id`, `lineage_id`, `direction` (`older`/`newer`), `source`, `features` (each with `included`), `rule_name` (`PT_<12 hex>_<older|newer>`), `rule_text` (<= 64 KiB), `rule_sha256`, `gates`, `compile_warnings`, `engine`, `unvetted` |
| `RuleDecision` | `decision_id`, `candidate_id`, `action` (`accept`/`reject`/`defer`/`archive`), `analyst_label`, `note`, `cve[]`, `kb[]`, `cwe[]` (regex-validated), `decided_at` |
| `RuleVersion` | `version_id`, `lineage_id`, `version`, `supersedes`, `candidate_id`, `decision_id`, `rule_text`, `rule_sha256`, `source`, `engine`, `created_at` |
| `TargetRef` | `target_id`, `label`, `role` (`older-anchor`/`newer-anchor`/`series`/`extra`/`clean`/`control`), `sha256`, `size`, `ordinal`, `expect`, `advisory_says`, `file_version`, `kb`, `toolchain_flag` |
| `CellResult` | `state` (`hit`/`no-hit`/`not-scanned`/`timeout`/`error`), `hits`, `offsets` (<= 8), `rvas`, `reason`, `elapsed_ms`, `verdict` (`as-expected`/`unexpected-hit`/`unexpected-miss`/`unscored`) |
| `MatrixRun`, `ExportRecord` | `run_id`, `cache_key`, `engine`, `status` (`complete`/`partial`/`cancelled`/`failed`), `targets`, `cells`, `limits`, `anomalies`; `export_id`, `version_id`, `basename`, `sha256`, `exported_at`, `warnings` |
| `WorkerRequest`, `WorkerResult` | request `op` (`probe`/`lint`/`scan`), rules as `[{name, text}]`, targets as `[{target_id, path, sha256 or null, size}]`, limits, result path; result `kind` (`ok`/`error`), `engine`, `lint`, `cells` |

Row ids: `domain_id('rule-candidate'|'rule-lineage'|'rule-version', 1, ...)`. Matrix cache key: `domain_id('rule-test', 1, {rule_sha256s, target sha256s, engine version, worker contract, limits})`, hashes only, never paths.

Limits (`limits.py`, one frozen dataclass whose digest enters the keys) `[proposal]`:

| Limit | Value |
|---|---|
| rule text | 64 KiB |
| patterns per rule | 12 (hex <= 4, text <= 8); v1 uses one hex pattern and at most 4 text patterns |
| hex pattern / text pattern | 512 B / 256 B |
| meta string | 512 characters |
| function bytes | <= 64 KiB |
| candidates | 3 per direction, 200 per run |
| versions per lineage | 50 |
| targets | series <= 8, extra <= 64, clean <= 2,000, file <= 128 MiB, 8 GiB per run |
| rules per run | 50 |
| grid cells | 105,000 |
| per-target timeout | 30 s (range 5..300), run wall time 1 h |
| `max_matches_per_pattern` | 64 |
| worker memory | 1 GiB (hard maximum 2 GiB) |
| stderr tail | 8 KiB, sanitized with `sanitize` |

Error codes (`PT-RULE-*`):

| Code | Meaning (state) |
|---|---|
| `PT-RULE-INPUT`, `-LIMIT`, `-STALE`, `-INTEGRITY` | bad selection or contract; a cap was hit; artifact or project moved; hash or row or sidecar mismatch |
| `PT-RULE-UNAVAILABLE`, `-ENGINE`, `-TIMEOUT`, `-CANCEL` | `yara_x` or decoder missing (state R1); worker crash, panic or non-zero exit; deadline; cooperative cancel |
| `PT-RULE-MASK`, `-DECODE`, `-COMPILE`, `-GATE` | no verified extent or mask source; invalid instruction; generated rule failed compile (a bug or engine drift); accept or export refused by a hard gate |
| `PT-RULE-STORAGE`, `-EXPORT` | row write failed; export path or policy refused |

Export header (exact lines; no paths or user names; names only with `--include-names`) `[proposal]`:

```
// patchtrace-rule-export/1
// Rule PT_0123456789ab_older version 2, label "<analyst label, ASCII>"
// Built by PatchTrace <ver> with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 1.21.0 (MIT)
// Project <project id>, analysis run <run id>
// Older build <basename> sha256 <64 hex>; newer build <basename> sha256 <64 hex>
// Source change: removed function at older RVA 0x104d, reviewed as material; function names omitted
// Accepted <UTC>. Tested <UTC>: 4 builds, 12 clean files, 0 unexpected matches, 0 not scanned (or "Not tested")
// Advisory anchors given by the analyst and not checked by this rule: CVE-YYYY-NNNN KBNNNNNNN CWE-NNN
// Origin: byte patterns copied from the analysed files on the analyst's computer. If those files are third-party software, check its licence before sharing this rule or committing it to a repository.
// A match means a file contains this pattern. It does not show whether the file is affected by a flaw.
```

## 7. Test and acceptance plan

Existing tests this spec relies on (they exist on this checkout; none covers `rules/`):

| Rule | Existing guard |
|---|---|
| R-06 no network in pure modules | `tests/test_enrichment_core.py:193`, `tests/test_kbc_contracts.py:384` (pattern) |
| CLI envelope and exit codes (section 8) | `tests/test_intel_cli.py` |
| Worker process supervision (R-08) | `tests/test_secondary_scheduler.py`, `tests/fake_exe.py` (fake child executable) |
| Synthetic PE fixtures | `tests/test_intel_tools_pe.py` |
| String redaction (R-10) | `tests/test_intel_tools_delta_wb3.py` `[unverified: not read for this spec]` |
| Tooltip registry (section 8) | `tests/test_tooltips.py` |

Planned tests `[proposal]` (none exist): `test_parent_never_imports_yara_x` (subprocess), `test_rules_have_no_network_imports` (AST), `test_cli_has_no_bulk_flags`, `test_accept_and_export_are_separate_actions`, `test_export_header_has_no_paths_or_names_by_default`, `test_secret_strings_never_exported`, `test_repo_guard_rejects_rule_exports`, `test_worker_timeout_kills_child_tree`, `test_worker_baseexception_exit_23`, `test_grid_cells_never_negative_for_unscanned`, `test_banned_strings_never_appear`, `test_synth_is_formatter_fixed_point`, `test_rules_contract_schema_regenerates` (regenerate-and-compare).

Known-answer scenario (`[proposal]`, file `tests/test_rules_synergy.py`, grid in `tests/fixtures/rules/synergy-matrix.json`): built from `tests/test_intel_tools_pe.py` pairs (`capa-api` older V1 and newer V2; `capa-control` with V1r; `diec-toolchain` with V1t) plus three new synthetic images. Expected: the older-build rule from `term` (removed function, RVA 0x104d) matches V1, V1r, V1t and no others. Exact bytes miss V1r (recall 2 of 3); masked bytes also hit the synthetic LA and BOTH images; only the call-target pin gives 3 of 3 with no false positive. These numbers are the plan's measurements with yara-x 1.21.0 and iced-x86 1.21.0 on Linux and must be confirmed on Windows CI.

Gaps against this spec: no `rules/` package, no fixture images for LA, IMP and BOTH, no golden grid, no worker, no store, no CLI, no Qt panel.

Gates that only CI or the owner can close, reported separately and never counted as done:

- Windows CI run of the known-answer grid and a frozen worker scan.
- Windows start-up time, Defender or EDR behaviour, and antivirus scan of `yara_x.pyd` (embedded JIT for rule conditions; ACG or EDR behaviour is `[unverified]`).
- NVDA or Narrator announcements and 125/150/200 % DPI of the panel.
- Tier R stability numbers (plan R8) and calibrated thresholds.
- Real Microsoft series through Tier W, local only; never committed.

## 8. Operating states and copy

Derived from the plan's states R0-R8 `[proposal]`. Exact text:

| ID | Trigger | Text |
|---|---|---|
| R0 | no project | "Open a project to work with detection rules." |
| R1 | engine or decoder unavailable | "The rule engine (YARA-X) is not available in this installation. Rules cannot be proposed or tested. Saved rules stay readable." |
| R2 | no accepted pair selected | "Select a function pair you have accepted. Rules are only proposed for pairs you have reviewed." |
| R3 | ready, nothing proposed | "No rules proposed for this pair yet. Choose Propose rules. Nothing is generated or saved until you ask." |
| R5 | no candidate passes | "No rule passed the checks for this pair: {first failing check}. Bytes are unavailable when the function size is not known." |
| R6 | stale | "These rules describe an earlier analysis or engine version ({reason}). Test again before relying on them." |

Grid footer (always visible): "A match means the file contains this pattern. It does not show whether the file is affected by a flaw. No match does not show that it is unaffected. Counts are raw numbers, not scores."

Not-scanned reasons (closed list): "file is larger than the limit", "file could not be read", "not a PE image", "file changed while reading", "run was cancelled".

The CLI (`rules/cli.py`, envelope `enrichment-cli/1`, `--json` one document; exit 0 ok, 2 invalid or unavailable, 3 runtime or partial, 4 complete but empty, 5 cancelled) `[proposal]`:

```
patchtrace rules probe
patchtrace rules propose PROJECT --match ID [--direction older|newer|both] [--confirm-material]
patchtrace rules show PROJECT [--candidate ID | --version ID]
patchtrace rules decide PROJECT --candidate ID (--accept --label TEXT [--cve --kb --cwe --note] | --reject | --defer | --archive)
patchtrace rules test PROJECT --version ID [--series DIR] [--extra FILE...] [--clean-dir DIR] [--expect FILE.json] [--timeout S]
patchtrace rules export PROJECT --version ID --out FILE.yar [--include-names] [--allow-git-tree]
patchtrace rules history PROJECT [--lineage ID]
```

GUI: one page "Rules" in the Workbench dock, registered through the panel registry. Until that registry exists, a dock is hidden until a project opens and is tabified with the evidence dock. Never a separate window. Accessible names and tooltip ids are defined in the plan (section 8) and are `[proposal]`.

## 9. Open questions with recommended defaults

| Question | Recommended default |
|---|---|
| Package name: `rules/` (plan) or `yarax/` (`docs/plans/ledger-B.md` line 10) | Keep `rules/`; contract `yara-rules/1`, classes `Rule*`, errors `PT-RULE-*`. The integrator reconciles the ledger line. |
| Decoder: iced-x86, capstone, or unified IR | `MaskSource` port; iced-x86 first; capstone is the documented fallback; unified IR preferred once S1 lands, with a mask parity test. |
| Both pins in the Windows alpha or an optional extra | Base dependency, because the feature is part of the standalone alpha. State R1 covers installs without them. |
| Several changed functions of one finding in one rule | No in v1; one pair per candidate. |
| Variant hunting in a clean or scan set | Out of scope in v1. |
| Clean-set definition | A project-level folder pointer; hashes and basenames recorded; files never copied. |
| More than 8 builds | Series (<= 8) plus <= 64 extra builds from the acquisition store or a file picker. |
| Expectations for series builds | The analyst sets them; advisory applicability is shown separately as "advisory says". |
| Per-crate licence texts for the 303 Rust crates in the wheel SBOM | Ship the SBOM and the upstream LICENSE now; the owner decides whether `cargo-about` output is required. |
| A blocked JIT (ACG or EDR): defect or limitation | Documented limitation: state R1 with the probe's reason. |
| Name overlap with `patch-rules/1` in `intelligence` | Keep `rules/` and `yara-rules/1`; `patch-rules/1` ids are referenced, never merged. |

## 10. External facts

Sources and facts are those in `docs/specs/program-e/YRX-integration-plan.md` section 2. They were retrieved on 2026-10-14 by the plan worker, and this writer did not re-fetch them. Carried here with their own confidence:

| Claim | Source | Confidence |
|---|---|---|
| `yara-x` 1.21.0 (2026-09-29) is latest; Python >= 3.9; wheels only, no sdist; no musllinux | https://pypi.org/pypi/yara-x/1.21.0/json | high |
| Licence BSD-3-Clause | https://raw.githubusercontent.com/VirusTotal/yara-x/main/LICENSE | high |
| Wheel SBOM: 303 Rust crates, all permissive; `r-efi` tri-licensed (take MIT) | wheel member `sboms/yara-x-py.cyclonedx.json` | high |
| `Scanner.scan` holds the GIL for the whole scan; `Compiler`, `Scanner`, `Formatter` are `unsendable` | https://raw.githubusercontent.com/VirusTotal/yara-x/main/py/src/lib.rs | high (plan measurement) |
| Rust panic surfaces as `PanicException`, derived from `BaseException` | https://raw.githubusercontent.com/PyO3/pyo3/main/src/panic.rs | high |
| Upstream memory-safety and panic fixes in 1.12 to 1.20 | https://github.com/VirusTotal/yara-x/releases | high / medium |
| Static only; `scan_file` memory-maps and a truncation raises SIGBUS | https://raw.githubusercontent.com/VirusTotal/yara-x/main/site/content/docs/intro/yara_vs_yara-x.md | high |
| iced-x86 1.21.0 is MIT, `cp38-abi3` wheels | https://pypi.org/project/iced-x86/ | high (licence from installed metadata: medium) |
| Qt UI Automation providers for grid and table views | https://github.com/qt/qtbase/tree/dev/src/plugins/platforms/windows/uiautomation | medium (`dev` branch, not the 6.12.0 tag) |
| Keyboard guidance: one tab stop per composite control, arrows inside | https://raw.githubusercontent.com/MicrosoftDocs/windows-dev-docs/docs/hub/apps/design/accessibility/keyboard-accessibility.md | medium |
| The frozen-app `importlib.metadata` gap and the `json`, `io`, `datetime` hidden imports | https://raw.githubusercontent.com/VirusTotal/yara-x/main/py/src/lib.rs (lines 49, 200, 755, 771) | high (plan measurement) |
| Behaviour under Windows Arbitrary Code Guard or EDR | none | `[unverified]` (owner machine) |
| `pe.offset_to_rva` absent in 1.21.0 (docs ahead of the wheel) | plan measurement | `[unverified]` on upstream main |

Hosts blocked from the research sandbox: virustotal.github.io, pyo3.rs, doc.qt.io, learn.microsoft.com, api.github.com.

## 11. Integrator asks

Nothing in this file changes an existing file. The integrator applies:

1. `docs/specs/REGISTRY.md`: add a row for this file in section 2. The registry says the next free number is SPEC-41; this spec uses SPEC-47 as assigned by the card. Confirm the number against open PRs before merging. Until the row exists, `tests/test_spec_registry.py` (if it is present in the merged tree) fails on this new file.
2. `pyproject.toml:15`: change `rules = ["yara-x>=1.0,<2"]` to exact pins `yara-x==1.21.0` and `iced-x86==1.21.0`, in a dedicated change that re-runs the grid (R-18).
3. `src/patchtrace/enrichment/storage.py` `KINDS`: the `rule-*` kinds are already present (lines 39-55). Verify, do not re-add.
4. `docs/specs/program-e/YRX-integration-plan.md` section 10 and `docs/specs/three-tool-evidence-adapters.md`: the plan cites the derived-evidence rule as SPEC-29; the canonical alias for that file is SPEC-36 (REGISTRY table A). Use the alias in any cross-reference.
5. `docs/plans/ledger-B.md` line 10: the package name there is `yarax/`; this spec says `rules/` (section 9, first row).
6. `docs/modules.md`, `tasks/todo.md` and `docs/qa.md`: append the workflow blocks when a slice is built; none is appended by this spec.
