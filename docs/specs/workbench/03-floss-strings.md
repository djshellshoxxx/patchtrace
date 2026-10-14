# PT-WB-03: FLOSS Versioned String Extraction and Side-by-Side Investigation

**Status:** Developer-ready integration spec; WB3-S0 (contracts and table) implemented in `patchtrace.strings`. **Contract:** `workbench-strings/1`. **Parent:** [integration index](README.md). **External project:** https://github.com/mandiant/flare-floss (Apache-2.0). **Depends on:** existing verified artifact reader, supervised subprocess, optional PT-WB-01 Search, PT-WB-02 graph. **Date:** 2026-10-14.

## 1. Goals

Make suspicious binaries easier to investigate by displaying readable and recovered strings alongside their origin, extraction type, binary side and possible functions, then comparing which strings are observed in the older/newer artifacts. Support analyst search and evidence linking without claiming recovered strings are proof of particular vulnerabilities or code changes.

FLOSS supports static, stack, tight, decoded and language-specific strings and emits a versioned JSON results document using `floss -j FILE`. Its current upstream documents `metadata`, `analysis`, `layout` and `strings`; arrays `static_strings`, `stack_strings`, `tight_strings`, `decoded_strings`, `language_strings`, `language_strings_missed` may differ by tool/schema version. Validate against exact pinned fixtures from upstream `floss/results.py` before writing a field adapter. **Never infer format solely from earlier FLOSS 2.x examples.** Sources: https://github.com/mandiant/flare-floss/blob/master/doc/results_document.md ; https://github.com/mandiant/flare-floss/blob/master/doc/usage.md .

## 2. Avoid duplicate integrations

`docs/specs/three-tool-evidence-adapters.md` already proposes `intelligence/tools/floss.py` under SPEC-29's three-tool suite (capa, FLOSS, DiE). The workbench MUST reuse that eventual canonical adapter contract rather than implement a competing scanner. Choose and document exact owner:
- Canonical FLOSS probe, subprocess runner, parser and cache adapter lives in `src/patchtrace/intelligence/tools/floss.py` (or existing equivalent if another agent implements it first).
- The workbench owns `workbench/strings_contracts.py`, `strings_delta.py`, `strings_search_adapter.py`, `strings_view_model.py` and `ui_strings.py`. It consumes the canonical normalized `StringEvidence` record.
- If `intelligence/tools` not yet present on current main, land the base FLOSS adapter as an independent PR satisfying SPEC-29 before the workbench's UI, then leave the other SPEC-29 engines optional. No temporary duplicate parser.
- Shared source/provenance contract may need a thin compatibility `FlossObservation` transform with schema tests to preserve existing SPEC-29 `StringEvidence` fields. This addition is versioned and additive.

Never add FLOSS to `secondary/contracts.py`'s BinDiff/rz-diff match-engine enum: FLOSS is an auxiliary string-evidence producer, **not** a function matcher.

## 3. Input and capability

Before enabling RUN, probe configured FLOSS executable (absolute resolved path, controlled working directory, no shell), record observed `version`, SHA-256 of executable, supported CLI options and JSON contract. Users may select an installed FLOSS binary; do not auto-download. The first release should work with CLI executable installed separately. No Python FLOSS import in the packaged PatchTrace EXE; packaging its entire Python/analysis stack would increase dependencies and risk.

Input is each project's immutable older/newer final verified PE file, reverified immediately before the run using existing `artifact_bytes.VerifiedArtifactReader` or artifact validation adapter. FLOSS must operate on a safe path in controlled read-only source custody. Executing the *target PE* is forbidden; FLOSS performs static/emulated analysis as designed, which still consumes attacker-controlled bytes and should be treated as high risk. Follow PatchTrace's existing process isolation and optional sandbox profile. On Windows do not imply the subprocess is an OS security sandbox merely because it is controlled by a Job Object.

No internet access is required by our adapter. Use existing `jobs.run_process` for termination/timeouts, exit status, sanitized stderr, process-tree kill and stdout limit. The exact return/signature of `run_process` must be read before implementation rather than guessed.

CLI execution form verified in upstream documentation: `floss -j -- PATH` or `floss -j PATH`, depending on probed version and path argument support. For Windows paths starting with hyphen, include `--` only if supported by exact pinned CLI version. Run `floss -j <verified-file>` under configured allowed profile, capture stdout as JSON rather than temporary HTML. Supported options can later include `--string-type`/ `--no-string-type`, minimum length and function filtering after versioned probe. Do not trust arbitrary user-provided extra argv.

## 4. Typed contracts and identity

```python
class StringObservation(BaseModel):
    model_config = ConfigDict(extra='forbid',frozen=True,strict=True)
    id: str  # stable content/source/location identity
    source_artifact_sha256: str
    run_id: str
    tool_id: Literal['floss']
    tool_version: str
    output_schema_version: str
    tool_binary_sha256: str
    config_sha256: str
    category: Literal['static','stack','tight','decoded','language','unknown']
    value: str
    value_sha256: str  # hash UTF-8 bytes only, not original artifact bytes
    encoding: Literal['ascii','utf-8','utf-16le','other','unknown']
    location_kind: Literal['file-offset','rva','va','decoder-function',
                           'stack-frame','none','ambiguous']
    location: int | None
    location_source_path: str | None
    containing_section: str | None
    function_id: str | None  # only if reliably mapped, else null
    provenance_ids: tuple[str,...]
    extraction_complete: bool
    redaction_tags: tuple[str,...]
class StringDelta(BaseModel):
    observation_keys: tuple[str,...]
    value_sha256: str
    status: Literal['in-both','only-older','only-newer',
                    'location-changed','method-changed',
                    'indeterminate','unknown']
    older_ids: tuple[str,...]
    newer_ids: tuple[str,...]
    cause_notes: tuple[str,...]
class StringRunResult(BaseModel):
    contract: Literal['workbench-strings/1']
    artifact_side: Literal['older','newer']
    status: Literal['ok','partial','unsupported','cancelled','error','stale']
    tool_version: str | None
    tool_hash: str | None
    artifact_sha256: str
    source_document_sha256: str | None
    extraction_stage_status: dict[str,str]
    observations: tuple[StringObservation,...]
    warnings: tuple[str,...]
```

Use source `raw_json_sha256` and semantic parser version in every run. Array data, native numeric offsets, tool-returned VA, file offsets, function values and stack addresses must not be assumed interchangeable; validate `location_kind` against exact upstream JSON object fields. Use existing PE SectionMap/RVA mapping only when image base and section relationship verified for that input artifact. Ambiguous mappings remain unlinked. Avoid guessing a function from nearby text or identical string content.

All strings from any input are untrusted. UI plain text; no HTML labels, Markdown/raw evidence execution or HTML reports. Strings may contain secrets/passwords, PII, URLs or hostnames. Default exports and context previews must redact appropriately; never send to remote AI without existing explicit preview/consent.

## 5. Output normalization and comparison semantics

1. Verify tool provenance and parse bounded strict JSON with duplicate-key rejection, explicit JSON schema/doc-version checking and unknown major => `unsupported`; validate metadata against **expected binary SHA** by tool or re-reading independently. JSON omission of binary hash is `source identity externally verified via input path` only, not a forged source-record digest.
2. Normalize supported categories without losing subtype labels, encoding or original locations. Keep repeated equal string values from different functions/offsets as separate observations. Canonical `id = domain_id('workbench.strings',1,{artifactSHA,runID,toolVersion,configSHA,category,valueSHA,locationKind,location,source array index})`.
3. Filter only after retaining raw normalized evidence; presentation may group repeated values. Empty string lists are valid when corresponding analysis stages completed. Unsupported/skipped/failed extraction stage is *unknown*, not `no strings`.
4. Compare stable `(value normalized conservatively,encoding,category)` buckets. `in-both` means observed in both samples, not byte-identical assembly. A changed decoder technique can move an observation from static to decoded without new string being introduced.
5. `only-newer` and `only-older` are **only allowed if both corresponding extraction methods finished successfully under comparable extraction options and versions**. Otherwise `indeterminate`. Missing strings cannot be used to prove code removal, CVE remediation, or secure behavior.
6. Optional class `location-changed` only when function/source identity resolution is reliable; same content relocated without supported mapping remains normal grouped observation with `ambiguous location`.
7. Highlight searches for suspicious APIs, messages, paths, mutex names, tokens, URLs and registry keys as **review cues only**, not automatically malicious categories.

Result order deterministic by (status,category,value casefold,source side,location-kind,location,observation id). String-count tables explicitly distinguish raw occurrences, unique normalized values and method groups. Preserve external tool JSON for optional local source inspection within quota and authorization; report only hashes/summary by default.

## 6. Runtime budgets and process safety

Choose initial thresholds: 300s per side default; user adjustable 30..1800s; stdout JSON max 32MiB; stderr tail max 1MiB; observations max 250k; single string max 64 Ki Unicode scalars; retained raw output <=128 MiB/project; two-side scheduling maximum 1 active FLOSS worker by default until profiling. All limits are provisional and require real benchmark validation. Treat overlimit as **partial/error with explicit stage**, never silently truncate while displaying `complete`. No unbounded recursive deserialization; use existing strict_json and content size limits.

Pass absolute configured executable, argv list, controlled cwd, restricted environment, no `shell=True`, no inherited arbitrary plugin hooks, limit memory/CPU via OS facilities when supported; otherwise document inability. Concurrency with active Ghidriff runner should be bounded by shared job policy. Cancellation kills child tree; temp data stays quarantined and is cleaned only when owned. Cache key `(older/newer SHA,tool path/version/hash,tool config,parser version,output schema,analyst profile)`. Never reuse an incomplete output as a complete cache hit. Hash and input order verified on every use.

## 7. UI

One **Strings** tab/dock, ideally shared with Search and Call Graph, not another application:
- Header: side extraction states, tool capability, exact runtime version, JSON source digest, 'Run FLOSS' (explicit; not automatic on project open), Cancel, Import JSON (strict same-artifact verification or explicit analyst asserted provenance).
- Table columns: Status, String, Extraction type, Encoding, Older location, Newer location, Function, Source. Filters: added/removed/shared/indeterminate, side, type, case-insensitive search, length, API/URL/path heuristics, exact only/unique only.
- Detail: full UTF-8 safe value, source location, extraction method, possible function links, raw source pointer, last run/time, redaction notice.
- `Open function` only if a verified function id/match navigation exists; `Open offset` only if a verified range within original file can be mapped through current representation reader; never use an unverified VA as file offset.
- Search integration: PT-WB-01 consumes **normalized** StringObservation, indexes at most 64KB per value and reports source tool/run/side; reindex when FLOSS evidence changes.
- Graph integration: PT-WB-02 adds optional string-reference badges *only* for verified linked functions; a decoder function address not automatically equivalent to a string consumer.
- Accessibility: plain text fallback, copy selected string with source/context, keyboard table navigation, no color-only status.

## 8. CLI

Proposed `patchtrace strings probe --json`, `patchtrace strings scan PROJECT --side both --floss-bin PATH --json`, `patchtrace strings list PROJECT --status only-newer --json`, `patchtrace strings export PROJECT --format json --redact --json`. CLI registration must preserve current commands and exit semantics. If SPEC-29 lands its own `intel-tools` command first, use `patchtrace intel-tools ...` as the *canonical execution verb* and keep `strings` for read-only viewing/delta: there must not be two independent execution paths. All commands are offline by default.

## 9. TDD and acceptance

Tests `test_floss_probe.py`, `test_floss_results_contract.py`, `test_string_delta.py`, `test_strings_search_index.py`, `test_strings_ui.py`, `test_floss_cli.py`.

Fixtures generated from recorded, pinned FLOSS output versions (license assessed); synthetic fixture PE builds with:
- added ordinary ASCII string; unchanged UTF-16 string; equal value in multiple locations;
- compiler-layout relocation with same string; same visible string with different encodings;
- stack string and decoded string with decoder location; unsupported language string;
- one old stage success/new stage skipped => `indeterminate`;
- same input SHA but different tool options => no unjustified equivalence;
- invalid JSON/version/duplicate keys/NaN/overflow/huge Unicode string;
- tool error/exit-zero empty stdout, partial JSON, early process termination, timeout and cancellation;
- symlink/changed on-disk input after verification, false source SHA and wrong project;
- source VA not mappable and duplicated function names -> no fabricated jump;
- HTML markup, ANSI escapes, newline, terminal codes and secrets in strings -> safe rendering/redaction;
- project revision/orientation swap before publish -> stale result not attached;
- CLI `--json` stdout one object; existing secondary engine and search tests not broken;
- Windows frozen EXE against separately installed FLOSS CLI with offline fixture, help/probe/extract/import/cancel.

Milestone 1: canonical adapter + JSON corpus, no UI. 2: pure delta + provenance. 3: Strings tab with function/offset navigation and search integration. 4: native Windows and recorded real sample after binary-license review. Maintain no CVE-positive claims from string matches.
