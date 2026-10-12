# SPEC-07: Phase 2 enrichment — change signals, ranking, WIL, CVE context, cache

Status: implementation contract, 2026-10-12. Contract version `enrichment/1`.

## 0. Provenance and reconciliation

The handoff package named in the delivery brief (`PatchTrace-Extension-Specification-2026-10-11.md`, `PatchTrace-Phase2-Contracts-v1.schema.json`, `PatchTrace-Phase2-Synthetic-Examples-v1.json`) was **not supplied** to the implementing session (absent from uploads and every repository branch on 2026-10-12). This specification is therefore authored by PatchTrace from the normative text of the 2026-10-12 delivery brief. Field names below are PatchTrace's own. When the supplied schema becomes available, reconcile it here first: rename or add fields through a new contract version, never by silently reinterpreting stored records. Until then the generated `docs/schemas/enrichment/*.json` are the only machine schema and **do not claim** to be the supplied one; the nine valid / nine invalid supplied examples have not been validated.

CLI exit codes for Phase 2 commands follow the brief (§8), which supersedes the unmerged SPEC-05 draft table for these commands.

## 1. Boundaries

Package `patchtrace.enrichment`:

| Module | Responsibility | May import |
|---|---|---|
| `contracts.py` | Strict frozen Pydantic records and enums for every enrichment output | pydantic, stdlib |
| `identity.py` | Canonical JSON and domain-separated SHA-256 identities | stdlib |
| `signals.py` | B1 deterministic detectors over immutable match views | contracts, identity, alignment |
| `ranking.py` | Exact integer `attention/1` scoring and ordering | contracts, identity |
| `wil.py` | B2 `Feature_<uint32>` recognition and transition classification | contracts, identity |
| `cve.py` | B3 pure CVE normalization and contextual reranking | contracts, identity |
| `intelligence.py` | B3 bounded HTTPS transport for MSRC/NVD (explicit consent only) | contracts, stdlib |
| `cache.py` | B4 content-addressed derived-stage and raw-output cache | contracts, identity, stdlib |
| `pipeline.py` | Stage orchestration, cancellation, partial results | all above except transport |
| `storage.py` | Additive SQLite tables via ProjectStore | persistence |

`contracts`, `identity`, `signals`, `ranking`, `wil`, `cve` import no Qt, Java, Ghidra, subprocess or network modules (enforced by test). Transport, subprocess, cache I/O and persistence are adapters injected into the pipeline. `ProjectService` remains the only transaction owner; GUI and CLI call the same application services.

## 2. Common record rules

All records: `extra='forbid'`, `strict=True`, frozen, `contract: Literal['enrichment/1']`. Integers reject booleans; floats are not used for scores. Strings are NFC-normalized at identity time, not mutated in records. Statuses: `complete | partial | unavailable | cancelled | failed`. `unavailable` means the required input evidence is missing — never "no defect". A valid zero-signal result is `complete` with an empty list.

Typed errors (`EnrichmentError`): `code` (`PT-ENRICH-INPUT`, `PT-ENRICH-OWNERSHIP`, `PT-ENRICH-CONFIG`, `PT-ENRICH-LIMIT`, `PT-ENRICH-CANCEL`, `PT-ENRICH-STALE`, `PT-ENRICH-CACHE`, `PT-ENRICH-NETWORK`, `PT-ENRICH-PROVIDER`), `recoverable: bool`, redacted `message`, developer `__cause__` chain. Completed earlier stages are preserved when a later optional stage fails.

Cancellation is checked at stage boundaries and at least every 256 functions. Per-function detector work is bounded: at most 20,000 lines and 2,000,000 characters per side are scanned; larger functions yield `partial` with limitation `function-too-large`.

## 3. Identity (`identity.py`)

`canonical_json(value)`: UTF-8, NFC strings, `sort_keys=True`, separators `(',', ':')`, `allow_nan=False`, integers only (floats rejected), booleans allowed only where typed. Unordered sets are passed as sorted, deduplicated lists by the caller.

`domain_id(domain, version, payload) = sha256(b'patchtrace\x00' + domain + b'\x00' + str(version) + b'\x00' + canonical_json(payload)).hexdigest()`.

| Identity | Domain | Payload |
|---|---|---|
| diff | `diff` v1 | `{older_sha256, newer_sha256, raw_sha256, tool}` (ordered sides; reversing changes it) |
| occurrence | `occurrence` v1 | `{diff_id, side, address, name, ordinal}` (address int or null; 0 valid) |
| pairing | `pairing` v1 | `{diff_id, category, manual, older: [occurrence...], newer: [occurrence...]}` (lists sorted) |
| signal | `signal` v1 | `{pairing_id, detector, detector_version, group_key, locations}` |
| stage | `stage` v1 | `{stage, stage_version, inputs: {name: digest}}` |
| config | `ranking-config` v1 | semantic config only (weights, enabled detectors, formula) |
| raw cache | `raw-cache` v1 | `{older_sha256, newer_sha256, fingerprint}` (ordered; full §9 runtime fingerprint) |
| edit group | `edit` v1 | `{pairing_id, hunk_ordinal, side, text}` shared by B1 and B2 (`signals.edit_group_key`) |

Timestamps, display preferences and absolute paths are never hashed. Existing project/run/function/match UUIDs are retained alongside. Manual rematching yields a new pairing identity (manual flag and membership change); dependent results become stale, history is kept. Identity equality is not authorization or semantic equivalence; ownership is validated separately.

## 4. Evidence locations

`SourceLocation`: `side`, `artifact_id`, `run_id`, `function_id`, `representation` (`decompiled|assembly|metadata`), `start_line`, `end_line` (1-based inclusive, `end >= start`), `excerpt_sha256` (SHA-256 of the exact UTF-8 lines joined by `\n`), optional `address` (int ≥ 0; 0 is valid; null = unknown). Before navigation or save, `validate_location(project, loc)` checks artifact/run/function ownership, side, line bounds and excerpt hash.

## 5. B1 change signals (`signals.py`)

Input: `MatchView` (immutable): pairing id, match id, category, older/newer function views (id, artifact id, run id, code lines, assembly lines or None), diff hunks from `alignment.diff_hunks`. Detectors only inspect lines inside changed hunks plus a bounded 6-line window of context for linkage.

| ID | Weight | Observable change (positive requires all) | Default confidence |
|---|---:|---|---|
| BND | 30 | Added/changed comparison of an index/length/offset/count variable against a bound **and** that variable used in a subscript, pointer arithmetic, or memcpy-family size within the window | moderate (text); strong only with typed IR (not available in this release) |
| INT | 22 | Comparison operator strictness change (`<`↔`<=`, `>`↔`>=`) or signedness/width cast change on the same operands | weak; moderate when both sides show the same operands |
| OVF | 28 | Added overflow guard: `a + b < a`, `x > MAX - y`, `x > MAX / y`, intrinsic/`ULongAdd`/`SizeTMult`-style checked arithmetic, linked to arithmetic feeding a size/alloc/copy | moderate |
| VAL | 20 | Added validation/probe call (`ProbeForRead/Write`, `*Validate*`, `*Check*` returning status) or newly checked return value of an existing call | weak |
| ERR | 12 | New predicate-controlled early return/goto with error status (`return 0xC000000D`, `STATUS_*`, negative errno, `return -1`) | weak |
| SIZE | 24 | Size argument changed for the same callee name at the same call ordinal (memcpy/memmove/RtlCopyMemory/alloc families) | moderate |
| WIL | 12 | Qualifying B2 feature-gate transition (introduced/removed/condition-changed/guarded-behavior-changed) for this pairing | from B2 |
| SCRUB | 34 | Added zeroing/masking (`memset(x,0,..)`, `RtlZeroMemory`, `RtlSecureZeroMemory`, `&= mask`) of object `x` **before** a copy-out/copy (`memcpy`, `RtlCopyMemory`, `copy_to_user`, `ProbeForWrite`+copy) whose source is the same `x` in the newer side | moderate |

Not sufficient alone (negative fixtures required): API names, nearby zeroing without the same object, decompiler variable renames, whitespace/display hunks, instruction hashes, call-name proximity. Added/removed functions (one side absent) cannot produce two-sided guard claims; detectors return `unavailable` for those categories except where the rule is one-sided by definition (none in this release). Missing decompiled code on a required side → detector status `unavailable` (not zero). No special-casing of any binary name.

Each detector declares: `id`, `version`, `prerequisites`, `categories` (default: `modified`, `split`, `merged`, `ambiguous` with ambiguity recorded), `limitations`. A disproved prerequisite suppresses that detector (status `complete`, no signal) and never yields negative scores.

`group_key`: the identity of the underlying edit — `sha256` of the normalized newer-side predicate/callsite text plus hunk ordinal. Signals on the same edit share a group.

## 6. Ranking `attention/1` (`ranking.py`)

Exact integer arithmetic; no floats anywhere.

1. Multiplier: strong=100, moderate=70, weak=35, unavailable=0.
2. `q = (weight * multiplier + 50) // 100`.
3. Deduplicate signals by `signal_id`; group by `group_key`.
4. Per group, sort q descending, tie by signal id; `a`,`b` = two largest (b=0 if absent); `group = min(40, a + min(12, b // 4))`.
5. `raw = min(80, sum(groups))`; `score = (raw * 100 + 40) // 80`.
6. Order: score desc, strong independent-group count desc, pairing id asc.

Weights: integers 0..100 for exactly the eight IDs; unknown IDs or bools rejected. `RankingConfig.digest` = config identity; formula version `attention/1`. Results store per-group subtotals (`a`, `b`, `points`, signal ids), raw, score, formula and config digests. Attention score, match certainty (`FunctionMatch.quality`), evidence coverage and counterevidence are separate fields. AI output never enters scoring. A score is research prioritization, not exploitability or CVE proof.

## 7. B2 WIL (`wil.py`)

Identifier: regex `(?<![A-Za-z0-9_])Feature_(\d{1,10})(?![A-Za-z0-9_])`, value must be ≤ 4294967295 (else rejected as `overflow`), leading zeros preserved in `identifier` text but numeric `feature_id` canonical. Unknown → `feature_id: null`; 0 is valid. No friendly names invented. Wrapper recognizers (`wil::details::FeatureImpl<...>::__private_IsEnabled`, `Feature_N__private_IsEnabledDeviceUsage`, `IsEnabled`) only from the documented public WIL pattern list; private families are not assumed.

Facts kept separate: `FeatureSite` (identifier, side, location, enclosing control text), `control` (`cfg-dominance` — never produced without CFG evidence; `lexical-enclosure`; `adjacent`; `unknown`), and per-pairing `FeatureTransition` with kind `introduced | removed | condition-changed | guarded-behavior-changed | unchanged-around-change | unknown`, both-side sites, confidence. Adjacent-only references are contextual notes and never qualify for WIL scoring. B1 prerequisites (a changed hunk inside the lexically enclosed region) apply before WIL scoring. Duplicate sites at distinct locations are preserved. Input bounds: 2,000,000 characters per function, 4,096 sites per pairing. PDB GUID/age validation and symbol provenance are recorded as `symbol_status` (`verified|unverified|mismatched|absent`); the detector never downloads symbols.

## 8. B3 CVE context (`cve.py`, `intelligence.py`)

CVE ID: `^CVE-\d{4}-\d{4,19}$`, length ≤ 24, validated before any I/O. Transport: explicit consent object listing providers and exact request URLs; HTTPS allowlist (`api.msrc.microsoft.com`, `services.nvd.nist.gov`), redirects only within the allowlist (max 3), 4 MiB response cap, connect timeout 10 s, total 30 s, max 3 attempts only for 429/502/503/504/timeouts, honoring `Retry-After` ≤ 60 s, cancellable sleeps. Never sends binary bytes, code, project paths or notes. API key session-only (NVD `apiKey` header), absent from logs/settings/exports. Wrong-ID HTTP 200 is invalid. Endpoint/schema details are pinned to captured fixtures; live probes are recorded separately.

`CveSnapshot` identity pins provider response digests and normalization version; retrieval time/freshness stored separately. Fields keep source attribution; conflicts are recorded, not merged.

Contextual ranking (never alters B1 values or order): tokenization `[A-Za-z_][A-Za-z0-9_]{2,}` lowercased, versioned stopword list, cap 256 terms. Contributions, each citing a context field and a binary evidence ref or B1/B2 signal:
- technical identifier/entity overlap (term equals a function name token or callee in the pairing): +12 each, cap 24;
- CWE aligned to an existing strong/moderate signal (mapping table versioned, e.g. CWE-787/125/119/120→BND/SIZE, CWE-190/191→OVF/INT, CWE-200/908/909→SCRUB, CWE-20→VAL): +10 each, cap 20;
- verified advisory feature ID also present in B2: +8;
- advisory product-module match to artifact name: +4 once;
- total adjustment cap 30; `context_score = min(100, base + adjustment)`.
Conflicting provider data blocks the affected contribution. No binary support → 0. The product-module contribution is artifact-wide, so it is awarded only to an entry that already has another contribution. Order: context desc, base desc, pairing id asc. Persist base/context ranks and contributions.

Feature IDs: neither NVD nor MSRC (as probed 2026-10-12) publishes WIL feature IDs, so `normalize` always leaves `CveSnapshot.feature_ids` empty and the +8 contribution is dormant until a curated, attributed source is specified (a future contract version must add it to `snapshot_id`). Snapshots loaded from a file cannot be re-verified against provider bodies: they are labelled unverified and their `feature_ids` are discarded. A stale snapshot (older than `max_age_days`, default 30, or dated in the future) is still usable offline but the result status is `partial` with a per-CVE warning.

## 9. B4 cache (`cache.py`)

Derived-stage cache keyed by stage identity (§3). Raw cache keyed by ordered artifact hashes + full runtime fingerprint (engine, Ghidriff revision, Ghidra, PyGhidra, Python, Java, platform arch, loader/analysis options, adapter version, effective symbol policy, symbol-input digest). Unverified runtime versions (`unknown`) or `online` symbol policy → raw entries ineligible. Reversed pair → different key.

Layout: `<cache>/v1/<stage>/<key[:2]>/<key>/` with `payload`, `manifest.json` written last (strict: key, stage, size, sha256, inputs, created), `complete` marker implied by manifest. Private same-volume staging `<cache>/v1/.staging-<uuid>`; `os.replace` publish; lock file per key via `O_EXCL` with owner pid+host+nonce; stale lock recovery only when the owning pid is provably dead on this host. Corrupt entries move to `<cache>/v1/quarantine/`. Budget default 20 GiB, raw JSON ≤ 100 MiB, LRU eviction by manifest access time excluding leased entries. Admission failure never fails analysis. `no_cache` = no reads/writes; `refresh` bypasses reads for the selected stage and descendants; both together invalid. The cache module bypasses exactly the stage names it is given; the pipeline expands descendants (`signals` → `wil` → `ranking` → `contextual`; only `signals` and `wil` are cached today, so CLI `--refresh` passes both). Cache hits create a new project-owned run with copied, re-validated raw output.

LRU clock: a hit updates the manifest file's mtime (content and hash unchanged); prune orders by mtime. atime is not used (unreliable on noatime mounts). Within-process orphan locks/staging are recognised by an unregistered nonce for the live pid. Raw-key payload: `raw-cache` identity (§3). Only fully `complete` stage values are admitted; a cache hit is served only after every record re-derives against the live views (pairing set, match ID, function/side/artifact/run ownership, excerpt hash), otherwise it is a miss.

## 10. Persistence

Additive tables in `project.sqlite3`: `enrichment_meta(key TEXT PRIMARY KEY, value TEXT)` with `extension_version`, and `enrichment_entries(id TEXT PRIMARY KEY, kind TEXT, project_revision INTEGER, run_id TEXT, raw_sha256 TEXT, input_digest TEXT, status TEXT, stale INTEGER, created TEXT, body TEXT)`. `user_version` stays 1 because v1 clients ignore unknown tables (demonstrated by test: open/read/save/backup with tables present). Before first creation a verified backup is made. Row body ≤ 32 MiB, project derived total ≤ 128 MiB. Publication rechecks project id, run id, raw hash and input digest immediately before commit; a mismatch stores the result as `stale` (revision is recorded as the revision the result was computed from, for provenance, but is not part of currency because note/review edits do not change derived inputs). Rows whose content depends on configuration (signals with merged WIL signals, ranking, pipeline) are keyed by the ranking stage ID; the `pipeline` row records `config_digest`, `default_profile` and all stage IDs. The desktop and exports load only the default-profile rows via `pipeline.load_default`; a CLI run with non-default weights/detectors/feature filter can never be presented as the default. Unknown future `extension_version` → read-only, never dropped.

## 11. CLI (headless, no Qt import)

`patchtrace rank PROJECT [--weights FILE] [--json] [--limit N]`, `patchtrace flags PROJECT [--feature-id N]... [--json]`, `patchtrace correlate PROJECT --cve ID... [--snapshot FILE] [--fetch --consent-providers msrc,nvd] [--json]`, `patchtrace cache {status,verify,prune} [--cache-dir D] [--json]`. JSON mode: exactly one document on stdout `{"contract":"enrichment-cli/1","command":..,"status":..,"result":..,"warnings":[..]}`; diagnostics on stderr. Exit codes: 0 success, 2 invalid arguments/config/environment, 3 runtime failure, 4 legitimate no-results (rank/flags with zero entries on complete evidence), 5 cancellation. Partial success is explicit (`status: partial`).

## 12. Analysis profiles (shared nonsecret settings)

Status: specified, not yet implemented (CLI flags only in beta.80).

`AnalysisProfile` (strict, versioned `profile/1`, stored as JSON in the desktop settings directory, never in the project and never containing secrets): `name` (1–64 chars), `weights` (exactly the eight detector IDs, integers 0–100), `enabled` (subset of the eight), `feature_ids` (≤ 256 uint32 or null), `symbol_policy` (`disabled|online`, maps to `BackendConfig.allow_symbol_downloads`), `cve_providers` (subset of `nvd,msrc`), `snapshot_max_age_days` (1–3650), `cache_dir` (absolute path or null), `cache_budget_gib` (1–1024). A built-in read-only `default` profile equals `RankingConfig()` with no feature filter. Identity: `profile_digest = domain_id('analysis-profile', 1, semantic fields)`; `name`, `cache_dir` and budget are presentation/operational and excluded. QSettings keeps only presentation preferences and the selected profile name.

Behavior: Setup gains a Profiles tab (create/duplicate/edit/delete non-default; validation errors shown inline; incompatible combinations — e.g. all detectors disabled — rejected). Rank changes uses the selected profile; when it is not `default` the navigator header shows the profile name and the ranking rows are published under their own stage IDs, so `load_default` remains correct; the desktop loads the selected profile's rows by `config_digest`. CLI gains `--profile NAME|FILE` (mutually exclusive with `--weights`/`--disable`). Exports record the profile digest and name. Acceptance: round-trip, strict rejection (bools, extra keys, unknown IDs), digest invariance under presentation edits, GUI/CLI/report agreement for a non-default profile, no secret persisted.

## 13. Raw output cache integration

Status: specified, not yet implemented (the B4 raw API exists).

After a completed native run, if `RuntimeFingerprint.eligible()` (all versions known, symbol policy `disabled`, no symbol inputs), `backend` admits the raw JSON (≤ 100 MiB) with `put_raw`. Before launching Ghidriff, `run_comparison` computes the fingerprint and, unless `no_cache`/`refresh`, calls `get_raw`; on a hit it writes a new project-owned run directory with the copied bytes, records provenance `cache_origin = {key, created}` in `AnalysisRun.settings`, and continues through the existing normalization/service publication (identical validation to a fresh run). A hit never skips normalization or artifact identity checks; the case remains usable after the global cache is deleted. Fingerprint inputs come only from probed versions (`diagnose`), never from defaults; `unknown` makes the run ineligible. Acceptance: hit produces byte-identical raw JSON and identical matches; swapped orientation misses; any version change misses; corrupted entry falls back to a real run; GUI displays "from cache" in run details.

## 14. Acceptance

See tests `tests/test_enrichment_*.py`. Golden arithmetic, invariants (property-based where useful), negatives listed per detector, ownership forgery, side reversal, stable ordering, CLI/GUI/report value agreement, storage compatibility with v1 code paths. Performance objectives: 10,000 pairs / 100,000 lines in 10 s / 512 MiB — measured 6.6 s / 240 MiB (synthetic, Linux, `tools/bench_enrichment.py`); derived-cache hit 500 ms — measured 3.1 s, **not met** (input hashing and ownership revalidation dominate; both are correctness requirements). UI responsiveness at that scale and Windows timings are unmeasured.
