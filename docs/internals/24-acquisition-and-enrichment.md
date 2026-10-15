# 24. Acquisition, enrichment and AI interpretation

Three Qt-free subsystems that bring in or derive context around a comparison: acquiring two builds from Microsoft's public sources (`acquisition/`), deriving signals, ranking and CVE context (`enrichment/`), and the optional AI path (`evidence.py`, `interpretation.py`, `providers.py`). User view: [11](../guide/11-workflow-compare.md), [17](../guide/17-privacy-and-network.md). Specs: SPEC-08 `docs/specs/acquisition.md`, SPEC-07 `docs/specs/enrichment.md` and `enrichment-hardening-backlog.md`, SPEC-41 `ai-provider-interpretation.md`. Previous: [23](23-gui-framework.md). Next: [25](25-intelligence-kb-kev-yara-capa.md).

## Acquisition (`acquisition/`, contract `acquisition/1`)

Goal: from a lower-case file name (for example `afd.sys`) get two builds and create an ordinary two-artifact project, without bypassing ingestion.

| Module | Role |
|---|---|
| `contracts.py` | strict records: `BuildCandidate`, `KbRef`, `PlannedDownload`, `AcquisitionError`; file-name and URL validation; `symbol_server_url(name, timestamp, size_of_image)` |
| `winbindex.py` | pure parser of Winbindex per-file metadata (`https://winbindex.m417z.com/data/by_filename_compressed/<name>.json.gz`); caps 64 MiB compressed, 256 MiB decompressed; Winbindex is GPL-3 *data fetched at runtime*, never bundled |
| `transport.py` | the only network module: consented HTTPS with an exact allow-list |
| `quarantine.py` | staging, identification (headers only), promotion |
| `delta.py` | optional Windows-only PA30/PA31 reconstruction through the system `msdelta.dll`; no pure-Python applier because none was both complete and licensed |

Flow: **search** (metadata only; x64 candidates with KB references) then **plan** (the exact URLs shown to the analyst) then **download** each build from `msdl.microsoft.com` (one redirect permitted to a `*.blob.core.windows.net` host, admitted only as that redirect target; the signed blob URL is never returned or stored) then **verify** size and SHA-256 against Winbindex then **quarantine** then **promote** through `ProjectService.create`. A matching hash proves identity with the Winbindex record, not vendor authenticity.

Transport limits (`acquisition/transport.py`): hosts `CONSENTABLE_HOSTS = {winbindex.m417z.com, msdl.microsoft.com}`; per-file cap 512 MiB; total download deadline 3,600 s (so a slow-drip server cannot hold a connection open); request timeout 10 s; metadata deadline 120 s; at most 3 attempts on 429/5xx with `Retry-After` capped at 60 s; 4 concurrent probes; headers `User-Agent: PatchTrace`; per-byte progress callback to the dialog bar. Every redirect hop is re-checked; non-ASCII or huge `Retry-After`/`Content-Length` values are rejected (audit fix). Consent is an object naming the exact hosts; the CLI requires the matching `--consent-hosts` list.

## Enrichment pipeline (`enrichment/`, contract `enrichment/1`)

`pipeline.run(project_snapshot, config)` is worker-safe, reads an immutable snapshot and returns an immutable result; `publish` must run on the thread owning the `ProjectStore` and is the only writer. Stage order: **views, signals (B1), wil (B2), ranking, contextual (B3)**. A later optional stage failing never discards earlier stages; the overall status degrades to `partial`. Missing evidence is `unavailable`, never an empty success. `STAGE_VERSIONS` (all 2 at `21a005e`) and the detector versions feed the cache key.

| Stage | Module | What it does |
|---|---|---|
| views | `views.py` | ownership-checked immutable `RunView`/`MatchView` with bounded code; forged ids rejected |
| signals | `signals.py` (about 1,000 lines) | eight lexical detectors over decompiled C text: BND, INT, OVF, VAL, ERR, SIZE, WIL, SCRUB. Rules are lexical, not typed IR; hunks that are comment-only are not edits |
| wil | `wil.py` | `Feature_<uint32>` sites and transitions, WIL wrapper evidence |
| ranking | `ranking.py` | exact integer `attention/1`: weighted detector scores grouped by underlying edit, ordering by score with explicit ties; no floats anywhere |
| contextual | `cve.py` | CVE context from NVD and MSRC snapshots; advisory text is context, not evidence: it only *reorders* B1 results when a context term coincides with something observed in the binary, never changes a B1 score; provider disagreements are recorded and block that contribution instead of being merged; CVSS cross-provider conflicts are kept |

Identity and storage: stage ids are `domain_id`s over canonical JSON of the inputs (older/newer SHA-256 plus sorted RVAs), so results are keyed by content and reproduce across OSes ([21](21-data-model-and-storage.md)). `cache.py` is the optional content-addressed derived-stage and raw-output cache (entry served only after its manifest parses and hash verifies; budget in GiB; `status|verify|prune`). `profiles.py` provides `profile/1`.

CVE transport (`enrichment/intelligence.py`): hosts `api.msrc.microsoft.com` (SUG v2.0 per-CVE entity) and `services.nvd.nist.gov` (CVE API 2.0), HTTPS port 443 only, 4 MiB response cap, optional NVD key header for NVD only (dropped on cross-host redirect), NVD pacing (5 requests per 30 s keyless, 50 with a key) and the expected duration stated in the consent preview, at most 64 CVEs per plan. The only data leaving the machine is the CVE identifier in the URL and two fixed headers.

Hardening already landed (backlog H1 to H13, `enrichment-hardening-backlog.md`): history and retention bounds with verified backups first, WIL `partial` for one-sided pairings, contextual rerank requires binary evidence, SIZE cast-only and BND added-loop false-positive fixes, `_TEMP` over-collapsing fixed, cancellation latency (`netutil.py`), NVD pacing, merged-snapshot `retrieved_at` = oldest contributor. Open items: hit-rate objective of 500 ms at 10,000 pairs measured 3.1 s (`tasks/todo.md`), env allow-list default pending a native Windows run.

## AI interpretation (optional)

The path is deliberately long so nothing reaches a model, or becomes a finding, by accident.

1. **Context** (`evidence.build_context`, default 24,000 characters, minimum 512): selects the chosen matches' functions (older/newer, sorted deterministically), then callers and callees that resolve to exactly one owned function (never "guess counted aliases"), records every omission ("context unavailable"), and fixes a digest. Evidence ids are derived from the artifact SHA-256 and line range, so a forged id cannot resolve.
2. **Preview** (GUI): the exact payload, provider, endpoint, model, budget, and a session-only credential field. Cancel sends nothing.
3. **Transport** (`providers.py`): kinds `ollama` (loopback only: `localhost`, `127.0.0.1`, `[::1]`; IPv4-mapped IPv6 refused so the verdict does not depend on the interpreter) and `openai` (HTTPS required). Endpoint may not carry credentials, query or fragment. Proxies are ignored (`ProxyHandler({})`), redirects refused, response capped at 2 MiB, 120 s deadline, cancellable. The bearer header is built only for `openai`; `ProviderConfig.api_key` is `repr=False` and ASCII-validated.
4. **Quarantine and validation** (`interpretation.py`): the system prompt embeds the JSON schema of `Response` and tells the model code and strings are untrusted evidence, to cite only supplied evidence ids, and that confidence is qualitative (low, medium, high), "not vulnerability probability"; no CVEs, severity or exploitability are to be inferred. The response must be strict JSON matching the schema (extra fields forbidden, size bounds), `validate_context` re-derives the digest and every evidence reference, and a finding is promoted only if each cited id exists in that context and belongs to its matches' runs. A malformed or rejected response stays inspectable as plain text and never becomes a finding.
   - **Claim screening** (`screen_claims`, SPEC-41 R29): CVE, CWE and CVSS claims (identifiers and scores, folded across case, dashes, width forms, invisible characters and digit scripts) that appear in a finding's model-written text but not in the supplied context cause that finding to be quarantined, except the one `cwe` the prompt invites with a rationale. The model therefore cannot introduce vulnerability facts of its own. If every finding is quarantined the run fails with a `PT-PROVIDER` note; if some are, the run completes with an error note, and the raw response is always kept.
5. **Review**: findings carry `review='unreviewed'`; analyst conclusion and decisions are yours, saved separately from model content.

`providers` never touches the project; `interpretation` returns a result only; `service.add_interpretation` stores it. AI-provider hardening (SPEC-41 R11, R14, R18, R29, R33) landed in slice AI-FIX. **Not accepted live:** local and remote provider acceptance is open in `tasks/todo.md`; provider tests use injected transports and are not live compatibility evidence.

## Reports (`reports.py`)

Atomic exports from validated persisted snapshots: Markdown (all `~`, `:` and markup escaped), self-contained HTML (escaped content, no scripts), and JSON. Options: include code (off), include notes (on), selected findings only. Code and path handling: `include_code=False` removes code from match-override annotations too; path redaction applies to prose, while verbatim code/evidence strings only get credential redaction. An `ExportManifest` records format, hash, finding ids and options. `kev/report.py` builds a KEV block for exported reports; `reports.py` does not import it, so that wiring is not in the exporter yet.

## Limits at a glance

| Subsystem | Limit | Value |
|---|---|---|
| Winbindex metadata | compressed / decompressed | 64 MiB / 256 MiB |
| Winbindex metadata | request deadline | 120 s |
| Download | per file | 512 MiB |
| Download | total deadline per attempt | 3,600 s |
| Download | request timeout / attempts | 10 s / 3 |
| Download | `Retry-After` cap | 60 s |
| Download | concurrent probes | 4 |
| CVE transport | response cap | 4 MiB |
| CVE transport | CVEs per plan | 64 |
| NVD pacing | keyless / with key | 5 per 30 s / 50 per 30 s |
| Enrichment store | per row / total | 32 MiB / 128 MiB |
| Enrichment retention | current / stale generations | 8 / 2 |
| AI context | default / minimum / setting range | 24,000 / 512 / 512 to 200,000 characters |
| AI provider | response cap / deadline | 2 MiB / 120 s |
| AI response | findings / alternatives per finding | at most 100 / 20 |
| AI response | explanation / summary / fix purpose | at most 8,000 / 4,000 / 4,000 characters |
| AI response | list fields (supporting, unknowns, ...) | at most 100 entries each |
| AI response | confidence | `low`, `medium` or `high` only |
| AI response | category | `security-fix`, `ordinary-bug`, `feature`, `refactor`, `compiler-noise`, `unknown` |
| AI response | CWE | optional, pattern `CWE-<1..5 digits>`, with a rationale |

## Error codes

- `PT-ACQ-*`: `INPUT`, `CONFIG`, `LIMIT`, `CANCEL`, `NETWORK`, `PROVIDER`, `NOTFOUND`, `VERIFY`, `UNSUPPORTED`. `PT-ACQ-NOTFOUND` is a normal outcome (no downloadable candidate), which is why `acquire search` exits 4, not 3. A `recoverable` flag marks errors worth a retry.
- `PT-ENRICH-*`: `INPUT`, `OWNERSHIP`, `CONFIG`, `LIMIT`, `CANCEL`, `STALE`, `CACHE`, `NETWORK`, `PROVIDER`.
- `PT-PROVIDER`, `PT-CANCEL`: AI transport and cancellation; `PT-SCHEMA` for context and response validation.
- Messages are fixed templates: no raw provider, advisory or file text appears in an error.

## Failure behaviour (what is preserved)

1. A failed, cancelled or timed-out acquisition leaves no project and no promoted file; staged bytes stay in quarantine until removed.
2. A failed enrichment stage degrades the overall result to `partial`; completed earlier stages are kept and published.
3. A publish whose guard no longer matches is stored `stale`; it never replaces a current result and is never deleted by retention until it ages out.
4. A rejected AI response is stored as an attempt with its status, model, error and context digest, and is inspectable as plain text; no finding is created.
5. Cancellation is cooperative everywhere (`netutil.interruptible` makes a blocking socket call observe a cancel promptly, with a bounded number of abandoned threads), with a hard kill for child processes after the deadline.

## Where to read the code first

| Question | Start at |
|---|---|
| How is a build chosen and verified? | `acquisition/winbindex.py`, `acquisition/transport.py`, `acquisition/quarantine.py` |
| Why did a function get its attention score? | `enrichment/signals.py` (`_detector` table near the end), `enrichment/ranking.py` |
| What is sent to a model? | `evidence.build_context`, then the GUI preview in `ui.py` (`preview_interpretation`) |
| Why was a response rejected? | `interpretation.validate_context`, `validate_response`, `screen_claims` and the stored attempt |
| How does CVE text affect order? | `enrichment/cve.py` (contextual stage), never B1 scores |
