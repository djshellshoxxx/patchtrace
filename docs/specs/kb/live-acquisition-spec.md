# KB live acquisition: consent hosts, request plans, caching and the L1 probe (KBF-01)

Status: draft, developer-ready design. Nothing in sections 4 to 8 is built unless it says BUILT. Date: 2026-10-15. Base commit: `54fd085` (`claude/instance-d-gui`). Proposed alias: KBF-01 (non-numeric family "KB finish"; SPEC-56 is claimed by PR #61, so no SPEC number is proposed; the owner confirms, REGISTRY rule 6). Owner packages: `kbcorrelation/sources/{net_plan,cvrf_fetch}.py`, `kbcorrelation/cli_online.py`, `acquisition/{transport,winbindex}.py`. Replaces the missing `docs/specs/kb-live-acquisition.md` that the header of `docs/research/gemini-kb-sources.md` says was split off (that file does not exist in the tree: verified by `ls`).

Reads with: `docs/specs/program-e/KB-integration-plan.md` (s6, s7.4, s8.1), `docs/specs/network-egress-privacy.md` (SPEC-42), `docs/specs/acquisition.md` (SPEC-08), `docs/research/kbcve/msrc-sources.md`, `docs/research/gemini-kb-sources.md`.

## 1. Purpose and non-goals

Purpose: make every byte the KB correlator receives from the network (monthly CVRF documents, Winbindex file records, symbol-server PE files, optional per-CVE JSON) arrive through one plan, one consent, one verified store, and make the first real-network run (probe L1) a recorded, honest gate.

Non-goals (each is a refusal, not a deferral): scraping the Microsoft Update Catalog or any HTML page; background or scheduled sync; auto-update; telemetry; sending any project data, path, hash or CVE list to a server (requests carry only the URL and two fixed headers `User-Agent: PatchTrace` and `Accept`); persisting a credential; downloading anything not named in the displayed plan; MSU/CAB/PSFX reconstruction (E3, separately gated).

## 2. Definitions

- Operation: one user action that may touch the network (`kb index sync`, `kb winbindex fetch`, `kb acquire`, `intelligence fetch`, `correlate --fetch`, `kev fetch`).
- Plan: the pure, I/O-free list of exact requests (`method`, `url`, `why`), hosts, caps and a `plan_sha` (`domain_id('kbc.indexplan', 1, plan minus plan_sha)`). BUILT for CVRF (`net_plan.build_plan`).
- Consent: the pair (hosts, plan_sha). Hosts must EQUAL the planned host set; a superset is refused. Consent is never stored; each operation asks again.
- Snapshot: bytes plus provenance (`SourceDoc`: kind, sha256 of decompressed bytes, uri, retrieved_at UTC, authenticity `tls-allowlisted-host`, parser_version).
- Probe: a read-only live run whose only output is a status file (`passed|failed|blocked`) and hash-only evidence.

## 3. Host and consent matrix (the rows that exist; code citations are for `54fd085`)

| # | Host and path | Used by | Consent flag | Caps (bytes / time / redirects) | Stored as |
|---|---|---|---|---|---|
| 1 | `api.msrc.microsoft.com` `GET /cvrf/v3.0/cvrf/<yyyy-Mmm>?api-version=2023-11-01`, `Accept: application/json` | `kb index sync` (`net_plan.py`, `cvrf_fetch.py`) BUILT, URL shape UNVERIFIED | `--consent-hosts api.msrc.microsoft.com --consent-plan <plan_sha>` | 32 MiB per document, 60 s per request, 15 min per plan, 3 attempts, Retry-After at most 60 s, 3 redirects same host https:443 | workspace `objects/<sha[:2]>/<sha>.gz` plus `docs` row (`store.py`) |
| 2 | `api.msrc.microsoft.com` `GET /sug/v2.0/en-US/vulnerability/<CVE>` | `correlate --fetch` (`enrichment/intelligence.py:55`) BUILT | `--consent-providers msrc` | 4 MiB, 30 s total (`TOTAL_TIMEOUT`) | `cve-snapshot` row |
| 3 | `services.nvd.nist.gov` `GET /rest/json/cves/2.0?cveId=<CVE>` | same | `--consent-providers nvd`; key only via `--api-key-env` | 4 MiB; pacing 6.0 s without key, 0.6 s with (`NVD_INTERVAL`) | `cve-snapshot` row |
| 4 | `msrc.microsoft.com` `/csaf/...`, `/.well-known/csaf/...` | `intelligence fetch` (`csaf/transport.py:31-32`) BUILT | `--consent-hosts msrc.microsoft.com` | 16 MiB per document | `advisory-source` row plus sidecar |
| 5 | `winbindex.m417z.com` `GET /data/by_filename_compressed/<name>.json.gz` | `acquire search` BUILT; KB use NOT BUILT (this spec, section 6) | `--consent-hosts winbindex.m417z.com` | 64 MiB compressed, 256 MiB decompressed (`winbindex.py:26-27`) | workspace `winbindex/<name>@<YYYY-MM-DD>.json[.gz]` |
| 6 | `msdl.microsoft.com` `/download/symbols/<name>/<TTTTTTTT><SIZE hex>/<name>` HEAD then GET; redirect only to `*.blob.core.windows.net` | `kb acquire`, `acquire download` BUILT | exact URL list from the plan | 512 MiB per file, 256 probes, 4 concurrent HEAD, 1 h per download | quarantine staging, then project |
| 7 | `www.cisa.gov` and `raw.githubusercontent.com` (CISA mirror) | `kev fetch` BUILT (`kev/contracts.py:155-158`) | `--consent-hosts <host>` | per KEV plan | `kev` snapshot files |

Corrections to the research file (`docs/research/gemini-kb-sources.md`, header says verified 2026-10-14; this tree cannot reach the hosts, so treat every row there as UNVERIFIED): its symbol URL formula `.../filename/timestamp_virtualsize/filename` is wrong, the code builds `<name>/<%08X timestamp><%x SizeOfImage>/<name>` with no underscore (`acquisition/contracts.py:53-58`); its Winbindex layout (`gh-pages`, `ntoskrnl.exe.json`, a `kbMapping` field) disagrees with the code's `by_filename_compressed/<name>.json.gz` and with the measured `windowsVersions.<ver>.<KB>` shape in `docs/research/kbcve/winbindex-servicing-catalog.md`; its NVD single-CVE query `?cveIds=` disagrees with the code's documented `?cveId=`. Do not copy any of those three into code.

SPEC-42 (`network-egress-privacy.md`) row 17 still says the CVRF sync has "no adapter"; `cvrf_fetch.py` exists and is routed (`kbcorrelation/cli.py:109-112`). Its census has no KEV rows. Both are documentation defects fixed in KBB-22.

## 4. Operation algorithm (all online verbs share it)

```
operation(plan_builder, args):
    plan = plan_builder(args)                       # pure; raises PT-KBC-SCOPE on bad scope
    render(plan) -> stdout/stderr                    # exact URLs, hosts, caps, plan_sha
    if args.offline:                                 # --offline with any consent flag is exit 2
        if any consent flag given: fail PT-KBC-INPUT "offline mode never fetches"
        return plan-only result (exit 2 if a fetch was requested)
    verify_consent(plan, consent_hosts, consent_plan)   # PT-KBC-CONSENT, nothing requested
    for request in plan.requests (concurrency 1):
        check cancel; check plan deadline
        body = bounded GET (no env proxy, redirects same host https:443, <= caps)
        raw  = gunzip_bounded(body) if gzip magic
        doc  = import_bytes(raw)                     # strict parse, dialect check (PT-KBC-SOURCE if unknown)
        require doc.release_id == requested month    # wrong month => PT-KBC-SOURCE, not stored
        store(doc) in ONE workspace transaction (BEGIN IMMEDIATE, busy_timeout 5000)
        yield per-month row {month, url, state: fetched|not-published|failed, sha256, bytes}
    coverage = build_coverage(requested, inspected, failed, retrieved_at)
    exit: 0 all stored (or present), 3 any month missing or failed (partial), 5 cancelled
```
Rules: one failed month never discards earlier stored months; a cancel raises `PT-KBC-CANCEL` after the documents already yielded (nothing half written); the plan time budget expiring marks the remaining months `failed` with `PT-KBC-ACQUIRE`.

HTTP classification (BUILT in `cvrf_fetch._fetch_one`): 200 -> parse; 301/302/303/307/308 -> follow only same host https:443 else `PT-KBC-SOURCE` "a redirect outside the consented host, or not https, was refused"; 404 -> `not-published`; 429/500/502/503/504 -> retry with backoff then `PT-KBC-ACQUIRE`; other -> `PT-KBC-SOURCE` "the server answered HTTP N". Proposed additions (KBB-10): 401/403 -> `PT-KBC-SOURCE` with details `{http: 401|403, key_required: unknown}` and the sentence "The server refused an anonymous request. PatchTrace does not store credentials; see the docs for the session-only key option." (only if L1 proves a key is needed).

## 5. Cache and refresh rules

- Content addressing: a document is identified by `doc_id = domain_id('kbc.source', 1, {kind, sha256})`. Fetching the same bytes twice is a no-op (`already_present: true`).
- A revised month has different bytes, so it becomes a second `SourceDoc`; the index keeps both and marks the older `superseded` (`index.py:111-166`). Never overwrite, never delete on sync.
- Default scope of a sync is finite and explicit (UI pre-fills 12 months, maximum 24 per plan, 60-month index ceiling, `limits.py`).
- Default refresh: fetch only months not already present. `--refresh-recent N` (proposed, N in 1..3, default off) re-fetches the N newest months because MSRC revises recent documents (RK1; CVE-2024-38063 evidence in the plan); a changed hash is stored as a new revision.
- Staleness: coverage reads `stale_cache` when the newest retrieval is older than `STALE_AFTER_DAYS = 45` (`scope.py:25`). This is wording only; no automatic refetch.
- No conditional requests in v1 (ETag / Last-Modified support of the MSRC API is UNVERIFIED).
- Offline reuse: every command except `index sync`, `winbindex fetch`, `acquire`, `intelligence fetch`, `kev fetch` and `correlate --fetch` reads only the workspace and the project; it never opens a socket (test `no_sockets` in `tests/test_kbc_net_plan.py`, `test_kbc_e0_e2e.py`).

## 6. Proposed addition: consented Winbindex record fetch for the KB workflow

Today the KB resolver reads Winbindex records from `<workspace>/winbindex/` that the user placed there (`kb index import --winbindex FILE`; `kbcorrelation/wiring.py:WorkspaceFileIndex`). `acquire search NAME` can fetch the same bytes but writes nothing KB can read. Add:

```
kb winbindex plan NAME [NAME...]          # pure: URLs, host winbindex.m417z.com, caps, plan_sha; zero network
kb winbindex fetch NAME... --consent-hosts winbindex.m417z.com --consent-plan SHA
    for name in names:  url = acquisition.winbindex.metadata_url(validate_file_name(name))
        resp = Transport.fetch_metadata(name, AcquisitionConsent.for_urls([url]))
        rows = winbindex.parse_rows(resp.body, name, resp.data_date)   # validates; md5-only rows kept
        write atomically workspace/winbindex/<name>@<resp.data_date>.json.gz   (sha recorded)
```
Error codes reuse `PT-ACQ-*` nested under `PT-KBC-ACQUIRE` (`details.acquisition_code`). A name may contain only `[a-z0-9._-]` and is lowercased (`validate_file_name`). At most 5 names per call (KB plan Q7). The record is GPL-3.0 data used at runtime and never committed (SPEC-08 licence note).

## 7. Probe L1 (the first real-network run) and its status file

Tool: `tools/live_kbc_probe.py` (NEW), workflow `.github/workflows/live-kbc.yml` (NEW; copy `live-kev.yml`: dispatch plus weekly cron, `contents: read`, `timeout-minutes: 15`, never required), marker `live_kbc` in `pyproject.toml` (integrator). Budget: at most 25 requests, 5 minutes, 200 MiB.

Requests (all GET, no credentials): P1 `/cvrf/v3.0/Updates?api-version=2023-11-01` (JSON); P2 the three newest `/cvrf/v3.0/cvrf/<yyyy-Mmm>?api-version=2023-11-01` with `Accept: application/json`; P3 one month with `Accept: application/xml` (is XML the only form?); P4 one month without `api-version` (record the 4xx); P5 one month without any key (record 401/403 if the API requires a key); P6 `winbindex.m417z.com/data/by_filename_compressed/afd.sys.json.gz`; P7 `msrc.microsoft.com/csaf/provider-metadata.json` (L4).

Evidence recorded (hash-only, no advisory text): HTTP status, `Content-Type`, `Content-Length`, SHA-256, top-level key names, whether `Vulnerability[].Remediations[].Type` exists, the SHAPE CLASS of `Remediations[Type==2].Description.Value` over all rows (`digits`, `KB+digits`, `prose`, `multi-line`, counts only), presence of `FixedBuild`, `Supercedence`, `ProductID` arrays, decompressed size, parse time and peak RSS of the parser (`resource.getrusage`, Linux only).

Classification (as `tools/live_kev_probe.py`): unreachable host, timeout, 403 or 429 from the runner address -> `blocked` (external condition, never a pass); reachable but the document does not parse as `cvrf-json/0` (or the key set differs from the pinned dialect), a different month than requested, or sizes above `KbcLimits.cvrf_doc_bytes` -> `failed` (this is the drift the probe exists to catch). Status file `build/live-status/kbc-cvrf.json`, strict JSON, keys `engine`, `status`, `reason`, `probes[]`, `runner`, `utc`; aggregated by `tools/check_live_status.py` into the Markdown table copied to `docs/qa.md`.

Pass criteria for the dialect pin (KBB-10): P2 returns JSON; every Type 2 `Description.Value` shape class is `digits` or `KB+digits`; P5 succeeds anonymously or the key requirement is recorded; the largest document is below 32 MiB; the parser peak RSS is at most 8 times the document size.

## 8. Credentials (only if P5 proves a key is required)

Session-only: read from the environment variable NAMED by `--api-key-env` (same mechanism as NVD, `cli.py:93,172-174`), sent only in the header the API documents, removed on any cross-host redirect, never written to `QSettings`, `analysis.log`, snapshots, plans, status files or error text (SPEC-42 R3). The plan shows "an API key from <ENV NAME> will be sent in a header to api.msrc.microsoft.com" without the value. `plan_sha` includes the header NAME, not the value. Test: a canary key value must not appear in any file under the workspace after a faked sync.

## 9. Error codes

`PT-KBC-INPUT` (offline with consent flag, bad month), `PT-KBC-SCOPE` (future month, over 24 months, over the 60-month reach), `PT-KBC-CONSENT` (hosts or plan_sha differ), `PT-KBC-SOURCE` (HTTP status, wrong month, dialect unknown, refused redirect), `PT-KBC-ACQUIRE` (network failure after retries, plan deadline), `PT-KBC-LIMIT` (document over cap), `PT-KBC-CANCEL`, `PT-KBC-UNSUPPORTED` (index request in a sync plan). Exit codes: 0, 2 (input, consent, scope, unsupported), 3 (runtime or any month missing), 5.

Real strings (BUILT, run on `54fd085`): `error: a requested month is in the future` (`kb index sync --months 2099-Feb`), `consent hosts must name exactly: api.msrc.microsoft.com`, `consent was given for a different plan; review the new plan_sha`, `offline mode never fetches`.

## 10. Determinism, privacy and security invariants

1. `plan_sha` is a pure function of months, URLs, hosts, caps, accept header, dialects, parser version; any change needs new consent.
2. No silent upload; no request without exact-plan consent; `--offline` wins over every consent flag.
3. No fabricated evidence: a fetched document is labelled `tls-allowlisted-host`, never "signed" or "trusted"; a local file is `unverified-local-file`.
4. Offline-first: every read path works with the network cable removed.
5. Hostile input: strict JSON (no duplicate keys, NaN, BOM), XML with any markup declaration refused, caps before parse, text never in error messages.
6. Environment proxies are ignored by design (`ProxyHandler({})`). Consequence for corporate networks: the verbs cannot work behind a mandatory proxy; the documented fallback is `kb index plan` on the online machine and `kb index import` offline (plan open question 15).

## 11. Test plan

Existing BUILT tests: `tests/test_kbc_net_plan.py`, `tests/test_kbc_cvrf_fetch.py` (fake opener: consent equality, offline refusal, 429/5xx, Retry-After, cap, cancel, hostile redirect). New (red first): `test_kbc_winbindex_fetch.py` (plan purity, consent equality, name validation, atomic write, md5-only rows kept), `test_live_kbc_probe.py` (classification blocked vs failed, schema drift, status file strictness), `test_kbc_key_never_persisted.py` (canary), `test_kbc_refresh_recent.py` (changed hash stores a revision, same hash is a no-op).

## 12. Open questions

Q1 Does the MSRC CVRF v3 endpoint serve JSON anonymously to a plain GET (L1/P2, P5)? Q2 Does it honour `Accept: application/json` or require a `.json` suffix? Q3 Real document size per month (limits are provisional). Q4 ETag support. Q5 Is a corporate-proxy option wanted (owner decision; changes the "ignore env proxies" privacy default)?

## 13. Acceptance

`kb index sync --months <3 real months>` run by CI probe or owner stores three documents with coverage `complete_in_scope`; the status file says `passed`; `kb search <real KB>` answers from the stored documents; the same run with the network disabled answers identically; `docs/qa.md` has the row. BLOCKED stays BLOCKED in reports and is never counted as done.
