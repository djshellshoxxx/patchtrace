# MSRC sources for the KB-to-CVE reverse index (research note RK1)

Status: research for SPEC-31-B, 2026-10-14 (UTC), researcher RK1. Docs and fixtures only; no `src/` or `tests/` code changed. Tags: `[S#]` primary source in section 0 (URL and SHA-256); `[live]` request made by this run through the sandbox proxy; `[unv]` not verified, a hypothesis and never a fact; `[inf]` inference from cited evidence.

## 0. Evidence ledger and egress result

**Headline: the MSRC data hosts were blocked, so no real CVRF, CSAF or SUG document was retrieved.** Live sizes, paging, rate headers, Microsoft's CSAF layout and field use are therefore `[unv]`. Verified facts come from Microsoft's own API repo and blog posts, the OASIS TC repo, and one live security.txt.

- `[live]` 79 requests, 782,479 body bytes of the 5 MB budget. Reachable: `raw.githubusercontent.com`, `www.microsoft.com`. Blocked (proxy answers 403 to CONNECT): `api.msrc.microsoft.com`, `msrc.microsoft.com`, `portal.msrc.microsoft.com`, `aka.ms`, `learn.microsoft.com`, `support.microsoft.com`, `catalog.update.microsoft.com`, `docs.oasis-open.org`, `services.nvd.nist.gov`, `www.cve.org`, `sugapitutorialv2.azurewebsites.net`. The code-hosting site and its API answer HTTP 403 "not enabled for this session". Nothing was routed around.
- Fixtures: `tests/fixtures/kbcve/msrc/` holds only MIT-licensed upstream bytes (7 files plus a swagger subset) with `PROVENANCE.json`. No MSRC data fixture is committed: no bytes were obtainable and the quoted terms (section 2) grant no redistribution right.

| ID | Source (all retrieved 2026-10-14 10:27-10:37Z unless noted) | Bytes | SHA-256 |
|---|---|---|---|
| S1 | https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/docs/swagger.json (OpenAPI 3.0.1, "MSRC CVRF API" v3) | 195,539 | 1632aa08008963cead7902c0051fb2ac09ac67c75a27f973f3d7238755d3ef3f |
| S2 | same repo `README.md`, `src/README.md`, `docs/README.md`, `LICENSE` (MIT), `src/MsrcSecurityUpdates/MsrcSecurityUpdates.psd1` (v1.9.9, release notes to 2024-11-26) | 2,740 / 9,399 / 1,434 / 1,183 / 7,338 | README 08c60404..a3; psd1 and LICENSE in PROVENANCE.json |
| S3 | same repo `src/MsrcSecurityUpdates/Public/{Get-MsrcCvrfAffectedSoftware,Get-MsrcSecurityUpdate,Get-MsrcCvrfDocument,Set-MSRCApiKey}.ps1`, `Private/Get-CVRFID.ps1` (committed byte-exact) | 4,708 / 5,596 / 2,654 / 1,899 / 1,160 | PROVENANCE.json |
| S3b | same repo `Public/Get-MsrcVulnerabilityReportHtml.ps1`, `MsrcSecurityUpdates.tests.ps1` (not committed) | 25,150 / 7,788 | b6cc76ca..cb7 / f8dc6607..f29 |
| S5 | https://www.microsoft.com/en-us/msrc/blog/2021/02/continuing-to-listen-good-news-about-the-security-update-guide-api (2021-02-09) | 91,696 decoded | 9c4f20867498927240f32f6d3b0aa1b7c9f91de14cc3d0885e9226340c9b5e83 |
| S6 | https://www.microsoft.com/en-us/msrc/blog/2024/07/announcing-the-cvrf-api-3-0-upgrade (2024-07-11) | 86,711 | da9f3d94261c91984d284392a817ab884ec66a09687f482cd1393979639d8826 |
| S7 | https://www.microsoft.com/en-us/msrc/blog/2023/01/publishing-cbl-mariner-cves-on-the-security-update-guide-cvrf-api (2023-01-06) | 87,870 | c88c4772e760c92ae00a258e6e50d483ac09434c455446c96bf0d2e422434108 |
| S8 | https://www.microsoft.com/en-us/msrc/blog/2024/11/toward-greater-transparency-publishing-machine-readable-csaf-files (2024-11-12) | 92,117 | c2811c335ecb6f953b7b16355a59e7330487a5300ae31a527afc217118e2b929 |
| S9 | https://www.microsoft.com/en-us/msrc/faqs-security-update-guide (SUG FAQ) | 121,846 | 5b36695b0ea80cd24c9a1700a75247cadb39cf2821f7f4419e0b8698fd8b370a |
| S10 | https://www.microsoft.com/en-us/legal/terms-of-use ("Last Updated: February 7, 2022") | 159,102 | a767ea37d14609773d4d32034500e8c0c975f05d87951e4fd7336072abeaadb1 |
| S11 | https://www.microsoft.com/.well-known/security.txt (`Last-Modified: Mon, 20 Apr 2026 13:51:07 GMT`) | 868 decoded | 6dd90223a6087731df8769ba1b2117b5c835cf5c62680ca1c5abceda7d47b318 |
| S12 | https://raw.githubusercontent.com/oasis-tcs/csaf/master/csaf_2.0/prose/csaf-v2-editor-draft.md (TC editor draft; the OS HTML on docs.oasis-open.org is blocked) | 294,479 | 5bc757cc8dcf1a48a73c50de8100b0437bda1f9b5b860afd051c585749f568be |
| S13 | https://raw.githubusercontent.com/oasis-tcs/csaf/master/csaf_2.0/json_schema/csaf_json_schema.json | 57,152 | 29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262 |
| S14 | repo `tests/fixtures/cve/msrc_CVE-2024-38063.json` and its `README.md` (prior-session live capture 2026-10-12, trimmed; not reproducible now) | 2,688 | 93cb029f122f71f53fbbcc0107e18ea4e03ecbe9fd7479bcbcd4ae37b9162621 |

## 1. Endpoints: exact URL templates and what they return

| # | Surface | Template and behaviour | Evidence |
|---|---|---|---|
| 1 | CVRF v3 index | `GET https://api.msrc.microsoft.com/cvrf/v3.0/Updates?api-version=2023-11-01` returns a bare JSON array of `{id, alias, documentTitle, severity?, initialReleaseDate, currentReleaseDate, cvrfUrl}` (all required except `severity`; `additionalProperties:false`). v2.0 uses `api-version=2016-08-01` and wraps the array in `.value`. Host and base path are NOT in the swagger (no `servers`); they come from the module. | [S1] schema `Update`; [S3] Set-MSRCApiKey, Get-MsrcSecurityUpdate |
| 2 | Index filters | `Updates?$filter=CurrentReleaseDate gt 2026-09-01 and CurrentReleaseDate lt 2026-10-01&api-version=...`. Swagger: "OData URL filtering ... on current and initial release dates"; query options filter/orderby/top/skip/skiptoken/count/search are declared. Server page size and `nextLink`: `[unv]`. | [S3] Get-MsrcSecurityUpdate; [S1] |
| 3 | Index by key | `Updates('{key}')`; key is a `yyyy-Mmm` ID, a CVE number, or a year (module validates 2016..current). Returns document summaries (`id`, `cvrfUrl`), never KBs. | [S1] `/updates({key})`; [S3]; [S14] README |
| 4 | Document | `GET .../cvrf/{yyyy-Mmm}?api-version=2023-11-01`, `Accept: application/json` or `application/xml`. Swagger gives only "Success" and no response schema, so the CVRF JSON shape is undocumented; the PowerShell code is the only first-party description. | [S1] `/cvrf/{id}`; [S3] Get-MsrcCvrfDocument |
| 5 | Auth | None. API-key and login requirement removed 2021-02-09 (an old key is ignored). An `Authorization` header is sent only if the caller set an AAD token. | [S5]; [S2] psd1 note 2021-02-03; [S3] |
| 6 | Versions | The 2.0 URL redirects to 3.0 since 2024-07-11. | [S6] |
| 7 | Unfetchable ID | `/Updates` lists `2017-May-B`; the module filters it out and its tests expect fetching it to throw. | [S3] Get-CVRFID; [S3b] tests |
| 8 | SUG v2.0 per CVE | `GET https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{CVE}`. Captured record: `releaseNumber` ("2024-Aug" = the monthly CVRF ID), `latestRevisionDate`, `revisions[]`, `cweList`, `tag`, `customerActionRequired`, `articles` (HTML); no per-product or KB field. Not in the swagger, so no stability or terms promise. | [S14] |
| 9 | SUG OData | `@odata.context` is `.../sug/v2.0/sugodata/v2.0/en-US/$metadata#vulnerability/$entity`, so an OData service with `$metadata` exists. Entity sets and filters: `[unv]`. | [S14] |
| 10 | CSAF pointer | security.txt contains `CSAF: https://msrc.microsoft.com/csaf/provider-metadata.json`. `www.microsoft.com/.well-known/csaf/provider-metadata.json` and `/csaf/provider-metadata.json` are 404. The metadata file itself: `[unv]`. | [live][S11][S8] |
| 11 | CSAF key | security.txt `Encryption:` `https://msrc.microsoft.com/.well-known/csaf/openpgp/998D7EC1A516E3D17FF90480EF148D3CDE714E0D.asc`. security.txt `Expires: 2026-09-23T16:00:00Z` is already past on 2026-10-14, so treat the pointer as a hint and pin the URL in code. | [live][S11] |
| 12 | CSAF layout (normative) | Filename = lower-cased `/document/tracking/id` with `[^+\-a-z0-9]+` -> `_` plus `.json` (5.1). Folders per year of `initial_release_date` (Req 11). `index.txt`: relative paths, one per line (Req 12). `changes.csv`: `"path","current_release_date"`, no header, newest first (Req 13). ROLIE feed JSON (Req 15-17) is preferred when both exist (7.3.2). Hash `.sha256/.sha512` (Req 18), `.asc` signature (Req 19), public key (Req 20). Trusted provider = Req 18-20 (7.2.3); consumers MUST check hash and signature before processing (7.3.2). | [S12] 3065, 5793-5830, 5835, 5997-6040, 6195, 6252 |
| 13 | CSAF document path | A per-year path such as `.../csaf/advisories/2024/msrc_cve-2024-38063.json` is a recollection only. Which of directory or ROLIE Microsoft serves, and whether hashes and signatures exist: `[unv]`. | `[unv]` |

## 2. Sizes, paging, rate limits, terms, cadence

| Topic | Finding | Evidence |
|---|---|---|
| Document sizes | Monthly CVRF document is "multi-MB" (prior session); exact bytes, gzip support, ETag: `[unv]`. Grew sharply after CBL-Mariner CVEs joined the API on 2023-01-11. Count of monthly IDs ~123 (2016-Aug..2026-Oct) `[inf]`; CSAF per-CVE size and count `[unv]`. Only sizes measured: swagger 195,539 B, OASIS draft 294,479 B, schema 57,152 B. | [S14] README; [S7]; [S3] |
| Pagination | CVRF documents are single bodies. Index paging: OData options declared, behaviour `[unv]`. CSAF: none (index.txt/changes.csv are whole files). | [S1][S12] |
| Rate limit | No numeric limit published. MSRC says v3 is faster so callers may exceed limits and shows the error text "Too many follow-up requests: 21". `Retry-After`/`x-ratelimit-*` headers: `[unv]`. Existing repo rule (4 MiB cap, 3 attempts, Retry-After <= 60 s) stays. | [S6]; `docs/specs/enrichment.md` |
| Terms | Sample code is MIT (Copyright Microsoft). Swagger `info` has only title and version (no terms, licence, contact). MSRC API terms live on `portal.msrc.microsoft.com` (blocked): `[unv]`. Website terms (S10): "Unless otherwise specified, the Services are for your personal and non-commercial use. You may not modify, copy, distribute, transmit, display, perform, reproduce, publish, license, create derivative works from, transfer, or sell any information, software, products or services obtained from the Services." and for Documents: use "for informational and non-commercial or personal use only and will not be copied or posted on any network computer ... and (3) no modifications of any Documents are made." | [S2][S1][S10] |
| Cadence | Patch Tuesday, second Tuesday 10:00 AM PST; some products off-cycle; email and RSS notifications exist. Revisions land in place: CVE-2024-38063 has `releaseNumber` 2024-Aug but `latestRevisionDate` 2024-09-10 and revision 2 says September updates were released for more products. CSAF update interval: `[unv]`. | [S9][S8][S14] |
| Incremental sync | CVRF: poll the index with `$filter=CurrentReleaseDate gt <watermark>` (documented usage), refetch each changed whole document. CSAF: `changes.csv` (read down to the watermark) or ROLIE `updated`, refetch only changed files, verify hash and signature. Microsoft's choice `[unv]`. | [S3][S12] |

## 3. How a KB number appears, and why a KB query endpoint does not exist

CVRF (monthly document), per `Vulnerability[]` item; the product join is `Remediations[].ProductID` (array) matched against `ProductStatuses[].ProductID` and `ProductTree.FullProductName[].ProductID`:

| Field | Meaning and evidence |
|---|---|
| `Remediations[].Type` | 0 Workaround, 1 Mitigation, **2 VendorFix (the KB row)**, 5 Known Issue [S3][S5][S2]. Other values `[unv]`. |
| `Description.Value` | The KB id ("ID") [S3]. PowerShell doc example shows `"kb123456"`; real text form (bare digits or `KB` prefix) `[unv]`. Not always a KB: for "Microsoft Edge (Chromium-based)" the report replaces the link with Edge release notes [S3b 550-554]. May hold several lines (module fix 2017-06-02 "multiline KB articles") [S2]. |
| `URL`, `SubType` | Support-article URL and a label; `SubType` is absent in older months [S3 Get-KBDownloadUrl]. Value list (e.g. Security Update, Monthly Rollup) `[unv]`. |
| `FixedBuild` | Per remediation row; shown as "Unknown" when absent [S3b]; module reported it from 2021-04-07 [S2], so older documents may lack it `[inf]`. Format (e.g. `10.0.x.y`) `[unv]`. |
| `Supercedence` (sic) | Replaced KBs for that row; "None" when empty [S3b]. Separator and form `[unv]`. |
| `RestartRequired.Value` | Per row [S3]. |
| Other | `CWE.Value`; Notes Type 2 Description, 4 FAQ, 7 Tag, 8 Issuing CNA; Threats Type 0 impact, 1 exploit status, 3 severity [S3b][S5]. `ProductStatuses[].Type` numbering `[unv]`. |

CSAF: `remediations[]` requires `category` (vendor_fix, mitigation, workaround, none_available, no_fix_planned) and free-text `details`; optional `date`, `product_ids`, `group_ids` (at least one of the two is mandatory), `url`, `restart_required.category` (connected, dependencies, machine, none, parent, service, system, vulnerable_component, zone), `entitlements`. `vendor_fix` excludes `none_available`/`no_fix_planned` per product. `product_status` keys: first_affected, first_fixed, fixed, known_affected, known_not_affected, last_affected, recommended, under_investigation [S12 2611-2840][S13]. The standard does not say where a KB number lives, and has no field for FixedBuild or Supercedence; Microsoft's mapping is `[unv]` (candidates: `details`, `url`, product-tree version branches, notes).

**Query-by-KB.** Refuted for the documented API: swagger has 9 path templates (`/cvrf/{id}`, `/cvrf({id})`, `/updates`, `/Updates`, `/Updates/$count`, `/updates({key})`, `/updates/{key}`, `/Updates({key})`, `/Updates/{key}`); key accepts update ID, CVE or year; the 195,539-byte file contains no "KB", "Article" or "Remediation" [S1]. The Security Update Guide website does pivot on KB ("pivots on vulnerability ID numbers (CVE) and KB Article ID numbers") [S9], so a private SUG OData route probably exists; probing it was impossible (host blocked) `[unv]`. It is undocumented, so it must not be a dependency. A live probe of `.../sugodata/v2.0/en-US/$metadata` would settle it (section 7).

**Product id to build.** `FullProductName.Value` is display text ("... for x64-based Systems"); a product id carries no build. Builds come only from `FixedBuild` on a remediation row and from KB article text (blocked) [S3]. Treat product-to-build as `candidate` until a row supplies `FixedBuild` plus an exact product name; the same row may list many product ids.

| Trap | Evidence |
|---|---|
| One remediation row lists many `ProductID`s, so one KB spans products, architectures and (often) client and server rows; join per product id, never per KB | [S3] `-contains` join; `[inf]` for x64/ARM64/server examples |
| Remediations are per vulnerability, so a KB repeats under every CVE it fixes; edges are (kb, cve, product) | [S3] |
| Type 2 is not always a KB (Edge version/links), may be multiline, `SubType` or `FixedBuild` may be absent; validate `^\d{4,10}$` after stripping `KB` per line, else `MENTION_ONLY` | [S3b][S2] |
| Non-Windows rows: CBL-Mariner CVEs share monthly documents since 2023-01-11; filter Notes Type 7 tag "Managed by Mariner"; many have another CNA (Type 8) | [S7] |
| Revision in place: a revised CVE stays under its original `releaseNumber`, so a September KB can sit in the August document and a window on KB ship month or document ID misses it; conversely `currentReleaseDate` of an old document moves | [S14] `[inf]` for placement in the CVRF document |
| Replaced and withdrawn KBs: `Supercedence` is structured; withdrawal or re-release appears only in free-text revision descriptions; no structured withdrawn flag known | [S3b][S14] revisions; `[unv]` |
| Cloud-service and no-action CVEs have no KB (`customerActionRequired`); a preview or non-security KB has no MSRC row, so absence is not "no change" | [S8][S14][S9] `[inf]` |
| CSAF contradictory `product_status` across statuses is a mandatory test; revisions carry `tracking.version` (integer or semver) and `revision_history` | [S12] 6.1.6, 6.1.14, 6.1.16; [S13] |
| Index id with no document (`2017-May-B`); v2 vs v3 index wrapper differs | [S3] |

## 4. Cheapest correct product-scoped reverse index (offline)

1. **Backfill from CVRF monthly documents**, not per-CVE calls: 1 index request plus N document requests (one per month in the window; 24 by default). Per-CVE SUG calls would be hundreds per month `[inf]` and carry no KB data [S14]. Normalize only `Remediations[Type==2]` rows plus the product-tree names, `ProductStatuses`, tag, CWE, `Revisions[]`; keep raw SHA-256, `currentReleaseDate`, parser version.
2. **Window on two axes.** Backfill selects document ids by month; incremental sync selects by `currentReleaseDate > watermark`, which also returns old documents that were revised (the only way to catch KBs shipped later for older CVEs).
3. **Incremental:** `Updates?$filter=CurrentReleaseDate gt <watermark>`; refetch whole changed documents (no delta exists); new immutable revision per raw hash; ETag or Last-Modified conditional GET only if the server sends them `[unv]`. If CSAF is verified, use `changes.csv` plus per-CVE files with hash and signature checks as the finer-grained path; the CSAF lineage is shared with CVRF, so it is not a second vote.
4. **Volume model (all `[unv]` until section 7 is run):** bytes(window) = sum of monthly document sizes in the window (+ revised older documents); requests = 1 + N; steady state = 1 index request + changed documents. Planning envelope: multi-MB per month [S14], so tens of MB per year uncompressed, 12 requests per year; keep the spec's provisional 64 MiB per-document cap until measured.
5. **Coverage disclosure the index cannot avoid:** scanned month ids and failures; unfetchable ids; revision lag (CVE first released before the window and revised into it is invisible unless its document was refetched); non-Windows and Mariner rows; CVEs without KB rows; KBs without CVE rows (non-security releases); product groups or "All Windows" rows with no resolvable id; undocumented `ProductStatuses` numbering; and that SUG, CVRF and CSAF share one MSRC lineage. "Not observed in scanned scope" is the strongest allowed negative.

## 5. Resolutions of RESEARCH_REQUIRED and section 17 items 1, 2, 5, 6

| Item | Resolution |
|---|---|
| RESEARCH_REQUIRED: universal KB query endpoint (3, B1, B2) | Refuted for CVRF v3 [S1]; SUG private route `[unv]`; keep "index unavailable" semantics. |
| RESEARCH_REQUIRED: documented release index (B2) | Exists: CVRF `/Updates` with OData date filters [S1][S3]. |
| RESEARCH_REQUIRED: per-CVE SUG endpoint | Only evidenced by the prior-session capture [S14]; not re-probed (blocked). |
| RESEARCH_REQUIRED: CSAF discovery (B1) | Pointer verified in security.txt [live]; provider-metadata content, role, layout `[unv]`. |
| RESEARCH_REQUIRED: B6 budgets (16/64 MiB, 600 docs, 2 concurrent, 30 s, 15 min) and 24/60-month window | Unmeasured, keep provisional. 600 documents exceeds the ~123 monthly ids `[inf]`; max 60 months is below it. |
| RESEARCH_REQUIRED: KB syntax 4-10 digits | Not verifiable here; keep, but validate per line (section 3). |
| 17.1 reverse-lookup completeness | Resolved as: no documented query-by-KB; build the edge table from CVRF monthly documents with a `currentReleaseDate` watermark; disclose coverage per section 4. |
| 17.2 CSAF authenticity | HTTPS plus security.txt is transport provenance only (security.txt expired 2026-09-23). `vendor-verified` requires verifying `.asc` over the exact bytes with a key whose fingerprint is pinned from two channels (security.txt shows `998D7EC1...4E0D`); whether MSRC publishes hashes and signatures: `[unv]`. If it does not, CSAF stays `transport-only`. |
| 17.5 component discovery | No MSRC structured field names a binary: CVRF fields read by the first-party code are title, notes, threats, CVSS, remediations, CWE, revisions [S3b]; SUG gives `tag` (e.g. "Windows TCP/IP") and `cweList` [S14]. Tier A (explicit filename in a structured field) is effectively never; use `tag` as a Tier D hint, never parse filenames from HTML, default `NEEDS_FILENAME`. |
| 17.6 data volume | ~123 monthly documents `[inf]`, multi-MB each [S14]; do not backfill everything by default; 24-month default is workable; size measurement is the first step of section 7. |

## 6. Corrections to the spec

1. B2/B3: define coverage on two axes (document id and `currentReleaseDate`); a month window alone is wrong because revised CVEs stay in their original document [S14].
2. B3: add the concrete KB rule: `Remediations[Type==2]`; split `Description.Value` lines; accept bare digits or `KB`+digits; others (Edge) are not KBs; `SubType`, `FixedBuild`, `Supercedence` optional (field is spelled `Supercedence`); `Type 5` rows are known issues, never edges.
3. B1: CSAF discovery is the `CSAF:` field of `https://www.microsoft.com/.well-known/security.txt` [live], not a `www.microsoft.com/.well-known/csaf` path (404 [live]); security.txt may be expired.
4. 3 table and B1 name the SUG v2 record as a per-CVE source; add that it yields `releaseNumber` (the CVRF id) and `tag`, but no KB or product rows [S14]; the repo's `intelligence.py` parsing should be checked for retaining `releaseNumber`.
5. B6: the 4 MiB cap fits SUG v2 per-CVE only; the monthly CVRF body is multi-MB [S14] and needs its own measured cap; "600 documents" is moot for CVRF.
6. 18/B8: the OASIS OS HTML was unreachable; this note used the TC editor draft [S12]; SPEC-28 cites `cs01`, SPEC-31 cites `os`; cite one version.
7. 14 "license-compliant official metadata": the only retrievable terms (S10) restrict copying and modifying documents; MSRC API terms are `[unv]`. The existing trimmed real MSRC fixture `tests/fixtures/cve/msrc_CVE-2024-38063.json` (S14) needs the same licence check; until confirmed, prefer synthetic fixtures with hash-only provenance for MSRC data.
8. B8: record the swagger-derived facts: 9 paths, no KB parameter, `Update` schema, no auth scheme, no response schema for `/cvrf/{id}`.

## 7. Probe pack for an environment with MSRC egress (turns `[unv]` into facts; about 25 requests)

1. `curl -sI -H 'Accept-Encoding: gzip, identity' 'https://api.msrc.microsoft.com/cvrf/v3.0/Updates?api-version=2023-11-01'` then GET it: ID count, `2017-May-B`, paging, rate headers.
2. `curl -sI` and `curl -r 0-65535` of `.../cvrf/2024-Aug?api-version=2023-11-01` (JSON and XML): Content-Length, gzip, ETag, `Remediations` row shapes, `Description.Value`, `SubType`, `FixedBuild`, `Supercedence`, `ProductStatuses.Type`.
3. `.../Updates('CVE-2024-38063')?api-version=2023-11-01` and the same filter with `CurrentReleaseDate gt` a recent date.
4. `https://msrc.microsoft.com/csaf/provider-metadata.json`: `role`, `distributions`, `canonical_url`, `last_updated`; then `index.txt`, `changes.csv` (HEAD plus first 2 KB), one advisory with its `.sha256` and `.asc`; record where the KB number and build sit.
5. `https://api.msrc.microsoft.com/sug/v2.0/sugodata/v2.0/en-US/$metadata`: look for KB or `affectedProduct` entity sets.
6. Quote the API terms at `https://portal.msrc.microsoft.com/en-us/developer`; only then decide on MSRC-derived fixtures.
