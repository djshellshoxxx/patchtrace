# Vulnerability data feeds: CISA KEV, FIRST EPSS, NVD API 2.0

Research note for Program E (KEV track, SPEC-46). Research only: no code, no schema generation.
Access date for every fact: **2026-10-15** (UTC, sandbox clock 2026-10-15T03:15Z) unless stated.
Confidence tags: **verified** (fetched this session), **secondary** (third-party page quoting the vendor), **[U]** unverified (primary host unreachable or not confirmable).

Primary hosts `www.cisa.gov`, `nvd.nist.gov`, `api.first.org` and `epss.empiricalsecurity.com` returned `getaddrinfo ENOTFOUND` from this sandbox on 2026-10-15. Their content below comes from the CISA-owned GitHub mirror (`raw.githubusercontent.com/cisagov/kev-data/develop/`, reachable) or from search snippets, and is marked accordingly.

## Verified facts

**CISA KEV**
- Canonical catalog page: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` (short link `https://cisa.gov/kev`). Source: `https://raw.githubusercontent.com/cisagov/kev-data/develop/README.md`, accessed 2026-10-15, **verified** (mirror README text; the cisa.gov page itself is [U]).
- Mirror README cadence wording: the mirror is "updated shortly after the canonical source at cisa.gov is updated"; both sources are "synchronized within minutes of each other". Same URL, **verified**. The older "weekdays during US Eastern business hours" wording quoted in the earlier plan was **not** seen in this fetch; treat it as [U] until the `main` README is re-read.
- Schema file `known_exploited_vulnerabilities_schema.json` (`develop`), accessed 2026-10-15, **verified**: top-level `required` = `catalogVersion`, `dateReleased`, `count`, `vulnerabilities`.
- `dateReleased` description in schema: "YYYY-MM-DDTHH:mm:ss.sssZ". Live value has four fractional digits (`2026-10-14T19:27:28.0105Z`), so the schema text and the data disagree on precision. **verified**.
- Live catalog today (`develop`, JSON, accessed 2026-10-15): `catalogVersion` **2026.10.14**, `dateReleased` **2026-10-14T19:27:28.0105Z**, `count` **1745**. First entry `CVE-2026-105134`, `dateAdded` 2026-10-14, `dueDate` 2026-10-17. **verified**.
- Mirror CSV header (accessed 2026-10-15), **verified**: `cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,forensicTriage,notes,cwes`. CSV first data row is the same CVE as the JSON first entry (dateAdded 2026-10-14). The CSV carries no catalog metadata.
- Licence, README (`develop`), accessed 2026-10-15, **verified** wording "licensed under the CC0 license, which allows for universal public domain use of the information here". The plan's longer verbatim CC0 text (from `main`) is consistent; not re-quoted.
- `knownRansomwareCampaignUse`: "'Known' if ... leveraged as part of a ransomware campaign"; "'Unknown' if CISA lacks confirmation". **verified** (schema, `develop`).
- `forensicTriage`: "'Yes' if this vulnerability requires forensic triage per BOD 26-04"; "'No' if ... not required per BOD 26-04". **verified** (schema, `develop`).
- `cveID` pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`; `cwes` items pattern `^CWE-([0-9])+$`. **verified** (schema, `develop`).

**FIRST EPSS**
- Official core CSV fields as shown by a mirror of FIRST's data page: `cve`, `epss` (0 to 1, 30-day probability), `percentile`. Source: `https://https-www_first_org.proxy.bugsmash.io/epss/data_stats` (mirror, accessed 2026-10-15), **secondary**; first.org itself [U].
- Daily refresh: "Scores are refreshed daily" (search summary of third-party pages, accessed 2026-10-15), **secondary**.
- Daily file URL pattern `https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz` and current file `https://epss.cyentia.com/epss_scores-current.csv.gz` (both from third-party pages, accessed 2026-10-15). The host has apparently changed over time: **[U]**.
- API endpoint `https://api.first.org/data/v1/epss` with a `date` parameter and `scope=time-series` for history (third-party, accessed 2026-10-15): **secondary**, [U] for the official parameter list.
- Usage terms: ScanCode license database lists a custom "FIRST EPSS Usage Agreement" (SPDX-style id `LicenseRef-scancode-first-epss-usage`, owner FIRST), accessed 2026-10-15: `https://scancode-licensedb.aboutcode.org/first-epss-usage.html`, **secondary**. Per that agreement mirror: scores are free to the public; attribution is "requested rather than mandated"; FIRST may update the model and pages, with notice for material changes. Not a Creative Commons licence (no CC link found for EPSS). Live agreement at `https://www.first.org/epss/#Usage-Agreement`: **[U]**.

**NVD API 2.0**
- Rate limits, from third-party pages quoting NVD (accessed 2026-10-15): 5 requests per rolling 30 s without a key; 50 per rolling 30 s with a free key. Sources: `https://nvd.nist.gov/General/News/changes-to-feeds-and-apis` (search snippet only; fetch failed), `https://nvd.nist.gov/developers/terms-of-use` (snippet). **secondary**; NVD page not read directly, so [U] for exact numbers. One mirror gives a rolling 60 s window instead of 30 s: **conflict, [U]**.
- NIST product-API page (search snippet, accessed 2026-10-15): "requesting an API key significantly raises the number of requests"; sleep "several seconds between requests" recommended; `startIndex` used for paging when `totalResults` exceeds `resultsPerPage`. **secondary**.
- Date-range filters: maximum window 120 consecutive days (third-party wrapper type definitions). `resultsPerPage` default and maximum 2000 (wrapper types; the NVD page snippet also states a 2,000 default and maximum). **secondary**.
- Terms (snippet): without a key, queries up to the public limits posted on the developers page; a key is sent as a request parameter and must not be shared with others. **secondary**.

## Schemas (field lists)

**KEV JSON (verified, `develop`)**
- Top level: `catalogVersion`, `dateReleased`, `count`, `vulnerabilities` (all required).
- Entry: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded` (date), `shortDescription`, `requiredAction`, `dueDate` (date), `knownRansomwareCampaignUse`, `forensicTriage`, `notes`, `cwes` (array).
- The entry-level `required` list was not read this session; the earlier plan's claim (8 original fields required) is carried as [U] here.
- The `title` field seen in the live JSON is not in the schema (carried from the plan; not re-checked).

**KEV CSV (verified header)**: the 12 columns above, same names, `cwes` comma-joined.

**EPSS CSV (secondary)**: `cve`, `epss`, `percentile`. Whether the official file carries a model-version/score-date comment line or a date column: [U]. Do not parse on this assumption.

**NVD CVE 2.0 response** (fields the plan uses): `id` (CVE id), `sourceIdentifier`, `weaknesses` (CWE), `configurations` (CPE match nodes), `references` (URLs, with `tags` such as `Exploit`), `metrics`, `cisaExploitAdd` / `cisaActionDue` / `cisaRequiredAction` / `cisaVulnerabilityName`. Only the wrapper-level mention of `cpeMatches` and `weaknesses` was seen; the exact names are **[U]** until the NVD schema is read. `cisaExploitAdd` was not found in any result.

## Rate limits and terms

| Source | Limit / cadence | Terms | Confidence |
|---|---|---|---|
| KEV (GitHub mirror) | No rate limit stated; updated shortly after cisa.gov | CC0 | verified (mirror) |
| KEV (cisa.gov) | [U] | CC0 per mirror; cisa.gov copy [U] | [U] |
| EPSS (FIRST) | Daily refresh | FIRST EPSS Usage Agreement; attribution requested, not mandated | secondary |
| NVD API 2.0 | 5 / rolling 30 s without key; 50 / rolling 30 s with key (60 s window in one mirror) | Key not to be shared; public limits without key | secondary; conflict on window |

Corporate proxy: the project ignores environment proxies (see plan F25). Any fetch that the sandbox cannot resolve is an egress gate, not a data fact.

## Gotchas

1. **The KEV catalog moves daily.** The plan's 1,741 entries and version 2026.10.13 are stale: today's catalog is 2026.10.14 with 1,745 entries. Any golden test or fixture must pin a version and SHA, never the "current" count.
2. **Precision mismatch on `dateReleased`.** Schema text says `.sss` (milliseconds); the live value has four fractional digits. Parse with a tolerant ISO-8601 reader and do not reject extra digits.
3. **Two directive names.** `forensicTriage` text cites BOD 26-04 (schema, verified). The plan's note that CONTRIBUTING cites BOD 22-01 is carried as [U] here.
4. **Cadence wording differs between `main` and `develop` READMEs** (or between plan and mirror). Re-read `main` before quoting cadence in the spec.
5. **EPSS is not CC-licensed.** Do not describe it as CC or "free use" without the attribution text; quote the agreement and link to it.
6. **NVD window and limit are not confirmed on NVD's own page.** Any retry or backoff constant must be a config value with a default at the stricter number (5 per 30 s), until the official page is read from a reachable host.
7. **NVD key handling.** The key is a request parameter. It must not be written into cache files, logs, snapshot metadata or error messages.
8. **Cached NVD bodies may be redistributed?** Unknown ([U]). Treat cached NVD JSON as local-only, per consent, and do not republish it.
9. **Whole-catalog GET is not per-CVE.** KEV needs one request; NVD needs paging with `startIndex` and a 120-day window, so incremental runs must be date-bounded.

## Corrections to our plan

- **F1 (KEV version, count, SHA):** superseded. Live `develop` on 2026-10-15: `catalogVersion` 2026.10.14, `dateReleased` 2026-10-14T19:27:28.0105Z, `count` 1745. The earlier SHA-256 is for 2026.10.13 and must not be reused.
- **F7 (cadence):** the plan's "weekdays during US Eastern business hours" quote is not in the `develop` README today. Replace with the verified wording and re-check `main`.
- **F11 (feed URLs):** the `develop` README names only the repo files and the cisa.gov catalog page; it does not state the `/sites/default/files/feeds/...` paths. Those paths remain [U]. The K6 live probe gate in the plan still applies.
- **F19 (EPSS, NVD `cisa*` fields):** the plan calls EPSS "free use with attribution". The licence is a custom usage agreement with attribution requested, not mandated. The NVD `cisa*` field names were not confirmed; the plan's claim stays [U].
- **Rate limits:** the plan has none. Add the NVD figures above as [U] pending the official page; use 5 / 30 s as the default.
- **EPSS deferral:** no change. Nothing found here argues for building EPSS now.

## Open questions

1. Can a reachable host confirm the NVD rate-limit window (30 s vs 60 s) and the key terms? Needs `nvd.nist.gov` or a reachable NVD mirror.
2. Official EPSS CSV header and API parameters: needs `first.org` or `api.first.org`.
3. Is the KEV entry-level `required` list still 8 fields? Read the schema `items.required` in full.
4. Does the `main` README still carry the older cadence wording?
5. Do cisa.gov feed paths (JSON, CSV, schema) resolve and match the mirror? (K6 probe.)
6. May cached NVD bodies be stored and reshared inside PatchTrace snapshots under NVD terms? [U].
7. Is consent per fetch (as the plan proposes) enough for EPSS and NVD, given their key and agreement terms? Owner decision.
