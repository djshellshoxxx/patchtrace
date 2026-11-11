# KB <-> CVE correlator: Microsoft security-update data sources (delta to KB2-source-facts.md)

Research date: 2026-10-15 (all "accessed" dates below). Base read: `docs/specs/program-e/KB-integration-plan.md` and `docs/specs/program-e/KB2-source-facts.md` (2026-10-14 ledger). Only new facts or corrections are recorded here.

**Access limit for this session.** The agent proxy denied CONNECT to `msrc.microsoft.com`, `api.msrc.microsoft.com`, `learn.microsoft.com` and `www.microsoft.com` (HTTP 403; proxy log `connect_rejected` for `msrc.microsoft.com:443` at 2026-10-15T03:14:47Z). WebFetch could not resolve those hosts or `powershellgallery.com` or `docs.brinqa.com`. No bypass was attempted. Primary Microsoft endpoints (CVRF, CSAF, ETag, rate limits, terms) were therefore not re-observed today. Everything tagged "excerpt" comes from search-index snippets and was not fetched.

Source keys:
- S1 https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/MsrcSecurityUpdates/MsrcSecurityUpdates.psd1 (accessed 2026-10-15; sha256 prefix 600aa08d47bf, matches KB2 2.0)
- S2 https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/MsrcSecurityUpdates/Public/Set-MSRCApiKey.ps1 (accessed 2026-10-15; prefix 712c122f42bd, matches KB2 2.0)
- S3 https://raw.githubusercontent.com/microsoft/MSRC-Microsoft-Security-Updates-API/main/src/README.md (accessed 2026-10-15; prefix bc6427fbd6dd, matches KB2 2.0)
- S4 https://msrc.microsoft.com/csaf/vex/2025/msrc_cve-2022-49124.json (search-index URL and excerpt only, not fetched; accessed 2026-10-15) [excerpt]
- S5 https://docs.brinqa.com/docs/connectors/microsoft-security-response-center (search excerpt; fetch failed, accessed 2026-10-15) [excerpt]
- S6 https://www.powershellgallery.com/packages/MsrcSecurityUpdates/1.9.6 (search excerpt; fetch failed, accessed 2026-10-15) [excerpt]
- S7 https://learn.microsoft.com/en-us/answers/questions/373685/regarding-the-microsoft-security-update-supersedence-and-cpe-correspondence-issues (2021 Q&A, search excerpt, accessed 2026-10-15) [excerpt]
- S8 https://learn.microsoft.com/en-us/windows/deployment/update/catalog-checkpoint-cumulative-updates (search excerpt; fetch denied, accessed 2026-10-15) [excerpt]
- S9 https://windowslatest.com/2024/09/12/windows-11-24h2-updates-might-fail-due-to-operation-is-not-supported-after-kb5043080/amp/ (search excerpt, accessed 2026-10-15) [excerpt]
- S10 https://www.elevenforum.com/t/more-info-on-the-new-checkpoint-incremental-updates-scheme.29386/ (forum post, search excerpt, accessed 2026-10-15) [excerpt]
- S11 https://www.microsoft.com/en-us/legal/terms-of-use (curl returned 403, accessed 2026-10-15; not re-read)

## Verified facts

- The repo's GitHub copy of the first-party module (S1) is version 1.9.9. Its release notes end at "November 26, 2024 - Small fix to Customer Action Required field". Dated entries in the notes that matter here: "April 7, 2021 - Adding FixedBuild to vulnerability report", "April 20, 2021 - Update API endpoint", "February 3, 2021 - Removed Api-key requirement", "April 16, 2024 - Adding CWE info". (S1, accessed 2026-10-15) [high]
- S1 contains no entry mentioning MSAL, a CVRF 3.0 switch in 2024, or a 2026 change. (S1, accessed 2026-10-15) [high]
- `Set-MSRCApiKey` (S2) sets the base URL to `https://api.msrc.microsoft.com/cvrf/v{0}`. It maps `APIVersion` '3.0' to `api-version=2023-11-01` and '2.0' to `api-version=2016-08-01`, with '3.0' as the default. It still removes a global `MSRCAdalAccessToken` variable, which is ADAL residue. It takes an optional key and a proxy. (S2, accessed 2026-10-15) [high]
- The API key is optional and stored only as a PowerShell global (`$global:MSRCApiKey`) when given. Nothing in S2 sends it as a header, and the function does not validate it. (S2, accessed 2026-10-15) [high]
- The Microsoft Q&A thread (S7, 2021, excerpt) says the monthly JSON "contains each CVE and remediation patch KBID, and the supercedence KBID". This supports the KB2 claim that `Supercedence` is a KB list in the CVRF document. [excerpt] (S7, accessed 2026-10-15) [medium]
- A Brinqa connector page (S5, excerpt) names `https://api.msrc.microsoft.com` as base and states "the default API version is 2024". This conflicts with the module default `2023-11-01`. (S5, accessed 2026-10-15) [excerpt] [U]
- A CSAF VEX document URL in the search index is `https://msrc.microsoft.com/csaf/vex/2025/msrc_cve-2022-49124.json` (S4). Its remediation objects have `category` (value `none_available`), `date` as an ISO timestamp with milliseconds (for example "2025-10-17T01:01:16.000Z"), `details` and `product_ids`. (S4, accessed 2026-10-15) [excerpt]
- Checkpoint cumulative updates: the first checkpoint update was KB5043080 (September 2024). Windows Update and WSUS apply prerequisites automatically. (S9, S8 excerpt, accessed 2026-10-15) [excerpt]
- Forum guidance (S10) says that in a checkpoint month one installs only the checkpoint KB, and in a differential month one installs two KBs in order. This is secondary and not an official statement. (S10, accessed 2026-10-15) [excerpt] [U]

## Corrections to KB2-source-facts.md

- KB2 2.C said the concrete CSAF name `2024/msrc_cve-2024-38063.json` was a recollection. The search index now shows the `csaf/vex/<year>/msrc_cve-<id>.json` pattern for VEX documents (S4). This is a partial confirmation of the rule and says nothing about the advisory profile path. [excerpt] (S4, accessed 2026-10-15) [medium]
- KB2 2.A marked the Auth row as "treat as unauthenticated" with a module note "Removed Api-key requirement". The S1 note is dated February 3, 2021, which matches KB2. Keep the auth conclusion, and add that the GitHub copy still contains ADAL residue (S2). A 2026-01-28 "modern MSAL authentication" entry seen in a PowerShell Gallery excerpt (S6) is not in the GitHub copy of the manifest, so it is recorded as an open question, not a correction. (S1, S2, S6, accessed 2026-10-15) [high for S1 and S2; S6 excerpt]
- KB2 2.A said the client defaults are `api-version=2023-11-01`. This holds for the GitHub copy (S2). A third-party connector excerpt quotes a 2024 default (S5). KB2 does not need a change, but the default should be treated as possibly stale. (S2, S5, accessed 2026-10-15) [high for S2; S5 excerpt]
- KB2 2.J said the Microsoft Terms of Use page was retrieved on 2026-10-14. This could not be re-read today (S11 returned 403), so the KB2 2.J quotes are not re-verified in this session. No change to the quoted text. (S11, accessed 2026-10-15) [unverified today]

## Gotchas

- Access: the blocked Microsoft hosts (listed above) mean that no run from this session can settle the CVRF index shape, ETag, rate limits, or CSAF layout. Those must be probed from an environment with egress, and the probe must record bytes, sha256 and date. (proxy status, accessed 2026-10-15) [high]
- Two KB rows per product per CVE can occur in the same month, for example "Security Update" and "Security Hotpatch Update" for one product in the 2026-08 document (KB2 2.A excerpt). A resolver must not pair across these classes by default. [excerpt] (KB2 2.A) [unverified]
- Older months have `SubType` absent, and older excerpts show "Monthly Rollup" and "Security Only" (KB2 2.A excerpt). These cannot be used to classify the row without a fallback. [excerpt]
- `Supercedence` is a list of bare KB digits attached to the product (S7 excerpt, KB2 2.A). Do not treat it as a single supersedence edge for the CVE.
- Checkpoint prerequisites form a DAG (S8 excerpt). A KB-first lookup that returns one row can miss the prerequisite checkpoint that must install first. Model the prerequisite chain separately. [excerpt]
- The CSAF schema has no KB, fixed-build or supersedence field (KB2 2.C, OASIS schema). Any KB reference in CSAF must sit in free text such as `details` or `url`, and that is not yet observed. [U]

## Open questions

1. Shape of the `/updates` response: bare array or OData `value` wrapper, and paging (`@odata.nextLink`). Probe P1, from egress.
2. Current default `api-version` (2023-11-01 in the module versus 2024 in the Brinqa excerpt) and whether a newer version exists. (S2 vs S5) [U]
3. Whether a 2026 MSAL change exists in the module (S6 excerpt versus S1 has no such entry). Changes the auth gate. (S1, S6) [U]
4. CSAF advisory profile path (not VEX) and content of `https://msrc.microsoft.com/csaf/provider-metadata.json`. (KB2 2.C) [U]
5. ETag, `Last-Modified` and `If-Modified-Since` behaviour on CVRF documents and CSAF files; `Retry-After` headers; numeric rate limit. No source reachable. [U]
6. Terms of use for API output and redistribution of CVRF/CSAF data. The Microsoft Terms of Use text is from KB2 2.J (2026-10-14); API-specific terms unread. (S11) [U]
7. Whether checkpoint prerequisite lists are available in a machine-readable form (S8 excerpt says the Catalog KB page lists them). [U]
