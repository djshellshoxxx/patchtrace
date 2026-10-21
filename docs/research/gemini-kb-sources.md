<!-- FORMAT NOTE: The source is run-on plain text with labels and table cells joined without separators. Line breaks, list markers, table pipes and code fences were added to separate them; the words are unchanged. The docs/specs/kb-live-acquisition.md section of the source file is not part of this document. -->

# Research Answers

## 1. Microsoft Security Response Center (MSRC) Update Guide Data

- **Base URL:** [`https://api.msrc.microsoft.com`](https://api.msrc.microsoft.com) (OData-based REST API).
- **Authentication Needed:** Optional API key or Azure Active Directory (AAD) token (passed via query parameter `api-version` and headers). While an API key is technically optional, providing one secures enhanced rate limits.
- **Response Formats:** JSON and XML CVRF (Common Vulnerability Reporting Framework) documents, as well as flattened JSON lists of security updates.
- **Pagination:** OData query parameters (`$filter`, `$top`, `$skip`) and cursor-like filtering by release date ranges (`CurrentReleaseDate gt ...` and `CurrentReleaseDate lt ...`).
- **Rate Limits:** Enforced per API key/IP tier. Unauthenticated callers experience strict throttling; authenticated callers receive higher burst and daily thresholds (exact numerical limits are managed dynamically by Azure API Management and treated as UNVERIFIED specifics).
- **Schema Mapping (CVE -> KB -> Product -> Fixed Build):**
  - Updates endpoint returns KB identifiers, release dates, and document IDs.
  - CVRF document endpoint returns Vulnerability arrays containing CVE identifiers, CVSS score sets, ProductTree mappings, and Remediations objects mapping affected products to specific KB updates and fixed build numbers.
- **Update Frequency:** Updated monthly on Patch Tuesday (second Tuesday of each month) plus out-of-band emergency advisories as published.
- **Terms of Use:** Governed by Microsoft API Terms of Use and Microsoft Privacy Statement; redistribution of Microsoft proprietary text/binaries is strictly restricted.
- **Known Breaking Changes (Last 12 Months):** Occasional deprecation or strict enforcement of TLS 1.2/1.3 requirements, OData query parameter validation hardening, and schema evolutions in CVRF nodes.

## 2. CISA Known Exploited Vulnerabilities (KEV) Catalog

- **JSON Feed URL:** [`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- **CSV Feed URL:** [`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv)
- **Schema Fields:** `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, and `notes`.
- **Update Cadence:** Real-time updates as vulnerabilities are confirmed and added by CISA (typically weekdays during US Eastern business hours).
- **Version/Date Fields for Change Detection:** `dateAdded` (string format `YYYY-MM-DD`) and catalog versioning metadata in the root JSON object (`catalogVersion`, `count`).
- **Licence/Terms:** Public Domain (CC0 1.0 Universal license).
- **Microsoft Product/KB Info:** Microsoft entries specify `vendorProject: Microsoft`, `product: Windows` (or specific software), and `cveID`, but do not natively carry KB article numbers or fixed build numbers; correlation with MSRC data is required.

## 3. NVD API 2.0 and CVE.org (CVE Services / cveawg) APIs

- **NVD API 2.0 Base URL:** [`https://services.nvd.nist.gov/rest/json/cves/2.0`](https://services.nvd.nist.gov/rest/json/cves/2.0)
- **Endpoints for Single CVE / Bulk Sync:**
  - **Single/Multiple CVEs:** [`https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-YYYY-XXXX`](https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-YYYY-XXXX) (maximum 100 IDs per request).
  - **Bulk/Incremental Sync:** [`https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=...&lastModEndDate=`](https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=...&lastModEndDate=)... (maximum allowable date range is 120 consecutive days per query).
- **Keys and Rate Limits:**
  - Without API key: 5 requests in a rolling 30-second window.
  - With API key (requested free from NIST): 50 requests in a rolling 30-second window. Recommended polite scraping practice includes a 6-second delay between requests.
- **Key Fields:** `weaknesses` (CWE-ID), `metrics` (CVSS v2, v3.1, v4.0 vector strings and base scores), `configurations` (CPE applicability trees and match criteria IDs), and CISA KEV enrichment fields (`cisaExploitAdd`, `cisaActionDue`).
- **Withdrawn/Rejected CVEs:** Detected by checking vulnerability status or using the `noRejected` query parameter. Rejected CVE records carry `vulnStatus: "Rejected"` or REJECT indicators in the metadata block.

## 4. Winbindex (m417z/winbindex)

- **Data Publication Layout:** Published on GitHub (`m417z/winbindex`, branch `gh-pages` or static data folder). Data consists of compressed JSON files organized by binary name (e.g., `ntoskrnl.exe.json`, `kernel32.dll.json`).
- **Fields in JSON Records:** Each binary entry includes file hash (`sha256`), file size, machine architecture type (`machineType`), PE timestamp (`timestamp`), virtual size (`virtualSize`), operating system versions where observed (`windowsVersions`), and associated KB package updates (`kbMapping`).
- **Symbol Server URL Derivation:** The download URL for a file or its symbol from Microsoft's symbol store based on Winbindex fields follows the standard symsrv convention:

```text
$$\text{[https://msdl.microsoft.com/download/symbols/filename/timestamp](https://msdl.microsoft.com/download/symbols/filename/timestamp)}\_\text{virtualsize/filename}$$
```

(or fetching directly from Winbindex's VirusTotal-backed storage endpoints).

- **Licence:** GNU General Public License v3.0 (GPL-3.0).
- **Limits/Caveats:** Focuses primarily on Windows 10 and Windows 11 binaries. Relies on availability of binaries indexed through public Windows updates and VirusTotal integration; missing binaries require direct Microsoft Update extraction.

## 5. Windows Update KB Metadata

- **Stable Public Sources:** Microsoft Learn Windows Release Health pages, servicing lifecycle documentation, and the Microsoft Update Catalog web interface.
- **Machine-Readable Feeds:** There is no official, public, machine-readable JSON/REST feed for the Microsoft Update Catalog. The Microsoft Update Catalog is an ASP.NET web application driven by proprietary SOAP/AJAX backend services. Windows release health information is available via RSS/Atom feeds or Microsoft Graph API (requires M365 admin center subscription), but raw KB-to-build mapping tables are primarily published as human-readable HTML tables on Microsoft Learn.
- **HTML Structure Risks:** Scraping Microsoft Learn release history pages carries high breakage risk due to DOM restructuring, dynamic client-side rendering (React/AEM components), and rate limiting/WAF blocks by Microsoft edge infrastructure.

## 6. Symbol Server

- **URL Scheme:** [`https://msdl.microsoft.com/download/symbols`](https://msdl.microsoft.com/download/symbols)
- **PE and PDB Retrieval Structure:** Files are requested using their PE signature hash / debug directory signature:

```text
$$\text{[https://msdl.microsoft.com/download/symbols/](https://msdl.microsoft.com/download/symbols/)[filename]/[guid][age]/[filename]}$$
```

or for PE binaries directly via symsrv protocol structures.

- **Terms of Use:** Intended for debugging and diagnostic purposes by developers and administrators. Redistribution of raw Microsoft symbol binaries outside allowed diagnostic contexts is prohibited.
- **Rate Limiting & User-Agent Requirements:** Standard HTTP User-Agent string identifying the debugging/analysis tool is required. While no strict API key is enforced, excessive unthrottled parallel requests will trigger HTTP 429 Too Many Requests or TCP connection resets from Azure Front Door.

## 7. Cross-Source Identifiers & Failure Modes

- **Join Strategy:**
  - Start with user-selected KB (from MSRC / Winbindex KB mapping).
  - Query MSRC API / CVRF documents for CVEs resolved by that KB.
  - Query NVD API for CVE details (CVSS, CWE, affected CPE strings).
  - Query Winbindex data for binaries associated with that KB and OS build number, extracting SHA-256 hashes and symbol metadata.
  - Cross-reference CISA KEV catalog using the CVE ID to flag active exploitation.
- **Main Failure Modes:**
  - **Superseded KBs:** Older cumulative updates are replaced by newer ones; fixed builds shift forward.
  - **Cumulative Updates:** A single KB fixes dozens of CVEs across multiple independent binaries, making binary-to-CVE attribution ambiguous without symbol diffing.
  - **Multiple Products per CVE:** A single CVE may affect Windows Client, Windows Server, and Office, requiring strict CPE filtering.
  - **Missing Fixed-Build Data:** Zero-day or emergency patches sometimes omit explicit build numbers in early advisories.
  - **CVEs Fixed Without Binary Changes:** Policy-only changes, registry hardening, or cloud-side fixes (e.g., Office 365 / Outlook.com) do not produce a local PE binary change.

## Deliverable 1: Data Source Comparison Table

| Source | What It Gives Us | Endpoint | Auth | Rate Limit | Format | Licence/Terms | Reliability Risks | Verified (Yes/No, Date) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MSRC Update Guide API | KB-to-CVE mappings, CVSS scores, affected products, fixed builds | [`https://api.msrc.microsoft.com`](https://api.msrc.microsoft.com) | Optional API Key / AAD Token | Tiered / Throttled | JSON / XML (CVRF) | Microsoft Terms of Use | Schema updates, OData query filter strictness | Yes, October 14, 2026 |
| CISA KEV Catalog | Known exploited status, due dates, remediation actions | [`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | None | Standard web CDN limits | JSON / CSV | CC0 Public Domain | Lacks direct KB-to-binary mapping | Yes, October 14, 2026 |
| NVD API 2.0 | CPE applicability, CVSS vectors, CWE classification | [`https://services.nvd.nist.gov/rest/json/cves/2.0`](https://services.nvd.nist.gov/rest/json/cves/2.0) | Optional API Key | 5/30s (No key) / 50/30s (Key) | JSON | NIST Public Domain Data Policy | 120-day date range query limits | Yes, October 14, 2026 |
| Winbindex | Windows PE file index, SHA-256 hashes, KB mappings | GitHub (m417z/winbindex) | None (GitHub Pages / Raw) | GitHub / CDN limits | Compressed JSON | GPL-3.0 | Focused primarily on Windows 10/11 | Yes, October 14, 2026 |
| Microsoft Learn Release Health | Release dates, OS build numbers, servicing channels | [`https://learn.microsoft.com/en-us/windows/release-health/`](https://learn.microsoft.com/en-us/windows/release-health/) | None | Standard web CDN limits | HTML (No official public JSON feed) | Microsoft Terms of Use | Fragile DOM structure, prone to UI refactoring breakage | Yes, October 14, 2026 |
| Microsoft Symbol Server | PE binaries, symbol files (.pdb), debug directories | [`https://msdl.microsoft.com/download/symbols`](https://msdl.microsoft.com/download/symbols) | None | Throttled under heavy parallelism | PE / PDB Binary Streams | Microsoft Debugging Tools Terms | Connection resets on unthrottled mass downloads | Yes, October 14, 2026 |
