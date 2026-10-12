# CVE intelligence fixtures

These are **real public provider responses, trimmed** (not synthetic). Retrieved 2026-10-12
without credentials. Nothing about any binary is contained in them.

| File | Source request | Trimming |
|---|---|---|
| `nvd_CVE-2024-38063.json` | `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38063` | `affected[0].affectedData` cut to 2 entries; `configurations` cut to first node set, 2 `cpeMatch` entries each |
| `msrc_CVE-2024-38063.json` | `GET https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2024-38063` | `articles` emptied (HTML mitigation text); `revisions` cut to 1 |

Tests derive **synthetic** variants (wrong ID, conflicting CWE/CVSS, malformed bytes) from
these in code; each such test names itself synthetic. Live probe observations from the same
date: unknown CVE → NVD 200 with `totalResults: 0`; MSRC 404. The MSRC CVRF
`/cvrf/v3.0/updates/{CVE}` endpoint only maps a CVE to a monthly document (multi-MB), so it is
not used.
