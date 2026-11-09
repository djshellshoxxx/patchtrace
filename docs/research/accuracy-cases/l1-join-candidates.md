# L1 KB/CVE join candidates (rq-l1-manifest/1)

Candidate corpus for AV-5, the automated KB/CVE join run. Each case says: for this CVE, KB and product, the join
should land on these binary file names. Nothing here has been run through PatchTrace's join. The manifest is a
candidate list, not yet frozen. Freeze it (record `manifest_sha256` from `l1_check`) before any engine run.

Files: `l1-join-candidates.json` (data), `tools/research_qualification/l1_check.py` (validator),
`tests/test_research_qualification_l1.py` (tests). This is a new schema; `cases.py` is untouched.

## Schema

Top level: `{"schema": "rq-l1-manifest/1", "generated": "2026-11-07", "cases": [...]}`. Cases are sorted by `id`.

| field | meaning |
| --- | --- |
| `id` | unique, `l1-YYYY-MM-cve-...-kb...` (or `...-nokb`) |
| `month` | MSRC CVRF month id, e.g. `2024-Aug` (same form the live probe uses) |
| `cve` | CVE id |
| `kb` | `KB` + digits as MSRC lists it for this CVE, or `""` for stratum `no-kb` |
| `product` | one product string exactly as MSRC writes it (a deterministic representative: first x64 non-server name, sorted) |
| `products_for_kb` | optional, every MSRC product string that shares this CVE+KB; `product` is a member |
| `expected_files` | sorted bare binary names the patch changes, only if a page I read states it; `[]` otherwise |
| `oracle_urls` | https pages and data files actually read for this case |
| `stratum` | see below |
| `facts` | `verified` or `unverified` |
| `notes` | what each source said, the Winbindex old to new version pair, supersedence, disagreements |

`verified` means: CVE to KB to product was read in MSRC, the file name was read on a page that states it, Winbindex
lists that file under that KB, and the KB's support article was read and carries the KB id. Anything short of that
is `unverified`, and the notes say which leg is missing. `expected_files: []` on an `unverified` case means no read
page states the file, not that the file set is empty.

## Counts (87 cases: 79 verified, 8 unverified)

| stratum | n | what it tests |
| --- | --- | --- |
| baseline-driver | 28 | one CVE, one KB family, a `.sys` file |
| baseline-usermode | 29 | same, for `.dll`/`.exe`/`.drv` |
| shared-file-kb | 6 | several CVEs fix the same file in the same KB (join must not fan out or collapse wrongly) |
| multi-product-kb | 7 | one CVE, different KBs per product (CVE-2022-41073 x1, CVE-2023-36802 x3, CVE-2024-38063 x3) |
| supersedence | 1 | CVE-2022-41073 / KB5019959; MSRC says it supersedes KB5018410, which is itself a case (CVE-2022-41033) |
| rollup-vs-security-only | 2 | Windows 7 KB5020000 (Monthly Rollup) vs KB5020013 (Security-only), same product strings |
| no-kb | 3 | MSRC lists no KB (Azure Linux / Mariner CVEs); expected: no pair |
| non-windows-kb | 6 | real KB but Exchange, SharePoint, Excel, SQL Server, Outlook, .NET 8; expected: no Windows pair |
| oracle-disagreement | 3 | Starlabs and MSRC name different KBs for the CVE; unverified |
| file-unstated | 2 | KB and product known, no page I read states the file; unverified |

Spread: 2022 24, 2023 14, 2024 18, 2025 31 cases across 37 distinct months; 47 distinct file names. 2025 is
over-represented because the file oracle (below) covers it best. Components range from CLFS, AFD-adjacent and
Kernel Streaming drivers to telephony, DWM, print and error-reporting services.

## How the oracle was used

The shell reached MSRC, Winbindex and the oracle sites directly, so the data was downloaded and read, not recalled.

1. CVE to KB and product: MSRC CVRF v3.0 (`/cvrf/v3.0/cvrf/<month>`), the same source the join consumes. I parsed it
   with a throwaway script, not PatchTrace code, so the join logic is independent but the upstream data is not.
   Remediation rows of type 2 with a numeric Description give the KB; their ProductID list gives the product names.
2. File name: a statement on a page, never inferred from the CVE title. Sources used:
   - Starlabs OnlyPatch (`onlyfm252.starlabs.sg/patch-tuesday/<YYYY-MM>/<cve>/`), "Patch Diff" section headed
     `ghidriff · <file> (KB...)`. 69 cases cite a Starlabs page (65 of them verified). Third-party, partly machine-written; it is the weakest leg, so it is
     always cross-checked below. It names one KB per CVE, not all of them.
   - Google Project Zero 0-day RCAs (human written): CVE-2022-24521 clfs.sys, CVE-2022-41033 es.dll,
     CVE-2023-28252 clfs.sys, CVE-2023-36033 dwmcore.dll, CVE-2023-36802 mskssrv.sys, and CVE-2022-41073, where the
     page says the patched file was winspool.drv.
   - bi.zone write-up for CVE-2024-38063 (tcpip.sys).
3. File in KB: Winbindex per-file data (`data/by_filename_compressed/<file>.json.gz`). It is built from Microsoft
   packages, so it is independent of both MSRC and Starlabs. Every verified case has the file listed under its KB.
   The notes carry the Winbindex x64 version pair (previous release in the same Windows version column to the KB's
   version), which is the old/new pair the join should hand to a diff.
4. KB exists and is what it should be: `support.microsoft.com/help/<n>` title read for each KB (build number matches
   Winbindex). Non-Windows KBs were confirmed the same way (e.g. KB5019758 is an Exchange update).
5. no-kb cases: MSRC record plus the NVD 2.0 API record for the CVE.

## What could not be read or used

- `github.com`, `cisa.gov` KEV and `exploit-db.com` returned 403/502 from the shell. The WebFetch tool refused MSRC and
  Winbindex hosts (not allowlisted); the shell was used instead.
- Windows 7 / Server 2008 R2 KBs: Winbindex has no winspool.drv entry, so the Rollup vs Security-only pair has no
  file oracle.
- The Update Catalog search page loads and lists package titles per KB, but I did not find per-binary file lists
  there, so it is not cited as an oracle URL.
- MSRC `AffectedFiles` is empty in the CVRF, and MSRC pages do not name binaries. Files cannot come from MSRC.
- Two Starlabs groups conflict with MSRC: CVE-2025-49677 (Starlabs KB5062553, MSRC only KB5062552) and the December
  2025 storvsp.sys CVEs (Starlabs KB5068861, MSRC later KBs). They are kept as `oracle-disagreement`, unverified.
- CVE-2022-21882 and CVE-2024-38193 have no page I read that names the patched file; left empty on purpose.
- Starlabs only diffs a subset of CVEs, so the corpus skews toward exploited or kernel-adjacent bugs and toward 2025.

## Proposed scoring rule

For each case the engine gets `(cve, month)` and, if the join needs it, the product. A case is **join correct** iff
the predicted `(product, file set)` equals the expected one:

- `product` correct when the predicted MSRC product string is a member of `products_for_kb` (the KB's product set),
  compared case-sensitively as MSRC writes it. Predicting a KB that does not match the expected `kb` for that product
  is wrong even if the file set is right.
- file set correct iff the predicted set of bare file names, lowercased, equals `expected_files` lowercased. Extra
  files and missing files both fail; no partial credit.
- negative strata (`no-kb`, `non-windows-kb`): correct iff the engine returns no Windows pair and says why.
- `rollup-vs-security-only`: correct iff both KBs are returned and kept separate.
- `file-unstated` and `oracle-disagreement` are reported but excluded from the bound until a human or a diff settles
  the expected files. `unverified` cases never enter a headline accuracy claim.
- Report per stratum and overall as "at least X% (95% one-sided), n cases, k errors" per the AV plan. Cases that share
  a CVE or a (KB, file) are not independent; count independent units, not rows.
