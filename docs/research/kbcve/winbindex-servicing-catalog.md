# Winbindex, Windows servicing and Update Catalog: research for SPEC-31

Researcher RK2, 2026-10-14. Scope: the Windows side of `kb-cve-correlation-and-acquisition.md` (branch `docs/spec-31-kb-cve-correlation-20261014`).
Tags: **[live]** observed by me today through the sandbox proxy; **[Wn]/[Dn]/[Gn]/[Mn]/[T1]** read in the primary file listed in section 0 (line numbers from my copy); **[repo]** read in this repository; **[inf]** my inference; **[unv]** not verified (host blocked, file not found, or not tested).
Budget: about 0.62 MB downloaded of 5 MB. Nothing was pushed; no GitHub write; only public `raw.githubusercontent.com` reads.

## 0. Sources and probe log

| Id | Primary source (all `https://raw.githubusercontent.com/...`) | SHA-256 prefix / size |
|---|---|---|
| W1-W5 | `m417z/winbindex/main/data/{upd01_get_list_of_updates,upd02_get_manifests_from_updates,upd03_parse_manifests,upd05_group_by_filename,config}.py` | 7f319302, cd3bfb5d, 1d341de1, 71ce10d9, a5f25e00 |
| W6, W7 | `m417z/winbindex/main/README.md`, `.../main/LICENSE` | 7c519161 (865 B); GPL v3 text, 35,112 B |
| W8 | `m417z/winbindex/gh-pages/data/by_filename_compressed/afd.sys.json.gz` (fetched 2026-10-14T10:31Z) | 1baa04ff, 97,669 B, 292 entries |
| D1 | `MicrosoftDocs/windowsserverdocs/main/WindowsServerDocs/administration/windows-server-update-services/manage/wsus-and-the-catalog-site.md` (ms.date 07/01/2025) | 1305df41 |
| D2 | `MicrosoftDocs/windows-driver-docs/staging/windows-driver-docs-pr/debugger/microsoft-public-symbols.md` (11/05/2025) | f458a905 |
| D3, D4 | `MicrosoftDocs/win32/docs/desktop-src/{SecBP/understanding-pe-signatures,DevNotes/msdelta-applydeltab}.md` | 1609d07a, 7b8dde66 |
| G1 | `microsoftgraph/microsoft-graph-docs-contrib/main/api-reference/beta/{api/windowsupdates-product-findbykbnumber,resources/windowsupdates-productrevision,resources/windowsupdates-qualityupdatecatalogentry}.md` (01/27/2026) | ea1569f5, 5139a4fb, 1b12f383 |
| M1 | `microsoft/MSRC-Microsoft-Security-Updates-API/main/docs/swagger.json` (OpenAPI 3.0.1, "MSRC CVRF API v3") | 1632aa08, 195,539 B |
| T1 | `https://www.microsoft.com/en-us/legal/terms-of-use` | 159,102 B HTML |

**Blocked by the sandbox proxy** ("request blocked: no rule or allowlist entry allows host") [live]: `winbindex.m417z.com`, `m417z.com`, `msdl.microsoft.com`, `www.catalog.update.microsoft.com`, `learn.microsoft.com`, `support.microsoft.com`, `docs.microsoft.com`, `download.windowsupdate.com`, `catalog.s.download.windowsupdate.com`, `download.microsoft.com`, `go.microsoft.com`, `aka.ms`, `msrc.microsoft.com`, `api.msrc.microsoft.com`, `techcommunity.microsoft.com`, `devblogs.microsoft.com`, `update.microsoft.com`, `fe2.update.microsoft.com`, `web.archive.org`, `archive.org`, `cdn.jsdelivr.net`, `unpkg.com`, `gist.githubusercontent.com`. `api.github.com` and `github.com` answer 403 "GitHub access to this repository is not enabled for this session" [live]. Reachable: `raw.githubusercontent.com` (public repos), `www.microsoft.com`, `packages.microsoft.com`.
Consequence: no live probe of the Update Catalog, symbol server, release-health, support pages or Learn; every Catalog/symbol/Learn fact below is from source code or doc sources, or is **[unv]**. `MicrosoftDocs/windows-itpro-docs` returned 404 on branches public/main/live/master/docs/staging [live], so the Learn pages for release health and checkpoint cumulative updates could not be read.

## 1. Winbindex data model

### 1.1 Layout of `<name>.json.gz` (gzip, strict JSON, key = lowercase SHA-256 of the file) [W4 L299-341, L771-810; W8]

| Path | Content | Notes |
|---|---|---|
| `<sha256>.fileInfo` | merged facts about the bytes | variants in 1.2; `sha256` may be absent from `fileInfo` (the dict key is the identity) [W4 L64, L284] [live] |
| `<sha256>.windowsVersions.<ver>.<KBnnnnnnn>.updateInfo` | `heading?`, `releaseDate`, `releaseVersion`, `updateUrl`, `otherWindowsVersions?` | copied from `updates.json` [W4 L323-326]; 1114 KB bodies in afd.sys [live] |
| `...<KB>.assemblies.<manifest name>` | `assemblyIdentity{name,version,processorArchitecture,publicKeyToken,buildType,language,versionScope}`, `attributes[{name,sourceName,destinationPath,importPath,sourcePath}]` | one assembly per KB body in afd.sys; this is the only component/path evidence [live] |
| `<ver>.BASE` | `windowsVersionInfo{releaseDate,isoSha256}`, `sourcePaths[]` (path inside the ISO) | no `updateInfo`, no `assemblies` [W4 L798-810]; 19 BASE bodies in afd.sys [live] |

`<ver>` keys seen in afd.sys [live]: 1507 1511 1607 1703 1709 1803 1809 1903 1909 2004 20H2 21H1 21H2 22H2 11-21H2 11-22H2 11-23H2 11-24H2 11-25H2 11-26H1.
`updateInfo` is built from two scrapes merged with assertions: support.microsoft.com update-history navigation (headings such as `September 22, 2026—KB5124006 (OS Build 28000.3086) Preview`) and the release-health tables (date, build, KB) [W1 L67-311, L314-410]. `releaseVersion` is the **first** `OS Build` number in the heading (`\(OS Builds? ([\d\.]+)`) [W1 L223]; release-health-only rows have no `heading` (2 of 1114) [live]. Known source errors are hand-patched in code (`Likely a mistake` blocks) [W1 L156-193].
Shared KBs: a KB listed for several Windows versions is stored once, under the first sorted version, with `otherWindowsVersions`; only these pairs are allowed: 1903/1909, 2004/{20H2,21H1,21H2}, 20H2/{21H1,21H2,22H2}, 21H2/22H2, 11-22H2/11-23H2, 11-24H2/{11-25H2,11-26H2}, 11-25H2/11-26H2 [W1 L10-60]. afd.sys: 219 of 1114 KB bodies carry it (22H2 60x, 11-23H2 47x, 21H1 45x, 21H2 37x, 20H2 33x, 11-25H2 32x, 1909 24x, 11-26H2 2x) [live].
Gotcha: KB5077181 under key `11-24H2` has `releaseVersion` **26200**.7840 (heading `OS Builds 26200.7840 and 26100.7840`), i.e. the build prefix can belong to the other version; the UBR (7840) is the shared part [live] (fixture).

### 1.2 `fileInfo` variants [W4 L41-100; W3 L185-246, L268-322; W8]

| Variant | Keys | afd.sys count [live] | Direct symbol-server URL |
|---|---|---|---|
| full (PE in package, VirusTotal or ISO) | size, md5, sha1, sha256, machineType, timestamp, virtualSize, signingStatus (+version, description, signatureType, signingDate[]) | 280 | yes |
| delta+ | size, machineType, timestamp, lastSectionVirtualAddress, lastSectionPointerToRawData, virtualSize, md5 and/or sha256 | 8 | yes |
| delta | same without virtualSize | 4 (2 with sha256, **2 md5-only**) | candidate enumeration |
| raw (non-PE) | size, md5/sha1/sha256 | 0 | never |

Delta fields come from the forward differential metadata (`DeltaDownloader /g`, `.dd.txt`: Hash, HashAlgorithm, Code, TimeStamp, RiftTable, TargetSize) [W3 L185-246; W2 L309-312]. `signingStatus` from update packages is the literal `Unknown` ("Verification is too time consuming") [W3 L314]; otherwise it is VirusTotal's `verified` string, and `signatureType` `Overlay` (embedded) or `Catalog file` is VirusTotal's view [W4 L440-442]. It is **not** a trust verdict. afd.sys: 270 Signed, 10 Unknown, 12 absent [live].

### 1.3 KB to files and file to builds

| Question | Answer |
|---|---|
| KB to the files it touched | **No KB index is deployed.** Deployed data is `data/by_filename_compressed/*.json.gz` plus `data/filenames.json` (1,985,960 B) [live HEAD]; `updates.json` is 404 on gh-pages and main [live HEAD]. The only route is scanning every per-file record, or reading the KB package manifests (Tier B). Winbindex builds records from the package `.manifest` files of each (version, KB) [W2, W3, W4]. Therefore SPEC-31 needs an analyst/advisory filename first (Tier A/D/E). |
| file to builds/KBs | iterate `windowsVersions.<ver>.<KB>`; add `otherWindowsVersions` members as extra versions of the same KB; treat `BASE` as the ISO baseline (`windowsVersionInfo.releaseDate`, `isoSha256`), not as a KB. |
| one SHA per (version, KB)? | afd.sys: yes, 1133 of 1133 rows have exactly one SHA [live]. Other files may have variants [unv]. |
| spread | median 1 KB row per SHA, maximum 61 [live]: a SHA is "first seen" at its earliest indexed KB, which is only an upper bound on where it was introduced. |

### 1.4 Completeness, cadence, terms

| Topic | Fact |
|---|---|
| Versions | Windows 10 and 11 client update histories only; every Catalog title matching `server`, `Dynamic Cumulative Update` or ` UUP` is dropped [W1 L142, L306-310; W2 L80]. Windows Server only KBs are listed as unsupported (KB5070881/2/3, KB5072359) [W5 L29-38]. Server 2016/2019 share client build numbers, so they appear only through client packages [inf]. Server 2022/2025-only builds are not covered [inf from the same code]. |
| Architecture | x64 main dataset [W5 L55]. ARM64: separate repo `m417z/winbindex-data-arm64` (afd.sys.json.gz 53,011 B) [live HEAD]. Insider: separate dataset with djb2 bucket directories [unv here; prior research `docs/research/phase3/acquisition.md` s.1]. |
| Holes | Updates removed from the Catalog are skipped with a warning ("probably removed from the update catalog") [W2 L364-370]; known bad: KB5071959 missing, KB5123099 corrupt, two KBs need alternate links [W5 L29-53]. Hotpatch calendar rows are excluded [W1 L332]. |
| Cadence | No schedule is documented; README says "updated on a regular basis by Python scripts" [W6]. Observed: the file fetched 2026-10-14T10:31Z already held KBs dated 2026-10-13 (Patch Tuesday) for 1607, 1809, 21H2, 11-23H2, 11-24H2, 11-26H1 [live]; the 2026-10-12 fixture had 286 entries, now 292 [repo README + live]. Deploy amends the last commit (`deploy_amend_last_commit = True`) [W5 L24-25], so gh-pages history is not an audit trail: pin by content SHA-256. |
| Licence | GPL-3.0 for the repository (code and data) [W7 live]; README: binaries are on msdl.microsoft.com, Winbindex indexes metadata [W6]. No separate data licence found [live]. PatchTrace is MIT [repo LICENSE]; runtime fetch is fine, bundling a snapshot needs legal review [inf]. Fixtures below are small test-only excerpts with the existing README precedent. |

### 1.5 What `acquisition/winbindex.py` keeps and drops [repo] (run against W8 [live])

| Raw data | Parser result |
|---|---|
| `fileInfo.sha256`, size, machineType, timestamp, virtualSize, lastSection*, version | kept |
| `windowsVersions` keys and KB tuples | **flattened separately**: version-to-KB pairing is lost (`_kbs`) |
| `updateInfo.otherWindowsVersions`, `heading` (Preview / Out-of-band / EXPIRED / multi-build), `updateUrl` | dropped |
| `BASE` | becomes `KbRef(kb='BASE', no date)`; `windowsVersionInfo.releaseDate/isoSha256` dropped |
| `assemblies` (component identity, `destinationPath`) | dropped |
| md5, sha1, description, signingStatus, signatureType, signingDate | dropped |
| entries whose `fileInfo` lacks `sha256` | **skipped as malformed (REQUIRED includes sha256)**: 3 of 292 afd.sys entries, exactly the 2026-10-13 builds KB5126651 (1809), KB5126653 (11-23H2), KB5126657 (21H2) [live, ran `parse`]. The key is a valid SHA-256 and should be used. |

## 2. Windows servicing facts for old/new resolution

### 2.1 Build, UBR and KB mapping sources

| Source | Machine readable? | Facts |
|---|---|---|
| Microsoft Graph beta `GET /admin/windows/updates/products/FindByKbNumber(kbNumber=N)?expand=revisions($expand=catalogEntry,knowledgeBaseArticle)` | yes, **authenticated** (Bearer token, Windows updates RBAC), beta | `productRevision.osBuild{majorVersion,minorVersion,buildNumber,updateBuildRevision}`, `releaseDateTime`, `knowledgeBaseArticle{id,url}`, product values `Windows 10`/`Windows 11` only [G1]. Not usable by an anonymous desktop tool; optional enterprise adapter. |
| MSRC CVRF API v3 | yes | OpenAPI documents only `/updates` (`alias,currentReleaseDate,cvrfUrl,documentTitle,id,initialReleaseDate,severity`) and `/cvrf/{id}` [M1]. Remediation field names such as `FixedBuild`/`Supercedence` are **not in the schema** [M1]; treat as [unv] until a real CVRF document is sampled (other researcher). |
| support.microsoft.com update history, release-health tables | HTML only | Winbindex scrapes both with regexes, cross-checks them and still hand-patches errors [W1]. |
| Winbindex `updateInfo` | JSON | the same data, one row per (version, KB) with `releaseVersion` = build.UBR; best offline source, with the caveats in 1.1. |

Measured on afd.sys [live]: file-version `build.UBR` equals the KB `releaseVersion` in only **152 of 1102** rows (14%); fixture example `10.0.26100.7824` under release UBR 7840. PE `timestamp` is above 1,791,000,000 (after about 2026-10-03, i.e. a hash, not a link date) in **142 of 316** (entry x version) rows (1809: 28 of 43). File version and timestamp must never order builds; use (version key, `releaseDate`, `releaseVersion`).
Heading classes among 1114 KB bodies [live]: standard 692, Preview 186, EXPIRED 142, Out-of-band 92, no heading 2. Whether Preview (non-security "D" releases) can be excluded as fix carriers needs the Learn servicing page [unv].

### 2.2 Supersedence, checkpoints, differentials

| Topic | Fact |
|---|---|
| Cumulative supersedence | Quality updates "are cumulative. Later versions always contain all previous fixes" [G1 qualityUpdateCatalogEntry]. Catalog "replaces / replaced by" fields exist on the Catalog details page [unv, host blocked]. Winbindex prefers a `Cumulative` title over a `Delta` title when both exist [W2 L86-89]. |
| Checkpoint cumulative updates (11 24H2, Server 2025) | Official Learn page `catalog-checkpoint-cumulative-updates` could not be read [unv]. Winbindex downloads one MSU per KB (URL filter `/windows[^-]*-<kb>-`) and asserts one `.psf` per update [W2 L126, L233-235]; it contains **no checkpoint chaining**, so it does not show how many predecessors an offline reconstruction needs. Keep checkpoints as analyst-supplied DAG input. |
| Package layout | MSU is a CAB (magic `MSCF`); nested `.cab`, `.psf` + `express.psf.cix.xml` (PSFExtractor), `MSWIM` WIM (7-Zip), `.esd`/`.mumx.esd` ignored; `n/` null differentials are unpacked, forward `f/` deltas are described via DeltaDownloader; manifests are DCM v1 compressed (SXSEXP) [W2 L161-317]. Winbindex does not use reverse `r/` deltas [W2, W3]. |
| Tool pitfalls | Old and new CAB layouts need different `expand.exe` versions; some 1607 packages fail with 0x80070302 [W2 L163-175]. This sandbox's `/usr/bin/expand` is the GNU tab expander, not Windows `expand.exe`; no `cabextract`/`7z` here [live]. |
| Delta apply API | `ApplyDeltaB(flags, Source, Delta, Target)`; free with `DeltaFree`; `DELTA_APPLY_FLAG_ALLOW_PA19` calls PatchAPI for legacy deltas [D4]. |

### 2.3 Choosing the previous build of a file, and where it fails

Algorithm [inf, from the data model]: for file F and target (version key V, KB K): `new` = SHA at (V,K); `old` = SHA at the latest earlier row (V,K') by `releaseDate` whose SHA differs; `intervening` = all rows between them (confounders). Fails when:

| Failure | Why |
|---|---|
| Missing rows | KBs removed from the Catalog, unsupported lists, Server-only KBs, ARM64/Insider: the "previous" row is not the true predecessor; flag `coverage_unknown`. |
| Version key is not a product | shared KBs live under one key (`otherWindowsVersions`); 11-25H2/11-26H2 appear almost only that way. |
| Unchanged file | one SHA spans many KBs; the earliest indexed KB is not proof of introduction. |
| Variants | several SHAs per (V,K) possible for other files (WOW64, SKU) [unv]; never auto-pick. |
| Preview / Out-of-band / EXPIRED rows | interleave by date within one version key; attribute carefully. |
| Delta-only rows | no `virtualSize` (candidate probing) or md5-only fileInfo; newest builds are the most exposed (3 of 3 in 2.1 above). |
| BASE | ISO baseline has a date but no KB; valid "old" side only for first-change questions. |
| File version / timestamp | not chronological (2.1). |

## 3. Microsoft Update Catalog

### 3.1 API status and URL patterns

| Item | Fact |
|---|---|
| Supported API | **None documented for catalog metadata or download.** Learn describes the Catalog as a website for search and download; the only programmatic hook is WSUS `ImportUpdateFromCatalogSite(updateId, fileList)` driven by the UpdateID copied from the details page; direct downloads are `.msu` which WSUS cannot import [D1]. Supported KB-to-build alternative: Graph (2.1). |
| Searchable fields | title, description, products, classifications, `KB1234567`; quotes for exact strings [D1]. |
| Search URL (used by Winbindex) | `GET https://www.catalog.update.microsoft.com/Search.aspx?q=<KB> <ver> x64`; HTML; result links `goToDetails("<guid>")`, `flatBlueButtonDownload` buttons; strings "We did not find any results" and "The website has encountered a problem" (retry) [W2 L23-42]. [live] none: host blocked. |
| Download dialog | `POST https://www.catalog.update.microsoft.com/DownloadDialog.aspx`, form field `updateIDs=[{"uidInfo":"<guid>","updateID":"<guid>"}]`; the HTML contains `downloadInformation[n].files[m].url = '...'` [W2 L45-54]; file hosts look like `catalog.s.download.windowsupdate.com/d/msdownload/update/software/{updt,secu}/YYYY/MM/windows10.0-kbNNNNNNN-x64_<sha1>.msu` [W5 L50-52]. Result titles follow `[YYYY-MM ]Cumulative Update [Preview ]for Windows 11 Version 24H2 for x64-based Systems (KBnnnn)` [W2 L111]. Undocumented, scraped with regexes: fragile by construction. |

### 3.2 Terms (quotes)

| Source | Quote | Reading |
|---|---|---|
| T1 [live], Microsoft Terms of Use | "Unless otherwise specified, the Services are for your personal and non-commercial use. You may not modify, copy, distribute, transmit, display, perform, reproduce, publish, license, create derivative works from, transfer, or sell any information, software, products or services obtained from the Services." | Whether it governs the Catalog is **[unv]**: the Catalog's own terms page was unreachable. |
| T1 [live] | "You may not use web scraping, web harvesting, or web data extraction methods to extract data from the AI services." | Scoped to AI services in the text; do not over-read. |
| D2 [live] | "Microsoft makes certain symbols, binary code, and other executables available through the Microsoft symbol server. Use these resources to debug and test your software with Microsoft software. Don't use these resources without authorization." (links `/legal/windows-sdk/microsoft-symbol-server-license-terms`, unreachable [unv]) | SPEC-08's user-initiated, consented download is not an explicit grant; no redistribution; flag for legal review. |

No robots.txt or Catalog ToS could be read [unv]. Consequence: PatchTrace must not automate Catalog scraping in the default product; offer browser handoff and local import (spec phase 1 stands).

### 3.3 Package types and safe read-only inventory

| Type | Identification | Inventory without installing |
|---|---|---|
| MSU | CAB magic `MSCF` [W2 L222-224] | list members (CFHEADER/CFFILE) without decompressing; never run `wusa` |
| CAB (nested) | `MSCF` | same; members `update.mum`, `update.cat`, `*.manifest`, per-component folders with `n/` `f/` |
| PSF (+ `express.psf.cix.xml`) | sibling descriptor | descriptor lists payload deltas; applying needs PSFExtractor (third-party) [W2 L184-209] |
| WIM | `MSWIM\0\0\0\xD0\0\0\0\0` [W2 L225] | 7-Zip in Winbindex; no pure-Python reader [inf] |
| MSIX/appx | zip-like | not handled by Winbindex; [unv] |

Hash evidence without Windows: each `.manifest` carries `DigestMethod`/`DigestValue` (SHA-256 or SHA-1, base64) per file [W3 L325-351]; a reconstructed PE can be matched to it (Tier B).
Signatures: embedded vs catalog signatures are different; "Catalog signature verification does not support every SIP... PE and CAB file types" and "If an executable file is Catalog-signed, the embedded signature is not checked" [D3]. `pe_overview/authenticode.py` verifies embedded signatures only via `WinVerifyTrust` and says so [repo]; catalog-signed verification needs `CryptCATAdmin*` + `WINTRUST_CATALOG_INFO` [unv, not fetched]. Winbindex itself parses signing times with `signify` but does not verify [W3 L1, L171-182, L314]. Here `cryptography` 50.0.1 is present; `signify`, `pefile`, `lief` are not [live]. Pure Python can only prove hash equality with a manifest or catalog entry; trust needs Windows [inf].
Hostile archives: Winbindex extracts everything with `expand.exe` and merges with `shutil.copytree` on a trusted build box, with no traversal checks [W2 L259-289]; it is not a safety template. Use the SPEC-31-D budgets (4 GiB in, 8 GiB out, 50k entries, depth 4) as proposals [unv: CAB limits from MS-CAB not fetched]. Header-only inventory first; reject absolute/`..`/ADS names, casefold collisions and size lies; incremental byte counting.

## 4. What can be automated (evidence tiers)

| Tier | Automatable | Condition |
|---|---|---|
| T0 deterministic | file name to Winbindex rows, SHA identity, direct symbol-server download for `virtualSize` rows, hash verification | metadata + download consent; result is "hash-matched-to-index" only |
| T1 assisted data | version/UBR/KB table from an imported Winbindex record or user-imported update-history page; Graph `FindByKbNumber` | token for Graph; scraped pages are semi-structured |
| T2 analyst | KB to filename (no index), product row choice, wide-window or variant choice, delta-only candidates | analyst supplies filename; resolver lists, never picks silently |
| T3 manual | Catalog search/download, MSU/CAB reconstruction, checkpoint chains, Server 2022/2025-only KBs, Insider/ARM64, catalog-signature verification | browser handoff + local import; label `USER_ASSERTED` |

## 5. Corrections to the spec

1. Section 6.1 "reuse `acquisition.winbindex.parse` ... thin adapter" is insufficient: the parser flattens version-to-KB pairing, drops `otherWindowsVersions`, `heading`, BASE dates, and **skips md5-only delta records** (3 of 292 for afd.sys, the newest builds). Fix the parser first (use the dict key as SHA-256) and add a per-row record; keep `acquisition/1` fields.
2. Sections 5.1/C1: Winbindex `windowsVersions` keys are not the product list; expand `otherWindowsVersions`; `releaseVersion` may carry the sibling version's build (KB5077181).
3. Section 3 Winbindex row: add "Windows 10/11 client x64 only; Server-only KBs excluded; no KB index; history amended".
4. Section 3 Catalog row is right to avoid an API claim; add that no catalog API is documented, the WSUS import API and authenticated Graph (beta) exist, and that Winbindex's scraping patterns are undocumented.
5. Section 6.2 / D3: Winbindex `signingStatus` is `Unknown` or VirusTotal's view; never map it to `embedded-signature-valid`. `catalog-signature-valid` needs CryptCATAdmin and is not in `authenticode.py`.
6. Section 5.3: the checkpoint doc could not be verified here; do not encode "needs N checkpoints" rules without it.
7. Section 18: `.../secbp/understanding-pe-signatures` exists (title "Understanding executable file signing", 07/24/2025) and supports the catalog/embedded distinction; MSRC swagger does not document remediation fields; the Learn symbol-server licence page is linked from D2 but unread.
8. Section 17.8: keep binaries out of fixtures: agreed, with the D2 licence quote above.

## 6. What to build vs defer

| Build now (pure, offline, small) | Defer |
|---|---|
| Parser patch: SHA from key, optional `fileInfo.sha256`, keep (version, KB) rows, `otherWindowsVersions`, heading class, BASE date; tests on `tests/fixtures/kbcve/windows/afd.sys.excerpt.json` | Catalog adapter (terms unknown, HTML fragile) |
| `WindowsVersionKey` + `build.UBR` normalizer; never order by file version or timestamp | Graph `FindByKbNumber` adapter (tenant, beta) |
| Resolver: previous distinct SHA in the same version key, with `intervening` rows and `coverage_unknown` flag | MSU/CAB/PSF/WIM extraction, checkpoint DAG, PA30 chains |
| Importer for a user-saved update-history/release-health table (parse only imported text) | Catalog-signature verification (CryptCATAdmin) |
| Header-only CAB lister behind explicit caps | Server 2022/2025, ARM64, Insider datasets |

Fixtures (`tests/fixtures/kbcve/windows/`): `afd.sys.excerpt.json` (6,295 B, six byte-exact entries from W8: three md5-only deltas, one shared KB, one BASE, one out-of-band) and `afd.sys.excerpt.json.provenance.json` (URL, UTC time, gzip and entry SHA-256, GPL-3.0 note). No Microsoft binaries, MSU, Catalog pages or Learn text were committed.
