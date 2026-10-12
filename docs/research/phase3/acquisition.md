# Acquiring Windows binaries: Winbindex, Microsoft Symbol Server, PA30/PA31 deltas

Research date: 2026-10-12.
Verification labels:
- **[src]**: I read the source or docs at the pinned revision.
- **[run]**: I ran it or fetched it live from this container.
- **[inf]**: inference that I did not verify.

Sources pinned:
- Winbindex: https://github.com/m417z/winbindex @ `aacec0c2e1c622127dc72123f60c9c986fc94a2f` (gh-pages branch, 2026-09-30).
- wumb0's delta notes: blog https://wumb0.in/extracting-and-diffing-ms-patches-in-2020.html and gist https://gist.github.com/wumb0/9542469e3915953f7ae02d63998d2553.
- smilingthax PA30 notes: https://github.com/smilingthax/msdelta-pa30-format @ `cc0eb6fe9ea070f0425e2e9449e3fd4c9b2c2ca8`.

## 1. Winbindex data files

### URL layout
| Dataset | URL | Notes |
|---|---|---|
| x64 / main | `https://winbindex.m417z.com/data/by_filename_compressed/<name>.json.gz` | [run] 200 for `afd.sys` |
| ARM64 | `https://m417z.com/winbindex-data-arm64/by_filename_compressed/<name>.json.gz` | [run] 200 |
| Insider | `https://m417z.com/winbindex-data-insider/by_filename_compressed/<hh>/<name>.json.gz`, where `hh = format(djb2(name) & 0xFF, '02x')` | djb2: start at `h=5381`, then `h = h*33 + charCode` for each character, reduced to uint32. [src] `winbindex.js` L650-655, L1301-1307; I did not fetch it |
| File list | `https://winbindex.m417z.com/data/filenames.json` | JSON array of lowercase names [run] |

- `<name>` is the **lowercase** filename, and the URL is case-sensitive: `AFD.SYS.json.gz` returns 404 [run].
- The files are gzip-compressed JSON written with `mtime=0` and no embedded filename [src] (`data/symbol_server_link_enumerate.py` `write_to_gzip_file`).
- `updates.json`, the KB list, lives only in the repo's `data/` folder. It is not deployed at `/data/updates.json` (404) [run].
- The database is in the `gh-pages` branch of the repo [src] (README).

### Schema of `<name>.json.gz` (verified on afd.sys: 286 entries) [run]+[src]
```
{ "<sha256 lowercase hex>": {
    "fileInfo": {
      "size": int, "md5": hex, "sha1": hex, "sha256": hex,
      "machineType": int,          # 34404=x64, 332=x86, 452=ARM, 43620=ARM64 (winbindex.js humanFileArch)
      "timestamp": int,            # PE COFF TimeDateStamp (on Win10+ a build hash, NOT a real date [inf, widely known])
      "virtualSize": int,          # PE OptionalHeader.SizeOfImage
      "version": "10.0.15063.936 (WinBuild.160101.0800)",
      "description": str, "signingStatus": "Signed"|"Unsigned"|"Unknown"|..., "signatureType": "Overlay"|"Catalog file",
      "signingDate": [iso8601,...],
      # delta-derived entries instead may have only:
      "lastSectionVirtualAddress": int, "lastSectionPointerToRawData": int
    },
    "windowsVersions": { "<e.g. 1703|11-24H2|...>": { "<KBxxxxxxx | BASE...>": {
        "assemblies": { "<assembly id>": { "assemblyIdentity": {...name, processorArchitecture, version, publicKeyToken, buildType, language, versionScope}, "attributes": [ {name, sourceName, destinationPath, importPath, sourcePath} ] } },
        "updateInfo": { "heading": str, "releaseDate": "YYYY-MM-DD", "releaseVersion": "15063.966", "updateUrl": "https://support.microsoft.com/help/<kb>" , "otherWindowsVersions"?: [...] }
    } } }
} }
```
- Field sources [src]:
  - `data/upd03_parse_manifests.py` L219-238 builds delta-derived records: `size`, `md5`/`sha256` taken from the manifest hash, `machineType`, `timestamp`.
  - L269-320 builds records from full PE files, with `virtualSize` read from the PE header.
  - `data/upd05_group_by_filename.py` L319-328 builds the `windowsVersions` → KB → `updateInfo`/`assemblies` nesting.
- **Optional fields:** a contract must treat everything except `sha256`, `size`, `machineType` and `timestamp` as optional. In the afd.sys sample, the key set varies. One entry has no `virtualSize`: it has only `size`, `sha256`, `machineType`, `timestamp` and the two `lastSection*` fields [run].
- **No direct link without `virtualSize`:** when `virtualSize` is absent, the SizeOfImage is unknown and there is no single download URL (see below).

### Symbol-server URL derivation (Winbindex)
- `winbindex.js` `makeSymbolServerUrl`: `https://msdl.microsoft.com/download/symbols/<peName>/<TIMESTAMP as %08X><SizeOfImage as %x>/<peName>`. This means an 8-digit zero-padded **uppercase** timestamp followed by a **lowercase**, unpadded size [src].
- The Python side matches it: `f'{timestamp:08X}{size:x}'` [src] (`symbol_server_link_enumerate.py` L44).
- Ghidriff uses uppercase for both parts (`format(virtual_size,'X')`, `ghidriff/utils.py` L64-67) [src].
- **Server is case-insensitive.** Each of these got a 302 [run]:
  - lowercase timestamp
  - uppercase size
  - uppercase file name in either path segment
  - Recommendation: emit `%08X%x` and compare case-insensitively.
- **Live test [run]:**
  - URL: `https://msdl.microsoft.com/download/symbols/afd.sys/D37888A1b2000/afd.sys`.
  - Response: `302` with a `Location:` pointing at a short-lived signed Azure blob URL (`*.blob.core.windows.net/...?...&se=<expiry>`), then 200.
  - The downloaded body starts with `MZ`. Its SHA-256 `7f145acc…70eb` equals the Winbindex key.
  - Wrong size (`…b2001`): 404.
  - Clients must follow redirects and must not cache the blob URL.
- **Candidate URLs for delta-only entries [src]** (`symbol_server_link_enumerate.py` L74-126; `winbindex.js` "Several download link candidates"):
  - Start from `mapped(lastSectionVirtualAddress + (size - lastSectionPointerToRawData))`, rounded up to 0x1000.
  - Step down by 0x1000 until reaching `lastSectionVirtualAddress + 0x1000`.
  - HEAD each candidate. 302 means valid, 404 means invalid; anything else is an error.
  - The size is accepted only if exactly one candidate is valid.
  - Winbindex uses 64 concurrent HEADs with a 10 s timeout.
- **Download availability [src]** (`winbindex.js` L560-585):
  - **Direct download** works only when `timestamp` and `virtualSize` are present.
  - **Candidate list** is offered when `timestamp`, `size` and both `lastSection*` fields are present.
  - Otherwise there is **no download**. For PE extensions (`exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv`) the message is "file isn't available on VirusTotal". Non-PE files (e.g. .png, .xml) are never downloadable from the symbol server and can only be extracted from update packages or ISOs.
  - **[inf]:** Not every indexed PE is actually on msdl. Microsoft does not index everything, so a 404 for a well-formed URL is a normal outcome.

### Licence and terms
- **Winbindex code and data repo:** GPL-3.0 (`LICENSE`) [src].
- **Hosted binaries:** the README says all linked binaries are hosted on msdl.microsoft.com and that Winbindex only indexes metadata [src].
- **Copyright:** the binaries are Microsoft-copyrighted. I found **no** published Microsoft terms page for the public symbol server that grants redistribution, so this could not be verified. PatchTrace should download on the user's behalf and not redistribute or re-host binaries [inf].
- **Bundled DLL:** `data/tools/` in the Winbindex repo bundles a Microsoft `msdelta.dll`. `msdelta.dll.txt` says it was taken from `UpdateCompression.dll` of Insider build 26040. Its redistribution status is unclear, so do not copy it [src].
- **Data reuse:** pulling Winbindex JSON at runtime is not a GPL code-linking issue. Bundling or redistributing a snapshot of the data is a GPL-3 question that needs legal review [inf].

## 2. Microsoft Symbol Server: PE vs PDB

| Artifact | Key | Example |
|---|---|---|
| PE image | `<name>/<TimeDateStamp %08X><SizeOfImage %x>/<name>` | above |
| PDB (RSDS CodeView) | `<pdbname>/<GUID as 32 uppercase hex, Data1-3 little-endian-decoded><Age %x>/<pdbname>` | `afd.pdb/08182D17CF4EBC10D661568A3DF1470E1/afd.pdb` |

- **PDB test [run]:**
  - I parsed the RSDS record from the downloaded afd.sys.
  - GUID formatting: `Data1 %08X`, `Data2 %04X`, `Data3 %04X`, then 8 bytes as hex.
  - Request flow: 302, then a blob, then a file starting `Microsoft C/C++ MSF 7.00`.
- **Compressed (`.e_`/`.dl_`/`.pd_`) and `file.ptr` [run]:**
  - The same keys with the last character replaced by `_` (`afd.sy_`, `afd.pd_`) returned **404**, with or without a `Microsoft-Symbol-Server/10.0.0.0` User-Agent. `file.ptr` also returned 404.
  - The classic SymSrv convention is that `_` files are CAB-compressed [inf, from SymSrv documentation; not re-verified here].
  - For these samples msdl serves only the uncompressed file. A client may try the `_` variant as a fallback and must CAB-extract it if found (`expand`, or cross-platform `cabextract`/libmspack).
- **Redirects [run]:** always one 302 to an Azure blob with a SAS (`se=` expiry about 1 day ahead).
- **Throttling:** Winbindex retries with exponential backoff up to 30 min on non-302/404 statuses [src]. I did not measure Microsoft's rate limits.

## 3. PA30/PA31 deltas in Windows updates

### Package layout [src: wumb0 blog]
- In cumulative updates, the extracted per-component folders contain:
  - `n/`: **null** differentials, a delta against an empty source, i.e. a compressed full file.
  - `r/`: **reverse** differentials, which take the installed file back to the base (RTM, `.1`) version.
  - `f/`: **forward** differentials, which take the base version to this update's version.
- To get build X from build Y on disk:
  1. Apply `r` (from Y's package) to the installed Y file. This yields the base.
  2. Apply `f` from X's package.
- The gist thread confirms that an `r` must be paired with the file it was made for. Otherwise `ApplyDelta` fails with error 13 (ERROR_INVALID_DATA) [src: gist comments].

### Magic and header bytes
- **Update payloads:** files carry a **4-byte little-endian CRC32 of the remainder**, followed by `PA30` (or `PA31`) at offset 4 [src: wumb0 blog; Winbindex `delta_patch.py` L46-60 checks `patch[4:6]==b"PA"` and strips 4 bytes].
- **Raw msdelta output:** starts directly with `PA30` [src: smilingthax README].
- **WinSxS-compressed files:**
  - `DCM\x01` + `PA30` is a delta against a dictionary in `wcp.dll`.
  - `DCD\x01` (delta needing a source), `DCH\x01` (header only) and `DCX\x01` are handled by SXSEXP. See https://github.com/hfiref0x/SXSEXP README. This was cited from search, and I did not read the source.
- **Legacy:** `PA19` is the old PatchAPI format. msdelta accepts it only with `DELTA_APPLY_FLAG_ALLOW_PA19 = 1` [src: delta_patch.py; smilingthax].
- **PA31:** needs a recent `UpdateCompression.dll`. Stock `msdelta.dll` does not handle it [src: gist comment by m417z; Cobalt write-up https://www.cobalt.io/blog/decoding-windows-cbs-manifests-reversing-the-dcm/pa30-delta-format].

### Applying
- **API:** `ApplyDeltaB(DELTA_FLAG_TYPE flags (uint64), DELTA_INPUT source, DELTA_INPUT delta, DELTA_OUTPUT* out) -> BOOL`, then `DeltaFree(out.lpStart)`.
  - `DELTA_INPUT` is `{LPVOID lpStart; SIZE_T uSize; BOOL Editable}`.
  - `DELTA_OUTPUT` is `{LPVOID lpStart; SIZE_T uSize}` [src: delta_patch.py; docs https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/DevNotes/msdelta-applydeltab.md].
  - `ApplyDeltaA/W(flags, sourceName, deltaName, targetName)` is the file-path variant.
  - `UpdateCompression.dll` is in-memory (B) only [src: SXSEXP README].
- **Inputs:** the base file must be the exact source. The delta embeds the target hash, so a wrong base fails rather than producing garbage [src: smilingthax].
- **Null deltas:** `n/` deltas take an empty buffer as the source.
- **Platform: Windows only.** `msdelta.dll` and `UpdateCompression.dll` are Microsoft binaries. I did not test whether they run under Wine.

### Pure-Python / open-source appliers
- **No complete, licensed, non-Windows PA30 applier was found.**
  - smilingthax/msdelta-pa30-format: partial C decoder plus format notes. It has **no LICENSE file**, so it is all-rights-reserved by default. The README has many TODOs, the rift and transform preprocessing is incomplete, and it does not cover PA31 [src].
  - libmspack does not support PA30 (issue https://github.com/kyz/libmspack/issues/3) [search result, not re-read].
  - `delta_patch.py` (wumb0 gist, vendored in Winbindex under GPL-3) is a **ctypes wrapper**. It needs `windll` and the DLL, so it is not an implementation [src].
  - The gist has no explicit licence that I could see.
- **Not verified:** whether any newer Rust or Python port exists beyond what search surfaced.

## Open questions
- Microsoft terms of use for msdl downloads and redistribution.
- Whether msdl ever serves `_`-compressed PEs today (none were observed).
- Rate limits.
- A licensed cross-platform PA30/PA31 decoder (none found).
- Whether `timestamp`-less Winbindex entries exist (none in the sample).

## Implications for PatchTrace contracts
1. **Winbindex is a metadata source only.** Resolve `(name, sha256)` → `fileInfo`.
   - If `virtualSize` is present, build one URL using `%08X%x`.
   - If only the `lastSection*` fields are present, enumerate candidates with HEAD and require exactly one 302.
   - Otherwise report "not downloadable (update-package only)".
2. **Verify every download** by SHA-256 against the Winbindex key, and by `machineType == 0x8664` for x64. Follow exactly one redirect to `*.blob.core.windows.net`. Treat 404 as "not on server", not as an error.
3. **PDB fetch:** build the URL from the RSDS GUID and age using the format above, and verify the `Microsoft C/C++ MSF 7.00` magic.
4. **Delta application is a Windows-only optional capability.**
   - It is `ctypes` → `msdelta.dll` (PA30) or a user-supplied `UpdateCompression.dll` (PA31).
   - Strip the 4-byte CRC32 and verify it (`zlib.crc32(data[4:]) == le32(data[:4])`). Require `PA30`/`PA31` at offset 4.
   - Chain `r` then `f`.
   - Do not ship Microsoft DLLs, and do not depend on smilingthax code (no licence).
5. **Licensing:** do not re-host binaries. Treat any bundled Winbindex data snapshot as GPL-3 material.
