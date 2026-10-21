# KB, Winbindex and update-package research (Program E, KB track)

Status: research notes, docs only, no code. Base: `origin/main` 21a005e (fast-forwarded 2026-10-15). Author: research worker (Haiku 5.5). Date of this pass: 2026-10-15.

Read first and not repeated unless corrected: `docs/specs/program-e/KB-integration-plan.md`, `docs/specs/program-e/KB2-source-facts.md` (KB2, 2026-10-14; its ledger rows are cited below as "KB2 row X"), `docs/specs/acquisition.md` (SPEC-08).

Evidence grading: **[V]** fetched or observed in this pass; **[E]** WebSearch excerpt only (an AI summary of a page this sandbox could not fetch; treated as a pointer, not as proof); **[K2]** carried from KB2, not re-verified here; **[U]** unverified.

Sandbox note: on 2026-10-15 `WebFetch` could not resolve `learn.microsoft.com` or `www.catalog.update.microsoft.com` (`getaddrinfo ENOTFOUND`). WebSearch still returned those URLs. Every Learn and Catalog statement below is therefore [E] unless marked otherwise.

## Verified facts

### Winbindex (m417z)

- F1. Winbindex's README says binaries are hosted on the Microsoft public symbol server, that the website and "the whole database" are served with GitHub Pages from the repo, that Winbindex "merely indexes metadata that enables to generate those links", and that the database "is updated on a regular basis by Python scripts" in the repo. Accessed 2026-10-15. [V] https://raw.githubusercontent.com/m417z/winbindex/main/README.md
- F2. The README fetched on 2026-10-15 contains no licence statement. The GPL-3.0 licence for the repo and data repos comes from the LICENSE file, which was not re-fetched here. [K2] 2.D row "Licence", https://raw.githubusercontent.com/m417z/winbindex/main/LICENSE
- F3. Data layout, hosting and the no-KB-index finding are as stated in KB2 2.D (per-file `data/by_filename_compressed/<name>.json.gz` on gh-pages, `filenames.json`, `hashes/`). Not re-fetched here. [K2]

### Microsoft symbol server

- F4. The public symbol server page says Microsoft "makes certain symbols, binary code, and other executables available" to "debug and test your software with Microsoft software" and "Don't use these resources without authorization". Accessed 2026-10-15 via search excerpt. [E] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols (also KB2 2.E row, which quotes the same wording from the windows-driver-docs source [K2])
- F5. The same page links to a separate "Microsoft license terms - Microsoft symbol server" document. Its text was not retrieved on 2026-10-15. [U] for its content and URL (KB2 lists `/legal/windows-sdk/microsoft-symbol-server-license-terms` as the candidate URL, not re-checked).
- F6. The public server is TLS 1.2+ only for https connections. [E] same page as F4. [K2] 2.E row agrees.
- F7. No published rate limit for `msdl.microsoft.com` was found in any reachable source on 2026-10-15. Community reports describe slow or timed-out downloads. Search results about 429 and Retry-After came from Microsoft Graph and OneDrive, not the symbol server. [E] (search, 2026-10-15), not applicable to msdl.
- F8. Microsoft Learn has a SymChk page on manifest files, showing `SymChk /om ... /ie ...` and `SymChk /im ... /s srv*...` usage. The `/s srv*https://msdl.microsoft.com/download/symbols` syntax and `/ocx` flag come only from third-party posts (pete.akeo.ie; CodeGuru), which use `http://` in older examples. Flag semantics are [U] until read against the current Debugging Tools documentation. [E] https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-a-manifest-file-with-symchk ; https://pete.akeo.ie/2020/07/

### Update package structure and tools

- F9. Checkpoint cumulative updates (Windows 11 24H2 onward): a monthly security or preview update may be preceded by a checkpoint cumulative update. Windows Update and WSUS install the chain seamlessly. [E] https://learn.microsoft.com/en-us/windows/deployment/update/catalog-checkpoint-cumulative-updates (KB2 2.G quotes the same page as "If any checkpoint ... precede a target update ... needs to take all prior checkpoint cumulative updates" [K2])
- F10. Microsoft's Tech Community post says a monthly update may ship more than one package file in the Catalog: one per checkpoint plus one with the latest cumulative payload. [E] https://techcommunity.microsoft.com/t5/windows-it-pro-blog/introducing-windows-11-checkpoint-cumulative-updates/ba-p/4182552
- F11. Microsoft support article "Operation is not supported" error: double-clicking a post-checkpoint `.msu` fails. The documented workaround is to download and install every checkpoint cumulative update and then the latest update. [E] https://support.microsoft.com/en-us/servicing/os/windows/2024/09/operation-is-not-supported-error-installing-a-post-checkpoint-update-by-double-clicking-the-msu-pack
- F12. PSFX whitepaper "Windows Updates using forward and reverse differentials": one update carries a forward differential (base to changed file) and a reverse differential (back to base) per file; Patch Storage Files are cached by WU, WSUS and ConfigMgr; "Baseless Patch Storage Files" carry full binaries; PSF size grows with the number of baselines covered; using RTM as the baseline gives an identical payload for all devices. [E] https://learn.microsoft.com/windows/deployment/update/psfxwhitepaper (the KB2 2.G row, rated "[excerpt]", gives the same model [K2])
- F13. MSU extraction with the Windows `expand` tool: Microsoft's driver documentation runs `expand` on the `.msu` (first pass, `-F:*` into a directory), then on the `.cab` it produces. [E] https://learn.microsoft.com/en-us/windows-hardware/drivers/print/getting-the-updated-core-driver-package
- F14. The `expand` command-line reference documents `-f:<files>` with `*` and `?` wildcards, and states that Intra-Package Delta (IPD) compressed updates need the Expand.exe from the Windows ADK or from Vista, 7 or 8; older Expand.exe builds do not handle IPD. [E] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825253(v=win.10)
- F15. Community write-ups (Seven Forums, Verboon) and a Microsoft-documented method agree on `expand` for MSU and CAB. A Seven Forums thread advises against third-party archivers for update packages, saying they extract incompletely. This is secondary guidance. [E] https://www.sevenforums.com/threads/windows-update-extract-an-update.155584/post-1441140 ; https://www.verboon.info/2010/09/extracting-cab-files-from-microsoft-update-standalone-package-msu/
- F16. Community reverse engineering of the PA30/DCM manifest delta format (Cobalt): the decoding dictionary is a resource (0x266) inside `wcp.dll`; the DCM header is stripped and the payload is applied with `ApplyDeltaB` from `msdelta.dll` using that dictionary as the source. This is third-party work and version-specific; its build numbers are [U]. [E] https://www.cobalt.io/blog/decoding-windows-cbs-manifests-reversing-the-dcm/pa30-delta-format ; https://www.cobalt.io/blog/part-2-decoding-windows-cbs-manifests-building-the-decoder

### Update Catalog

- F17. The Catalog FAQ is reachable as a URL: `https://catalog.update.microsoft.com/Faq.aspx`. Its text was not fetched on 2026-10-15 (see Open questions). [E]
- F18. A search summary (2026-10-15) reports Microsoft guidance that the Catalog is mainly for corporate distribution and aimed at advanced users, with a manual search and Download click as the documented method. No source URL was retained for this summary, so it is [U]. Nothing on automated access, scraping or redistribution was found.

## Corrections

- C1. KB2 2.E/2.G and KB-plan section 2 describe the symbol-server licence as the Learn page with `/legal/windows-sdk/microsoft-symbol-server-license-terms`. The search on 2026-10-15 showed the link text "Microsoft license terms - Microsoft symbol server" on the Learn public-symbols page, not the URL. The URL remains [U].
- C2. KB2 2.F says Learn and Catalog hosts are refused by the egress proxy. On 2026-10-15 the failure mode for `WebFetch` was DNS (`ENOTFOUND`), not a proxy 403. The result is the same (no fetch), but the cause differs. Do not cite the proxy as the reason without a proxy log.
- C3. A secondary page (iTechtics, via search) writes the expand flag as `_f:*`. Microsoft's reference uses `-f:*`. The underscore is a typo. [E]
- C4. Winbindex's README (F1) does not contain a licence statement. KB2 2.D correctly points to the LICENSE file for GPL-3.0. Keep the licence claim sourced to the LICENSE file, never to the README.

## Gotchas

- G1. The Winbindex key (SHA-256 of the manifest file) is Microsoft's manifest digest relayed by a third party. A match proves the index record, not a signature. [K2] 2.D; KB-plan section 6 already limits the label to `hash-matched-to-index`.
- G2. Checkpoint chains: a single KB can need several `.msu` files, in order. A post-checkpoint `.msu` cannot be installed alone by double-click (F11). Model prerequisites as a DAG and never as "this KB introduced the change" (F9, F10, KB2 2.G).
- G3. `expand` and MSU: use Microsoft's `expand` with `-f:` wildcards on the `.msu`, then on the `.cab`. Use an Expand.exe that supports IPD (F14). A third-party archiver is not a safe substitute (F15, secondary).
- G4. The symbol server licence excerpt (F4) limits use to "debug and test your software with Microsoft software" and forbids use "without authorization". Patch diffing of Microsoft binaries by a third-party tool may not fit that wording. This is a legal reading, not a technical one, and must be settled by the owner before binaries are fetched by default (matches KB2 5.1 item 9).
- G5. No rate limit is published for msdl (F7). Per-operation consent, one request at a time and a visible cap are the only controls PatchTrace can state.
- G6. Full binaries may sit in Baseless PSFs (F12) even where delta payloads are not usable. This is a possible route to a complete file, but no extraction path for PSFs is verified here; PSFX tooling is third-party (KB2 2.G cites PSFExtractor [K2]).
- G7. Every Learn and Catalog statement in this file is a search-summary excerpt. KB2 rule: an `[E]` row may pose a probe or a parameter, never be the sole basis of a recommendation.
- G8. Community sources (Cobalt, pete.akeo.ie, CodeGuru, Seven Forums, iTechtics) are reverse engineering or user guides. Use them only as leads that a Windows host must confirm.

## Open questions

- Q1. Text and URL of the Microsoft symbol-server licence page. Owner or legal reading needed before default downloads (G4). Probe: fetch the page where egress allows and record SHA-256 and date.
- Q2. Update Catalog terms of use and any statement on automated or bulk access (F17, F18). Probe: fetch `catalog.update.microsoft.com/Faq.aspx` and the Microsoft legal terms page; record bytes and date.
- Q3. Whether the KB "File information" CSV exists. KB2 2.F [excerpt] says a CSV is linked from KB support pages. This pass found only the HTML "File information" tables described in general terms. Keep the CSV as [U] until one KB page and its download link are read (KB2 probe P7).
- Q4. msdl rate limits and behaviour on HEAD and GET under bursts (F7). Probe on a Windows host with bounded requests.
- Q5. Whether Baseless PSFs are reachable from a Catalog package for a named KB, and whether any open tool extracts them without executing anything. Unknown.
- Q6. PA31 and `UpdateCompression.dll` (KB2 2.G route 2 [K2]). Not re-checked.
- Q7. Current checkpoint lists per KB: read from the Learn page on a host where it resolves.

## Sources

Accessed 2026-10-15 unless stated.
- https://raw.githubusercontent.com/m417z/winbindex/main/README.md [V]
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols [E]
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/using-a-manifest-file-with-symchk [E]
- https://pete.akeo.ie/2020/07/ [E, third party]
- https://learn.microsoft.com/en-us/windows/deployment/update/catalog-checkpoint-cumulative-updates [E]
- https://techcommunity.microsoft.com/t5/windows-it-pro-blog/introducing-windows-11-checkpoint-cumulative-updates/ba-p/4182552 [E]
- https://support.microsoft.com/en-us/servicing/os/windows/2024/09/operation-is-not-supported-error-installing-a-post-checkpoint-update-by-double-clicking-the-msu-pack [E]
- https://learn.microsoft.com/windows/deployment/update/psfxwhitepaper [E]
- https://learn.microsoft.com/en-us/windows-hardware/drivers/print/getting-the-updated-core-driver-package [E]
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825253(v=win.10) [E]
- https://www.sevenforums.com/threads/windows-update-extract-an-update.155584/post-1441140 [E, secondary]
- https://www.verboon.info/2010/09/extracting-cab-files-from-microsoft-update-standalone-package-msu/ [E, secondary]
- https://www.cobalt.io/blog/decoding-windows-cbs-manifests-reversing-the-dcm/pa30-delta-format [E, third party]
- https://www.cobalt.io/blog/part-2-decoding-windows-cbs-manifests-building-the-decoder [E, third party]
- https://catalog.update.microsoft.com/Faq.aspx [E, not fetched]
- KB2 (`docs/specs/program-e/KB2-source-facts.md`, 2026-10-14) rows 2.A-2.J, cited as [K2].
