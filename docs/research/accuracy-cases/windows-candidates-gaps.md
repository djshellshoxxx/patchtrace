# Windows L3 candidates: coverage gaps

Research date 2026-11-06. Companion manifest: `windows-candidates-gaps.json` (schema `rq-case-manifest/1`, 13 cases, all `facts: unverified`).

Validation: this manifest uses `expected.accept`, so it validates only with the `cases.py` from PR #260 (`research/windows-pair-candidates-20261107`, head `e5e783f6`), run as `python -m tools.research_qualification cases <manifest>` from a checkout of that branch. Exit code 0 (13 cases, 12 independent projects, 3 holdouts). The `cases.py` on `main` rejects `accept` (`expected has unknown keys`). Merge after #260.

Every function name is as stated by the cited page, read through WebFetch, which summarises pages. Treat each name as unverified until a second source or the real binary diff agrees. No KB or build was invented; where a page gave none the ref says "needs pinning". No case has a verified build pair, so none is `verified`.

## Cases

Holdout rule, fixed before looking at any outcome: sort case ids alphabetically and hold out every fourth one starting at the fourth (3 of 13, 23%). It was applied mechanically, so it picks two weak cases (17001, dnsclient); that is a consequence of the rule, not a choice.

| CVE | Binary | Gap | Expected function | Confidence | Holdout |
|---|---|---|---|---|---|
| CVE-2014-6321 | schannel.dll | crypto | `DecodeSigAndReverse` (accept `iCM_DecodeSigAndReverse`) | medium-low | no |
| CVE-2020-0796 | srv2.sys | SMB | `Srv2DecompressData` | medium | no |
| CVE-2020-1048 | localspl.dll | Print Spooler | `LcmCreatePortEntry` (accept `LcmXcvDataPort`) | medium | no |
| CVE-2020-17001 | localspl.dll | Print Spooler | `LcmCreatePortEntry` + 4 accepted | low | yes |
| CVE-2020-17087 | cng.sys | crypto | `CfgAdtpFormatPropertyBlock` | medium-high | no |
| CVE-2021-26897 | dns.exe | DNS server | `SigFileWrite` | medium-low | no |
| CVE-2021-28476 | vmswitch.sys | Hyper-V | `VmsIfrInfoParams_OID_SWITCH_NIC_REQUEST` | medium-low | no |
| CVE-2021-31956 | ntfs.sys | ntfs | `NtfsQueryEaUserEaList` | medium-low | yes |
| CVE-2022-33647 | kdcsvc.dll | Kerberos | `KerbInitPreferredCryptList` (accept `KerbGetEncTypeBitmask`) | medium-low | no |
| CVE-2024-38256 | win32k.sys | win32k | `GreGetGlyphOutlineInternal` | low | no |
| CVE-2026-41089 | netlogon.dll | netlogon | `NetpLogonPutUnicodeString` + 5 accepted | medium | no |
| CVE-2026-41096 | ws2_32.dll | DNS client | `WSCGetApplicationCategoryEx` | low | yes |
| CVE-2026-58594 | mstscax.dll | RDP client | `CacNx::SurfaceDecoderCpu::Init` | low | no |

Confidence reasons (details and quotes are in each case's `notes`):

- cng 17087: two independent pages name the function; Versprite shows the fixed code calling `RtlUShortMult`. Best-supported case here. P0 lists affected `KB4579311` and first fixed `KB4586781` for Win10 2004; no file versions.
- netlogon 41089: adscanpro (own ghidriff run) and SecPod agree on `NetpLogonPutUnicodeString`; per-SKU patched builds known, vulnerable build not.
- srv2 0796: K7 states the patch is in `Srv2DecompressData`; Trellix shows the fixed arithmetic but not the function. The earlier pass dropped this CVE for lack of a diff statement; K7 supplies one.
- localspl 1048: build pair (6.1.7601.24383 to 24554) and function list from one blog; contradiction below.
- ntfs 31956 and vmswitch 28476: pages name the vulnerable function, none states what Microsoft changed. A vulnerable function is usually the fixed one, but this is inference.
- kdcsvc 33647, dns 26897, schannel 6321, mstscax, win32k 38256, dnsclient: single source for the function.

## Per-gap summary

- **ksecdd.sys / CNG / schannel**: cng.sys 17087 and schannel 6321 found. No ksecdd.sys write-up with a named function turned up. `keyiso.dll` 28229 (0patch names `SrvAddKeyToList`) and `ncryptprov.dll` 36906 have good write-ups but are CVEs already in the L1 corpus, so skipped.
- **NTLM / Kerberos**: one new case (kdcsvc 33647). No NTLM case: CVE-2019-1040 (NSFOCUS) and CVE-2024-43451 pages name no binary or function. Kerberos 33679 and 35756 (0patch) name only binaries (`kdcsvc.dll`, `kerberos.dll`), no function. Silverfort's CVE-2020-17049 article names no binary or function. CVE-2024-26209 (lsasrv.dll) is only a one-line entry on PatchDiffWednesday; its per-CVE README was not fetchable.
- **RDP beyond rdpbase.dll**: one case, the mstscax client (single source, 2026). Nothing for termsrv/rdpserverbase/rdpcorets.
- **DNS server and client**: dns.exe 26897 (second dns.exe case). Client 41096 is low confidence (see contradictions). dnsapi.dll itself has no named function anywhere found.
- **Print Spooler, non-ZDI**: two localspl.dll cases from cve-north-stars. 0patch posts on PrintNightmare (names API `AddPrinterDriverEx`, not a patched function), 30206/21997 and 1030 name no function, and SpoolFool pages (0patch, Logpoint) describe behaviour only. Nothing for spoolsv.exe or win32spl.dll, and the cap on localspl.dll (2) is reached.
- **Modern win32k, 2022-2025**: weakest gap. One low-trust case (38256). CVE-2023-29336 has a named function (`xxxEnableMenuItem`, Numen and KernelSight) but win32kfull.sys already has three cases. Unit 42 part 1 (CVE-2022-21882) names no patched function. KernelSight pages for 24983, 62458, 27732 name no function.
- **Others**: SMB srv2.sys 0796 and Hyper-V vmswitch.sys 28476 added; ntfs.sys 31956 added. MSMQ: only CVE-2023-21554 has a function-level write-up (IBM X-Force: `CQmPacket::CQmPacket`, `GetNextSectionPtrSafe`, `CEodHeader::GetNextSectionSafe`, build 10.0.22621.1555, April 2023) but that CVE is in the L1 corpus, so it was not duplicated. Say so if you want it added anyway; it is the best MSMQ case available. Other MSMQ pages (CVE-2024-30080) name nothing patched (The Stack says the bug is `RPCToServer` in mqise.dll, no patch statement). At cap or already well covered, so not searched further: clfs.sys, afd.sys, http.sys, ntoskrnl.exe.

## Sources searched

Used: Project Zero RCA, Versprite, 0vercl0k GitHub, Akamai, y3a blog, NCC Group, cve-north-stars (Patch-Diffing-Applied and CVE page), K7 Labs, Trellix, Core Security, 0patch blog (several), BeyondTrust, Unit 42, cnblogs, adscanpro, SecPod, Origin HQ, Xcitium, KernelSight (splintersfury.github.io), onlyfm252.starlabs.sg (OnlyPatch), Numen, Silverfort, NSFOCUS, IBM X-Force (MSMQ), The Stack, PatchDiffWednesday and originsec/patchwatch READMEs.

Refused or unreachable (recorded, not worked around): WebFetch returned `URL_NOT_ON_ALLOWLIST` for `onlyfm252.starlabs.sg/patch-tuesday/2026-07/`, `github.com/T-RN-R/PatchDiffWednesday/tree/main/Windows`, and KernelSight case-study URLs that had not appeared in a search result (the same URLs worked once a search surfaced them). No ZDI, Synacktiv, Quarkslab, Check Point, Kaspersky, Positive Technologies, SSD, Elastic or Rapid7 page produced a usable function name; Kaspersky's CVE-2021-31956 article did not surface in search (NCC and y3a used instead). No curl or mirrors were used.

## Cases rejected

- Duplicates of the L1 corpus: CVE-2023-21554 (mqqm.dll), CVE-2023-28229 (keyiso.dll), CVE-2023-36906 (ncryptprov.dll).
- Cap reached: CVE-2023-29336 (win32kfull.sys, 3 cases already).
- CVE-2025-21333 (KernelSight): says binary `vsp.sys` with `VspReceivePacket`; the page is auto-generated and the file name looks wrong (the Hyper-V NT Kernel Integration VSP is a different driver, which I did not verify). Rejected as untrustworthy.
- CVE-2024-35250 (ks.sys, KernelSight): lists only generic `DispatchDeviceControl`; DEVCORE blog was not fetched. Also outside the requested gaps.
- CVE-2023-36427 (KernelSight, ntoskrnl.exe): names MSRs, no function; ntoskrnl.exe at cap.
- CVE-2022-33679 (kdcsvc): same fix as 33647; no extra signal.
- CVE-2020-1048 sibling CVE-2020-1337 (localspl.dll): cap reached; only `LcmStartDocPort`/`PortIsValid` plus noise listed.
- CVE-2022-21999 SpoolFool, CVE-2021-34527 PrintNightmare: no patched function named by any fetched page.
- CVE-2026-41089 duplicate rows (SecPod, adscanpro) were merged into one case.

## Contradictions

- CVE-2020-1048: diff table says `LcmCreatePortEntry` changed; a quoted public report says the `PortIsValid` check moved into `LcmXcvDataPort`. Both accepted.
- CVE-2020-0796 (K7): text says `Srv2DecompressData` was patched, a figure caption says `Srv2CompressionDecompress`. K7's KB4541338 link could not be confirmed as the security KB, so no KB recorded.
- CVE-2014-6321: BeyondTrust `DecodeSigAndReverse` vs Unit 42 `iCM_DecodeSigAndReverse`; Unit 42 gives no patch statement. Both accepted.
- CVE-2026-41089: KB numbers differ between SecPod (KB5089549 for 2016 to 2025) and adscanpro (per-SKU KBs).
- CVE-2026-41096: Origin HQ says `ws2_32.dll`/`webio.dll`; Xcitium says `dnsapi.dll`. Origin's pre and post builds (26100.8328, 28000.1896) are different branches, and the author notes the repro only reached a local OOB read.
- CVE-2026-58594: the page cites two feature flag names (`Feature_2141685050` used, `Feature_2208793915` in another write-up).
- CVE-2024-38256: KernelSight labels the binary `win32k.sys`, but the function likely lives in win32kfull.sys on the build given.
- CVE ids and builds dated 2026 (41089, 41096, 58594) come from search results only; not cross-checked against MSRC.

## Cases per binary across ALL manifests

Counted from `windows-candidates.json` (#260), `-sources`, `-github`, `l1-join-candidates.json` (one count per CVE per file, CVEs with an empty `expected_files` ignored) and this manifest. A CVE present in both L1 and an L3 manifest counts twice, as the cap rule is per case.

| Binary | Count | Binary | Count |
|---|---|---|---|
| clfs.sys | 9 (L1 7 CVEs + 2 L3, 2 shared) | dns.exe | 2 (this: 1) |
| bfs.sys | 6 (all L1) | kdcsvc.dll | 2 (this: 1) |
| cldflt.sys | 6 | localspl.dll | 2 (this: 2) |
| mskssrv.sys | 5 | netlogon.dll | 2 (this: 1) |
| afd.sys | 3 | ntfs.sys | 2 (this: 1) |
| dwmcore.dll | 3 | srv2.sys | 2 (this: 1) |
| tcpip.sys | 3 | http.sys, ntoskrnl.exe, ikeext.dll, prjflt.sys, raspptp.sys, storvsp.sys, tapisrv.dll | 2 each |
| win32kfull.sys | 3 | cng.sys, schannel.dll, vmswitch.sys, mstscax.dll, ws2_32.dll, win32k.sys | 1 each (this) |

Existing manifests already exceed the cap for clfs.sys, bfs.sys, cldflt.sys, mskssrv.sys, afd.sys, dwmcore.dll, tcpip.sys and win32kfull.sys (mostly because L1 CVEs repeat L3 ones). This manifest touches none of them. Every binary it adds ends at 2 or fewer.

## Next steps if more cases are wanted

Get a second source or a ghidriff run for the single-source names; pin real build pairs via Winbindex; fetch the CVE-2024-26209 lsasrv.dll README from PatchDiffWednesday once allowed; decide whether CVE-2023-21554 should be added despite the L1 overlap.
