# Windows L3 candidates, GitHub and web sweep (2026-11-07)

Companion to `windows-candidates-github.json` (schema rq-case-manifest/1, 12 cases, all `facts: unverified`, `holdout: false`, licence `reference-only`). No CVE here overlaps `windows-candidates.json` from PR #260. Cap of 2 cases per binary counted across both manifests. Facts below were read on the cited pages through a fetch tool that summarises pages; treat every row as unverified until the binary pair is diffed. The `accept` field needs the `cases.py` change from PR #260; current main rejects it.

## Candidates

| CVE | Binary | Month | Function | Sources | Fix type | Confidence |
|---|---|---|---|---|---|---|
| CVE-2024-38063 | tcpip.sys | 2024-Aug | Ipv6pProcessOptions | malwaretech.com/2024/08/exploiting-CVE-2024-38063.html; gist.github.com/clearbluejar/d13fba26cab3a7ff2a995558d62cdd80 | call swapped (IppSendErrorList to IppSendError) | medium (contradicted by KernelSight) |
| CVE-2019-0708 | termdd.sys | not stated | IcaBindVirtualChannels (+ IcaRebindVirtualChannels) | malwaretech.com/2019/05/analysis-of-cve-2019-0708-bluekeep.html | same change in both | high |
| CVE-2019-1181 | rdpbase.dll (Win7: RDPCoreTS.dll) | not stated | DecompressUnchopper::Decompress | coresecurity.com DejaBlue blog; malwaretech.com/2019/08/dejablue-analyzing-a-rdp-heap-overflow.html | decompress bounds | medium-high |
| CVE-2020-1350 | dns.exe | 2020-Jul | SigWireRead | labs.k7computing.com forgotten-windns post; 0patch.com/blog/micropatch-available-for-sigred | overflow checks | high |
| CVE-2020-1472 | netlogon.dll | 2020-Aug | NetrServerAuthenticate3 (+ NlIsChallengeCredentialPairVulnerable added) | 0patch.com/blog/micropatch-for-zerologon-perfect | new check, helper added | medium (single source) |
| CVE-2025-33073 | mrxsmb.sys | not stated | SmbCeCreateSrvCall | synacktiv.com NTLM reflection post; anorak001.github.io/posts/CVE-2025-33073 | reject marshalled target info | high |
| CVE-2023-29360 | mskssrv.sys | 2023-Jun (per KernelSight KB5027231) | FsAllocAndLockMdl | onlyfm252.starlabs.sg diff md; splintersfury.github.io KernelSight CVE-2023-29360 | probe mode KernelMode to UserMode | medium |
| CVE-2024-30085 | cldflt.sys | 2024-Jun | HsmIBitmapNORMALOpen | starlabs.sg/blog/2024/12-all-i-want-for-christmas-is-a-cve-2024-30085-exploit/; onlyfm252 RCA md | size check before memcpy | high |
| CVE-2025-55680 | cldflt.sys | 2025-Oct | HsmpOpCreatePlaceholders | onlyfm252.starlabs.sg cldflt_sys-kb5066835.md (ghidriff) | TOCTOU | medium-high |
| CVE-2024-38106 | ntoskrnl.exe | not stated | VslpEnterIumSecureMode (+ VslGetSetSecureContext) | KernelSight CVE-2024-38106 and Patch Patterns | locking added | medium |
| CVE-2022-21882 | win32kfull.sys | 2022-Jan | xxxClientAllocWindowClassExtraBytes | coresecurity.com Core Labs analysis | ExStyle2 console-mode check | high |
| CVE-2025-60705 | csc.sys | 2025-Nov | CscRebootRenamepOpenKey | onlyfm252.starlabs.sg csc_sys-kb5068861.md | OBJECT_ATTRIBUTES flag fix | LOW (single source, possible analyst labels) |

## Contradictions and alias notes

- CVE-2024-38063: MalwareTech and the clearbluejar ghidriff gist show Ipv6pProcessOptions changed; KernelSight lists Ipv6pReassembleDatagram, Ipv6pReceiveFragment, IppReassembleDatagram as affected and describes reassembly arithmetic checks (fixed 10.0.22621.4036, KB5041585). The gist's own build metadata disagrees with itself (3147 vs 3139).
- CVE-2019-1181: binary differs by OS (rdpbase.dll on Win10 1903 per Core, RDPCoreTS.dll on Win7 per MalwareTech).
- CVE-2019-0708: sources spell the names with a leading underscore (x86 decoration); manifest uses the undecorated form.
- CVE-2023-29360: diff report file name says 22621.1848 but its PE version shows 22621.2050.
- CVE-2025-33073: mrxsmb (client) per Synacktiv part 1; a later Synacktiv post says srv2!Smb2ValidateLoopbackAddress and srvnet!SrvNetIsAddressLoopback were added by the same fix. Both could be exercised, only mrxsmb has a named changed function.
- CVE-2020-1350: 0patch says Server 2012 builds, K7 gives 6.3.9600 (2012 R2 line).
- CVE-2024-38106: stated KB5043076 may post-date the first fixing update.

## Held back (cap of 2 per binary or out of range)

- cldflt.sys: CVE-2025-50170 (HsmpOpCreatePlaceholders, KB5063878, 26100.4484 to 4946, ghidriff report) and CVE-2023-36036 (HsmFltProcessReparse, HsmpRpReadBuffer, HsmpRpWriteBuffer; KB5032190; 10.0.22621.2715; KernelSight).
- Out of the requested 2019-2025 range: CVE-2026-41089 netlogon.dll (adscanpro.com blog, ghidriff, May 2026, KB5089549; modified NlGetLocalPingResponse, BuildSamLogonResponse, NetpDcBuildPing, PrimaryQueryHandler, NetpLogonPutUnicodeString, NetpLogonPutBytes; 20 modified, 5 added) and CVE-2026-26128 srv2!Smb2ExecuteNegotiateReal (Synacktiv reflection-mitigation post, March 2026). Both would be good netlogon and SMB cases if the year window is relaxed.
- Left to the other agent (ZDI): thezdi.com 2020-08-11 spooler post names IsValidNamedPipeOrCustomPort and PortIsValid added in localspl.dll for CVE-2020-1048.

## Excluded (vulnerable function only, or no function named)

- KernelSight "Affected Functions" pages: CVE-2023-29336 (xxxEnableMenuItem, xxxMNDestroyHandler), CVE-2024-21338 (AipSmartHashImageFile, CTuneupMgr::NotifyRefresh; patch described as IOCTL dispatch changes, no function), CVE-2024-38063 tcpip list.
- hackyboiz CVE-2024-21338: vulnerable chain only. y3a CVE-2021-31956: NtfsQueryEaUserEaList is bug location only.
- Project Zero RCA CVE-2020-17087 (CfgAdtpFormatPropertyBlock): bug location only, patch CL N/A.
- McAfee SMBGhost: Srv2DecompressData named for the bug, patch functions not named.
- Secura Zerologon factsheet: no patched function. 0patch CVE-2022-37967, CVE-2022-33647/33679 and Silverfort: kdcsvc.dll named only as the micropatch target.
- 0patch PrintNightmare: AddPrinterDriverEx and localspl.dll are the micropatch site; Microsoft's patched function not named. Thalpius, Sygnia, VerSprite spooler: vulnerable functions only. 0patch SpoolFool/CVE-2022-30206/CVE-2022-21997: no functions.
- 0patch Kerberos CVE-2025-60704, Kudelski CVE-2022-26923, BI.ZONE CVE-2024-38063, ZeroPath CVE-2025-49667, Medium CVE-2025-24983, protoslabs CVE-2023-29336, KernelSight/starlabs patch-tuesday CVE-2022-21999 and CVE-2023-29336 pages: no changed function.

## Could not read

- gh REST `repos/{owner}/{repo}` and `/contents` returned 403 "not enabled for this session" for ByteRay-AI/drift-corpus, ghidriff-bot/winbindex-diffs, T-RN-R/PatchDiffWednesday, originsec/patchwatch and clearbluejar/patch-diffs. Not worked around; I did not attach them with add_repo. Existence of clearbluejar/patch-diffs is not confirmed (never appeared in search).
- WebFetch allowlist refused unseen URLs: onlyfm252.starlabs.sg root, KernelSight pages for CVE-2024-38256, CVE-2025-24983, CVE-2024-49114, CVE-2025-62221, 0patch blog.0patch.com Kerberos redirect target. originhq.com patch-diffing-pipeline returned a stub with no body.
- Not read: Black Hat USA 2021 spooler PDF, codeblue 2024 Angelboy PDF, devco.re kernel streaming post (surfaced in search only).

## Searches run and what each yielded

- gh search repos (REST): patch diff CVE windows, ghidriff, patch tuesday diff, patch-diffs windows, winbindex, 1-day / n-day kernel analysis, bindiff CVE driver. Yielded the repo list below; no per-CVE function files readable. gh search code: returned unrelated trickest/cve and pocindex markdown only.
- Web: mskssrv (found KernelSight and the onlyfm252 diff set), cldflt (StarLabs blog, diff md), ksecdd (nothing; ksecdd only appears as a called function in CVE-2025-33073), Zerologon (0patch gave functions), tcpip CVE-2024-38063 (gist, MalwareTech), win32k modern (Core 21882 only; 2023-2025 win32k pages named vulnerable functions only), BlueKeep, DejaBlue, SIGRed, SMBGhost, NTLM relay, Kerberos (all pages micropatch-only), spooler (functions only for vulnerable code or ZDI), RPC runtime CVE-2022-26809 (Akamai pages returned landing page only), SPNEGO CVE-2022-37958 (news only).
- Remaining gaps with no valid case: ksecdd.sys, Kerberos client/KDC beyond the existing kdcsvc case, print spooler (non-ZDI), modern win32k (2023-2025) with a named patched function.

## Reusable diff repos and sites (licence as shown by search or page)

| Resource | What | Licence | Per-CVE changed-function output |
|---|---|---|---|
| clearbluejar/ghidriff | Ghidra diff engine; emits Markdown, HTML, JSON | GPL-3.0 | tool, yes (JSON/MD per run) |
| originsec/patchwatch | ingests Patch Tuesday CVEs, diffs with ghidriff | Apache-2.0 | likely; repo unreadable |
| ByteRay-AI/drift-corpus | "repository of Windows Kernel patch diffs" | CC-BY-4.0 (search metadata) | unreadable |
| Shellpecker/winsight | CVE to patched/unpatched binary and builds via MSRC, Winbindex, ZDI | MIT (README) | no, binaries only |
| m417z/winbindex | index of Windows binaries and download links | GPL-3.0 | no |
| ergrelet/windiff | symbol/type/syscall diffs across OS builds | not shown | no, not per CVE |
| kernelstub/Cognitor | Patch Tuesday semantic diff CLI | GPL-3.0 | unread |
| ghidriff-bot/winbindex-diffs, T-RN-R/PatchDiffWednesday | diff collections | none listed | unreadable |
| onlyfm252.starlabs.sg/data/patch_diffs/*.md | per-CVE ghidriff or disassembly reports, with RCA files | none stated | yes, per KB; provenance unclear (subdomain not confirmed as StarLabs-run, some reports look machine-generated) |
| splintersfury.github.io/KernelSight | dated case studies with affected and fixed functions | none stated | no raw output; Affected Functions are vulnerable-side |

Reference-only use throughout: no bulk data copied.
