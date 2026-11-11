# Windows L3 candidates from named sources (2026-11-07)

Companion to `windows-candidates.json` (PR #260). Same rules: every fact is `unverified` in the manifest; the table records what each cited page said when read. CVEs already in the PR #260 manifest are not repeated. Max 2 cases per binary (this file adds 1 each).

Validator note: `expected.accept` is only allowed by the `cases.py` change in PR #260. On current `main` the validator rejects it (`expected has unknown keys`) for the two cases that use it. Validated OK with the PR #260 `tools/research_qualification`; merge #260 first.

## Cases

| CVE | Binary | Month | Function (expected) | Source | Fix type | Confidence |
|---|---|---|---|---|---|---|
| CVE-2019-1184 | CoreShellExtFramework.dll | 2019-Aug | CoreShellComServerRegistrarFactory::HasRequiredPermissions | [ZDI](https://www.zerodayinitiative.com/blog/2019/12/19/privilege-escalation-via-the-core-shell-com-registrar-object) | permission check added, descriptor loosened | high |
| CVE-2020-0729 | StructuredQuery.dll | 2020-Feb | StructuredQuery1::ReadPROPVARIANT | [ZDI](https://www.zerodayinitiative.com/blog/2020/3/25/cve-2020-0729-remote-code-execution-through-lnk-files) | buffer zero-fill, only changed function in diff | high |
| CVE-2020-0792 | win32kfull.sys | 2020-Feb | NtUserResolveDesktopForWOW | [ZDI](https://www.zerodayinitiative.com/blog/2020/5/7/how-a-deceptive-assert-caused-a-critical-windows-kernel-vulnerability) | raise exception on bad Length instead of continuing | medium |
| CVE-2019-9512 | http.sys | 2019-Aug (year inferred) | UxDuoParsePing (accept UxDuoApplyPingFrameDosPrevention) | [ZDI](https://www.zerodayinitiative.com/blog/2019/12/4/cve-2019-9512-a-microsoft-windows-http2-ping-flood-denial-of-service) | rate limit added (new helper + call) | medium |
| CVE-2021-27077 | win32kbase.sys | 2021-Mar | bIsSurfaceAllowedInDC (accept UMPDAllowPrinterSurfaceInDisplayDC) | [ZDI](https://www.zerodayinitiative.com/blog/2021/7/26/cve-2021-27077-selecting-bitmaps-into-mismatched-device-contexts) | new guard functions added, caller unnamed | low |

No KB number was stated on any cited page. Older refs are the month before the patch month.

## Contradictions and caveats

- CVE-2019-1184: the August 2019 change was reverted in October 2019 (page says all August changes to the DLL were backed out and the Low label became Medium, no functions named). Use Jul to Aug pair only.
- CVE-2021-27077: page says the patch was not a validation fix in `win32kfull!MulTextOut`, which is the exploitation target. Do not accept MulTextOut.
- CVE-2020-0792: page also mentions `xxxResolveDesktopForWOW`; not stated as changed, not accepted.
- ZDI print spooler post (below): its own text gives July for the CVE-2020-1337 analysis and "August patches" in the intro; unresolved on the page.

## Excluded (source read, no changed function named)

| CVE / topic | Binary | Why excluded | Source |
|---|---|---|---|
| CVE-2020-1048 and CVE-2020-1337 spooler | localspl.dll | page names only functions called by added code (IsValidNamedPipeOrCustomPort, PortIsValid, GetFinalPathNameByHandleW, GetFileInformationByHandle); the modified function is unnamed | [ZDI](https://www.thezdi.com/blog/2020/8/11/windows-print-spooler-patch-bypass-re-enables-persistent-backdoor) |
| CVE-2021-26900 | win32kbase.sys | fix spans add/modify/release paths; only CleanUpListItemsPendingDeletion named in patch discussion and it is described as the release path, other changed functions unnamed. Closest to valid; revisit if a second source names them | [ZDI](https://www.zerodayinitiative.com/blog/2021/5/3/cve-2021-26900-privilege-escalation-via-a-use-after-free-vulnerability-in-win32k) |
| CVE-2026-47291 | http.sys | vulnerable path only (UlpParseNextRequest, UlpCopyIndicatedData, UlpMergeBuffers, UlpAdjustBuffers); fix not described | [ZDI](https://www.zerodayinitiative.com/blog/2026/7/9/cve-2026-47291-remote-code-execution-in-the-windows-httpsys) |
| CVE-2026-33824 | IKEEXT.DLL | vulnerable path only (IkeReinjectReassembledPacket etc.); fix not described | [ZDI](https://www.zerodayinitiative.com/blog/2026/4/22/cve-2026-33824-remote-code-execution-in-windows-ikev2) |
| CVE-2021-31166 | http.sys | vulnerable only (UlpParseAcceptEncoding etc.) | [ZDI](https://www.zerodayinitiative.com/blog/2021/5/17/cve-2021-31166-a-wormable-code-execution-bug-in-httpsys) |
| CVE-2023-24941 | nfssvr.sys | vulnerable only (XdrDecodeString, Nfs4SvrXdrpDecode_STRING) | [ZDI](https://www.zerodayinitiative.com/blog/2023/5/31/cve-2023-24941-microsoft-network-file-system-remote-code-execution) |
| CVE-2022-34715 | nfssvr.sys | vulnerable only (Nfs4SrvAclBuildWindowsAclsFromNfsAcl, NfsMemMgrBufferAllocate) | [ZDI](https://www.zerodayinitiative.com/blog/2022/8/31/cve-2022-34715-more-microsoft-windows-nfs-v4-remote-code-execution) |
| CVE-2022-30136 | nfssvr.sys | vulnerable only, no binary named | [ZDI](https://www.zerodayinitiative.com/blog/2022/7/13/cve-2022-30136-microsoft-windows-network-file-system-v4-remote-code-execution-vulnerability) |
| CVE-2023-28231 | dhcpssvc.dll | vulnerable only (ProcessRelayForwardMessage) | [ZDI](https://www.zerodayinitiative.com/blog/2023/5/1/cve-2023-28231-rce-in-the-microsoft-windows-dhcpv6-service) |
| CVE-2021-31969 | cldflt.sys | fix described (length check) but function unnamed | [ZDI](https://www.zerodayinitiative.com/blog/2021/7/19/cve-2021-31969-underflowing-in-the-clouds) |
| CVE-2019-1362 | win32k.sys | vulnerable only (CreateSurfacePal) | [ZDI](https://www.zerodayinitiative.com/blog/2019/12/16/local-privilege-escalation-in-win32ksys-through-indexed-color-palettes) |
| CVE-2020-1300 | localspl.dll | vulnerable only (NCabbingLibrary::FdiCabNotify), no fix detail | [ZDI](https://www.zerodayinitiative.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files) |
| CVE-2020-16939 | gpsvc | no function, binary or fix named | [ZDI](https://www.zerodayinitiative.com/blog/2020/10/27/cve-2020-16939-windows-group-policy-dacl-overwrite-privilege-escalation) |
| CVE-2024-20697 | libarchive | vulnerable only (execute_filter_e8) | [ZDI](https://www.zerodayinitiative.com/blog/2024/4/17/cve-2024-20697-windows-libarchive-remote-code-execution-vulnerability) |
| CVE-2024-38213 | n/a | no function named | [ZDI](https://www.zerodayinitiative.com/blog/2024/8/14/cve-2024-38213-copy2pwn-exploit-evades-windows-web-protections) |
| ZDI-CAN-12671 | win32kfull.sys | unpatched when written (BLTRECORD::bRotate vulnerable only), no CVE | [ZDI](https://www.zerodayinitiative.com/blog/2021/1/27/zdi-can-12671-windows-kernel-dosprivilege-escalation-via-a-null-pointer-deref) |
| (fuzzing post) | oleaut32/gdi32 | not serviced, no CVE | [ZDI](https://www.zerodayinitiative.com/blog/2019/10/31/the-little-bitmap-that-couldnt) |
| CVE-2022-37969 | clfs.sys | not an assigned source; Zscaler page names vulnerable CLFS functions only, not the patched one | [Zscaler](https://www.zscaler.com/blogs/security-research/technical-analysis-zero-day-vulnerability-cve-2022-37969-part-1-root-cause) |

## Could not read

- textfiles.com: fetch refused (`robots_disallowed`). Not worked around.
- phrack.org (`/issues.html`): not on the session allowlist. Not retried.
- packetstormsecurity.com search page: not on the session allowlist. Not retried. www.packetstorm.news not fetched. Search-engine results for it surfaced only MS bulletin summaries, which do not name functions.
- exploitreversing.com PDF (`exploit_reversing_02-2.pdf`): not on the session allowlist.
- reverseengineering.stackexchange.com (question 6228): site blocked.
- rapid7.com blog post `2020/02/04/doublepulsar-rce-2-an-rdp-story`: fetch was stopped by a cyber safeguard on the fetch helper. Not retried.
- attackerkb.com: not on the session allowlist.

## Sources searched and what each yielded

- phreedom.org PDF: read (WebFetch loops between http and https redirects, so it was downloaded with plain curl from the exact http URL given; 359 KB). It is a 2000s-era talk on how to build a Windows binary database and use BinDiff. Mentions MS03-007 only as a sample database row (ntdll.dll). No patch-diff case study, no named changed function. Nothing usable.
- zerodayinitiative.com/blog: read the Research-tag archive back to Dec 2019 (about 10 pages) plus the Microsoft tag; fetched 21 Windows-related posts. 5 valid cases, 17 excluded (table above; most ZDI write-ups name the vulnerable code, not the diff). Site-limited WebSearch did not return ZDI pages reliably; the tag archive was the working route. Monthly Security Update Reviews were not read for functions (they do not name them).
- rapid7.com: blog index readable, no relevant posts found; Rapid7 DB vulnerability pages only appear in search results and are description-level (no functions). Zero cases.
- packetstorm, textfiles, phrack, exploitreversing, RE.SE: unreadable (above). Zero cases.
- Gap components requested but not yielded by these sources: ksecdd.sys, NTLM, Kerberos, RDP, SMB/srv2, CLFS, afd, ntfs, DNS, Netlogon, mshtml/jscript.
