# Windows fixed-function candidates (L3)

Research date 2026-11-06. Companion manifest: `windows-candidates.json` (schema `rq-case-manifest/1`). All cases are `facts: unverified` because binaries are not hash-checked yet. Function names below are as stated by the cited page; each page was read in full by the research pass. No write-up text is copied. Marked holdout: every third case by order of the manifest (re-derived after removing CVE-2020-0796; the Holdout column of the table is superseded by the JSON). Cases whose fix touched several functions, or renamed one, list the extra names in `expected.accept`; the scorer counts the best-ranked listed name. Cases from the unknown-author aggregator carry a LOW-TRUST note in the JSON.

| # | CVE | Binary | Month | Fixed function (per source) | Source | Fix type | Confidence | Holdout |
|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2022-34718 | tcpip.sys | 2022-Sep | `Ipv6pReassembleDatagram` | [link](https://www.ibm.com/think/x-force/dissecting-exploiting-tcp-ip-rce-vulnerability-evilesp) | bounds check + ESP next-header check | high | no |
| 2 | CVE-2022-21907 | http.sys | 2022-Jan | `UlFastSendHttpResponse` | [link](https://piffd0s.medium.com/patch-diffing-cve-2022-21907-b739f4108eee) | unclear (zeroing/state clear, author unsure) | medium | no |
| 3 | CVE-2023-21768 | afd.sys | 2023-Jan | `AfdNotifyRemoveIoCompletion` | [link](https://www.ibm.com/think/x-force/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock) | added ProbeForWrite/PreviousMode check | high | yes |
| 4 | CVE-2025-60719 | afd.sys | not stated (2025) | `AfdGetInformation` | [link](https://www.akamai.com/blog/security-research/2025/dec/inside-fix-ai-root-cause-analysis-cve-2025-60719) | unbind synchronisation (race/UAF) | medium | no |
| 5 | CVE-2023-28252 | clfs.sys | 2023-Apr | `CClfsBaseFile::GetControlRecord` | [link](https://onlyfm252.starlabs.sg/data/patch_diffs/rca-cve-2023-28252.md) | range checks, return-value check | medium-low | no |
| 6 | CVE-2022-24521 | clfs.sys | 2022-Apr | `LoadContainerQ` | [link](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-24521.html) | offset validation | high | yes |
| 7 | CVE-2020-17096 | ntfs.sys | 2020-Dec | `NtfsOffloadRead` | [link](https://www.jamf.com/blog/ntfs-remote-code-execution-cve-2020-17096-analysis/) | IrpContext argument fix | high | no |
| 8 | CVE-2022-32230 | srv2.sys | 2022-Apr (silent) | `Smb2ValidateVolumeObjectsMatch` | [link](https://www.rapid7.com/blog/post/2022/06/14/cve-2022-32230-windows-smb-denial-of-service-vulnerability-fixed/) | null check | medium | no |
| 10 | CVE-2025-47987 | tspkg.dll | 2025-Jul | `TSCreateKerbCertLogonBuffer` | [link](https://kryptoenix.github.io/blog/demystifying-CVE-2025-47987) | checked integer add | high | no |
| 11 | CVE-2024-30051 | dwmcore.dll | 2024-May | `CCommandBuffer::Initialize` | [link](https://onlyfm252.starlabs.sg/data/patch_diffs/rca-cve-2024-30051.md) | size consistency + validation | medium-low | no |
| 12 | CVE-2023-36802 | mskssrv.sys | 2023-Sep (inferred) | `FSRendezvousServer::FindObject` | [link](https://onlyfm252.starlabs.sg/data/patch_diffs/mskssrv_sys-kb5030219.md) | object type check | medium-low | yes |
| 13 | CVE-2023-28244 | kdcsvc.dll | not stated | `KerbGetEncTypeBitmask` | [link](https://0patch.com/blog/we-patched-cve-2023-28244-before-anyone) | validation removal for weak enctypes | medium | no |
| 14 | CVE-2019-1436 | win32kfull.sys | 2019-Nov | `NtGdiEnsureDpiDepDefaultGuiFontForPlateau` | [link](https://versprite.com/vs-labs/silently-patched-information-leak/) | returns 0 (info leak) | medium | no |
| 15 | CVE-2024-30088 | ntoskrnl.exe | 2024-Jun (one source) | `AuthzBasepCopyoutInternalSecurityAttributes` | [link](https://splintersfury.github.io/KernelSight/case-studies/CVE-2024-30088) | lock around check-and-copy (TOCTOU) | medium-low | yes |

Confidence reflects how directly the page shows a before/after change in that function, not whether the CVE is real. Pages on `onlyfm252.starlabs.sg` are an aggregator whose authorship I could not establish and whose pages carry 2026 report timestamps; treat as single-source. Corroborating links: CVE-2023-21768 also at [clearbluejar ghidriff guide](https://clearbluejar.github.io/ghidriff/docs/guides/Diffing%20afd.sys%20-%20CVE-2023-21768) and [starlabs diff](https://onlyfm252.starlabs.sg/data/patch_diffs/afd_sys-kb5022303.md); CVE-2025-47987 also at [0patch](https://0patch.com/blog/micropatches-released-for-credential-security-support-provider-protocol-credssp-e) (fix type only); CVE-2024-30088 also at [gengstah](https://gengstah.github.io/wiki/cves/CVE-2024-30088/).

## Read but not usable as cases

- CVE-2024-38063 tcpip.sys (Aug 2024): [BI.ZONE](https://bi.zone/eng/expertise/blog/analiz-kriticheskoy-uyazvimosti-windows-cve-2024-38063/) and [ynwarcs](https://github.com/ynwarcs/CVE-2024-38063) were read. Neither names the function Microsoft changed. ynwarcs lists functions involved in the bug (Ipv6pReceiveDestinationOptions, Ipv6pProcessOptions, IppSendErrorList, IppSendError, Ipv6pReceiveFragment, Ipv6pReassembleDatagram, Ipv6pReassemblyTimeout) and says patched 13 Aug 2024. Skipped; also tcpip.sys is already used once.
- CVE-2024-38193 afd.sys: [KernelSight](https://splintersfury.github.io/KernelSight/case-studies/CVE-2024-38193) names AfdRioDeregisterBuffer and AfdRioCloseCompletion but gives no month and contradicts itself on KB (KB5041585 vs KB5040442). Excluded to keep afd.sys at two cases; could replace CVE-2025-60719.
- CVE-2025-29824 clfs.sys: [clearbluejar](https://clearbluejar.github.io/posts/how-llms-feed-your-re-habit-following-the-uaf-trail-in-clfs/) names no patched function.
- CVE-2024-21338 appid.sys: [starlabs diff](https://onlyfm252.starlabs.sg/data/patch_diffs/appid_sys-kb5034765.md) shows AipDeviceIoControlDispatch as the only changed function, but gives no month or KB and does not call it a security fix. Candidate if a third independent component is wanted.
- CVE-2023-29361 cldflt.sys: [Richard Osgood](https://www.richardosgood.com/posts/windows-patch-diffing/) names no changed function.
- Telephony tapi32/tapi3: [SecureLayer7](https://blog.securelayer7.net/windows-telephony-services-2025-patch-diffing-and-analysis-pt-2/) names changed functions (GrowBuf, lineDevSpecific and others) but no CVE.
- Unit 42 win32k part 1: covers CVE-2022-21882 / CVE-2021-1732 but names no patched function.

## Contradictions and warnings

- CVE-2024-30088: KernelSight says lock added in AuthzBasepCopyoutInternalSecurityAttributes; gengstah names the same function as vulnerable but says nothing on what was changed. Month only from gengstah.
- CVE-2023-21768: build numbers differ between sources (IBM and starlabs: 22621.608 vs 22621.1105; clearbluejar: 22621.1028 vs 22621.1415). Starlabs diff also shows inconsistent file version metadata.
- CVE-2024-38193 (KernelSight): two KBs for one build.
- CVE-2020-17096 (Jamf): the stated day looks inconsistent with Patch Tuesday; month Dec 2020 taken as is.
- CVE-2020-0796: srv2.sys `Srv2DecompressData` is named as the vulnerable function but the page shows no diff, so it was removed from the manifest (no ground truth for a changed function).

## Could not read

- Elastic Security Labs, `https://www.elastic.co/security-labs/patch-diff-to-system`: refused (not on the fetch allowlist). Not worked around.
- `https://github.com/VulnerabilityResearchCentre/patch-diffing-in-the-dark/...CVE-2021-1657.md`: fetch error (server error). Not retried via other routes.

## Gaps

No Win32k case from a modern kernel write-up, no ksecdd.sys, no RDP service (only tspkg), no NTLM case. Search results for those were mostly vendor news pages.
