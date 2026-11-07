# Windows L3 candidate pins (before/after builds)

Pins file: `docs/research/accuracy-cases/windows-pins.json` (schema `rq-win-pins/1`). Validator: `tools/research_qualification/pins_check.py`. Data fetched 2026-11-07 from Winbindex (`https://winbindex.m417z.com/data/by_filename_compressed/<file>.json.gz`, the per-entry `source.url`). Stacks on PR #271 (`winpairs.py`). No existing file or case manifest was edited.

## Result

- Cases covered: 31 (14 in windows-candidates.json, 5 in windows-candidates-sources.json, 12 in windows-candidates-github.json).
- Pinned: 26. Unpinned: 5.
- Pinned and fetchable end to end (msdl symbol-key download hashes to the pinned sha256 on both sides): 18. One side only: 3. Neither side: 5.

## Method

1. Winbindex per-file JSON is the authority: sha256 key, `fileInfo.timestamp`, `fileInfo.virtualSize`, `fileInfo.version`, `windowsVersions[ver][KB].updateInfo.releaseDate`. Only x64 (machineType 0x8664) rows with integer timestamp and virtualSize and a non-empty version are considered.
2. After build: the single x64 sha256 listed for the fix update, either the KB or version the case names, or else the Patch Tuesday (second Tuesday) of the month the case names. Several distinct shas in one update for one Windows version means that version is skipped.
3. Before build: the case-named build when the case gives a version or KB, otherwise the single x64 sha256 in the newest earlier update for the same Windows version. When no earlier update lists the file, the RTM install-media row (Winbindex `BASE`) is used and flagged as inferred.
4. A pair is accepted only if sha256 and dotted file version both differ. Windows versions are tried newest first (22H2, 11 24H2/25H2/23H2/22H2, then older 10 and 11 labels). Candidates whose msdl download hashes to the pinned sha256 on both sides are preferred over the newest Windows version, so some pins sit on older Windows 10 builds. Windows 10 22H2 and Windows 11 23H2 did not exist for 2019 to 2022 fixes, and the 19041.x binaries are shared by 2004/20H2/21H1/21H2/22H2 labels in Winbindex.
5. `windows_version` is the Winbindex label. `kb` is null and `release_date` null for RTM media rows.
6. `fetch_check`: each pinned side was fetched once from `https://msdl.microsoft.com/download/symbols/<file>/<TIMESTAMP:08X><VIRTUALSIZE:x>/<file>`, hashed, its PE version resource read, then deleted. Nothing was executed and no binary is in the repo.

## Per-case table

| case_id | status | Windows | before | after | fetch (b/a) |
|---|---|---|---|---|---|
| win-cve-2022-34718-tcpip | pinned | 11-21H2 | 10.0.22000.918 KB5016691 | 10.0.22000.978 KB5017328 2022-09-13 | ok/ok |
| win-cve-2022-21907-http | pinned | 11-21H2 | 10.0.22000.348 KB5008215 | 10.0.22000.434 KB5009566 2022-01-11 | no/ok |
| win-cve-2023-21768-afd | pinned | 11-22H2 | 10.0.22621.608 KB5021255 | 10.0.22621.1105 KB5022303 2023-01-10 | no/no |
| win-cve-2025-60719-afd | pinned | 11-24H2 | 10.0.26100.6899 KB5066835 | 10.0.26100.7171 KB5068861 2025-11-11 | ok/ok |
| win-cve-2023-28252-clfs | pinned | 11-22H2 | 10.0.22621.1265 KB5023706 | 10.0.22621.1555 KB5025239 2023-04-11 | no/no |
| win-cve-2022-24521-clfs | pinned | 1607 | 10.0.14393.5006 KB5011495 | 10.0.14393.5066 KB5012596 2022-04-12 | ok/ok |
| win-cve-2020-17096-ntfs | pinned | 1903 | 10.0.18362.1171 KB4586786 | 10.0.18362.1256 KB4592449 2020-12-08 | ok/ok |
| win-cve-2022-32230-srv2 | unpinned | | | | |
| win-cve-2025-47987-tspkg | pinned | 11-24H2 | 10.0.26100.3624 KB5060842 | 10.0.26100.4652 KB5062553 2025-07-08 | ok/ok |
| win-cve-2024-30051-dwmcore | pinned | 11-22H2 | 10.0.22621.3527 KB5036980 | 10.0.22621.3593 KB5037771 2024-05-14 | ok/ok |
| win-cve-2023-36802-mskssrv | pinned | 11-22H2 | 10.0.22621.1848 KB5029263 | 10.0.22621.2283 KB5030219 2023-09-12 | no/no |
| win-cve-2023-28244-kdcsvc | unpinned | | | | |
| win-cve-2019-1436-win32kfull | pinned | 1903 | 10.0.18362.449 KB4522355 | 10.0.18362.476 KB4524570 2019-11-12 | ok/ok |
| win-cve-2024-30088-ntoskrnl | pinned | 11-22H2 | 10.0.22621.3672 KB5037853 | 10.0.22621.3733 KB5039212 2024-06-11 | ok/ok |
| win-cve-2019-1184-coreshellextframework | pinned | 1903 | 10.0.18362.1 RTM | 10.0.18362.295 KB4512508 2019-08-13 | no/no |
| win-cve-2020-0729-structuredquery | pinned | 1803 | 7.0.17134.1246 KB4534293 | 7.0.17134.1304 KB4537762 2020-02-11 | ok/ok |
| win-cve-2020-0792-win32kfull | pinned | 1903 | 10.0.18362.628 KB4532695 | 10.0.18362.657 KB4532693 2020-02-11 | ok/ok |
| win-cve-2021-27077-win32kbase | pinned | 1909 | 10.0.18362.1411 KB4601380 | 10.0.18362.1440 KB5000808 2021-03-09 | ok/ok |
| win-cve-2019-9512-http | pinned | 1809 | 10.0.17763.404 KB4507469 | 10.0.17763.678 KB4511553 2019-08-13 | ok/ok |
| win-cve-2024-38063-tcpip | pinned | 11-24H2 | 10.0.26100.1301 KB5040529 | 10.0.26100.1455 KB5041571 2024-08-13 | ok/ok |
| win-cve-2019-0708-termdd | unpinned | | | | |
| win-cve-2019-1181-rdpbase | pinned | 1903 | 10.0.18362.1 RTM | 10.0.18362.295 KB4512508 2019-08-13 | no/ok |
| win-cve-2020-1350-dns | pinned | 1809 | 10.0.17763.1075 KB4561608 | 10.0.17763.1339 KB4558998 2020-07-14 | ok/ok |
| win-cve-2020-1472-netlogon | pinned | 1903 | 10.0.18362.752 KB4565483 | 10.0.18362.1016 KB4565351 2020-08-11 | ok/ok |
| win-cve-2025-33073-mrxsmb | unpinned | | | | |
| win-cve-2023-29360-mskssrv | pinned | 11-22H2 | 10.0.22621.1 RTM | 10.0.22621.1848 KB5027231 2023-06-13 | no/no |
| win-cve-2024-30085-cldflt | pinned | 21H2 | 10.0.19041.4412 KB5037768 | 10.0.19041.4522 KB5039211 2024-06-11 | no/ok |
| win-cve-2025-55680-cldflt | pinned | 11-24H2 | 10.0.26100.6725 KB5065789 | 10.0.26100.6899 KB5066835 2025-10-14 | ok/ok |
| win-cve-2024-38106-ntoskrnl | unpinned | | | | |
| win-cve-2022-21882-win32kfull | pinned | 1507 | 10.0.10240.19119 KB5008230 | 10.0.10240.19177 KB5009585 2022-01-11 | ok/ok |
| win-cve-2025-60705-csc | pinned | 11-24H2 | 10.0.26100.5074 KB5066835 | 10.0.26100.7171 KB5068861 2025-11-11 | ok/ok |

## Unpinned and why

- `win-cve-2022-32230-srv2`: Winbindex lists the identical srv2.sys (same sha256 and file version) in the March 2022 and April 2022 updates on every Windows version that has rows, so the case's April 2022 silent fix is not observable as a file change; the actual fixing build is not identified from this data
- `win-cve-2023-28244-kdcsvc`: case gives no fix month, KB or build ('pre-patch' / 'month not stated'); not inferred. Pin once the case names the Patch Tuesday or KB
- `win-cve-2019-0708-termdd`: termdd.sys is absent from Winbindex (HTTP 404 for by_filename_compressed/termdd.sys.json.gz at fetch time); the case's May 2019 pair targets Windows 7 / Server 2008 R2 era builds that Winbindex does not index
- `win-cve-2025-33073-mrxsmb`: case gives no fix month, KB or build ('month not stated'); not inferred. Pin once the case names the Patch Tuesday or KB
- `win-cve-2024-38106-ntoskrnl`: case names the September 2024 update (KB5043076, 10.0.22621.4169) as the fixed build, but CVE-2024-38106 is listed in the August 2024 Patch Tuesday (per web search results from StarLabs / Ivanti / Tenable pages, not an MSRC page read). A KB5043076 pair would start after the fix, so it is not pinned. Candidate to confirm against MSRC: Windows 11 22H2 x64 10.0.22621.3958 (KB5040527) -> 10.0.22621.4036 (KB5041585, 2024-08-13); not recorded as a pin

## Findings worth knowing

- The msdl symbol key (PE timestamp + SizeOfImage) is not unique per Winbindex sha256. In 8 pinned pairs at least one side downloads a different binary with the same timestamp and SizeOfImage (often another servicing or Insider build, for example afd.sys 10.0.23414.1000 for the 22621.1105 pin). The pinned sha256 is still the Winbindex identity; the msdl bytes are a code-identical-by-key but not byte-identical file. Per-side details are in each entry's `caveats` and `fetch_check`.
- This explains the two mskssrv.sys cases. Winbindex says 10.0.22621.1 and 10.0.22621.1848 for the pinned shas, while the msdl downloads carry PE file versions 10.0.22621.1774 and 10.0.22621.2050, which are exactly the values quoted in the case notes for win-cve-2023-29360-mskssrv. Both are recorded as pinned on the Winbindex shas with that caveat.
- win-cve-2024-38106-ntoskrnl: the case names the September 2024 KB5043076 as the fixed build, but web search results list the CVE under the August 2024 Patch Tuesday. Left unpinned; the candidate August pair is in the reason text. The case author should reconcile.
- Pairs where the case-named before build is not the immediate predecessor (win-cve-2025-60719-afd, win-cve-2019-1181-rdpbase) keep the case-named build and say so in `caveats`.
- win-cve-2020-1350-dns and win-cve-2020-1472-netlogon name Windows Server 2012 R2 / 2012, which Winbindex does not index. They are pinned on Windows 10 1809 / 1903 x64 instead, with a caveat that the function name is not confirmed in that pair.
- Where the before side is a non-Patch-Tuesday preview build or RTM media, `caveats` says so.

## Using the pins with PR #271 (`winpairs.py`)

`winpairs.py` reads `rq-case-manifest/1` (`cases[].id`, `older`, `newer` with keys `file`, `version`, `kb`, `sha256`, `month`, `machine`). It does not read `rq-win-pins/1` directly, and the field names differ (`case_id`, `before`/`after`, `arch`). No file of #271 was edited. Bridge with the validator:

```
python -m tools.research_qualification.pins_check --pins docs/research/accuracy-cases/windows-pins.json --emit-case-manifest /tmp/pins-cases.json
python -m tools.research_qualification.winpairs --manifest /tmp/pins-cases.json --out-dir /tmp/pairs --pair-manifest /tmp/pairs.json
```

Mapping: `case_id` to `id`; `before`/`after` to `older`/`newer`; `file`, `version`, `sha256` copied; `arch` to `machine` (`amd64`); `kb` copied when non-null; `release_date[:7]` to `month`. `timestamp` and `virtual_size` are not inputs, winpairs re-derives them from Winbindex and they must equal the pins (a test asserts this against a synthetic index). Mismatches to be aware of:
- winpairs fails a side with `sha256 mismatch against Winbindex` when the msdl bytes differ from the expected sha256. Every side marked `no` in the table above will therefore end as `missing` in the pair manifest. Use only pins whose `fetch_check` matches both sides for automatic fetching, or add an explicit opt-in to accept key-matched binaries in a follow-up to #271.
- Pins with `kb: null` (RTM media) rely on the sha256 and version only.
- `--resolve-only` works for all 26 pinned entries regardless of fetchability.

Cross-check against the manifests (extract them with `git show` from the three research branches):

```
python -m tools.research_qualification.pins_check --pins docs/research/accuracy-cases/windows-pins.json --manifest windows-candidates.json --manifest windows-candidates-sources.json --manifest windows-candidates-github.json
```

## Unverified

- That each pinned after build actually contains the fix, and that the before build is vulnerable. The pairing rests on the month, KB or version in each case plus a changed file version; it is not confirmed by diffing. The fix months in the cases were not independently checked against MSRC, except CVE-2024-38106 (web search only).
- That the case's expected function exists and changed in the netlogon and dns pairs (different OS from the case ref).
- Winbindex completeness: an absent row is read as unchanged-since-previous only where stated in `caveats`; rows with a missing file version were excluded.
- Winbindex `fileInfo.version` strings versus the PE version resource differ for the unsigned rows noted above; the PE values were read only for fetched binaries.
- `generated`/`fetched` dates are 2026-11-07 per the shell clock.
