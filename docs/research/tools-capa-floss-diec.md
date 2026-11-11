# Research: capa, FLOSS and Detect It Easy (diec), current versions and release facts

Status: research note, no code. Date of research: 2026-10-15. Every fact carries a source URL and the date accessed (2026-10-15 unless the row says otherwise). Items marked **[U]** are unverified: the reason is given. Repository facts are cited as `[repo]` with the file and the date the source plan recorded them (2026-10-14). The sandbox cannot reach `api.github.com`, `doc.qt.io` or `learn.microsoft.com` (403 or DNS), so GitHub's own per-asset digest field could not be read.

Abbreviations: PyPI = `https://pypi.org/pypi/<name>/json`; capa = `https://github.com/mandiant/capa`; FLOSS = `https://github.com/mandiant/flare-floss`; DIE = `https://github.com/horsicq/DIE-engine`; DIE data = `https://github.com/horsicq/Detect-It-Easy`.

## Current versions and assets

| tool | latest stable (2026-10-15) | evidence |
| --- | --- | --- |
| capa | **9.4.0** (PyPI upload 2026-04-01T09:03Z; GitHub release "01 Apr 09:30") | PyPI JSON (`flare-capa`), `https://github.com/mandiant/capa/releases/latest`; both 2026-10-15 |
| FLOSS | **3.1.1** (PyPI and GitHub release 2024-09-26). No newer tag on PyPI | PyPI JSON (`flare-floss`); `https://github.com/mandiant/flare-floss/releases/tag/v3.1.1`; both 2026-10-15 |
| DIE (diec) | **3.21** (GitHub "Latest"; changelog "3.21 (2026-04-22)") | `https://github.com/horsicq/DIE-engine/releases`; `https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/changelog.txt`; 2026-10-15 |

Other DIE facts:
- The changelog on `master` has a **4.0.0** entry at the top, undated. It replaces Qt Script by a custom DiE-JS engine, adds a new PE heuristic module and "false-signature countermeasures" (changelog, 2026-10-15). The GitHub releases page shows no 4.0.0 tag, so 4.0.0 is unreleased as of this date. Its output will differ from 3.21: keep the 3.21 pin.
- Releases page order (2026-10-15): 3.21 "Latest" (21 Apr), 3.20, a "Pre-release" Beta (3 Jun), 3.10 (3 Nov 2024 per changelog). Years are not shown on the page; the changelog gives 3.20 (2026-04-20) and 3.10 (2024-11-03).
- 3.21 asset names (page, 2026-10-15): `die_win64_portable_3.21_x64.zip`, `die_win32_portable_3.21_x86.zip`, `die_winxp_portable_3.21_x86.zip`, `die_3.21_Ubuntu_22.04_amd64.deb` (also 16.04, 20.04, 24.04, 26.04, Debian 10-13, Kali 2026.1), `die_3.21_portable_Ubuntu_20.04_amd64.tar.gz`, `Detect_It_Easy-3.21-x86_64.AppImage`, `detect-it-easy-3.21-1-x86_64.pkg.tar.zst`, macOS pkg/zip, `die_sourcecode_3.21.tar.gz`. The page says 22 assets; 20 names are visible. The two extra are most likely GitHub's automatic source archives [U]. The page shows **no sizes and no digests**.
- capa 9.4.0 release page says "Assets 8", with the file list failing to load. The repo plan lists six build-workflow assets (linux, linux-arm64, linux-py312, windows, macos, macos-arm64) [repo: CAP row 5, 2026-10-14]. Two more is consistent with GitHub's automatic source archives [U].
- FLOSS 3.1.1 release page says "Assets 5" and the list failed to load (2026-10-15). The repo pins one Windows zip and one Linux zip [repo: WB3 F7, 2026-10-14]; the other three are not named [U].
- capa 9.4.0 assets named in the repo plan (own download, 2026-10-14, not repeated today): `capa-v9.4.0-windows.zip` 35,994,071 B, sha256 `670ab1a5...3bb5`; `capa-v9.4.0-linux.zip` 47,477,971 B, sha256 `07800a1d...81e4`.
- FLOSS 3.1.1 pins (repo WB3 F7, 2026-10-14): `floss-v3.1.1-windows.zip` 31,580,022 B, sha256 `6c71089b...fdac2fb`; `floss-v3.1.1-linux.zip` 40,571,555 B, sha256 `40c05a86...a54666`.
- FLOSS 3.1.1 PyPI files (PyPI JSON, 2026-10-15): wheel `flare_floss-3.1.1-py3-none-any.whl` 15,186,846 B (sha256 prefix `7b57fdc9...`); sdist `flare_floss-3.1.1.tar.gz` 15,343,712 B (sha256 prefix `4f74458b...`). `requires_python >=3.8`; requires `pydantic>=2`, `binary2strings>=0.1`, `vivisect>=1.1.1`.
- capa 9.4.0 PyPI files (PyPI JSON, 2026-10-15): wheel `flare_capa-9.4.0-py3-none-any.whl` 1,207,044 B (sha256 prefix `708188e0...`); sdist `flare_capa-9.4.0.tar.gz` 21,237,530 B (sha256 prefix `c4f421ab...`). `requires_python >=3.10`; requires `pydantic>=2`, `protobuf>=5`, `vivisect>=1.1.1`.
- capa release cadence (PyPI upload dates, 2026-10-15): 9.2.1 2025-06-06, 9.3.0 2025-11-12, 9.3.1 2025-11-20, 9.4.0 2026-04-01. The repo plan (CAP row 1) listed 9.0.0 to 9.3.0 and omitted the 9.2.1 and 9.3.1 patch releases [repo, 2026-10-14].
- FLOSS 3.1.1 release note (2026-10-15): "The v3.1.1 release relaxes restrictions on dependencies, which enables you to use FLOSS with Python 3.12 and newer."

## Licences

| component | licence | evidence |
| --- | --- | --- |
| capa (code) | Apache-2.0 (PyPI `info.license` contains the full Apache 2.0 text; `license_files`: LICENSE.txt) | PyPI `flare-capa`, 2026-10-15 |
| capa-rules | Apache-2.0 (first lines "Apache License / Version 2.0, January 2004") | `https://raw.githubusercontent.com/mandiant/capa-rules/v9.4.0/LICENSE.txt`, 2026-10-15 |
| capa FLIRT signatures (`sigs/`) | Apache-2.0, Mandiant-generated | [repo] CAP row 2, 2026-10-14 (not re-fetched today) |
| FLOSS | Apache-2.0 (PyPI license text and classifier; `license_expression` is null) | PyPI `flare-floss`, 2026-10-15 |
| binary2strings (FLOSS dependency) | MIT (PyPI `info.license`) | PyPI `binary2strings`, 2026-10-15 |
| DIE (code and console) | MIT, "Copyright (c) 2012-2026 hors" | `https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/LICENSE`, 2026-10-15 |
| DIE signature database | **No licence stated.** The README says the database "preserves a large amount of historical material imported from the original PEiD rules" and calls many signatures "noisy by modern standards". Treat as unlicensed for redistribution | `https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/README.md`, 2026-10-15; the DIE plan records the same gap [repo, 2026-10-14] |
| Qt linked by diec 3.21 | Qt 5 (LGPL) [U]: the Qt version is taken from the packaging dependency `libqt5core5a`, which the DIE plan records [repo, 2026-10-14]; the Qt licence text was not fetched | repo DIE plan row 20 |

Bundled-rule licences: capa's rules are Apache-2.0 (above). DIE's database is the unlicensed part. FLOSS bundles vivisect (Apache-2.0 per the PyPI classifier, as recorded by WB3 F2 [repo]).

## JSON schema notes

**capa** (`capa -j`):
- Root: `ResultDocument` with two fields, `meta` and `rules` [capa `capa/render/result_document.py` at tag v9.4.0, read 2026-10-15].
- `Metadata` fields: `timestamp`, `version` (string), `argv`, `sample`, `flavor`, `analysis`. `version` is the only version field; there is **no `schema_version`** [same source]. Pin on `version` plus the executable sha256, not on the document shape.
- Coverage and address fields (`feature_counts.functions`, `library_functions`, `layout.functions[].matched_basic_blocks`, address types) are repo-verified against the 9.4.0 goldens [repo: CAP rows 8-10, 2026-10-14]. Not re-read today.
- Output embeds scratch paths and timestamps (`meta.argv`, `meta.sample.path`, `meta.timestamp`) [repo: CAP plan section 6, 2026-10-14]; compare normalised content, not raw bytes.

**FLOSS** (`floss -j`):
- The usage page documents `-j` only as "Write FLOSS results to stdout structured in JSON", with **no schema and no version field** [`https://raw.githubusercontent.com/mandiant/flare-floss/v3.1.1/doc/usage.md`, 2026-10-15].
- The 3.1.1 result keys and their absence of hashes are repo-verified [repo: WB3 F3, 2026-10-14]. The master branch is ahead of 3.1.1 and changes the schema (tags, layout, `metadata.md5/sha1/sha256`); a master build still reports `__version__` 3.1.1 [repo: WB3 F2, 2026-10-14]. Pin by asset hash, not by "FLOSS 3.x".

**diec** (`diec -j`):
- Root array `detects`; nested header nodes and leaves with `type`, `name`, `version`, `info`, `string` [repo: DIE plan row 28, quoting upstream `scanitemmodel.cpp`, 2026-10-14]. Not re-read today.
- Output is version-sensitive: DIE 4.0.0 changes its engine and heuristics [changelog, 2026-10-15]. Pin 3.21 and reject other versions unless opted in.

## Headless and CLI flags

- **capa**: `-j` selects JSON (no long form in the usage page). `-v` shows nested matches, `-vv` shows how each rule matched, `-t` filters by rule metadata, `--restrict-to-functions` and `--restrict-to-processes` are documented [`https://raw.githubusercontent.com/mandiant/capa/v9.4.0/doc/usage.md`, 2026-10-15]. The usage page does **not** list `-b` (backend), `-r` (rules), `-s` (signatures), `--os`, `--format`, `-q` or any timeout or `-o` option; read them from `capa -h` at the pinned version [U]. The only file write is vivisect's `.viv` cache when `CAPA_SAVE_WORKSPACE` is set [same source]. The page does not document any network access by the CLI.
- **capa exit codes** (verified in `capa/main.py` at v9.4.0, 2026-10-15): 10 missing rules, 11 missing file, 12 invalid rule, 13 corrupt file, 14 file limitation, 15 invalid signature, 16/17/18 unsupported file type/arch/OS, 19 IDA version, 20 Ghidra version, 21/22 CAPE static/dynamic missing, 23 empty report, 24 Ghidra execution mode, 25 input format, 26 feature extractor. The repo plan's map (rows 12) matches [repo, 2026-10-14].
- **FLOSS**: `-j/--json`, `-l/--load`, `-v`, `-q/--quiet`, `-n/--minimum-length` (default 4), `-f/--format` (shellcode `sc32`/`sc64`), `--no {static,decoded,stack,tight}`, `--only {static,decoded,stack,tight}` (cannot be combined with `--no`), `--language`, `--functions` (hex VAs), `-h` and `-H` [`https://raw.githubusercontent.com/mandiant/flare-floss/v3.1.1/doc/usage.md`, 2026-10-15]. The `-L` option and the 16 MiB emulation limit are **not** in the usage page; the repo plan cites them from `floss/main.py` and `const.py` [repo: WB3 F5, 2026-10-14]. Re-read the source before relying on them [U].
- **diec** (3.21 `--help`, repo golden `tests/fixtures/intel_tools/diec/help.stdout.txt`, captured 2026-10-14): `-j/--json`, `-x/--xml`, `-c/--csv`, `-t/--tsv`, `-p/--plaintext`, `-d/--deepscan`, `-u/--heuristicscan`, `-g/--aggressivecscan`, `-a/--alltypes`, `-b/--verbose`, `-D/--database`, `-E/--extradatabase`, `-C/--customdatabase`, `-S/--struct`, `-s/--showdatabase`, `-M/--messages`, `-U/--hideunknown`, `-r` (recursive), `--test`, `--addtest`. Upstream `docs/RUN.md` documents none of them [repo, 2026-10-14]. The DIE plan's `-E` and `-C` must stay empty folders because extra and custom databases are script code [repo, 2026-10-14].

## Gotchas

**Memory and time on large PEs.** No measured numbers for real binaries exist in the sources read today [U].
- capa: the only measurements are repo tests on tiny synthetic PEs, 8.4 to 9.5 s per file, Linux, onefile start included [repo: manifest `elapsed_s`, 2026-10-14]. The repo's own parse of a 27.8 MB document with 20,000 matches took 5.6 s and 745 MiB peak RSS [repo: CAP row 20, 2026-10-14]. Vivisect analysis is not bounded by capa's output limits.
- FLOSS: 1.0 to 1.1 s static on a tiny synthetic file, emulation 5.7 to 6.3 s [repo: WB3 F14, 2026-10-14]. Emulation bounds: 20,000 instructions per function, 10,000 per tight loop, 300 revisits, 100 MB per emulator map [repo: WB3 F6, 2026-10-14]; the analysis phase before emulation is unbounded [repo, same].
- DIE: 0.13 to 0.23 s on 2 to 4 KiB synthetic PEs under `unshare -rn` [repo: DIE plan row 26, 2026-10-14]. DIE's `decompressBytes` inflates in memory, so a decompression bomb is a memory and timeout risk [DIE plan row 25, citing `help/Util.md`, 2026-10-14].

**Failure modes.**
- capa and FLOSS both run on PyInstaller onefile on Windows (FLOSS 3.1.1 Windows bundle includes CPython 3.8.10, which is end of life [repo: WB3 F8, 2026-10-14, measured]). Onefile extracts to `_MEIxxxxxx` and removes it at normal exit, not after a kill [PyInstaller docs v6.22.3 `doc/operating-mode.rst`, 2026-10-14 per WB3 F10].
- capa: packed programs and installers give misleading or incomplete results [`https://raw.githubusercontent.com/mandiant/capa/v9.4.0/doc/limitations.md`, repo CAP row 11, 2026-10-14]; capa does not follow calls.
- DIE: "many signatures are noisy by modern standards and can produce convincing-looking false positives" [DIE README, 2026-10-15]. The DIE plan's heuristic examples (for example `(Heur)Protection: Generic` on plain MinGW) are repo-observed [repo, 2026-10-14].
- DIE database merge: the shipped database is the repo `db` plus every `db_extra/*` folder. The README says `db_extra` rules are "not approved for the main database" [repo: DIE plan row 22, 2026-10-14].

**Hash and signature verification.**
- PyPI publishes sha256 for every file (wheel and sdist). Verified today by reading `digests.sha256` from the JSON API (2026-10-15). These verify the Python packages, not the Windows or Linux binaries.
- The capa, FLOSS and DIE release pages list **no checksum files and no digests** (2026-10-15). The GitHub asset digest field is not reachable from this sandbox [U].
- The release commits are GPG-signed by GitHub's web-flow key `B5690EEEBB952194`; this covers the tagged commit, not the release assets (capa and FLOSS release pages, 2026-10-15).
- capa `capa.exe` in the Windows zip carries no Authenticode signature [repo: CAP row 3, measured 2026-10-14]. DIE Windows zip signature status: [U].
- Practical path: pin the sha256 of each file as downloaded, record the URL and date, and compare with a second network path when one is available. Do not claim upstream attestation.

## Corrections to our plans

1. **WB3 F9 ("FLOSS cannot be pip-installed on Python 3.12")**: the 3.1.1 release note says the release "enables you to use FLOSS with Python 3.12 and newer" (`https://github.com/mandiant/flare-floss/releases/tag/v3.1.1`, 2026-10-15). The statement that `pip --only-binary=:all:` fails still holds, because `binary2strings` 0.1.13 (2023-07-20) ships only a `cp310` Windows wheel and an sdist (PyPI, 2026-10-15). Reword WB3 F9 to say the install succeeds only through an sdist build.
2. **CAP row 1 (capa release cadence)**: add the 9.2.1 (2025-06-06) and 9.3.1 (2025-11-20) patch releases (PyPI, 2026-10-15). The cadence claim "about 2 per year" still holds, with patches.
3. **CAP row 12 and section 7 (exit codes)**: confirmed against `capa/main.py` at v9.4.0 today. Add codes 19 to 22 and 24 to 26 to the error map, since the 9.4.0 source defines them.
4. **DIE plan row 18 (version state)**: confirmed 3.21 as the GitHub "Latest". Add that the changelog already carries an undated 4.0.0 entry with output-changing work, so any pin bump needs a fresh golden run.
5. **DIE plan row 19 (assets)**: the plan's list omits the 32-bit and XP Windows portable zips and the macOS and AppImage assets are named differently. Replace the list with the page's names above.
6. **DIE plan row 43 (licence table)**: the DB has no licence statement at all; the plan says "PEiD-derived data without licence text", which is correct. Keep "never redistribute or commit the DB".
7. **CAP plan `capa -j` (CLI flags)**: correct as written. Note that `--json` is not documented and `-b`, `-r` and `-s` need checking from `capa -h` at the pin.
8. **CAP plan row 5 (six assets)**: the release page shows 8 assets. The two extra are most likely GitHub's automatic source archives [U]. Treat the six build-workflow artifacts as the authoritative count.

## Open questions

1. GitHub per-asset digests for capa 9.4.0, FLOSS 3.1.1 and DIE 3.21: reachable from a network path that is not this proxy? Until then, pins are trust-on-first-use.
2. capa 9.4.0 `capa -h` output: backend (`-b`), rules (`-r`) and signature (`-s`) flags and any timeout option (not in the usage page).
3. FLOSS `-L` option and the 16 MiB emulation limit: confirm in `floss/main.py` and `const.py` at v3.1.1.
4. FLOSS 3.1.1 release page reports 5 assets. Which other binaries exist (macOS?) and do they matter for us? [U]
5. DIE 3.21 Windows zip Authenticode status, and whether `diec.exe` calls `WinVerifyTrust` with network revocation (repo DIE plan row 27 is unresolved) [U].
6. Qt licence and version inside `diec` 3.21 [U].
7. Real-binary time, RSS and output size for all three tools, measured on a lawful local sample on the owner's machine. No data exists in the sources read.
8. DIE database provenance and licence: ask upstream before any redistribution. Until then, the DB stays out of the repository.
9. DIE 4.0.0: when a tag appears, it needs its own golden run and a new pin; this research does not cover its output.
