# Phase C research: headless BinDiff automation, .BinDiff import hardening, CI

Validated 2026-10-14 (second pass; supersedes the first, which could not reach the sources). Companion to `docs/specs/bindiff-execution.md` (SPEC-29, C4).
Labels: **[M]** measured by running the real BinDiff 8 Linux CLI in this session (extracted `.deb`, `env -i`, non-root, private dirs; synthetic BinExport2 pairs built by hand-encoding the wire format); **[S]** read in a primary source (raw.githubusercontent.com works; github.com `releases/expanded_assets/v8` works via WebFetch; sqlite.org, docs.python.org and learn.microsoft.com are blocked here, so their content was read from their GitHub source mirrors); **[X]** inspected statically (MSI contents, PE headers); **[H]** hypothesis. Windows was **not run**.

## 1. Sources (all primary, all validated 2026-10-14)

| # | Source | Used for |
|---|---|---|
| 1 | raw.githubusercontent.com/google/bindiff/main/main_portable.cc [S] | flags, exit codes, output naming, UI trigger, config load |
| 2 | .../main/database_writer.cc, call_graph.cc, version.h, reader.cc [S] | exact `.BinDiff` DDL, `metadata.version`, `file.hash`, name derivation |
| 3 | github.com/google/bindiff/releases/expanded_assets/v8 and /releases/tag/v8 [S] | asset names and sizes, notes; the download URLs themselves returned 200 |
| 4 | `bindiff_8_amd64.deb`, `bindiff8.msi`, `.deb.asc` (downloaded, hashed, extracted in separate dirs) [M][X] | layout, deps, licences, run tests |
| 5 | .../main/README.md, docs/version-history.md, LICENSE, CMakeLists.txt [S] | yFiles, JDK 16 JRE, OOB fix in v7, Apache-2.0 |
| 6 | .../google/binexport/main/binexport2.proto [S] | schema used to build test inputs |
| 7 | .../quarkslab/python-bindiff/main/src/bindiff/bindiff.py [S] | independent third-party driver (argv, output name, no timeout) |
| 8 | .../sqlite/sqlite/master/src/sqlite.h.in [S] | URI `immutable`, `DBCONFIG_DEFENSIVE`, `TRUSTED_SCHEMA`, limits, `hard_heap_limit64` |
| 9 | .../sqlite/sqlite/master/doc/trusted-schema.md, tool/mkpragmatab.tcl [S] | `trusted_schema` semantics; pragma names `max_page_count`, `hard_heap_limit`, `cell_size_check`, `query_only` |
| 10 | .../python/cpython/main/Doc/library/sqlite3.rst [S] | `setconfig`/`getconfig` (3.12), `setlimit` (3.11), `set_authorizer`, `set_progress_handler` |
| 11 | .../MicrosoftDocs/sdk-api (`AssignProcessToJobObject`, `JOBOBJECT_BASIC/EXTENDED_LIMIT_INFORMATION`, `CreateFileW`) [S] | nested jobs, kill-on-close, memory limits, MAX_PATH |
| 12 | .../google/binexport README and Ghidra extension in the `.deb` [S][X] | headless producer recipe |
| 13 | .../clearbluejar/ghidriff README; trailofbits ghidra-headless (search snippet only) [S/search] | other Ghidra-batch tooling; no BinDiff CI found |

Searched for GitHub Actions or Docker images that run BinDiff: **none found** (search 2026-10-14). The only batch driver found is the python-bindiff wrapper (#7). Diaphora is IDA-plugin-only and AGPL: reference, never vendor.

## 2. Corrections and confirmations of the spec (validated 2026-10-14)

| # | Spec claim | Result |
|---|---|---|
| C1 | `--version` prints `BinDiff <detail>`, exit 0 | **Confirmed [M]**: stdout `BinDiff 8 (@568181968, Sep 25 2023)`, exit 0 (before logo; `^BinDiff (\d+)` matches). |
| C2 | `--help` exit 0 or 1 | **Exit 1 [M]**, text on **stdout**. Accept 0 or 1 still fine. |
| C3 | Only exit 0 and 1 [src] | **Confirmed [S][M]**. Extra: `bindiff` with no input flags prints help and exits **0** (also with only `--primary`), so exit 0 does not mean a result exists. Per-pair errors in directory batch mode are printed but exit 0; irrelevant because we never pass a directory. |
| C4 | `Error:` line on stderr | **Confirmed [M]**; progress/summary is stdout. Messages embed full input/output paths (sanitize). Unknown flag: `ERROR: Unknown command line flag 'x'` (uppercase, absl), exit 1. |
| C5 | Output `older_vs_newer.BinDiff` | **Confirmed [S][M]**. Name = `GetFilename()` of the *input path* (basename, last extension removed), not `executable_name`. python-bindiff relies on the same rule. Name is truncated so that dir + name <= 250 chars; if impossible, error. |
| C6 | `--config=<file {}>` accepted and isolating | **Confirmed [M]**: `{}` accepted (merged over defaults). **Isolation is essential**: a `~/.bindiff/bindiff.json` with a reduced matching list changed the result to `Similarity: 0%` without `--config`, and `--config={}` restored 62.81%. Also user config can set `log.directory`. |
| C7 | CLI needs no Java | **Confirmed [M]**: `ldd` shows only libc/libstdc++/libgcc/libm; strace: one `execve`. JRE only for `--ui`. |
| C8 | No network | **Confirmed on Linux [M]**: strace shows zero `socket`/`connect`; run succeeds under `unshare -rn`. |
| C9 | Env allowlist (HOME etc.) | **Refined [M]**: with `HOME` set, the CLI does `mkdir -p $HOME/.bindiff` and probes `$HOME/.bindiff/bindiff.json`; with **no HOME** it still runs. `FLAGS_*` env vars are ignored unless `--fromenv/--tryfromenv` is passed. Other opens: only inputs, output, `/etc/localtime`, `/dev/urandom`. |
| C10 | SIGKILL leaves nothing usable | **Dangerous nuance [M]**: a SIGKILL during the write phase leaves `older_vs_newer.BinDiff` (valid SQLite header, schema present, `function` table **empty**) plus `older_vs_newer.BinDiff-journal`. An `immutable=1` open ignores the hot journal and would read the half-written state. Rule: never import after a non-clean stop; discard the workdir (spec already says so; add a test). |
| C11 | Success leaves exactly one file | **Confirmed [M]**: journal exists during write, removed on exit 0. Output guard must tolerate a transient `-journal` file while running. |
| C12 | Existing output file | Non-database file at the target name -> exit 1 `preparing statement 'DROP TABLE IF EXISTS metadata': file is not a database` [M]; valid DB is rebuilt by DROP/CREATE [S]. Always use a fresh `out/`. |
| C13 | `bindiff_ui` basename triggers UI | **Confirmed [S]**, and in the `.deb` `bin/bindiff_ui` is a **symlink to `bindiff`** [M]. Resolve symlinks before probing and execute the *resolved* path (argv[0] basename decides UI mode); `/usr/bin/bindiff -> /opt/bindiff/bin/bindiff`. |
| C14 | `bindiff_cli` does not exist | **Confirmed [X]**: deb ships `bindiff`, `bindiff_ui`, `binexport2dump`, `libexec/bindiff_config_setup`; MSI ships `bindiff.exe`, `bindiff_ui.cmd` (`bindiff.exe --ui %*`), `binexport2dump.exe`, `bindiff_config_setup.exe`. |
| C15 | `--output_format=none` exists | **Confirmed [M]**: runs the diff, prints the summary, writes nothing. Usable as a cheap "does it run end to end" probe. |
| C16 | `file.hash` is CHARACTER(40) | The column stores `BinExport.meta_information.executable_id` verbatim (SQLite does not enforce length) [S][M]: a 64-hex SHA-256 is stored intact. D11 binding holds. |
| C17 | Ghidra exporter writes `getExecutableSHA256` | Still **unverified** (BinExport2Builder.java path 404 on raw; extension jar is in the package, `BinExport-src.zip` could be read next). |

## 3. BinDiff 8 CLI contract as measured (validated 2026-10-14)

- Flags (absl, `--help`): `--config --export --flagfile --fromenv --logo --ls --md_index --output_dir --output_format --primary --print_config --secondary --tryfromenv --ui --undefok`. `--nologo` works (absl bool negation). Positional forms also exist; we use named flags.
- Never pass: `--ui --export --ls --md_index --flagfile --fromenv --tryfromenv --undefok` or a directory. `--flagfile` would let a file inject flags.
- Success stdout lines: `primary:   older: 20 functions, 21 calls`, `matched: 20 of 20/21 (primary/secondary, 20/21 non-library)`, `Similarity: 62.8143% (Confidence: 98.2876%)`.
- Failure texts [M] (stderr, exit 1): `Invalid inputs, --primary and --secondary must point to valid files/directories.`; `file too small: <path>`; `parsing failed for exported file: <path>`; `Output parameter (--output_dir) must be a writable directory: <dir>`; `Invalid output format: x`; `invalid JSON in security.bindiff.Config ...`; `Need primary input (--primary)`.
- Metadata written: `metadata.version = "BinDiff 8 (@568181968, Sep 25 2023)"`; `file.id` 1 = primary (older), 2 = secondary [M].
- Real run with the spec argv on a 20/21-function pair: exit 0, one 53,248-byte file, repo `import_bindiff` accepted it (20 matches, algorithm names present, swapped hashes -> ORIENTATION) [M].

## 4. `.BinDiff` schema (from `database_writer.cc`, confirmed by `sqlite_master` of a real file) [S][M]

Plain SQLite 3 (`SQLite format 3\0`, page 4096, UTF-8, `application_id` 0, `user_version` 0, `journal_mode` delete). Objects: 7 tables + autoindexes only; **no views, triggers or virtual tables**, so rejecting them is safe. Declared types (affinity): `basicblockalgorithm(id SMALLINT PK, name TEXT)`; `functionalgorithm(id SMALLINT PK, name TEXT)`; `file(id INT, filename TEXT, exefilename TEXT, hash CHARACTER(40), functions, libfunctions, calls, basicblocks, libbasicblocks, edges, libedges, instructions, libinstructions: all INT)`; `metadata(version TEXT, file1 INT, file2 INT, description TEXT, created DATE, modified DATE, similarity DOUBLE PRECISION, confidence DOUBLE PRECISION)`; `function(id INT PK, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT, similarity/confidence DOUBLE, flags INTEGER, algorithm SMALLINT FK, evaluate BOOLEAN, commentsported BOOLEAN, basicblocks/edges/instructions INTEGER, UNIQUE(address1,address2))`; `basicblock(id INT PK, functionid, address1 BIGINT, address2 BIGINT, algorithm, evaluate)`; `instruction(basicblockid, address1, address2)`. Optional later table `commentsported(address BIGINT PK)` is written only by the UI path. Observed values: addresses INTEGER, `name1` like `sub_1000`, `flags` 0, `created` text `YYYY-MM-DD HH:MM:SS`, 19 function and 20 basicblock algorithm rows (e.g. `function: prime signature matching`, `basicBlock: ...`). `REQUIRED` in `secondary/bindiff.py` matches this DDL exactly. Addresses are signed 64-bit in SQLite: values above 2^63 appear negative (importer masks; keep a test).

## 5. Release and install facts (v8, 25 Sep 2023) [S][M][X]

| Asset | Size (bytes) | SHA-256 (computed here, not published upstream) |
|---|---|---|
| `bindiff_8_amd64.deb` | 62,663,460 | `821990e3974a9df6733794370e485486ac276ba5d777a06b4ebe575f092f4dda` |
| `bindiff8.msi` | 72,237,056 | `688831e490bef8a20c9917048b693bad591f346b3b96489fc79ad8d20d7cb15f` |
| `bindiff_8_amd64.deb.asc` | 819 | `1efbb4c656b97c4a2a73c4193b512546799d08683c8ff9ff2ae79d88ccdef0f5` (RSA signature, issuer key id `4EB27DB2A3B88B8B`, created 2023-09-25; public key not obtained, so the signature is **not verified**) |
| `BinDiff8.dmg` (93 MB), source zip/tar.gz | n/a | n/a |

URL pattern `https://github.com/google/bindiff/releases/download/v8/<name>` (200 through the proxy). GitHub shows no per-asset digests on this page; a human must re-hash from a second network path before trusting these pins.
- Deb: `Depends` libc6>=2.16, libstdc++6>=5.2, libgcc1, zlib1g and X11/ALSA libs (GUI only). `dpkg-deb -x` as non-root yields a **runnable** `/opt/bindiff/bin/bindiff` (3.9 MB ELF) with a clean env [M]; `postinst` only writes `/etc/opt/bindiff/bindiff.json` and per-user plugin links, not needed for the CLI. Bundles `jre/` (OpenJDK 16, 53 MB), `bin/bindiff.jar` (28.9 MB), IDA/Binary Ninja plugins, Ghidra BinExport extension.
- MSI (via `msiextract`): `ProgramFiles/BinDiff/bin/bindiff.exe` (3.4 MB, PE32+, **console subsystem**), imports `MSVCP140`, `VCRUNTIME140`, `VCRUNTIME140_1`, UCRT api-sets, `dbghelp` -> needs the **VC++ 2015-2022 x64 runtime** (not in the MSI). ProductVersion 8.0.0, `ALLUSERS=1`, LaunchConditions: admin and x64. Machine config `CommonAppData/BinDiff/bindiff.json` (= `%ProgramData%\BinDiff`). The MSI adds a per-user Run key and edits system PATH, which is why admin-extract (D5) is preferred. `msiexec /a` itself was **not run** (live-only).
- Licensing: Apache-2.0 for the CLI sources and `LICENSE` in the package; the Debian `copyright` file only says "Usage is subject to license terms" (ambiguous, mention in NOTICE review). `bindiff.jar` contains **97 entries under `y/`** (the yFiles 2.x package root) [M], confirming that redistributing the GUI/jar means redistributing a commercial library: D1 stands. The bundled JRE (OpenJDK, GPLv2+CPE) and Roboto fonts add notices. Fetching from upstream at CI time, not redistributing, is the safe pattern.
- v8 release notes [S]: open-source snapshot (v7 changes), IDA 8.3 (min 8.0), Binary Ninja 3.5, `--output_format=none` ("similarity only"), memory-leak fix in the SQLite class, C++ exceptions removed (so allocation failure is an abort, not a catch), BinExport at f908beb.

## 6. Resource behaviour [M] (Linux x64, 4 cores, synthetic near-identical pairs; real drivers may be slower)

| Functions | BinExport size | Wall | Peak RSS | Output |
|---|---|---|---|---|
| 2,000 | 0.65 MB | 0.1 s | 20 MiB | 1.1 MB |
| 20,000 | 6.5 MB | 1.1 s | 131 MiB | 10.6 MB |
| 100,000 (200k calls) | 35 MB | 10.1 s | 638 MiB | 55 MB |

Roughly 18x input size in RSS and a ~1.6x output/input ratio. Extrapolating to the 512 MiB BinExport cap gives ~9 GiB RSS, so a memory cap is justified for D10 once a real-driver number exists. No orphan or temp files outside `out/` after SIGKILL [M] (U11).

## 7. Hardening for an untrusted `.BinDiff` (validated 2026-10-14)

- `mode=ro&immutable=1` on a private copy: `sqlite.h.in` says immutable "opened read-only and all locking and change detection is disabled" [S], so the earlier forum worry (opened read-write) does not apply to current SQLite, but keep `mode=ro` anyway. No journal/WAL side files are created next to the copy.
- `PRAGMA trusted_schema=OFF` [S doc/trusted-schema.md]; `Connection.setconfig(SQLITE_DBCONFIG_DEFENSIVE/TRUSTED_SCHEMA, ...)` exists from **Python 3.12** only [S]; guard with `hasattr` and fall back to pragmas on 3.11. `setlimit` from 3.11 [S]: lower `SQLITE_LIMIT_SQL_LENGTH`, `LIMIT_ATTACHED=0`, `LIMIT_VDBE_OP`, `LIMIT_TRIGGER_DEPTH`, `LIMIT_LENGTH`.
- `PRAGMA query_only`, `cell_size_check=ON`, `max_page_count` (cap by file size / page size), `hard_heap_limit` / `soft_heap_limit` exist in the pragma table [S]; `set_progress_handler(cb, n)` lets the importer abort a runaway query [S]. `set_authorizer` allows SELECT/READ on the 7 table names, `count` only, denies PRAGMA/ATTACH/FUNCTION others [S].
- The repo importer already implements most of this (`_harden`, authorizer, trigger/view/virtual-table rejection, magic and 512 MiB checks) and accepts a genuine v8 file [M]. Remaining gaps: `max_page_count`/`cell_size_check`, `hard_heap_limit`, a progress-handler deadline, row-count caps per table before iteration, and `PRAGMA integrity_check` is **not** recommended (it scans the whole file; `quick_check` with a deadline at most).

## 8. Windows containment and paths [S]

`AssignProcessToJobObject` on a process already in a job works from Windows 8 (nested jobs) provided the new job has no UI limits [S #11], so running inside a CI job or another job object is fine. `KILL_ON_JOB_CLOSE` kills all members when the last handle closes; `JOB_OBJECT_LIMIT_PROCESS_MEMORY` / `JOB_MEMORY` limit **committed** memory and make the allocation fail (BinDiff 8 has no exceptions, so expect an abort/non-zero exit, not a clean message) [S]. `PeakJobMemoryUsed` gives measurable peaks. MAX_PATH is 260 unless `\\?\` or the manifest opt-in is used [S CreateFileW]; BinDiff builds `dir + "\\" + name` itself and caps at 250, so keep the workdir short (`%TEMP%\pt-xxxx`, not the project tree) and use fixed 6-char input names.

## 9. Answers to SPEC-29 section 12 unknowns

| ID | Answer (validated 2026-10-14) | Status |
|---|---|---|
| U1 | Names/sizes/hashes in section 5; deb layout `/opt/bindiff/bin/bindiff`, symlink `/usr/bin/bindiff`; `dpkg-deb -x` runnable [M] | **Answered** (upstream digest/signature check still human) |
| U2 | MSI contents and console exe known [X]; needs VC++ runtime; `msiexec /a` result not run | Partial, live Windows |
| U3 | Section 3 | **Answered (Linux)**; Windows exe output assumed identical |
| U4 | stderr gets only `Error:`/signal lines; progress on stdout; no flood seen [M] | **Answered (Linux)** |
| U5 | `{}` accepted; replaces user config; HOME/.bindiff is created; `%ProgramData%\BinDiff` machine config path from MSI [M][X] | **Answered (Linux)**, Windows path live |
| U6 | No network syscalls, runs in empty netns [M] | **Answered (Linux)**; Windows live |
| U7 | No JRE for CLI; no env vars needed; works with `env -i`, even without HOME [M] | **Answered (Linux)** |
| U8 | Table in section 6 (synthetic); zero-match behaviour not exercised; overwrite behaviour section 2 C12 | Partial, needs a real driver pair |
| U9 | Ghidra writer unverified (C17); IDA/Binary Ninja unknown | Open, live-only |
| U10 | Hand-built minimal graphs (20 funcs, 1 block each, 2-byte instrs, no operands) are accepted and produce matches [M]; Subtract-Imagebase effect unmeasured | Partial |
| U11 | SIGKILL leaves partial DB + journal only in `out/` (section 2 C10) | **Answered (Linux)** |

Still live-only: everything on Windows (exe run, `msiexec /a`, redist need, ProgramData config, AV/locking, path limits), real-driver time/memory, exporter `executable_id` formats, upstream signature verification.

## 10. C4 follow-up measurements (2026-10-14, same day, Linux; runs as uid 65534 with an environment built from scratch)
Corrections and additions from the C4 follow-up session, which re-ran the real CLI from a fresh, independently downloaded package:
- **Assets** [M]: a second download (new directory, then a third through `tools/provision_bindiff.py`) gave the identical sizes and SHA-256 of §5. The GitHub release API returned HTTP 403 through the egress proxy, so no upstream digest could be compared; the pin stays trust-on-first-use (same egress path both times). The stdlib `ar`+`tar` extraction reproduces the `dpkg-deb -x` regular-file tree byte for byte (117 files); `opt/bindiff/bin/bindiff` is 3,894,808 bytes, `eb0a88eb6518e000bc3c4eef66c22db7ace197173eb933ea5d1c8ac3f7d8d0fb`.
- **C3 correction** [M]: a call **without `--primary`** exits **1** with `Error: Need primary input (--primary)` (a bare call also prints the logo); it is `--primary=<file>` **without `--secondary`** that prints the usage text on stdout and exits **0** with no output. The rule "exit 0 does not prove a result" stands.
- **C6 extended** [S][M]: `Proto()` merges `Defaults()`, then the machine config, then the user config, ignoring unreadable files; `--config` replaces that with `Defaults()` + the file (`main_portable.cc`, `config.cc`). Machine config is `/etc/opt/bindiff/bindiff.json` on Linux (fixed path; binexport `util/process.cc`), `SHGetFolderPath(CSIDL_COMMON_APPDATA)\BinDiff` on Windows; user config `$HOME/.bindiff` / `SHGetFolderPath(CSIDL_APPDATA)\BinDiff`. A one-step `function_matching` list as user **or** machine config (machine case in a private mount namespace) gave 19 matches / 85.34% instead of 20 / 97.19%; `--config` with `{}` restored the baseline in both. Environment redirection alone is therefore insufficient. A user config with `log.to_file`/`log.directory` produced no file in either mode.
- **C8 nuance** [M]: strace of bindiff alone shows no socket calls at all; the AF_UNIX `nscd` connects seen when wrapping with `setpriv` came from `setpriv`.
- **C10 variant** [M]: a SIGKILL about 50 ms after the file appeared (100k functions) left the 53,248-byte database with 7 tables and 0 `function` rows but **no** journal; a cancel at the first output byte saw a 0-byte database plus a 512-byte `-journal`. Both are discarded unread by the run code.
- **§5 MSI correction** [X]: the MSI does carry `System64/msvcp140.dll`, `msvcp140_1.dll`, `msvcp140_2.dll` and `vcruntime140.dll` (installed to System32 by a normal install) but **not `vcruntime140_1.dll`**, which `bindiff.exe` imports (full import list: UCRT api-sets, `dbghelp`, `KERNEL32`, `MSVCP140`, `SHELL32`, `SHLWAPI`, `VCRUNTIME140`, `VCRUNTIME140_1`). An administrative extract places none of them in System32. `bindiff.exe` is 3,396,896 bytes, `b1d4844d7c7f1ca7f9684e280e0807668633e1b2410b31beca5c9ace79b747dd`, PE32+ console.
- **U10** [M]: the stdlib encoder pair of `tests/bindiff_live_pair.py` (20/21 functions, two patched) gives 20 of 20/21 matched, 97.19%, the two patched functions flagged `(I,E)` and `(G,E)`; C3's committed synthetic fixtures give 3 of 3/4, 87.47%. All matches use `function: name hash matching` because the synthetic names agree.
- **Resources** [M]: encoder pairs, 2k functions 0.08 s / 17.6 MiB peak RSS, 20k 0.9 s / 77 MiB, 50k 2.7 s total with the first output byte after 1.9 s.
- **D1** [M]: `opt/bindiff/LICENSE` is Apache-2.0; `bindiff.jar` has 97 `y/` entries; the Debian `copyright` says only "Usage is subject to license terms."
