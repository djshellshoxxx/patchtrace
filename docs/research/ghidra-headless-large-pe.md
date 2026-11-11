# Ghidra 12.x headless on large Windows PEs via PyGhidra and JPype: settings, pitfalls, determinism, bundle size

Date: 2026-10-15. Scope: research for the unified-engine extractor ([SPEC-31 / 03](../specs/unified-engine/03-extraction.md)) and the offline bundle ([BUNDLE-integration-plan sections 6-7](../specs/program-e/BUNDLE-integration-plan.md)). Read-only context: `src/patchtrace/backend.py`. No code was changed. Research note, not a contract.

Evidence tags. **[S]** = read in the cited source on 2026-10-15 (all "accessed" dates below are 2026-10-15). **[M]** = measured by me on 2026-10-15 in a throw-away scratch directory (not committed; method in section 7). **[U]** = unverified or inferred, with the reason. Hosts `ghidra.re`, `ghidradocs.com`, `docs.python.org`-style documentation sites were unreachable from this sandbox (DNS or proxy 403), so everything marked [S] comes from the Ghidra, PyGhidra, JPype and ghidriff **source and release files on GitHub** at the exact tags we pin, plus Temurin release assets. I could not read the Ghidra HTML help pages themselves.

Versions used: Ghidra 12.0.4 (`ghidra_12.0.4_PUBLIC_20260303.zip`, sha256 `c3b458661d69...a120`, matches `tools/backend_pin.json`), PyGhidra 3.0.2 and JPype 1.5.2 (both taken from the wheels shipped inside Ghidra's `Ghidra/Features/PyGhidra/pypkg/dist`), Temurin `jdk-21.0.12.1+1`, ghidriff at the pinned sha `4f5d895f`.

Short answer: the plan's pins and the `JAVA_HOME_OVERRIDE` guard are right. Three things in the plan are wrong or too timid: the size estimates (section 5 gives real numbers), deferring jlink (a 78 MB runtime ran Ghidra + PyGhidra fine on Linux), and the strip list (it omits the biggest items). One safety issue needs a decision: ghidriff enables remote symbol servers by default, which contradicts an offline policy.

## 1. Recommended settings (table with sources)

| # | Topic | Recommendation | Evidence and source |
|---|---|---|---|
| 1 | JVM heap | Pass an explicit `-Xmx` through `HeadlessPyGhidraLauncher.add_vmargs`. Our L-03 (50 % of RAM, max 16 GiB) is a sane ceiling; floor it at 4 GiB and refuse to start below 8 GiB of RAM for ntoskrnl-class files. The right number for ntoskrnl/win32k/tcpip is **not measured** (no such binary in the sandbox). Measure peak heap once with `-Xlog:gc` and set the floor from data | PyGhidra adds **no** heap flag of its own: `_jvm_args()` only emits `-Dpyghidra.sys.prefix=` and `-Dpyghidra.sys.executable=` plus `launch.properties` VMARGS; `launch.properties` in 12.0.4 has no `MAXMEM`/`-Xmx` line [S] https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/launcher.py , https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/RuntimeScripts/Common/support/launch.properties . Ghidra's own `analyzeHeadless.bat` sets `MAXMEM=2G` and says: "For headless, it is recommended to not use the default value because garbage collection could take too long on systems with a large amount of physical memory." [S] https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat . ghidriff uses `-XX:MaxRAMPercentage=60` (CLI `--max-ram-percent`, default 60) [S] https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py |
| 2 | Heap-dump flags | Do **not** copy ghidriff's `-XX:+HeapDumpOnOutOfMemoryError` blindly: a 16 GiB heap writes a multi-GB `.hprof` into the cwd. If used, add `-XX:HeapDumpPath=<private work dir>` and delete it with the work dir. `-XX:+CrashOnOutOfMemoryError` is good (turns a silent hang into a non-zero exit our runner classifies) | ghidriff sets both flags, no `HeapDumpPath` [S] same ghidriff file, lines ~108-109. Cleanup consequence is my inference [U] |
| 3 | GC and JIT threads | Leave JVM defaults for our one-JVM-at-a-time design (sides run sequentially, [01 s3 / L-03](../specs/unified-engine/01-architecture.md)). Only cap if two JVMs ever run in parallel: `-XX:ParallelGCThreads=2 -XX:CICompilerCount=2` | Ghidra's headless script sets exactly these for parallel headless instances (comment: "Java will assign one thread per core which does not scale well on servers with many cores") [S] `analyzeHeadless.bat` URL above |
| 4 | Analysis threads | Ghidra has a shared analysis pool ("Analysis", option `Max Threads`, default `SystemUtilities.getDefaultThreadPoolSize()`). System properties `-Dcpu.core.limit=` and `-Dcpu.core.override=` exist (blank by default). For reproducible timing on CI set `cpu.core.limit` | [S] `AutoAnalysisManager.java` lines 66-83 https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java ; `launch.properties` lines 66-71. **Caveat:** PyGhidra 3.0.2 may let `launch.properties` values win over `add_vmargs` (the README says user properties take precedence only "Since 3.1.0"), so a `-Dcpu.core.limit=` passed with 3.0.2 may be ignored [U]; I passed it and saw no effect on output, but did not verify it took effect |
| 5 | Thread stack (`-Xss`) | No Ghidra-documented value. Leave default; raise only on a demonstrated `StackOverflowError` | No source found [U] |
| 6 | Analysis timeout | The in-process `-analysisTimeoutPerFile` exists only in `HeadlessAnalyzer` (the `analyzeHeadless` script path, `perFileTimeout`). Our extractor and ghidriff go through PyGhidra, which calls `FlatProgramAPI.analyzeAll` with a dummy monitor, so **there is no in-process analysis timeout**. The enforcement is the process-level L-04 (analyze 7,200 s) via `run_process`, which kills the tree. Keep it that way, or install a timed monitor (PyGhidra has a task-monitor helper with an optional timeout, per search summary [U]) | [S] `HeadlessAnalyzer.java` lines 1044-1067 (`perFileTimeout`, `HeadlessTimedTaskMonitor`) https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/HeadlessAnalyzer.java ; PyGhidra `core.py` `_analyze_program` calls `flat_api.analyzeAll(program)` and the flat API is built with `TaskMonitor.DUMMY` https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/core.py ; ghidriff also uses `flat_api.analyzeAll` (lines ~952-981) |
| 7 | Decompiler timeout | 30-60 s per function. API: `DecompInterface.decompileFunction(func, timeoutSecs, monitor)`; a timeout shows up as `decompileCompleted() == False` and our `decomp.jsonl` status `timeout` (03 s4). ghidriff defaults: 60 s (`--decompiler-timeout`), 15 s inside `enhance_sym`. Raise the payload cap for big functions: ghidriff sets `setMaxPayloadMBytes(100)` ("default 50MB") | [S] ghidriff engine lines ~379-384, 686-688, 743-754, CLI help in https://raw.githubusercontent.com/clearbluejar/ghidriff/main/README.md . I found no Ghidra doc stating the semantics of timeout 0 [U] |
| 8 | Analyzers to disable for speed | **Default: change nothing in v1** (keeps parity with a plain Ghidriff run, which 03 s1 promises). If speed is needed later, the measured top costs on a 555 KB / 2,999-function clang PE are in the table below. Any change must go into the cache key (`runtime_id` or an options hash) and into the IR header, because it changes facts | [M] section 3 timing table. Analyzer names and defaults dumped from `prog.getOptions('Analyzers')` on an x86-64 PE |
| 9 | "Shared Return Calls" on huge binaries | ghidriff turns off `Shared Return Calls.Assume Contiguous Functions Only` when a program has more than 1,000 functions, citing Ghidra issue 4573. Relevant for ntoskrnl (tens of thousands of functions). Not part of plain Ghidra defaults, so applying it would diverge from "plain Ghidra defaults"; decide explicitly | [S] ghidriff engine lines ~952-965 (comment "see ghidra/issues/4573"). I did not read the issue [U] |
| 10 | Decompiler Parameter ID | It is **on by default** in 12.0.4 for PE x86-64 and was the largest single analyzer in my run (17.0 s of 50 s). ghidriff additionally force-enables it only when `program_options` is given (its comment "turned off by default in 10.x" is out of date for 12.0.4) | [M] analyzer list and timings, section 3; ghidriff engine lines ~958-960 [S] |
| 11 | Function ID (FID) | Keep the analyzer on; the databases are optional. Ghidra ships ten Visual Studio library DBs (`vs2012`..`vs2019`, `vsOlder`, x86 and x64): **204.1 MB uncompressed, 79.5 MB in the zip**. With the `.fidbf` files deleted the analyzer ran in 9 ms and every output hash was unchanged on my test PE. For kernel images FID mostly matters for statically linked MSVC CRT/library code; how much it helps ntoskrnl/win32k is **not measured** | [M] zip listing, stripped run; the "what it matches" description is general knowledge [U]. 12.0 change history: "The FID plugin delays loading FID DB resources, which speeds up tool load time (GP-6073)" and `security_check_cookie()` VS2022 fix (GP-5998) [S] https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md |
| 12 | PDB offline | For offline runs give Ghidra the PDB through the local symbol store or the analyzer option `PDB Universal.PDB File`, and make sure no remote server is reachable. The analyzer first checks the manual `PDB File` option, then asks `PdbPlugin.findPdb` which uses the configured servers (local store plus trusted); remote untrusted servers are searched only if option `Search untrusted symbol servers` is true. Binaries without CodeView data log "Skipping PDB processing: missing PDB information in program metadata". **ghidriff sets that untrusted option to true and loads the well-known Microsoft server URLs** unless `--no-symbols` (which also turns off the `PDB Universal` analyzer) | [S] `PdbAnalyzerCommon.java` (lines ~36-41, 104-148), `PdbUniversalAnalyzer.java` (option registration ~262-270) in Ghidra 12.0.4; ghidriff engine lines ~520-640, 818-870 (`setup_symbol_server`, `setAllowUntrustedOption(program, True)`). The default value of the untrusted option in plain Ghidra was not visible in the lines I read [U] |
| 13 | Private settings and temp | Keep the per-run `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `TEMP/TMP/TMPDIR`. Ghidra also honours `-Dapplication.settingsdir`, `-Dapplication.cachedir`, `-Dapplication.tempdir`, `-Djava.io.tmpdir` (commented out in `launch.properties`) | [S] `launch.properties` lines 110-145. The env-based route is what the plan uses; the `-D` properties are a stronger alternative if a Windows quirk appears [U] |
| 14 | CDS | Ghidra sets `-Xshare:off`, so the JVM does not use the class-data archive; startup is ~5-7 s [M]. Not worth changing | [S] `launch.properties` line 95; [M] startup 4.7-7.2 s over 5 runs |

## 2. Pitfalls and fixes

| Pitfall | Evidence | Fix or guard |
|---|---|---|
| **Which `java` PyGhidra uses.** With `JAVA_HOME_OVERRIDE` set the launcher takes it directly; without it, it runs `java -cp .../LaunchSupport.jar LaunchSupport <ghidra> -jdk_home -save` through a shell and (in 3.1.0+) checks `java -version` on PATH first. `-save` writes a remembered Java home into the user's Ghidra config | [S] `launcher.py` lines ~200-206, 309-320 https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/launcher.py ; PyGhidra README (JAVA_HOME fallback since 3.1.0) https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md | The plan's guard (set `JAVA_HOME_OVERRIDE`, prepend `jdk/bin`, `backend.build_child_env` already does it, lines 197-202) is correct and also avoids the `-save` write. Keep the test that PATH has no `java` |
| **JPype locates `jvm.dll` by walking `JAVA_HOME`** (`os.walk` for `jvm.dll`), applies `os.path.realpath`, and falls back to the Windows registry only if `JAVA_HOME` fails. PyGhidra sets `os.environ['JAVA_HOME']` itself before `startJVM(None, ...)` | [S] JPype 1.5.2 `_jvmfinder.py` lines ~89-125, 209-227, 353-385 https://raw.githubusercontent.com/jpype-project/jpype/v1.5.2/jpype/_jvmfinder.py ; `launcher.py` lines ~418-428 | A jlinked runtime must keep `bin/server/jvm.dll` (it does on Linux for `lib/server/libjvm.so` [M]). A stale registry JVM is never consulted when `JAVA_HOME` works. Do not set `JAVA_HOME` to a path with a trailing `bin` |
| **Bitness mismatch** (32-bit JVM with 64-bit Python and the reverse) fails to load | JPype install docs, via search summary https://jpype.readthedocs.io/en/stable/install.html [U: page not fetched] | Bundle is amd64 only; `_checkJVMArch` exists in `_jvmfinder.py` [S] |
| **`ImportError: DLL load failed while importing _jpype`** on a clean Windows | JPype changelog documents it and the fix: install the Microsoft Visual C++ Redistributable (#1167) [S] https://raw.githubusercontent.com/jpype-project/jpype/master/doc/CHANGELOG.rst | Add the VC++ runtime check to the Windows acceptance run (a clean VM without Visual Studio) and either ship `vcruntime140*.dll`/`msvcp140.dll` next to `python.exe` (embeddable Python already carries `vcruntime140.dll`) or document the redistributable. Whether `_jpype*.pyd` needs more than the embeddable set is **untested** [U] |
| **JPype version regressions on Windows.** PyGhidra 3.0.0 pinned JPype 1.5.2 "to avoid a possible Windows crash with 1.6.0"; as of 3.2.0 it excludes 1.6.0 and 1.7.0. JPype 1.7.0 (2026-04-04) fixed a Windows import race (#1316) | [S] PyGhidra README (URL above); JPype changelog | Keep exact pins (plan does: 1.5.2 + pyghidra 3.0.2, both are inside Ghidra 12.0.4's `pypkg/dist`, which I confirmed lists `pyghidra-3.0.2-py3-none-any.whl`, `pyghidra-3.0.2.tar.gz`, `packaging-25.0`, `setuptools-80.9.0`, `wheel-0.45.1`, and `jpype1-1.5.2` wheels for cp310-cp313 including `cp312-cp312-win_amd64`) [M]. Note `mdutils` (needed by ghidriff) is **not** in that folder |
| **JDK version.** Ghidra 12.0 documents "Java 21 64-bit ... JDK"; the repository `master` getting-started now says Java 25 | [S] https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/GhidraDocs/GettingStarted.md (21) and https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/GhidraDocs/GettingStarted.md (25). 12.0.3 notes mention a JDK 21.0.10 hostname-check change (GP-6426) | JDK 21 is the supported pin for 12.0.x; see section 5 for the plan row that proposes flipping to 25 |
| **Install path rules.** Ghidra fails to launch if its path contains `^`; older 7-Zip fails on 0-byte files in the distribution; extracting to `C:\` root may need admin; Windows 10 build 1809 or later | [S] 12.0.4 `GettingStarted.md` (URL above) | Builder: assert no `^` in the install path (user-chosen extraction folder; also check at runtime in `bundle_backend_kwargs`); prefer our own ZIP writer or Windows' extractor. Existing `backend._validated_ghidra_output_path` already rejects dot-led components and long paths |
| **Short (8.3) paths and long paths.** JPype calls `os.path.realpath(JAVA_HOME)`; Ghidra project paths hit `MAX_PATH` | JPype `_jvmfinder.py` line ~221 [S]; backend.py path checks (read-only) | Behaviour of `realpath` on 8.3 names under Python 3.12 was not tested [U]. Resolve `Path.resolve()` once, in the parent, and pass the long absolute path. Keep the builder's longest-relative-path <= 150 chars rule |
| **`JAVA_TOOL_OPTIONS` noise.** The JVM prints `Picked up JAVA_TOOL_OPTIONS: ...` to stderr on every start; in this sandbox it also leaks proxy settings | [M] every JVM invocation printed it | The allowlist env (`restrict_env`) already drops it. Keep `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` off the allowlist so output parsing and the probe line stay clean |
| **Antivirus and SmartScreen.** Scanning 40,000 files in the install tree and the JVM mapping large `.jar` files can slow first start; real-time scanning of the Ghidra project directory can slow analysis | No source retrieved [U] | Plan row on Mark-of-the-Web is the right mitigation. Measure on a Defender-enabled VM: time (a) cold first start, (b) second start, (c) analysis with the work dir excluded, then decide whether to document an exclusion (never set one silently). The cold-versus-warm difference I saw on Linux (77 s versus 50 s for the same analysis, first run versus second) is page cache, not antivirus [M] |
| **`pyghidra.open_program` is deprecated in 3.0.2** (use `open_project` and `program_context`); the extractor script in 03 s4 already uses `GhidraProject` directly | [S] PyGhidra README; [M] DeprecationWarning printed | No action for 03; avoid `open_program` in new probes |
| **Interpreter and import order.** PyGhidra removes the cwd from `sys.path` after the JVM starts, and 12.1 restores `sys.modules` after each script by default (switchable by a Java system property) | [S] `launcher.py` `_setup_java` ; 12.1 change history via search summary https://www.ghidradocs.com/12.1_PUBLIC/docs/ChangeHistory.html [U: not fetched] | Matches 03's "script alone in its own directory" rule. Re-check if the pin moves to 12.1 |
| **Concurrency inside ghidriff.** Decompile and symbol enhancement run in a `ThreadPoolExecutor` with `max_workers = cpu_count()` and, when threaded, create two `DecompInterface`s per worker | [S] ghidriff engine lines ~65, 143-146, 691-700, 1015, 1635 | Memory scales with core count on a many-core machine: on a 32-thread host with ntoskrnl pairs, cap workers or heap together. Not applicable to our own extractor (one session) |

## 3. Determinism

What I ran [M]: a synthetic Windows DLL (clang `--target=x86_64-pc-windows-msvc`, `lld-link`, 555,520 bytes, 2,999 functions, 142,609 instructions), Ghidra 12.0.4 default analysis, Linux x86-64, 4 CPUs, `-Xmx2g`. For each run I hashed the sorted function list (entry, name, body size, signature), the instruction text of the whole listing, and the C text of the first 200 decompiled functions.

| Run | JDK | Ghidra tree | function-list hash | instruction hash | decompile hash (200 fn) |
|---|---|---|---|---|---|
| full1 | Temurin 21.0.12.1 full | as shipped | `572f539d42bf34b0` | `0ee8a12d4748dcc9` | `9d531015a15541d5` |
| full2 | same | as shipped | identical | identical | identical |
| min1 | jlinked 26-module runtime | as shipped | identical | identical | identical |
| cpu1 | full | as shipped, `-Dcpu.core.limit=1` passed | identical | identical | identical |
| stripA | jlinked | docs, Extensions, FID DBs, golang typeinfo, other-OS natives removed | identical | identical | identical |
| stripB | jlinked | stripA plus Jython, BSim, GhidraServer, Debug removed | identical | identical | identical |

Symbol count (13,586) and reference-source count (25,713) were also identical in all six. Analysis wall time varied 42-77 s with no relation to the configuration (page cache and noise), so **timing is not a reproducibility signal**.

Not covered, and therefore **not claimed**: Windows versus Linux output; an MSVC binary with a PDB; FID hits; a real kernel image; load on a busy machine; the GZF bytes. Reasons for caution:

- Analysis is multi-threaded in places (shared "Analysis" pool, `Max Threads`) [S: `AutoAnalysisManager.java`]; I saw no divergence, but the `cpu.core.limit` test may not have taken effect with PyGhidra 3.0.2 (row 4 above) [U].
- The decompiler is a native C++ executable built per OS (`os/win_x86_64` versus `os/linux_x86_64`, 4.6 and 4.7 MB [M]). Cross-OS byte-identical C text is plausible but **unproven** [U].
- A GZF or Ghidra project contains timestamps and database internals; byte equality of the GZF should not be assumed [U]. Hash **semantic content** (what 03 already does with `blake2b` over bytes and instruction masks), never the GZF file.
- ghidriff-style parallel decompile returns results in completion order; any consumer must sort by RVA (03 already keys by `rva`).

Recommendation: before claiming "same input, same IR on both OS", run the existing `live-unified-extract` fixture on Windows and Linux and compare the function, instruction and decompile hashes of this note's method (cheap, and it is the first real Windows evidence). Put `ghidra`, `pyghidra`, `jpype`, JDK build, analyzer-options hash and OS family into the cache key (03 s3 already records versions).

## 4. Measured analyzer costs (default options)

Same synthetic 555 KB x64 DLL, 4 CPUs, `-Xmx2g`, total reported "50 secs" by `AutoAnalysisManager.getTaskTimesString()` [M]. Order is by cost; "default" is the value in the dumped `Analyzers` options.

| Analyzer | Time (s) | Default | Disabling it changes |
|---|---|---|---|
| Decompiler Parameter ID | 17.0 | on | parameter types and names (visible in `fn.sig`, decompiled C) |
| Disassemble Entry Points | 10.4 | on | function discovery (do not disable) |
| WindowsResourceReference | 6.3 | on | references into resource data only |
| x86 Constant Reference Analyzer | 6.0 | on | constant-based references |
| Stack | 5.7 | on | stack variable and frame facts |
| Apply Data Archives | 1.1 | on | data types applied from GDTs |
| Demangler Microsoft | 0.9 | on | C++ names |
| ASCII Strings | 0.8 | on | string facts (03 extracts strings) |
| Scalar Operand References | 0.7 | on | references |
| PDB Universal | 0.003 | on | symbols and types (here: no PDB) |
| Function ID | 0.009 | on | library function names (no DBs present in the stripped run) |
| PDB MSDIA | n/a | **off** | Windows-only native DIA path; leave off |

Other defaults seen: `Aggressive Instruction Finder` off, `Variadic Function Signature Override` off, `Condense Filler Bytes` off, `WindowsPE x86 Propagate External Parameters` off. Costs on ntoskrnl will have a different mix (Decompiler Parameter ID scales with function count and size; the plan quotes ~1,349 s per side for ntoskrnl from R03 [U: not re-read]). Only the order of magnitude and the names are reusable.

## 5. Bundle size reduction options

### 5.1 What the Ghidra 12.0.4 distribution contains [M]

The release asset is 509,952,513 bytes (486 MiB; confirmed by `Content-Length` and by a full download whose sha256 equals the pin). The zip has 8,000 entries, 866.4 MB uncompressed (847 MB `du` on disk), 508.1 MB sum of compressed sizes.

| Component (path under the root) | Uncompressed MB | Zip MB | In plan 7.4 strip list? | Verified removable in my run |
|---|---|---|---|---|
| `Ghidra/Features/FunctionID/data/*.fidbf` (10 VS DBs) | 204.1 | 79.5 | no | yes (stripA) |
| `docs/` (Javadoc zip 52, stubs 46, class material 6, others) | 105.6 | 64.8 | yes | yes |
| `Ghidra/Features/Base/data/typeinfo/golang/*.json` | 96.2 | 8.2 | no | yes |
| `Ghidra/Features/Jython` | 75.9 | 56.1 | no | yes (stripB) |
| `Extensions/` (BSim Elastic plugin zip, Eclipse, Skeleton, examples) | 46.9 | 46.3 | yes | yes |
| `Ghidra/Features/BSim` | 36.5 | 35.6 | no | yes (stripB) |
| `Ghidra/Features/GhidraServer` | 25.5 | 22.5 | no | yes (stripB) |
| `Ghidra/Debug` | 24.9 | 23.2 | listed as **keep** | yes (stripB) |
| `os/` natives of the other OS (mac and win, or mac and linux) | ~9 | ~5 | yes | yes |
| Everything else (`Base` jars, `Decompiler`, `Framework`, processors 26 MB, `PDB`, `PyGhidra` with `pypkg/dist` ~25 MB of wheels for all platforms) | ~230 | | keep | needed |

On-disk result, same machine [M]: 847 MB as shipped, 394 MB after stripA, **234 MB after stripB**. The analysis outputs in section 3 were identical at every step. Limits of this evidence: Linux only, one small non-MSVC PE, no PDB, no FID hit, no Ghidra GUI or Jython scripts, no BSim, no server features. Windows and an MSVC kernel binary are not covered, so every removal still needs the acceptance run the plan already requires.

Further candidates not tried: `Ghidra/Features/VersionTracking` (3.8 MB, needed by ghidriff's `VersionTrackingDiff` engine, keep), `Ghidra/Features/FunctionGraph`, `Sarif`, and the 8 MB `GPL/` tree (keep, licence). Processors other than x86 total ~26 MB; stripping them saves little and risks loader errors, so the plan's "no processor stripping" is right.

### 5.2 JDK

| Item | Size | Source |
|---|---|---|
| Temurin 21.0.12.1+1 Windows x64 zip | 205,073,461 bytes (HEAD `Content-Length`); sha256 of my download `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` | [M] https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip (compare with Adoptium's published `.sha256.txt` in B1; I did not fetch it) |
| Same, uncompressed (zip central directory) | 343.8 MB: `lib/modules` 140.9, `lib/src.zip` 53.0, `bin/server` 40.8, `jmods/` 84.2, `lib/ct.sym` 10.7 | [M] |
| Linux x64 tar.gz | 207,473,347 bytes; 346 MB unpacked | [M] https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz |
| Plan's safe strip (`lib/src.zip`, `jmods/`) | saves about 137 MB uncompressed | [M] arithmetic from the listing |
| **jlinked runtime, 26 modules** | **78 MB on disk (`lib/modules` 33 MB), 52.3 MB as tar.gz**, versus 346 MB | [M] |

jlink recipe that worked (command-line facts, no script committed): `jdeps -summary` run **per Ghidra jar** (a single multi-jar run fails because `jgrapht-io` needs automatic modules that are not present), then `jlink --add-modules <list> --strip-debug --no-man-pages --no-header-files --compress=zip-6`. The static scan of 199 Ghidra and GPL jars reported: `java.base` (169 jars), `java.desktop` (70), `java.xml`, `java.logging`, `java.datatransfer`, `java.management`, `java.sql`, `java.naming`, `java.rmi`, `java.scripting`, `java.compiler`, `java.net.http`, `java.security.jgss`, `java.prefs`, `java.instrument`, `jdk.unsupported`, `jdk.xml.dom`, `jdk.security.auth`, `jdk.net`, `jdk.management`, `jdk.jshell`, `jdk.jdi`. I added `jdk.compiler` (PyGhidra imports `pyghidra.javac.java_compile`), `jdk.crypto.ec` and `jdk.charsets`, `jdk.zipfs`, since `jdeps` cannot see service providers and reflection (the JDK bug tracker entry and Bazel's `minimize_jdk.sh` make the same point: https://bugs.openjdk.org/browse/JDK-8189320 , https://bazel.googlesource.com/bazel/+/master/src/minimize_jdk.sh , accessed 2026-10-15, via search summary [U: not opened]). Final module list: `java.base, java.desktop, java.xml, java.logging, java.datatransfer, java.management, java.sql, java.naming, java.rmi, java.scripting, java.compiler, java.net.http, java.security.jgss, java.prefs, java.instrument, jdk.unsupported, jdk.xml.dom, jdk.security.auth, jdk.net, jdk.management, jdk.compiler, jdk.crypto.ec, jdk.zipfs, jdk.charsets, jdk.jdi, jdk.jshell`.

Functional proof [M]: PyGhidra 3.0.2 + JPype 1.5.2 + Ghidra 12.0.4 imported the PE, ran full auto-analysis and decompiled 200 functions on the jlinked runtime with output identical to the full JDK (section 3). `java.desktop` has to stay: Ghidra's jars reference AWT/Swing types even in headless mode (70 jars) and the build docs mention a virtual display for CI [U], though in headless runs here no display was needed.

Not proven: Windows jlink (needs the Windows `jmods`; jlink can build an image for another platform from that platform's jmods, which I believe but did not run [U]); the Ghidra GUI; Java scripts compiled at run time (kept `jdk.compiler`); TLS to a symbol server (kept `jdk.crypto.ec`; irrelevant offline). Licence: a jlink image still ships under GPLv2 with Classpath exception, so `legal/` and the source offer remain; jlink keeps `legal/` only if copied, so copy it explicitly [U: not checked in my image].

### 5.3 Estimated bundle (replaces plan 7.4 "~0.7-1.0 GB zip, 1.5-2.0 GB extracted")

| Variant | Ghidra tree | JDK | Total extracted (Ghidra + JDK, without Python and wheels) |
|---|---|---|---|
| Plan v1 strips only | ~700 MB | ~207 MB (JDK minus src.zip and jmods) | ~0.9 GB |
| Plan strips plus FID, golang typeinfo, Jython, BSim, GhidraServer, Debug (stripB) | ~234 MB (Linux; Windows similar, win natives instead of linux) | ~207 MB | ~0.44 GB |
| stripB plus jlinked JDK | ~234 MB | ~78 MB | **~0.31 GB** (zip roughly 0.15 GB, from the 52 MB jre tarball plus a compressed Ghidra tree [U: not zipped]) |

Python embeddable (~11 MB), site-packages and Ghidriff are small beside these, but I did not measure them (the plan flags the sizes as unverified too).

Recommended order: (1) adopt stripB-style removals in `tools/backend_pin.json` `strip.ghidra` **including `Ghidra/Debug`**, gated by the acceptance run, and keep FID DBs behind a separate pin flag until someone shows FID is not useful for kernel images; (2) move jlink from "not built" to slice B-next after Windows acceptance is green, because it saves ~270 MB of 350 MB for the JDK; (3) never remove `Decompiler`, `PDB`, `Base`, `PyGhidra`, `VersionTracking` or the processors.

## 6. Corrections to our plan

| Where | What the plan says | What the evidence says | Proposed change |
|---|---|---|---|
| BUNDLE 6, row 1 (bare `java` on PATH) | `JAVA_HOME_OVERRIDE` guard | Correct, and also avoids the shell-out to `LaunchSupport -save` [S] | Keep. Add a note that the override skips both the PATH probe and the `-save` write |
| BUNDLE 6, row 2 (JDK 25 fallback) | "if 21 fails, B1 flips the pin to 25" | Ghidra 12.0.4's own `GettingStarted.md` requires JDK 21 (25 appears only on `master`) [S]; 12.0.x is not documented for 25 | Fallback should be "different 21.0.x patch release" or "pin to the Ghidra version whose docs say 25", not a JDK-only flip |
| BUNDLE 6, row 3 (pins) | pyghidra 3.0.2, JPype 1.5.2, cross-check against `pypkg/dist` | Confirmed: both wheels are in `pypkg/dist`, including `jpype1-1.5.2-cp312-cp312-win_amd64.whl`; `mdutils` is not there [M] | Keep. The `any` wheel list still needs a source for `mdutils` |
| BUNDLE 6, symbol policy and offline claims | Not stated as a row | ghidriff **enables untrusted remote symbol servers and loads the well-known URLs by default** (engine lines ~520-640, 818-870). `--no-symbols` is the only CLI switch and it also disables `PDB Universal`; the `symbol_urls` parameter exists in the Python API (CLI exposure unknown [U]) | Add a row and a test: bundle mode must run ghidriff with `--no-symbols` unless the user opts in (`allow_symbol_downloads`, already in `backend.py`), and the acceptance network-block run must prove no socket opens. For "offline PDB use" a separate slice is needed (local store plus `PDB Universal.PDB File`) |
| BUNDLE 7.4 sizes | zip 0.7-1.0 GB, extracted 1.5-2.0 GB [unverified] | Ghidra zip is 486 MiB; extracted Ghidra is 866 MB; Temurin 21 is 205 MB (zip) and 344 MB (extracted) [M] | Replace the estimates with these numbers; the 1.2 GB gate and 1.9 GiB hard limit are now very comfortable; lower the gate (for example 0.7 GB) so growth is noticed |
| BUNDLE 7.4 strip list | docs, Extensions, other-OS natives, JDK `src.zip` and `jmods`; keep `Debug` | Largest removable items are missing: FID DBs 204 MB, golang typeinfo 96 MB, Jython 76 MB, BSim 36.5, GhidraServer 25.5, Debug 25 [M]. `Debug` was safe to remove in my run | Extend the list as in 5.3, each behind the acceptance run |
| BUNDLE 7.4 "Deferred: jlink" | jlink deferred | A 26-module image (78 MB, 52 MB gz) ran the full pipeline identically on Linux [M] | Un-defer after the first green Windows acceptance; add a `jlink` stage to the builder |
| BUNDLE 7.4 "`javac` (jdk.compiler) is required by pyghidra" | stated as fact | `launcher.py` imports `pyghidra.javac.java_compile`; Ghidra also says it "requires a JDK to launch" [S]. The jlinked image I tested contained `jdk.compiler`; I did **not** test without it | Keep the statement but mark "kept by choice; removal untested" |
| 03 s4 (`launcher.add_vmargs('-Xmx..')`, `pyghidra.start()` takes no VM args) | as written | Confirmed for 3.0.2/README [S] | None. Add `-XX:+CrashOnOutOfMemoryError` and, if heap dumps are ever enabled, a `HeapDumpPath` inside the private dir |
| 03 s4 (`pyghidra.analyze(program)` and "GhidraProject.analyze lacks the bundle host") | as written | `pyghidra.analyze` ran and produced the full analysis [M]; PyGhidra's own helper wraps `analyzeAll` in `acquireBundleHostReference` / `releaseBundleHostReference` [S] | None |
| 03 s1 / L-04 (analysis timeout) | process timeout 7,200 s | No in-process timeout exists on the PyGhidra path (table row 6) | State explicitly in 03 that the process timeout is the only analysis timeout; decompile has a per-function one |
| 03 s3 (private settings dir, "no symbol server state") | private `XDG_CONFIG_HOME` | Correct as a default (no servers configured means no remote search), but `PDB Universal` stays **on** by default and will try the local store [M/S] | Also set `PDB Universal.Search untrusted symbol servers` to false explicitly in the program options (belt and braces) |
| L-03 (50 % RAM, max 16 GiB) | as written | Reasonable; Ghidra advises not using default heaps on big machines, ghidriff uses 60 % [S] | Add a floor (4 GiB) and a "fail fast, clear message" below it |
| Ghidriff comment "turned off by default in 10.x" | n/a (upstream) | `Decompiler Parameter ID` is on by default in 12.0.4 [M] | Do not rely on ghidriff's behaviour when comparing our extractor's options with plain Ghidra |

## 7. Method notes (so a reviewer can reproduce)

Scratch only, nothing committed besides this note. Environment: Linux x86-64, 4 CPUs, 16 GB, Python 3.12 venv with `pip install --no-index --find-links <ghidra>/Ghidra/Features/PyGhidra/pypkg/dist pyghidra==3.0.2 jpype1==1.5.2`. Launcher: `HeadlessPyGhidraLauncher(install_dir=...)`, `add_vmargs('-Xmx2g')`, `start()`; environment `JAVA_HOME_OVERRIDE=<jdk>` and private `XDG_CONFIG_HOME`/`XDG_CACHE_HOME`; analysis through `pyghidra.analyze(program)`; hashes with SHA-256 over repr/text as described in section 3; timing from `AutoAnalysisManager.getTaskTimesString()`. Windows was not available; every Windows statement is source reading or [U].

## 8. Open questions

1. How much heap, and how long, do ntoskrnl, win32k, clfs and tcpip need with default analysis on Ghidra 12.0.4? (Needs a real PE and a Windows runner; the current numbers are only the plan's R03 figure of ~1,349 s per ntoskrnl side.) Decide the L-03 floor from one `-Xlog:gc` run per binary.
2. Does `launch.properties` override `add_vmargs` in PyGhidra 3.0.2 (README says user properties win only since 3.1.0)? Test by passing `-Dcpu.core.limit=1` and reading `Runtime.availableProcessors` / the Ghidra thread-pool size.
3. Is FID useful for kernel images (statically linked MSVC code in ntoskrnl, win32k, clfs, tcpip)? If not, the 80 MB zip saving is free; if yes, keep a "with FID" bundle flavour.
4. Do the Ghidra 12.0.4 stripped tree and the jlinked JDK also work on **Windows** with an MSVC PE plus PDB (PDB Universal, MSDIA off, Windows PE exception handling, RTTI analyzers, FID)? Needs the acceptance run; none of the Windows-specific analyzers was exercised here.
5. Is the Linux-versus-Windows analysis output equal for the fixture pair? (Native decompiler differs per OS.) Compare the three hashes of section 3.
6. Exact behaviour with Defender real-time protection on a 40,000-file install: first start time, analysis slowdown with and without a work-dir exclusion. No source found.
7. Does `Python 3.12 embeddable + _jpype*.pyd` load on a clean Windows without the VC++ redistributable? (JPype documents the failure mode.)
8. Which analyzer options does ghidriff's `--program-options` accept for removing remote symbols while keeping local PDB use, and is `symbol_urls=[]` reachable from the CLI?
9. Can `jdk.compiler` and `ct.sym` (10.7 MB) be dropped from the runtime, given no Java scripts are run? Test by running the whole pipeline without them.
10. Does Ghidra 12.1 change the JDK requirement (the repository `master` says 25) and does it ship PyGhidra 3.1/3.2 with JPype pins that differ from ours? 12.1's change history page could not be fetched.
11. Was the `-Dcpu.core.limit` run really single-threaded, and does the analysis-thread count change any output on a larger binary (the only multi-threaded analysis claim I could not test)?
12. GZF byte reproducibility: do two runs of the same input produce identical GZF files? Not tested; we avoid relying on it.

## 9. Sources (all accessed 2026-10-15)

- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/GhidraDocs/GettingStarted.md
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/GhidraDocs/GettingStarted.md
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/RuntimeScripts/Common/support/launch.properties
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/launcher.py
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PyGhidra/src/main/py/src/pyghidra/core.py
- https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/Base/src/main/java/ghidra/app/util/headless/HeadlessAnalyzer.java
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PDB/src/main/java/ghidra/app/plugin/core/analysis/PdbUniversalAnalyzer.java
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Features/PDB/src/main/java/ghidra/app/plugin/core/analysis/PdbAnalyzerCommon.java
- https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.0.4_build/Ghidra/Configurations/Public_Release/src/global/docs/ChangeHistory.md
- https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip (downloaded, listed, extracted)
- https://raw.githubusercontent.com/jpype-project/jpype/v1.5.2/jpype/_jvmfinder.py , https://raw.githubusercontent.com/jpype-project/jpype/v1.5.2/jpype/_core.py , https://raw.githubusercontent.com/jpype-project/jpype/master/doc/CHANGELOG.rst
- https://raw.githubusercontent.com/clearbluejar/ghidriff/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py , https://raw.githubusercontent.com/clearbluejar/ghidriff/main/README.md
- Temurin 21.0.12.1+1 assets under https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1 (Windows zip listed, Linux tar.gz downloaded and unpacked)
- Search-summary only, pages not opened [U]: https://jpype.readthedocs.io/en/stable/install.html , https://bugs.openjdk.org/browse/JDK-8189320 , https://bazel.googlesource.com/bazel/+/master/src/minimize_jdk.sh , https://www.ghidradocs.com/12.1_PUBLIC/docs/ChangeHistory.html , https://www.ghidradocs.com/12.0_PUBLIC/help/PDB/help/topics/Pdb/LoadPDB.html
