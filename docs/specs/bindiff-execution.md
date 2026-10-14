# SPEC-29: Real BinDiff execution (Phase C, step C4)

Status: developer-ready draft, 2026-10-14. Contract versions: reuses `engine-run/1`, `secondary/2` (SPEC-28), `bindiff-adapter/1` (SPEC-10). Extends SPEC-10 §4 ("Running the tools") and fills the `bindiff` adapter stub in SPEC-28 §4.2. Depends on C3 (`.BinExport` validator + protobuf) and C1/C5 (`runs.py`, `registry.py`, `store.py`). No GUI (C6), no BinExport *production* (C3 decision), no calibration.

Evidence labels: **[src]** read in `google/bindiff` `main` (`main_portable.cc`, `config.cc`, `README.md`, `docs/`) and `google/binexport` `util/process.cc` on 2026-10-14, plus the pinned research in `../research/phase3/binexport-bindiff.md`; **[rel]** from GitHub release pages; **[M]** measured by running the real BinDiff 8 Linux CLI (`bindiff_8_amd64.deb`, SHA-256 `821990e3…4dda`, extracted without installing) on synthetic BinExport2 pairs, in the research session (`../research/phase-c/bindiff-automation.md`) and again in the C4 follow-up session (2026-10-14, as uid 65534 with an environment built from scratch); **[X]** static inspection (MSI contents, PE headers); **[inf]** inference, must be confirmed on a live install (collected in §12). **Windows was not run**: every Windows statement is [src]/[X]/[inf].

## 1. Decision record

| # | Question | Decision | Rationale |
|---|---|---|---|
| D1 | Bundle BinDiff in the Windows ZIP? | **No (alpha and beta).** User-installed or CI-provisioned only. | Apache-2.0 allows redistribution of the CLI sources **[src LICENSE/README]** (the packaged `opt/bindiff/LICENSE` is Apache-2.0 **[M]**), but upstream installers bundle a JRE (OpenJDK 16, `opt/bindiff/jre/`, 53 MB **[M]**), an IDA/Binary Ninja plugin set and a Java GUI built against the commercial yFiles library **[src README "Java GUI and yFiles"]**: `bin/bindiff.jar` contains 97 entries under `y/`, the yFiles 2.x package root (e.g. `y/module/BalloonLayoutModule.properties`) **[M]**, and the `.deb`'s `usr/share/doc/bindiff/copyright` says only "Usage is subject to license terms." **[M]** (ambiguous). Redistributing those needs a separate notice/licence review; we only call the headless CLI, fetched from the upstream release at CI time. Revisit only via the offline-bundle track, with a NOTICE audit. |
| D2 | How does a user point PatchTrace at BinDiff? | **Explicit absolute path** (CLI `--bindiff PATH`, env `PATCHTRACE_BINDIFF`, QSettings `engines/bindiff/path` later) with **read-only discovery prefill** via `runtime_discovery` (exactly one candidate, else list). Never `PATH` lookup, never auto-install. | Same rule as Python/Ghidra (SPEC-05) and `run_process` which already demands an absolute argv[0]. A probe (§2) validates before any run. |
| D3 | Which BinDiff builds are supported? | **BinDiff major 8** (`v8`, 2023-09-25 **[rel]**), plus self-built `main` whose probe passes. Minimum = 8; unknown newer majors are **supported only if the feature probe passes**, flagged `untested_version` in provenance. | v8 is the only open-source release; it added `--output_format=none` **[rel]**. We use only `bin`. |
| D4 | CI acquisition (Linux) | Download the pinned **v8 `.deb`** (`bindiff_8_amd64.deb`, 62,663,460 bytes) from the GitHub release, verify size and the **SHA-256 pinned in the repo** (`tools/bindiff_pin.json`), extract it **without installing** with a stdlib `ar` + `tar` reader (equivalent to `dpkg-deb -x`; no `dpkg -i`, no root, no maintainer scripts, no IDA symlinking) that writes only regular files and directories (links such as `usr/bin/bindiff -> /opt/bindiff/bin/bindiff` and `bin/bindiff_ui -> bindiff` are not materialised), then verify the extracted `opt/bindiff/bin/bindiff` against a pinned size/SHA-256; cache by archive SHA-256. | Legal: Apache-2.0, we do not redistribute, we fetch from the upstream release. Avoids root and postinst side effects (postinst only writes `/etc/opt/bindiff/bindiff.json` and per-user plugin links **[M]**). The extracted CLI runs as non-root under an empty environment; `ldd` lists only libc, libstdc++, libgcc_s, libm, libdl, librt, libpthread **[M]**. The pin is trust-on-first-use: upstream publishes no per-asset digest (the GitHub release API was not reachable through the egress proxy, HTTP 403) and the `.deb.asc` signature (issuer key id `4EB27DB2A3B88B8B`) has not been verified. |
| D5 | CI acquisition (Windows) | Download pinned `bindiff8.msi` (72,237,056 bytes), verify SHA-256, **administrative extract** `msiexec /a bindiff8.msi /qn TARGETDIR=<dir>` (no system install), locate `bin\bindiff.exe` and compare it with the pinned executable hash; the Windows CI leg is **advisory** (records `blocked`/unverified instead of failing) until a run proves it. Fallback if admin extract lacks the CLI: `msiexec /i … INSTALLDIR=…` on the ephemeral runner. | Ephemeral runner, nothing persistent. Static inspection with `msiextract` **[X]**: `ProgramFiles/BinDiff/bin/bindiff.exe` (3,396,896 bytes, SHA-256 `b1d4844d…47dd`), PE32+ x86-64, **console subsystem** (stdout capture works), next to `bindiff_ui.cmd` (`@"%~dp0bindiff.exe" --ui %*`), `binexport2dump.exe`, `bindiff_config_setup.exe`. The exe imports `MSVCP140`, `VCRUNTIME140`, `VCRUNTIME140_1`, UCRT api-sets, `dbghelp`, `SHELL32`, `SHLWAPI` and `KERNEL32` **[X]**: it needs the **VC++ 2015-2022 x64 runtime**. The MSI carries `System64/msvcp140.dll`, `msvcp140_1.dll`, `msvcp140_2.dll` and `vcruntime140.dll` for a normal install but **no `vcruntime140_1.dll`** **[X]**, and an administrative extract does not place any of them in `System32`, so the provisioning preflight records whether `vcruntime140.dll`, `vcruntime140_1.dll` and `msvcp140.dll` are present in `System32` (`redist`). **[inf]** whether `/a` yields a runnable `bin\bindiff.exe` (live-only). |
| D6 | Who produces `.BinExport` inputs? | **Out of scope for C4**: C4 consumes two user/CI-supplied `.BinExport` files. | SPEC-10 §4; Ghidra headless export is unverified and version-pinned (C3). |
| D7 | Unsupported/unknown behaviour | Probe returns `Capability(supported=False, reason=…)`; scheduler records `EngineRun(status='unsupported')`; never a crash, never a guess. | Mirrors rz-diff `probe`. |
| D8 | Output formats requested | `--output_format=bin` only. No `log` (text `.results` is unparsed and adds an untrusted artefact). | Smaller attack surface; schema is fully validated by `import_bindiff`. |
| D9 | Default timeout | 1,800 s, range 60..86,400 (same as rz-diff). Probe 30 s. | Synthetic near-identical pairs **[M]**: 2,000 functions 0.08 s / 17.6 MiB peak RSS, 20,000 functions 0.9 s / 77 MiB (C4 follow-up), 100,000 functions about 10 s / 638 MiB (research). BinDiff runtime on real drivers is unmeasured **[inf]**; bound with cancel. |
| D10 | Memory cap | None in v1 (documented), output-size cap enforced. Optional follow-up `memory_limit_bytes` in `run_process` (Job Object `JOB_OBJECT_LIMIT_JOB_MEMORY`, POSIX `RLIMIT_AS`) after live measurement. | `jobs.py` today only sets KILL_ON_JOB_CLOSE; AGENTS/architecture say "no invented hard memory cap". Synthetic RSS grows roughly 20x the BinExport size **[M]**, so a cap needs one real-driver number first (§12 U8). |
| D11 | `.BinExport` ↔ artifact binding | `executable_id` **must equal the project artifact SHA-256** (64 hex). Empty/absent/other length → refuse (`binexport-unbound`). No override flag in v1. | Fail closed; pairing evidence must not rest on filenames. See §3. |

### Bundling vs configuring vs discovery (summary)
Configured path is authoritative; discovery only pre-fills; the CI job sets `PATCHTRACE_BINDIFF` explicitly. A discovered or configured path is not a compatibility guarantee: the probe is.

## 2. Capability probe

Function `probe(executable: Path, env, cancel, runner=run_process) -> Capability` in `secondary/bindiff_run.py`. Never installs anything, never launches the UI, never touches inputs. Private temp cwd, sanitized env (§4.2), 30 s timeout, 64 KiB log cap.

Facts **[src main_portable.cc]**: the binary is `bindiff` (also acts as the UI launcher when `argv[0]` basename is `bindiff_ui` or `--ui` is passed; **never pass `--ui`**). Abseil flags are used. Measured on v8 **[M]**: `--version` prints exactly `BinDiff 8 (@568181968, Sep 25 2023)` on stdout and exits 0; `--nologo --help` prints the usage text and flag list on **stdout** (stderr empty) and **exits 1**, so exit 1 after `--help` is normal and the probe judges the text, not the code (exit 0 stays accepted for other builds). The real v8 help text is committed as `tests/fixtures/secondary/bindiff-8-help.txt`; its flag list is `--config --export --flagfile --fromenv --logo --ls --md_index --output_dir --output_format --primary --print_config --secondary --tryfromenv --ui --undefok`. There is **no `bindiff_cli` binary**: the `.deb` ships `bin/bindiff`, `bin/bindiff_ui` (a **symlink to `bindiff`**), `bin/binexport2dump` and `libexec/bindiff_config_setup`, plus `/usr/bin/bindiff -> /opt/bindiff/bin/bindiff` **[M]**; the MSI ships `bindiff.exe`, `bindiff_ui.cmd`, `binexport2dump.exe`, `bindiff_config_setup.exe` **[X]**. Treat `bindiff_cli` as non-existent and report it in the unsupported reason if a user selects one.

Probe steps (each failure → unsupported with a specific reason, no raise):
1. `stat` the path: absolute, then **resolve symlinks fully** and require a regular file. Reject (case-insensitive) when the selected name or the resolved name starts with `bindiff_ui` or `bindiff_cli`, or when the resolved basename is not `bindiff`/`bindiff.exe`. The probe and every run **execute the resolved path**, never the selected link, because `argv[0]`'s basename decides UI mode (selecting `/usr/bin/bindiff` runs `/opt/bindiff/bin/bindiff`; selecting `bin/bindiff_ui` is refused rather than silently redirected).
2. Run `[exe, '--version']`. Exit 0 and `^BinDiff (\d+)` found in stdout/stderr (first matching line) → `major`, `detail` (rest of line, ≤120 chars, control chars stripped). Else `unsupported: "--version printed no recognisable BinDiff version"`.
3. `major < 8` → `unsupported: "BinDiff {detail} is older than 8"` (v7 and older lack the open CLI contract we verified; do not try).
4. Run `[exe, '--nologo', '--help']` (exit **1** measured on v8; 0 or 1 accepted). Required substrings (feature probe, from the measured flag list): `--output_dir`, `--output_format`, `--primary`, `--secondary`, `--logo`, `--config`. Missing any → `unsupported: "bindiff lacks required option --X"`. This also catches a renamed/changed CLI in future majors.
5. `major > 8` → supported only if step 4 passed; set `untested_version=True` in the Capability note (provenance + UI limitation "version newer than tested").
6. Capability: `Capability(engine='bindiff', supported=True, version=f'{major}{detail}', path=str(exe), supports_json=False)`. (`supports_json` is rz-diff-specific; keep `False`.)

Probe results are cached per `(path, mtime_ns, size)` in-process only. The metadata written into the `.BinDiff` (`"BinDiff " + detailed version`) is later compared with the probed version (prefix match on the major) as a consistency check (§5, step 11); a mismatch is a warning in provenance, not a failure (the file could be produced by a different build behind the same path only if the install changed during the run, which we record).

Unsupported-version behaviour is uniform: no run, one `EngineRun(status='unsupported', error_code='PT-SECONDARY-UNSUPPORTED', engine_version=<observed or None>)`, CLI exit 2 when BinDiff was the only selected engine, otherwise the batch continues (SPEC-28 §5 failure isolation).

## 3. Input handling and artifact binding

Inputs: `older.BinExport`, `newer.BinExport` (paths supplied by the user: `--older-binexport`, `--newer-binexport`, or a directory with exactly those two roles via GUI later). Orientation is fixed: **older = BinDiff primary, newer = secondary** (`FLAGS_primary`/`--secondary`; `file.id` 1 = primary **[src]**).

Binding algorithm (pure, uses C3 `validate_binexport` which returns `BinExportResult`):
```text
bind_binexport(path, expected_artifact_sha256, side):
    r = validate_binexport(path)                       # C3: size<=512MiB, parse, bounds, sorted call graph
    if r.status == 'unsupported':  raise SecondaryError('PT-SECONDARY-UNSUPPORTED', r.reason)
    id = (r.executable_id or '').strip().lower()
    if not id:                     raise fail('binexport-unbound', side)       # no hash to tie to the artifact
    if not re.fullmatch('[0-9a-f]{64}', id): raise fail('binexport-unbound', side)   # md5/sha1 ids: unsupported in v1
    if id != expected_artifact_sha256: classify (below)
    return BoundInput(path, id, r.architecture_name, r.executable_name, len(r.function_addresses))
classify: 
    if side=='older' and id==project.newer_sha256 and project.older!=project.newer: ORIENTATION ('binexport-orientation')
    if side=='newer' and id==project.older_sha256 ...                              : ORIENTATION
    else                                                                            : PAIR ('binexport-wrong-artifact')
```
Cross-checks after both bind: `architecture_name` equal on both sides (else `binexport-arch-mismatch`, PT-SECONDARY-PAIR: BinDiff can still diff but the result is meaningless for a patch pair, refuse); `older != newer` ids; both non-empty call graphs (C3 already). `executable_name` is informational only (basename of the imported file; never trusted for identity).

Why `executable_id` is sufficient: the Ghidra exporter writes `program.getExecutableSHA256()` **[src BinExport2Builder]**, which is the SHA-256 of the file Ghidra imported; PatchTrace stores an immutable copy whose SHA-256 is the artifact hash, so equality proves "exported from byte-identical input". It does **not** prove the exporter did not tamper with the protobuf; the file is still an untrusted input to BinDiff (§7). IDA's `executable_id` format is unverified **[inf]** (the `.BinDiff` `file.hash` column is `CHARACTER(40)`, suggesting legacy SHA-1/MD5); v1 refuses non-64-hex ids with the message in §6 rather than comparing a weaker digest. A later slice may accept `md5`/`sha1` by hashing the stored artifact bytes, with a distinct provenance field `binding_digest='md5'` and a UI limitation.

Working copies: validated inputs are **copied** (not hardlinked/symlinked) into the private workdir as fixed names `older.BinExport` and `newer.BinExport`, then re-hashed; the SHA-256 of the copies is recorded as `input_file_sha256` and must equal the hash computed during validation (closes the validate→use window if the source changes). The fixed names make the output filename deterministic: `older_vs_newer.BinDiff` **[src GetTruncatedFilename(dir, primary_basename, "_vs_", secondary_basename, ".BinDiff")] [M]**. The name derives from each input's *file name* (basename with the last extension removed), not from the BinExport `executable_name`. BinDiff caps `output_dir + separator + name` at **250 characters**: above that it silently truncates the two name parts (so the file would no longer be called `older_vs_newer.BinDiff`) and errors only when truncation cannot fit **[src]**. PatchTrace therefore checks before spawning that the encoded length of `<workdir>/out/older_vs_newer.BinDiff` is at most 250 and otherwise fails closed with `workdir-error`; workdirs live under the system temp directory (short on Windows too: `%TEMP%\patchtrace-engine-…\patchtrace-bindiff-…`), and Windows MAX_PATH (260) is not reached. Source `.BinExport` files are never modified; they are stored read-only under `raw/secondary/inputs/<sha256>.BinExport` (bounded by the 512 MiB cap) so the run is reproducible (SPEC-27 provenance). Filenames from users never reach argv.

## 4. Invocation design

### 4.1 Argv (list, `shell=False`, absolute argv[0])
```
[<abs bindiff>, '--nologo', '--output_format=bin', '--output_dir=<workdir>/out',
 '--config=<workdir>/bindiff.json',
 '--primary=<workdir>/in/older.BinExport', '--secondary=<workdir>/in/newer.BinExport']
```
- Named flags beat positionals and avoid the "Extra arguments" path **[src]**. `=`-joined forms avoid argv-splitting ambiguity on Windows `list2cmdline` (paths may contain spaces; `run_process` passes through `subprocess.list2cmdline`).
- `--output_dir` must be an existing writable directory **[src]**: create `out/` first. The directory contains only our outputs.
- `--config`: `bindiff.json` is a private minimal config (the two bytes `{}`, UTF-8 without BOM, written verbatim) and is **the** mechanism that neutralises user and machine configuration. At start-up BinDiff merges `Defaults()` with the machine config (`/etc/opt/bindiff/bindiff.json` on Linux, a fixed path; `SHGetFolderPath(CSIDL_COMMON_APPDATA)\BinDiff\bindiff.json` on Windows) and the user config (`$HOME/.bindiff/bindiff.json`; `SHGetFolderPath(CSIDL_APPDATA)\BinDiff\bindiff.json`), silently ignoring unreadable files; `--config=<file>` then **replaces** that result with `Defaults()` merged with the given file only **[src main_portable.cc, config.cc, binexport util/process.cc]**. Measured **[M]**: `{}` is accepted; a user config **or** a machine config (mounted over `/etc/opt` in a private mount namespace) holding a reduced `function_matching` list silently changed the result of a 20/21-function pair from 20 matches, similarity 97.19% to 19 matches, 85.34% without `--config`, and `--config` with `{}` restored the baseline exactly in both cases. Redirecting `HOME`/`APPDATA`/`PROGRAMDATA` (§4.2) is therefore **not sufficient on its own**: the Linux machine path ignores the environment **[src][M]**, and on Windows BinDiff asks `SHGetFolderPath` **[src]**, which resolves the folders from the user profile rather than from those variables **[inf, live-only]**; the environment redirection only keeps BinDiff's `mkdir $HOME/.bindiff` inside the private workdir on POSIX (on Windows it may still create `%APPDATA%\BinDiff` in the real profile **[inf]**). `--config` is a required option of the probe (§2 step 4) and an invalid config (empty file, BOM) fails with `invalid JSON in security.bindiff.Config` **[M research]**.
- Never passed: `--ui`, `--export`, `--ls`, `--md_index`, `--print_config`, `--flagfile` (would let a file inject arbitrary flags), `--fromenv`, `--tryfromenv` (would read `FLAGS_*` environment variables), `--undefok`, `--helpfull`/`--help*`/`--version` outside the probe, positional inputs, and directory inputs (batch mode would diff every ordered pair and, with no `--output_dir`, write beside the inputs **[src]**). `build_argv` re-checks every element against this list (`FORBIDDEN_FLAGS`) and the argv-equality test pins the exact list. `FLAGS_*` environment variables are ignored unless `--fromenv`/`--tryfromenv` is passed **[src absl] [M research]**, and the child environment is built from scratch anyway (§4.2).
- `argv_digest` (SPEC-28 §5.1): argv with the executable basename and paths replaced by `<exe> <workdir> <older> <newer>` placeholders; includes `--config` presence and `config_sha256` of the config bytes.

### 4.2 Environment (allowlist, built from scratch; `os.environ` is never copied)
POSIX: `PATH=<exe dir>:/usr/bin:/bin`, `HOME=<workdir>/home`, `TMPDIR=<workdir>/tmp`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`. No `LD_*`, `JAVA_*`, `JDK_JAVA_OPTIONS`, `XDG_*` (except `XDG_CONFIG_HOME=<workdir>/home/.config`), proxy, `PYTHON*`, credentials.
Windows: `SystemRoot`, `SystemDrive`, `windir` (copied), `PATH=<exe dir>;%SystemRoot%\System32`, `TEMP=TMP=<workdir>\tmp`, `USERPROFILE=<workdir>\home`, `APPDATA=<workdir>\home\AppData\Roaming`, `LOCALAPPDATA=<workdir>\home\AppData\Local`, `PROGRAMDATA=<workdir>\programdata` (defence in depth only: BinDiff's machine config is located with `SHGetFolderPath(CSIDL_COMMON_APPDATA)` **[src]**, which is not expected to honour the variable **[inf]**; `--config` is what neutralises it, §4.1). Missing `SystemRoot` makes many Windows DLL loads fail, so it is required.
Rationale: the CLI never needs Java (only `--ui`) **[src]**; measured on Linux **[M]** it is a single `execve` with no child process, `ldd` shows only libc/libstdc++/libgcc_s/libm/libdl/librt/libpthread, it runs under an empty environment and also **without `HOME`**, and makes **zero network syscalls** (strace) and runs unchanged in an empty network namespace (`unshare -n`). With `HOME` set it creates `$HOME/.bindiff` (left empty) and probes `$HOME/.bindiff/bindiff.json` even when `--config` is given; other files touched: the inputs, the `--config` file, `out/` (plus SQLite's `-journal` and `-wal` probes), `/etc/opt/bindiff` (stat), `/etc/localtime`, `/dev/urandom`, `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf` **[M strace]**. JVM variables are therefore excluded; if a live check ever shows the CLI loading a JRE, add `JAVA_HOME` from the install dir only.

### 4.3 Process, limits, cancellation
- Spawn only through `jobs.run_process(argv, cwd=<workdir>/cwd, env=env, cancel=job.cancel, timeout_seconds=deadline, check_output=guard, log_limit=64*1024, separate_streams=True, stderr_limit=256*1024)`. No new spawn code in `secondary/`. `cwd` is a private empty directory distinct from `in/` and `out/`.
- Windows: `run_process` already creates the child suspended, assigns it to a kill-on-close Job Object, then resumes; failure to contain fails closed **[src jobs.py]**. `terminate()` = `TerminateJobObject`, so the whole tree (including any JRE child) dies on cancel/timeout/exit. POSIX: `start_new_session` + `killpg(SIGKILL)`. BinDiff installs a SIGINT/SIGBREAK handler for graceful shutdown **[src]**; we do not rely on it (we SIGKILL; partial `.BinDiff` files are discarded with the workdir).
- `check_output` guard (polled every 50 ms by `run_process`): returns `'output-limit'` if `sum(size of files under out/) > 1 GiB` or the number of files in `out/` exceeds 4, and `'output-unexpected'` (→ `output-ambiguous`) if any entry in `out/` is a symlink/directory. Ceiling is above the importer's 512 MiB, so oversize is classified distinctly from a bounded-but-rejected file (§6). While the process runs, `out/` legitimately holds `older_vs_newer.BinDiff` **plus a transient SQLite rollback journal `older_vs_newer.BinDiff-journal`** **[M]**; the guard tolerates it (regular file, counted towards size/count). After a clean exit 0 the journal must be gone: any leftover entry, including a `-journal`, makes the output `output-ambiguous` (§4.4).
- Memory/CPU: no cap in v1 (D10). Document that parallelism with Ghidra/rz-diff is limited by SPEC-28 `max_parallel ≤ 2`.
- Timeout: `timeout_seconds` = caller value (default 1,800; validated int in 60..86,400, bool rejected, as in `run_rzdiff`). `reason=='timeout'` → status `timeout`.

### 4.4 Exit codes and success definition **[src]**
`0` success; `1` any `absl::Status` error printed as `Error: <msg>` on the error stream (`EXIT_FAILURE`), plus `exit(1)` on the third Ctrl-C. No "differences found" code. Measured **[M]**: progress and the summary go to stdout, errors to stderr (e.g. `Error: Need primary input (--primary)`, `Error: preparing statement 'DROP TABLE IF EXISTS metadata': file is not a database` for a non-database file already at the target name, `ERROR: Unknown command line flag 'x'`); success prints `matched: 20 of 20/21 (primary/secondary, 20/21 non-library)` and `Similarity: 97.1948% (Confidence: 99.2608%)`, writes one file and removes its journal.

**Success = exit 0 AND `reason is None` AND exactly one regular file named `older_vs_newer.BinDiff` in `out/` (no `-journal`, nothing else) AND it passes `import_bindiff`.** Two measured rules follow:
- **Exit 0 does not prove a result.** `--primary=<file>` without `--secondary` prints the usage text on stdout and exits **0** with no file **[M]** (a call with no `--primary` at all exits 1, `Need primary input`). Exit 0 with no file is `output-missing`; when stdout starts with the usage banner (`bindiff: Find similarities`) the message says BinDiff printed its usage text instead of diffing.
- **Any non-clean stop discards `out/` unread.** A SIGKILL about 50 ms after the output appeared left `older_vs_newer.BinDiff` of 53,248 bytes with a valid SQLite header and all seven tables but **zero `function` rows** (C4 follow-up; the research run also left a `-journal`) **[M]**. Imported, it would look like a clean "zero matches" result. So after `timeout`, `cancelled`, `output-limit`, `output-unexpected`, any other stop reason, or a non-zero/abnormal exit (including death by signal, returncode < 0), `out/` is never listed, hashed, preserved or imported; the whole workdir is removed.

Stdout is parsed only for the *advisory* summary lines `matched: N of P/S` and `Similarity: X% (Confidence: Y%)` for `EngineRun` diagnostics (bounded regex, never trusted over the database).

## 5. Pseudocode (adapter `bindiff` inside SPEC-28 registry)

```python
# secondary/bindiff_run.py   (pure + injected runner; no Qt)
def run_bindiff(cap, older_be, newer_be, project, *, cancel, timeout_seconds, runner=run_process,
                env_base=None) -> BindiffOutcome:
    require cap.supported and cap.version                      # else SecondaryError UNSUPPORTED
    validate_timeout(timeout_seconds)                          # int, 60..86400, not bool
    older = bind_binexport(older_be, project.older_sha256, 'older')   # §3, raises SecondaryError
    newer = bind_binexport(newer_be, project.newer_sha256, 'newer')
    require older.arch == newer.arch and older.id != newer.id
    with TemporaryDirectory(prefix='patchtrace-bindiff-') as wd:      # 0o700 on POSIX; ACL default on Windows
        wd = Path(wd)
        for d in ('in','out','cwd','home','tmp','programdata'): (wd/d).mkdir()
        h_old = copy_and_hash(older.path, wd/'in'/'older.BinExport'); h_new = copy_and_hash(newer.path, wd/'in'/'newer.BinExport')
        require h_old.sha256 == older.file_sha256 and h_new.sha256 == newer.file_sha256   # TOCTOU
        (wd/'bindiff.json').write_text('{}')
        argv = build_argv(cap.path, wd); env = build_env(cap.path, wd, env_base)          # §4.1/4.2
        started = utcnow()
        result = runner(argv, cwd=wd/'cwd', env=env, cancel=cancel, timeout_seconds=timeout_seconds,
                        check_output=lambda: out_guard(wd/'out'), log_limit=64*1024,
                        separate_streams=True, stderr_limit=256*1024)
        # ---- classify process result (order matters)
        if result.reason == 'cancelled':     raise SecondaryError('PT-SECONDARY-CANCEL', ...)
        if result.reason == 'timeout':       raise SecondaryError('PT-SECONDARY-RUN',  kind='timeout')
        if result.reason == 'output-limit':  raise SecondaryError('PT-SECONDARY-LIMIT', kind='output-limit')
        if result.reason:                    raise SecondaryError('PT-SECONDARY-RUN',  kind='stopped')
        if result.returncode != 0:           raise SecondaryError('PT-SECONDARY-RUN',  kind='nonzero-exit',
                                                  detail=sanitize(first_error_line(result.stderr_tail or result.log_tail)))
        # ---- locate output
        entries = list((wd/'out').iterdir())
        expected = wd/'out'/'older_vs_newer.BinDiff'
        if not entries:                       raise fail('output-missing')
        if entries != [expected] or expected.is_symlink() or not expected.is_file(): raise fail('output-ambiguous')
        size = expected.stat().st_size
        if size == 0:                         raise fail('output-invalid')          # importer rejects too
        # ---- preserve raw output BEFORE parsing (AGENTS.md: preserve upstream raw data)
        raw_dir = project.raw_dir/'secondary'; raw_dir.mkdir(exist_ok=True)
        out_sha = sha256_file(expected)                                           # streamed
        kept = raw_dir/f'bindiff-{out_sha}.BinDiff'
        if not kept.exists(): copy_atomic(expected, kept)                          # write temp + os.replace
        require sha256_file(kept) == out_sha
        # ---- validate + import (read-only SQLite, mode=ro&immutable=1, all checks of SPEC-10 §2)
        match_set = import_bindiff(kept, project.older_sha256, project.newer_sha256)  # raises PT-SECONDARY-INPUT/PAIR/ORIENTATION/LIMIT
        require match_set.file_sha256 == out_sha                                    # importer re-hashes: must agree
        require match_set.matches                                                   # zero matches: engine ran, status ok, CLI exit 4 (not error)
        warn_if(not match_set.engine_version.startswith(str(cap.major)))            # §2 consistency
        return BindiffOutcome(match_set, out_sha, kept, advisory=parse_summary(result.log_tail),
                              returncode=0, stderr_tail=sanitize(result.stderr_tail), started=started,
                              input_file_sha256=(h_old.sha256, h_new.sha256), config_sha256=sha256(b'{}'),
                              argv_digest=argv_digest(argv))
```
`require match_set.matches`: an empty `function` table from a *successful* run is legitimate (two unrelated or tiny binaries). It is returned as a set with zero matches and the scheduler maps it to the existing "ran cleanly, zero matches" outcome (CLI exit 4); it is not an error. The only exception: if the BinExports had ≥1 function each and BinDiff stdout claims `matched: N` with N>0 while the database has 0 rows → `output-invalid` (advisory contradiction).

Persistence (CLI/worker after the scheduler returns, `store.py`; scheduler itself never writes):
```text
on outcome ok:
    ms2 = ms.model_copy(update={contract:'secondary/2', run_id: run.run_id, image_base_subtracted:'unknown'})
    entry = publish_engine_set(store, guard(project, run, raw_sha256=run.raw_sha256, input_digest=ms.file_sha256), ..., ms2)
    run = EngineRun(engine='bindiff', engine_version=cap.version, executable_path_sha256=sha256(str(path)),
                    argv_digest, older_sha256, newer_sha256, orientation='older->newer', cache_key,
                    status='ok', error_code=None, returncode=0, started_utc, duration_ms,
                    stderr_tail=sanitize(stderr)[-65536:], output_sha256=out_sha, match_set_id=entry.id)
    publish_run(store, run)            # written even on failure/unsupported/timeout/cancelled with error_code
```
Provenance beyond `EngineRun` v1 fields goes in the **match-set `limitations`/`notes`** only if schema-neutral; additional fields (`input_binexport_sha256` pair, `config_sha256`, `untested_version`, `bindiff_summary`) require an append-only `engine-run/1` optional field set `provenance: dict[str,str]` (max 16 keys, 256 chars each, defaults `{}`; omitted when empty so old rows round-trip). That is the single contract change C4 requests from SPEC-28 and needs a schema regeneration.

Cache key (SPEC-28 §5.1) = `sha256(["bindiff", cap.version, argv_digest, older_sha256, newer_sha256, 'older->newer'])` **plus** the two `.BinExport` file hashes (they, not just artifact hashes, determine output). C4 therefore passes `extra=(older_binexport_sha256, newer_binexport_sha256)` into `cache_key`; this is an additive parameter of `cache_key()`.

## 6. Failure taxonomy and user-facing messages

`SecondaryError.code` stays within the existing `ErrorCode` Literal (no schema change); a new optional attribute `kind` (str, default `None`) carries the sub-class and is stored in `EngineRun.provenance['failure_kind']`. CLI exit mapping per SPEC-28 §7 (`INPUT/UNSUPPORTED/PAIR/ORIENTATION` → 2, `RUN/LIMIT` → 3, `CANCEL` → 5).

| kind | code | When | Message (no paths, no raw stderr beyond one sanitized line) |
|---|---|---|---|
| `not-configured` | UNSUPPORTED | no path configured/discovered | "BinDiff is not configured. Install BinDiff 8 and choose its `bindiff` executable (Setup), or pass --bindiff." |
| `not-found` | UNSUPPORTED | path missing / not file / is `bindiff_ui` | "The selected BinDiff executable is not usable (missing, not a file, or the UI launcher)." |
| `probe-failed` | UNSUPPORTED | spawn error, timeout, non-zero `--version`, no version text | "BinDiff did not report a version; it may be damaged or need a missing runtime library." |
| `unsupported-version` | UNSUPPORTED | major < 8 | "BinDiff {v} is older than the supported version 8." |
| `missing-option` | UNSUPPORTED | feature probe | "This BinDiff build lacks the command-line option {opt}; it cannot be driven safely." |
| `binexport-invalid` | INPUT | C3 validator fails | "{older/newer} .BinExport is not a valid BinExport2 file: {validator reason}." |
| `binexport-unsupported` | UNSUPPORTED | protobuf bindings absent | "BinExport validation is unavailable in this build." |
| `binexport-unbound` | INPUT | no/non-SHA-256 `executable_id` | "The {side} .BinExport does not record a SHA-256 of its source executable, so it cannot be tied to this project's file. Re-export it with a BinExport that writes the executable hash." |
| `binexport-wrong-artifact` | PAIR | id ≠ artifact hash | "The {side} .BinExport was exported from a different file than this project's {side} artifact." |
| `binexport-orientation` | ORIENTATION | ids swapped | "The .BinExport files are swapped: older and newer are reversed." |
| `binexport-arch-mismatch` | PAIR | architecture names differ | "The two .BinExport files describe different architectures." |
| `workdir-error` | RUN | temp dir/copy/hash mismatch/disk full | "Could not prepare a private working folder ({OS error name})." |
| `spawn-failed` | RUN | `OSError`/containment failure | "Could not start BinDiff ({reason}); the process could not be contained." |
| `timeout` | RUN | `reason=='timeout'` | "BinDiff exceeded the {N} s limit and was stopped. Increase the timeout or use smaller inputs." |
| `cancelled` | CANCEL | shared cancel event | "BinDiff was cancelled; its process tree was stopped and no result was stored." |
| `nonzero-exit` | RUN | returncode ≠ 0 | "BinDiff reported an error: {first sanitized `Error:` line, ≤200 chars}." |
| `output-missing` | RUN | exit 0, no file | "BinDiff finished without writing a result file." (stdout starting with the usage banner: "BinDiff printed its usage text instead of comparing the inputs and wrote no result file.") |
| `output-ambiguous` | RUN | unexpected/extra files, symlink | "BinDiff produced an unexpected set of output files; the result was discarded." |
| `output-limit` | LIMIT | > 1 GiB or too many files | "BinDiff output exceeded the safety limit and was stopped." |
| `output-invalid` | INPUT | importer reject (magic, schema, ranges, duplicates, > 512 MiB → LIMIT) | "BinDiff wrote a database that failed validation: {importer reason}." (importer's own messages) |
| `output-pair-mismatch` | PAIR/ORIENTATION | `file.hash` ≠ project hashes | importer messages (already specified) |
| `store-failed` | RUN | `EnrichmentError` on publish | "The result was valid but could not be stored: {code}. The raw `.BinDiff` was kept." |

Rules: stderr text is shown only after `sanitize()` (strip control chars/ANSI, collapse paths to basenames, cap 200 chars, never echo environment values); full tail only in memory for `--verbose`. A failure never deletes or modifies previously stored sets or runs; a failed run still writes an `EngineRun`.

## 7. Security invariants

1. Targets and inputs are **never executed**; BinDiff is the only child, launched with the CLI-only flag set (§4.1). `--ui`, `--export` (IDA `.idb` batch export, would launch IDA) and directory inputs are unreachable by construction; add a unit test asserting argv equality.
2. The `.BinDiff` database is **untrusted**: opened only via `import_bindiff`, from the preserved copy (not from a path BinDiff can still write to), and only after a clean stop (§4.4). Importer layers, in order: 16-byte SQLite magic and the 512 MiB size cap; SHA-256 of the bytes; `mode=ro&immutable=1` URI; `PRAGMA trusted_schema=OFF`; `PRAGMA query_only=1`; `SQLITE_DBCONFIG_DEFENSIVE` where Python exposes it (3.12+); `PRAGMA cell_size_check=ON`; `PRAGMA max_page_count` capped at the file's own page count; a **progress-handler deadline** (wall clock from the start of the import, checked every 10,000 SQLite VM steps, default 120 s, `PT-SECONDARY-LIMIT` on expiry); a fail-closed authorizer allowing only `SELECT`, reads of the seven fixed tables, `count()` and `PRAGMA table_info` on them; rejection of any trigger, view, virtual table or index on a non-table in `sqlite_master` (a genuine v8 file has the seven tables plus autoindexes only **[M]**); then the column, metadata, file-hash, range and duplicate checks of SPEC-10 §2. No extension loading, no `ATTACH`, nothing from the file executed beyond plain `SELECT` over fixed table names. Tests cover a trigger, a view named like a required table, a virtual table, the hardened pragmas, the deadline and byte-level mutation fuzz.
3. The `.BinExport` files are untrusted input to a native C++ parser with a history of an OOB read fixed in v7 **[src]**: validate with our parser first (bounds), run in a contained, killable, resource-timed process, **no network**, private cwd/HOME, allowlisted env. This is not a sandbox and must not be described as one.
4. **No network**: BinDiff CLI makes none on Linux **[M strace: zero socket/connect calls; identical result inside `unshare -n`]**. The live job re-checks with `unshare -rn` on Linux (records `blocked` where user namespaces are unavailable); Windows is unverified (manual/firewall note, §12 U6). PatchTrace passes no URLs, no proxy variables.
5. Filesystem containment: all writes go to the private workdir; the only project writes are PatchTrace's own copies (`raw/secondary/…`) after the process has exited. Workdir removal retries per architecture.md scratch policy; cleanup failure never changes a result status.
6. No user path or environment value reaches the stored record (`executable_path_sha256`, basenames only). Log tails are sanitized and bounded (64 KiB stored, 256 KiB captured stderr, 64 KiB stdout).
7. Deterministic identity: results are tied to artifact hashes via `file.hash` (importer) **and** via `.BinExport.executable_id` (before the run); orientation is fixed older→newer and re-checked.
8. Reconciliation is unchanged and read-only; BinDiff similarity/confidence are never combined with other engines and carry `BINDIFF_LIMITATIONS`.
9. Atomic persistence: raw file via temp+`os.replace`; set and run rows via `EnrichmentStore.publish` (transactional). Prior sets survive any failure.

## 8. Module layout and interface changes

```
src/patchtrace/secondary/
  bindiff.py          import_bindiff (unchanged API) + hardening in _read(): reject sqlite_master entries of type trigger/view/index-on-virtual; keep REQUIRED check
  bindiff_run.py      NEW  probe(), build_argv(), build_env(), out_guard(), run_bindiff(), parse_summary(), sanitize()   (pure + injected runner)
  bindiff_inputs.py   NEW  bind_binexport(), BoundInput, copy_and_hash()                 (uses binexport.validate_binexport)
  registry.py         bindiff adapter = {probe: bindiff_run.probe, argv, run: run_bindiff, parse: import_bindiff}  (replaces C1 stub)
  contracts.py        + SecondaryError.kind (optional attr); + EngineRun.provenance (SPEC-28 §4.1 addition)
src/patchtrace/runtime_discovery.py  + RuntimeCandidates.bindiff_executables (default () so positional construction stays valid)
src/patchtrace/cli.py                + `secondary run --engine bindiff --bindiff PATH --older-binexport P --newer-binexport P`;
                                       `secondary import-bindiff` unchanged
tools/bindiff_pin.json               NEW  bindiff-pin/1: {version, version_text, trust, signature, assets:{linux|windows:{name, url,
                                       size, sha256, executable, executable_size, executable_sha256, advisory}}, licence}
tools/provision_bindiff.py           NEW  download+verify+extract (CI only; stdlib ar+tar for the .deb; never runs the tool)
tests/ …                             see §9
docs/qa.md, tasks/todo.md            record live status (§9.4)
```
`runtime_discovery` additions (read-only, no execution, no `PATH`): env `PATCHTRACE_BINDIFF`; Windows `%ProgramFiles%\BinDiff\bin\bindiff.exe`, `%LOCALAPPDATA%\PatchTrace\runtimes\bindiff*\bin\bindiff.exe`; Linux `/opt/bindiff/bin/bindiff` **[M: deb layout]**, `~/.local/share/patchtrace/runtimes/bindiff*/bin/bindiff`. Candidates must be regular non-symlink files (so `/usr/bin/bindiff`, a symlink to `/opt/bindiff/bin/bindiff` in the `.deb` **[M]**, is intentionally not discovered; users can still select it explicitly, where it is resolved and probed). One-level `bindiff*` scan, bounded by `MAX_CHILDREN_PER_ROOT`.

`ui.py` untouched in C4. Setup-tab fields belong to C6.

## 9. Test plan

### 9.1 Fake `bindiff` executables (default CI, no real BinDiff)
`tests/fake_bindiff.py` writes a Python launcher usable as an *absolute executable*: on POSIX a `#!<sys.executable>` script with mode 0o755; on Windows a `.cmd`/tiny `.exe`-free approach is not allowed by `run_process` (CreateProcessW needs an image), so tests use `sys.executable` as argv[0] through an injected `runner` that rewrites argv to `[sys.executable, fake.py, *argv[1:]]` (as `test_secondary_rzdiff.py` does with fakes). Modes (selected by a marker file in `wd/cwd` or env-free sentinel in the fake's own dir):
`ok` (builds a valid `.BinDiff` using `tests/test_secondary_bindiff.py::build()` hoisted to `tests/bindiff_builder.py`, hashes taken from `--primary/--secondary` copies read via the BinExport protobuf); `version-7`, `no-version`, `missing-option`, `help-exit-1`, `exit-1-error`, `exit-0-no-file`, `two-files`, `symlink-output`, `huge-output` (sparse file > 1 GiB), `hang` (sleep → timeout/cancel), `spawn-grandchild` (verifies tree kill: grandchild pid must be dead after return), `wrong-hashes`, `reversed-hashes`, `stdout-claims-matches-but-empty-db`, `trigger-in-db`, `stderr-flood`, `writes-outside-out`; follow-up modes from the measurements: `usage-exit-0` (real usage text, exit 0, no file), `journal-transient` (journal present while running, removed before exit 0 → ok), `journal-left` (journal left after exit 0 → `output-ambiguous`), `partial-then-hang` (valid `.BinDiff` with an empty `function` table plus `-journal`, then sleeps → timeout/cancel must not preserve or import it) and `partial-then-kill` (same files, then dies by SIGKILL, or exit 137 where signals are unavailable). The fake's default `--version`/`--help` texts are the real v8 ones (help exits 1).
Assertions: exact argv list (no `--ui/--export/--ls`), `cwd` is a fresh empty dir distinct from `in/`+`out/`, env equals the allowlist exactly (sentinel secrets in `os.environ` such as `AWS_SECRET_ACCESS_KEY`, `JAVA_TOOL_OPTIONS`, `LD_PRELOAD`, `HTTPS_PROXY` absent), working dir removed afterwards, raw copy kept with matching hash, previous sets untouched on every failure, one `EngineRun` row per attempt with right `status/error_code/kind`, every failure kind in §6 reachable and message free of paths.
Probe tests: `--version` parsing table (`BinDiff 8`, `BinDiff 8, (c)…`, `BinDiff 9 (@abc)`, garbage), `bindiff_ui` rejected, `bindiff_cli` name rejected, unknown major with and without options.

### 9.2 Inputs
Generated BinExport2 messages (C3 builder): matching ids, empty id, md5-length id, uppercase id, swapped ids, arch mismatch, same id both sides, id of a third file, truncated/zero-byte file, 512 MiB+1 (size guard), TOCTOU (file mutated between validate and copy → `workdir-error`).

### 9.3 Golden `.BinDiff` fixtures
`tests/fixtures/secondary/bindiff-v8-pair.BinDiff` + `README` (provenance: tool version, command line, input BinExport SHA-256s, date, size ≤ 200 KiB) generated **once** by the live job (§10) from a small compiled pair (`tests/fixtures/old.c/new.c` DLLs or a synthetic BinExport pair) and committed. Tests: import golden → expected counts/algorithm names/flags set (snapshot), hash stability, mutation fuzz (flip bytes in header/schema rows → clean `SecondaryError`, never an uncaught `sqlite3` exception; Hypothesis is available in dev extras). A tiny stdout golden (`bindiff-v8-stdout.txt`) feeds `parse_summary`.
As built (C4 follow-up, 2026-10-14): `tests/fixtures/secondary/bindiff-v8-real-on-synthetic.BinDiff` (53,248 bytes) + `-stdout.txt` + provenance JSON were written by the **real** BinDiff 8 through the live harness from the synthetic encoder pair; `tests/test_bindiff_real_golden.py` checks hash/provenance, reproducible inputs, 20 matches with the two patched functions flagged, orientation, schema shape, the stdout summary and mutation fuzz. A golden from real-driver exports remains open.

### 9.4 Live acceptance, never silent
Marker `live_bindiff` (register in `pyproject.toml` `[tool.pytest.ini_options] markers`). A session-level hook in `tests/conftest.py`:
- if `PATCHTRACE_BINDIFF` is set and probe supports → run live tests (§10);
- else, **do not `skip`**: the live test file emits a single test `test_live_bindiff_status` that always passes but writes `build/live-status/bindiff.json` `{"status":"blocked","reason":"…","engine":"bindiff"}` and prints a `LIVE ACCEPTANCE BLOCKED: bindiff (reason)` section via `pytest_terminal_summary`;
- if `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` (set by the live CI job) and the tool is unavailable → the test **fails**.
`tools/check_live_status.py` aggregates `build/live-status/*.json` into the CI job summary and `docs/qa.md` row text (manual copy by the integrator; AGENTS.md requires blocked checks be tracked in `docs/qa.md`/`tasks/todo.md`). Statuses: `passed | failed | blocked`.
Live tests (each records `passed/failed/blocked` in `checks`): (a) probe returns supported with version 8 and, when provisioning exported `PATCHTRACE_BINDIFF_EXPECTED_VERSION`, exactly the pinned version text; (b) end-to-end through `run_engines` + `BinDiffAdapter` → `ok`, matches > 0, `file.hash` pair equals the bound ids (importer), `function.algorithm` names non-empty, exactly one raw `.BinDiff` preserved with the run's output hash, no workdir left; (c) cancel as soon as the output file appears on a large synthetic pair → `cancelled`, nothing preserved, no workdir left (the measured partial-file hazard of §4.4); (d) timeout on the same pair with a sub-second scheduler deadline → `timeout`, nothing preserved; (e) reversed BinExports rejected before spawn; (f) `unshare -rn` run succeeds on Linux (`blocked` where user namespaces are unavailable, always `blocked` on Windows); (g) output golden regenerates byte-different but import-equal (open). Input pair: `PATCHTRACE_LIVE_BINEXPORT_DIR` (real exports, accepted through C3's `accept_binexport`; `blocked` without C3) or, with `PATCHTRACE_LIVE_SYNTHETIC_PAIR=1`, a **synthetic** BinExport2 pair written by the stdlib encoder `tests/bindiff_live_pair.py` (20/21 functions with distinct mnemonic sequences, two patched functions, one added function, call edges, `executable_id` = SHA-256 of `patchtrace.sample.synthetic_pe(0/1)`; the ids are known by construction, so this route does not exercise the C3 validator). The status JSON records which input and which acceptance route ran; synthetic inputs are never described as real-driver evidence.

## 10. CI design

New workflow `.github/workflows/live-bindiff.yml` (owner C2/C4; do not touch `qa-windows.yml` gates):
- Triggers: `workflow_dispatch`, weekly `schedule`, and `pull_request` with path filters `src/patchtrace/secondary/bindiff*`, `tools/bindiff_pin.json`, `tools/provision_bindiff.py`. **Not** a required check until stable for ≥10 runs (then promote); the default `qa` job (fakes + golden) stays the merge gate.
- Matrix `ubuntu-22.04` (required mode) and `windows-latest` (**advisory** mode). Steps: checkout; `python -m pip install -e .[dev]`; `tools/provision_bindiff.py --os …` (downloads the asset URL from the pin file, compares size + SHA-256, extracts per D4/D5, verifies the extracted executable's pinned size/SHA-256, records the Windows `redist` preflight, **never executes the tool**); `actions/cache` keyed by pinned SHA-256; on success provisioning exports `PATCHTRACE_BINDIFF` and `PATCHTRACE_BINDIFF_EXPECTED_VERSION`, plus `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` in required mode only; the job sets `PATCHTRACE_LIVE_SYNTHETIC_PAIR=1`; `pytest -m live_bindiff -rA`; upload `build/live-status/` (status JSON, the produced `.BinDiff` and stdout); write the status table to `$GITHUB_STEP_SUMMARY`.
- Advisory (Windows): extraction, executable-hash or `redist` problems are recorded as `blocked` with an `unverified: …` reason and exit 0; the live-test step runs with `continue-on-error`, so a real failure is recorded as `failed` in the status JSON and summary but does not turn the workflow red. Integrity failures (download error, size/SHA-256 mismatch of the pinned asset) still fail the job on both OSes.
- Pin: `tools/bindiff_pin.json` holds the real v8 values (§12 U1). They are **trust-on-first-use**: computed from downloads of the official release assets in two sessions on 2026-10-14 through the same egress proxy (identical results), with no upstream-published digest to compare and the `.deb.asc` not verified (`"verified": false`, `signature.verified: false`). Before beta a human re-hashes from an independent network path and verifies the `.asc` with the maintainer key, then records `signature_verified_by` and the date. A pin whose URL/size/SHA-256 are missing still makes provisioning record `blocked` (`pin-missing`) instead of trusting a download.
- BinExport inputs in CI: the **synthetic pair from `tests/bindiff_live_pair.py`** (§9.4, generated per run; no committed binary inputs). A maintainer-generated pair from repo-owned sources may be committed later (spec decisions: only from repo-owned synthetic sources, ≤ 1 MiB, with provenance) and then supplied via `PATCHTRACE_LIVE_BINEXPORT_DIR`. Real BinDiff 8 accepts minimal synthetic graphs (20/20 matches on the encoder pair, 3/3 on C3's committed synthetic fixtures) **[M]**. Running Ghidra headless in CI is explicitly out of scope for C4.
- Windows job also exercises Job Object containment: `spawn-grandchild` live variant using the real exe is not possible, so rely on the fake test under `windows-latest` in the normal QA matrix (already `os: windows`), plus live cancel test (c).
- Failure policy: live job red = reported, not silently ignored; infra failures (download 404/5xx, sha mismatch) produce status `failed` with reason `provision`, distinct from `blocked` (tool intentionally absent on a fork without network, or an advisory Windows step that could not be verified).
- Licence hygiene: job logs the Apache-2.0 notice and records `bindiff_pin.json` source URL; nothing from the upstream package is committed except the golden `.BinDiff` produced by it (result data, not code) and its provenance.

## 11. PR breakdown and model tier

| PR | Scope | Tier | Notes |
|---|---|---|---|
| P1 | Spec freeze: this doc, SPEC-28 §4.1 `provenance` field + `cache_key(extra=)`, SPEC-10 §4 pointer, `docs/qa.md` row "BinDiff live: blocked" | low-cost (docs) | mergeable alone |
| P2 | `bindiff_inputs.py` + tests (needs C3 validator) | mid-tier | pure, fakes only |
| P3 | `bindiff_run.py` (`probe`, argv/env builders, `run_bindiff`, sanitize, out_guard) + fake-exe harness + failure taxonomy tests; adapter registration; CLI `secondary run --engine bindiff` | **mid-tier** (core slice) | escalate to top tier only for the Windows containment/env review if a test shows a leak |
| P4 | Importer hardening (trigger/view/virtual-table rejection, Hypothesis fuzz on header/schema) + `runtime_discovery` extension + tests | mid-tier | importer API unchanged; add regression for a trigger-bearing DB |
| P5 | `tools/provision_bindiff.py`, pin file (null hashes), `live-bindiff.yml`, conftest status hook, `check_live_status.py`, marker | mid-tier | workflow review by C2 owner |
| P6 | Live run on both OSes; fill pin hashes; commit golden `.BinDiff` + stdout + provenance; record real flags/exit codes back into §12; update SPEC-10 §4 as `verified` | **top-tier engineer or human with a live machine** if any unknown in §12 breaks the design | only item that cannot be done blind |
P2→P3 depend on C3/C1/C5 merges (see plan order C5 → C4). P4/P5 are independent of P3. Gates per PR: focused tests, `QT_QPA_PLATFORM=offscreen python -m pytest -q`, `python -m ruff check src tests tools`, Linux+Windows CI, schema regeneration for P1/P3.

## 12. Unknowns a live install resolves (answers measured 2026-10-14; Linux only)

Answered on Linux by running the real v8 CLI (**[M]**, research session and C4 follow-up; details in `../research/phase-c/bindiff-automation.md` §2-§9 and its follow-up section). Windows halves stay live-only.
- U1 **Answered.** Assets `bindiff_8_amd64.deb` (62,663,460 bytes, SHA-256 `821990e3974a9df6733794370e485486ac276ba5d777a06b4ebe575f092f4dda`) and `bindiff8.msi` (72,237,056 bytes, `688831e490bef8a20c9917048b693bad591f346b3b96489fc79ad8d20d7cb15f`) at `https://github.com/google/bindiff/releases/download/v8/<name>`; trust-on-first-use (two downloads, same proxy, identical hashes; no upstream digest; `.deb.asc` unverified). Deb layout `/opt/bindiff/bin/bindiff` (3,894,808 bytes, `eb0a88eb6518e000bc3c4eef66c22db7ace197173eb933ea5d1c8ac3f7d8d0fb`), `/usr/bin/bindiff` and `bin/bindiff_ui` are symlinks; runtime deps libc/libstdc++/libgcc_s/libm/libdl/librt/libpthread; extraction without postinst yields a runnable CLI.
- U2 **Partial, Windows live-only.** Static **[X]**: `ProgramFiles/BinDiff/bin/bindiff.exe` (3,396,896 bytes, `b1d4844d7c7f1ca7f9684e280e0807668633e1b2410b31beca5c9ace79b747dd`), PE32+ x86-64 console subsystem, imports the VC++ 2015-2022 runtime (`vcruntime140_1.dll` is not in the MSI). Whether `msiexec /a` yields a runnable exe, the exit/console behaviour and the redist need on `windows-latest` are recorded by the advisory Windows job.
- U3 **Answered (Linux).** `--version` → `BinDiff 8 (@568181968, Sep 25 2023)`, exit 0; `--help` → exit 1, stdout; `--logo` present; `metadata.version` = `BinDiff 8 (@568181968, Sep 25 2023)`. Windows output assumed identical (live-only).
- U4 **Answered (Linux).** `Error:` lines on stderr; progress/summary on stdout; no stderr output on success.
- U5 **Answered (Linux, plus source for Windows).** `{}` accepted; `--config` replaces the machine+user merge with `Defaults()` + the file; machine config `/etc/opt/bindiff/bindiff.json`, user config `$HOME/.bindiff/bindiff.json` (Windows: `SHGetFolderPath` APPDATA/COMMON_APPDATA `\BinDiff`). Both silently change results without `--config` and are neutralised with it (§4.1). `--print_config` is not used (no need for a config digest: the config bytes are fixed and hashed as `config_sha256`). Windows paths live-only.
- U6 **Answered (Linux).** Zero network syscalls; identical result in an empty network namespace; touches `$HOME/.bindiff` (created) and the paths listed in §4.2. Windows (Procmon/firewall) live-only.
- U7 **Answered (Linux).** No JRE, no child process, no environment variables needed; runs under `env -i` and without `HOME`.
- U8 **Partial.** Synthetic resource table in D9/D10. A non-database file already at the target name → exit 1 `file is not a database`; a valid database would be rebuilt by `DROP`/`CREATE` **[src]** (we always use a fresh `out/`). Real-driver runtime/memory and the zero-match behaviour on a real pair remain open.
- U9 **Open, live-only.** IDA/Binary Ninja `executable_id` formats unknown; BinDiff copies `executable_id` verbatim into `file.hash` (a 64-hex id survives intact) **[M]**.
- U10 **Partial.** Minimal synthetic BinExport2 graphs are accepted and matched (20/20 on the encoder pair, 3/3 on C3's committed synthetic fixtures) **[M]**; the "Subtract Imagebase" effect is unmeasured.
- U11 **Answered (Linux).** A SIGKILL leaves nothing outside `out/`; inside `out/` it can leave a valid-looking partial `.BinDiff` (and a `-journal`), handled by §4.4.

## 13. Decisions that need the product owner

1. Accept D1: BinDiff is never redistributed in the PatchTrace ZIP, only user-installed or provisioned by CI (alternative: later offline bundle after a NOTICE/JRE/yFiles licence review).
2. Accept D11: refuse `.BinExport` files without a 64-hex SHA-256 `executable_id` (blocks IDA exports if they use MD5/SHA-1) versus allowing an explicit "unverified binding" override with a UI warning.
3. Whether the weekly/path-filtered `live-bindiff` workflow may become a required check, and whether committing a maintainer-generated `.BinExport` pair (derived from our own compiled fixtures) is acceptable as CI input.

## 14. Build notes (C4 builder, 2026-10-14; append-only)

Implemented P1-P5 against fakes; P6 (live run, real pin, real golden) stays open. Deviations and decisions as built:
- **Override (supersedes D11 per spec-decisions-20261014.md):** a non-SHA-256 `executable_id` is refused by default (`binexport-unbound`); `--accept-unbound-binexport` binds it, records `EngineRun.provenance['binexport_binding'] = 'asserted:older=<kind>,newer=<kind>'`, and the importer then checks `file.hash` against the asserted ids via `import_bindiff(..., expected_hashes=)` while the set keeps the artifact hashes. A 64-hex id must always equal its artifact (override never hides a mismatch).
- **Seam:** `bindiff_inputs.AcceptedBinExportLike` Protocol (`snapshot_path`, `summary.file_sha256/executable_id/id_binding`, optional `architecture_name`); no C3 import in tested paths. CLI wraps C3 `accept_binexport` when `secondary/binexport_run.py` exists (C3 PAIR `executable_id_mismatch` that matches the other artifact is re-classified ORIENTATION); without C3, BinDiff is `unsupported` (`binexport-unsupported`). The separate `raw/secondary/inputs/<sha>.BinExport` copy of §3 is C3's snapshot (`<run>/raw/secondary/inputs`), not duplicated.
- **Modules:** probe/env in `bindiff_probe.py` (ownership table name), run in `bindiff_run.py`; the child env comes from the single shared `secondary/engine_env.py` (rz-diff reuses `backend.build_child_env(for_tool='rizin')`; `registry.safe_env` removed).
- **Raw location:** `<project>/runs/<run_id>/raw/secondary/bindiff-<sha256>.BinDiff` (the completed analysis run the set is attached to), preserved via temp + `os.replace` before import.
- **Scheduler seam (additive):** optional adapter hooks `cache_extra(cap, job)` (passed as `cache_key(extra=)`, the two snapshot hashes) and `provenance()`; `failure_kind` = `SecondaryError.kind` (or `timeout`/`cancelled`). Adapters without hooks produce identical rows/keys as before.
- **Timeout** maps to `PT-SECONDARY-TIMEOUT` (SPEC-28 code), not `RUN`+kind; `run_bindiff` validates 60..86,400; the scheduler path uses the CLI-validated deadline.
- **Output guard:** size/count -> `output-limit` (LIMIT); a symlink/directory in `out/` -> `output-ambiguous` (RUN), deterministic regardless of poll timing.
- **argv digest** uses a placeholder template plus a `--config-sha256=` pseudo element (digest only, never passed to BinDiff).
- **Importer hardening:** rejects triggers, views, virtual tables and indexes on non-tables; `PRAGMA trusted_schema=OFF`, `query_only`, `SQLITE_DBCONFIG_DEFENSIVE`, and a SELECT/READ-only authorizer over the fixed tables (research note bindiff-automation.md §3); `UnicodeDecodeError`/`OverflowError` from corrupt text now map to `PT-SECONDARY-INPUT` (found by the mutation fuzz).
- **Probe names:** only `bindiff`/`bindiff.exe` are accepted; tests add `bindiff.cmd` for the Windows fake launcher via monkeypatch. Relative `--bindiff` values are made absolute from the current directory, never looked up on PATH.
- **Pin gap (U1 still open):** `tools/bindiff_pin.json` has null URL/size/SHA-256; `provision_bindiff.py` records `blocked` (`pin-missing`) and exits 0 rather than trust-on-first-use; download/verify/extract failures record `failed` and exit 1. Asset names `bindiff_8_amd64.deb`/`bindiff8.msi` are unverified candidates.
- **Goldens:** `tests/fixtures/secondary/bindiff-synthetic-*` are SYNTHETIC (repo script `tools/make_bindiff_fixtures.py`); the live v8 golden of §9.3 remains open.
- **Live harness:** `tests/test_live_bindiff.py` + `tests/conftest.py` record `passed|failed|blocked` to `build/live-status/bindiff.json` (`PATCHTRACE_LIVE_STATUS_DIR`), print `LIVE ACCEPTANCE BLOCKED`, fail only with `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` (set by provisioning on success). End-to-end needs `PATCHTRACE_LIVE_BINEXPORT_DIR` and C3; the `unshare -rn` check (f) is recorded `blocked` (not wired).

### C4 follow-up (2026-10-14, after measuring the real BinDiff 8; supersedes the "Pin gap" and "Live harness" notes above)
- Spec text corrected from measurements (§1 D1/D4/D5/D9/D10, §2, §3, §4.1-§4.4, §6, §7, §9.4, §10, §12). Pin filled (U1), trust-on-first-use.
- Probe: `--config` added to the required options; symlinks resolved and the resolved path executed (unchanged code, now tested); the real v8 `--help` text is the fake's default and exits 1 as measured.
- Argv: `FORBIDDEN_FLAGS` gains `--flagfile`, `--fromenv`, `--tryfromenv`, `--undefok`, `--helpfull`, `--version`, `--help`; `build_argv` re-checks its output.
- Run: transient `-journal` tolerated during the run and rejected after exit 0; usage-text exit 0 reported as such (`output-missing`); every non-clean stop (timeout, cancel, guard stop, non-zero or signal exit) discards `out/` unread (tests with a fake that leaves a valid partial `.BinDiff` + journal); the 250-character output-path rule is checked before spawning (`workdir-error`).
- Importer: `cell_size_check`, `max_page_count` and a progress-handler deadline (`PT-SECONDARY-LIMIT`) added.
- Provisioning: stdlib `ar`+`tar` extraction (regular files/dirs only, path traversal and size caps), pinned executable hash check, Windows `--advisory` mode with the `redist` preflight. Live harness: synthetic pair encoder, end-to-end through `run_engines`, cancel-at-first-output, sub-second timeout, `unshare -rn`, pinned version text.
