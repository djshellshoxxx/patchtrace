# SPEC-29: Real BinDiff execution (Phase C, step C4)

Status: developer-ready draft, 2026-10-14. Contract versions: reuses `engine-run/1`, `secondary/2` (SPEC-28), `bindiff-adapter/1` (SPEC-10). Extends SPEC-10 §4 ("Running the tools") and fills the `bindiff` adapter stub in SPEC-28 §4.2. Depends on C3 (`.BinExport` validator + protobuf) and C1/C5 (`runs.py`, `registry.py`, `store.py`). No GUI (C6), no BinExport *production* (C3 decision), no calibration.

Evidence labels: **[src]** read in `google/bindiff` `main` (`main_portable.cc`, `README.md`, `docs/`) on 2026-10-14, plus the pinned research in `../research/phase3/binexport-bindiff.md`; **[rel]** from GitHub release pages; **[inf]** inference, must be confirmed on a live install (collected in §12). Nothing below was **[run]**: this environment has no BinDiff.

## 1. Decision record

| # | Question | Decision | Rationale |
|---|---|---|---|
| D1 | Bundle BinDiff in the Windows ZIP? | **No (alpha and beta).** User-installed or CI-provisioned only. | Apache-2.0 allows redistribution **[src LICENSE/README]**, but upstream installers bundle a JRE (JDK 16 in v7 **[src version-history]**), an IDA/Binary Ninja plugin set and a Java GUI built against the commercial yFiles library **[src README "Java GUI and yFiles"]**. Redistributing those needs a separate notice/licence review; we only call the headless CLI. Revisit only via the offline-bundle track, with a NOTICE audit. |
| D2 | How does a user point PatchTrace at BinDiff? | **Explicit absolute path** (CLI `--bindiff PATH`, env `PATCHTRACE_BINDIFF`, QSettings `engines/bindiff/path` later) with **read-only discovery prefill** via `runtime_discovery` (exactly one candidate, else list). Never `PATH` lookup, never auto-install. | Same rule as Python/Ghidra (SPEC-05) and `run_process` which already demands an absolute argv[0]. A probe (§2) validates before any run. |
| D3 | Which BinDiff builds are supported? | **BinDiff major 8** (`v8`, 2023-09-25 **[rel]**), plus self-built `main` whose probe passes. Minimum = 8; unknown newer majors are **supported only if the feature probe passes**, flagged `untested_version` in provenance. | v8 is the only open-source release; it added `--output_format=none` **[rel]**. We use only `bin`. |
| D4 | CI acquisition (Linux) | Download the pinned **v8 `.deb`** from the GitHub release, verify a **SHA-256 pinned in the repo** (`tools/bindiff_pin.json`), extract with `dpkg-deb -x` into a cache dir (no `dpkg -i`, no root, no postinst/IDA symlinking), cache by SHA-256. | Legal: Apache-2.0, we do not redistribute, we fetch from the upstream release. Avoids root and postinst side effects **[inf: postinst symlinks plugins, README/v7 notes "symlinked into per-user plugin directories"]**. |
| D5 | CI acquisition (Windows) | Download pinned `bindiff8.msi`, verify SHA-256, **administrative extract** `msiexec /a bindiff8.msi /qn TARGETDIR=<dir>` (no system install). Fallback if admin extract lacks the CLI: `msiexec /i … INSTALLDIR=…` on the ephemeral runner. | Ephemeral runner, nothing persistent. **[inf]** whether `/a` yields a runnable `bin\bindiff.exe`. |
| D6 | Who produces `.BinExport` inputs? | **Out of scope for C4**: C4 consumes two user/CI-supplied `.BinExport` files. | SPEC-10 §4; Ghidra headless export is unverified and version-pinned (C3). |
| D7 | Unsupported/unknown behaviour | Probe returns `Capability(supported=False, reason=…)`; scheduler records `EngineRun(status='unsupported')`; never a crash, never a guess. | Mirrors rz-diff `probe`. |
| D8 | Output formats requested | `--output_format=bin` only. No `log` (text `.results` is unparsed and adds an untrusted artefact). | Smaller attack surface; schema is fully validated by `import_bindiff`. |
| D9 | Default timeout | 1,800 s, range 60..86,400 (same as rz-diff). Probe 30 s. | BinDiff runtime on large drivers is unmeasured **[inf]**; bound with cancel. |
| D10 | Memory cap | None in v1 (documented), output-size cap enforced. Optional follow-up `memory_limit_bytes` in `run_process` (Job Object `JOB_OBJECT_LIMIT_JOB_MEMORY`, POSIX `RLIMIT_AS`) after live measurement. | `jobs.py` today only sets KILL_ON_JOB_CLOSE; AGENTS/architecture say "no invented hard memory cap". |
| D11 | `.BinExport` ↔ artifact binding | `executable_id` **must equal the project artifact SHA-256** (64 hex). Empty/absent/other length → refuse (`binexport-unbound`). No override flag in v1. | Fail closed; pairing evidence must not rest on filenames. See §3. |

### Bundling vs configuring vs discovery (summary)
Configured path is authoritative; discovery only pre-fills; the CI job sets `PATCHTRACE_BINDIFF` explicitly. A discovered or configured path is not a compatibility guarantee: the probe is.

## 2. Capability probe

Function `probe(executable: Path, env, cancel, runner=run_process) -> Capability` in `secondary/bindiff_run.py`. Never installs anything, never launches the UI, never touches inputs. Private temp cwd, sanitized env (§4.2), 30 s timeout, 64 KiB log cap.

Facts **[src main_portable.cc]**: the binary is `bindiff` (also acts as the UI launcher when `argv[0]` basename is `bindiff_ui` or `--ui` is passed; **never pass `--ui`**). Abseil flags are used, so `--version` prints `BinDiff <kBinDiffDetailedVersion>` (usage-config `version_string`) and exits 0 **[src + inf: absl `--version` exit 0]**; `--help` prints usage (absl may exit 1 for help **[inf]**, so accept exit 0 or 1 and judge by text). There is **no `bindiff_cli` binary** in the source tree; treat that name as non-existent and report it in the unsupported reason if a user selects one (`bindiff_cli` appears only in third-party docs **[inf]**).

Probe steps (each failure → unsupported with a specific reason, no raise):
1. `stat` the path: absolute, regular file, not a symlink target outside its parent install dir (resolve; reject if basename is `bindiff_ui*`, case-insensitive; accept `bindiff`, `bindiff.exe`).
2. Run `[exe, '--version']`. Exit 0 and `^BinDiff (\d+)` found in stdout/stderr (first matching line) → `major`, `detail` (rest of line, ≤120 chars, control chars stripped). Else `unsupported: "--version printed no recognisable BinDiff version"`.
3. `major < 8` → `unsupported: "BinDiff {detail} is older than 8"` (v7 and older lack the open CLI contract we verified; do not try).
4. Run `[exe, '--nologo', '--help']` (exit 0 or 1 accepted). Required substrings (feature probe, from the verified flag list): `--output_dir`, `--output_format`, `--primary`, `--secondary`, `--logo`. Missing any → `unsupported: "bindiff lacks required option --X"`. This also catches a renamed/changed CLI in future majors.
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

Working copies: validated inputs are **copied** (not hardlinked/symlinked) into the private workdir as fixed names `older.BinExport` and `newer.BinExport`, then re-hashed; the SHA-256 of the copies is recorded as `input_file_sha256` and must equal the hash computed during validation (closes the validate→use window if the source changes). The fixed names make the output filename deterministic: `older_vs_newer.BinDiff` **[src GetTruncatedFilename(dir, primary_basename, "_vs_", secondary_basename, ".BinDiff")]**. Source `.BinExport` files are never modified; they are stored read-only under `raw/secondary/inputs/<sha256>.BinExport` (bounded by the 512 MiB cap) so the run is reproducible (SPEC-27 provenance). Filenames from users never reach argv.

## 4. Invocation design

### 4.1 Argv (list, `shell=False`, absolute argv[0])
```
[<abs bindiff>, '--nologo', '--output_format=bin', '--output_dir=<workdir>/out',
 '--config=<workdir>/bindiff.json',
 '--primary=<workdir>/in/older.BinExport', '--secondary=<workdir>/in/newer.BinExport']
```
- Named flags beat positionals and avoid the "Extra arguments" path **[src]**. `=`-joined forms avoid argv-splitting ambiguity on Windows `list2cmdline` (paths may contain spaces; `run_process` passes through `subprocess.list2cmdline`).
- `--output_dir` must be an existing writable directory **[src]**: create `out/` first. The directory contains only our outputs.
- `--config`: `bindiff.json` is a private minimal config (`{}` written verbatim) so user/machine config files cannot change matching steps or the algorithm table **[inf]**: `LoadFromFile` is merged over `config::Defaults()` **[src]**; whether an empty JSON object is accepted is unverified, so the PR includes a live check, with the fallback "omit `--config`, set `HOME`/`APPDATA` to the private dir" (already in env). If `--config` is rejected the probe's `--print_config` run (see §12 U5) is the diagnostic.
- Never passed: `--ui`, `--export`, `--ls`, `--md_index`, `--print_config`, directory inputs (batch mode would diff every ordered pair and, with no `--output_dir`, write beside the inputs **[src]**).
- `argv_digest` (SPEC-28 §5.1): argv with the executable basename and paths replaced by `<exe> <workdir> <older> <newer>` placeholders; includes `--config` presence and `config_sha256` of the config bytes.

### 4.2 Environment (allowlist, built from scratch; `os.environ` is never copied)
POSIX: `PATH=<exe dir>:/usr/bin:/bin`, `HOME=<workdir>/home`, `TMPDIR=<workdir>/tmp`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`. No `LD_*`, `JAVA_*`, `JDK_JAVA_OPTIONS`, `XDG_*` (except `XDG_CONFIG_HOME=<workdir>/home/.config`), proxy, `PYTHON*`, credentials.
Windows: `SystemRoot`, `SystemDrive`, `windir` (copied), `PATH=<exe dir>;%SystemRoot%\System32`, `TEMP=TMP=<workdir>\tmp`, `USERPROFILE=<workdir>\home`, `APPDATA=<workdir>\home\AppData\Roaming`, `LOCALAPPDATA=<workdir>\home\AppData\Local`, `PROGRAMDATA=<workdir>\programdata` (BinDiff's machine config lives under ProgramData **[inf]**). Missing `SystemRoot` makes many Windows DLL loads fail, so it is required.
Rationale: the CLI never needs Java (only `--ui`) **[src]**, so JVM variables are excluded; if the live check shows the CLI loads a JRE, add `JAVA_HOME` from the install dir only.

### 4.3 Process, limits, cancellation
- Spawn only through `jobs.run_process(argv, cwd=<workdir>/cwd, env=env, cancel=job.cancel, timeout_seconds=deadline, check_output=guard, log_limit=64*1024, separate_streams=True, stderr_limit=256*1024)`. No new spawn code in `secondary/`. `cwd` is a private empty directory distinct from `in/` and `out/`.
- Windows: `run_process` already creates the child suspended, assigns it to a kill-on-close Job Object, then resumes; failure to contain fails closed **[src jobs.py]**. `terminate()` = `TerminateJobObject`, so the whole tree (including any JRE child) dies on cancel/timeout/exit. POSIX: `start_new_session` + `killpg(SIGKILL)`. BinDiff installs a SIGINT/SIGBREAK handler for graceful shutdown **[src]**; we do not rely on it (we SIGKILL; partial `.BinDiff` files are discarded with the workdir).
- `check_output` guard (polled every 50 ms by `run_process`): returns `'output-limit'` if `sum(size of files under out/) > 1 GiB` or the number of files in `out/` exceeds 4 or any entry in `out/` is a symlink/directory. Ceiling is above the importer's 512 MiB, so oversize is classified distinctly from a bounded-but-rejected file (§6).
- Memory/CPU: no cap in v1 (D10). Document that parallelism with Ghidra/rz-diff is limited by SPEC-28 `max_parallel ≤ 2`.
- Timeout: `timeout_seconds` = caller value (default 1,800; validated int in 60..86,400, bool rejected, as in `run_rzdiff`). `reason=='timeout'` → status `timeout`.

### 4.4 Exit codes and success definition **[src]**
`0` success; `1` any `absl::Status` error printed as `Error: <msg>` on the error stream (`EXIT_FAILURE`), plus `exit(1)` on the third Ctrl-C. No "differences found" code. **Success = exit 0 AND `reason is None` AND exactly one regular file named `older_vs_newer.BinDiff` in `out/` AND it passes `import_bindiff`.** Exit 0 with no file (e.g. only help printed) is `output-missing`. Stdout is parsed only for the *advisory* summary lines `matched: N of P/S` and `Similarity: X% (Confidence: Y%)` for `EngineRun` diagnostics (bounded regex, never trusted over the database).

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
| `output-missing` | RUN | exit 0, no file | "BinDiff finished without writing a result file." |
| `output-ambiguous` | RUN | unexpected/extra files, symlink | "BinDiff produced an unexpected set of output files; the result was discarded." |
| `output-limit` | LIMIT | > 1 GiB or too many files | "BinDiff output exceeded the safety limit and was stopped." |
| `output-invalid` | INPUT | importer reject (magic, schema, ranges, duplicates, > 512 MiB → LIMIT) | "BinDiff wrote a database that failed validation: {importer reason}." (importer's own messages) |
| `output-pair-mismatch` | PAIR/ORIENTATION | `file.hash` ≠ project hashes | importer messages (already specified) |
| `store-failed` | RUN | `EnrichmentError` on publish | "The result was valid but could not be stored: {code}. The raw `.BinDiff` was kept." |

Rules: stderr text is shown only after `sanitize()` (strip control chars/ANSI, collapse paths to basenames, cap 200 chars, never echo environment values); full tail only in memory for `--verbose`. A failure never deletes or modifies previously stored sets or runs; a failed run still writes an `EngineRun`.

## 7. Security invariants

1. Targets and inputs are **never executed**; BinDiff is the only child, launched with the CLI-only flag set (§4.1). `--ui`, `--export` (IDA `.idb` batch export, would launch IDA) and directory inputs are unreachable by construction; add a unit test asserting argv equality.
2. The `.BinDiff` database is **untrusted**: opened only via `import_bindiff` (`mode=ro&immutable=1`, `query_only`), after magic/size checks, from the preserved copy (not from a path BinDiff can still write to); no extension loading, no `ATTACH`, no view/trigger/function from the file executed beyond plain `SELECT` over fixed table names. Add a test with a database containing a trigger and a view named like a required table (must be rejected or inert) **[new hardening: importer currently checks `type='table'` only; PR-4 adds rejection of any trigger/view/virtual table in `sqlite_master`]**.
3. The `.BinExport` files are untrusted input to a native C++ parser with a history of an OOB read fixed in v7 **[src]**: validate with our parser first (bounds), run in a contained, killable, resource-timed process, **no network**, private cwd/HOME, allowlisted env. This is not a sandbox and must not be described as one.
4. **No network**: BinDiff CLI makes none **[inf]**. CI verifies with `unshare -rn` (Linux) in the live job; Windows verified manually/with a firewall rule note (§12 U6). PatchTrace passes no URLs, no proxy variables.
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
tools/bindiff_pin.json               NEW  {version, assets:{linux:{url, sha256, size}, windows:{url, sha256, size}}, licence:"Apache-2.0"}
tools/provision_bindiff.py           NEW  download+verify+extract (CI only; stdlib; never runs the tool)
tests/ …                             see §9
docs/qa.md, tasks/todo.md            record live status (§9.4)
```
`runtime_discovery` additions (read-only, no execution, no `PATH`): env `PATCHTRACE_BINDIFF`; Windows `%ProgramFiles%\BinDiff\bin\bindiff.exe`, `%LOCALAPPDATA%\PatchTrace\runtimes\bindiff*\bin\bindiff.exe`; Linux `/opt/bindiff/bin/bindiff` **[inf: deb layout]**, `~/.local/share/patchtrace/runtimes/bindiff*/bin/bindiff`. Candidates must be regular non-symlink files (so `/usr/bin/bindiff`, a probable symlink, is intentionally not discovered; users can still select it explicitly, where it is resolved and probed). One-level `bindiff*` scan, bounded by `MAX_CHILDREN_PER_ROOT`.

`ui.py` untouched in C4. Setup-tab fields belong to C6.

## 9. Test plan

### 9.1 Fake `bindiff` executables (default CI, no real BinDiff)
`tests/fake_bindiff.py` writes a Python launcher usable as an *absolute executable*: on POSIX a `#!<sys.executable>` script with mode 0o755; on Windows a `.cmd`/tiny `.exe`-free approach is not allowed by `run_process` (CreateProcessW needs an image), so tests use `sys.executable` as argv[0] through an injected `runner` that rewrites argv to `[sys.executable, fake.py, *argv[1:]]` (as `test_secondary_rzdiff.py` does with fakes). Modes (selected by a marker file in `wd/cwd` or env-free sentinel in the fake's own dir):
`ok` (builds a valid `.BinDiff` using `tests/test_secondary_bindiff.py::build()` hoisted to `tests/bindiff_builder.py`, hashes taken from `--primary/--secondary` copies read via the BinExport protobuf); `version-7`, `no-version`, `missing-option`, `help-exit-1`, `exit-1-error`, `exit-0-no-file`, `two-files`, `symlink-output`, `huge-output` (sparse file > 1 GiB), `hang` (sleep → timeout/cancel), `spawn-grandchild` (verifies tree kill: grandchild pid must be dead after return), `wrong-hashes`, `reversed-hashes`, `stdout-claims-matches-but-empty-db`, `trigger-in-db`, `stderr-flood`, `writes-outside-out`.
Assertions: exact argv list (no `--ui/--export/--ls`), `cwd` is a fresh empty dir distinct from `in/`+`out/`, env equals the allowlist exactly (sentinel secrets in `os.environ` such as `AWS_SECRET_ACCESS_KEY`, `JAVA_TOOL_OPTIONS`, `LD_PRELOAD`, `HTTPS_PROXY` absent), working dir removed afterwards, raw copy kept with matching hash, previous sets untouched on every failure, one `EngineRun` row per attempt with right `status/error_code/kind`, every failure kind in §6 reachable and message free of paths.
Probe tests: `--version` parsing table (`BinDiff 8`, `BinDiff 8, (c)…`, `BinDiff 9 (@abc)`, garbage), `bindiff_ui` rejected, `bindiff_cli` name rejected, unknown major with and without options.

### 9.2 Inputs
Generated BinExport2 messages (C3 builder): matching ids, empty id, md5-length id, uppercase id, swapped ids, arch mismatch, same id both sides, id of a third file, truncated/zero-byte file, 512 MiB+1 (size guard), TOCTOU (file mutated between validate and copy → `workdir-error`).

### 9.3 Golden `.BinDiff` fixtures
`tests/fixtures/secondary/bindiff-v8-pair.BinDiff` + `README` (provenance: tool version, command line, input BinExport SHA-256s, date, size ≤ 200 KiB) generated **once** by the live job (§10) from a small compiled pair (`tests/fixtures/old.c/new.c` DLLs or a synthetic BinExport pair) and committed. Tests: import golden → expected counts/algorithm names/flags set (snapshot), hash stability, mutation fuzz (flip bytes in header/schema rows → clean `SecondaryError`, never an uncaught `sqlite3` exception; Hypothesis is available in dev extras). A tiny stdout golden (`bindiff-v8-stdout.txt`) feeds `parse_summary`.

### 9.4 Live acceptance, never silent
Marker `live_bindiff` (register in `pyproject.toml` `[tool.pytest.ini_options] markers`). A session-level hook in `tests/conftest.py`:
- if `PATCHTRACE_BINDIFF` is set and probe supports → run live tests (§10);
- else, **do not `skip`**: the live test file emits a single test `test_live_bindiff_status` that always passes but writes `build/live-status/bindiff.json` `{"status":"blocked","reason":"…","engine":"bindiff"}` and prints a `LIVE ACCEPTANCE BLOCKED: bindiff (reason)` section via `pytest_terminal_summary`;
- if `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` (set by the live CI job) and the tool is unavailable → the test **fails**.
`tools/check_live_status.py` aggregates `build/live-status/*.json` into the CI job summary and `docs/qa.md` row text (manual copy by the integrator; AGENTS.md requires blocked checks be tracked in `docs/qa.md`/`tasks/todo.md`). Statuses: `passed | failed | blocked`.
Live tests (each records `passed/failed`): (a) probe returns supported with version 8; (b) end-to-end on the real pair → `ok`, matches > 0, `file.hash` pair equals artifact hashes, `function.algorithm` names non-empty, set stored and `reconcile` runs; (c) cancel mid-run kills the tree; (d) timeout with 1-s fake… (use `run_process` timeout 60 with a huge synthetic input only if available, else mark `blocked: no long-running input`); (e) reversed BinExports rejected before spawn; (f) `unshare -rn` run succeeds (no network need) on Linux; (g) output golden regenerates byte-different but import-equal (tolerance: `created/modified` timestamps).

## 10. CI design

New workflow `.github/workflows/live-bindiff.yml` (owner C2/C4; do not touch `qa-windows.yml` gates):
- Triggers: `workflow_dispatch`, weekly `schedule`, and `pull_request` with path filters `src/patchtrace/secondary/bindiff*`, `tools/bindiff_pin.json`, `tools/provision_bindiff.py`. **Not** a required check until stable for ≥10 runs (then promote); the default `qa` job (fakes + golden) stays the merge gate.
- Matrix `ubuntu-22.04`, `windows-latest`. Steps: checkout; `python -m pip install -e .[dev]`; `tools/provision_bindiff.py --os …` (downloads the asset URL from the pin file, compares size + SHA-256, extracts per D4/D5, prints version path, **never executes the tool**); `actions/cache` keyed by pinned SHA-256; set `PATCHTRACE_BINDIFF` and `PATCHTRACE_REQUIRE_LIVE_BINDIFF=1`; build the BinExport pair (committed generated pair, see below); `pytest -m live_bindiff -rA`; upload `build/live-status/` and the produced `.BinDiff` + stdout as artifacts; write the status table to `$GITHUB_STEP_SUMMARY`.
- Pin refresh: the first provisioning run in the PR that adds the job prints the real SHA-256; a human reviews and commits it (`tools/bindiff_pin.json` initial values are `"sha256": null` which makes the script fail with "pin missing" rather than trust-on-first-use). Optional: verify upstream `.asc` with the maintainer key whose fingerprint a human adds to the pin file **[inf: `.asc` exists for the deb **[research]**; key fingerprint unverified]**.
- BinExport inputs in CI: preferred = **committed small `.BinExport` pair** (generated once by a maintainer with Ghidra+BinExport, kept ≤ 1 MiB, with provenance README; reproducibility is *not* required in CI). Alternative if C3 ships a builder: synthetic BinExport2 messages (risk: BinDiff may reject minimal graphs **[inf]**). Running Ghidra headless in CI is explicitly out of scope for C4.
- Windows job also exercises Job Object containment: `spawn-grandchild` live variant using the real exe is not possible, so rely on the fake test under `windows-latest` in the normal QA matrix (already `os: windows`), plus live cancel test (c).
- Failure policy: live job red = reported, not silently ignored; infra failures (download 404/5xx, sha mismatch) produce status `failed` with reason `provision`, distinct from `blocked` (tool intentionally absent on a fork without network).
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

## 12. Unknowns only a live install can resolve (record answers in the golden README)

- U1 Exact asset names/URLs/sizes/SHA-256 of v8 (`bindiff_8_amd64.deb`, `bindiff8.msi` per research; the release page listing did not render asset names to the fetcher). Deb install layout (`/opt/bindiff/bin/bindiff`? `/usr/bin` symlink?) and runtime library deps (glibc, libstdc++); whether `dpkg-deb -x` extraction yields a runnable CLI without postinst.
- U2 Whether `msiexec /a` yields a runnable `bindiff.exe`, whether the exe is a console-subsystem app (stdout capture works) and whether it needs the MSVC redistributable.
- U3 `--version` exact output and exit code; `--help` exit code (0 or 1); presence of `--logo` in help; format of `kBinDiffDetailedVersion` and of `metadata.version` in produced databases.
- U4 Where `Error:` messages go (stderr vs stdout; assumed stderr) and whether any progress text arrives on stderr (flood risk).
- U5 Whether `--config=<file with {}>` is accepted, merged vs replacing defaults, and where user/machine config is read from (`~/.bindiff`, `%PROGRAMDATA%`); whether `--print_config` is safe to use in the probe for a config digest.
- U6 Network behaviour (none expected) and whether the CLI touches any user-profile path; verify with `strace -f -e trace=network,openat` / Procmon.
- U7 Whether the CLI loads a JRE (expected no); required environment variables for DLL/so resolution (`LD_LIBRARY_PATH` needs?); behaviour with a minimal env.
- U8 Real runtime/memory on a ~10 MB driver pair (informs default timeout and whether D10 needs a cap); behaviour when a pair has zero matches; whether `.BinDiff` already existing in `out/` is overwritten or errors (we always use a fresh dir).
- U9 `executable_id` format written by the IDA and Binary Ninja exporters (SHA-256 vs MD5/SHA-1), and by the Ghidra exporter when the program was imported from a non-flat container.
- U10 Whether minimal synthetic BinExport2 graphs are accepted by BinDiff; behaviour on a BinExport with "Subtract Imagebase" (addresses differ from Ghidriff's: affects reconciliation `absent` rows, currently flagged by `image_base_subtracted='unknown'`).
- U11 Whether a SIGKILLed BinDiff can leave temp files outside `out/`/`tmp` (assumed no).

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
