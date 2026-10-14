# Tool-adapter audit (C-tools) - 2026-10-14

Scope: `src/patchtrace/intelligence/tools/` (`common.py`, `process.py`, `capa.py`, `floss.py`, `diec.py`, `normalize.py`, `delta.py`), the containment they use (`jobs.run_process`, `secondary/engine_env.engine_env` via `process.tool_env`, `backend.build_child_env` only indirectly) and their tests, against `docs/specs/three-tool-evidence-adapters.md` (T1-T10) and `docs/plans/phase-d-build-coordination.md` s2. Read-only: no `src/` or test change. Baseline `67e5a6c` (branch `worktree-agent-ac64ba20cde289afd`), Linux, Python 3.13, uid 0. Windows was not run; Windows items are code reading and are labelled HYPOTHESIS. Reproductions are throw-away scripts kept outside the repository (scratchpad `tools_c_*.py`, `r1.py`, `r2.py`, run with `python -I`, `PYTHONPATH=src`).

Not re-audited (already in `docs/audits/process-supervision-20261014.md`): Job Object/`killpg` mechanics (PS-1..PS-14), SIGCHLD, `setsid` grandchildren, handle inheritance. Where a finding reuses one of them it says so.

Runner, scheduler, store, CLI, pin file, provisioning and live test do not exist yet (spec header, `tasks/todo.md:117-119`), so several containment properties below are "the helper API makes the mistake easy", not "a shipped path is broken". Those are marked CONTRACT.

## Summary

| Severity | Count | Ids |
| --- | --- | --- |
| High | 0 | |
| Medium | 6 | TA-1 .. TA-6 |
| Low-Med | 4 | TA-7 .. TA-10 |
| Low | 5 | TA-11 .. TA-15 |
| Info / doc | 3 | TA-16 .. TA-18 |

What held up (tried, no defect): absolute-executable-only (`regular_file` refuses relative paths and never searches PATH; `run_process` re-checks `Path(argv[0]).is_absolute()`), `shell=False` (POSIX `Popen`; Windows `CreateProcessW` with `lpApplicationName`), env is a from-scratch allow-list (no `AWS_*`, `PYTHON*`, proxy variables reach the child; repro E1), `stdin=DEVNULL`, separate bounded stderr, scratch under `mkdtemp` (0700), artifact re-hashed and made read-only before use, tools never given the project path, no target execution anywhere (static tools; FLOSS emulation gated by `EMULATION_CONSENT_SHA256`, `floss.build_argv` raises `PT-TOOL-CONSENT` otherwise), JSON strictness (duplicate keys, NaN, 200 000-deep nesting rejected in milliseconds), capa binding by md5/sha1/sha256, FLOSS static offsets re-read from verified bytes, RVA range checks against `SizeOfImage`, overlapping-section ambiguity, no nearest-function guessing. `sanitize` and `secret_kind` are linear on 200 KB hostile inputs (S1: 0.05-0.07 s).

## Findings

### TA-1 Medium - pydantic `ValidationError` escapes the parsers as a non-`PT-TOOL-*` exception
`capa.py:451-457` builds `CapabilityEvidence(address=address.value ...)`; `common.py:40` caps `Address` at `2**64-1`. `floss.py:320-322` builds `EvidenceLink(file_offset=item.offset)`; `common.py:177` caps it below `2**40`. The tool-side models (`capa.Address.value: int`, `floss.StaticString.offset: int >= 0`) accept any integer, and the range check that exists (`offset_to_rva`, `va_to_rva`) only records an anomaly and returns, so the unbounded value reaches the strict record.

Failing scenario: a tool (or a corrupted/hostile `matches[0][0]`) reports `{"type":"absolute","value": 2**70}` or a static string `offset: 2**41`. `parse()` raises `pydantic_core.ValidationError`, not `ToolError`. Spec T4/T7 wants "invalid address" to be a typed outcome and "one job's exception is that job's `failed` run"; a runner that maps `ToolError.code` gets no code, and the generic fallback (`PT-TOOL-RUN`) is the wrong one (should be `PT-TOOL-OUTPUT`/`PT-TOOL-ADDRESS`). `PT-TOOL-ADDRESS` (`common.py:43`) is defined and never raised anywhere in `src`.

Repro (ran): capa fixture with one match address `{'type':'file','value':2**70}` and the `absolute` variant -> `ValidationError ... CapabilityEvidence address Input should be less than or equal to 18446744073709551615`. FLOSS fixture with `static_strings[0].offset = 2**41` -> `ValidationError ... EvidenceLink file_offset Input should be less than 1099511627776`. Neither is a `ToolError`.
Fix direction: clamp or reject out-of-range addresses/offsets into an anomaly before constructing records, and wrap record construction in `except ValidationError -> ToolError('PT-TOOL-OUTPUT')`. Add the two repros as red tests.

### TA-2 Medium - capability delta keyed by `(kind, rule_id, scope)` hides a capability that appears in a new or changed function (SPEC T6.2 as written, but misleading)
`delta.py:141` groups by `(item.kind, item.rule_id, item.scope)`, `delta.py:147-148` calls any group present on both sides `unchanged/unchanged`. A function-scope rule that already matches somewhere in the older file (very common: loops, string references, stack-string helpers) therefore never produces `newly-introduced` when the newer file adds a second match in an added or modified function. Only a free-text note `match count 1 -> 2` is added (`delta.py:154-155`), and `has_changes` (`delta.py:305-307`) ignores notes, so the `intel-tools delta` exit code would be 4 ("comparable without changes").

Repro (ran, `tools_c_b.py`): capa `capa-api` goldens; add to the newer `get hostname` rule a second match at the added function `0x140001030`, pairing says that function is `added`. Result: `change='unchanged' classification='unchanged' notes=('match count 1 -> 2',)`, newer links `[rva:0x1030 function-start, rva:0x1053 function-start]`, `has_changes` for that rule `False`. The localized evidence that would rank candidate function 0x1030 is discarded from the classification.
Fix direction (spec first): classify per link, not per group - when counts or function sets differ, emit `added`/`removed` sub-entries for the extra localized links, or classify `unchanged` only when the localized function sets (mapped through the pairing) are equal. Keep the current behaviour only for file-scope rules.

### TA-3 Medium - truncated evidence sets are diffed as if complete
`capa.py:436-437` keeps the first `max_rule_matches` (20 000) matches in document order and sets `truncated`; `floss.py:304` does the same at 200 000 strings; `diec.py:256` at 512. `delta.compute` (`delta.py:299-302`) only ORs `truncated` into the output flag; entries beyond the cut on one side become `added`/`removed` with a definite classification, and `comparable` stays `True` with no reason.

Repro (ran): older capa set cut to its first 2 capabilities with `truncated=True`, newer complete -> `comparable True`, `truncated True`, `counts['capabilities_added'] == 5` (all five are artefacts). Document order is the tool's dict order, which is not stable across versions or rule sets, so the cut itself is arbitrary.
Fix direction: when either side is truncated, mark non-`unchanged` entries `unknown` (or make the pair non-comparable with `PT-TOOL-MISMATCH`), and sort before truncating.

### TA-4 Medium - tool stdout is lossy text: strict-UTF-8 contract is unenforceable, `stdout_digest` is not of the captured bytes, oversize can be a false positive
`jobs.py:328` decodes with `errors='replace'`; `process.py:258-263,278` re-encode that text. Consequences against spec T2/T4/T5.1 ("UTF-8 only", "SHA-256 of the exact captured bytes", "above the limit is `PT-TOOL-LIMIT`"):
1. `load_json_strict` can never see invalid UTF-8 from a tool, so the `not UTF-8` rejection (`common.py:354-356`) is dead for subprocess output; a stray `0xFF` inside a JSON string becomes U+FFFD and is accepted as valid evidence.
2. `Execution.digests()` hashes the re-encoded text, so `stdout_digest` and the raw sidecar (spec T2 "raw stdout preserved before parsing") differ from what the tool wrote.
3. `oversize = len(log_tail.encode()) > stdout_bytes` (`process.py:278`): each invalid byte grows from 1 to 3 bytes when re-encoded.

Repro (ran, real `execute()` with a Python child writing bytes): `b'{"a":"\xff"}'`, limit 64 -> accepted, `stdout_bytes == b'{"a":"\xef\xbf\xbd"}'`, `digest == sha256(raw)` is `False`. `b'\xff'*4`, limit 10 -> `oversize=True` for a 4-byte output (false `PT-TOOL-LIMIT`; Windows tools writing a cp1252 byte stream or a stray BOM are the likely trigger).
This is PS-13 in the process-supervision audit (Info there, left open "until an adapter needs exact bytes"): the adapters now need them. Fix direction: add a `log_bytes`/`stdout_bytes` field to `ProcessResult` (spec first), decode in the adapter strictly, and make the oversize test use byte counts.

### TA-5 Medium (CONTRACT) - `execute()` bounds memory of the parent but not time-to-limit or the child's memory
`process.py:273-274` passes `log_limit=limits.stdout_bytes+1` and no `check_output` and no `memory_limit_bytes`.
1. Output flood: the buffer keeps only a tail, so a child that prints without end is not stopped at the limit; it runs to the full timeout (capa default 1800 s, FLOSS deobfuscation 3600 s) burning a core and the pipe, then is reported `PT-TOOL-LIMIT`. Repro (ran): `limits=1 MiB`, `timeout=6`, child writes forever -> `elapsed 6.1 s, reason timeout, oversize True`. Spec T4 says "bounded output"; the unit being bounded is memory only. `check_output` (50 ms hook, `jobs.py:305-306`) could return a reason as soon as the cap is exceeded, but the tail buffer is private to `run_process`.
2. No memory cap: the consent text (`floss.py:45-51`) promises "a restricted environment and a timeout" and warns of "a lot of memory"; nothing caps the emulator or capa's Python process (the BinExport worker self-limits, process-supervision hazard 5). A hostile PE driving vivisect can exhaust host RAM; on Windows a Job-wide cap would also cover the PyInstaller bootloader child. (A 3 GiB allocation in a child was SIGKILLed in this container, rc -9, but that was the container's own limit, not PatchTrace's.)
Fix direction: add a `max_output` stop to `run_process` (kill when total bytes read exceed the limit) and decide a per-tool memory policy (Job Object `PROCESS_MEMORY` on Windows; do not use `RLIMIT_AS` for Ghidra's JVM).

### TA-6 Medium (CONTRACT) - the pin is recorded, not enforced; the executable is hashed once at probe and executed later
1. `capa.probe`/`floss.probe` mark any `9.x.y`/`3.x.y` build `supported=True` with `untested_version=True` (`capa.py:152-155,180`, `floss.py:136-152`). `tools/intel_tools_pin.json` does not exist (`ls tools`), so no component compares `executable_sha256` with a pinned digest, and the rules identity for embedded rules is just `embedded:<exe sha>`. diec is stricter (version and DB digest must be known or `accept_untested`, `diec.py:159-163`), so the three adapters disagree on what "version pin check" means. A newer capa that keeps the JSON shape but changes rule semantics is accepted and compared against an older-version run only by `config_digest`.
2. `executable_sha256` is computed in `_probe` and the path is later executed by the runner without a re-hash; `regular_file` resolves symlinks, and the probe cache key is `(path, mtime_ns, size)`. Swapping or replacing the binary in a user-writable directory (Downloads, a portable unzip) after the probe, with the same size and mtime restored, yields evidence stamped with the pinned hash. Same class for the rule/signature directories: `tree_digest` at probe vs `copy_tree` at run (the copy's digest is returned, but nothing compares it with the manifest, `capa.prepare`/`diec.prepare`).
Fix direction: land the pin file and make "supported" = pinned (or explicit opt-in), have the runner copy or re-hash the executable immediately before spawn and compare with the manifest and with `prepare()` digests, failing `PT-TOOL-STALE`.

### TA-7 Low-Med - FLOSS deobfuscation accepted when the emulation types were not actually enabled (false `none-found`)
`floss.py:291-295` only rejects types enabled beyond those requested. With `deobfuscate=True` the output may report `enable_stack_strings/tight/decoded = false` and zero such strings, and `parse()` returns a normal set. The delta then reads "no decoded strings" as a measured fact (T6.3, `representation-changed`).
Repro (ran): `floss-decode-older.deobfuscate.json` with the three flags set false and `decoded_strings=[]` -> accepted, `analysis['types'] == 'static'`, `0` decoded. Fix: require `enabled == requested` (or record `types_missing` and make the run `failed`/`PT-TOOL-OUTPUT`), and include the effective types in `options` comparison.

### TA-8 Low-Med - `process.sanitize` mangles any DiE text that contains `/` (path scrubber applied to non-path fields)
`process.py:37,45`: `_PATHISH` treats `/segment` runs as paths and replaces the whole run by its basename. `diec._evidence` applies it to `detector_rule`, `version`, `detect_string`, `filetype` (`diec.py:238-240`) and `delta.quality_flags` shows `detect_string`.
Repro (ran): `sanitize('Microsoft Visual C/C++(19.29.30133)[LTCG/C++]')` -> `'Microsoft Visual CC++]'`; `'UPX/LZMA'` -> `'UPXLZMA'`; `'Borland Delphi/Lazarus'` -> `'Borland DelphiLazarus'`. Distinct detections can collapse to one `detector_rule`, and `_environment`'s key (`delta.py:195-196`) falls back to `detector_rule` for library/format/other categories, so two different libraries can merge or an altered string can read as a change. Fix: sanitize paths only in stderr/error text; use `display_text` for tool-provided names.

### TA-9 Low-Med - `toolchain`/`packer`/`protector` carry unsanitized hostile text
`diec.py:233-237`: `label` is the raw `name`+`version` (200 chars), unlike `detector_rule` which is sanitized. `EnvironmentEvidence` accepts it (no character validation) and `delta._environment` surfaces it as `EnvironmentChange.label` (`delta.py:195,204`) and in the `toolchain-changed` flag text (`delta.py:221`).
Repro (ran): a detection named `'MSVC‮\x1b[31mevil\x00'` -> `toolchain == 'MSVC‮\x1b[31mevil\x00 1'` (bidi override, ESC and NUL preserved) while `detector_rule` shows `'MSVC‮evil'` (bidi survives even there; `sanitize` strips only control characters, not format characters). Spec T1/CLI: "never prints markup", `display_text` is "the only way a tool string becomes displayable text" (`common.py:5-6`). Fix: pass every tool string through `display_text`.

### TA-10 Low-Med - probe "never raises" is not true; transient failure is cached for the process lifetime
1. `process.tool_env` -> `engine_env` raises `OSError('SystemRoot is not set ...')` on Windows when neither `SystemRoot` nor `windir` is present (`engine_env.py:44-45`). `run_version_probe` (`process.py:282-292`) only has `finally`; the three `_probe` functions catch only `ToolError` (`capa.py:144`, `floss.py:128`, `diec.py:136`), so the documented "Never raises" (`capa.py:105`) is violated. Reproduced the raise with `tool_env(..., environ={}, windows=True)` (E3).
2. `probe` stores every outcome, including timeouts and spawn failures, in `_CACHE` keyed by `(path, mtime_ns, size, config)` (`capa.py:122-125`, same in floss/diec). Each probe makes two 60 s runs (`--version`, `--help`; `process.py:284`). HYPOTHESIS (Windows): a cold PyInstaller onefile start (extract 100+ MB into the scratch `tmp`, Defender scan of the extracted files) can exceed 60 s once; the adapter then reports `unsupported` until the application restarts. A user fixing nothing sees a permanent negative.
3. `Execution.spawn_error` is never surfaced: `capa.py:149-150` formats `exit_text(None)` = "no exit code" and a timeout is "signal 9" (`returncode` after kill), hiding `reason`.
Fix: catch `OSError` in `run_version_probe`; do not cache `timeout/cancelled/spawn` outcomes; include `reason`/`spawn_error` in the message.

### TA-11 Low - capa rule ids truncated to 256 characters collide
`capa.py:452` stores `rule_id=name[:256]` while the tool model accepts 1024 (`RuleMeta.name`, `capa.py:303`). Delta groups by `rule_id` (`delta.py:141`). Repro (ran): three rules named `'x'*300 + '0|1|2'` -> three evidence items with one distinct `rule_id` (256 chars). Custom rule directories are user-controlled; embedded rules are short. Fix: reject names over 256 as an anomaly or hash-suffix them.

### TA-12 Low - FLOSS `metadata.imagebase` is never compared with the PE header
capa records `base-differs` (`capa.py:411-412`); FLOSS uses `metadata.imagebase` for every stack/tight/decoded RVA (`floss.py:299,329`) with no check against `pe.image_base`. Repro (ran): imagebase `0x10000000` for a `0x140000000` image -> anomaly `address-out-of-image:0x140001036` and the link loses its function; a smaller shift that stays inside the image would silently move every `function_id` by the delta. T5.3 requires every RVA be checked against PatchTrace's own parse; here the base itself is trusted. Fix: compare and record `base-differs` (use PatchTrace's ImageBase when the tool's differs? no - treat as unlocalized).

### TA-13 Low - parse memory amplification
`capa.parse` validates the whole document with pydantic before the 20 000-match cap applies (`capa.py:397` vs `436`). Repro (ran): a 40.8 MB capa document with 40 000 matches -> 16.7 s, 857 MB peak RSS (about 21x); the 64 MiB limit extrapolates to about 1.3-1.5 GB and half a minute, on whatever thread calls `parse`. `Match.children`/`captures` are unbounded lists. Fix direction: parse in the worker process, lower `DEFAULT_LIMITS['capa']` or cap rule/match counts while streaming.

### TA-14 Low - environment key ignores `version` for non-toolchain categories
`delta.py:195` label = `toolchain or packer or protector or detector_rule`; for `library`, `format`, `overlay`, `other` the version (kept separately in `EnvironmentEvidence.version`) is not part of the key, so a library version change (for example an embedded runtime update) shows as `unchanged`. Informational flag only; no classification impact today.

### TA-15 Low (HYPOTHESIS, Windows) - containment details specific to PyInstaller onefile tools
Not run on Windows; these follow from code reading plus how capa/FLOSS are packaged (spec T1).
1. Encoding: `engine_env` Windows env has no `PYTHONUTF8`/`PYTHONIOENCODING` (repro E2: both absent), while POSIX gets `LANG=C.UTF-8`. A Python tool whose stdout is a pipe uses the ANSI code page on Windows; if capa/FLOSS emit non-ASCII JSON (pydantic `model_dump_json` does not escape non-ASCII; rule `source` is included in the capa document) the bytes are cp1252, not UTF-8, which TA-4 then silently mangles or a crash occurs on unencodable characters. Needs one live Windows run with a non-ASCII rule to confirm; if true set `PYTHONUTF8=1` in `tool_env` for these engines.
2. Kill vs onefile bootloader: on timeout/cancel `TerminateJobObject` kills the bootloader and child without the cleanup of `_MEI*`; those files live in `scratch/tmp`, and `remove_tree` (`process.py:209-224`) retries 3 times (0.6 s) then `ignore_errors=True`, so a locked tree is leaked silently (hundreds of MB per cancelled capa run) with no log.
3. `MAX_INPUT_PATH = 200` limits `scratch/in/artifact.bin` only; the onefile extraction adds `\tmp\_MEIxxxxxx\` plus capa's deep rule paths under the same root, which can pass 260 characters on long scratch parents (user-configured `--scratch`).
4. `_tree_entries` (`process.py:100-119`) rejects symlinks via `is_symlink()`; NTFS junctions are not symlinks to `Path.is_symlink()`/`os.walk(followlinks=False)` in all supported Python versions, so a junction inside a rules directory may be traversed and copied (information stays local; low impact).
5. POSIX/Windows `PATH` starts with the executable's directory (`engine_env.py:40,48`): a tool unzipped into a shared folder resolves siblings (`java`, helper exes) from there first. Acceptable for a private unzip; not for Downloads.

### TA-16 Info - `load_json_strict` accepts `1e999` (parses to `inf`)
`common.py:360` rejects the `Infinity` token only through `parse_constant`; `json.loads(b'{"a": 1e999}')` yields `inf` (R5). Today floats only occur in FLOSS `Number` fields that are never stored, so no impact; add `parse_float` if floats ever reach records.

### TA-17 Info / doc - the spec overclaims Ghidra backend coverage
Spec T10 says "The Ghidra backend is fake-tested only". `grep -n ghidra tests/test_intel_tools_*.py` finds only cache-key assertions (`test_intel_tools_common.py:66-67`); `_ghidra_version`, `ghidra_extra`, the `JAVA_HOME` PATH prepend in `tool_env` (`process.py:238-241`) and the probe branch are untested. Also `ghidra_extra` would emit the string `'None'` for an unset directory (`capa.py:75`) if called without the probe having passed.

### TA-18 Info - test evidence classification
No test is counted as live evidence incorrectly: `tests/test_intel_tools_parsers.py` header and `docs/qa.md:205-213` label the goldens as real tool output on synthetic PE inputs, "not evidence about real binaries", and list runner, CLI, Windows, Ghidra and live workflow as not run. Gaps (not mislabelling): `process.py`, all three `probe()` functions, `classify_exit`, `build_argv` for capa/diec, `copy_artifact`, `tool_env` and `execute` have no test at all (`grep` finds only `process.ArtifactCopy` imported by a test). TA-4, TA-5, TA-10 live exactly there. The error-code table also has unreachable codes: `PT-TOOL-ADDRESS`, `PT-TOOL-MISMATCH` (comparability returns plain reasons), `PT-TOOL-STORE` appear only in the `Literal` (`common.py:42-44`).

## Reproductions index (all run on this host)

| Id | Script | Output line |
| --- | --- | --- |
| TA-1 | `r2.py` (C1/C1b), `tools_c_a.py` (F1) | `ValidationError` for CapabilityEvidence.address and EvidenceLink.file_offset |
| TA-2 | `tools_c_b.py` D1 | `change= unchanged ... notes=('match count 1 -> 2',)`, has_changes False |
| TA-3 | `tools_c_b.py` D2 | `comparable True truncated True ... added count 5` |
| TA-4 | `r1.py` R3 | `digest==raw False`, `oversize True` for a 4-byte output at limit 10 |
| TA-5 | `tools_c_c.py` O1 | `elapsed 6.1 s reason timeout oversize True kept 1048577` |
| TA-7 | `tools_c_a.py` F2 | `accepted; types= static decoded 0` |
| TA-8 | `r1.py` R1 | `'Microsoft Visual CC++]'`, `'UPXLZMA'` |
| TA-9 | `r1.py` R2 | toolchain keeps U+202E, ESC, NUL |
| TA-10 | `tools_c_c.py` E3 | `OSError` from `tool_env` |
| TA-11 | `r2.py` C2 | `truncated rule ids 3 distinct 1` |
| TA-12 | `tools_c_a.py` F3 | `anomalies ('address-out-of-image:0x140001036',)` |
| TA-13 | `r2.py` C3 | `bytes 40778823 secs 16.7 maxrss MB 857` |
| TA-16 | `r1.py` R5 | `{'a': inf}` |

## Suggested order

1. TA-1 and TA-4 (typed errors, byte-exact stdout) before the runner is written; both change contracts, so spec first.
2. TA-2 and TA-3 before any delta is shown to a user; they decide whether the headline output is trustworthy.
3. TA-6 with the pin file and TA-5 limits inside the runner.
4. TA-7..TA-12 are small, each with a ready red test from the scripts above.
5. TA-15 needs a Windows run of the pinned capa/FLOSS with a non-ASCII rule and a cancelled run before the Windows leg of `live-intel-tools.yml` can be called green.
