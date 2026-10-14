# BinExport2 hostile-input research (Phase C, SPEC-10b)

Last validated: 2026-10-14 (second pass, primary sources + local measurement). Companion to `docs/specs/binexport2-support.md` (the spec). Plan: `docs/plans/hard-problems/binexport2-plan.md`; triage: `docs/plans/hard-problems/binexport2-troubleshooting.md`.

Evidence labels: [src] raw primary file read this pass; [run] measured locally this pass (Linux x86_64, CPython 3.13, protobuf 7.36.2 abi3 wheel, upb); [unv] could not be verified (github.com HTML/API return 403 in this session, only raw.githubusercontent.com works); [inf] inference. "validated 2026-10-14" = the line was re-checked on that date.

## A. Validation of the earlier note (row by row)

| # | Earlier claim | Verdict (validated 2026-10-14) |
|---|---|---|
| 1 | Headless Ghidra uses `-preScript BinExport.java` + `BinExport.properties`; spec §8 says `-postScript` | **Note right, spec wrong** [src README "Scripting"]. Exact recipe in §B1. Menu label also differs between docs (§B1). |
| 2 | BinDiff is the companion consumer; input rules undocumented | Confirmed, rules still not documented in bindiff README [src]. U12 stays open. |
| 3 | Diaphora AGPL, not a parser reference | [unv] licence not re-fetched; keep as design-only. No code reuse regardless. |
| 4 | atheris: py 3.11-3.14, instrument_imports | Confirmed [src atheris README] **plus a gap**: supports "Linux (32- and 64-bit) and Mac OS X" only, no Windows. Fuzz job must be Linux (or WSL). |
| 5 | env var `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION` is "belt-and-braces"; `Type()` unofficial | `Type()` unofficial: confirmed [src README: "not an officially-supported or stable API"]. **Env var correction** [src api_implementation.py]: setting it to `upb` does NOT prevent fallback. If `google._upb._message` fails to import, the code only emits a `warnings.warn` and sets type `python`; it raises only when the *internal* var `PROTOCOL_BUFFERS_PYTHON_INTERNAL_FORCE_IMPLEMENTATION` is set (unsupported). So the post-import `Type()=='upb'` assertion is the only real guard, not optional. |
| 6 | GHSA-8qvm-5x2c-j2w7 / CVE-2025-4565 pure-Python only | [unv] advisory page 403. Keep as "reported"; do not quote versions. Pure Python is a DoS vector regardless: measured 85x RSS / 16 s (spec §1). |
| 7 | Issue #26437 MessageSet depth reset | [unv] page 403. Not schema relevant. Local check [run]: unknown-group nesting 99 OK, 101 `DecodeError` (limit 100 holds for groups in upb 7.36.2). |
| 8 | Issue #28864 text_format quadratic | [unv]. Irrelevant (binary only). |
| 9 | grpc #9160 size limits are app-level | [unv]. Principle stands (protobuf itself has no default size cap in Python). |
| 10 | libprotobuf-mutator depth issue #143 | [unv] issue; README fetched [src]: it is a libFuzzer C++ mutator, not usable from Python. Hypothesis remains the Python option. |
| 11 | `resource`: RLIMIT_AS bytes of address space, RLIMIT_DATA heap, `prlimit` Linux>=2.6.36/glibc>=2.13, Unix-only | Confirmed [src resource.rst]. `RLIMIT_CPU` sends SIGXCPU. |
| 12 | Job docs: KILL_ON_JOB_CLOSE; "silently ignored" | Quote is real [src job-objects.md] but it is about **working-set/priority changes**, not memory commit. **Gap closed** [src JOBOBJECT_BASIC_LIMIT_INFORMATION]: `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (0x100) -> "When a process attempts to commit memory that would exceed the per-process limit, it fails" (allocation fails, process is not terminated by the system); `JOB_OBJECT_LIMIT_JOB_MEMORY` (0x200) same for job-wide sum. See §B3. |
| - | "RLIMIT_AS limits VM not RSS, upb reserves more; a 14x formula could fail at startup" [inf] | **Mostly wrong for upb on Linux** [run]: Python+upb imports under a 64 MiB AS cap; a 10 MB / 2 M-record parse had VmPeak 115 MB vs VmHWM 107 MB. AS ~= RSS + ~10-60 MiB here. Windows commit limit is a different metric (§B3). |
| - | Spec §1 "protobuf 7.36.2, no deps, upb wheel" | Re-confirmed [run]: `pip download protobuf==7.36.2` gives `cp310-abi3-manylinux2014_x86_64`; version 7.36.2 imports as upb. |

## B. Deeper findings

### B1. Producing BinExport files (google/binexport README + java/README, [src], validated 2026-10-14)
- Tools: IDA Pro **9.4+ only** (8.x dropped), **Binary Ninja** (minimal UI: Tools > Plugins > BinExport; file placed next to the database; spec/earlier note omit Binary Ninja), Ghidra extension. Ghidra extension builds against **Ghidra 11.0.3**, OpenJDK 21, Gradle 8.7; java/README calls it "experimental" and "no operand trees" (supports spec tier-2 warn on operand shape).
- Ghidra GUI label: main README says "Binary Export (v2) for BinDiff", java/README says "Binary BinExport (v2) for BinDiff". The two upstream docs disagree; do not hard-code either in UI copy or detection, resolve on a live install.
- Ghidra headless (exact, from README): project must exist with the binary imported (`analyzeHeadless <loc> <proj> -import <file>`), then
  `analyzeHeadless <loc> <proj> -process <file> -propertiesPath <dir> -preScript BinExport.java -noanalysis` with `BinExport.properties` containing
  `Choose export file Export = test.BinExport` and `Choose options IDA Pro Compatibility = "Subtract Imagebase;Remap mnemonics;Prepend Namespace to Function Names"` (option list is semicolon separated);
  or positional args `-preScript BinExport.java test.BinExport "Prepend Namespace to Function Names" -noanalysis`. So the script runs as a **pre**-script of `-process`, on an already analyzed program (`-noanalysis`), not as post-script after import. Auto-appended `.BinExport` extension [src].
- IDA headless [src]: `idat -A -OBinExportAutoAction:<ACTION> -OBinExportModule:<PARAM> [-OBinExportLogFile:<f> -OBinExportAlsoLogToStdErr:TRUE] <file>` (options must precede file names); IDC functions `BinExportBinary(filename)`, `BinExportText`, `BinExportStatistics`; alternative `load_and_run_plugin("binexport12_ida", 2)` which ignores the filename and writes `<database stem>.BinExport`. Exact `BinExportAutoAction` value spelling for binary export is not in the README table [unv].
- Not verifiable this pass: the `BinExport.java` source (path 404 on `main`), its failure signalling ("Export failed" without throwing, spec §8(2)), and the latest release tag (API 403). Keep spec U11 open.
- Exporter id/arch details in spec §1 (executable_id sources) were read by the spec author from source; not re-read here [unv].

### B2. Protobuf runtime behaviour on hostile input ([run], protobuf 7.36.2 upb, validated 2026-10-14)
- **U4 resolved (Linux/upb)**: a proto2 `repeated string` field containing invalid UTF-8 (`b'\xff\xfe'`) **parses without error and the element is returned as `bytes`**, valid ones as `str`. Pure Python backend raises `UnicodeDecodeError` instead. Consequences: spec §6.5 `s.encode(...)` on a `bytes` element would raise `AttributeError` (an uncaught non-`SecondaryError` crash); backends disagree, another reason to assert upb. Check `isinstance(s, bytes)` -> `utf8_invalid`.
- **Memory cap failure shape**: under `RLIMIT_AS`, a too-small cap during `ParseFromString` raised `google.protobuf.message.DecodeError: ... Arena alloc failed` (not `MemoryError`) and Python exit code 1. A naive worker maps this to `parse_failed` (INPUT, "bad file") instead of `worker_oom`. Worker must treat "parse failed AND cap-sized process" as ambiguous: re-run once with a larger/no cap is wrong; instead compare `resource` peak (`ru_maxrss`/`VmPeak`) with the cap and report `memory_cap_suspected`.
- Plain Python allocation under the cap raised catchable `MemoryError` [run].
- Backend selection logic [src api_implementation.py]: default order upb > cpp > python; silent warn-and-fallback described in A5.
- Unknown-field/recursion limit 100 confirmed for groups [run]; spec's top-level wire pre-scan remains the right first gate.

### B3. Windows Job Object memory semantics [src MicrosoftDocs/sdk-api, validated 2026-10-14]
- `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.ProcessMemoryLimit` applies when `LimitFlags` has `JOB_OBJECT_LIMIT_PROCESS_MEMORY (0x100)`; `JobMemoryLimit` with `JOB_OBJECT_LIMIT_JOB_MEMORY (0x200)`. Both limit **committed (virtual) memory**, not working set/RSS; exceeding makes the commit attempt **fail** (no automatic kill). Optional completion-port message `JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT` / `JOB_OBJECT_MSG_JOB_MEMORY_LIMIT`. Nested jobs: the most restrictive wins; since Windows 8 a process may be in several jobs (AssignProcessToJobObject doc), so being inside a CI/parent job is not fatal.
- `PeakProcessMemoryUsed` / `PeakJobMemoryUsed` exist on the same structure: the doc says use them to calibrate limits. Query after exit via `QueryInformationJobObject` before closing the handle. This gives a measurable "peak committed" number per run.
- Existing code (`src/patchtrace/jobs.py`) creates the child suspended (flag 0x4), sets only `KILL_ON_JOB_CLOSE`, assigns, then resumes; the ctypes struct already has `process_memory`/`job_memory` fields. Adding the limit is a flag (0x2000 | 0x100) and one field; the suspended-start makes the cap race-free.
- **What the child sees is NOT documented**: [unv] exit code and whether CPython surfaces `MemoryError`, a fatal "Failed to allocate" abort, or a `DecodeError` as on Linux. Must be measured (plan step W1). Treat Windows `exit != 0` with `PeakProcessMemoryUsed >= 0.9 * limit` as `worker_oom`.
- Commit-vs-RSS mismatch: committed memory on Windows includes reserved-and-committed heap and each DLL's private data; the 14x-file formula was RSS-based [run] and must be re-derived from `PeakProcessMemoryUsed` on a Windows runner.

### B4. POSIX caps [src resource.rst + subprocess.rst, validated 2026-10-14]
- `preexec_fn` is documented "NOT SAFE to use in the presence of threads" (deadlock before exec) -> in the Qt GUI process use a tiny launcher (`python -c` setting `RLIMIT_AS` then `os.execv`) or `prlimit(pid, ...)` from the parent right after spawn (small race window before the worker reads input; make the worker block on stdin until the parent signals "limits applied"). `prlimit` is Linux-only (>=2.6.36, glibc>=2.13); macOS would need the launcher.
- `RLIMIT_CPU` -> SIGXCPU gives a second, independent CPU bound (belt to the wall-clock kill).

### B5. Prior art on bounding untrusted structured input (design references only)
- google/atheris [src]: instrument just the modules under test (`atheris.instrument_imports()`); Python-level uncaught exception = finding; Linux/macOS only.
- libprotobuf-mutator [src README]: structure-aware mutation exists only for C++ libFuzzer; there is no Python binding. Substitute: hypothesis mutation table (spec §10.2) or atheris with seed corpus from goldens and custom mutator that edits at the wire level (re-encode with the descriptor).
- BinDiff reads BinExport natively in C++ (google/bindiff); its acceptance rules are undocumented, so differential testing is the only way to learn them (spec U12).

## C. Corrections the spec should absorb
1. Spec §8 item 2: replace `-postScript BinExport.java <out> "<choices>"` with the README headless recipe (B1); script runs as `-preScript` of `-process` with `-noanalysis`.
2. Spec §2 rule 1: the env var does not enforce upb; keep the assertion and drop "belt-and-braces" wording. Add a note that the fallback is a warning, not an error.
3. Spec §6.5 string check: handle `bytes` elements returned by upb for invalid UTF-8 (U4 resolved).
4. Spec §7 / §6.1 exit-code table: add the "DecodeError under memory cap" ambiguity; decide cap-hit detection by peak memory, not exception type.
5. Spec §5 `memory_bytes` and U7: on Linux AS ~= RSS + ~60 MiB (measured); on Windows the metric is committed memory, to be measured via `PeakProcessMemoryUsed`.
6. Spec §10.2 nightly fuzz: Linux only (atheris); Windows relies on hypothesis.
7. Spec §8: mention Binary Ninja exporter and 'Ghidra extension built for 11.0.3' as a version-lock; Ghidra menu label differs between upstream docs.

## D. Still open (needs live runs or unreachable pages)
GHSA/CVE details and issue #26437 status (github.com 403); BinExport.java source and latest release; Windows child failure shape under `ProcessMemoryLimit`; real-export VM/RSS ratios; BinDiff acceptance parity.

## E. Sources (primary, fetched 2026-10-14 unless noted)
1. github.com/google/binexport README.md and java/README.md (raw)
2. github.com/google/bindiff README.md (raw)
3. protocolbuffers/protobuf python/README.md (raw)
4. protocolbuffers/protobuf python/google/protobuf/internal/api_implementation.py (raw)
5. CPython Doc/library/resource.rst and Doc/library/subprocess.rst (raw)
6. MicrosoftDocs/win32 desktop-src/ProcThread/job-objects.md (raw)
7. MicrosoftDocs/sdk-api ns-winnt-jobobject_basic_limit_information.md, ..._extended_limit_information.md, ..._notification_limit_information.md (raw)
8. MicrosoftDocs/sdk-api nf-jobapi2-assignprocesstojobobject.md, nf-jobapi2-setinformationjobobject.md (raw)
9. google/atheris README.md (raw)
10. google/libprotobuf-mutator README.md (raw)
11. Local measurements: protobuf 7.36.2 upb, CPython 3.13, Linux (scripts not committed; reproducible from B2 text)
12. In-repo: `src/patchtrace/jobs.py` (Windows Job Object code, read-only)
Unreachable this session: github.com HTML pages/advisories/issues, learn.microsoft.com, Ghidra repo help pages.
