# BinExport2 hostile-input plan (C3), ordered

Date 2026-10-14. Inputs: `docs/specs/binexport2-support.md` (spec), `docs/research/phase-c/binexport2-hostile-input.md` (research, "R"). Triage: `binexport2-troubleshooting.md`. Spec PR slices C3-1..C3-8 stay; this plan orders the *risky* work, adds decision points, measurements and fallbacks. Policy: AGENTS.md (spec first, red/green, no silent bypass, report blocked external acceptance separately).

## 0. Spec edits first (one docs PR, before C3-1 code)
Apply R section C items 1-7 to the spec. Gate: spec diff reviewed; no code yet. Why first: three spec statements are wrong or unsafe (Ghidra `-postScript`; env var "enforces" upb; `s.encode` on `bytes`).

## 1. Ordered steps

| # | Step | Decision point | Acceptance (measurable) | Fallback if it fails |
|---|---|---|---|---|
| S1 | Dependency + private-pool descriptor (C3-1) | D1: private pool works frozen on Windows? | Linux+Windows CI: `pip install --only-binary=:all:` ok; `api_implementation.Type()=='upb'`; golden field-table test green; frozen `--self-test` parses a minimal message and prints `upb` | Gencode (spec option B, header <= pin, same major). Never vendored pure Python (85x RSS) or hand decoder |
| S2 | Upb assertion + fallback tripwire | D2: how to detect silent fallback | Test: with `google._upb` import blocked (sys.modules hack) `load_binexport2_class()` returns `unsupported(protobuf_not_upb)`; warning "Falling back to the python implementation" is promoted to error in the worker (`-W error::UserWarning:google.protobuf` is not enough alone; assert `Type()`) | If `Type()` is renamed on a bump: pin test fails the bump PR; fall back to `import google._upb._message` success check |
| S3 | Limits, prescan, checker, identity (C3-2/3) | D3: which strict rules reject real exports (U3/U9) | Red/green per taxonomy slug; property tests (spec 10.2) green; **plus** `bytes`-element string case (R B2) returns `utf8_invalid` | Rule that false-rejects real goldens becomes a warning + test (spec U3 policy) |
| S4 | Snapshot + pipeline in-process (C3-4) | - | Mutation table: 100% of mutations give the exact slug; arbitrary bytes never raise non-`SecondaryError` (hypothesis 2,000 examples) | - |
| S5 | **Windows memory cap measurement spike (W1)** before coding C3-5 | D4: what the child sees at `ProcessMemoryLimit` | See section 2 W1; produces `docs/qa.md` row | If limit gives unrecoverable crash/no signal: rely on wall timeout + parent-side poll of `PeakProcessMemoryUsed` (QueryInformationJobObject) and `TerminateJobObject` when above cap; `JobMemoryLimit` as alternative |
| S6 | Isolation (C3-5): `jobs.run_process(memory_limit_bytes=)` | D5: POSIX mechanism | Windows: flags `0x2000|0x100`, `ProcessMemoryLimit` set, test child allocating past cap ends with mapped `worker_oom`. Linux: cap via launcher (no `preexec_fn` in threaded GUI) or `prlimit`; same test | `RLIMIT_CPU`+wall kill only; document cap as best-effort |
| S7 | Cap-hit classification | D6: DecodeError under cap | Linux [measured]: `Arena alloc failed` DecodeError. Rule: if worker fails with parse_failed and peak >= 0.9*cap, report `worker_oom`/`memory_cap`, not INPUT. Test with a cap-sized valid file | Parent re-checks result with `PeakProcessMemoryUsed`/`ru_maxrss` |
| S8 | Frozen worker smoke on both OSes | - | `PatchTrace secondary _binexport-worker` as child of frozen exe: exit 0, result JSON valid, `upb` | `--hidden-import google._upb._message` only if proven needed |
| S9 | Fuzz + goldens (C3-6/7) | D7: golden provenance (human w/ Ghidra) | Nightly atheris (Linux only) 30 min no crash; goldens carry PROVENANCE.json; U1/U3/U5/U6/U9 rows recorded | Without goldens: report "synthetic only, no live compatibility" (AGENTS.md) |
| S10 | Phase E headless producer spec | D8: ship own script vs upstream | Written spec using README recipe (R B1), not `-postScript` | Keep user-supplied only |

## 2. Measurements on live CI

### W1 Windows memory-limit behaviour (new `tools/qa_binexport_memcap.py`, run in `qa-windows.yml`, record in `docs/qa.md`)
1. Spawn via `jobs.run_process` a child (`python -I -c`) that tries `bytearray(n)` in 64 MiB steps up to 2x the limit, printing progress. Limits tested: 256 MiB, 512 MiB, 1 GiB (ProcessMemoryLimit).
2. Record: exit code (hex), stderr tail, last printed step, whether `MemoryError` appears, `PeakProcessMemoryUsed` via `QueryInformationJobObject` (class 9) before closing the job, wall time.
3. Second child: same limit, `ParseFromString` of a generated N-record message (as research B2 script, 2 M records) with limit just below/above measured peak. Record whether error is `DecodeError("Arena alloc failed")`, `MemoryError`, or abnormal exit.
4. Third: frozen exe (`PatchTrace.exe`) doing the same via the worker (ensures PyInstaller bootloader/DLL commit fits: measure committed bytes of an *idle* frozen worker; set `memory_bytes` floor >= 4x that).
Pass criteria: every case ends within 60 s, no orphan process, parent parses a deterministic outcome. Output feeds the exit-code table in spec §7.

### W2 Linux caps
`ru_maxrss`, `VmPeak` (from `/proc/<pid>/status` before exit) vs file size for synthetic and golden files (2, 14, 100, 256 MiB). Fit `memory_bytes = a*file + b`; spec's 14x+256 MiB is RSS-based, R B2 shows AS ~= RSS + 10..60 MiB for upb. Pass: worker succeeds at cap = 1.25 x measured peak and `worker_oom` at 0.5 x.

### W3 Throughput and timeouts
Per pass wall time for 14 MB synthetic, golden, and a 100 MB synthetic on `windows-latest` and `ubuntu-latest` (record machine type). Pass: whole `inspect_binexport` of 14 MB <= 20 s on the slower runner; if not, raise `wall_seconds` or fix the slowest pass (profile via `cProfile` in worker with an env switch, off by default).

### W4 Packaging deltas
Frozen size delta (Windows+Linux), `google/_upb/_message.*` present in inventory, AV scan result (Defender on runner log), `pip check`. Record in `docs/qa.md`.

### W5 Compat with real exports (needs human/Ghidra)
Strict-rule hit counts per rule over real goldens; any rejection of an exporter-written file = bug in rule (downgrade to warning).

## 3. Risks

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| Silent pure-Python fallback (frozen build misses `_message.pyd`) | M / high (85x RSS, 16 s) | S2 tripwire, inventory guard, frozen smoke |
| Memory cap cut-off reported as "bad file" | H (measured Linux) / medium | S7 classification |
| Windows commit-limit too tight for frozen worker | M / medium | W1 idle-commit floor; `memory_bytes` floor 512 MiB |
| Strict rules reject real exports | M / high (user-visible) | W5, warn-not-reject fallback, goldens before enabling hard rules |
| `bytes` string elements crash checker | H unless fixed | Handle `bytes`; test |
| Ghidra extension locked to 11.0.3 | H / Phase E only | Version probe; refuse unsupported |
| Backend `Type()` API renamed | L / low | Pin + dedicated bump PR |
| Fuzzing impossible on Windows | certain | Linux nightly + hypothesis in CI |

## 4. Reporting
Each PR: spec section, red tests, exact test commands/results, CI Linux+Windows links. External-blocked items (Ghidra/IDA goldens, Windows measurements before runner access, GHSA verification) listed separately as open gates. Never report synthetic tests as live compatibility.
