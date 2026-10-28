# Security and robustness review: Windows alpha run (2026-10-28)

**AI-assisted review, not an independent audit.** Scope: the changes on branch `claude/patchtrace-haiku-agent-motpbx`
(PR #102), the release pipeline, and a time-boxed hostile-input sweep of the pure-Python parsers. Nothing analysed was
executed; all inputs were synthetic or mutated test fixtures. No guarantee of absence of defects is implied.

Base: `main` at `e093ade`. Evidence commands and run numbers are given per finding; QA records are in `docs/qa.md`
(entry SPEC-26-A2 and the Windows alpha entry below it).

## Method

1. Self-review of every diff in this run (dead code, debug output, unhandled returns, cleanup, copy-paste).
2. Source sweep of `src/` and `tools/` for `shell=True`, `eval`/`exec` on data, `pickle`/`marshal`, unsafe YAML,
   string-built SQL and archive extraction.
3. Release-pipeline review (`.github/workflows/qa-windows.yml`): permissions, third-party actions, integrity checks.
4. Mutation fuzzing (random, not coverage-guided) of: `pe_overview` (PE reader, resources, version info, manifest,
   tables), `representations`/`artifact_bytes`/`raw_view`, Ghidriff JSON import and normalization, the strict-JSON
   loaders, BinDiff SQLite import, rz-diff output parsing; plus scale probes. Iterations: PE about 249k; BinDiff about
   503k (bytes and SQL modes); JSON loaders 330k; rz-diff 146k; Ghidriff normalization 518k; byte representations 125k
   calls. BinExport2 is excluded (fuzzed nightly by `tools/fuzz_binexport.py`).
5. Performance: profile of the enrichment cache-hit path at 10,000 pairs (`tools/bench_enrichment.py`).

## Findings

Severity is the reviewer's judgement of impact on a desktop analysis tool that opens untrusted files.

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| S1 | Medium | Release pipeline | `softprops/action-gh-release@v2` ran by mutable tag in the only `contents: write` job, with the release bytes in reach | **Fixed**: pinned to `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` (v2 = v2.6.2 on 2026-10-28); `tests/test_release_gate.py` rejects a tag-pinned third-party action in that job |
| S2 | Medium | Release integrity | `PatchTrace-Windows-x64-Setup.exe.sha256` was written in text mode, so on Windows it ended in CRLF and `sha256sum -c` failed (`...Setup.exe\r: No such file`); the release job checked only the ZIP sidecar, so published Setup sidecars carried the defect | **Fixed**: LF-only writer `package_windows_installer.write_checksum` + regression test; `windows-validate` and the release job run `sha256sum -c` on both sidecars. Evidence: run 40625345051 failed on it, run 40626210012 passed. Earlier release assets are unchanged (the hash values were right, the line ending was not) |
| S3 | Low-Medium | Data safety | Report export replaced an existing file at the fixed default path `exports/report.<ext>` without a backup | **Fixed**: differing earlier bytes kept as `<stem>.previous-<sha8><suffix>` before the atomic replace; failed backup aborts; oversized existing file refused. `tests/test_report_export_backup.py` |
| F4 | Low | Ghidriff import | `strict_json` accepted nesting to about 9,000 levels; from about 250 levels pydantic failed with an untagged error **after** the raw bytes were staged, leaving read-only orphan files in `runs/<id>/raw/` | **Fixed**: deterministic `MAX_JSON_DEPTH = 128` in `persistence.strict_json` (all 22 callers), rejected before staging; regression asserts nothing is left under `runs/` |
| F3 | Low | Ghidriff normalization | A `ratio` integer of 10^309 or more raised `OverflowError` in `math.isfinite` instead of `PT-SCHEMA` | **Fixed**: range check first (`normalization.py`); regression test |
| F6 | Low | Winbindex (network data) | A `"\ud800"` escape passed Winbindex's own loader and raised `UnicodeEncodeError` when hashed, instead of `AcquisitionError` (CLI exit 3, not 2) | **Fixed**: the loader rejects unencodable strings; regression test |
| F8 | Low | Project files | A crafted `project.sqlite3` path with a NUL byte, a component over 255 bytes or a lone surrogate raised raw `OSError`/`ValueError` out of `ProjectService.open` | **Fixed**: `ingestion.safe_path` validates the text and maps filesystem errors to `PT-STORAGE`; regression tests |
| F7 | Low | rz-diff / BinDiff output | Deep JSON (RecursionError), lone surrogates in names and version strings beyond 4,300 digits escaped as other exception types. Only reachable from a replaced tool binary, already trusted to run; the scheduler caught all of them | **Fixed**: parse errors are `SecondaryError`; absurd version strings are "unrecognised"; regression tests |
| F1 | Low (Medium if wired) | `pe_overview/tables.py` | `PeTables.relocations` counted only appended entries: a zero-filled or section-aliased `.reloc` made it loop up to 64 MiB of virtual data (1.5 KiB file: 9 s, 157 MB; 995 KiB: up to 30 s, 3 GB, 16M warnings) before failing. No shipped caller today (tests and a `rules/window.py` protocol only) | **Fixed**: `parse_base_relocations` checks each block's declared count against `MAX_RELOCS` before walking it and reports an unknown type once; regression tests |
| F2 | Info | `pe_overview/tables.py` | `runtime_functions` accepts up to the documented `MAX_PDATA` = 4M entries (aliased sections: 21 s, 720 MB). The wired twin `unified/ir/pe_tables.py` is bounded (`PT-UNIFIED-LIMIT` in 1.7 s, 33 MB) | Open, by design: revisit the cap and add a deadline when `PeTables` gets a shipped caller |
| F5 | Medium (resource) | Ghidriff import | About 16 KB RSS per imported function record (76-113x input). Measured: 3.1 MB / 20k functions = 350 MB; 31.7 MB / 200k = 3.13 GB, 40 s. The only bound is `MAX_RAW_BYTES` = 100 MiB (extrapolated about 10 GB, not measured) | Open: needs a function-count limit or a leaner normalized model; a limits decision for the owner (`docs/specs/enrichment.md`), not changed here |
| S4 | Low | CI supply chain | `ilammy/msvc-dev-cmd@v1` is tag-pinned in read-only corpus/unified workflows | Open: no write permission in those jobs; pin to a SHA when they are next touched |
| S5 | Low | Dependencies | Top-level runtime and dev dependencies are exact pins (dev pins added in this run) and installs use `--only-binary=:all:`, but transitive dependencies are not hash-locked | Open: a hashed lock (`pip-compile --generate-hashes`) would close it |
| S6 | Info | Child processes | Ghidra/Java children inherit the full environment unless `restrict_env` is set (SPEC-07h H7, default off until a native Windows run validates the allowlist) | Open, existing decision |
| S7 | Info | Distribution | Builds are unsigned (SPEC-52); integrity rests on SHA-256 sidecars; SmartScreen and antivirus may warn | Open, owner decision on signing |
| S8 | Info | Version resource | PyInstaller `eval()`s the generated version file | Mitigated by design: every value validated against a strict pattern and `repr()`-quoted; injection attempts (a quote in a tag name, a crafted copyright) are rejected by tests |

Closed as expected behaviour by the sweep: PE reader, resources, version info, manifest and exports (peak 1.75 s and
35 MB on the complexity probes); BinDiff import (progress-handler deadline; 22-28x memory, file cap 512 MiB);
calibration loaders; a non-finite Winbindex number (type-checked only); rz-diff raw-surrogate cases (impossible after
`errors='replace'` decoding); byte-representation API-misuse arguments.

## Source sweep (evidence)

`shell=True`: 0. `eval`/`exec` on data: 0. `pickle`/`marshal`: 0. `yaml.load`: 0. Archive extraction in `src`/`tools`:
0. String-built SQL: one statement, `search/capability.py:32`, whose only inputs are three constant tokenizer names
(`:53-56`); not injectable. The SPEC-41 loopback finding is already fixed in `providers.py:68-79` (IPv4-mapped IPv6
refused).

## Diff self-review

No debug output or dead code left; every new error path raises the module's tagged error; temporary files are written
beside their target and replaced atomically (`windows_icon`, `windows_version_info`, report backup via `O_EXCL`);
subprocesses use argument lists (`git rev-parse` in `windows_version_info`). One behaviour change is deliberate: the
swap-orientation confirmation defaults to **No**.

## Performance

Slowest PatchTrace-owned operation on a large diff: the enrichment cache-hit path at 10,000 pairs. Measured 1.31 s
(best of 3; 1.75 s single run, Python 3.13, 4 vCPU) against the SPEC-07 objective of 500 ms. The profile is flat:
`pipeline._cached` 0.38 s (strict re-validation of a 32 MB cached payload 0.28 s), `ranking.rank` 0.28 s,
`build_views` 0.22 s, garbage-collector catch-up 0.15 s. The spec-required re-validation alone costs about 0.65-0.8 s,
so the objective needs a persisted ranking stage (a storage-contract change) or an owner relaxation of SPEC-07. No
change was made; output-hash baselines exist for a future change.

## Not covered

Live rz-diff, BinDiff and Ghidra executables (fake runners only); Windows-specific parser behaviour beyond CI;
coverage-guided fuzzing; the Qt GUI and network transports; the Winbindex gzip path beyond its caps; manual GUI and
SmartScreen checks.
