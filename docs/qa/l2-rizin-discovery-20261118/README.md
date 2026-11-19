# Rizin 0.9.1 function-discovery diagnosis

Date: 2026-11-18. **Post-measurement diagnosis; no accuracy score.** The first http-parser pilot remains an immutable MISS. Candidate reruns: zero. No target execution, new target acquisition, repository edits, remote changes, or producer/scorer/oracle changes occurred in this diagnosis.

## Finding

The pinned native `rz-diff` function path skips the symbol/entry analysis that ordinary Rizin automatic analysis performs first. Independently authored controls reproduce the resulting omission. PatchTrace retains the complete producer output; changing its parser cannot recover missing native function rows.

| Authored control | Production native rows | Existing changed-name ranking | Independent `rizin -N -A ... aflj` inventory |
| --- | ---: | --- | --- |
| ELF shared library | 5, all similarity 1.0 | Empty | 14 functions, including all four authored functions |
| ELF executable, same control source | 5 | `sym.diag_changed` (native similarity 0.75) | 13 functions, including all four authored functions |
| Existing Tier-W PE pair | 14 | Five address-derived names | 20 functions on the older file |

The shared-library producer emits three PLT stubs, `loc.imp.__cxa_finalize`, and `entry0`; it emits none of `diag_stable_add`, `diag_stable_xor`, `diag_changed`, or `diag_dispatch`. The executable producer emits the first three authored bodies but omits `diag_dispatch`. Static `readelf` records show all four exports, and `objdump` records show library calls through PLT versus direct calls to the executable's three bodies. No program was executed to obtain these observations.

Every production operation exited 0, was accepted by the scheduler/adapter, and retained complete stdout/stderr. This is operational acceptance, not function-coverage acceptance. Shared-library stderr contains the entrypoint warning; PE stderr contains an ESIL memory-peek warning. Both are retained. The PE native stdout hash exactly matches the earlier authored smoke output.

## Pinned source explanation

Upstream commit: `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`.

- [`librz/main/rz-diff.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c): core loading performs no `rz_core_analysis_all` call. The functions branch calls only `rz_core_analysis_everything` for each input before matching. Its calls at source lines 2367 and 2374 are unconditional: adding `-B` does not supply the missing seed pass. The output loop supports both ordinary and symbol function types, so it does not explain away these missing symbol bodies.
- [`librz/core/canalysis.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/canalysis.c): `rz_core_analysis_all` at 2275 analyzes entries, valid symbols, and main. `rz_core_analysis_everything` at 4236 performs deeper call/reference analysis without that initial pass. `rz_core_perform_auto_analysis` calls `analysis_all` at 6281, then `analysis_everything` at 6299.
- [`librz/main/rizin.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rizin.c): `-A` selects the deep automatic-analysis wrapper at 1429. The captured help also identifies `-A` as `aaa`.

This establishes the native setup discrepancy and explains the authored reproducer. The original candidate's omitted exported function is consistent with the same mechanism. It was not rerun or instrumented to turn that explanation into a new candidate result.

## Proposed change and remaining limits

The smallest source-backed upstream/native candidate is to call `rz_core_analysis_all` before each functions-path `rz_core_analysis_everything` call, or use an equivalent complete automatic-analysis entry that preserves interruption and error handling. This is a proposal, **not an applied or validated repair**. It requires a newly pinned tool build and fresh authored symbol/entry controls, plus the existing native ownership/boundary tests, before production adoption. A flag-only `-B` change is not supported by the inspected code. The current production status should be understood as accepting the returned match set, without asserting exhaustive discovery.

A separate naming limit remains: the actual executable result uses `sym.diag_changed`; the existing qualification scorer compares names literally and its adapter preserves that prefix. Future source-oracle scoring needs a predeclared, engine-aware naming contract verified independently. The current oracle, aliases, ranking, and first MISS were not modified. A producer discovery repair alone does not establish a scored HIT.

These authored controls do not establish Windows/MSVC L2 acceptance, CVE attribution, desktop acquisition, L3, or corpus accuracy. No aggregate percentage or confidence bound was computed. The original pilot is no longer held out for any future work informed by this diagnosis.

## Commands and identities

PatchTrace checkout: `/workspace/scratch/e83fbf4505c3/repair-receipt-identity`, commit `9ac9cbeb8ba1947b5e0889e03dccad769a6d155b`, tree `eba3ca64508f9989c63dcbe0f42a90cd668ffebd`. The harness checks the same relevant source hashes as the first pilot before and after the controls.

Exact executed harness invocation, from this directory:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/repair-receipt-identity/src:/workspace/scratch/e83fbf4505c3/repair-receipt-identity QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python run_controls_v2.py
```

`control-plan.json` was frozen before execution, SHA256 `51b132d76f0f82edb45c2ba4f82f0f637c63f76f0b43941a13d41739ddba2169`. `run_controls.py` was never executed: before running, source inspection corrected its success predicate from the nonexistent `reason == 'completed'` to `reason is None` in `run_controls_v2.py`. The original script and `harness-correction.json` remain. No input or compiler/native setting changed.

Compilation uses `/usr/bin/cc` (Debian GCC 14.2.0-19), common flags `-O2 -DNDEBUG -Wl,--build-id=none`, plus `-fPIC -shared -Wl,-soname,libdiag.so` for libraries or `-Wl,--export-dynamic` for executables. Each side uses identical flags. Individual receipts contain exact command arrays and compiler hashes.

The production command is `rz-diff -C -j -t functions OLDER_PRIVATE_COPY NEWER_PRIVATE_COPY`, using `run_engines`, the real adapter, no cache, one worker, a 30-second per-engine deadline, and an 8 MiB stdout cap. The observer returns the unmodified real `jobs.run_process` result. Older-file inventories use `rizin -N -A -q -c aflj FILE`; static call inspection uses `objdump -d --disassemble=diag_dispatch FILE`.

| Binary | SHA256 |
| --- | --- |
| Shared older | `e229bdc6e83e66f09ca0c415ac43d9b97ef19d223c0daa8c2b7528d64fd64aff` |
| Shared newer | `d3b73651874bfaccc4f3455e74f31e085b94bf45a0a340a741d9dbb3f3a8c8c2` |
| Executable older | `a81ae9251aa512e0ea6c6c2fd1cabbfafaecad7cd90ff0e83b5f6cd1faa5c24e` |
| Executable newer | `b5aa048f04bf788eecf0d912c46b1658c56acfa2918d04aefe0f5bf81dd7ca9f` |

Existing PE bytes and their self-made MIT provenance are copied under `controls/existing-authored-pe`; their upstream repository paths remain in operation receipts. All newly compiled targets were made read-only before analysis.

Tool archive URL: `https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz`, SHA256 `9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf`. Verified executable hashes: `rz-diff` = `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e`; `rizin` = `ab5614cf137608cffc5a3f4f471a91c995cfa7c0c35465bfb73876e5b95561ba`. Tool preparation and version receipts remain in the sealed preparation folder; this diagnosis does not duplicate the large reconstructible tool cache.

`control-results.json` retains full native rows and production events; `control-comparison.json` provides the compact inventory comparison. `raw/` and `receipts/` retain every operation. Source files and their fetch receipts, plus upstream licensing, are under `tools-source/` and `receipts/`. Reproduce in a fresh output directory: the harness deliberately refuses to overwrite an earlier run's files.
