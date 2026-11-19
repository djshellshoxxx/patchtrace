# Native primary-environment qualification harness — 2026-11-19

## Qualification gap and change

The default-isolation port #311 requires actual-candidate Linux and Windows
primary-engine acceptance, raw-cache reuse and authored secret/JVM-option
sentinels. The existing workflows exercised real engines and cache behavior, but
did not record those sentinels inside a real primary process. Their success alone
could not satisfy the amended H7 gate.

Source commit `f6c0146f` adds `tools/live_primary_environment_check.py`, a separate
qualification step in the Windows native `raw-cache-hit` job and the Linux
live-unified job. Windows retains its existing Ghidra 12.0.4 / Temurin 25
qualification; Linux uses the existing pinned runtime and Windows-built authored
fixture DLLs. Existing native pair, seeded-symbol-store, cache and extraction
steps and assertions remain unchanged. No target DLL is executed.

The qualifier uses the actual default `BackendConfig` and production backend,
process supervisor, native Ghidriff/Ghidra and cache. It temporarily seeds five
authored parent variables: `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` and `JDK_JAVA_OPTIONS`. All existing parent
values and the observation seam are restored after the check, including failure.
The variables contain no real credentials.

Every backend launch's supplied environment is checked. For the actual primary
invocation, the same isolated Python flags launch a short observation entry that
records only sentinel-name absence booleans, process ID and a unique attempt ID.
It then dispatches the real `ghidriff` module through `runpy`, preserving all
engine arguments. The child environment object passes unchanged to the real
process runner. No environment variables, startup hooks, Python paths or fake
engine are inserted into the scrubbed child.

The receipt is read with an 8 KiB cap and must have the exact schema, current
attempt and true Boolean absence checks. A missing, stale, oversized or malformed
receipt cannot qualify even when a delegate reports process exit zero. The first
comparison must be a fresh native run and the second must come from cache, with
exactly one actual primary invocation across both. Raw bytes and normalized match
content must have identical SHA-256 values; generated project/run/function
identifiers are excluded from the match-content comparison. Dependency and JVM
version probes must also have been observed.

The published JSON binds the checked source SHA, implementation file digests,
fixture digests, runtime versions, sanitized observations and cache outcomes. It
never dumps environment values or native log text. A malformed source identifier
is omitted, and arbitrary native exception text is replaced by its exception
class. Missing prerequisites produce `blocked` and exit 2. A failed observation
produces `failed` and exit 1. Only completed real qualification produces `passed`
and exit 0. A prewritten incomplete receipt remains blocked if a job is interrupted.

## Local verification

The new workflow-gate control failed before wiring: **1 failed, 19 deselected in
1.37 seconds**. After implementation and the additional source-value sanitization
control, the final focused selection passed **66 tests in 1.83 seconds** with no
skips. These are **21 harness controls and 45 workflow checks**, not native
acceptance. The prior intermediate 65-test run is superseded, not additive.

The controls check restoration, pre-spawn leakage refusal, unchanged environment
and engine arguments, child receipt authenticity/shape/bounds, a real isolated
Python entry's refusal of an authored retained token before any engine import,
cache-gate failures, missing-prerequisite reporting and metadata sanitization.
Stubbed delegate controls are explicitly labelled as harness tests. No local test
reports a stub as a qualified native engine. Whole-tree Ruff and whitespace
checks passed.

```sh
PYTHONPATH=src python -m pytest -q \
  tests/test_live_primary_environment_check.py tests/test_workflows.py
python -m ruff check src tests tools
git diff --check
```

The [manifest](manifest.json) binds the exact implementation and the
[raw red/green receipts](evidence.zip), including commands and source hashes.

## Required hosted evidence

**Native acceptance is BLOCKED locally and not claimed by this report.** The
integrator must inspect both actual-candidate jobs and their sanitized artifacts:

- `live-backend.yml`: `native (raw-cache-hit)` must pass its original native
  cache step and the added H7 step; artifact
  `native-static-acceptance-raw-cache-hit` includes
  `live-primary-environment-windows.json`.
- `live-unified.yml`: the Linux job must pass its existing extraction checks and
  the added H7 step; artifact `live-unified-linux` includes
  `live-primary-environment-linux.json`.

Both H7 receipts must say `passed` and identify the source being promoted. A
blocked, skipped, missing, stale or failing receipt does not satisfy the gate.
Existing full suites, native Windows acceptance, package and security gates are
still required. No main merge or release is authorized by local harness tests.

## Separate profile review interruption

Independent static review of profile repair `5997321a` found no scoped blocker.
Eight additional authored New/Duplicate controls were prepared alongside the
author's nine controls, but the shared execution host stalled before producing
a final result. The reviewer stopped only its own pytest process with exit 130.
That attempted 17-case run is **BLOCKED/interrupted**, not passed; its draft test
source remains in the shared scratch workspace for later use. It is not included
in the 66-test result above.
