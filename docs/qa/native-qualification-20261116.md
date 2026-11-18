# Native and release qualification inventory — 2026-11-16

This is a read-only inventory of the Linux session environment and repository gates. No runtimes or data were
downloaded, no workflows were dispatched, and no target binaries were executed. This record does not qualify a
native backend or a release. Repository baseline: `7401078490eb7a447f5ec7274339cb08b051f395`; the inventory also
observed the session's shared Python test environment. Historical evidence below is attributed to its original
source SHA, not transferred to the current integration head.

## Local observations

| Component | Observation | Dependency before acceptance |
| --- | --- | --- |
| Ghidra | No executable found on PATH or in the session workspace; `GHIDRA_INSTALL_DIR` unset | Verified runtime installation and actual pair inputs |
| Ghidriff | No executable on PATH; shared venv cannot import `ghidriff`, `pyghidra`, or `jpype`; `PATCHTRACE_BACKEND_PYTHON` unset | Pinned Ghidriff and compatible Python/JVM bridge |
| Java | `/usr/bin/java`: OpenJDK 21.0.13, build 21.0.13+9-1-deb13u2-Debian; `JAVA_HOME` unset | Select and record the effective runtime; installed Java alone proves no Ghidra compatibility |
| Rizin | No `rz-diff` or `rizin` executable on PATH or in workspace; `RZ_DIFF` unset | Pinned Rizin 0.9.1 and real pair execution |
| BinDiff | No executable on PATH or in workspace; `PATCHTRACE_BINDIFF` unset | Provision pinned BinDiff 8 and resolve independent asset/signature verification |
| PE compiler | `/usr/bin/gcc` exists, but no supported PE build profile is ready | LLVM/Clang/lld/PDB tools and/or MinGW; MSVC profile requires Windows |
| Windows package | Linux host; no `dist` package in inspected checkout | Exact-head Windows build and acceptance runner; clean Windows GUI profile |

These are observations of configured paths, PATH discovery and the workspace, not a claim that every directory
on the machine was exhaustively searched.

## Commands and results

Commands used the session test venv interpreter and `PYTHONPATH=src` where needed. The paths below are
repository-relative commands that can be repeated in an equivalent environment.

- `command -v ghidra`, `command -v ghidriff`, `command -v bindiff`, `command -v rz-diff`, and `command -v rizin`:
  no executable found.
- `java -version`: OpenJDK 21.0.13 as recorded above.
- Python `importlib.util.find_spec` for `ghidriff`, `pyghidra`, `jpype`: all absent in shared test venv.
- `python tools/check_backend_pin.py --release`: **backend pin ok**. This checks pin metadata, not installed
  runtime bytes, network availability or a successful analysis.
- `python -m tools.unified.corpus check`: **ok: the catalogue is consistent**.
- `python -m tools.unified.corpus toolchain`: all supported profiles **BLOCKED**:
  - `msvc-free`: missing clang, lld-link, llvm-pdbutil, llvm-objdump, llvm-nm, llvm-strip.
  - `mingw-gcc`: missing mingw-gcc, llvm-dwarfdump, llvm-objdump, llvm-nm, llvm-strip.
  - `mingw-clang`: missing clang, mingw-gcc, llvm-dwarfdump, llvm-objdump, llvm-nm, llvm-strip.
  - `msvc`: only builds on Windows; this host is POSIX. `/usr/bin/link` is not Microsoft's linker.

## Native execution gates

### Ghidra / Ghidriff

`tools/backend_pin.json` and `.github/workflows/unified-live-gates.yml` name Ghidra **12.0.4** and Ghidriff
`4f5d895fcbb1eacd65efd81145922c15bb7e741d`. The bundle pin specifies Temurin **21.0.12.1+1** and PyGhidra **3.0.2**.
The observed system Java is a different build; no compatibility inference is made.

Actual acceptance entry points are `.github/workflows/live-backend.yml`,
`.github/workflows/unified-live-gates.yml`, and `tools/unified/live_pairs.py`. The latter needs completed native
runs, matching corpus/labels, and configured runtime paths. Missing runs are blocked, never counted as misses.

### rz-diff

`.github/workflows/live-rizin.yml` pins Rizin **0.9.1** for Linux and Windows.
`tools/live_rzdiff_check.py` takes the executable, older/newer inputs, output path, pin, archive SHA-256 and OS.
Both ordinary multi-function pairs and ownership-refusal regressions remain relevant. Mocked parser tests do
not replace real tool execution, and a prior native pass on another SHA cannot qualify current adapter changes.

### BinDiff / BinExport

`tests/test_live_bindiff.py` uses `PATCHTRACE_BINDIFF`; required-mode acceptance also uses
`PATCHTRACE_REQUIRE_LIVE_BINDIFF=1` and optionally `PATCHTRACE_BINDIFF_EXPECTED_VERSION`.
`.github/workflows/live-bindiff.yml` runs the real tool on a **synthetic BinExport2 pair**. Such a pass proves
that adapter/tool path, not real Ghidra BinExport compatibility or ranking accuracy.

`tools/bindiff_pin.json` names BinDiff 8 and explicitly retains `verified: false` for independently unverified
assets/signature. Windows extraction is advisory/unverified. These are separate trust and platform gates, not
fixed by a successful synthetic parser test. Workspace `.BinExport` fixtures are explicitly synthetic; no real
export pair was found in the inventory.

## Original Windows timeout pair

`docs/qa/ghidriff-timeout-20261106.md` records:

- Older: `86926f78fad0d8c75c7ae01849bf5931f4484596d28d3690766f16c4fb943c19.bin`
- Newer: `3691adcefc6da67eedd02a1b1fc7a21894afd83ecf1b6216d303ed55a5f8d129.bin`

Neither pair bytes nor original log attachments are present in the inspected checkout/workspace. The source
record says original filenames and binary bytes were not supplied. These names must not be treated as
independently verified digests or assigned an inferred product identity.

The source record reports Ghidra **12.1.4**, `VersionTrackingDiff`, and 2,161,955 StructuralGraphHash entries.
Its effective PatchTrace timeout, installed Ghidriff revision and actual Python/JVM remain unknown. Reproducing
and profiling this failure needs the actual pair, retained logs/`backend-execution.json`, effective settings and
Windows runtime. Synthetic tests or a longer timeout do not establish a measured performance repair.

## Unified and release acceptance

`tools/unified/gates_u.py` keeps the evidence requirements separate:

| Gate | Missing dependency/evidence relevant here |
| --- | --- |
| G-U1 / G-U2 | Actual A/A and planted-mutant native outcomes, with complete required corpus/classes |
| G-U3 | Pinned independently verified BinDiff oracle and real correspondence/parity evidence |
| G-U4 | Repeated runs plus Linux/Windows, permutation and swapped-orientation outcomes |
| G-U5 | Linux and Windows benchmark reports plus largest Tier R pair through the whole pipeline |
| G-U6 / G-U7 | Evaluated native rows with legacy flags, supports and truth labels |
| G-U8 | Required full-suite JUnit checks and applicable frozen-smoke attestation |

The unified default-on rule still requires recorded passing G-U1 through G-U6; missing evidence is not a pass.
`docs/specs/windows-acceptance-and-milestone-builds.md` separately requires Windows frozen startup/CLI smoke,
Job Object containment/cancel tests, native analysis, package evidence and clean Windows manual GUI acceptance.
Linux cannot cross-compile the Windows interpreter or certify those behaviors.

## Evidence boundaries and remaining offline work

`docs/qa.md` records historical Windows native workflow success for source
`31f51e76831ff58ff1ba4982a9c34df1b9b39a01`, run
[41934879294](https://github.com/djshellshoxxx/patchtrace/actions/runs/41934879294). The inventory did not query
that remote run; it is repository-recorded old-head evidence, not a current-head pass. The QA record itself says
it does not establish G-U1–G-U8 or clean-machine acceptance.

Safe offline work remains available: parser/property/security regressions, offscreen GUI tests, metadata and
catalogue checks, synthetic benchmarks, and portable archive preflight if an actual package and expected digest
are provided. These establish only their stated synthetic/static scope. Real native execution currently needs
external runtime provisioning; original-pair acceptance additionally needs the pair; Windows qualification
needs an actual Windows runner/profile. No native accuracy percentage or release approval follows from this
inventory.
