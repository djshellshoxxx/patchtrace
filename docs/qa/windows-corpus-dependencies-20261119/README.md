# Windows corpus dependency repair — 2026-11-19

## Confirmed current failure

PR #318 head `202bda41ea84784f2871289f36b9f5341c366a80` was checked through merge
commit `3626cdcc6d8edf389d8f6826c7ec54856dfeeecc` in
[workflow run 44484082165](https://github.com/djshellshoxxx/patchtrace/actions/runs/44484082165),
Windows advisory job `135423105494`. The earlier calibration home-directory
import failure no longer occurred. The job reached the complete 11-case smoke
plan, then exited 3 with seven blocked entries: six zlib cards lacked
`llvm-dwarfdump`, and the independent rz-diff evaluation lacked its executable
for five available pairs. The result listed no failed case. These are blocked
native attempts, not successful corpus or engine qualification.

The Windows job installed only Python/project dependencies. It provisioned
neither complete LLVM inspection tools nor rizin and inherited the workflow's
Linux rizin asset name. The missing dependency reports are therefore consistent
with the checked workflow, rather than evidence that target analysis succeeded.

## Verified dependency provenance

The exact hosted
[Windows image readme](https://github.com/actions/runner-images/blob/win25-vs2026/20261103.298/images/windows/Windows2025-VS2026-Readme.md)
lists LLVM 20.1.8. Its
[LLVM installation source](https://github.com/actions/runner-images/blob/win25-vs2026/20261103.298/images/windows/scripts/build/Install-LLVM.ps1)
uses the Chocolatey LLVM installer for x64. LLVM's matching
[release build source](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/utils/release/build_llvm_release.bat)
builds the installer with `LLVM_INSTALL_TOOLCHAIN_ONLY=ON`, then separately
creates the full tar archive with that option disabled. This distinction explains
why compiler availability does not establish inspector availability.

The official
[LLVM 20.1.8 release metadata](https://api.github.com/repos/llvm/llvm-project/releases/tags/llvmorg-20.1.8)
identifies full Windows asset `271333338`,
`clang+llvm-20.1.8-x86_64-pc-windows-msvc.tar.xz`, as 939,541,912 bytes with SHA-256
`f229769f11d6a6edc8ada599c0cda964b7dee6ab1a08c6cf9dd7f513e85b107f`.
The archive root follows the release build script. The repair keeps LLVM at the
version already recorded for the failing host, while supplying the full `bin`
directory, companion files and the compiler's adjacent `lib/clang` resources.

The Windows rizin pin is copied from this repository's existing
`live-rizin.yml`: version 0.9.1, asset `rizin-windows-static-v0.9.1.zip`, SHA-256
`2d14e0a6ecba1196dcd742d63de83bbaffed2a7a78ef5a0a9b4e92a0f73d1d28`.
No new engine version or unverified fallback URL is introduced.

## Bounded change

Source commits `e76a1b19` and `47378084` add Windows-specific asset settings and setup steps to
`corpus-tier-r.yml`. The complete LLVM archive is cached by its content digest;
restored and freshly downloaded bytes are hashed before every extraction.
Nonregular/reparse archive objects and existing runtime directories are refused.
The `bin` and `lib/clang` directories are extracted. The expected
`llvm-dwarfdump.exe` must exist and answer its version probe. The selected
archive compiler must resolve its own resource directory and have its builtin
`include/stddef.h` before its directory reaches `PATH`.

Rizin is likewise hashed before extraction. Exactly one expected `rz-diff.exe`
must be present before its path is exported. The actual factory toolchain report
is retained as `windows-toolchain.json` with the shard JSON. The plan, smoke
subset, engine selection, timeouts, advisory status, blocked/failure meanings and
every original case remain unchanged. The setup does not mark any native result
as passed.

The full LLVM download is approximately 940 MB on a cache miss. Caching only the
archive keeps integrity validation mandatory and avoids trusting an extracted
runtime cache. Native runtime compatibility and the ensuing toolchain's outcomes
must be observed on the Windows runner.

## Local verification and remaining gates

Four prerequisite controls failed before the setup change. Independent root
review then caught an omission in the initial bin-only extraction: exporting
that directory also selects its compiler, which needs adjacent builtin headers.
A new control failed on that initial implementation (**1 failed, 4 deselected**).
The follow-up preserves the `lib/clang` subtree and verifies the selected
compiler's resource path; the initial 115-test result did not establish compiler
completeness and is superseded by the final selection.

The final selection passed **116 tests in 4.25 seconds**, covering the new configuration controls,
existing shard semantics, Linux archive-cache integrity controls and workflow
validation. Whole-tree Ruff and whitespace checks passed. These results establish
the inspected configuration and preserve existing host-independent behavior;
they do not execute the Windows setup script, inspector or engine.

```sh
PYTHONPATH=src python -m pytest -q \
  tests/test_tier_r_windows_dependencies.py tests/test_tier_r_shard.py \
  tests/test_corpus_cache_integrity.py tests/test_workflows.py
python -m ruff check src tests tools
git diff --check
```

The [manifest](manifest.json) binds source hashes, the original decoded hosted
job log, primary-source provenance and [local red/green receipts](evidence.zip).

**Native Windows dependency installation, corpus builds, repeatability,
containment and scoring remain BLOCKED/pending exact-source hosted execution.**
This change repairs the observed provisioning gap; it makes no claim that later
compiler, parser, engine or platform failures cannot occur. The separate strict
security scan remains outside this repair. No target binary was executed, remote
branch mutated, PR merged, or release qualified by this worker.
