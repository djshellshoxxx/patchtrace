# Pinned native provisioning checkpoint — no native execution

This finite checkpoint starts from PatchTrace `f33e2a0a`. Source Rizin is exactly
`c3a90e9226d977f58f4e9c75f78fa6b07afe13c7` (v0.9.1); `similarity.c` matches the
approved SHA-256 in `receipt.json`. Upstream tracked source has no diff.
Meson 1.12.1 and Ninja 1.13.2 were installed only into `/tmp/pt-rizin-buildenv`.
The project's Meson license is LGPL-3.0-only; default GPL components are enabled.
No Rizin binaries, libraries or source archive are redistributed by this receipt.

Actual checks and failures:

- Exact pinned source and its upstream-pinned subprojects were fetched. The
  receipt records subproject Git heads and byte/checksum-bound raw logs.
- The existing authored native oracle compiled into an object against actual
  Rizin/generated headers with C99, Wall/Wextra/Werror: exit 0. This is header/API
  compilation evidence, **not an executed native ownership oracle**.
- Default native linking failed: the util link command omitted PCRE2 libraries,
  yielding unresolved PCRE2 symbols. The first failure is preserved unchanged.
  Supported `use_sys_pcre2=enabled` selected installed PCRE2 10.42 (upstream
  requires >=10.42); the subsequent util library linked successfully. No upstream
  source was edited to repair the dependency configuration.
- Release optimization was replaced by upstream `buildtype=plain`; this is an
  ownership/API experiment, not a performance measurement. Unrelated upstream
  tests, rz-test and command regeneration are disabled.
- To protect the coordinator's full suite, compilation was lowered to nice +15,
  one job, then narrowed to the exact `librz_arch` dependency closure. The final
  checkpoint deliberately stopped with SIGINT/exit 130. There were 525 remaining
  API target steps. This is an unfinished local build, not an unavoidable external
  blocker or a failed native ownership result.

The complete source/build cache remains at `/tmp/pt-rizin-native-source`. Exact
resume command (not a promise of background execution):

```sh
nice -n 15 /tmp/pt-rizin-buildenv/bin/ninja -C /tmp/pt-rizin-native-source/build -j 1 librz/arch/librz_arch.so.0.9.1
```

The oracle references analysis/list APIs, so it can link with `rz_arch`, `rz_io`
and `rz_util`; the historical example's `rz_core` dependency is unnecessary.
The separately inspected `rz-diff`/`rizin` CLI dependency closure is larger and
has not completed. Stock-red/corrected-green 32-row API runs, distinct-byte/IO
controls, CLI JSON/recovered inventories, native Windows, quarantine removal and
Tier R requalification all remain open. No target inputs or native oracle were
executed. No workflow, product parser, cache policy or quarantine changed.

Every `.log.gz` decompresses to the complete corresponding raw log at this finite
checkpoint; raw and compressed SHA-256 values are in `receipt.json`. Intentional
resource/configuration interruptions remain distinct from the actual linker
failure. The final dry-run target list is retained separately.
