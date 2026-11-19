# Isolated Rizin 0.9.1 discovery correction

**Result: the narrow native CLI patch builds successfully and removes the reproduced discovery omission on the frozen authored controls.** This is post-measurement tool research. It does not change the original http-parser pilot, its first MISS, any oracle/scorer/ranking, the production bundled tool, adapter defaults or repository acceptance.

## Preserved evidence

The [verbatim compact archive](l2-rizin-discovery-patch-20261118/evidence.zip)
contains the full research record, exact patch and source, authored controls,
raw results and both reviewers' receipts. [Manifest](l2-rizin-discovery-patch-20261118/manifest.json)
paths refer to members under `l2-rizin-discovery-patch-20261118/` inside that
archive. The adjacent report and [commands](l2-rizin-discovery-patch-20261118/commands.md)
are readable copies with trailing whitespace removed; exact originals remain
archived. [Archive identity](l2-rizin-discovery-patch-20261118/archive.json).

## What was built

The CLI implementation is pinned to Rizin commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`. The original `librz/main/rz-diff.c` has SHA-256 `d44bfe9d05da81ace0ce46eae8e69555c080719cebac3cb72d6686917ab1ea5b` (Git blob `3be455f898e91b906ed2d2307060f41c0833450e`). The patch changes only the whole-functions branch of `rz_diff_graphs_files`: run `rz_core_analysis_all`, refuse interruption, then run the original `rz_core_analysis_everything`. Existing error reporting and cleanup remain in place. The graph/plot-specific branch is unchanged.

The unchanged and patched CLI were compiled with the same thin launcher, flags, compiler and original release static libraries. All 674 copied SDK/header/data files were verified against the sealed preparation manifest. This is a narrow CLI rebuild linked against the pinned release SDK, not a fresh build of every Rizin library.

The existing SDK was built for Alpine/musl. This environment had no musl compiler or Meson/Ninja. An isolated auxiliary musl 1.2.4 toolchain was built from its official release using Debian GCC 14.2.0-19; no system installation occurred. The package-cache preflight failure is retained. Both native rebuilds then succeeded on their first compilation attempt. The build window was **143.72 seconds**, within the 900-second cap; the actual configure/make/install and two CLI compile operations totaled about 14.8 seconds.

## Baseline proof and authored results

All commands used identical `-C -j -t functions` flags and the same frozen authored older/newer bytes, with a 30-second deadline and bounded complete stdout/stderr capture. No fixture executable was run.

The original archive tool's stdout matches the earlier sealed native output byte for byte for all three cases. The unchanged rebuild's stdout **and stderr** match that archive execution exactly. Patched analysis began only after that baseline comparison passed.

| Authored control | Archive and unchanged rebuild: match rows | Patched: match rows | Distinct original/modified functions emitted after patch | Discovery observation |
| --- | ---: | ---: | ---: | --- |
| ELF shared library | 5 | 14 | 14 / 14 | All four authored exported functions now appear on both sides; none appeared in the baseline |
| ELF executable | 5 | 13 | 13 / 13 | All four authored functions now appear; the baseline omitted `sym.diag_dispatch` |
| Existing self-made PE pair | 14 | 22 | 20 / 20 | Entry/export names are retained, including the authored `tiny_v1.dll_*` and `tiny_v2.dll_*` functions |

The PE row count is not a function count: unmatched or differently paired rows make 22 rows from 20 distinct addresses per side. Additional rows establish an observable discovery/output difference, not correct matching, exhaustive function coverage or improved ranking accuracy. The ELF names remain exactly `sym.diag_stable_add`, `sym.diag_stable_xor`, `sym.diag_changed` and `sym.diag_dispatch`; no labels or aliases were patched.

## Existing normalizer and independent review

After raw comparison, all nine completed outputs were passed unchanged through the existing production `rzdiff.interpret` normalizer at PatchTrace `9ac9cbeb8ba1947b5e0889e03dccad769a6d155b`. All were accepted, the current singleton-ownership guard passed, and normalized sets retain the exact raw SHA-256. The reviewed normalizer/runner/registry source is byte-identical at PW integration `0be3b9eb`. No scheduler run or persisted project mutation is claimed for this new experiment.

The integration reviewer independently reviewed the frozen patch routing/order/error cleanup, then reran unchanged and patched binaries on the shared control using normalizer source `939d4a9051ecbd6ebc0cc97e20756c1a881ee070`. Their stdout matches these captures byte for byte: 5 rows/no authored symbols before, 14 rows/all four on each side after. Their raw output, script, receipts and explicit limitations are copied unchanged under `independent-review/`. They did not independently rebuild the binaries.

Normalizer acceptance and the existing singleton guard do not establish general producer ownership correctness. The prior ownership research remains open. These results are not Windows/MSVC L2 acceptance, L3, CVE attribution accuracy or a scored corpus result. No ranking or scoring was performed. Original candidate reruns remain **zero**, and preserved pilot plan/result and diagnosis archive hashes are unchanged.

## Exact identities

| Component | SHA-256 |
| --- | --- |
| Original pinned archive | `9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf` |
| Original archive `rz-diff` | `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e` |
| Unchanged CLI rebuild | `238983217e7b752b2bf7b059303dc0d3a4d36aeb81fb506a4e38b509738414e1` |
| Patched CLI rebuild | `9fda591fe2d64ec5db5579849c52b03eae67930b1f342a0d0161e2eeeecef3c7` |
| Patched CLI source | `ced2de0813a2b284d34f1402ceaef84be5fb7a69465939ca025f371ac0cdcf6f` |
| Minimal patch | `4a536f2e3506f139c0e973d8f9f0774a24225037411556c30cd37ba3866923d1` |
| Thin launcher | `dace7e38fa110c61f80e15680361e1ea8a7dcb82075aca47deac73fbaa63a990` |
| Official musl 1.2.4 source release | `7a35eae33d5372a7c0da1188de798726f68825513b7ae3ebe97aaaa52114f039` |
| GCC driver `/usr/bin/x86_64-linux-gnu-gcc-14` | `a23ecab8ff08f09ad8c80602c2c5df7f49e09c25905cb8975902e101bf72635f` |
| GNU linker `/usr/bin/x86_64-linux-gnu-ld.bfd` | `d2766988b6a1b1d1518cdc09242e726d1f24e151e16410ada3092b11ffd9081b` |

Both rebuilt tools report upstream version `0.9.1` and commit `c3a90e...`; version text alone cannot identify the patch. Every native receipt therefore binds the executable SHA-256. The built binaries remain local at `runtime/unmodified/bin/rz-diff` and `runtime/patched/bin/rz-diff`, each 58,471,984 bytes. Neither replaces the production binary.

Primary tool inputs:

- Rizin archive: https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz
- Pinned CLI source: https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c
- Auxiliary source: https://musl.libc.org/releases/musl-1.2.4.tar.gz

The auxiliary release was captured through ordinary verified HTTPS and hashed before extraction/build. Extraction refused absolute/traversal paths and any non-regular/non-directory member. Upstream Rizin LGPL licensing, musl copyright and the authored PE MIT provenance are retained. No target, PDB or Windows package was downloaded.

## Reproduction and artifact scope

`build_musl.py`, `build_cli.py` and `run_authored_variants.py` retain the exact executed build/control logic. Per-operation receipts contain argv, working directories, limits, output hashes, tool hashes and relevant environment records. The compiler, linker, GCC internal programs/runtime objects, auxiliary installed files and original SDK inputs are separately hashed. `receipts/link-inputs.json` records the only SDK-path relocation: its original Alpine absolute `libutil.a` token becomes the equivalent library in the isolated musl prefix. Mutually dependent static Rizin libraries are linked in a linker group.

The same native command for the shared control is:

```text
TOOL -C -j -t functions controls/build/shared/older/control.so controls/build/shared/newer/control.so
```

The environment is the unchanged `engine_env(os.environ, 'rz-diff')` from the recorded PatchTrace source. The control harness imports only the frozen production runner and normalizer, verifies source/input/tool hashes, and refuses to overwrite prior output. The original sealed diagnosis and pilot metadata remain required preservation inputs; they are never analyzed as candidates by this harness.

The compact Git-oriented evidence archive excludes the large reconstructible SDK, generated toolchain and rebuilt tool binaries. The source/reproducibility archive adds the small pinned auxiliary source tarball; it likewise excludes those large generated/cache trees. Existing authored C source and compiled controls, raw outputs, normalized sets, patch/source, licenses and all operation receipts are included. Rebuild into a fresh research directory, restoring the exact pinned SDK and musl source under the paths named by the receipts; never overwrite this sealed run. Reproducing an identical executable hash also depends on the recorded compiler/runtime objects and build paths.

This patch is ready for a separately pinned tool proposal and broader, independently declared native qualification. Production selection remains unchanged.
