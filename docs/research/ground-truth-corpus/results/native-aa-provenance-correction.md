# A/A and compiler-noise provenance correction

Correction date: 2026-10-31 UTC. Finding: CodeRabbit comment `4429457726`, independently reproduced locally. This report and its JSON are new evidence; the original native/control reports and label documents were not edited by this worker. No fixture DLL was executed and no matching engine was rerun.

The executing worker observed HEAD `0d14548eef118ac32789da1e410fc1aa6b9f27f2` at preflight. Its execution transcript and reflog place the direct `F.run_aa` / `F.run_noise` builds at that checkpoint, and their factory/build dependencies were unchanged. Unpublished wrapper/test/documentation edits existed; the direct drivers did not invoke the wrapper. No per-run code snapshot was embedded at launch, so this is an observed checkpoint with a dirty-worktree caveat, not a certified pristine-tree provenance claim.

## Confirmed defect and actual recovery

The original `Session.side` cache used only the debug-image hash, although `SideData` retains a `BuildResult` and source context. An A/A build correctly invoked `session.build` separately for variants `aa-a` and `aa-b`; because the artifacts were identical, the second `session.side` returned the first build's cached object. The label therefore reported both endpoint variants as `aa-a`. Artifact comparison itself used the actual two `BuildResult` objects and remained valid. This is a provenance-field defect rather than evidence that the second compilation was absent or the machine-code truth changed.

The independently checked affected published labels are the generic Clang A/A record and the compiler-qualified MinGW GCC native A/A record. The same original session also contaminated the Clang O2 endpoint metadata of three compiler-noise labels with `aa-a` instead of `noise-msvc-free-o2`. Their requested compiler profiles and optimization levels were correct. The GCC/MinGW Clang noise record was already correct.

Recovery used the existing fixed `Session.side`, whose cache key includes the complete build specification and recipe/source context, and actual `F.run_aa` / `F.run_noise` calls in new external stores. Both A/A rebuilds returned two distinct actual build specifications and two source-analysis cache entries, with `aa-a` and `aa-b` respectively. All four compiler-noise comparisons were actually rebuilt. No endpoint variant was repaired by simply assigning an expected string to an old label.

For the proposed matching replacements, full engine/debug/PDB hashes and all function records—including identities, RVAs, sizes, body relationships, labels and checks—match the original records. Only the affected build-variant metadata and the resulting canonical label digest differ. Existing source, artifact and function truths remain unchanged.

## Original records and immutable evidence binding

- Original native receipt: `docs/research/ground-truth-corpus/results/native-aa-control.json`.
- Original native receipt file SHA-256: `6746eba2955ee0ef2afcfe21ac98aece63bb3e05521ebd7f33b8ed7ea3927895`.
- Original external native label digest: `9d9a2c79fd0101a0e4d58db0949795d7c6c576236528610c48017b54bf8e379e`.
- Original published compiler-qualified native label digest: `bce0f84260d125168b2142888547438b810abb4189d8688e1778699995025e92`.
- Original generic Clang A/A digest: `1792c140953da1e24c01e697731f3f9d3e5e0065e8358418d3f1fe1aed19e26f`.

The native A/A published record includes historical namespace metadata (`case.original_pair_id`, `case.original_labels_sha256` and its namespace note). The proposed compiler-qualified replacement preserves that metadata while taking actual endpoint build records from the fresh native-profile rebuild. The fresh generic GCC label is also retained separately in the new store; it is not substituted into the canonical compiler-qualified namespace by an unrecorded rename.

## Exact proposed label staging paths

The integration owner owns publication. These are actual fresh labels, or the explicitly namespace-preserving compiler-qualified proposal derived from the actual fresh GCC label:

| Record | Corrected canonical digest | Actual staging path |
|---|---|---|
| Native MinGW GCC A/A | `a6a8ff0fafca6df5afcdee88e909deaaf24a12d808d04a1513ad8e6f2777739c` | `/workspace/scratch/a55b59b3e326/r1-native-aa-provenance-store-2/labels/aa-defined-v1-mingw-gcc-O2-rebuild.json` |
| Clang A/A | `49e2c720f47aa51e4f1d75eacc7024ecdb88cf5dc7bca15e0987712f216f83a7` | `/workspace/scratch/a55b59b3e326/r1-controls-provenance-versioned-store/clang-aa/labels/aa-defined-v1-O2-rebuild.json` |
| noise-defined-v1-msvc-free-O0-msvc-free-O2 | `e14ec54f3ad6d3e98ea4eca15b57027b2d3fca5386d11be3bdf192e4010828ab` | `/workspace/scratch/a55b59b3e326/r1-controls-provenance-versioned-store/noise/labels/noise-defined-v1-msvc-free-O0-msvc-free-O2.json` |
| noise-defined-v1-msvc-free-O2-msvc-free-Os | `493e916f8e181d49e770ad9f7e0d1b07b3a948db1d795ff6401ed957686103bd` | `/workspace/scratch/a55b59b3e326/r1-controls-provenance-versioned-store/noise/labels/noise-defined-v1-msvc-free-O2-msvc-free-Os.json` |
| noise-defined-v1-msvc-free-O2-mingw-gcc-O2 | `3e6b8993516328e25e504ab18337bb5d45ec19124054b2d8e2ef81c49bf73d6b` | `/workspace/scratch/a55b59b3e326/r1-controls-provenance-versioned-store/noise/labels/noise-defined-v1-msvc-free-O2-mingw-gcc-O2.json` |
| noise-defined-v1-mingw-gcc-O2-mingw-clang-O2 | `81fe7c29372134b2ba1efa5f958ee42629e22c71b722089e7dfc02085afaac8c` | `/workspace/scratch/a55b59b3e326/r1-controls-provenance-versioned-store/noise/labels/noise-defined-v1-mingw-gcc-O2-mingw-clang-O2.json` |

The precise metadata changes are:

- Both A/A records: `newer.build.variant` changes from `aa-a` to actual `aa-b`.
- Clang O0 → O2 noise: `newer.build.variant` changes from `aa-a` to actual `noise-msvc-free-o2`.
- Clang O2 → Os noise: `older.build.variant` changes from `aa-a` to actual `noise-msvc-free-o2`.
- Clang O2 → MinGW GCC O2 noise: `older.build.variant` changes from `aa-a` to actual `noise-msvc-free-o2`.
- MinGW GCC O2 → MinGW Clang O2 noise: no change; the entire fresh label and digest equal the original.

Each old and new digest, original file SHA-256, exact field diff and corresponding requested comparison are recorded in `native-aa-provenance-correction.json`. There are five affected records and one verified unaffected noise record. Recovered actual compiler/source/build receipts are copied under the new `native-aa-recovered-build-receipts/` directory. Per-build `BuildSpec` bindings in the correction JSON retain the actually observed variants; identical compiler recipes can share one immutable receipt because the variant is bookkeeping metadata rather than a compiler flag.

## Reproduction initially failed when executable invocation spelling changed

The first fresh Clang A/A attempt used current default tool discovery. It correctly produced `aa-a` / `aa-b`, and the two new builds were mutually reproducible, but its artifacts did **not** match the historical Clang images. This mismatch was preserved and stopped automatic replacement. Source-file hash, source digest, normalized recipe digest and tool version banners matched; `.text` bytes and function facts also matched. The full stripped images differed in headers and `.rdata` (the factory comparison counted 36 differing bytes), and debug/PDB hashes differed.

Direct `llvm-pdbutil-18 dump --symbols` inspection establishes an invocation-path difference in `S_ENVBLOCK`: the original PDB records `/usr/bin/lld-link-18`, while the new default-discovery PDB records `/usr/bin/lld-link`. The independent truth-audit worker reproduced the original artifact triples using explicit versioned tool paths. This worker then independently reproduced them for both A/A and noise labels using the exact original tool paths recorded in `controls-and-structure.json`.

This is a real reproducibility limitation: the current normalized recipe drops executable argv[0], although the executable invocation path can enter a PDB and therefore the CodeView GUID and PE metadata. An equal source digest, recipe digest and version banner alone do not establish complete input identity. The nonmatching attempt is not relabelled as original-byte reproduction. Its actual paths, artifact hashes, `.text` hashes, differing sections and direct PDB evidence are preserved in the correction JSON. No tool binary, compiler option or source was changed to force a match; the matching retry selected the **recorded original invocation paths** explicitly.

The Clang overrides used the existing `probe` mechanism, for example:

```python
env = dict(os.environ)
for tool in ('clang', 'lld-link', 'llvm-pdbutil', 'llvm-objdump', 'llvm-nm', 'llvm-strip'):
    env['PATCHTRACE_KA_' + tool.upper().replace('-', '_')] = f'/usr/bin/{tool}-18'
tools = probe(env)
```

For the mixed compiler comparisons, all available original paths—including the MinGW GCC driver and `llvm-dwarfdump-18`—were copied from the original control receipt into corresponding override variables. The full original invocation pins and actual matching-rebuild `Toolchain.describe()` are in JSON. Only these matching runs supply proposed replacements. The source and stock compiler/linker flags remain unchanged.

## Existing native engine results remain artifact-bound

The MinGW native A/A corrected label has exactly the same engine/debug artifact hashes as both original endpoints. Both original successful raw Ghidriff files were rehashed, rebound through production `verify_diff_identity` / `normalize_ghidriff` against the proposed corrected label, projected to image scope, and converted with `ghidriff_observations`. Their actual observation sequences remain exactly equal to the original observations. No native engine rerun was needed or claimed.

| Existing successful raw result | Raw SHA-256 | Binding/observations under corrected proposal |
|---|---|---|
| `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-1/raw/json/older.dll-newer.dll.ghidriff.json` | `81e7647bb284d0a7ab72bedf36725cadf0ac84036b29e0d0a0ee5df29a0dea6a` | Accepted; 53 image observations unchanged |
| `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-2/raw/json/older.dll-newer.dll.ghidriff.json` | `12e6642d25d2e15d7929f56c20659a7e1175fd1b6b5062d09774fc881839c297` | Accepted; 53 image observations unchanged |

The successful native results remain scoped to identical artifact bytes, distinct input basenames and 21 visible PE exports. Unknown change flags remain unknown. This correction does not improve an engine metric, alter ambiguity admission, erase earlier failures or promote a new accepted truth population.

## Publication handoff

The integration owner has preserved the original active A/A and three affected noise labels under `historical-labels/` and published the five matching staged replacements. [label-provenance-corrections.json](label-provenance-corrections.json) maps exact historical and current file hashes, canonical digests and the two-field differences. `original_canonical_path` in this worker's evidence describes the location at the time of recovery; the archived path now holds those original bytes. [final-label-integrity.json](final-label-integrity.json) and [final-partition-audit.json](final-partition-audit.json) validate the corrected 23-label inventory. The fourth noise label is unchanged.

The original `native-aa-control.json`, `native-aa-control.md` and `controls-and-structure.json` remain unchanged. The reproduction snippets in `controls-and-structure.md` add the missing `from tools.calibration.mutations import opt_transforms as O` import without altering experimental facts. The correction JSON distinguishes the originally committed Markdown hash from the corrected reproduction-document hash; the original experiment JSON hash remains independently bound.

The integration owner decides whether to close the separate executable-invocation identity gap in the canonical build-receipt contract or retain it as an explicit limitation. This worker made no code or schema change for that issue, and made no change to original or canonical label files. Every proposed correction is anchored to a fresh real build and exact original artifact hashes.
