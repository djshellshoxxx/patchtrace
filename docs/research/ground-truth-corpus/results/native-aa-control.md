# Genuine native Ghidriff A/A control, including failed conditions

Date: 2026-10-30 UTC. Outcome: **two direct native Ghidriff force runs completed on byte-identical MinGW GCC images when staged with distinct input basenames**. Both produced the same 53 unique image-scope correspondence observations, including all 21 construction-known project RVA pairs. Full raw JSON bytes differed. The original same-basename condition failed before producing a diff and is preserved as a distinct condition.

This experiment invoked the actual installed Ghidriff/Ghidra process. It did not use PatchTrace's intentional identical-image backend shortcut. It did not execute a fixture DLL, use predicted matches as ground truth, supply private DWARF/PDBs to Ghidriff, relax the default function-length filter, or alter fixture bytes. The MinGW images retain **21 named PE exports**, which remain visible despite `--no-symbols`; this is explicitly a names-visible identity control and not evidence of general matching accuracy with names hidden.

## Built control and exact identity

The reviewed v1 source was built using `F.run_aa` with a derived `BaseSource(profile='mingw-gcc')`, O2, and `layout=True`, in the separate external store `/workspace/scratch/a55b59b3e326/r1-native-aa-store`. The stock GCC profile and existing factory APIs were retained. Two independent builds produced byte-identical engine and debug images; GCC uses embedded DWARF rather than a PDB. Single-translation-unit link-order diversity was not applicable.

- Source SHA-256: `5f0468899fbc95fa4026c3c74b0731a5ab412fe017bbddbed00ad7b0d97acb5f`.
- Engine SHA-256, both sides: `c03b76a0e6db62ac35c5f4fa727f38cafdcfb5e7b8544c327b4c9587f8707b58`.
- Debug SHA-256, both sides: `82507c9e80aa0493860ca0b56a7400ec67dbda7ae3a32185aa19aaefa5b1b701`.
- Label path: `/workspace/scratch/a55b59b3e326/r1-native-aa-store/labels/aa-defined-v1-O2-rebuild.json`.
- Canonical label digest: `9d9a2c79fd0101a0e4d58db0949795d7c6c576236528610c48017b54bf8e379e`.
- Label file SHA-256: `f9dd2823212a8a5330bb1d3c96e0511d6a9c0a4726487c98c8ee2debe4d73934`.

The label document contains 21 same/unchanged identities with identical bodies and zero factory disagreements. Those are construction/debug/binary facts, not native-engine predictions or a native accuracy percentage. The factory pair ID is the same generic A/A ID used in a different profile's separate store; the full store path, profile, image hashes and label digest distinguish these records. Do not merge them by pair ID alone.

For publication and the combined partition audit, the integrator preserved a
compiler-qualified copy as
[`aa-defined-v1-mingw-gcc-O2-rebuild.json`](labels/aa-defined-v1-mingw-gcc-O2-rebuild.json).
Its `case` retains the original pair ID and digest above. Source, artifact and
function facts are unchanged; this explicit namespace change avoids colliding
with the separately published freestanding A/A document. The original native
receipts remain bound to the original digest.

## Native tool configuration and containment

The actual executable was `/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -I -X utf8 -m ghidriff`, Ghidriff distribution **1.0.0**, Ghidra **12.0.4 PUBLIC**, and Java **21** from `/usr/lib/jvm/java-21-openjdk-amd64`. Exact JVM version output and the Ghidriff engine-module SHA-256 are retained in JSON. Environment construction used existing `build_child_env(..., for_tool='ghidra', symbol_downloads=False)` with writable per-run settings directories, and the explicit `JAVA_HOME`, `JAVA_HOME_OVERRIDE` and `GHIDRA_INSTALL_DIR` values requested by the integration owner.

Each launch used existing `jobs.run_process` with a 300-second timeout, bounded captured output and descendant termination. All image imports were static analysis. Each successful run used fresh settings, Ghidra project, GZF and raw-output directories. The successful command shape was:

```text
/workspace/scratch/a55b59b3e326/patchtrace-venv/bin/python -I -X utf8 -m ghidriff
  /workspace/scratch/a55b59b3e326/r1-native-aa-store/inputs/older.dll
  /workspace/scratch/a55b59b3e326/r1-native-aa-store/inputs/newer.dll
  --force-diff --no-symbols --no-threaded
  --output-path <fresh-run>/raw
  --project-location <fresh-run>/projects
  --gzfs-path <fresh-run>/gzfs
  --log-path <fresh-run>/ghidriff.log
```

The exact argv for every launch is in JSON. Engine logs confirm the default **VersionTrackingDiff**, `min_func_len=10`, BSim enabled, no BSim-full, no calling-count option, no custom program options and no custom JVM arguments. No alternative diff engine or filter was selected. `--force-diff` forced the real CLI path rather than changing artifact content.

## Preserved failures and controlled recovery

| Condition | Observed outcome | Treatment |
|---|---|---|
| Experiment wrapper initially omitted required `for_tool` argument | Python wrapper error before any engine launch | Corrected API invocation; recorded as preflight finding, not an engine failure or pass |
| Optional `/usr/bin/time -v` wrapper | `/usr/bin/time` absent; launch failed before Ghidriff started | Removed optional measurement wrapper; no peak-RSS result claimed |
| First genuine CLI launch, inherited settings location | Exit 1 after approximately 0.76 s; Ghidra could not create `/root/.config/ghidra/ghidra_12.0.4_PUBLIC`; zero raw diffs | Retained log; next attempt used existing supported writable settings-dir environment |
| Writable settings, original `older/defined.dll` and `newer/defined.dll` basenames | Ghidra analysis ran, then exit1 after approximately 16.25 s; `saveAsPackedFile` raised `IllegalStateException: Attempted to end Transaction more that once: Batch Processing`; zero raw diffs | Retained logs, project and GZF directory. No observer or score fabricated |
| Fresh settings and distinct `older.dll` / `newer.dll` basenames, identical hashes | Exit 0 and one raw PDiff JSON | Accepted for binding/observation checks, then repeated in another fresh directory |

For the same-basename condition, logs explicitly report a duplicate-file SHA1, import `defined.dll-68aa04`, and load the same ProgramDB twice. Changing the basenames removed the failure in the two observed retries. This is an experimentally relevant input-name condition, not a claimed complete upstream root-cause proof or a backend patch. The bytes, tool versions and diff options were not changed. The initial failures remain separate entries in the receipt.

## Native observations and repeatability

Both successful raw files were rehashed and passed the production `verify_diff_identity`/`normalize_ghidriff` binding path against the exact A/A label document. Only after binding, the new `ghidriff_image_projection` explicitly separated 22 EXTERNAL address edges from 53 image address edges. The raw files remain immutable and available outside git. `ghidriff_observations` then produced actual image correspondences without reading truth labels or granting implicit unchanged classification credit.

| Observation | Successful run 1 | Successful run 2 |
|---|---:|---:|
| Process wall time | 22.677194s | 22.778953s |
| Exit code | 0 | 0 |
| Unique image address correspondences | 53 | 53 |
| Construction-known project RVA pairs observed | 21 of 21 | 21 of 21 |
| Other image pairs, outside project truth scope | 32 | 32 |
| Validated EXTERNAL edges excluded from image scope | 22 | 22 |
| Explicit modified/added/deleted function records | 0 / 0 / 0 | 0 / 0 / 0 |
| Change flags on observed image correspondences | 53 unknown (`None`) | 53 unknown (`None`) |
| Peak RSS | not measured | not measured |

All project RVA pairs were present in the engine's actual address table. The 32 additional image pairs are unscored background/runtime scope. The unchanged label set is independent construction evidence; unknown native change flags are not silently converted to negative/materially-unchanged predictions. Ghidriff's own aggregate reports 188 total/matched/no-change entries and 100% in its internal statistics, but those counts are not the 21-function independent project denominator and are not reported as benchmark accuracy here.

| Hash | Successful run 1 | Successful run 2 |
|---|---|---|
| Full raw JSON SHA-256 | `81e7647bb284d0a7ab72bedf36725cadf0ac84036b29e0d0a0ee5df29a0dea6a` | `12e6642d25d2e15d7929f56c20659a7e1175fd1b6b5062d09774fc881839c297` |
| Canonical image observations SHA-256 | `134f6977b4fb960664ad6cbcba4838c2af40ea8c11a4591f2b11b1f347e76d76` | `134f6977b4fb960664ad6cbcba4838c2af40ea8c11a4591f2b11b1f347e76d76` |

The canonical image observation sequences were exactly equal across the two fresh analysis runs. The complete raw JSON files were not byte-identical, so the result establishes scoped observation repeatability on this machine/tool configuration rather than deterministic entire Ghidriff output. No cross-platform or across-version determinism is claimed. The measured wall times include process startup, JVM/Ghidra setup, import, analysis and diff/output overhead; they are not per-function throughput measurements.

## Evidence locations and acceptance boundary

- Successful run 1: raw `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-1/raw/json/older.dll-newer.dll.ghidriff.json`; captured process log `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-1/process.log`; complete argv/settings metadata in the companion JSON.
- Successful run 2: raw `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-2/raw/json/older.dll-newer.dll.ghidriff.json`; captured process log `/workspace/scratch/a55b59b3e326/r1-native-aa-store/native-distinct-name-2/process.log`; complete argv/settings metadata in the companion JSON.

Failure logs remain under `native-1` and `native-settings-1` in the same external store. Successful runs are `native-distinct-name-1` and `native-distinct-name-2`. The companion report and JSON contain only metadata and observations; compiled DLLs, debug images, GZF/project databases and raw tool outputs stay outside git.

This completes a genuine repeated native A/A control in a visible-export condition and preserves the failed same-basename path. It does not establish native success for the stock symbols-hidden/no-export Clang profile, patched-versus-unpatched classification accuracy, realistic security-patch recall, or held-out results. No product backend code, ground-truth labels, fixture source, matching thresholds or engine defaults were changed.
