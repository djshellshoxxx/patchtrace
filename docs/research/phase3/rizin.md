# Rizin rz-diff

Research date: 2026-10-12.
Verification labels:
- **[src]**: I read the source at the pinned tag.
- **[run]**: I ran the release binary.
- **[inf]**: inference that I did not verify.

Sources pinned:
- Repo: https://github.com/rizinorg/rizin. Latest release **v0.9.1** (2026-06-29), tag commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`.
- Previous releases: v0.9.0 (2026-06-21) and v0.8.2 (2026-02-01).
- Binary I ran: `rizin-v0.9.1-static-x86_64.tar.xz` on Linux. `rz-diff -v` prints `rz-diff 0.9.1 @ linux-x86-64` and `commit: c3a90e92…`.

## Licence and availability
- **Licence:** `librz/main/rz-diff.c` and `binrz/rz-diff/rz-diff.c` are `SPDX-License-Identifier: LGPL-3.0-only` [src].
  - The repo also carries `COPYING` (GPL-3) and `COPYING.LESSER`, plus a `LICENSES/` dir with many SPDX texts (REUSE layout). Some bundled parts carry other licences.
  - Running the CLI as a separate process creates no linking obligations. Redistributing the binaries requires shipping the licences and source offer [inf].
- **v0.9.1 release assets** [src: release page]:
  - Windows: `rizin-windows-static-v0.9.1.zip`, `rizin-windows-shared64-v0.9.1.zip`, `rizin_installer-v0.9.1-x86_64.exe` (and x86).
  - Other platforms: `rizin-v0.9.1-static-x86_64.tar.xz` (Linux), a macOS `.pkg`, and Android tarballs.
  - **Windows availability:** official. I did not run the Windows build.

## CLI (`rz-diff -h`, v0.9.1) [run]
```
rz-diff [options] <file0> <file1>
 -a arch  -b bits  -e k=v  -A (compare virtual and physical addrs)  -B (run 'aaa' when loading)
 -C (no colors)  -j (JSON)  -q (quiet)  -V (verbose to stderr)  -T (timestamps)  -H (hex visual)  -S WxH
 -d myers|leven|lcs-roll|ssdeep   (edit distance between whole files)   -i (args instead of files, -d only)
 -0 <cmd|fcn>  -1 <cmd|fcn>
 -t bytes|lines|functions|classes|command|entries|fields|graphs|imports|libraries|sections|strings|symbols
```

Modes relevant to function-level diffing:
- **`-t functions`** compares all functions found in both files. An optional `-0 <fcn name|offset>` restricts it to a single function.
- **`-t graphs`** diffs two functions and outputs graphviz/dot. It requires `-0 <fcn>`, and `-1` is optional.
- **`-t symbols|imports|sections|strings`** are metadata diffs.
- Note: per the source (L2361-2380), `-t functions` **always** runs `rz_core_analysis_everything` (full auto-analysis, `aaa`-like) on both files. `-B` only matters for `-t command` and for single-function graph mode.

## `-t functions` output [run on two afd.sys builds, 10.0.26100.9444 vs .9549, x64, ~740 KB each]
- **Table output (no `-j`):** columns `name0 | size0 | addr0 | type | similarity | addr1 | size1 | name1`.
- **JSON (`-j`):** a top-level **array** of objects:
  ```json
  {"similarity": 0.962963, "type": "PARTIAL",
   "original": {"name": "fcn.140001008", "addr": 5368713224, "size": 54},
   "modified": {"name": "fcn.140001008", "addr": 5368713224, "size": 54}}
  ```
  - `addr` is a decimal integer (VA).
  - For unmatched functions, `original` or `modified` is `null`, with `"type":"UNLIKE"` and `"similarity":0.0`.
  - In this run, all 915 entries had exactly these 4 keys.
- **`type`** has three values [src: `librz/include/rz_analysis.h` L1713-1749]:
  - `COMPLETE`: similarity ≥ 1.0
  - `PARTIAL`: 0.5 ≤ similarity < 1.0 (`RZ_ANALYSIS_SIMILARITY_THRESHOLD = 0.5`)
  - `UNLIKE`: similarity < 0.5, or no counterpart
  - Run result: 78 COMPLETE, 702 PARTIAL, 135 UNLIKE.
- **Similarity algorithm** [src: `librz/arch/similarity.c`]:
  - It concatenates each function's **raw basic-block bytes** (`iob.read_at`) and computes **Levenshtein** similarity, after a fast pre-compare.
  - Bytes are **not masked or normalized**, so relocated call or RIP-relative displacements lower the score. In the run, functions at the same address and size scored 0.93–0.98 PARTIAL.
  - Matching is threaded: `rz_th_pool_new(RZ_THREAD_N_CORES_ALL_AVAILABLE)`.
- **Naming and symbols:** functions are named `fcn.<addr>` because no PDB symbols are loaded by default. Whether `-e` options such as `pdb.*`/`bin.dbginfo` make rz-diff fetch or load PDBs is **unverified**.
- **Resource use** (afd.sys pair, 4 cores) [run]:
  - Wall time about **90 s** (user 281 s): `real 1m32s` for table mode, 90 s for JSON mode.
  - Peak RSS about **235 MB**.
  - **[inf]** All-pairs Levenshtein over functions is roughly O(F₀·F₁·L²). Large binaries such as ntoskrnl (~10 MB, tens of thousands of functions) are likely to take hours. I did not measure this, so contracts need a timeout and cancellation.

## Exit codes [run + src]
| Case | Exit |
|---|---|
| Success, whether or not differences were found (`-t functions`, `-t bytes` with different files) | `0` |
| Identical files (`-t bytes`) | `0` |
| Cannot open file (`ERROR: rz-diff: error, cannot open file 'X'`) | `1` |
| Unrecognized `-t` type | `1` |
| `-h`, `-v` | `0` |

- rz-diff does **not** signal "differ" through the exit code, so parse the output.
- Errors go to stderr with the prefix `ERROR: rz-diff:`.

## Open questions
- Behavior and time on large PE files (ntoskrnl, win32kfull).
- PDB symbol loading in rz-diff.
- Windows build behavior and paths.
- Whether JSON output is guaranteed to be emitted only after analysis completes. Observed: one JSON document on stdout, valid.

## Implications for PatchTrace contracts
- **Role:** rz-diff is a usable, LGPL, cross-platform (Windows/Linux/macOS) second-opinion engine.
- **Invocation:** `rz-diff -C -j -t functions <old> <new>`. Parse a JSON array of `{similarity, type, original|null, modified|null}`, and treat `addr` as an unsigned VA.
  - Exit 0 = ran. Non-zero = error; capture stderr.
  - Validate that stdout parses as a JSON list. An empty or invalid result is an error even with exit 0.
- **Limits to state in contracts:**
  - Similarity is raw-byte Levenshtein. It is not semantic and is sensitive to relocations and address shifts.
  - No PDB names by default (`fcn.*`), so map functions by address to PatchTrace/Ghidra functions.
  - There is no per-match algorithm or confidence.
- **Resources:**
  - Enforce a wall-clock timeout and kill on cancel.
  - Expect about 0.25 GB RAM for a small driver and much more time on big binaries.
  - Matching uses all cores; there is no thread-limit flag in `-h`.
