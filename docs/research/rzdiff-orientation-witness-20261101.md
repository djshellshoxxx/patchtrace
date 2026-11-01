# Rizin 0.9.1 orientation witness preparation

Status: READY research; observation decoder only. The 0.9.1 quarantine remains in force.
The initial preparation did not execute native tools. The continuation below records fresh, bounded
native research on the approved original release; no pin change, target execution or quarantine lift occurred.
The 27 retained #131 recordings remain historical evidence, separate from these new controls.

## Source proof and proposed static query

All source links below are pinned to the approved 0.9.1 source tree
`c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`.

- [`rz-diff.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/main/rz-diff.c):
  lines 642–705 define the common loader; 1379–1418 load fresh cores for command mode,
  optionally call `rz_core_analysis_everything(core, false, NULL)` with `-B`, then capture command output;
  2303–2384 use that same loader and analysis call in function mode. Command mode logs analysis
  failure and continues; a successful process exit cannot prove complete analysis.
- [`cmd_analysis.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/cmd/cmd_analysis.c),
  lines 3673–3676, and [`function.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/arch/function.c),
  lines 446–453: `aflc` prints `rz_list_length(analysis->fcns)`. This is the same unfiltered
  list returned by `rz_analysis_function_list`, cloned before matching in `core_diff_show`.
  The FCN/SYM output filter occurs after matching and cannot establish this cardinality.
- [`cmd_math.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/cmd/cmd_math.c),
  lines 414–422: `%vi -1` prints signed `-1` followed by newline.
- [`lines_diff.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/diff/lines_diff.c)
  preserves newline-terminated lines without adding an empty trailing line;
  [`unified_diff.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/diff/unified_diff.c),
  lines 55–70, 284–327 and 417–484, serializes the differing one-line outputs as one
  delete and one insert, each with its newline and a `[1, 1]` range.
- [`canalysis.c`](https://github.com/rizinorg/rizin/blob/c3a90e9226d977f58f4e9c75f78fa6b07afe13c7/librz/core/canalysis.c),
  `rz_core_perform_auto_analysis`, calls `rz_core_analysis_all` before `everything`.
  Standalone `rizin -A` plus `aflc` is therefore not established as an equivalent substitute.

The proposed fixed, static-analysis-only argv is:

```text
rz-diff -C -j -B -t command -0 aflc -1 "%vi -1" ARTIFACT ARTIFACT
```

The decimal count is a count of the first command-mode core's recovered list. The negative
sentinel makes counts zero, one and many distinguishable. It is not a function-mode orientation witness.
No user command, architecture override, environment-variable override or target execution is accepted.

## Bounded observation contract

`tools/research/rzdiff_count_observation.py` prepares the fixed argv and decodes a retained capture.
It does not launch processes, read targets or change adapter policy. A capture binds exact argv,
artifact digest, approved Linux archive/member digests, caller-supplied runtime/config manifest digest,
and raw stdout/stderr digests. These are capture claims, not independently verified filesystem attestations.
The decoder accepts only bounded UTF-8 strict JSON, exact paths/ranges/opcodes and canonical nonnegative
decimal count text; nonzero exit, any stderr, extra JSON keys or process anomaly fails closed.
Every returned observation has `orientation_authorized=false` and `capture_binding_verified=false`.
Synthetic tests exercise decoding and negative controls only; they prove no native compatibility.

## Runtime inventory and unresolved prerequisites

Read-only PATH checks found no real `rz-diff` or `rizin`; bounded filename scans of `/workspace`, `/opt`
and `/tmp` found Python fake test launchers and retained receipts, not an approved runtime/archive.
Historical `/workspace/scratch/a55b59b3e326/research-tools/` paths are absent. This is a bounded inventory,
not a universal claim about the host. The retained Linux archive SHA-256 is
`9102249a9f0b6319c5334a2e5cf8d9cc3f2035e1d3def027c41f6a90f647e8cf` and its `bin/rz-diff`
member SHA-256 is `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e`.

The next READY work must establish all of the following before independently reviewing any quarantine lift:

1. Recover an already approved same-version runtime/archive through the permitted source, verify the exact
   bytes, dynamic libraries/plugins and effective configuration/environment; loading all core plugins means
   an executable hash alone is insufficient runtime binding.
2. Run the fixed static query with immutable copied input, bounded stdout/stderr, deadline/cancellation,
   process-tree control, and before/after artifact/runtime verification. Treat every diagnostic as abstention.
   Retain raw bytes, argv, config/runtime manifests and all hashes, including failed negative controls.
3. Prove that the count observed in a separate fresh command-mode core equals the exact input0 list
   selecting the singleton branch in the actual function-mode run. Same function names, list shapes,
   version suffixes, repeated equal counts, and same source call sequence alone do not prove state identity.
   A source-bound same-run observation before matching, or an independently justified deterministic
   analysis-state equivalence argument with controls, remains the unresolved technical prerequisite.
4. Exercise zero, singleton, many, reversed-input, partial-analysis, configuration drift, tool/plugin drift
   and artifact mutation controls on the pinned runtime, then obtain independent review. A zero recovered
   list is an analysis error, never successful empty acceptance. A proven singleton witness would permit
   only the source-established conditional side mapping, never a global swap.

These are agent-doable research/preparation tasks subject to the existing host job slot and approved tools;
they are not assigned to a human or classified externally blocked merely because the current JSON omits metadata.

## Original pinned runtime controls (2026-11-01 continuation)

The official [0.9.1 release API](https://api.github.com/repos/rizinorg/rizin/releases/tags/v0.9.1)
advertises Linux asset `460538308`, size `137626404`, with the existing repository archive SHA-256.
An ordinary TLS-verified download through the inherited proxy matched that digest and exact size;
the extracted `bin/rz-diff` matched the existing member digest above. The first attempt's arbitrary
128 MiB collector ceiling was smaller than the published asset; that failure receipt was retained,
and the retry used the exact published size. No Rizin pin was changed.

[Bounded native evidence](rzdiff-witness-native-20261101.json) contains all 13 direct control argv,
raw streams/digests, exact input digests, full child environment, version, configuration observation,
resource-manifest digest, before/after integrity checks, and debugger failure/provenance. The original
ELF64 x86-64 static executable has no dynamic section; 675 executable/resource files were inventoried
and verified unchanged before/after the controls. PE inputs were only read by Rizin, never executed.

| Fresh native control | Observation | What it establishes |
|---|---|---|
| Fixed count query on zero/one/two/shifted-two fixtures | Counts `0 / 1 / 2 / 2`, empty stderr | Query decodes real pinned output for those command-mode cores |
| Zero recovered input0, all-function mode | Exit 0, empty stdout, `No functions found in file0` diagnostic | Successful exit is insufficient; no successful empty acceptance |
| One versus two, then reversed inputs | Exactly identical raw JSON SHA-256 | Neither output shape nor raw hash establishes input-side ownership |
| Two versus shifted two, all-function mode | Original RVAs `0x1010/0x1020`, modified `0x1050/0x1060` | Ordinary branch retains order on this control; global swapping is wrong |
| Two versus shifted two, `-0 0x180001010` | Original shifted endpoints; modified selected input0 endpoint | A selected-function singleton branch reverses endpoint ownership in that same scoped run |
| Missing `-0` function | Exit 0, empty stdout, not-found diagnostic | Selected-function lookup must also fail closed |
| Extra `-e analysis.calls=false` | Count happens to remain two | Equal counts cannot attest matching configuration; the fixed-argv decoder must reject this capture |

The `-0` control is source-bound: `rz-diff.c` lines 372–377 allow that option in function mode,
and lines 2145–2165 build a new input0 list containing exactly the recovered function at that numeric VA
before calling the matcher. The actual binary's disassembly also tests `rz_list_length(input0) == 1`
before selecting the singleton callback and swapped list arguments. This proves a bounded singleton
control, not the full-list cardinality of the normal all-function run; no new per-function production
matching loop or alternate default query is introduced.

The read-only `elj` command is registered by pinned `cmd_eval.yaml` and implemented by
`rz_eval_list_handler` in `cmd_eval.c`. A separate command-mode core reported 597 configuration keys,
including x86/64, `analysis.calls=true`, `analysis.timeout=0`, and `cfg.plugins=true`. Pinned `libs.c`
shows all configuration/env/home/system/extra plugin lookup paths and script-plugin loading.
The pinned archive's `rz_lib.h` defines `RZ_LIB_ENV` as `RZ_LIB_PLUGINS`; that variable was absent.
The supplied legacy `RZ_LIBR_PLUGINS` variable is ignored by this loader. The private home search path
`HOME/.local/lib/rizin/plugins` and configured compiled plugin directory did not exist;
the portable runtime had no plugin directory; its verified
`rz_userconf.h` sets `RZ_EXTRA_PREFIX=0`. These source/config/filesystem observations bind the recorded
experiment, but they do not prove the exact configuration in a different matcher core or constitute
a complete trace of actually opened resources.

GDB 15.1 and seven necessary runtime packages were acquired from the configured signed Ubuntu snapshot
index, SHA-256 checked, and extracted privately without system installation. A breakpoint at the original
binary's list-length comparison failed **before the inferior started**, with `ptrace: Operation not permitted`.
That host restriction was preserved and not bypassed. GDB and static binary/source identities are recorded;
the failure yields no same-run witness. A source-built instrumented derivative would have different producer
bytes and could not silently authorize the original producer's output.

The original all-function same-state prerequisite therefore remains **READY research**, with these precise
next boundaries: a supported source-bound observation mechanism for the original runtime, or a separately
specified, hashed and independently reviewed instrumented producer with its own native evidence and explicit
scope. Repeating the count query is insufficient. Quarantine, nonzero live-gate behavior, broad corpus/GT and
Windows acceptance remain unchanged. No GT acceptance or production repair is claimed by these controls.
