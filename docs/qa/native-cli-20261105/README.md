# Actual pinned CLI probe — not qualified

The exact `rz-diff` and `rizin` target closure linked at nice +15/-j1 (198 steps).
Both report/use pinned Rizin 0.9.1. Executable and native-library hashes are
retained. Stock/corrected library sets differ only in `librz_arch.so.0.9.1`.
No binaries are redistributed and no target input was executed.

Four tiny authored C sources were compiled into ELF relocatable objects, then
linked without libc/CRT with `component` as the entry point into ELF executables.
The files have one or two functions by construction. Separately executed
`rizin -N -A -q -c aflj` recovered exactly those counts for every source/format
and both library variants. `inventory-summary.json` lists the recovered names,
addresses and sizes; complete raw JSON and stderr remain untouched.

Actual production flags `rz-diff -C -j -t functions` were run for 1:1, 1:2,
2:1 and 2:2 inputs, both ELF formats and both native-library variants. **All
16 returned exit 0 but empty stdout and `No functions found in file0` on stderr.**
No valid CLI JSON pair was produced. These are genuine local CLI failure
observations, not expected stock ownership-red results and not successful
compatibility evidence. The API/IO milestone is unaffected and remains separate.

The cause is not established. This build used exact target closures without a
complete runtime-data installation. Next investigate full runtime data/prefix
configuration and CLI load/analysis initialization against the independently
recovered inventories before attributing an upstream source defect. Do not
change the product parser, frozen flags, quarantine, inventories or thresholds
to hide this failure. Exit status alone cannot qualify this tool.

Compiler inputs/settings:

```text
cc -c -O0 -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector SOURCE.c -o INPUT.o
cc -nostdlib -no-pie -Wl,-e,component INPUT.o -o INPUT.elf
```

Sources, exact derived-input hashes and all execution argv/return codes are
retained. All data is authored synthetic ELF, not Microsoft input or Windows
acceptance. Product runtime/provider/cache/quarantine and automation are
unchanged. These finite receipts preserve every attempted dataset; none was
replaced by a passing-looking retry. No new background job is promised.

## Separately authorized seeded-CLI experiment

After retaining the failed baseline, source inspection found an analysis setup
contract difference. `rizin -A` calls `rz_core_perform_auto_analysis`, which seeds
symbols/entry0 with `rz_core_analysis_all` before any deeper analysis. Pinned
`rz-diff`'s functions branch called only `rz_core_analysis_everything`. The exact
research experiment adds `analysis_all` for both cores before the existing calls;
`seeded-analysis.patch.gz` and whole source hashes retain the two-line intervention.
This extra CLI modification is **outside the approved patcher/pin**.

The seeded main library was built at nice +15/-j1, then copied into new isolated
stock/corrected library sets. Only `librz_main` differs from their respective
baseline sets; only `librz_arch` differs between the seeded stock/corrected sets.
The third experimental executable has its own path but the same binary bytes:
analysis entrypoint code lives in dynamic `librz_main`. Complete runtime library
hashes distinguish the experimental producer; no version suffix asserts trust.

All 16 seeded cases now emit strict nonempty JSON with empty stderr. Separately
recovered inventory tuples (address, size) verify complete owned-side coverage in
all eight corrected cases. Seeded stock 1:2 emits an original-side new-helper
endpoint outside the older inventory, in both formats; corrected assigns it to
the proper newer side. Other stock cases are not declared ownership-safe merely
because overlapping endpoint tuples pass membership. The exact shared-tuple
ambiguity counts are retained; names and similarity numbers never decide credit.

This verifies a causal two-call seeding intervention on these authored ELF cases
and reproduces observable singleton serializer ownership failure. It does not
qualify an approved producer: additional source was changed, PE/Windows and full
installed-runtime behavior are untested, ambiguous/wrong-input/tool witness
rejection and application cache adoption remain open. Quarantine, product flags,
parser, provider/cache interfaces and automation remain untouched. The original
16 failures and candidate-cause checkpoint remain historical evidence, not erased
by the successful experiment. `seeded-manifest.json` binds both stages and records
limits. No background job remains running for this slice.

Raw inventory stderr contains terminal clear-line/carriage-return bytes, and the source diff contains native tab context. These artifacts are retained losslessly as deterministic `.gz` files, with raw and compressed hashes; no upstream whitespace was normalized.
