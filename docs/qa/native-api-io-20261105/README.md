# Actual pinned-native API and IO milestone — API scope only

Frozen control source: `0bf2f62b`; exact source/executable/library hashes and every
raw artifact hash are in `manifest.json`. This runs the actual linked Rizin
v0.9.1 API at approved commit `c3a90e9226d977f58f4e9c75f78fa6b07afe13c7`.
Inputs are authored API objects and buffers. No compared target binary ran.

- Default unchanged 32-row oracle: stock completed with singleton-only ownership
  failures (expected exit 1); corrected completed with zero errors (exit 0).
  The existing strict native evidence runner accepted both complete matrices.
- Distinct-buffer/IO mode: stock failed the two 1:2 orientations/address-overlap
  controls and passed the two ordinary 2:1 controls; corrected passed all four.
  Both IO contexts were read by the matcher in each positive case.
- Corrected wrong-bytes control: all four rows failed when both sources supplied
  identical bytes. Corrected wrong-IO control: both overlapping-address rows
  failed with reads only from the incorrectly shared IO context. These deliberate
  negative controls are oracle checks, not producer failures.
- All final raw stderr files are empty. Incomplete output, extra/missing rows,
  wrong exits or wrong read/error patterns were refused by the validation run.

The same final executable was used for stock and corrected. Eighteen native
library files were snapshotted and hashed before execution; only `librz_arch`
differs. Source mutation used the existing exact-byte patcher. Default PCRE2
configuration failure, provisioning and incomplete first checkpoint remain in
`../native-provision-20261105/`; supported system PCRE2 10.42 and a plain build
completed the exact API dependency closure at low priority/one job. No binary or
library is redistributed. Source/project LGPL/GPL scope is unchanged.

First attempts are retained at this directory's top level. An actual wrong-IO
negative exposed two control defects: constructor reads polluted counters, and
function-count-clipped IO caused an allocation failure. The final source resets
counters immediately before matching and keeps two valid IO slots independent
of function-inventory cardinality. Reruns under `final/` supersede those attempts;
the first results were not overwritten. This is distinct from the preserved
actual upstream default dependency-link failure.

Final executable: `/tmp/pt-rizin-native-final-control`; stock and corrected
library snapshots: `/tmp/pt-rizin-native-{stock,corrected}-libraries`. Select the
respective snapshot through `LD_LIBRARY_PATH`, run the existing native evidence
runner for the default matrix, and invoke the same executable with
`--io-context`, `--io-context --wrong-bytes`, or `--io-context --wrong-io` for the
separately recorded modes. Source/API compile commands and complete build logs
are retained; no environment secrets were captured.

Independent source review covered ownership, reference lifetimes, callback ABI,
threaded counter protection, default compatibility and expected Levenshtein
values. Existing synthetic/compiled-double tests remain separate from these
actual linked-native runs. CLI JSON/recovered inventory, real binary analysis,
Windows, product cache adoption/quarantine removal and Tier R requalification
remain open. This milestone is not release readiness or complete producer
qualification. CLI continuation is a separate bounded slice.
