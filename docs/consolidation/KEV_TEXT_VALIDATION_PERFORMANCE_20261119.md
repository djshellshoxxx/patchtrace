# KEV text validation: measured ASCII fast path

## Result and scope

This newly authored performance change adds one printable-ASCII fast path to
`kev.contracts._plain_line`. It follows the existing `clean_text` approach in the
same module. Text still must equal its stripped value. Printable ASCII cannot
match any character in the existing unsafe ranges, so only that subset avoids the
Unicode regex search; every other value retains the original regex fallback.

The branch starts at `cf55415587f996f54a9d957a48d57818ebe9ff42`. Changes are
confined to `src/patchtrace/kev/contracts.py`, 77 additional semantic cases in
`tests/test_kev_contracts.py`, and this report. The complete contracts-module AST
is unchanged apart from `_plain_line`. Digest consistency validation, the identity
implementation, field definitions, schemas, dependencies, and the existing
less-than-one-second parser assertion remain unchanged.

Two bounded paired experiments support retaining this small optimization on the
recorded Linux interpreter. Results vary between blocks and do not establish a
Windows performance fix. The original Windows failure remains preserved.

## Why this was examined

PR #318 Windows full-QA job `135484259463`, run `44502066991`, failed
`tests/test_kev_parse.py::test_a_full_size_catalog_parses_within_the_budget`.
It parsed all 1,741 entries but took **1.4662241000000904 seconds**, exceeding
`elapsed < 1.0`. Its terminal summary was **1 failed, 25,615 passed, 151 skipped,
2 xfailed, 25 warnings in 4,612.02 seconds**. The failure is not attributed to
runner load or discarded as a flake.

The actual checked-out PR merge was
`de9a8cf060a5def95acb9d887f68e0dc01237221`, merging PR head
`c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` into
`f2b6827fc6270b96fb241b0722f2878de5a17361`. REST metadata confirms tree
`ee130e5c201683794abf42b76fb6c9372731d892`. The failing test, fixture helper,
parser, contracts, limits and shared identity module match the integration base
byte for byte. The tested Windows environment used CPython 3.12.10, Pydantic
2.13.5 and pydantic-core 2.46.5; this work uses Linux CPython 3.12.14, Pydantic
2.14.2 and pydantic-core 2.50.2. A local pass cannot qualify that earlier Windows
execution or prove the timing defect resolved.

Before the optimization, the existing single parser performance test passed
unchanged on current Linux: **1 passed in 1.25 seconds of total pytest time**.
Three direct parse samples took 0.169237, 0.106382 and 0.123659 seconds.
The local fixture is 3,023,173 bytes, SHA-256
`39652f335cf25e9b3f55ddea462085729b7f9d96dc6427c0df2d8f178842ef04`.
These observations use the authored fixture construction already in the test.

## Profile and validation decision

The initial instrumented parse took 0.308392 seconds including profiling overhead.
`_plain_line` was called 10,446 times; regex searches accounted for approximately
0.022 seconds. The larger cost was `entry_digest`: 3,482 calls, twice per entry,
with approximately 0.138 seconds cumulative. The second digest computation checks
that the public record's supplied identity matches its validated fields. That
consistency check remains intact; it was not removed to improve the timing.

The change only avoids work whose answer is already known for printable ASCII.
Leading/trailing ASCII and Unicode whitespace still fail. Embedded C0/C1 controls,
DEL, bidi/zero-width controls, separator characters, BOM, tag characters and other
existing unsafe ranges still fail. Visible non-ASCII text, combining marks,
replacement characters, emoji and allowed internal Unicode spaces retain their
exact values. Lone surrogates retain the earlier Pydantic string-boundary refusal.

## Paired measurements

The baseline source was exported from the immutable integration commit into a
small temporary source snapshot. The candidate lived in an isolated worktree.
Both used the same lightweight symlink interpreter and read-only qualified
libraries; no packages were installed. No compared binary or exported data was
executed. All input data was authored by the existing fixture builder.

### Fresh-process comparison

Four sequential ABBA blocks ran in fresh processes. Each process warmed once and
timed five complete parses, retaining all **80 measured parses**, 40 per variant.
The candidate and baseline returned identical full catalog serialization and the
same CVE index, content digest, fixture hash and dependency versions.

| Metric | Baseline median | Candidate median | Reduction |
| --- | ---: | ---: | ---: |
| Wall time | 0.193756 s | 0.184248 s | 4.91% |
| CPU time | 0.180851 s | 0.162501 s | 10.15% |

Two of four wall-time blocks were slower for the candidate. This mixed result was
preserved and prompted one bounded confirmation; it was not treated as conclusive
by itself.

### Same-process confirmation

Six ABBA blocks reused the same compiled Pydantic model objects in one private
process. The exact baseline or candidate `_plain_line` code, extracted from its
source AST, was selected outside each timed parse. No other validator, parser or
schema was changed. The original function code was restored in `finally`.
Each block retained three complete parse timings per position, for **72 measured
parses**, 36 per variant. Full serialized outputs again matched exactly.

| Metric | Baseline median | Candidate median | Reduction |
| --- | ---: | ---: | ---: |
| Wall time | 0.166770 s | 0.146045 s | 12.43% |
| CPU time | 0.165850 s | 0.146022 s | 11.96% |

Four of six wall-time blocks improved by 11.6–19.9%; two were 1.1% and 3.3% slower.
All block and sample values remain in the receipts. These are descriptive results
for this fixture and environment, without a statistical guarantee or an assumed
cause for the variation. The observed local benefit is useful for the one-line
change; no further optional benchmark repetitions were used to seek a better
result.

## Semantic and functional verification

The new tests assert behavior through the public `KevEntry` model. They check
exact accepted values, field locations and rejection/error behavior. They do not
count regex calls or reproduce the implementation condition as a test oracle.

| Stage | Observed result |
| --- | --- |
| Initial authored semantic controls on unchanged runtime | 217 passed, 2 test-expectation failures |
| Corrected semantic controls on unchanged runtime | 219 passed in 1.37 seconds |
| Candidate contract, parser and schema files | 386 passed in 5.55 seconds |
| Whole-tree `ruff check --no-cache src tests tools` | Passed |
| AST/source check | Only `_plain_line` changed; parser timing test, identity module and dependencies unchanged. |

The two initial failures were in the authored surrogate expectations. Existing
Pydantic rejects lone surrogates as `string_unicode` before the AfterValidator;
the test had incorrectly expected its later `value_error`. The expectations were
corrected before runtime optimization. That is a harness correction, with no
production-defect repair credit. The initial receipt is retained.

An initial benchmark harness likewise tried to call `model_dump` on the
`KevCatalog` dataclass after timing its first worker. It failed before any sample
record was written. The corrected harness serializes the contained Pydantic meta
and entries, verifies the CVE index, and retains the released timestamp. Both
harness versions and the explicit failure receipt remain available; no results
from the failed harness are included above.

## Provenance and retained evidence

The baseline contracts blob is `6b0d584d20ed8acc5f87449a191d7890ced6d3c5`,
SHA-256 `418b53261b215c33c3d78135dc54454caf539edcdeb15263e4e05034627a8d98`.
The candidate SHA-256 is
`81ae7597745d477f4f7c9ff61d046de44560b98d52d50fde7f63199c65a7877a`.
This is a narrow new optimization based on an existing in-module pattern, not
recovery of an unreviewed retained branch or proof that its parent work is done.

Workspace `verification/kev-text-performance-*` receipts retain the baseline and
corrected semantic runs, both paired scripts and all samples, the failed initial
harness, final functional log/JUnit, whole-tree Ruff, source/AST binding and full
owned-file checkpoints. The earlier `ci318-windows-qa-failure-*` and
`ci318-kev-current-root-*` receipts retain the original Windows failure, exact
checkout/dependency binding, pre-change local test and profile. The
`ci322-pr318-review-manifest-20261119.json` binds that earlier read-only phase.

Native Windows testing, final combined-head CI, packaging and the original
Windows one-second gate remain separate qualification. The threshold was not
relaxed, and the passing local result is not substituted for those gates. No
remote operation or shared consolidation-document edit was made by this slice.

## Independent acceptance and archive

Independent review approved source `c84ca5a2`, integrated through `8efb7a45`. It checked 690 baseline/candidate string comparisons and 14 public-model probes, including misleading string-subclass methods and wrong digest refusal, and recalculated both sets of benchmark medians with all slower blocks retained. The [verified archive](evidence/kev-text-performance-20261119.zip) preserves 43 payloads plus the archive manifest; SHA-256 `20701bf98f9c5e271be7ca6b4bfef6aa549faa66233b59996b6ef65d95ae98bd`, 139595 bytes. The original manifest records its then-pending review; the later independent report and exact source binding are separate preserved payloads. This acceptance does not establish the Windows timing gate.
