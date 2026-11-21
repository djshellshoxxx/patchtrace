# Recovery batch 7: strings publication ownership

## Result and scope

Recover the retained held-source, held-parent **no-force** publisher, correct its
creation boundary for a supplied directory anchor, and normalize unavailable
publication capabilities into `PT-STR-EXPORT`. Recover exclusive random staging
for forced writes and remove every forced-failure pathname unlink. Forced cleanup
closes only owned handles; complete or partial stages, including intentionally
revealed strings, can remain.

**Successful forced replacement remains pathname-based and unresolved under
source or parent substitution.** A fresh authored probe after this repair still
publishes foreign bytes for those two success schedules. This batch fixes the
separate forced-failure deletion defect; it does not supply the missing
source-bound forced replacement operation.

The isolated branch starts at `5208c7589495cea749142f57599c4382be9caed5`.
Implementation ownership covers two runtime files and six test files, plus this
report. The coordinating branch amended WB3 section 8 and indexed the new runtime
helper before runtime work. Those shared documents are outside this commit.
There are no schema, dependency, research-tooling, backend-build, or remote changes.

## Retained contribution and exact provenance

The source is recovered from fetched PR #319 at
`a56ab13aaf9916fc12bea70ba1494075991b7f09`, not from the unreviewed remainder
of that branch. The same exporter is present at retained
`f6c4b0844e5973ba054d58490628e77492d57ec0`.

| Path or contribution | Retained Git blob | Disposition |
| --- | --- | --- |
| `src/patchtrace/owned_publication.py` | `71f3bbd5b74fb8ddfa212001e50ade82e4340354` | Recover, then gate both directory traversals on verified anchors. |
| `src/patchtrace/strings/export.py` | `28a79b13e0ae70d158a5ac2c3494311f9717bfdb` | Recover adapter/staging, add fixed capability text, remove forced pathname cleanup. |
| `tests/test_owned_publication.py` | `fbaa21e606cc1dc3a5d79fd5418b2d9fc200e956` | Recover and add anchor creation regressions. |
| `tests/test_strings_export_publication.py` | `b2ecad4095009d10d693ba772e6e8d3e3255234f` | Recover unchanged. |
| `tests/test_strings_export_source_ownership.py` | `20870a57524cfbe7479a5ebe9e850f9b88fc8987` | Recover and add capability, exception, and ancestor controls. |
| `tests/test_strings_export_force_cancellation.py` | `ed4fd7f5ba470808e5943a679dd9a52fad2a3259` | Recover unchanged. |

The integration-base exporter has blob
`c642cc148f9f8d90373e679f81f46f8976c72537`. Its existing
`tests/test_strings_export.py` is changed only to inject the no-force failure at
`fsync`, which is a real prepublication seam in the recovered implementation.
Injecting `os.replace` no longer exercises no-force publication.
`tests/test_strings_export_force_cleanup.py` is newly authored for this batch.

Earlier retained `2e37daf175533113fe73dc9a903f797a10ea9fc9` supplies useful
exclusive-staging history, but its pathname-link no-force publication remains
substitutable and its broader cleanup can delete foreign names during non-I/O
failures. It is not the implementation adopted here. Original historical repair
hashes that are not locally resolvable are not claimed as recovered commits.
The review binds accessible Git objects and individual file contents instead.

## Reproduced defects and repair

### No-force publication

The original exporter checks existence before a later replacing rename, and uses
a predictable PID staging name. The recovered route instead writes through its
held source and publishes exclusively into its held, verified parent. Existing
and concurrently arriving destinations are refused even if their bytes match.
Linux uses an anonymous staging descriptor and descriptor-assisted link;
Windows uses rooted native source/directory handles and a no-replace source-handle
rename. Strings does not opt into the helper's existing-content reuse facility.
The production helper depends only on the standard library and does not import
PW-01 research tooling.

The selected parent must already exist. Unsupported platforms, absent anonymous
staging, filesystem refusal, and `NotImplementedError` do not trigger a pathname
fallback. The adapter catches `NotImplementedError` around both anchor acquisition
and publication and emits fixed capability text, without including raw exception
text or a parent path. `FileExistsError` retains its distinct already-exists
message. Unrelated non-I/O failures and cancellation propagate unchanged.

Independent review found an additional issue in the retained helper: after
capturing `selected/leaf`, parking `selected`, and creating a foreign replacement
`selected`, traversal could create a new foreign `leaf` before rejecting its
identity. Both Linux `mkdir` and Windows `OPEN_IF` are now prohibited before or at
an unverified anchor. Creation strictly below an already verified anchor remains
available to generic helper callers. The strings adapter never needs to create
its selected parent. Controls verify that the foreign marker and directory
contents stay unchanged and that below-anchor creation still succeeds.

### Forced failure cleanup

Exclusive `mkstemp` staging avoids the predictable PID-name collision. The raw
descriptor remains owned by the writer until `fdopen` succeeds; if transfer fails,
it is closed. Once transferred, the stream owns the descriptor. After failure,
no pathname unlink is attempted, whether the primary exception is I/O,
`KeyboardInterrupt`, `SystemExit`, or another non-I/O exception.

The meaningful failure schedule closes the source stream, moves its stage to a
parked name, writes foreign bytes at the former stage name, and raises an authored
`OSError` at replacement. Before the repair, cleanup deleted the foreign file.
Afterward, the prior destination, parked original stage, and foreign replacement
are all preserved. Separate controls cover absent destinations, own stages,
partial writes, failed descriptor transfer, restrictive stage mode on Linux,
and non-I/O exception identity.

Retaining a mutable pathname is deliberate: even a matching `lstat` immediately
before unlink would leave a substitution interval. This policy can leave empty,
partial, or complete stages containing redacted or revealed data. It does not
promise complete temporary-file cleanup.

## Verification and receipts

All attack schedules use small authored files in temporary directories. No sample
binary or exported content is executed. Final focused qualification used a small
symlink virtual environment with task-local source and read-only qualified
Pydantic 2.14.2 / pydantic-core 2.50.2 dependencies; no new packages were installed.
A `/tmp` reset interrupted an attempted retained-source run before process
creation. Source checkpoints and earlier receipts survived in the workspace; the
worktree and lightweight interpreter were recreated before the recorded run below.

| Stage | Observed result |
| --- | --- |
| Original exporter and CLI baseline | 28 passed in 2.73 seconds |
| New ownership controls against original runtime | 11 failed, 11 passed in 1.39 seconds |
| Anchor, capability, and cleanup controls against unchanged retained runtime | 11 failed, 3 passed in 1.97 seconds |
| Corrected focused exporter/helper/CLI selection | 74 passed in 3.56 seconds |
| Whole-tree `ruff check --no-cache src tests tools` | Passed |
| Independent final anchor controls | Four passed: Linux negative/positive and portable Windows mismatch/order. |
| Fresh forced source-substitution success probe | Foreign bytes still published; ownership defect remains open. |
| Fresh forced parent-substitution success probe | Foreign bytes published in replacement parent; ownership defect remains open. |
| Fresh forced OSError cleanup probe | Prior destination and foreign stage both preserved. |

The focused selection consists of `test_owned_publication.py`,
`test_strings_export.py`, `test_strings_export_publication.py`,
`test_strings_export_source_ownership.py`,
`test_strings_export_force_cancellation.py`,
`test_strings_export_force_cleanup.py`, and `test_strings_cli.py`.
The Windows creation-order control uses portable native-call fixtures; it is not
a native Windows filesystem qualification. Independent review matched the full
eight-file manifest, checked the ten unchanged serialization/result ASTs, and
recorded its four fresh controls in
`verification/strings-independent-final-probes-20261119.json`.

Durable receipts under workspace `verification/` use the prefix
`strings-ownership-peer-batch7-`: `baseline`, `red-original`, `red-retained`,
`focused-green`, and `ruff` retain commands, raw logs, and results; pytest runs
also retain JUnit XML. `source-manifest.json` records all eight source/test hashes,
base/retained blobs, and unchanged ASTs for serialization, rendering, digest/result
handling, and `ExportResult`. `force-probe.py` and `force-probe.json` preserve the
three final authored schedules. Source checkpoints preserve full owned-file
contents independently of the temporary worktree. The earlier 27-schedule review
and its immutable receipts remain separate and unchanged.

## Qualification limits and remaining work

This is a scoped Linux and portable-call recovery. Native Windows execution,
packaging, and combined-head CI gates remain the coordinating branch's work.
No native or complete-suite acceptance is claimed here.

The held-source guarantee concerns the source and parent used by no-force
publication; it does not make the resulting name immutable against later writers.
A parent or destination change detected after publication can return an error
while a file has already been published. The caller must not infer from every
error that no output exists. This slice also does not establish directory fsync
or power-loss durability.

Forced successful replacement still needs a separate capability/design and native
qualification. The inspected Windows source-handle API offers a future design
direction with an explicit replacement flag; the recovered helper deliberately
keeps its no-replace API. The inspected Linux descriptor-link primitive cannot
replace an existing destination, and a subsequent pathname rename reintroduces
the source substitution interval. Pre/post pathname checks are not credited as a
force-success repair.
## Integrated follow-up

The accepted source was merged locally as `cf55415587f996f54a9d957a48d57818ebe9ff42`.
On the combined integration source `541bf83c1894e8111e6f35da7c14f3e04c5e71a2`,
the helper/export/CLI controls plus both offscreen strings UI modules passed
**115 tests in 10.95 seconds** using Pydantic 2.14.2/core 2.50.2. This selection
overlaps the contributor's 74 tests and must not be added to it as distinct
coverage. It does not qualify native Windows or the remaining successful-force
source/parent substitution boundary.

[The archived recovery and independent-review evidence](evidence/strings-ownership-20261119.zip)
preserves all original schedules, red/green results, source manifests, the
qualified source checkpoint and the separate integrated run.

## Later retained-source force review

The [read-only design and history archive](evidence/strings-force-design-20261119.zip) compares latest PR319 `8d130aefe1be6e737cff1d90d2a5b1658d60a3a6` separately from the original retained `a56ab13a`. Its exporter, owned-publication helper and WB3 force specification remain unchanged from that retained head. All 29 inspected path-history commits reduce to four exporter and three helper blobs; no complete held-source force implementation was recovered. The current successful source and parent substitutions remain open. The report records a possible Windows handle-based replacement design and the narrower Linux held-directory option, with native and contract constraints; it makes no new implementation or test claim. Archive SHA-256 `a094c8cc8ad0114a77d232a16957f4579a3bcae03e00d3787d4226d30fab3666`, 15375 bytes, two payloads plus manifest.
