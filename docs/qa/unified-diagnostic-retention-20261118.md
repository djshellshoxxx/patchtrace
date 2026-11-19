# Bounded live-unified diagnostic retention — 2026-11-18

## Exact source and result

Source **adab5118264011ed2da0a664b198a1288391c25f** passes **333 affected
checks**, with zero failures, errors or skips, in 15.61 seconds. All 211 recorded
project/tool imports match the exact source; the worktree stayed clean and the
original external probe stayed byte-identical. Six separate stable-file and
interrupt boundary controls also pass. Full normal Ruff passes. Independent
root replay and integration are separate gates.

The retained branch is `codex/unified-diagnostic-retention-20261118` in
`/workspace/scratch/c7a9e8d98848/security-residual-qa`. The implementation starts
from `52a562b6f4c8063b7cb47b31c3942f55db7fa5f5`. Only the existing live tool, a
new focused test file, SPEC-31 extraction subsection 12.8a and the existing
module-index row change before this QA packet.

| Role | Exact commit |
| --- | --- |
| Initial specification and tests | `abb201de7c6653eb2d33464800090da54f4275fe` |
| Initial implementation | `86aa905ab86881624aea4b690c112b2ec9b1d7be` |
| Explicit omission/count and final-byte-cap controls | `18afb550134c83b7605ed5257710e18da2c07fa8` |
| Omission/count and final-cap correction | `e3f07f76f564b37a8bf9c410a4474b160918fba7` |
| Fresh-reporting-interrupt specification and tests | `61e5eab3d19cfa8b23ab47a2fe75bc31bbae1e0c` |
| Final caller-entry exception shield | `adab5118264011ed2da0a664b198a1288391c25f` |

## Observed problem and evidence layer

The actual Windows live-unified run 44409973392, job 135175184056, used the
published 771e5a775f5bf60a8d9094232b51dcdbb47d6389 source. Its exact local tree
is `ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`. The CI pair passed, but the probe
pair's newer-side repeated analyses had different canonical content digests:
`a658ef9f00c21c74bac115a68414f8188206258c051a9c3ea9c484e0d0e65c0c` and
`b7dc355b73b3482f82fff8c81ba8d32e51e285a357dc39ba96ba0f6bcf3bf936`.
The IR key remained equal. The archive retained only first-run summaries and
four fixture DLLs, so it cannot explain the difference in second-run rows.
Artifact 14477506098 is 215,897 bytes with SHA-256
`f785fd27d473c0410c4bbd57459cedf94fbee7e8f45e9b6f4319c801c81e3e9d`.
Its existing verified metadata, log and two JSON summaries are copied here;
no DLL was extracted or executed for this work.

The separate portable probe supplies authored extraction records to the real
ingester and tool lifecycle. An alias-only second run retains the same counts,
IR key and old six-field function summary while its canonical digest differs.
The original tool removed that second-run evidence with its private work.
Another case loses a completed first run when the second extraction raises.
An identical-run positive retains the existing passing gate and cleanup.
These controls originally produced two failures and one pass. They demonstrate
the retention defect; they do not reproduce or diagnose the native producer's
particular nondeterminism.

The sealed original design packet is included unchanged as
`original-design/evidence.zip`, SHA-256
`07570484efe7aa948fa7bc3fe587e7c115795cbb238c44623c54ed4f3fc77bd5`.
Its 37 payloads and original source/log/XML/observations remain intact. The
original probe SHA-256 remains
`8f5d054cdca97976ef6c8f663c159d061ff1926ed1a1e5067fe797e66e9f3bd2`.

## Resulting behavior and quotas

Each successfully ingested first and second analysis is captured immediately,
before the next analysis or later gate. The writer reserves a slot before any
capture or publication: at most four `(older|newer, ordinal 1|2)` attempts per
invocation, without retry or refund. A random UUID distinguishes invocations.
Files use the fixed top-level name
`live-unified-diagnostics-<uuid>-<side>-analyze-<ordinal>.json` and exclusive
creation, so existing files are preserved. They survive the tool's existing
private-work cleanup and fit the current `live-out/*.json` upload glob.

A complete `live-unified-diagnostics/1` envelope binds the ordered artifact
hashes, validated manifest, bounded runtime context and exact tool/extractor/
schema/ingest identities. It contains exact JSONL and IR database bytes encoded
as base64, with decoded lengths and file hashes, plus a readable full-column
function projection. The IR snapshot must match the manifest file hash and is
queried from those same copied bytes. Its byte hash is explicitly distinct from
the unchanged canonical content digest. All eight IR tables remain available
in a complete binary snapshot; capture does not decompress instruction blobs.

| Limit | Per attempt | Four-attempt invocation |
| --- | ---: | ---: |
| Encoded JSON file, including final newline | 12 MiB | 48 MiB |
| Exact decoded JSONL | 4 MiB; 4,098 records | 16 MiB; 16,392 records |
| Exact decoded IR | 4 MiB; 32,768 rows across eight tables | 16 MiB; 131,072 rows |
| Readable functions | 4,096 rows; 512 KiB encoded | 16,384 rows; 2 MiB |
| One encoded function row | 16 KiB | Same bound |
| Encoded metadata/status | 128 KiB | 512 KiB |
| Cooperative capture time | 2 seconds | 8 seconds |
| Post-open SQLite progress | 2,000,000 steps | 8,000,000 steps |

Binary sizes use powers of 1024. Reads use finite chunks and at most cap plus
one detection byte. Each attempt reserves the full 12 MiB, including failures.
The budget is per invocation; it is not retention management for an indefinitely
reused output directory. Every component declares complete, prefix, omitted or
error, with explicit retained counts and a bounded reason. Omitted components
declare zero retention rather than inventing observed hashes. A readable prefix
is labeled; a capped or unqueryable snapshot is not declared complete. A partial
publication is not announced as saved, and its bytes are retained without a new
deletion route. A final envelope byte-cap refusal is reported even if no envelope
fits. No input DLL, GZF, unrestricted environment or stderr payload is retained.

## Reporting failures and interrupts

Ordinary diagnostic/reporting Exceptions remain observational and cannot add an
acceptance failure or replace a caller failure. The first implementation also
suppressed fresh reporter BaseExceptions. Its 326-pass affected result remains
historical; a separate two-red/four-positive probe and six-red/35-positive
spec-first extension exposed and pinned that distinction.

Final source takes an explicit local snapshot of whether a caller exception is
already active at capture entry. Only that state shields the original caller
exception from a secondary reporter BaseException. Internal diagnostic stops,
metadata failures and publication failures do not manufacture protection. Fresh
KeyboardInterrupt and SystemExit from the reporter therefore propagate after
otherwise ordinary capture or refusal. Existing active-primary assertions are
unchanged. No exception object or shield is retained globally or after capture.
Seven new cases cover success, byte refusal and collision for both fresh
interrupt types, plus an active-primary/SystemExit refusal case.

## Preserved red and green records

| Receipt directory | Source | Failed | Passed | Errors / skips |
| --- | --- | ---: | ---: | ---: |
| Original sealed design | `0201a4c8` (tool equals hosted tree) | 2 | 1 | 0 / 0 |
| `spec-red` | `abb201de` | 27 | 1 | 0 / 0 |
| `focused-initial` | `86aa905a` | 0 | 28 | 0 / 0 |
| `receipt-red` | `18afb550` | 2 | 32 | 0 / 0 |
| `focused-final` | `e3f07f76` | 0 | 34 | 0 / 0 |
| `affected-final` | `e3f07f76` | 0 | 326 | 0 / 0 |
| `boundary-red` | `e3f07f76` | 2 | 4 | 0 / 0 |
| `interrupt-red` | `61e5eab3` | 6 | 35 | 0 / 0 |
| `focused-interrupt-green` | `adab5118` | 0 | 41 | 0 / 0 |
| `boundary-green` | `adab5118` | 0 | 6 | 0 / 0 |
| `affected-interrupt-green` | `adab5118` | 0 | 333 | 0 / 0 |

The final focused gate is 38 repository cases plus the three unchanged original
public controls. It covers exact raw round trips, a difference outside the
function projection, byte/record/row caps and exact boundaries, Unicode encoded
size, explicit prefix/omission, changed and malformed snapshots, stable symlink
refusal, filename uniqueness/collision, spent slots, deadlines/query progress,
bounded growth after stat, final newline accounting, partial writes and reporter
precedence. Separate external controls cover stable directories/FIFOs and
capture/reporter interrupts. FIFO opening is instrumented and never attempted.

The 333-case affected gate additionally includes live-tool/workflow, ingestion,
extract-runner, packaging and registry neighbors. It records 211 canonical
project/tool imports with no drift; focused runs record 91 and the external
boundary runs 56. Each implementation gate records zero network audit events. The affected
runs record **34 process audit events** from inspected existing fake-producer/
runner tests; they are not zero-child runs. Focused and boundary runs record
zero process events. No Ghidra, Java, compiler, target binary, live download or
native acceptance run was requested or performed. The additional offline
filter's receipt does not establish a product sandbox guarantee.

## Structural verification and reproduction

`structural-preservation.json` verifies that removing only the diagnostic
constants/helpers/imports and their optional capture hooks restores the entire
original tool AST. The acceptance calculations, digest algorithms, native calls,
summary shape and main cleanup are thereby unchanged. The `src`, workflow,
fixture and configuration trees remain equal to the baseline. All 29 existing
test functions at e3f07f76 remain AST-identical through the interrupt extension.
Canonical Git snapshots, exact blob IDs/hashes, source-chain diffs and the
receipt/import recheck are included in this packet.

Each phase retains its precise invocation, XML, log, import record, offline
record, exit status and fresh public-probe observations. The runner uses
`/workspace/scratch/3a6632a6e5ff/venv/bin/python`, absolute checkout `PYTHONPATH`,
`QT_QPA_PLATFORM=offscreen`, `PYTHONDONTWRITEBYTECODE=1` and no pytest cache.
`run_gate.py` requires an exact clean source checkout and a new phase label;
`run_boundary.py` selects the separate external controls. The original public
probe deliberately loads the tool from the retained security-residual-qa path.
For a combined integration replay, root must verify that tool's bytes equal
the integration candidate before and after execution and report that equality
separately from canonical root-module imports. This checkout will remain stable
until that replay completes.

Reviewable authored final envelopes are copied under `examples/`, including
both runs of the divergent pair and the first capture before a later failure.
The original failure observations and failed temporary directories are retained;
no historical failure has been relabeled or overwritten. The QA archive omits
large temporary cap-test payloads, which remain in the recorded owned temporary
directories. All raw receipts and selected example bytes are hashed.

## Practical scope limits

This is a bounded diagnostic retention repair. It neither fixes nor explains the
preserved native nondeterminism and does not turn its failed L1 check into a
pass. Future native evidence is still required.

The reader's stable lstat-kind check is followed by a normal path open. The
contract assumes the existing cooperative private-work boundary; concurrent
same-user namespace replacement is not qualified. Root explicitly treated that
review question as outside this slice after reading the full specification.
Stable symlink and nonregular controls do not imply an atomic hostile-path open.

The two-second deadline is cooperative and cannot preempt blocked OS I/O.
`schema.open_readonly` executes initial metadata SQL before the progress handler
can be installed. The 2M-step bound covers subsequent fixed-table queries only;
the 4 MiB snapshot limit and checks around opening cover the earlier helper
within the documented cooperative boundary. The tool's preexisting full JSONL
read is unchanged. These limits and the reporter correction are appended to
`scope-clarifications.md`; the sealed original proposal remains byte-identical.

The tracked sibling manifest lists every archive payload's byte count and
SHA-256, the exact source chain and final archive identity. The archive contains
the original sealed design packet plus the full implementation chronology;
its verification receipt recounts all XML, checks original hashes and matches
the canonical source snapshots. No scanner rule, source suppression, workflow,
frozen outcome or native engine semantics changed.
