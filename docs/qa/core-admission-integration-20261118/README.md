# Core admission identity, checkpointed reads and initialization cleanup

## Exact candidate and acceptance boundary

Local source **a8f698f6a1d075b673bc6ec94c991141113d2b30** passes **1,200 checks,
zero failures, errors or skips, in 17.85 seconds**. The reviewed selection contains
39 repository test files and six unchanged external probe files. All **434**
imported project/tool modules and **21** reviewed source/test/specification paths
match canonical Git bytes. The complete command, selected file hashes, source
manifest, JUnit, output and observations are retained. Full normal
`ruff check src tests tools` passes. The isolated strict S scan exits **1** with
**80 unchanged path/code/selected-statement findings**. Their earlier manual
dispositions remain evidence; no finding is suppressed or waived here.

Later commits through documentation parent
`cf5f7301c735c6b6ca1c0d64242804bfb432dfa1` add evidence and read-only proposals.
Product, test, tool, workflow, specification, schema and configuration bytes
remain equal to the tested source. This is an affected-scope gate, with actual
SQLite and authored PE/portable-C fixtures. It is not the complete platform,
native, packaging, security, reproducibility or analyst journey acceptance.

Fresh GitHub readback retains canonical main
**9c411ca3d7b47f950be5f0c6f01b3c54184554c6**. PRs **304, 307 and 316 are open and
unmerged**. PR307 remains stacked on PR304. The current published PR316 head is
`771e5a775f5bf60a8d9094232b51dcdbb47d6389`; this local checkpoint has not yet
been attributed to a new remote head. Main merge and beta classification remain
blocked. No branch deletion, force-push, tag, release or deployment occurs.

## Reviewed implementation

The initial core source is `441c47c2262603555aa77c11e63fedcce11ba502`, after
specification/tests `cb26b38de018612e76f87c544fb8b1dfe70acbf2`. It changes two
existing files, `service.py` and `persistence.py`, without a schema migration:

- Optional creation identity is validated with the existing strict Record ID
  contract before store/source access. The real first committed project receives
  that ID. Omission preserves default UUIDs and existing injected call shapes.
  An expected ID does not authorize reusing or deleting an existing project.
- Explicit `recover_interrupted=False` and `maintenance=False` permit committed
  reads without application recovery/maintenance mutations. Both flags are
  needed. Existing default behavior stays enabled, and lock bookkeeping still
  occurs. This is not a forensic SQLite read-only mode.
- An optional original read checkpoint flows through snapshot/aggregate checks,
  existing copy/raw/PE verification and interrupted-run recovery save. Actual
  positive reads are charged; cache checks use zero. The callback is not retained
  or called after recovery save commits. OS/SQLite work remains cooperative.
- Once store construction returns, failed open closes its acquired store on
  ordinary errors, neutral stops and BaseException. A secondary close error
  adds a fixed bounded uncertainty note while preserving the primary exception.

Root then independently demonstrated a constructor boundary that precedes that
open handler. The follow-up specification/tests are
`f40d14c1970bf45efba4de448c00c8c49b463ae7`; corrected source is
**63ebc42746fbfbded311084288a339f26ed08d8c**. Only the existing constructor
exception handler changes, 14 insertions and 10 removals. It catches interruptions
and preserves primary error precedence while retaining the existing connection
close, positively owned new-file discard and final store-close order. The ordinary
SQLite-to-storage ValueError mapping and cause remain intact. Cleanup uncertainty
is reported without raw secondary paths/messages or a claim that cleanup succeeded.
Generic close, the discard helper and file ownership/deletion policy are unchanged.

Actual creation controls preserve new/zero-byte/current-empty database retry
semantics, committed projects and foreign analyst files. Unknown outcomes after
commit retain their project and copies. None of these hooks supplies durable
package intent, lineage, expected-ID association policy or lost-lease recovery.

## Preserved failures and independent evidence

| Boundary | Original evidence | Corrected evidence at its own source |
| --- | --- | --- |
| Acquired-open interruption and secondary-close masking | Unchanged five-case probe: 4 failures / 1 positive; committed core regressions: 41 failures / 6 positives | Initial source: 47 focused and 512 affected passes |
| Constructor interruption before the store returns | Root actual SQLite probe: 2 failures / 1 neutral positive | Same original three controls pass in the corrected focused, affected and root integration gates |
| Secondary constructor cleanup masking | Additional six-case probe plus original root cases: 6 failures / 3 positives | Corrected 50-case focused scope passes |
| Complete additional constructor regressions | Spec-first scope: 31 failures / 19 positives, zero setup errors/skips | Author affected scope: 562 passes, zero skips, 463 canonical parent imports |
| Integrated core/KB/encoding/portable diagnostics | Same six external probes and selected repository assertions retained | Root: 1,200 passes, zero skips; all source/test/owner hashes exact |

The original first implementation's normal Ruff import-format error and first
affected runner's **510 passes / 2 policy refusals** remain immutable. The runner
omitted two existing headless Python commands; its corrected version admits only
the inspected commands while retaining exact interpreter and source pins. That
correction changed no product source or assertions. All five existing headless
children are documented; the author audit records parent events, not every child
syscall/import. Original failed-run fixture directories and raw observations are
retained. Successful owned temporary trees were removed only after validation.

Root independently verified the first 136-payload archive/54 canonical snapshots
and the separate 140-payload constructor archive/49 canonical snapshots, all
source-pinned import records, JUnit totals, original probes and unchanged test
bytes. AST comparison proves that only the existing constructor handler changes
in the second slice. The first archive is byte-identical in the follow-up.

The root gate uses the reviewed inherited network-denial filter and file-only Git
transport before collection. It records 810 hostname events, 121 process events
within the inspected fixture/CLI/compiler scope, and no socket operation. Only
authored portable formatter code is compiled/executed. No retained target or
Windows image is executed. This safeguard is not product containment evidence.

## New actual Windows evidence at published source 771e

These are hosted results for the preceding published tree
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`, not native execution of the new local
core source. Root independently verified all three original artifact ZIPs,
206 members, ten canonical source snapshots and three exact decoded job logs in
the sealed 245-payload Windows packet.

**Dependency encoding is now verified in actual Windows jobs.** Canonical push
run `44409963273` completes runtime job `135175146507` and packaging job
`135175146843`. Each profile has 22 successful process receipts with
`-I -X utf8`, exact output hashes and no timeout/output-limit error. Actual UTF-8
U+1F44B bytes survive the scanner inventory. Runtime audits 17 distributions;
Windows packaging audits 34. Raw installed inventory, separately proved
repository-owned distribution, requirements and audit sets agree exactly. Pip
26.3 is included; pip-audit is 2.10.1. Bootstrap issuer 25.0.1 remains separately
recorded. Both audits have zero vulnerability, skipped-distribution and fix rows.
The original external/native/frozen/scanner-tool exclusions remain explicit.

**The new Windows C diagnostics compile and identify a failing boundary.** Run
`44409973491`, job `135175184142`, artifact `14475538670` has an advisory success
badge but actual pytest failure and `no_network: failed`. All three C source
hashes equal the reviewed diagnostic source. Nine bounded records show four
loopback timeouts, external TCP 10013, then restricted `nul-open` Win32 error 5
and `child-spawn` error 5. The source opens NUL before CreateProcessW; no
descendant process creation is reached. The outer launcher records exit 125,
no timeout and an empty tree. Aggregate incomplete-flow cleanup remains distinct.
Six other fixture subchecks pass. Timeouts still do not establish denial; full
restricted descendants, adapter and lifecycle acceptance remain unqualified.

## Additional unified-native failure and pending checks

At **2026-11-18 22:37:08 UTC**, published source 771e has 32 successful, three
failed, four skipped and six still-running check records. Six Linux/Windows QA
and Qt jobs remain incomplete; their artifact collection is
empty at that snapshot. One Qt shard is complete. The release gate is skipped.
No missing, pending or skipped check is credited as acceptance.

The new non-static failure is unified Windows run `44409973392`, job
`135175184056`. The CI fixture step passes; the probe-pair newer side fails the
extractor's L1 determinism assertion. Two analyses of the identical fixture yield
`a658ef9f00c21c74bac115a68414f8188206258c051a9c3ea9c484e0d0e65c0c` and
`b7dc355b73b3482f82fff8c81ba8d32e51e285a357dc39ba96ba0f6bcf3bf936`.
Their ir_key agrees. GZF/Ghidriff comparisons to the first run pass; those results
do not replace the failed repeated-analysis assertion. Downstream Linux is skipped.

Artifact `14477506098` retains two first-run summaries and four authored DLLs.
All four input hashes, four first-run digests and six traced checker/extractor
files equal the earlier fb09 evidence. Only the JSON summaries are materialized;
the DLLs remain inert in their original ZIP. The second-run/function records are
absent and the checker removes its work directory. The actual divergent field
and native cause remain unknown. A bounded diagnostic-retention proposal is
assigned, with no change to canonical digest, engine or acceptance rules.

The separate frozen fb09 Tier R packet preserves five of eleven completed Linux
rz-diff pairs and the six no-functions outcomes. Its source-pinned injected-runner
probe confirms a reporting defect: unexpected exit 1 with no valid summary loses
its diagnostic classification/stderr. It records two expected failures and two
positive controls, 38 exact imports, and no child/network execution. This does
not prove the original Windows child cause or a cause for the six Linux misses.
Original corpus outcomes remain unchanged.

## Durable package design and next source boundary

The read-only design at `efe68b18` and QA `988ce3f7` are integrated. Root verifies
93 archive members, 42 canonical source snapshots, 56 complete symbol spans,
11 prior-source equalities, five exact caller searches and 16 preserved prior
files. Its seven authored SQLite observations pass with 32 exact imports.
An already-open v1 client can still write after a v2 stamp, so every held-package
phase is proposed outside legacy journal enumeration. New recovery must inspect
bounded coherent package state before marking any ordinary interrupted work.

The proposal binds immutable intent/expected UUID before creation, checks actual
project ID and side-keyed hashes before sidecars/rows and on every later open,
uses selected-row idempotent provenance, and limits explicit reconciliation to
one already committed project. Original readers, deadline and budget remain live
through admission. Stored IDs, hashes or paths do not reconstruct a source lease
or grant cleanup authority. Whole package exposure remains absent.

Independent review adds one demonstrated prerequisite: ordinary
`WorkspaceStore(create=False)` initializes existing zero-byte or unrelated v0
databases. Its unchanged four-case probe records **2 failures / 2 positives**,
31 exact imports. These failures challenge a proposed capture assumption; they
do not redefine ordinary workspace behavior. An explicit non-initializing mode
must validate the actual connection before schema initialization/WAL configuration,
preserve defaults and close acquired resources on refusal. New controls must
exercise that explicit mode; the original counterexample must not be disguised
as passing by altering ordinary defaults or injecting a wrapper.

Root accepts the review's first-slice bounds: acyclic strict canonical identities,
finite metadata caps, coherent phase/body/index binding, atomic table/first-intent/
version transition, current/captured/source CAS within the writer transaction,
stable intent-specific provenance guard and exact historical-row reuse. Source
implementation requires its own specification, meaningful failures and review.
Native FDI, stage identity, worker transfer and Windows package journey remain
separate prerequisites. Design and observation passes provide no implementation
or whole-feature completion credit.

## Repository continuity, cleanup and active assignments

The prior publication's 18 appended remote commits, exact trees/parents, final
non-force ref lease and body/merge-preview readbacks are retained. The current
priority heads are PR304 `d8c02caea407f6d323eecd636735849c1eb31a2d`, PR307
`58fc130631f602b6e907bb054d30c21d810551d4` and PR316 771e. Their main/stack
relationship remains unchanged. The previous complete 316-branch/63-open-PR
inventory remains separately sealed; this checkpoint performs a priority-head
refresh and does not pretend to be another complete branch census.

Four completed clean checkouts were removed only after root verified 16,505
tracked files and archived 1,144 non-bytecode test-support files. All branch
heads remain unchanged. The receipts and 749,190-byte support archive are
retained. Active worktrees, dependency environments, unknown-provenance temporary
files and failed test evidence were preserved.

Core hooks and both cleanup corrections are independently integrated. KB owns
the actual-connection capture seam and later strict durable contracts. CI owns
the trusted stdin handoff design and actual Windows qualification; handle type
alone cannot prove NUL origin. The independent reviewer owns bounded unified
first/second-run diagnostic retention. Root owns source review, exact-candidate
tests, evidence, branch reconciliation and append-only publication. Tier R
diagnostic repair remains eligible after the higher-priority native blockers.

Main merge, full CVE-to-function and analyst journeys, native accuracy/calibration,
Windows containment and package staging/FDI, full platform/Qt, frozen ZIP/installer/
Linux packaging, dependency lock closure, strict security and reproducibility
remain required. Percentages in the matrix count named D/R/J/G milestones for
their stated scope. No whole-project beta readiness follows from this checkpoint.


## Checkpoint environment error and verified space recovery

The first seal attempt stopped at its destination-directory creation with
`OSError: [Errno 28] No space left on device` (tool chunk `a1493b`). No archive or
repository change was written. Its helper and input note remain byte-identical;
the v2 helper adds this recovery evidence only. The tested source, tests, limits
and acceptance results are unchanged.

The coordinator then verified seven completed, clean, branch-backed worktrees:
cvrf-pilot, inventory, object-publication, release-qualification,
security-contract-triage, tooltip-review and integration307. All 28,491 tracked
files matched their canonical Git blobs before removal. The support archive
retains 1,545 non-bytecode ignored files with per-file hashes and a verified CRC;
only reproducible Python bytecode was omitted. The three active agents confirmed
no ownership or pending process in these paths. The process scan covers the
current execution namespace, supplemented by those explicit ownership checks.

All seven checkouts were removed with ordinary `git worktree remove`, without
force. Every branch ref remains at its original exact SHA. This removal's own
measurement increased available bytes from 1,205,018,624 to 1,705,549,824. The
dirty cve-review worktree, active checkouts, failed-run evidence, dependency
environments and unknown-provenance files were retained. The complete cleanup
packet was copied from its owned temporary stage and independently checked for
byte equality, branch retention, ZIP integrity and every support-file hash.
The temporary stage remains available. This recovery is separate from the four
earlier completed-checkout removals documented above.

## Archive integrity

139 verified payloads; 10,539,029 bytes. SHA-256 `c3ad78f56976be2b5c96f30061f6a10262c1a22b16dd4bfc06f1a87452cce4e7`.
