# Portable worker, held core input and signal navigation checkpoint

## Exact candidate qualification — 2026-11-18

Clean candidate `207eea9d4e125ac1d371139d4db803ddbc2b4c8a`, tree `29065e36f19ed4e3b0df73d80c8e16cabba1ce6f`, passes **1,103 tests**,
with **one native Windows skip**, zero failures/errors/expected failures, in
**44.57 seconds** (46.26 seconds including coordinator verification). The
51 selected files contain all three affected author scopes, five publication/
packaging neighbors and four unchanged independent probes. All **498** loaded
PatchTrace modules match this commit's Git bytes; all **23** changed source,
test, tool and schema files since `9f4e1a57dc75de8d34ef9023bea2fb7619690f0b` match reviewed owner bytes.

Normal `python -m ruff check src tests tools` and
`python tools/generate_package_schemas.py --check` pass. The isolated strict S
scan, with ignore-noqa and no suppression, still exits1 on **80 unchanged
path/code/selected-statement sites**. This milestone does not close that gate.
The sole skip is native Windows junction creation; the duplicate-ZIP fixture
produces its expected warning. Full/platform/native/package/security acceptance
and beta readiness remain open.

## Reviewed changes

| Scope | Implemented behavior | Reviewed source and acceptance boundary |
| --- | --- | --- |
| Serial package worker grants | Strict operation/request/attempt/source bindings, fresh nonce and canonical grant digest, bounded wire size, explicit envelope version, cumulative feasible counters, one outstanding grant, original deadline and quiescence, atomic receipt validation, permanent failure on missing/malformed receipt. | `7259f86838c2181d6bdbcabe98c7a294a4499e8d`; portable records/accounting only. No worker launch, native handles, package intake caller or project admission. |
| Held core inputs | Qt-free optional path-bound readers, bounded read/PE/hash validation without source-path fallback, original error propagation, checkpoints during owned reads and immediately before the first-save COMMIT, preserved ordinary call shapes. | `9740860928c7911e6fa975528db1f7fa5ca1940b`; held provider owns source-read accounting and native identity. No KB propagation or native provider in this slice. No callback after committed save can enter creation rollback. |
| Signal navigation | The existing GUI action uses the unchanged live location validator before reveal and refuses unsupported representations through a 19-line helper. Current mode/cursor/evidence remain unchanged on refusal; valid decompiled navigation is preserved. | `9592f8b362537c0545010d4499e35770a248297e`; persisted/reopened Linux offscreen controls. Validator, detector, scoring, schema and enrichment storage behavior unchanged; existing UI line ceiling remains3077, current3069. |

Three defects reproduced during independent review were corrected with tests
before source changes:

1. A terminal worker receipt prevented later admission but still allowed
   `complete_output` to mutate counters before raising. The correction refuses
   both complete/fail callbacks before token or counter mutation. Original
   independent **2-failed/3-passed** evidence remains; preterminal late-cancel
   accounting and allocation cleanup remain valid.
2. Temporary stage unlink failure could replace the original held-input
   cancellation. Cleanup now preserves the exact primary exception and adds a
   fixed bounded possible-retention note. Successful-path cleanup failure still
   raises. Original independent **1-failed/51-passed** evidence and new
   **6-failed/15-passed** regression remain; independent corrected replay is
   **52 passed**.
3. Validating a stored assembly location was insufficient when the action
   always displayed decompiled text. Original root **1-failed/1-passed** evidence
   and author **4-failed/11-passed** controls remain. The helper explicitly
   refuses unsupported representations while preserving current decompiled
   behavior. The original stale-location **3-failed/4-passed** probe also passes
   unchanged in this integrated candidate.

The coordinator verified all author archive member hashes, canonical Git
snapshots, original independent files and source boundaries. Worker/core
first-source packets, correction packets, all navigation fixture/line-ceiling
failures and corrected receipts remain immutable at their original sources.
Counts from overlapping invocations are not added into coverage percentages.
Original 28 independent cases are replayed directly from unchanged files;
only observation destinations are routed to new directories, with their
original observations protected by hashes.

## Execution and preparation evidence

The reviewed offline guard installs network denial before test collection,
rejects inherited sockets and restricts Git to local file transport. The audit
records410 hostname events and11 inspected local fixture/import subprocesses,
with no network socket operation. An owned temporary directory outside any
Git repository was removed only after success. This guard is not a claim of a
qualified native product sandbox. No native or target binary was executed.

An initial coordinator scope assertion stopped before collection: an extra
existing publication-neighbor test had not belonged to the preceding CI gate.
The original helper and observed preflight failure are retained. That small
file was reviewed directly and kept in the scope; no test or assertion was
removed. The corrected harness distinguishes the four previously reviewed
neighbors from this additional direct review.

The complete command, selected files, environment, source ownership, collection,
JUnit, normal lint, strict scan, schema check, audit and post-run preservation
receipts are in this archive. The combined command uses the retained
`continuation_offline_pytest.py`, `full_batch_receipt` and unchanged
`phase2_observation_redirect` plugins, `QT_QPA_PLATFORM=offscreen`, explicit
candidate PYTHONPATH and an owned system temporary directory.

## Retained design and reconciliation evidence

The nine-family Phase2 reference disposition, dependency-installer map and
native package seam design are integrated as evidence/design records. They do
not implement wire compatibility, statistical calibration, hash-lock closure
or native package support. All131 original focal branch tips retain a
disposition; this does not close whole-branch residue or research work.

The prior KB held-reader/durable-linkage proposal is now independently checked:
49 payloads,27 exact source snapshots, frozen source27e4318b. Its two corrected
real-service authored controls demonstrate current path opens and the
after-project-create intent gap; the initial two fixture failures remain.
The next approved work is narrow propagation through existing KB/core services.
Native stage/FDI/process transfer, read-work accounting and durable package
provenance/reconciliation remain separate implementations and acceptance gates.

## Repository, prior publication and hosted state

At `2026-11-18T21:29:19.946Z`, main is `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` and PR316 remains open/unmerged
at `e78788791f03bd27b68e5891cd75ff0856b86342`. Its tree `a389462c90ad84960ad2c7ae26217baa83a92bcc`
equals local `9f4e1a57dc75de8d34ef9023bea2fb7619690f0b`. The preceding13-commit append-only publication,
exact remote object/ref readback and merge-preview parents are preserved here.
The prior CI gate remains1,028 passed/two skips/one known CODEX5 xfail at its
own f3b7a0e8 source; it is not relabeled as this new candidate.

Fresh metadata lists45 check runs for e787: full Linux/Windows QA and repeated
Qt jobs are in progress; Windows dependency inventory and strict security jobs
fail. Other success badges do not establish artifact or native acceptance.
Earlier independently hashed f3 artifacts retain the CP1252 inventory failure
and restricted native process-chain exit125. Read-only diagnosis identified
socket timeout errors and a separate unresolved descendant boundary; timeout
is not reclassified as network denial. No manual Windows/native/paid dispatch
has been requested and no native artifact was executed locally.

PR304 and307 remain blocked by actual-candidate full, Windows, native, package
and security gates. No PR is merged/closed and no branch is deleted. No main,
release/tag/deployment mutation occurs in this milestone. All24 local source/
design/QA commits retain `[no release]`; subsequent remote publication and
readback are separate receipts.

## Next workstreams and release limits

- CI owns bounded stderr diagnostics for the failed native chain, preserving
  every containment/permission/refusal decision; actual Windows build/runtime
  acceptance remains pending.
- Security/review owns an exact-source, spec/test-first Windows inventory UTF-8
  invocation correction, preserving isolated mode and raw strict JSON/exit
  validation. Native hosted replay and dependency hash closure remain required.
- CVE/KB owns the narrow held-reader propagation design and then approved
  existing-service implementation; saved-scope/global index/revision/approval
  checks and caller-thread SQLite remain required. Postcommit durability is
  separate, and expired native leases cannot be resurrected from pathnames.
- Root continues independent review, exact-candidate integration, branch/PR
  disposition and publication. Full current-source qualification and remaining
  analyst/CVE-to-function journeys remain incomplete. Frozen L1/L2/L3 outcomes
  are unchanged; no synthetic test supplies real binary accuracy or calibration.

## Sealed archive

132 verified payloads; 943,483 bytes. SHA-256 `afa877d8bf7c413121d65e8194b97adaecc34fd1983ae64778e75565f12b68f2`.
