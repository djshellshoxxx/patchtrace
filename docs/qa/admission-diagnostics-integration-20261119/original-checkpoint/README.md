# Workspace admission and diagnostic integration — 2026-11-19

## Exact decision

The independently reviewed source at
`1a9942a5c63ba707e8678cb2f6dcd1dc39c4afd2`, tree
`defbdfa98a6f61c1a355ad2a57b62dfe34994fc8`, passes the bounded combined replay:
**2,043 passed, zero failures, errors or skips, in 34.62 pytest seconds**
(36.602 seconds outer elapsed). It covers 64 complete selected files: 54
repository files and ten unchanged external probes, with 480 canonical
project/tool imports and 32 reviewed owner paths. Normal Ruff passes. The strict
security scan still exits 1 with the same 80 path/rule/selected-statement sites;
no finding is suppressed or waived.

The documentation parent is `f16d41062a5d558d889ef6a6bda922004e0ac3b4`.
It adds only the three-file unified diagnostic QA packet after the tested
source. Product, test, tool, workflow, specification, schema and configuration
bytes are unchanged between those two commits. The 2,043 result belongs to
the stated source; it is not a full-platform or release acceptance result.

Main remains `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. PR304 is
`d8c02caea407f6d323eecd636735849c1eb31a2d`; PR307 is
`58fc130631f602b6e907bb054d30c21d810551d4`, still stacked on PR304.
Published PR316 remains `771e5a775f5bf60a8d9094232b51dcdbb47d6389`.
All three are open and unmerged. No PR was closed, branch deleted, history
rewritten, main merged, tag/release created, or deployment performed.

## Reviewed changes now integrated locally

| Bounded change | Original source | Integrated source | Result and limit |
| --- | --- | --- | --- |
| Explicit existing-workspace admission | `c470a31a` | `0196dc4a` | Actual connection and supported v1 layout checked without application initialization; ordinary defaults retained. This is not a forensic guarantee of zero SQLite filesystem activity. |
| Protected workspace connection handoff | `a7a4fb16` | `3711b2d4` | Final `self.db` assignment remains inside the owned BaseException cleanup region. Original root two-red/one-positive trace probe is unchanged and passes. No universal asynchronous return-atomicity claim. |
| Trusted native stdin forwarding | `3d083102` plus import-only `49e2bf90` | `a28c37eb`, `4e086f10` | Three authored C files retain a verified original stdin object, make explicit fresh/forward selection and close outbound ownership before resume. Real portable scripted-API controls pass; actual Windows ABI, restricted descendants and isolation remain unqualified. |
| Tier R exit-one diagnostic retention | `4cdd463f` | `4c5cb091` | Unrecognized return-code-1 output remains a failed case with bounded diagnostics; a closed recognized-summary policy preserves existing findings behavior. Native causes and frozen research outcomes are unchanged. |
| Independent first/second unified diagnostics | `86aa905a`, `e3f07f76`, `adab5118` | `d5ecd296`, `4c1f8d42`, `1a9942a5` | At most four independently retained external reports, complete-or-explicitly-omitted records, fixed byte/count/work limits and fresh-interrupt propagation. Canonical digests, acceptance decisions, native invocation and frozen corpus are unchanged. |
| Exact shared reader import policy | `52a562b6` | `4c12b601` | Seven exact file/symbol exceptions and adversarial controls repair the known stale guard. Existing restrictions and old tests remain intact; no production import expansion. |

The preceding core ID/checkpoint/cleanup changes remain in this combined
source. Their original 1,200-check gate is historical and overlaps this replay;
the counts must not be added. All author/source histories, original failures,
peer packets and root review receipts remain immutable. The one documentation
append conflict preserved both bodies; there was no source conflict.

Root independently verified 427 workspace packet payloads, 526 stdin payloads,
59 Tier R payloads and 162 unified diagnostic payloads, including canonical
Git snapshots, import receipts, unchanged controls and phase-specific JUnit
counts. The archive contains the verification helpers and their retained
metadata-reader failures/corrections. Those failures are not product-test reds.

## Actual test execution and source binding

The retained command, selection and replay helper specify the full invocation:

```text
/workspace/scratch/3a6632a6e5ff/venv/bin/python ops/run_admission_diagnostics_integration_gate.py
/workspace/scratch/3a6632a6e5ff/venv/bin/python ops/scan_admission_diagnostics_integration.py
```

The first command used the inspected offline pytest wrapper, explicit candidate
PYTHONPATH, Qt offscreen configuration and fixed test selection. Its process
scope includes only authored local C formatter/scripted-Win32 controls and
inspected local Git/Python/fake-engine/heartbeat children. The inherited socket
filter was installed, no inherited socket descriptor existed, and the receipt
records only 810 `socket.gethostname` audit events and 201 process audit events.
No downloaded target, actual native engine, Windows ABI or network-containment
acceptance follows from that execution. The previously rejected broad runner
was not resumed.

All 408 protected original files and all selected-test hashes stayed unchanged.
The ten original external probes retain their exact bytes. One original unified
probe explicitly loads the tool from the preserved author worktree; that file's
SHA-256 `546c616adfb15fc132cb7124d8053c4bd2c4615adfe010caa0a724b1aa689730`
was independently pinned to the candidate before and after execution. This is
recorded separately from the 480 canonical imports; its loader was not patched.
The owned successful temporary test directory was removed after verification.

JUnit SHA-256:
`5fd7767b920a8bdaddca388dc8990d1fc5ccaf68991f03810c87fe15191247cf`.
The archive retains full commands, raw output, JUnit, collection/import data,
compiler identity, original probes, resource denial receipt and lint results.

## Complete branch and priority review refresh

REST pagination and read-only `git ls-remote --heads` agree on all **316 remote
branches** and **63 open PRs**. There are no new or removed branches. All 315
other heads are unchanged; only PR316 advanced from the previous fb09 census
to the already verified 771e publication. The 18 canonical GitHub commit headers
prove that linear advance. All 131 original focal tips remain exact.

The new machine inventory recomputes current head/main merge bases and preserves
the prior complete inventory, eleven followup dispositions and all seven
source-pinned semantic batches. Its conservative whole-branch classifications
are 114 already incorporated, 25 blocked by qualification, 25 documentation-only,
131 needing reconciliation, 15 research/quarantined and six valuable but
incomplete. A scoped retained feature does not erase unrelated branch residue.
Priority PR304/307/316 discussions are unchanged. Other discussions and closed
PR metadata remain the explicitly historical census, not a fresh all-PR review.

Thirty-three append-only remote commit objects have been prepared and each
canonical parent, tree and message read back. They end at remote object
`f1634bd6dfdce5dcbe4d73a482f46763e6f9abf8`, equal to local f16's tree.
The branch ref has not moved. Publication still requires a fresh head lease,
one append-only update, exact PR-body readback, and new main/preview/parent/tree
verification. These prepared objects do not carry hosted acceptance.

## Actual hosted evidence remains failed

The Windows full QA job at published 771e finished with **51 failed, 25,155
passed, 150 skipped and two expected failures**, plus 25 warnings, in 5752.39
console seconds. Root independently recounts **25,358 JUnit cases, 51 failures,
zero errors and 152 skipped elements**; JUnit time is 5748.985 seconds. The
separate publication step has 133 passes and four explicit skips and overlaps
the full suite. Windows Ruff, memory, frozen build/smoke, ZIP and installer
steps were skipped after the failure.

The exact head and merge preview share tree
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`; preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1` has main then 771e parents.
Root verifies the original 466,659-byte artifact, all three members, complete
connector-decoded log, 28 canonical source snapshots and every classified node.
Its retained diagnosis archive is
`22d8e0e7acb7014104d3f1c8457b05c5c95ba22e43e532ddbe05536381650d6c`.

Only three failures are the already repaired import guards. Twelve healthy
creation/retry paths are refused; the compared metadata values were not logged,
so the suspected descriptor/path timestamp mismatch is not claimed established
for those invocations. Thirty-two failures arise in platform-invalid fixture
operations, bytes, path models or lexical assertions. Four remain unresolved:
two tiny Git source fixtures, an unreached replacement hook and a formatter's
combined count/error predicate. The exact table and original failure text are
retained. No old result is relabeled as a newer-source pass.

The earlier Linux full run remains 25,292 passes, three failures, 60 skips and
three expected failures. Its import-guard cause and newer correction are separate
source-specific facts. At **2026-11-19 00:18:02 UTC**, 771e has 45 checks:
34 success, five failure, four skipped and two still in progress. The remaining
Ubuntu Qt shard3 and Windows Qt repeat jobs are unverified. The release gate
is skipped. The snapshot is not a claim about their later outcome.

The actual native containment run still failed before descendant creation with
restricted NUL-open error5. New stdin repair requires actual-source Windows
acceptance. The unified Windows digest mismatch remains unresolved; the new
diagnostic retention supplies evidence for its next run and does not repair or
waive that mismatch. Strict security remains 80 failed sites. Dependency-profile
evidence, complete packaging, native engines and real CVE/KB/analyst journeys
retain their own qualification limits.

## Next implementation and repair work

The first pure package-admission contract design and independent critique are
preserved. Root approved two persisted roots only, with strict finite envelopes,
exact-byte identity before the existing domain helper, detached worker parsing
at its original raw cap, own-grant accounting, original-deadline coherence,
materialized-limit binding and complete standalone reducer lineage. All 23
transitively embedded models have fixed fields and no opaque/mapping-valued
fields. Existing-helper observations are not tests of the proposed models.

A separate post-seal observation confirms actual core create/reopen revision
zero. The new observed project revision must allow zero while investigation
revision remains positive. The original positive-only draft and critique remain
unchanged, with that correction retained separately. The author owns the new
pure module, exact import controls and two-root schema generator on a branch
from f16. Store/CAS/provenance/recovery/native implementation stays separate.

The native leaf/held-reader proposal is independently source-verified and
approved for a narrow future slice: one owned file, an existing borrowed parent,
original locks and budget, independently rooted reader and explicit bounded
cleanup. It has no private-directory creator, worker transfer, decoder or
package route. Its implementation is queued while the Windows failures receive
priority; no native acceptance is claimed from the design.

Active repair ownership is split between CI fixture/normalization/Linux-inventory
work and core creation/replacement/held-reader ownership work. Root retains
formatter diagnosis, independent review, integration and publication. Specifications
and meaningful controls precede behavioral changes; original assertions, failed
receipts, frozen outcomes, strict limits and `[no release]` remain preserved.
Main merge and beta readiness remain blocked by the missing or failed gates.

## Archive integrity

420 verified payloads; 13,132,985 bytes. SHA-256 `ab11b8c014d5fdf0cfe94b2e29f661bd20974019f7c4f9a91151b7593dce4ece`.

The directly accessible `branch-inventory.json` is a compact index of every current head and disposition. The complete 12,907,552-byte inventory, including original semantic and patch records, remains unchanged in `evidence.zip` at `branch-refresh/inventory.json`. `compact_inventory.py` verifies that member before deriving the index.
