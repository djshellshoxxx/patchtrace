# Formatter observations and completed Qt evidence — 2026-11-19

This checkpoint records a narrow diagnostic improvement at `16c35e1fb1a4dd54b2c2c0cb2033c8160ee99347` and the
final outcomes of the earlier published `771e5a775f5bf60a8d9094232b51dcdbb47d6389` Qt jobs. Main was last
verified at `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`. PR #304, #307 and #316 remain open and unmerged at the
preceding API checkpoint. No release, tag, deployment or manual dispatch occurs.

## Formatter result and preserved failure

Spec `fdc1f606dd0b8a3ce94ae2db94f4fb6984a02b69` precedes source `16c35e1fb1a4dd54b2c2c0cb2033c8160ee99347`. The authored C harness now records
`pt_diag_count` and one captured `ferror(stderr)` value if its original success
predicate fails. It still requires exactly 16 attempts and a nonzero stream error;
failure still returns 4. The passing path still emits no stdout. The fixed numeric
failure record is bounded below 128 bytes, and pytest retains at most 512 bytes
from each stream in its assertion message. No extra write to the failed stream,
stream-error clearing, fake sink or production formatter change is introduced.
The original Python assertion condition and every other test AST are preserved.

The reviewed file passes **9 tests, zero failures/errors/skips**, in 0.49 seconds
of pytest time (1.101 seconds for the outer recorder) at the exact source above.
All **40 project/tool imports** match Git and disk. The inherited offline filter
loads; there are no inherited sockets or network audit events. Seven process
audit events cover the reviewed authored compiler/helper scope. Changed-file Ruff
passes. The independent static review, complete commands, original XML/log,
collection, filter and source-equivalence recorder are retained in `evidence.zip`.

The actual old Windows W51 result remains exit 4 with empty streams. Neither
individual predicate value was present in that receipt. These nine portable
passes do not establish the Windows cause or a fix. The previous **2,043-pass**
combined gate belongs to source `1a9942a5c63ba707e8678cb2f6dcd1dc39c4afd2`;
the two counts are separate observations, not an additive total. Production,
tools and workflow bytes have not changed since that gate. The retained normal
lint success and strict **80 unchanged findings** remain the preceding source
observations; no security waiver or suppression is added.

## Final old-head Qt outcomes

| Job | Repetition scope | Final result | Completed UTC | Job elapsed |
| --- | --- | --- | --- | --- |
| 135175350753 | Windows, all selected files, five repeats | Cancelled; no full passing summary | 2026-11-19 00:19:44 | 7,208 s |
| 135175350919 | Ubuntu, shard 3 of 4, twenty repeats | Cancelled; no full passing summary | 2026-11-19 00:19:53 | 7,216 s |

Both belong to run 44409973351, remote head `771e5a775f5bf60a8d9094232b51dcdbb47d6389`, merge preview
`ac6632ad6de486ba16343f0eeb4a2b5a446e4ac1`, tree
`ddf151c6ff8fb3f70b74378525fe1d8d5c9050e3`. Equal-tree local source
`361dd495a7e050121f2b3cae4e7678faad7fee35` supplies the verified runner/workflow snapshots. Both files remain
byte-identical at the newer formatter source. The runner selects 82 GUI files,
sorts and shards them, and repeats them in one pytest session. Its outer workflow
job timeout is 120 minutes. The logs end with cancellation; the annotation lookup
was unavailable through the connector and its two errors are preserved. The
specific cancellation cause and any slow-test cause are not inferred.

All **48** old-head checks are now completed: **34 success, 5 failure, 7 skipped,
2 cancelled**. The two cancelled Qt jobs are unverified, and dependent Linux
package/smoke/release checks are skipped. The earlier 00:18:02 pending snapshot
is retained unchanged as a historical observation. There was no cancellation
request from this work and no manual workflow dispatch.

Same-tree full-suite JUnit timings are retained as diagnostic context: 2,120
Windows GUI cases total 2,246.171 seconds; multiplying that separate session's
case times by five gives 187.18 minutes. The four Linux shards' analogous
arithmetic totals are 72.66, 81.79, 70.17 and 47.21 minutes for twenty repeats.
These are **not predictions, measured repeated-run durations or passing repeat
receipts**. No repeat count, assertion, skip policy, timeout or shard layout has
been changed. Per-file timings and bounded slowest-case lists are in the packet.

## Remaining work and evidence

Windows fixture repairs and the actual core creation/ownership investigation
continue on separate branches. The strict pure package admission contracts are
being developed from their reviewed specification. The approved native leaf and
reader work remains queued. Full Windows/Linux/Qt/native/frozen/package/security
gates and real CVE/KB/analyst journeys continue to block main merge and beta
readiness. Diagnostic retention does not resolve the native digest mismatch or
restricted Windows descendant/network qualification.

The archive has **30 payloads**, plus its manifest, and **110,138 bytes**.
SHA-256: `c0114cbe0d060d293f9237009594e1b4a757e51a9eedd9c0d706a65e61bd5092`. Every payload was reread, length/hash checked and ZIP-CRC
verified. Original failure evidence is in the preceding
[integration checkpoint](../admission-diagnostics-integration-20261119/README.md),
whose archive SHA-256 remains
`ab11b8c014d5fdf0cfe94b2e29f661bd20974019f7c4f9a91151b7593dce4ece`.
