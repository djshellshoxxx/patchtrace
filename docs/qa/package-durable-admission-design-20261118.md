# Durable held-package admission design — source and observation receipt

**Read-only design; production and repository tests are unchanged.**
Frozen product source is `195e04af27f7a724c6a2037363b7fe68df418a6b`, tree
`b976c61b0ac4ffb55b7b0e78d7a2b206742c00b1`. The reviewable
[proposal](../plans/package-durable-admission-20261118.md) and
[machine index](../plans/package-durable-admission-20261118.json) are committed
at `efe68b18654459e704d358d64423fbc1820afc0a`.

## Retained packet

[93-member archive](package-durable-admission-design-20261118.zip) —
461,545 bytes; SHA-256
`156c93ba411214921694e865a7615e0f9357b2d43ffbd82348cf65dfb58dec82`.
The [outer receipt](package-durable-admission-design-20261118.manifest.json)
records archive/source/design identity and verification counts. The ZIP's
`manifest.json` gives each member's exact size and SHA-256; its own SHA-256 is
`7ba6aa764f17a13b02b91e8e73eedb18a097d828df26ea84713deda69c2afa42`.

The archive contains 42 exact current Git snapshots, 56 complete source spans,
11 byte-equality checks to reviewed core/KB/worker sources, five original and
replayed caller searches, 16 unchanged prior design/observation files, the
frozen proposal, the new observation and all verification scripts/results.
`source-provenance.json`, `source-seams.json`, `verification.json` and the two
correction records distinguish source authority, historical evidence and
artifact-verification changes.

## Current-source observation

The one new invocation ran seven authored Linux SQLite behavior controls:
**7 passed in 0.35 seconds**, zero failures/errors/skips. All **32** imported
project modules match the exact frozen Git bytes; no network or child-process
attempt occurred. Exact argv/environment/import comparisons are in
`workspace-version.command.json`; original log, XML and observation JSON are
alongside it. Test source SHA-256:
`f7a0cdcf8d079068f39a34ccca17adb11c72c2594c88535db7e03310bf078a5c`.

The decisive observations are:

- A freshly opened higher-version workspace is read-only to the inspected
  current client, and its generic repair refuses before attempt/project calls
  in the quiescent fixture.
- A v1 WorkspaceStore already open when another connection stamps v2 still has
  `read_only=False`. It can write, and its marking code ignores held-looking
  fields added to an ordinary journal body.
- A separate additive package table is absent from that old journal enumeration.
  This isolates package recovery state without claiming to prevent every old
  connection from changing ordinary workspace state.
- An authored transaction rolls back its new table, first row and version stamp
  together; ordinary v1 writes remain possible afterward. No production
  migration was implemented by this observation.

These are current-behavior results, not passing acceptance for the proposed
facade. The original marker-plus-version design assumption is explicitly
corrected in `interpretation-corrections.json`. The final proposal keeps every
held attachment phase outside the legacy journal and requires a new-code guard
before `mark_interrupted`, including direct and mixed-workspace callers.

## Source conclusions and review gate

The inspected attachment operation ID lacks package intent/expected identity;
its ordinary receipt can fall back to expected hashes; its sidecars precede the
project row open; and its reducer reads the then-current investigation revision.
The proposal therefore binds immutable intent before create, requires actual
ID plus side-keyed hashes, verifies a held existing-service association before
sidecars and rows, uses exact selected-row provenance compare/reuse, and limits
reconciliation to one already committed expected project under current and
captured saved-scope/revision CAS. Committed, foreign and unknown outcomes remain
retained and distinct. Stored hashes/identities cannot recreate a source lease
or authorize cleanup.

The core identity/open/load additions are absent at frozen `195e04af`. Later
owner/root-reported source `441c47c2` and constructor-cleanup follow-up
`63ebc42746fbfbded311084288a339f26ed08d8c` remain subsequent dependencies;
the latter's exact diff is retained. Their reported 562-case author result is
not rerun or added to this packet's seven observations.

Root has assigned independent design review. The new schema/table, strict
metadata caps, package mode, recovery guards, provenance and reconciliation are
still proposals needing specification, genuine red regressions and separate
source ownership. No CLI/UI/native entry is exposed and no package schema is
generated here.

## Artifact-only correction and limits

The first seal verifier stopped because it required a replayed `rg` output to
have the original traversal order. All five complete filename/line/text match
multisets were unchanged. The initial verifier and exact tool-returned traceback
are retained. The corrected check preserves both raw outputs/hashes and compares
sorted full multisets without dropping duplicates. No source or observation
assertion changed, and the product observation was not rerun for this correction.
Final archive/source/span/reference/import checks all passed.

Documentation diff checks pass. A full product/Ruff/platform suite was not run
for this documentation-only design. Native original-lock sharing, rooted opens,
FileIdInfo, FDI, child/Job handoff, cleanup and the frozen package journey remain
separate qualification gates. This receipt grants no release or whole-PW-02
completion credit.
