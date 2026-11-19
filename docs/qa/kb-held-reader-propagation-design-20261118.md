# KB held-reader propagation design receipt

This is a **read-only proposal**, not an implementation or a fresh runtime gate.
Frozen comparison: `bca79c2371dc674e1b66177e0396f10332dcf198`, tree
`aa51e77cc9946305592866a6385b63dfb7bcdc3c`.

[Concrete plan](../plans/kb-held-reader-propagation-20261118.md) and
[machine-readable scope](../plans/kb-held-reader-propagation-20261118.json) propose
only the existing KB service/wiring/attachment reader propagation. Root must
review the bounded production ownership and test-first contract before edits.

## Verified evidence

[Archive](kb-held-reader-propagation-design-20261118.zip): **72 members**,
**441,569 bytes**, SHA-256
`5bf8094a69a28256d0d0ee70c71c0eaf3ebd7fcd5e6f2e131ea29f557a46b1a8`.
Every member is hashed by the manifest; all bytes were read back and verified.
Forty exact Git snapshots and 51 complete symbol-span/signature proofs were
checked against the frozen commit. Three complete production caller searches
were replayed byte-for-byte. Five core files/spec are identical to reviewed
`9740860928c7911e6fa975528db1f7fa5ca1940b`; both worker files are identical to
`7259f86838c2181d6bdbcabe98c7a294a4499e8d`.

All 16 captured KB production files equal the prior design's `27e4318b` source.
Twenty-one original prior-design/probe/harness/result files are copied unchanged
and rechecked against their original paths. Its two-pass ordinary public-route
observation remains historical; the preceding two SSL/socket harness errors
remain fixture errors. Neither result is relabeled as current held-reader proof.

## Scope and limits

Proposed files: `kbcorrelation/service.py`, `wiring.py`, `store.py`. The same
operation pair would reach inspection, intent/create hashing and the existing
core create API. Ordinary injected call shapes, full-global saved-scope admission,
create-only/reuse policy and committed-project retention remain unchanged. A
neutral InputReadError needs an explicit pass-through at the current generic
creation exception wrapper; no new serialized capability or error text is needed.

The plan does not implement a package facade, native adapter, durable lost-lease
reconstruction or created-project reconciliation. Generic reader-less repair
and postcommit project-copy verification remain explicit later boundaries.
No product/native test, network request, target or package process was executed
for this design. No source, schema, workflow, remote, main or release changed.
Mechanical provenance counts are not feature coverage or acceptance percentages.
