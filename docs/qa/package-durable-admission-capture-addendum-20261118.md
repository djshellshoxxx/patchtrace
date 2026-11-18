# Independent capture prerequisite — attributed design correction

This append follows design `efe68b18654459e704d358d64423fbc1820afc0a` and sealed
QA `988ce3f746fe65bc022b4f3a6c1f2234989ec985`; neither original commit nor its
93-member archive was rewritten. Production remains unchanged at frozen
`195e04af27f7a724c6a2037363b7fe68df418a6b`.

`report_evidence_review` independently traced the proposal and authored the
capture probe. The [unchanged independent packet](package-durable-admission-independent-20261118.zip)
contains 45 payloads and is 185,510 bytes. SHA-256:
`ab2e7ecb8e44f6c78c0f8af76c7bdb6bdf1f93a8ca41c23f20f680d86a49c2af`.
Its [original manifest](package-durable-admission-independent-20261118.manifest.json)
retains all member sizes/hashes; this author verified every payload against it.

The original four-case result is **2 failed / 2 passed**, no errors/skips,
0.34 seconds. All 31 project imports match frozen source, with no source drift,
network or child attempts. Existing zero-byte and unrelated SQLite-v0 databases
were initialized/stamped1 despite `create=False`; their bytes changed while the
analyst file remained intact. Initialized-v1 and missing-file controls passed.

The original probe SHA-256 is
`823117ef4d6886ceebe747020aece47cc07f4758c7c94217cbdec31394a8e2d3`.
It and `capture-red.*` remain unchanged under
`qa/package-durable-admission-independent/`; failed fixtures remain at the
reviewer's recorded system-temp location. No additional product invocation was
run for this attribution/copy verification.

The failed assertions challenge the design's promised capture precondition.
They do not show that ordinary `create=False` violated its documented behavior.
That behavior must remain: the new optional non-initializing mode needs its own
spec-first controls, with ordinary zero/v0 initialization as explicit positives.
The original probe is not to be rewritten, wrapped or relabeled as a passing
regression after the additive mode is implemented.

The [design addendum](../plans/package-durable-admission-20261118.md)
now requires actual-connection validation before initialization or WAL setup.
A separate path check alone cannot close a replacement interval. The proposed
mode is limited to existing WorkspaceStore mechanics; no package schema,
provenance, recovery, facade, CLI/UI or native implementation is authorized by
this correction. Root reviews the precise signature/policy/ownership next.
