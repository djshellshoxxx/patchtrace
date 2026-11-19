# Advisory sidecar read bounds — 2026-11-18

## Confirmed issue and repair

At published PR #307 `58fc130631f602b6e907bb054d30c21d810551d4`, existing advisory reads and idempotent sidecar reuse called unbounded `Path.read_bytes()` before validating the digest. Seven regression controls failed, while digest-mismatch and symlink positive controls passed. Spec/test commit `7d0e8bac82c8624708932eaff723c246f878835c` precedes implementation `06f5b210e5c6daffaae2b4d51fd8950c28be25c3` (tree `564ce17da6e8d6fd9e15ad3b3fde16cd91f825bd`).

The store now uses the existing owned-file reader. Each read holds a regular file and its parent identity, bounds content allocation, validates the SHA while held and rechecks identity/change state. The default maximum is 64 MiB; raw recovery uses the recorded source size; reuse is bounded by the incoming object's exact size. Oversized normalized facts are rejected before writing any import sidecar or pointer. Verified facts-cache recovery and damaged-cache repair remain usable. No second platform reader was introduced.

## Verification and review

The author affected selection passed **140 tests in 11.88 s**. Required Ruff over `src tests tools` passed after correcting two import-only findings; the initial lint output remains retained. The independent reviewer reran the exact final source: **140 passed in 12.07 s**, then **11 independent filesystem controls plus five backup-sidecar tests passed in 0.85 s**. No skips occurred in those local selections. Source paths and commands are recorded in the independent archive provenance.

The independent controls exercise an actual sparse 64 MiB + 1 byte file with a correct digest and zero content reads, growth after the size check, identical-byte leaf/parent replacement, in-place changes, descriptor cleanup, FIFO/directory refusal, parent symlink and real cache repair with unchanged pointer rows. No blocking finding remains in that reviewed scope. Root read the source, tests and review, and independently verified all 13 archived members and the complete archive digest. Original red evidence is retained, not replaced by passing results.

[Independent review and limits](advisory-read-bounds-independent-20261118.md); [manifest](advisory-read-bounds-independent-20261118/manifest.json). Archive SHA-256: `361bc6154240dd9969ffdf803f09d6f565794dfd4dd6b262d19b03bfd1f89339`.

## Remaining gates

Native Windows filesystem behavior, actual final-head full suites and packages remain unverified. This bounds individual retained files; total advisory count, cumulative I/O, parsed-model memory, owner-thread responsiveness and broader publication races remain separate scopes. No native engine, target execution, source retrieval, research outcome change or release occurred. Main remains at the last observed `9c411ca3d7b47f950be5f0c6f01b3c54184554c6`; this is a focused follow-on PR on #307, not a merged production claim.
