# Recovered work — exhaustive consolidation

## Checkpoint identity

Integration branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Draft review: [PR #320](https://github.com/djshellshoxxx/patchtrace/pull/320).
This record describes source through local `7dfba50f`; the first remote checkpoint
is `188b4962e527c82b29e599f75cd952029b749348` (tree
`07ba32f4c80d2d36597879c415fabf0ce3f3a854`). Later checkpoints must update the
handoff before claiming their changes are remotely preserved.

## Accepted contributions

| Contribution | Exact source | Integration and behavior |
|---|---|---|
| Reviewed #319 work | `a56ab13aaf9916fc12bea70ba1494075991b7f09`, `consolidation/patchtrace-reviewed-20261119` | Preserved on top of main `fdc2696c23bdbfe7668348f25e3b336ce33039f7`: scoped profile/raw alignment, search, advisory, CVRF and publication fixes. Broad regression qualification remains separate. |
| #316/#318 recovery stack | `f2b6827fc6270b96fb241b0722f2878de5a17361` and `c4ace2088ce8dc9ce78a0bf3036b81096accbdb5` | Entire stack ancestry preserved with #319 in a two-parent integration checkpoint. Includes core/adapter ownership, scoped KB behavior, portable native diagnostics and Windows fixture/toolchain work. Eleven conflicts resolved explicitly. Historical passing receipts are retained as historical receipts. |
| Tier-W offline CLI | `ce02504a266929a2648297a6f4d488523b3c48f1`, `bff635ffab2a5900ac3086bac9bac782cc52bfd2` on `claude/autonomous-finish-20261104` | Catalogue import, pairs, offline fetch preview, MSF symbols, labels, evaluation, status and guard; strict JSON result and explicit blocked stages. Unknown exports remain unknown. Invalid ratios and foreign matches are handled conservatively. |
| Calls graph layout | `6e1e153bd90b251b81b9cc919b0cbbb7f1d8d9ac`, selectively ported as `02055acb`, integrated `77204ef5` | Bounded deterministic ego layout is wired through the existing worker to the canvas. Cancellation, seed retention, font scaling and input/output caps are tested. Table/tree/DOT behavior remains available when layout declines. See `CALLGRAPH_LAYOUT_RECOVERY.md`. |
| Tier-W runner library | `c1a46beb46a8cd100c262d9e2143c47c0a892f3b`, integrated `edb6f20f` before publication | Explicit engine/condition cells and strict `RunRecord` contract. Imported implementation was audited before exposing execution through the CLI. CLI run remains blocked at this checkpoint. |
| Failed SQLite constructor ownership | `63cc10d4bb892214d12cf715cf33f039a6fe5d42` → `ebff6bab` | Close acquired SQLite connections on initialization, WAL, read-only reopen and root failures without masking the primary failure. |
| Schema and transaction rollback failure preservation | `82a58748bcd40f7b34dd20936124b797faf69dfa` → `dd3efbeb`; `644f4ab6bfce46561f0826dcfa059349ba0bfc3c` → `b8315a29` | A secondary rollback failure no longer replaces the original initialization, write or commit error. Caller-owned connections remain owned by their caller. |
| Export/publication ownership repairs | `dcfc7e8158d897a3cd30b6d5880ac357781378b1`, `5a448d06cd988e06fd819c0ef224cddb6916589c`, `9680379522654bd3c2234d5f8149cdcd3e59e524` → `4bb7c25f`, `c4585021`, `708b670c` | Explicit Windows replacement semantics; anonymous Linux staging and held parent; bounded length/hash/stable-descriptor verification before crediting a receipt; cleanup errors associated with the active operation. The remaining Linux force source-name race is documented in `SECURITY_REVIEW.md`. |
| Tier-W bounded and owned input admission | `811713a9` | Real calendar dates, corpus ownership, binary/producer symbol-map ownership, all-map admission before label writes, audit/aggregate validation before evaluation publication, bounded regular-file descriptor reads. Generated `RunRecord` schema and drift test updated. |
| Runner provenance and output admission | `d3fe7f652cad96389085a5a3309bb1294a6cde4d` → `ac41813f` | Only eligible completed rows with matching backend, inputs and symbol condition may be reused. Prevents aliases to binary/project/run summary paths, duplicate IDs and empty engine selections. Old rows lacking provenance become blocked. Cancellation and paired output preservation remain in progress. |
| Exhaustive structural census | `e65ce7b7` → `7dfba50f` | 319 branches, 59 tags and 309 PR heads, with per-branch disposition and exact machine evidence. Frozen semantic baseline is `77204ef5`; later repairs are not retroactively credited. |

## Publication equivalence

Public Git fetch works, but this environment has no Git push credential. The
first checkpoint was published through GitHub Git-object REST operations. Its
tree was required to equal the local `edb6f20f` tree before moving the new branch.
Commit metadata differ; source files do not. The remote commit keeps both stack
parents. The local source history remains at
`checkpoint/exhaustive-local-source-20261119`. Subsequent updates must use an
expected-head guard and prove exact tree equality again.

## Still actionable

Tier-R managed training-artifact transfer, research runner/receipt recovery,
runner output preservation, remaining branch residue and complete integrated
qualification are active work. No claim of full semantic exhaustion, native
tool compatibility, accuracy acceptance or release readiness is made.
