# Independent advisory read-budget review — 2026-11-18

## Result and exact source

No blocking finding was confirmed in the reviewed Linux behavior. The repair enforces each retained file's byte budget on a held regular-file descriptor, verifies its digest while held, and rejects observed leaf/parent replacement or file changes before returning evidence. Existing valid normalized-cache reuse, verified raw recovery, damaged-cache replacement, and restored-project reads remain compatible in the exercised paths.

Reviewed source: `06f5b210e5c6daffaae2b4d51fd8950c28be25c3`; tree: `564ce17da6e8d6fd9e15ad3b3fde16cd91f825bd`. Baseline: published #307 `58fc130631f602b6e907bb054d30c21d810551d4`; spec and original failing controls: `7d0e8bac82c8624708932eaff723c246f878835c`. Review ran in a separate initially detached worktree, `/workspace/scratch/c7a9e8d98848/advisory-bounds-review`. No product source was edited by the reviewer; this follow-up commits only the independent receipt.

## Evidence

| Check | Exact-source outcome | Scope |
| --- | --- | --- |
| Author's affected selection, independently replayed | **140 passed in 12.07 s; no skips** | New read-budget tests; existing intelligence storage, CLI and explain; pilot CLI; portable shared-reader Windows call assertions |
| New independent behavior controls | **11 passed**, within the 16-case run below | Actual regular-file reads, growth and replacement, descriptor cleanup, nonregular input, cache repair |
| Existing backup-sidecar tests | **5 passed**, within the same run | The remaining direct `read_verified` consumer and restored project sidecars |
| Independent controls plus backup cases | **16 passed in 0.85 s; no skips** | Disjoint from the 140-case affected selection; these are bounded checks, not a full suite |
| Author's original failing budget controls, preserved verbatim | **7 failed, 2 passed** | Historical baseline evidence, not a current-source result |
| Author's lint receipt, inspected and preserved | Final `All checks passed!`; earlier import-formatting failure retained | The reviewer did not rerun lint; the independent test runs occurred after final formatting |

Both independent commands use `/workspace/scratch/3a6632a6e5ff/venv/bin/python`, `QT_QPA_PLATFORM=offscreen`, and absolute worktree `src` in `PYTHONPATH`. The external run also includes the same worktree's `tests` directory for existing fixture helpers. The receipt records exact command arguments, imported module paths, Python/platform details, source hashes, log/XML hashes, and the original author receipt paths. The shared environment's editable install is not used as source provenance.

## Independent controls and interpretation

A real sparse file of **64 MiB + 1 byte** was hashed incrementally and read using that matching digest. The store refused it before any content-read call; this exercises the actual default limit without allocating an over-budget payload in the test. A file exactly equal to its custom budget returned its exact bytes and closed its descriptor. A file grown after the initial held-size check was limited to the requested budget plus the one-byte overflow sentinel and refused.

Three separate controls changed evidence immediately after its real content read. Replacing the leaf with a different inode containing identical bytes failed; moving the held parent and constructing a new same-byte path failed; changing the held file in place failed. Therefore a matching digest of the captured bytes did not bypass post-read identity/change validation. The controls asserted that their mutations occurred and that descriptors were closed. A separate digest-mismatch control also verified descriptor cleanup.

A directory and an unwritten FIFO were rejected in bounded child processes; the FIFO control would time out if a blocking path read were used. A parent symlink was refused despite an exact matching payload hash. These Linux checks cover symbolic links and observed changes during a held read; they do not establish general selected-root identity across independent operations.

The real-project cache control first damaged only raw source bytes and observed that the independently verified facts cache remained usable without warnings. After also damaging facts, the advisory became unavailable. Reimport restored both original sidecars, retained identical pointer rows, and returned the same facts without warnings. Existing backup cases verified compatible reads after restoration.

## Limits and remaining gates

The supported desktop target is Windows; Linux is the local source/test environment. This repair reuses the existing platform reader rather than introducing a second native implementation. Portable assertions exercise Windows access/share/no-reparse flags, but **native Windows filesystem behavior, exact-head full/platform qualification, and frozen packaging are not certified here**. Other platforms still fail closed under the shared helper's existing contract; this review makes no macOS compatibility claim.

Individual retained-file reads are bounded. Total advisory count, cumulative store I/O, parsed-model memory, owner-thread responsiveness, broader publication/replacement races, and changes before selected-root capture remain separate unqualified scopes. No live advisory acquisition, external engine, target execution, manual desktop acceptance, or release was performed. No completion or accuracy percentage is derived from test counts.

## Retained packet

`advisory-read-bounds-independent-20261118/manifest.json` binds all 13 members in `raw-evidence.zip`: the unchanged author red/log/XML and lint evidence; independent raw logs/XML; external control source; provenance; and the receipt-building script. The ZIP is **18,672 bytes**, SHA-256 **`361bc6154240dd9969ffdf803f09d6f565794dfd4dd6b262d19b03bfd1f89339`**. CRC validation, every member's SHA-256, exact source/tree identity, and source file hashes were checked before this documentation commit.
