# Static review and staging ownership follow-up — 2026-11-18

Current integration source: **`2c0d51cb3cd237dfd6ef8740f36404cd15abe1bc`**, tree **`0a65914426d61e391fff83b9ebfa8aa7a7347f92`**.
This append follows the [combined checkpoint](../verified-followup-integration-20261118/README.md).
It adds the reviewed staging ownership repair and source-specific static review;
main remains held for actual candidate qualification. No main merge, PR closure,
release, tag or deployment occurred.

## Staging ownership: independently reproduced and repaired

At combined source `c80aae27427e1f7b4006b97173e8b59560836808`, root independently
replayed the unchanged authored-project probe: **one failure / one healthy
positive, 0.47 s**. Failed directory creation deleted another operation's
existing directory. Only token selection was fixed to reproduce a collision;
nonce predictability and arbitrary namespace attacks are not claimed.

The accepted source is `43ac4829f4e196d7001714bff3622229f5c64d00`, preceded by
specification/regressions `e6e6ca13ec64f05b33edf6adea1286655d4ca25c`.
Root reviewed the complete patch: exclusive `mkdir` now occurs before entering
cleanup for subsequent writes. Failed creation preserves the occupied entry;
after successful creation, write errors, KeyboardInterrupt and SystemExit still
clean the newly owned directory and preserve the original exception. Existing
siblings remain untouched. Cooperative namespace assumptions, process kill and
power-loss limitations remain explicit.

Root's committed-source selected gate passes **140 cases in 13.66 s**, zero
skips, covering the unchanged external probes, new ownership controls, existing
store/current-input/CLI/report and offscreen freshness behavior. Author's wider
source-specific gate independently reports **219 passed in 26.29 s**; these
selections overlap and are not summed. The original author packet and separate
root addendum retain every red/green receipt without rewriting prior evidence.

The local port is `c24aff36` → `fb529d90` → `cdeada1b`, with root-review QA at
`2c0d51cb`. At `cdeada1b`, every production/test/tool/workflow/pyproject byte is
identical to reviewed source `43ac4829`; normal Ruff and diff checks pass.
The source-preservation receipt accounts for **76 changed paths** against #307
and preserves actual #308–#315 ancestors. These facts establish source mapping,
not a full/platform/native test pass at the current documentation head.

## Forty-three reviewed static sites

The [assertion/SQL receipt](../security-contract-triage-20261118.md) classifies
nine S101 and 34 original S608 rows at their recorded caller/input boundaries.
The review found no assertion-dependent validation bypass or SQL injection at
those sites. It does not declare their modules or the full application secure.

Root read that receipt and its external probe, independently verified all 229
archived payloads, then replayed **eight groups in normal and optimized Python**
on combined source `ba515e9f111d895779becc1b4f4e7af470212223`.
All 16 child processes exited 0, optimization was verified, corresponding outputs
matched, and each imported source file was rehashed against the actual combined
checkout. The cases use real authored SQLite/storage/search/IR state and Qt
models; an audit hook refuses network and external process activity inside the
probes. Injected BinDiff runners only create authored records, not native output.
Root does not relabel the author's separate 1,012-test run as a combined-source
run. All original diagnostics remain in the raw data.

## Fresh complete scan: 81 findings, still failed

Root ran the full strict S rule set at `cdeada1b` with isolated configuration,
no inline ignores, no cache and no Git-ignore filtering. It exits **1**:

| Rule | Current findings |
|---|---:|
| S101 | 9 |
| S105 | 14 |
| S108 | 1 |
| S110 | 13 |
| S310 | 6 |
| S314 | 2 |
| S603 | 1 |
| S608 | 35 |
| Total | **81** |

The original 79-row scan remains byte-for-byte intact. The encoding-independent
manifest repair now produces two S314 parser/fromstring diagnostics in place of
the old single call. One additional S608 row is the later bounded metadata
query in `pilot/sources/kb_context.py`; it is assigned for explicit review and
must not disappear merely because the original selected ledger had 34 SQL rows.
Root's post-processing expectation of 80 therefore failed; the saved raw output
and source/command receipt correctly record 81. That expectation is not scanner
acceptance or a product test. The earlier manifest-reader preflight also assumed
`members/files` instead of the packet's actual `payloads` key; corrected
verification checks every member and leaves the archive unchanged.

No finding was excluded, no rule was disabled, no automatic fix or allowlist was
added, and this remains a failed strict-security scan. Review of the remaining
families/current extra site continues independently. The S108 warning remains
visible after the actual cleanup ownership defect was repaired.

## Separate unresolved failed-attempt retention defect

The inventory reviewer used a real MainWindow and sample database with
`PRAGMA query_only=ON`. Three failed/cancelled/timeout attempt controls fail and
a writable-store positive passes. `EvidenceController._engine_finished` swallows
the save failure, strips the run from its lightweight outcome and gives no
persistence diagnostic. The engine remains unsuccessful: no false success or
trusted match-set admission was observed. Raw probe, source receipt and 3-red /
1-positive evidence are retained under `s110-unresolved/`.

A separately owned specification/test/repair is assigned: preserve original
engine status and reason, report that the attempt could not be saved, retain
bounded details through final aggregation, preserve existing trusted sets and
honor generation/project/thread guards. No automatic retry or duplicate write
is authorized by that fix. This checkpoint does not claim it repaired.

## Qualification and archive

The previous **1,770-pass / three-xfail** combined selection belongs to
`3be3af16`, before the two-line staging change. The current staging source has
its separately recorded 140/219 selections and byte mapping. Full actual-head
Linux/Windows, repeated Qt, native, package and complete dependency/security
qualification remain required. Windows BinDiff effective-denial implementation,
compiler-sweep 5/11 completion, approved acquisition and complete analyst/manual
journeys remain open. No overall security or beta-readiness claim follows.

The archive has **75 members**, **84,434 bytes**, SHA-256
**`6fca0efe267d4c9090af0098af20ac5f4079773224c65c80411afc0da898021c`**. Its manifest, CRC and every member hash were
verified. It also preserves the first 30 local-to-remote Git-object mappings;
those objects were prepared without creating a branch ref. Subsequent
publication must identify its final local/remote head and exact tree separately.
