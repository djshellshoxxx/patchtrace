# Neutral held inputs and operation checkpoints — 2026-11-18

## Qualified source and result

Implementation **b85a0cf7bf135e9431677737613000707553b192** passes **297 tests**, zero
failures/errors/skips, in 6.18 seconds of pytest-reported time. The independent
runner verifies all **301 loaded PatchTrace modules** against that exact Git
source, with no location or byte drift. Configured Ruff over `src tests tools`
and `git diff --check` pass. This is a portable core implementation receipt;
root independent review and integration remain separate.

| Role | Commit |
|---|---|
| Approved baseline | `068513a72e8a1412ce3960d3024c462d68d51376` |
| Specification and failing controls | `f3456f92681168f7c93a85c40d13f6903cf94de8` |
| Implementation | `b85a0cf7bf135e9431677737613000707553b192` |

Branch: `codex/core-held-inputs-20261118`, reusing the clean
`security-residual-qa` worktree. The former saved-scope branch is preserved at
`feb8472928f827a7b5c64c68304703d9e6f5da52`. Only `input_readers.py`, ingestion's
reader/verification boundaries, `ProjectService.create` and the optional
`ProjectStore._verify_files/save` checkpoint paths change in production.

The read-only design remains independently sealed under
`qa/pw02-kb-held-reader-design`; its 49-payload archive SHA-256 is
`c9be94c2e699a08ef394c26fd8b3cd542ae78f5d34d825edd8f4e3831626df3e`.
This source implements the first root-approved core slice of that map.

## Behavior and ownership

The Qt-free, standard-library-only `input_readers.py` introduces
`HeldInput.check(path)`, `open_reader(path)`, a frozen non-pickleable ordered
`PairInputReaders(older, newer, checkpoint)` and bounded `InputReadError` reasons.
The provider must retain its original object, prove the captured path/name
binding, lend a serial independent read-only cursor and account bounded reads
and seeks. The path is an assertion, not authority for a new arbitrary open.

Held source copying avoids selected-source pathname opens and pathname
fingerprints. Core still checks regular-file type, size, descriptor stability,
complete length, full SHA-256 and the existing AMD64/PE32+ structure. Both input
modes share immutable copies, full copied-PE validation, exclusive publication
and the existing creation ownership ledger. Both held inputs are checked before
store acquisition and again before the first save; no borrowed stream survives
its copy. Core does not close the provider's retained original.

The callback's zero count checks the original operation; a positive count
accounts bytes actually read. Held providers count their own reads. Core counts
ordinary and project-owned copy verification reads, including PE headers, so it
does not double-charge held reads. Read work remains distinct from decompression
output reservations and native hash-specific counters. The later adapter owns
the finite aggregate read-work allowance, deadline and cancel token; this slice
does not create a new timer or an aggregate cap.

`save` checks before verification, after serialization before its transaction,
and immediately before COMMIT while the SQLite transaction remains active. A
raising last check rolls back snapshot/history writes. Creation cleanup retains
preexisting empty/zero-byte/foreign state and uses only its original ownership
ledger. There is no callback after successful `store.save` inside create. Later
cancellation belongs to an outer retained-project outcome. Existing defensive
committed-snapshot preservation in `_rollback_creation` stays intact.

Ordinary positional call shapes and injected-function compatibility are kept;
unused None keywords are not forwarded. Verification caches and complete
hash/PE checks are retained. A final documentation precision makes explicit that
neutral operation stops use `InputReadError`, preserving that reason, while
unrelated OSError/SQLite failures keep existing storage-error mapping. The
precision is preserved as `review-spec-precision.patch`; production is unchanged.

## Preserved observations

| Observation | Source/state | Result |
|---|---|---|
| New authored controls before implementation | Committed `f3456f92`; original production bytes | 36 failed / 2 ordinary-path positives; no collection errors |
| First implementation check | Uncommitted candidate, four exact source snapshots retained | 38 passed |
| First external affected runner | Committed `b85a0cf7` | One collection error, no test bodies executed |
| Corrected exact-source affected run | Same committed `b85a0cf7` | 297 passed / 0 skips; 301 pinned modules, no drift |
| Configured Ruff and whitespace | Same production source | Passed |

The original 36 failures show missing new APIs/module, not 36 existing product
vulnerabilities. No original assertion was weakened. All four first-green
production snapshots equal the committed implementation; all original tests
equal their spec-first commit. The first external runner omitted the exact
repository root from sys.path, preventing the existing `tests.pe_builder`
import. Its raw log/XML/runner remain untouched. `run_pinned_v2.py` adds that
root while retaining the absolute src pin and exact loaded-module byte checks.
The correction and original hashes are recorded separately.

The 38 new controls use authored PE bytes and real project SQLite. They cover
source-path reopen denial, ordered hashes and reopen after source deletion,
provider/original lifetime, descriptor drift, truncated/oversized/malformed
input, read accounting, copy/stage/save cancellation and pre-COMMIT cancellation
for new, zero-byte and empty-current databases with healthy retry. They also
cover retained committed projects, corrupted immutable copies, verification
cache checks and ordinary injected call shapes. The affected neighbors cover
existing ingestion, creation ownership/schema/replacement refusal, core storage,
KB import/store/CLI/investigation/current-project behavior, artifact bytes and
history pruning/backup. The exact 19-file selection is in the command receipt.

The CI peer read the complete exact neutral interface and found no mismatch
with the sealed provider map or its separately owned pure worker-grant contract.
That interface review does not qualify either native implementation.

## Limits and reproduction

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python` with absolute
`PYTHONPATH=<checkout>/src` and `QT_QPA_PLATFORM=offscreen`. The runner also adds
that exact repository root for existing test-package imports. Commands, Python/
pytest/Ruff versions, all four JUnit recounts and exact imported-file hashes are
retained. The full original red and collection-error receipts remain alongside
current success. `source-chain.json` records all 11 changed source/test/spec
snapshots and Git blob IDs; no KB/package/native/jobs changes are included.

The portable provider uses serial POSIX duplicates; it is not a native rooted
reopen or Windows sharing proof. Provider name/identity guarantees, foreign
write/delete denial, native handle transfer and independently rooted reader
qualification remain later Windows work. No target, compiler, native analyzer,
network, acquisition, frozen corpus, hosted CI or release run occurred here.
No package facade, durable package provenance, expired-lease recovery or KB
propagation is implemented. SQLite/OS operations are cooperative boundaries;
the callback does not preempt a blocking syscall or COMMIT. Aggregate byte
limits and cancellation semantics of the future provider need their own tests.

Raw receipts remain in `qa/core-held-inputs`. The adjacent retained archive and
manifest include this report, all exact source snapshots/diffs, original and
current commands/logs/XML, runner correction and source/peer/verification
receipts. Root must independently review before selective integration.

## Sealed payload

The [archive](core-held-inputs-20261118.zip) contains 56 verified payloads
(1,549,497 uncompressed bytes; 463,879 ZIP bytes).
Archive SHA-256: `2d6f638bfec1887188aa15c94a0305dac0efb5b13d2ccff725f3d55566816f4d`. The
[manifest](core-held-inputs-20261118.manifest.json) records every payload byte count and SHA-256.
