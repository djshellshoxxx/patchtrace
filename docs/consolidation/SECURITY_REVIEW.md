# Consolidation security review

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Source checkpoint: `7dfba50f`. This is a scoped review, not a security approval of
every historical contribution or a release gate waiver.

## Repaired and tested

1. **SQLite resource and primary-error ownership.** Ordinary constructor failures
   close acquired connections. Initialization, transaction writes and commit
   failures retain their original error when rollback also fails. Caller-owned
   connections stay open for the caller. Tests use real SQLite failure controls.
2. **Forced export ownership.** Windows replacement uses explicit held-source
   replacement semantics. Linux uses anonymous initial staging and a held parent,
   and failure cleanup does not unlink a mutable name it cannot prove it owns.
   Force/reuse combinations that cannot satisfy the contract are refused.
3. **Publication receipt integrity.** Bounded expected-length-plus-one reads,
   SHA-256 and stable descriptor metadata are checked before and after publication.
   Same-inode mutation cannot silently receive a success receipt.
4. **Cleanup failure precedence.** Export cleanup receives the active operation's
   exception explicitly. An unrelated outer handled exception no longer hides a
   new close failure.
5. **Tier-W input admission.** Dates must exist on the calendar. Corpus documents
   and symbol maps must match their requested corpus, binary and producer. All
   selected maps and optional audit data are admitted before deterministic input
   errors can overwrite earlier results. Descriptor reads reject nonregular
   input and enforce a strict integer byte budget with growth/stability checks.
6. **Recovered runner provenance.** Completed analysis rows are not automatically
   ghidriff results. Backend, input and symbol-condition provenance must match;
   missing provenance is blocked. Protected paths and duplicate identifiers are
   refused before execution or publication.

The red/green observations and source identities are in `TEST_RESULTS.md` and
`RECOVERED_WORK.md`. These controls do not execute untrusted sample binaries.

## Open findings and limitations

| Finding | Current behavior and next action |
|---|---|
| Linux forced publication final source-name race | An adversary can replace the staged source name after its last name check and before rename. Post-publication verification refuses a success receipt, but foreign bytes may already be visible and the previous destination cannot be guaranteed preserved. A negative regression demonstrates this. Do not describe Linux force mode as atomic held-source ownership. Investigate an identity-safe primitive or narrow/refuse the unsupported guarantee. |
| Tier-W runner cancellation and paired output publication | The imported runner can replace prior matches on a cancelled rerun or leave run summary/matches inconsistent if a later write fails. A repair is in progress. CLI run remains explicitly blocked until the recovery is reviewed and tested. |
| Tier-W multi-file CLI output | Preflight fixes deterministic bad-input clobbering, but labels/evaluation output sets are not a filesystem transaction against concurrent input changes or later publication failure. Do not claim otherwise. |
| Shared Tier-R publication scope | Managed credit receipts verify exact retained bytes and ownership. Existing named-stage path cleanup is not proof of immunity to an arbitrary same-user filesystem race. Training transfer recovery must retain this bounded scope. |
| Historical strict security scan | Prior #316/#318 records include 80 scanner findings requiring triage (including constant SQL, sentinel and exception-handling classifications). The count is not 80 proven vulnerabilities. No blanket suppression or threshold weakening was introduced. Current source scanning and individual dispositions remain required. |
| Native/platform ownership | Portable controls do not qualify native Windows file-handle behavior, toolchain compatibility or package installation. Those require actual platform results. |

## Remaining audit scope

Continue current-source inspection of parsers, archive/path handling, resource
budgets, subprocess argument arrays and timeouts, dependency audit, persisted
ownership and report rendering. Existing static findings must be explained or
repaired, never hidden to obtain a green job. Remote/native operations remain
explicit; no release or deployment was performed.
