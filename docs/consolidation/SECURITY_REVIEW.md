# Consolidation security review

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Source checkpoint: `eb595b82`; strict scan source `3c6f5905`. This is a scoped review, not a security approval of
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
| Tier-W paired output publication | Reviewed repair `0f0e44d7` retains exact attempt history, preserves canonical prior outputs on cancellation and restores only owned replacements on failure. Two filenames do not provide an atomic view and the final name race is not eliminated. CLI wiring is separate ongoing work. |
| Tier-W multi-file CLI output | Preflight fixes deterministic bad-input clobbering, but labels/evaluation output sets are not a filesystem transaction against concurrent input changes or later publication failure. Do not claim otherwise. |
| Shared Tier-R publication scope | Managed credit receipts verify exact retained bytes and ownership. Existing named-stage path cleanup is not proof of immunity to an arbitrary same-user filesystem race. Training transfer recovery must retain this bounded scope. |
| Current strict security scan | Exact workflow flags at `3c6f5905` reproduce 80 findings: S310=6, S101=9, S608=35, S105=14, S603=1, S110=12, S314=2, S108=1. Existing residual/contract triage covers the categories; this is not 80 proven vulnerabilities or a passing gate. No suppression or threshold change was introduced. Later source still requires matching scan coverage. |
| Native/platform ownership | Portable controls do not qualify native Windows file-handle behavior, toolchain compatibility or package installation. Those require actual platform results. |

## Additional recovered boundaries

Managed Tier-R transfer verifies declared image/provider/builder/evaluator/report
ownership and final manifest credit. Research recovery caps raw observer rows
before normalization, limits source/matrix input and uses exclusive owned receipt
publication. Cleanup receives the local pending error explicitly. Actual native
runs, archive transport round trips and arbitrary same-user race immunity are
not inferred from these controls.

The installed Linux development environment audit initially identified only its
old bootstrap pip 25.0.1. Upgrading with the repository's exact hash pin to 26.3
left 32 audited distributions with zero known advisories at the observation.
Retained inputs/results are under `evidence/`. Fresh isolated dependency profiles,
other platforms and later advisory changes remain separate qualification.

## Remaining audit scope

Continue current-source inspection of parsers, archive/path handling, resource
budgets, subprocess argument arrays and timeouts, dependency audit, persisted
ownership and report rendering. Existing static findings must be explained or
repaired, never hidden to obtain a green job. Remote/native operations remain
explicit; no release or deployment was performed.
