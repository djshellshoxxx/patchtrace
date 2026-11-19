# Consolidation security review

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Source checkpoint: `cb1b508c`; latest strict scan source `ecfd5960`. This is a scoped review, not a security approval of
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
| Tier-W paired output publication | Reviewed repair `0f0e44d7` retains exact attempt history, preserves canonical prior outputs on cancellation and restores only owned replacements on failure. Two filenames do not provide an atomic view and the final name race is not eliminated. Hidden-symbol CLI wiring is now integrated with explicit runtime paths and retained cancelled-attempt identity. |
| Tier-W multi-file CLI output | Preflight fixes deterministic bad-input clobbering, but labels/evaluation output sets are not a filesystem transaction against concurrent input changes or later publication failure. Do not claim otherwise. |
| Shared Tier-R publication scope | Managed credit receipts verify exact retained bytes and ownership. Existing named-stage path cleanup is not proof of immunity to an arbitrary same-user filesystem race. Training transfer recovery must retain this bounded scope. |
| Current strict security scan | Exact workflow flags at `ecfd5960` reproduce 81 findings: S310=6, S101=9, S608=36, S105=14, S603=1, S110=12, S314=2, S108=1. The additional S608 is the shared source reader metadata query: identifiers/caps are local constants and values remain SQLite parameters. Existing residual/contract triage covers earlier categories; counts are not proven vulnerabilities or a passing gate. No suppression or threshold change was introduced. Hosted `087f` independently fails with the original 80 findings. |
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

## New independently reviewed boundaries

Shared stored-tool capture binds row/guard/status/revision, current artifact,
manifest/config/cache digest, sidecar header/content, counts and retained producer.
The five independent negative controls are retained. Strings refuses unreadable
stored evidence, verifies both artifacts, cancels older requests before admitting
a replacement, and distinguishes normalized-evidence digest from raw stdout.

Download staging is now held and rehashed before receipt; same-inode mutation
cannot receive success. The initially proposed whole-PDB memory copy was rejected
before integration. FileSnapshot verifies fixed-size blocks and bounded parser
ranges; publication uses at most 1 MiB physical reads, retains only block digests,
and preserves active failure during owned cleanup. Native Windows acceptance is
still skipped here and no arbitrary mutable-name rollback is claimed.

A real configured Git clean filter executed during the first version observer.
The correction removes status and describe --dirty, including the tempting but
race-prone config-preflight alternative. Source cleanliness is unknown. Version
reads remain bounded; packaged metadata is validated without source fallback.
Project creation cleanup likewise retains active failure across secondary process
interruptions and preserves files when database state is uncertain.
