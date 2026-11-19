# Consolidation security review

Branch: `integration/exhaustive-patchtrace-consolidation-20261119`.
Source checkpoint and latest strict scan: `7e610c03`. This is a scoped review, not a security approval of
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
| Current strict security scan | Exact workflow flags at `7e610c03` reproduce 80 findings: S310=6, S101=9, S608=37, S105=14, S603=1, S110=10, S314=2, S108=1. This is a different set from the earlier 80/81 findings. Shared-source and cache query identifiers/caps are local constants and values remain SQLite parameters. Existing residual/contract triage covers earlier categories; counts are not proven vulnerabilities or a passing gate. No suppression or threshold change was introduced. Hosted `087f` independently fails with its original 80 findings. |
| Native/platform ownership | Portable controls do not qualify native Windows file-handle behavior, toolchain compatibility or package installation. Those require actual platform results. |
| BinDiff digest-to-parser binding | Independent review at schema/key source `8a3a4255` changes a function name between pathname hashing and SQLite opening. Returned matches contain the changed name while `file_sha256` still names the earlier bytes. The affected boundary also exists in this checkpoint. `evidence/bindiff-import-digest-binding-review.json` retains the actual unequal digests. Held-source verification and owned preservation are under repair; schema/key acceptance does not resolve this defect. |
| Proposed journey source identity | The unintegrated gate at `b7aa97f5` accepts changed consumed production source under the same clean HEAD/tree when Git index flags hide the edit. Both actual `assume-unchanged` and `skip-worktree` controls fail. `evidence/journey-independent-source-red.log` and its original probe retain the observation. The proposed gate remains excluded pending canonical tracked-byte verification. |

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

## Reviewed retry, saved execution and cache boundaries

Explicit retry uses current exact-schema empty-database admission, retained
kernel-lock identity and selected artifact bytes. Independent review reproduced
recursive deletion after private-stage substitution. The correction detaches the
temporary-directory finalizer immediately, captures root/ancestor identities and
retains an observed replacement. Completion refuses; an active primary failure
remains primary. The last check-to-removal interval remains a documented limit.

Saved-plan execution confirms the displayed digest, current recomputed plan and
exact hosts before requests; it preflights all targets and retains immutable
attempt events. A genuine modified-symbol PDB retaining GUID/age was initially
credited on reuse. Strict immutable receipts now bind URL/name/GUID/age and the
downloaded SHA/size. Missing, conflicting, linked or changed receipts refuse;
arbitrary preexisting PDB bytes are never adopted. Receipt/body publication is
separate, so interrupted states remain explicit and are verified on retry.

The PE cache bounds actual returned body and row metadata before Python
materialization, validates complete owner/revision identity, and protects that
owner in the SQL write predicate. Capacity failure cannot evict pipeline history.
Artifact bytes are freshly verified and current OS trust is evaluated separately;
cached metadata does not establish certificate-chain or revocation acceptance.

The build producer additionally had an independently reproduced Git-root error:
an unrelated parent repository could supply a nested source tree's commit. Exact
top-level observations and stable ordinary-root identity now bind ref queries to
the selected root, including real worktrees. The actual Linux frozen-consumer
probe verifies record placement and refusal of changed metadata; it does not
attest source immutability throughout compilation or qualify full packages.

Parser recovery refuses excess Winbindex input before decoding, preserves exact
CVSS tenths independently of caller decimal context, maps unrepresentable UTC
times and malformed redirects to typed errors, retains healthy N-way hops after
pair-path faults, bounds missed BinExport text fields and limits rz-diff
diagnostic allocation. Historical native-receipt conversion remains blocked:
review proved that its source/environment attribution and optional digests can
fabricate a PASS, so it has not been imported into the candidate.
The exact authored offline converter observations are retained in
`evidence/native-receipt-historical-review.json`; they are not native execution.
