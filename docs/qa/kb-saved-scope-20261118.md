# Saved KB/CVE advisory scope — 2026-11-18

## Result and source ownership

Exact source **`a7f6c9c41b3772dc33a787e100097c085389a594`**, tree
`ff1354fb9166fc856d5ca608e22b0f831969c54a`, passes **2,604 checks with one
explicit native Windows skip**, zero failures/errors, in **86.22 seconds**
(87.495 seconds wall). The affected command names 100 test files, including
the unchanged public, legacy CSAF, root context-identity and inventory-selection
probes. Configured Ruff over `src tests tools` and `git diff --check` pass.
All changed source/test/specification bytes were verified unchanged after testing.

This is an authored offline service/store/CLI repair. The tests use synthetic PE
bytes and authored advisory inputs. They do not execute targets, compilers or
native analyzers, make network requests, mutate frozen outcomes, or qualify
Windows packaging, vendor compatibility or native matching accuracy. The skip is
`test_windows_existing_object_validation_holds_read_only_sharing`; its actual
Windows sharing behavior remains unexecuted here.

The branch is `codex/kb-saved-scope-20261118`, based on reviewed continuation
`ae0b1660e0cc71c51698d70a685ceeb646619184`, in the reused
`security-residual-qa` worktree. Prior COFF and static-review branches remain
preserved. The original peer failures belong to `55f3d074`; `baseline.json`
records byte comparisons and the intervening named-superseded warning changes.

| Step | Exact commit |
|---|---|
| Initial specification and failing controls | `273799c7e4e6cd6cb8a123a7bffae473fc732231` |
| Correct authored negative status grammar | `39f232e6b33fd58ffc003c7ad3bec19362e23ad3` |
| All selected journal revisions before recovery | `85b5fa8a35d85c1e4e3b6f15bb0220c86137927f` |
| Approved fixtures and additional boundary controls | `278b8839146c30ece29b2ad7c279c1203bd393dd` |
| Initial source repair | `60d8006358dc82a49a42e57eaaac548d4706359f` |
| Legacy coverage and admitted-context identity controls | `f4f99d40fce00fb412cb3a09a8bcbb543f0853ee` |
| Keep authored CSAF withdrawal schema-valid | `bb82764ed31f1bce87fecaf878ba10bf418d4e29` |
| Legacy inspection bookkeeping and effective edge identities | `cc408c390ec9c9f8e7b907f7c2d61d06e17e77f8` |
| Inventory saved-scope specification and failing controls | `cfae7bb5c4574dd92b9412ff52a4b821e8a93624` |
| Final inventory preflight source | `a7f6c9c41b3772dc33a787e100097c085389a594` |

## Behavior repaired

A cached search keeps the exact document IDs that it inspected, including an
empty selection. Reopening, adding unrelated cached documents or importing a
pair cannot silently widen that search. Provided-file IDs stay finite too.
Recorded month selectors retain their months; detectable inspection or watermark
changes require a repeat search before a new derivation.

The pure `saved_scope.py` boundary validates the coverage reference, validated
body, recomputed `kbc.coverage/1` identity, coherent selector fields, corpus digest
and current readable inspection state. Service callers reject missing, malformed
or changed coverage with `PT-KBC-SCOPE` and repeat-search guidance before decisions,
approval, journal changes or project creation. The direct context builder applies
the same record checks before interpreting cards or generating a context key.

`attach --repair` checks the current investigation and **every matching captured
journal revision**, including a valid first journal followed by an invalid one,
before invoking generic recovery. Tests inspect actual SQLite dumps, workspace
and project bytes, and entry into write transactions; an exception alone is not
counted as evidence of zero writes. A captured KB/CVE revision still needs readable
current admission even when the current investigation has become pair-only.

Admission uses the complete current index before finite projection. Later
same-group withdrawal, negative facts, tied native revisions and unknown ordering
cannot make an old selected claim current. Unreadable current sources prevent
establishing that admission set. The selected population is used only to reconstruct
historical coverage bookkeeping: an existing CSAF receipt can name two snapshots
while counting one inspected logical revision. That compatibility calculation is
never substituted for the full admission index.

New context digests use the existing `kbc.edgeset/1` namespace and sorted identities
of selected, globally active edges. A shared global revision-conflict calculation
feeds both lookup and the digest; an edge made disputed uses its existing derived
disputed identity. This fixes the reproduced case in which tied native
counterevidence removed a CVE card but left a different context under the same key.
An unrelated month or an agreeing source outside the finite selection keeps the
context key stable. Recorded legacy bundles remain readable without rewriting.

Final call-site review reproduced one further inventory-selection bypass:
`inventory_selection._scope` discarded the unreadable list and omitted its already
loaded index when calling `_stored_scope`. A requested March month arriving after
a partial February search could then publish a selection and advance revision
3 to 4. The four-line final repair forwards that existing index and unreadable
list. Existing source snapshots, raw inventory replay, eligibility conflicts and
revision compare-and-swap guards remain in place. KB and CVE negative controls
assert zero writes; unchanged partial scope, cached unrelated-month growth and
idempotent selection remain usable.

Production changes are limited to `context.py`, `index.py`, `service.py`,
`inventory_selection.py` and new `saved_scope.py`. There are no schema, UI,
acquisition, generic recovery or native-tool changes.

## Preserved test chronology

These are overlapping runs, not additive counts of independent findings.

| Receipt label | Observed result |
|---|---|
| Peer original public probe at `55f3d074` | 2 failures / 1 positive |
| `public-baseline` at `ae0b1660` | 2 failures / 1 positive, 0.58 s |
| `historical-baseline` | 40 failures / 4 passes, 1.09 s |
| `spec-tests-red-corrected` | 60 failures / 6 passes, 1.26 s |
| `multi-journal-red` | 1 failure, 0.49 s |
| `focused-first` | 155 passes, 6.69 s |
| `affected-first` | 2,548 passes / 15 failures / 14 setup errors / 1 Windows skip, 89.40 s |
| `additional-boundary-red` | 3 failures / 2 passes, 1.43 s |
| `corrected-focused` | 164 passes, 8.77 s |
| `committed-affected`, exact `60d80063` | 2,586 passes / 1 Windows skip, 88.52 s |
| `legacy-csaf-coverage-review`, exact `60d80063` | 1 failure / 1 positive, 0.46 s |
| Root unchanged native-admission probe at `60d80063` | 2 failures; original collection and import ownership retained |
| `admission-compatibility-red` | 9 failures / 1 pass, 0.77 s; includes one invalid authored withdrawal fixture |
| `csaf-withdrawal-red-corrected` | 1 intended failure, 0.50 s, after schema-valid fixture correction |
| `admission-compatibility-first-green` | 144 passes, 4.97 s |
| `corrected-committed-affected`, exact `cc408c39` | 2,598 passes / 1 Windows skip, 89.67 s |
| `inventory-saved-scope-review`, exact `cc408c39` | 1 failure, 0.49 s |
| `inventory-saved-scope-spec-red` | 4 failures / 1 positive, 0.58 s |
| `inventory-saved-scope-first-green` | 99 passes, 1.39 s |
| `final-committed-affected`, exact `a7f6c9c4` | 2,604 passes / 1 Windows skip, 86.22 s |
| `historical-at-final`, exact `a7f6c9c4` | 41 passes / 3 preserved policy conflicts, 0.81 s; exit 1 retained |

The first red run used an unrecognized authored `NotAffected` label; the correction
uses supported `known_not_affected` and asserts that parsing actually produces a
disputed relation. Both original and corrected receipts remain. The first broad
gate exposed two legacy test builders that passed `coverage=()` and a conflict
fixture that added its March competitor only after capturing finite cached scope.
With root approval, the builders now supply their actual index coverage, preserving
their provenance assertions. The competitor is imported before search to retain
the real within-scope build-conflict refusal; a separate positive checks that later
March additions do not expand saved scope. During-read, replay and CAS race tests
are unchanged. Original fixture bytes and failing receipts are retained.

The historical file remains byte-for-byte unchanged. Three expectations still
conflict with current global admission: the files/cached forms of
`test_unselected_newer_same_month_revision_neither_replaces_nor_suppresses_selected_snapshot`
and `test_explicit_file_search_selects_older_snapshot_when_newer_already_loaded`.
They demand restoration of selected old claims despite current supersession.
This repair deliberately does not implement that behavior. The other 41 historical
nodes pass; the original 40 failures were never treated as 40 product findings.

## Caller audit and limits

`final-caller-audit.json` records exact source hashes and all production
`_stored_scope`, `_saved_search`, `_checked_index` and `build_bundle` references.
Products, components and pair/plan/acquire entry paths preflight their saved search;
import retains its validated index across approval; attachment preflights all
captured revisions. Only service `_bundle` calls the pure builder in production.
The inventory peer independently traced direct builders and the read-only CLI
annotation path at `cc408c39`; its receipt is retained separately.

Explicit new search/import/status operations may describe new current inputs.
`explain` and export read recorded context without silently rebuilding it.
`cli_leads._elsewhere` is read-only; its discarded unreadable annotation input is
outside this pre-mutation claim, not a newly demonstrated write defect.

The existing generic recovery policy may mark unrelated unfinished operations
on a valid repair; this change provides no new operation-isolation guarantee.
A malformed journal missing `revision` can still fail in existing `_ops_for`
before writes; this slice does not redesign journal corruption handling.
Month-only coverage does not retain every historical source digest. No arbitrary
concurrent SQLite tampering, filesystem replacement or Windows sharing guarantee
is claimed by these cooperative, bounded controls.

## Evidence and replay

Raw receipts are in `qa/kb-saved-scope`. The adjacent manifest and ZIP retain source,
test and spec snapshots; exact commits and diffs; original, intermediate and final
commands/logs/JUnit; immutable probes and observation JSON; fixture corrections;
caller audits; and before/after hash checks. `release-source.json` identifies final
source. Earlier `source.json`/`final-source` describe the initial `60d80063` candidate,
and `corrected-source.json` describes `cc408c39`; those historical names and bytes
were not overwritten.

Use `/workspace/scratch/3a6632a6e5ff/venv/bin/python` with absolute
`PYTHONPATH=<checkout>/src:<checkout>/tests:<checkout>` and
`QT_QPA_PLATFORM=offscreen`. `run_checks.py` records the commit and status, checks
the imported service location and refuses to replace an existing receipt label.
The final full command and extra root-probe environment are retained in
`final-committed-affected.command.json` and `.environment.json`. The root probe
requires a fresh `PATCHTRACE_SCOPE_REVIEW_OUTPUT` because it opens observations
exclusively. The final public probe is a byte-identical copy in a fresh directory;
its relative output does not overwrite the peer's original observations.

Public probe SHA-256:
`cf2f3320e7eaab89a2e38d8a71724e2de67f6270c3a6c4c154fa2f56218fcb5c`.
Historical file SHA-256:
`baa5b56e0c238f74b91c71706abb9a7161cd616f51f1a53a8a1b6ed13a97f0a9`.
The final verification receipt confirms both, all original peer observations,
and the retained root-probe copies. Root independent review and integration follow
this handoff; no remote action accompanies it.
