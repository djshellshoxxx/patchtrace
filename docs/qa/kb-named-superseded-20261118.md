# Explicitly selected superseded sources — authored QA (2026-11-18)

Source: `51f33d5a0f0e7e48868ff184a54635ff92606f96`; tree: `d220282a6b9011b1bdd975fc207e2b9018be2f37`.
Base: actual published PR #316 `55f3d0742f7d4cf32357a42b8b1cc76d85875e71`.
Branch: `codex/kb-named-superseded-20261118`.

## Result and behavior

The two-file source change restores a bounded explanation for an explicitly
selected older source whose matching rows are withheld. `index._lookup` derives
the named sources from superseded rows **after product filtering** and only for
`provided_files`/`mixed` explicit document IDs. `_warnings` emits one deterministic
`NAMED_SUPERSEDED` line: the first five distinct full source IDs in lexical order,
then the exact remaining count. Existing source IDs are validated 64-character
lowercase hexadecimal digests. With five IDs and a maximum supported-platform
source count, the fixed wording is 485 characters, below the existing 500-character
retained-warning cap.

`service._search_outcome` uses the displayed product's named warning, carries it
into JSON and `Outcome.text`, and omits the incorrect ordinary negative sentence
only when this explanation applies. Status, exit codes, active rows, cards,
coverage, source admission, native ambiguity and conflict handling are unchanged.
The generic CLI writer and desktop source have no edits.

This selectively recovers B2-C1 from the frozen semantic batch, without importing
the old implementation. The batch-2 observation at `3be3af16` remains historical;
this later repair does not rewrite its original failure or disposition window.

## Source and test chronology

| Snapshot | Content |
|---|---|
| `58e45dd60dd272bd342551509aa1cdab7c61ae42` | Specification and 32 new behavioral controls before source edits |
| `1f3d4e4fc69b2a4cc63c543c07a29fa3249b6d36` | Fixture-only correction before source edits: initialize SSL before the no-socket fixture, and inspect the full details pane while preserving the existing abbreviated status label |
| `51f33d5a0f0e7e48868ff184a54635ff92606f96` | Two approved production files, 13 insertions / 4 deletions |

The first run is retained unchanged: **20 failed / 12 passed** (1.37 s).
Nine failures reached the actual index omission; nine hit the test's socket-class
guard before stdlib SSL initialized; two wrongly expected the deliberately
abbreviated status label to retain full text. Those eleven harness expectations
were corrected explicitly. No production behavior was changed to satisfy them.
The corrected source-baseline run is **18 failed / 14 passed** (2.08 s), with
zero collection/setup errors; every remaining failure identifies the explanation
omission. Its exact files and both test snapshots are archived.

## Qualification

| Invocation | Actual result | Scope |
|---|---|---|
| `red-corrected` | 18 failed / 14 passed, 2.08 s | Corrected new controls against unchanged PR #316 production code |
| `historical-red` | 1 failed, 0.37 s | Byte-for-byte original historical named-source control against unchanged production code |
| `focused-green` | 32 passed, 1.89 s | Initial working-tree source repair; dirty state and exact production hashes are recorded |
| `affected` | 411 passed / 0 skipped, 15.67 s | Clean exact source `51f33d5a`, 15 current files |
| `historical-green` | 1 passed, 0.30 s | Same unchanged historical node, separate invocation |
| Actual headless CLI | 8 calls passed; exits 0, 4, 4, 4, 4, 0, 4, 0 | Import, named KB/CVE JSON/text, named active source, cached old and cached CVE controls |
| Whole Ruff / whitespace | Passed | `ruff check src tests tools`; `git diff --check 55f3d074 51f33d5a` |

The 411-case gate includes the 32 new controls and current index, scope, service,
CLI, end-to-end, original bugfix, native revision, card provenance, CVRF, CSAF,
investigation service/dialog and **global tooltip registry sweep**. Absolute
`PYTHONPATH` pins the worktree's source/tests; Qt is offscreen. The actual child
CLI calls assert no PySide6 module is imported and retain every stdout/stderr and
exit. Durations above are the terminal pytest summaries; JSON separately retains
JUnit durations. Overlapping invocations are not additive coverage or completion.

The desktop control exercises the existing real dialog and worker ownership with
a real scoped service result. Its injected executor supplies the file scope;
the desktop dialog itself does not expose a new scope-file control. The bounded
status label and full plain-text details pane keep their existing limits.
No native/manual GUI, live provider, network, target or packaged acceptance is claimed.

## Preserved historical evidence

Original control file:
`tests/test_kbc_bugfixes_20261029.py` from historical tip
`798e11ef345ed7a7a65508a466eaf77ee85ef77c`, node
`test_kbc12_a_named_superseded_file_says_its_hit_is_not_counted`.
Full-file SHA-256:
`5933280cb0f685f2ec129750aecb4a1859c67ed0de178ef4b1f358711d05a665`.

The archive includes this exact file, its original batch-2 red/output observations,
the new-baseline red and source green, all new initial/corrected tests, four
source/spec/test snapshots, complete production/spec-test diffs, exact command
records, JUnit, Ruff, raw CLI outputs and authored temporary workspace inputs.
The original batch-2 packet remains independently sealed at its own comparison
source and is not overwritten.

## Archive and remaining gates

[Sealed evidence](kb-named-superseded-20261118.zip): **79 members**,
**400,967 bytes**. SHA-256:
`0867346af2fa623d1bf6a69a256342b085c5a3df37ec5910311f060711d0687b`.

Every payload size and SHA-256 is in `manifest.json`; archive integrity and every
member hash were verified after reopening it. Python caches and transient SQLite
lock/WAL/SHM files are excluded. Source/tests are unchanged from `51f33d5a`.

Root's independent review is pending at this authored checkpoint. Integration,
exact combined/hosted qualification and any release/platform/package/manual gates
remain separate. This receipt supplies no whole-branch closure, native acceptance
or product-completion percentage.
