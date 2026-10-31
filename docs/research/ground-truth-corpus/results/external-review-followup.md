# External review follow-up

Reviewed code checkpoint: `de72e150bb9f40a18dffbc0960226677555e4431` on
[PR #128](https://github.com/djshellshoxxx/patchtrace/pull/128).
Qodo submitted its [independent automated review](https://github.com/djshellshoxxx/patchtrace/pull/128#issuecomment-6535935632)
on 2026-10-30, identifying one
medium and two low-severity findings. This record distinguishes implemented
repairs from an explicitly retained compatibility limit. It is not an owner's
GitHub APPROVE review or a substitute for current-head CI.

## 1. Undeclared suite endpoints — corrected

The existing strict `suite/1` model validates the versions and pairs separately;
it can accept a pair whose `old` or `new` version is undeclared. The new research
matrix subsequently indexed the version-to-source map, allowing an uncaught
`KeyError` after tool probing. The finding is recorded in
[Qodo's inline comment](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429415913).

The research wrapper now checks every endpoint against both declared versions
and available source bases before constructing cells or probing compilers. The
error identifies the pair index, side and version. The API raises `ValueError`;
the existing CLI handler returns 2 without creating a store or output receipt.
No persisted contract, factory schema, valid experiment or label was changed.

Four tests use the real suite loader and real source-directory preparation,
covering old/new endpoints through both API and CLI. Before the fix, all four
reached a forbidden probe sentinel and failed. Afterward the complete build
test file passed **15 tests in 0.74 seconds**. These are input-validation tests,
not native engine acceptance. Exact commands and red/green counts are retained
in `suite-endpoint-red-green.json`; the original red trace was tool output,
not a saved full log.

## 2. Filesystems without hard links — explicit supported-store boundary

The compatibility observation is valid: atomic complete build-receipt
publication depends on `os.link`. A filesystem or policy that denies that
operation cannot provide the implemented receipt guarantee. Support for those
stores has **not** been added.

The proposed exclusive-create/write/fsync fallback would expose the canonical
content-addressed filename before writing all bytes. A later `fsync` does not
remove that partial-publication window. An independent review of existing
repository helpers found no portable regular-file atomic-no-replace fallback
that preserves this invariant; directory publication and mutable lease-owner
helpers have different guarantees.

The spec, protocol, limitations and handoff now state the hard-link-capable
store requirement. Non-`FileExistsError` publication failures become a clear
`BuildError` retaining the actual OS reason, which can be unsupported capability,
permissions or another storage error. No partial canonical file is published,
temporary staging is removed and the previous legacy receipt remains unchanged.
The existing idempotence and corruption checks remain intact.

Failure-injection tests cover unsupported and denied publication. They first
failed **2 cases, with 4 existing cases passing**, then the full receipt file
passed **6 tests in 0.51 seconds**. The red result was observed in tool output;
the green log is hashed in the final validation record. This verifies failure
semantics, not native acceptance on a filesystem without hard-link support.

## 3. Temporary native log comment — corrected

The live-pair CLI removes its temporary projects before writing its bounded
failure-summary sidecar. Its new comment incorrectly said native logs remained
there. The comment now states that the temporary projects and native logs were
deleted and only the bounded explanation remains. Cleanup behavior is unchanged.
R1's separate pilot runner retains its own native projects outside the worktree;
the two paths must not be conflated. A comment-only correction needs no new
behavioral test.

The integrated six-file follow-up selection passed **69 tests in 12.20 seconds**,
covering build receipts, matrix validation, the existing factory, session
provenance, live-pair orchestration and pilot behavior. Full repository Ruff and
diff-whitespace checks passed. The selection overlaps earlier runs and is not
added to their counts; its log hash and node list are in `final-validation.json`.

## Gate and ownership status

SonarCloud passed at `de72e150bb9f40a18dffbc0960226677555e4431`, with zero new
issues, zero security hotspots and 2.7% new-code duplication. That historical
result does not certify a subsequent commit. Final-head checks are read from
the PR. CodeRabbit and GitHub QA remain separate external checks; no thresholds,
exclusions, branch protections or owner approval identities were changed.

The final handoff records active R2–R8 PRs. These follow-ups modify only the R1
research wrapper, build-receipt error reporting, tests and research notes. The
conditional-branch/store production defect remains a separately coordinated
matching/semantic-analysis task, with the original R1 evidence preserved.

## CodeRabbit follow-up — 2026-10-31

CodeRabbit's later review supplied seven concrete findings. The response keeps
historical experiment records intact and makes current evidence independently
checkable. No original engine result was replaced to improve a score.

| Review comment | Disposition and evidence |
|---|---|
| [4429457695](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457695): table pipes | Escape the two bitwise-OR pipes in the source-suite README so the flags row renders in the correct columns. Source code is unchanged. |
| [4429457709](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457709): missing accepted build receipts | Recover one exact historical receipt and reproduce both complete receipt hashes and accepted artifact triples with real stock builds. Add the two missing files. [Recovery evidence](hidden-receipt-reconciliation.md) explains why equal normalized recipe digests did not make the matrix artifacts interchangeable. |
| [4429457714](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457714): missing structural import | Add `from tools.calibration.mutations import opt_transforms as O` to both reproduction snippets. The actual structural experiment JSON and its measured results remain unchanged. |
| [4429457719](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457719): stale integrity inventory | Preserve the original 22-label gate snapshot; add an actual [current 23-label integrity audit](final-label-integrity.json) and [partition audit](final-partition-audit.json), with explicit historical scope. |
| [4429457726](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457726): stale A/A variant | Rebuild both A/A cases and all four noise cases using the fixed cache and original tool paths. Five labels change only one variant field plus their digest; all artifact/function facts match. Archive original label bytes and publish [exact mappings](label-provenance-corrections.json). [Recovery evidence](native-aa-provenance-correction.md) binds the original native results to the corrected metadata without fresh-engine credit. |
| [4429457729](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457729): missing review-file hash | Preserve the historical hidden receipt, and run the current reader over a private copy of its validated primary project. The [replay binding](hidden-review-binding-reconciliation.json) records the exact review hash and equal observations, metrics and selection digest. It explicitly reports persisted-native evidence and no new matching-engine execution. |
| [4429457734](https://github.com/djshellshoxxx/patchtrace/pull/128#discussion_r4429457734): matrix output overwrite | Validate a new absolute `.json` path outside the repository before building; reject existing files and destination/ancestor symlinks; recheck after builds and parent creation; publish with exclusive `xb`. Tests preserve competing files appearing during builds and at the final open. |

### What the rebuilds established

The original hidden/Clang-control PDBs embed `/usr/bin/lld-link-18`; the matrix
and the first default-discovery control retry embed `/usr/bin/lld-link`.
Version banners and normalized recipes match, but PDB/CodeView and whole-image
hashes differ. Corresponding code sections are identical. Explicitly selecting
the recorded original paths reproduces the accepted artifact hashes. This is
an observed input-identity gap because `build._template` omits executable
`argv[0]`; it is recorded as a limitation and reproduction requirement, not
concealed as unexplained nondeterminism or fixed by changing historical digests.

The current active inventory contains 23 strict, unique label documents, all
development-only. The six deliberately induced cross-partition findings remain
unchanged. All 39 published receipt files match their content-addressed names;
they represent 36 unique hashes because some actual control builds share full
compiler receipts. Five historical label copies preserve the original metadata
and digests. The original native/control experiment JSON is unchanged.

### Verification and independent review

The matrix destination tests first exposed **9 failures with 18 passing tests
in 0.82 s**. After repair the entire file passed **27 tests in 0.69 s**; a
combined matrix/cache/receipt selection passed **39 tests in 0.86 s**. A separate
read-only reviewer independently reran the 27-test file, all passing in 0.61 s,
and found no blocking defect. The guarantee concerns mistaken invocations in
private directories; it does not claim isolation from a hostile process that
replaces a parent directory after the final check.

The final integrated selection passed **175 tests in 31.62 s**. It includes
actual factory/compiler tests as well as unit/orchestration substitutes. Full
repository Ruff passed. Exact log hashes and retained logs are recorded in
`final-validation.json`; these overlapping runs must not be summed. No full
Linux or native-engine rerun is implied by these focused counts.

An independent read-only provenance review verified the two recovered hidden
receipts, replay binding, five exact historical-to-current label diffs and
unchanged fourth noise label. It found one documentation binding issue: the
corrected structural Markdown hash had been named historical. The record now
retains both the original checkpoint hash and corrected reproduction-document
hash, and distinguishes the import-only Markdown edit from immutable experiment
JSON. The native correction's observed preflight checkpoint has an explicit
dirty-worktree/no-per-run-code-snapshot caveat.

SonarCloud also passed at the subsequent `0d14548` checkpoint with zero new
issues, zero security hotspots and 2.6% new-code duplication. This remains a
historical observation; final-head external checks and independent approval
must be inspected before merge. No branch protections or quality thresholds
were changed.

### Additional editorial observation

The review also included an unverified readability observation about compressed
prose such as `returns0` and `by5`. Those forms were confirmed in the source-suite
README and corrected to ordinary spaced prose, along with analogous size,
offset, bit and XOR descriptions. This editorial change does not alter either
C source file, the suite specification or compiled artifacts. Historical
generated label intent/notes strings remain exact evidence: changing their
wording would change canonical label digests and invalidate existing review
bindings. A future generator-text cleanup must create a new explicitly bound
label/review generation rather than silently rewriting these records. No new
behavioral test is claimed for the Markdown-only edit.
