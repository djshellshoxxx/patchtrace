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
