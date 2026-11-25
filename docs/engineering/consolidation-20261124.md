# November 24 PatchTrace consolidation

This continuation combines the reviewed project, installer, backup, network and
tooling stacks with current main. It preserves all donor heads and the merged
catalogue-ID correction. The combined PR is the qualification and integration
vehicle; its live checks and merge state supersede the historical pending-state
paragraphs below for these named changes only.

## Source and scope

Main at assembly was `44c62cbf94c2d25c0c383eeb0072b7adf2bbb415`. The frozen
combined implementation is `c6b215c5222e4ec3ed760bc4fc9f92719b18bda8`, tree
`4ec56b8211818475b6e72396b4b65f4d27ddd8eb`. The publication adds only this
continuation record, review receipts and current index pointers. Resolve branch
`integration/patchtrace-consolidated-20261124-7de6` for its final documentation
head; do not substitute donor CI for combined-source qualification.

| Donor | Preserved head | Included behavior |
| --- | --- | --- |
| [#360](https://github.com/djshellshoxxx/patchtrace/pull/360) | `ca95a7d045f3fa44551934680fa90c2af00370e5` | Preserve existing SQLite projects on creation retries, clean up only owned files, correct Windows path handling and recent-project settings. |
| [#361](https://github.com/djshellshoxxx/patchtrace/pull/361) | `457444c682a1bf7e5166030c065f0365ad2c6976` | Preserve preferences during Windows uninstall, avoid unnecessary offscreen formatting work, and complete keyboard/install documentation. |
| [#362](https://github.com/djshellshoxxx/patchtrace/pull/362) | `47478d563bc91529446b4b1d1f461f01ececb245` | Verify backups before publication, preserve competing destinations, report retained copies after interrupted verification, and recover from desktop worker launch failures. |
| [#358](https://github.com/djshellshoxxx/patchtrace/pull/358) | `18edf3012a26eaeb037c2b970a252cc14481fba8` | Enforce network deadline/cleanup boundaries, bound CSAF cache reads, recover from optional-module initialization failures, and protect pilot/Sigstore tooling installs with complete hashed closures. |
| [#359](https://github.com/djshellshoxxx/patchtrace/pull/359) | `173f18d3a6ddd88aaaf514ced71b1be0c3db7954` | Correct the stale Sigstore installer assertion while retaining the exact locked-install and closure checks. |

## Integration decisions

No application-source conflict occurred. The two documentation conflicts retain
both complete historical line sequences. The workflow census conflict retains
both the Windows preflight and the pilot hashed installer: 21 workflows,
204 run steps, 42 explicit installs, three protected commands and 39 commands
without the audited boundary. Both repository-wide strict CODEX-5 expected
failures remain unchanged. The census specification records this composition.

The pilot requirements lock loses only an empty trailing line; every version,
wheel hash, URL and substantive line is preserved. All 21 workflow files retain
the exact intended donor bytes. No workflow trigger, permission or gate changed.

Independent record review verified all 130 unique task IDs, all 46 notes, deep
history and the five historical task before-images. The combined ledger is the
complete #359 ledger plus #362's two qualification sections. All 95 changed
desktop evidence files and 70 network evidence files retain their donor blobs.
All five donor heads and captured main remain ancestors of the candidate.

## Independent verification

These are separate source-specific runs, not one combined or deduplicated total.

| Reviewed source | Executed selection | Result |
| --- | --- | --- |
| #360 `ca95a7d0` | Eleven storage, GUI and inventory modules | 230 passed; zero skips or failures. Required Ruff and whitespace checks passed. |
| #361 `457444c6` | Code display, keyboard help and installer contracts | 256 passed; zero skips or failures. Focused Ruff and whitespace checks passed. |
| #362 `47478d56` | Backup integrity/publication, CLI and desktop recovery | 249 passed; one native Windows junction skip; zero failures. Focused Ruff and whitespace checks passed. |
| Corrected #358/#359 `173f18d3` | Network cleanup/deadlines, enrichment, CSAF cache, optional dependencies and tooling locks | 109 passed; zero skips or failures. Focused Ruff passed. The inherited lock-file trailing blank line was removed during integration. |
| Combined `c6b215c5` | Workflow audit, both lock contracts, backend workflow and corpus checks | 141 passed; four compiler-backed corpus checks skipped because Clang is unavailable; one existing strict CODEX-5 expected failure. |
| Combined `c6b215c5`, independent reviewer | Census plus full ledger/history/ancestry/blob review | 103 passed; one existing strict CODEX-5 expected failure; no blocking record or source finding. |

The combined implementation passes repository-wide Ruff, dependency consistency,
the pinned protobuf/upb check and `git diff --check`. Python 3.12 and the declared
development/search/rules/site dependencies were installed before verification.
The offscreen Qt application starts successfully.

A full local offscreen run on the frozen implementation was started with JUnit,
preserved output and a process-result/resource receipt. Its result is separate
from the focused passes above and must be read from the PR qualification record.
This execution environment independently refuses `socket(AF_UNIX)` with
`PermissionError: [Errno 1] Operation not permitted`; no test was weakened or
skipped to conceal that limitation. A preliminary resource-wrapper invocation
could not start because `/usr/bin/time` is absent; the actual full run uses a
Python subprocess/resource recorder. No successful full local run is asserted
by this document.

## Hosted evidence and merge gate

The original #360, #361, #362 and corrected #359 QA runs all completed
successfully. Their source-specific runs are retained in
`evidence/consolidation-20261124/donor-ci.json`. The desktop stack's completed
jobs include Linux/Windows full QA, Qt repetition, Windows installer production
and separate downloaded-artifact validation, Linux packages and frozen CLI
smokes, and native Windows Ghidriff. They establish donor qualification only.

The new combined head must complete the same applicable checks. Merge through
REST with an expected-head guard only after those checks are successful and
blocking reviews are clear. Both the actual merge title and body must include
`[no release] [no deploy]`. Verify the resulting main ancestry before reconciling
the contained donor PRs. Do not delete their branches or rewrite their history.

## Remaining work

This composition does not establish full historical semantic consolidation.
Keep retained historical decisions and the separate holds on broader #312,
#316 and #320 scopes. Review unique remaining work against the newly qualified
main instead of importing older whole-file snapshots.

Release acceptance remains separate: native screen-reader/keyboard/DPI and
clean-machine checks, disconnected non-admin full-runtime installation, trust
and signing, broader CODEX-5/C6 closure, raw-source provenance, and separately
measured L1/L2/L3 accuracy. The manual pilot workflow remains unexecuted in the
retained evidence. No release, deployment, tag or accuracy claim is authorized
by this consolidation.
