# Output credit completion and aggregate budget — November 2, 2026 (UTC)

Source `a14255715b051b0e5500786049669f77789943d9`, tree
`9fa4779bf8031878ded162ebc64328db01ab3a1d`, based on
`692e9b009c9f4bba5edceb2a97c207713152d4cb`. This is a separate follow-up to
the Windows stat compatibility repair. Independent review found no blocking
issues in this source; this is helper review, not a GitHub approval or native gate.

## Defect and boundary

PR #157 review [4436071863](https://github.com/djshellshoxxx/patchtrace/pull/157#discussion_r4436071863)
identified that the full aggregate credit manifest reused the single-output
64 MiB budget and could fail after providers finished. The library withheld the
assembled report; the CLI's existing ValueError envelope classified that runtime
failure as exit-2 usage/contract error. The CLI did catch the exception.

A constructed reduced-budget control recorded one provider call, a valid
582-byte normalized output and a 583-byte simulated cap. The aggregate failed;
the exact output and managed marker remained, with no credit manifest. This is
not a demonstrated production corpus above 64 MiB, native evidence, or a reason
to widen the limit. The preserved JSON records the actual control result.

## Change and invariants

The aggregate manifest now has its own explicit, unchanged 64 MiB constant.
The pure preflight helper and finalization share the exact builder, validation
and serialization budget. The existing successful report, credit and engine
output wire formats remain unchanged. Transfer adoption belongs to a separate
reviewed change; this commit supplies its preflight API only.

A completion sentinel is published exclusively before any credit publication.
Its owned identity comes from the publishing file descriptor. Every credit and
directory check finishes before removal; owned removal is the final success
transition. Initial publication, postcredit verification and removal failures
remain incomplete. Readers refuse any sentinel or diagnostic filename, even a
malformed file or broken link, without falling back to legacy credit.

After assembly, a typed evaluator exception retains the complete report and
original cause. Exclusive best-effort diagnostic marker/report writes preserve
the report without promoting it to credit. Their attempted and successful paths
and errors are explicit. Even two failed diagnostic writes cannot make an
already published credit readable while its sentinel remains. Prior completed
stores cannot be finalized again or marked failed. The CLI returns exit 1,
failed/uncredited, and includes report data when diagnostic report storage fails.

This retains the existing local-integrity boundary: no lock against arbitrary
same-user hostile mutation or full power-loss durability on every filesystem.

## Local verification

- 140 focused checks passed, 3 expected legacy warnings, 3.19 seconds:
  completion/budget, output persistence, credited replay, Windows clock controls
  and report/schema tests.
- 15 existing CLI checks passed, 2 native-tool-dependent fixtures skipped,
  1.56 seconds. This host lacks the required clang/LLVM toolchain; skipped
  fixtures are not acceptance evidence.
- Changed-file Ruff and `git diff --check` passed. Generated schemas add only
  `EvaluationFailure.json` and `OutputCompletion.json`; existing generated
  schemas/examples did not change.
- Exact budget boundary and one-byte overflow use small valid synthetic data.
  Failure controls cover initial sentinel creation, credit publication,
  postcredit verification, sentinel removal, one/both diagnostic writes,
  unexpected diagnostic exception, foreign sentinel identity/content, existing
  user files, prior completion and public reader refusal. Ordinary successful
  manifests remain byte-identical to the same canonical document.

Some older output-write injection tests previously selected every filename
outside the two successful managed files. They now target the actual normalized
output filename, preserving their intended per-output failure scope while
completion failures have dedicated controls. The prior credit-failure test's
expected message now recognizes the explicit incomplete state.

The adjacent JSON binds source files, logs/JUnit, and the compressed raw evidence
archive by SHA-256. Full integration, actual native Windows and final evaluation
remain separate gates owned by the coordinator. No real training, native engine,
corpus evaluation, performance run or remote publication occurred in this scope.

## Independent review

The reviewer repeated all 140 focused checks (3 expected legacy warnings,
2.60 seconds) and independently verified child-process exits immediately after
sentinel publication and after credit publication. Both output and training
readers refused those incomplete runs without a diagnostic exception handler
running; a completed process remained readable. A two-report manifest passed
at exactly 7,882 bytes and failed with a 7,881-byte budget in both preflight and
finalization; preflight wrote no files and retries remained refused. These are
process-exit controls, not power-loss durability or hostile-writer locking proof.
The adjacent independent-review JSON binds the source and archived control
script/results; source and test bytes stayed unchanged through the QA commits.
