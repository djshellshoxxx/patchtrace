# Tier R exit-1 diagnostic retention

## Disposition

The bounded repair is ready for independent review. Missing, malformed and
unrecognized command summaries at exit 1 now enter the existing failed-command
path in both shard case steps and the independent evaluation lane. That path
retains the existing bounded reason and logs the existing bounded stderr tail.
No command parser, CLI implementation, native engine, workflow or corpus outcome
was changed.

This establishes reporting behavior with authored injected runner tuples. It
does not establish why the retained Windows Tier R command originally exited 1,
resolve the Linux missing-old-functions cases, or qualify any native execution.

## Exact source chain and ownership

| Role | Commit | Tree |
| --- | --- | --- |
| Preserved stdin QA baseline | `584e76d59405e53311e2ca9f953700407b8f0c8e` | `604183ae557f3a28cf28eda2caea2d737d89628f` |
| Spec and authored failing controls | `b8a7633f69b015a7080a6086580659008f90d041` | `ffe665a0ee53fb38d7fcd69102a595c4d1983b3c` |
| Production repair | `4cdd463fa8d903c8b2ea6d2149d5003d23978122` | `a102cb9c3948f103fc72f1759f65da0b7691a2eb` |

The dedicated branch is `codex/tier-r-exit1-diagnostics-20261118` in the reused
`pw02-local-packages` worktree. Its only source/spec/test changes are
`tools/calibration/tier_r/shard.py`, `tests/test_tier_r_exit1_diagnostics.py`,
section 13 of `docs/specs/known-answer-corpus.md`, and one Tier R module-index row.
The source change adds 17 lines. `source-boundary.json` verifies ten inherited
stdin source/test/spec/QA paths byte-for-byte against the baseline; the separate
stdin branch still points to that exact baseline. Its existing module row is
unchanged.

## Recognition rule

JSON extraction remains separate and unchanged. An exit-1 summary is recognized
only when its exact string command is one of `fetch`, `build-suite`, `build-card`,
`aa`, `noise`, `mutate`, `evaluate`, or legacy `suite`, and its string status is
`ok`, `findings` or `failed`. When status is absent, legacy `suite` alone may use
a nonnegative integer `disagreements` count; booleans are excluded. A present
invalid status cannot fall back to the legacy count.

This is recognition rather than a complete result schema or an argv binding.
The original `{"command":"suite","disagreements":1}` positive remains accepted
in both lanes. Current fetch/evaluate `status: failed` summaries retain their
established exit-1 `findings` classification for this narrow repair. Existing
A/A nonidentity precedence, timeout, blocked, other-exit and exit-0/skipped
behavior is covered by unchanged and new positive controls.

Newly failed case steps stop the remaining steps of that case. Independent
evaluation retains its existing scheduling. The existing limits remain a
240-character one-line reason and a 20-nonempty-line / 4,000-character stderr
tail. Raw stderr remains in the log, outside aggregate shard JSON. Existing
sanitization, metadata absorption and merge validation were not broadened.

## Evidence and results

| Gate | Exact source | Result | Exact project/tool imports |
| --- | --- | --- | --- |
| Spec-first red, 84 authored plus 4 original controls | `b8a7633f` | 46 failed / 42 passed / 0 skips; 0.75 s | 71 |
| Focused replay of the same 88 cases | `4cdd463f` | 88 passed / 0 skips; 0.62 s | 71 |
| Affected gate | `4cdd463f` | 265 passed / 0 skips; 1.23 s | 72 |
| Workflow Ruff scope | `4cdd463f` | `src tests tools`: passed | Not a pytest import receipt |
| Diff whitespace check | Baseline through `4cdd463f` | Passed | Not applicable |

Times in the table are pytest's printed summaries; JUnit and full process times
remain separately recorded in the raw receipts. Every test run recorded zero
source drift and zero denied runtime network/child attempts. The audit hook
refuses socket creation/connect/bind/DNS, HTTP connections, subprocesses and
spawn/fork/exec/system calls during the test gate. Local read-only Git commands
used to pin identity completed before that hook. No compiler, native target,
engine, network request or package installation was performed.

The affected gate consists of 84 new cases, the unchanged original 4 cases,
48 existing shard cases, 16 A/A cases and 113 spec-registry cases. It exercises
both reporting lanes, all recognized command/status combinations, legacy counts,
unrecognized/malformed objects, bounded reason/tail behavior, case-step stopping,
independent evaluation, and persisted shard/merge failure classification.

The first lint invocation mistakenly used `ruff check --no-cache .`. It scanned
files outside the workflow's configured `src tests tools` scope and reported
1,112 findings. Its complete output and exact command are retained as `ruff.*`;
no findings were suppressed and no unrelated files were edited. The corrected
workflow command is retained as `ruff-workflow.*` and passed. The first lint
wrapper stopped before its diff check; the separate successful `diff-check.*`
receipt records the check actually performed.

## Original evidence remains unchanged

The original public probe remains at
`/workspace/scratch/c7a9e8d98848/qa/tier-r-fb09-diagnosis/test_exit1_diagnostics.py`.
Its SHA-256 is
`ab1629e9f61a3ca6b380f2abc4488cf2327a7891dcac977a1c6c25c3235d806e`.
It still contains the original two negative and two positive controls, and
contributed two failures/two passes to the new red run before all four passed
on the repaired source.

`original-diagnosis/` contains a byte-identical copy of the prior sealed packet,
its manifest/seal and the original probe. The old archive is 227,300 bytes,
78 members / 77 payloads, SHA-256
`feb8c805e92d3d9747968c73175719c6e38dddd3c42e36526d0b6d14912ca283`.
It retains the initial harness/import failures and the final old-source v3
2-red/2-positive result with 38 pinned imports. Those records remain historical
failures; no repaired-source claim is applied to them.

## Reproduction and packet layout

`affected.command.json` holds the complete Python invocation, exact source,
environment, snapshot hashes and pytest argument list. The test-file portion is:

```text
tests/test_tier_r_exit1_diagnostics.py
/workspace/scratch/c7a9e8d98848/qa/tier-r-fb09-diagnosis/test_exit1_diagnostics.py
tests/test_tier_r_shard.py
tests/test_tier_r_aa_failures.py
tests/test_spec_registry.py
```

The runner uses `-q -p no:cacheprovider`, an owned system-temporary basetemp and
JUnit output. It pins the checkout's `src`, repository root and test helper
directory before pytest imports, removing editable-install ambiguity. Each
loaded project/tool module is hashed against the exact commit's Git blob.
The test/probe and snapshot bytes are checked again after execution. Each
phase has its own captured runner, command, log, JUnit, import and exit receipts;
the runner refuses overwriting those paths.

Raw evidence is under `/workspace/scratch/c7a9e8d98848/qa/tier-r-exit1-repair`.
The committed checkpoint contains this README, `evidence.zip`, `manifest.json`
and `seal.json`. The ZIP includes all raw payloads and its own manifest, but not
itself or its outer seal. The seal binds archive size/hash and member count.
`source-snapshots.json` binds captured source bytes to full Git commits and
blobs; `source-chain.json` and `source-boundary.json` bind ancestry and ownership.
The QA checkpoint commit is documentation/evidence only; production remains
exactly `4cdd463fa8d903c8b2ea6d2149d5003d23978122`.
