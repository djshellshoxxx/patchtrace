# ASM lexer budget investigation — 2026-11-19

## Finding and disposition

PR [#322](https://github.com/djshellshoxxx/patchtrace/pull/322) recorded a real
ASM budget failure: **0.156169465 seconds**, against the existing strict
**`< 0.150`** limit. The miss is 6.169465 ms (4.113%). Keep that failed result.

The same gate subsequently passed in both hosted Linux and Windows QA, and the
unchanged tokenizer passed all 218 focused tests in this investigation. Neither
the lexer nor its test changed between #322's base and head. The evidence does
not establish a lexer-code regression introduced by this PR, or the cause of
the original miss. Indirect effects from the larger suite and environment remain
possible; attributing the archived miss to host load or garbage collection would
be speculation.

Profiling identifies the per-token assembly scan and allocation path as the
hot path. Two candidate optimizations failed to demonstrate a useful, consistent
improvement and were rejected. The accepted code change only preserves all five
raw samples in future budget-failure messages. The production lexer, acceptance
threshold, repetition count, input and timed-call boundary are unchanged.

## Source and environment identities

- Investigated PR head: `f2458aae22ea6177be64cfc2fb439a79950f00ff`.
- PR base: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.
- Original diagnostic source: `8efb7a4501bdcea77f6aca68f92c5459af47a838`.
- Hosted merge reference: `ded94401f023414a4a6d77df5946182c324203b2`, merging the
  investigated head into the above base.
- `src/patchtrace/codetext/tokens.py` has the same Git blob at base and head:
  `10bdd826799e74e1cf030a7b73962d95661f52d4`.
- `tests/test_codetext_tokens.py` has the same Git blob at base and head:
  `5180a37a39914e2ffc8891a6db2edf937059380f`.
- Local investigation: CPython 3.12.14, Linux 6.18.57, glibc 2.41; nine visible
  CPUs. GC enabled with thresholds `(700, 10, 10)`.
- The original diagnostic's archived environment also identifies the same
  CPython 3.12.14 build, Pydantic 2.14.2/core 2.50.2 and Qt 6.12.0. Its private
  interpreter/source paths differ; no original heap, GC or scheduling telemetry
  is available. `original-diagnostic-environment.json` is retained from
  `evidence/phase7-gates-20261119.zip`.
- Pydantic 2.14.2/core 2.50.2, PySide6/shiboken6 6.12.0, protobuf 7.36.2,
  pytest 9.2.0, Hypothesis 6.170.16, Pygments 2.21.0. Exact installed versions
  and source SHA-256 hashes are retained in `environment.json` in the archive.

The lexer and 200k-character gate predate #322. Commit `4d976f4` changed only the
separate hostile-name timing assertion; it did not change this 150 ms gate.

## Original failure and current hosted results

The preserved [original record](TEST_RESULTS.md) identifies group 021 as
727 passed, one failed, one skipped and four xfailed. Its failed node is
`tests/test_codetext_tokens.py::test_200k_characters_tokenize_within_the_budget[asm]`.
The original executor's raw group logs were not available in this workspace;
this investigation verified the committed record, not a recreation of that run.

Hosted [QA run 44539958881](https://github.com/djshellshoxxx/patchtrace/actions/runs/44539958881)
tests the merge reference above. Downloaded JUnit artifacts explicitly include
the ASM case with no failure, error, skip or xfail:

| Hosted leg | Exact ASM gate | Whole testcase time | Full pytest result |
| --- | --- | --- | --- |
| Linux, Ubuntu 26.04, CPython 3.12.16 | Passed | 0.789 s | 23,473 passed; 50 skipped; 6 xfailed, 2,344.92 s |
| Windows Server 2025, CPython 3.12.10 | Passed | 0.859 s | 23,394 passed; 130 skipped; 5 xfailed, 3,434.03 s |

**These JUnit durations cover all five calls and testcase overhead. They are not
the fastest individual lexer call.** The unchanged passing assertion proves at
least one call was below 150 ms; successful tests did not retain its exact value.
Both legs also passed the C tokenizer and comment-prepass budget tests.

Verified artifact ZIP identities (the original ZIP/XML payloads were parsed in
memory, not retained in this investigation archive):

- Linux artifact `14551339403`: 405,510 bytes, SHA-256
  `01c2e13049e39a79d46ba6595e82925c720cd6f62150d4cf1e0759710e8c7629`.
- Windows artifact `14553213725`: 415,086 bytes, SHA-256
  `a4b664294bbe7520039b0da87e39219f9d796013bde1ec9e8cb1aaac0fadddbf`.

`hosted-qa-evidence.json` records job URLs, environments, testcase outcomes,
artifact identities and the distinction between testcase and per-call timings.
These hosted results qualify that existing merge reference, not a later commit.

## What the benchmark measures

The test repeats a seven-line Ghidra-like assembly fixture and slices exactly
200,000 Python characters. Fixture construction is outside the measured call.
It invokes `tokenize(text, 'asm')` five times through `_elapsed`, takes the minimum,
and compares it with 0.150 seconds. Returning and discarding the token tuple
occurs inside `_elapsed`, so disposal is included. There is no explicit warmup
or GC adjustment in the test.

The fixture SHA-256 is
`202e0b0c6f3fb49f953378a8fe90ef164977a188ca8460f69be7b552f6d8e77c`.
It produces **73,896 tokens**, **67,000 regex matches** and **25,618 matched words**.
The difference between token and regex-match counts includes the separately
created newline tokens.

The runtime lexer is the project's own stdlib implementation. Pygments is a
development oracle, not the performance bottleneck or a runtime dependency.

## Profile and allocation observations

In one instrumented `cProfile` call, `tokenize` took 0.163 s and `_scan_asm`
accounted for 0.144 s cumulatively, including about 0.099 s attributed to its
body and regex iteration. Token construction accounted for about 0.013 s,
`Match.end` 0.009 s, and list append 0.008 s. Profiling adds substantial overhead;
**these are hotspot observations, not acceptance timings**. The lexer already
memoizes word classification and uses `tuple.__new__` for `Token` construction.

A separate 20-call observation used GC callbacks without changing GC enablement
or thresholds. Each call observed 105 collections, mostly generation zero.
Summed elapsed intervals between GC start and stop callbacks ranged from approximately **4.825 to
19.397 ms**, with a **12.484 ms median**. Observed total scan times ranged from
42.498 to 78.797 ms. This demonstrates a material allocation/collection cost in
the present process. These intervals include collection, callback overhead and
any scheduling delay; they are not an isolated measure of GC CPU time. This is not
evidence of what happened during the original group 021 failure.

The first exploratory 15-call measurements per language overlapped dependency
installation. They are retained in `baseline.json` for completeness and are not
used for candidate speed comparisons. The unchanged-source focused pytest run
completed separately: **218 passed in 5.04 s**.

## Controlled candidate experiments

Each experiment used three 200,000-character workloads: the exact gate fixture,
instructions with varied labels/addresses, and a denser instruction stream.
For each workload, ten blocks alternated original/candidate order. Each variant
had one warmup followed by five timed calls per block. GC remained enabled.
The table reports the median of the ten per-block minima; all 300 raw samples
per experiment are retained. These diagnostic warmups are not changes to the
acceptance test. No full-line cache or benchmark-specific production path was
introduced.

Both variants run in the same process with the expected parity-output tuple
retained. These warmed comparison measurements are diagnostic benchmarks, not
exact reproductions of the bare acceptance-test environment. The conclusions
apply to these tested candidates, not every possible regex or `findall` design.

| Candidate | Workload | Original median block-best | Candidate median block-best | Change in time | Candidate faster blocks |
| --- | --- | --- | --- | --- | --- |
| Trailing regex kind markers | Gate | 40.375 ms | 40.238 ms | -0.34% | 5/10 |
| Trailing regex kind markers | Varied labels/addresses | 35.427 ms | 34.696 ms | -2.06% | 7/10 |
| Trailing regex kind markers | Dense instructions | 72.693 ms | 70.607 ms | -2.87% | 5/10 |
| Per-line `findall` scan | Gate | 41.109 ms | 42.996 ms | +4.59% | 2/10 |
| Per-line `findall` scan | Varied labels/addresses | 38.447 ms | 40.634 ms | +5.69% | 3/10 |
| Per-line `findall` scan | Dense instructions | 76.511 ms | 74.009 ms | -3.27% | 7/10 |

The marker experiment moved named captures to empty trailing kind markers while
preserving the matched language. It passed 20,128 deterministic whole-match
text/span/group-index comparisons and exact public token comparisons for all
three workloads. Its small, inconsistent gain does not justify the change.

The `findall` experiment replaced each Python-visible match with a tuple of
captured alternatives, calculating offsets from captured text lengths. It passed
5,000 deterministic full-token comparisons and all three workload comparisons,
but regressed both the actual gate and varied-address workload. It was rejected.
Neither candidate is part of the production change.

## Accepted change and validation

`test_200k_characters_tokenize_within_the_budget` now retains the same five
measurements in a tuple and adds this information to an assertion failure:

- language and actual character count;
- all five raw float samples;
- fastest sample and the unchanged 0.150-second budget.

An explicit synthetic message control failed before the change because the
additional diagnostics were missing, and passed afterward. Its injected sample
values are labelled synthetic in both the script and logs; they are not a second
observed lexer failure. Independent review verified the unchanged timing region,
sample count and strict boundary. Passing samples are retained in this report's
benchmark evidence, not automatically added to pytest's JUnit output.

After the diagnostic patch, the same tokenizer selection passes again:
**218 passed in 4.84 s**. Configured whole-tree Ruff and `pip check` pass.
The repository-required unsplit full-suite run was also started. At the
[2026-11-19 checkpoint](evidence/asm-lexer-full-suite-checkpoint-20261119.zip),
it was still running at 26%; no terminal result was available. This is explicitly
not a full local pass and is not substituted for final-head hosted qualification.
The checkpoint ZIP is 803 bytes, SHA-256
`d9b4310260c90617f0dd07eee080bc7137d2615ecbf6027e7b7aa88f400a17ff`.

## Reproduction and evidence

From a checkout with the repository's dev dependencies installed:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_codetext_tokens.py
QT_QPA_PLATFORM=offscreen python -m pytest -q --junitxml=qa-results.xml
python -m ruff check src tests tools
python -m pip check
```

The [investigation archive](evidence/asm-lexer-performance-20261119.zip) contains
26 payload files plus a SHA-256 manifest: source identities, focused test
receipts, raw candidate measurements, original probe scripts, GC observations,
profiles, synthetic diagnostic controls and normalized hosted evidence. Its
size is 64,149 bytes and SHA-256 is
`00b6a400e75319556e59502b89022ad7c2f2f0c28d167b6bde187026b961b602`.
Every payload hash and ZIP integrity check passed. The separate aggregate run
is not included in this focused evidence archive. The probe
scripts retain their observed absolute checkout paths; adjust those paths to
replay in a different checkout. Their candidate code is experimental evidence,
not an accepted implementation.

The original failure remains part of #322's history. Reopening lexer optimization
should require a reproducible miss or a candidate with repeatable improvements
across the actual gate and varied inputs, followed by semantic parity checks.
This investigation does not resolve the PR's separate release or native-acceptance
blockers and does not authorize a main merge or release.
