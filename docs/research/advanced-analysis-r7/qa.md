# R7 QA evidence ledger — advanced binary security research

**Status:** research-only; no native acceptance or security accuracy claim.  
**Date:** 2026-10-30. **Baseline:** main `a04f5a299a8d4afef023261e52e08d14678cf1e7`; owner branch `research/r7-advanced-binary-analysis-20261030`; draft PR https://github.com/djshellshoxxx/patchtrace/pull/134

## Executed local verification

**Host:** Linux-6.18.57-x86_64-with-glibc2.41, CPython 3.13.5, Pytest 9.0.2 (not production Python 3.12). Full source repository checkout unavailable; tests imported the two isolated R7 prototypes and needed no network or target binaries.

```text
$ cd /mnt/data/patchtrace_r7
$ python3 -m pytest -q tests/test_r7_patterns.py tests/test_r7_slicing.py
........................................                                 [100%]
40 passed in 0.08s
$ python3 -m compileall -q tools/research/r7 tests/test_r7_slicing.py tests/test_r7_patterns.py
[success, no output]
```

Coverage by example: cross-side provenance syntax rejection; transitive SSA def-use and explicit control edges; negative unrelated guard; forward dependencies; within-graph-only completeness; missing definition; ambiguous non-SSA multiple definitions; unlisted control; memory alias and indirect call unknown flags; deterministic cyclic graph; depth/node caps/frontier; input size bounded before full iterator materialization; malformed opcode and field rejection; cancellation; missing seed and unsupported direction. Source tests are under `tests/test_r7_slicing.py`.

Tests were written against behavior first. Two additional red failures prompted slicing hardening: unbounded materialization of generator inputs, and false silence for `INDIRECT` and unrecognized P-code opcodes. The pattern pilot was also developed red/green: a qualified guard plus an unresolved other control edge initially emitted a candidate and now correctly abstains. Current slicer subtotal is **27 passed**; structural pattern subtotal is **13 passed**; combined **40 passed, 0 failed, 0 skipped**. This is not an integrated baseline regression run.

## Synthetic structural pattern pilot

`tools/research/r7/patterns.py` implements an explicitly **nonsecurity** structural guard-to-memory-operation hypothesis, with outcomes `candidate`, `not-observed`, or `inconclusive`. The caller supplies already-matched old/new sink IDs, SSA-like inputs and declared control dependencies; no Ghidra provenance, actual postdominators, alias analysis or branch polarity is verified.

13 focused test cases cover one synthetic positive; unrelated-value, already-guarded-old and missing-control negatives; ambiguous definition, unresolved old/new control, mixed unknown control, mismatched sinks; invalid scopes, missing sink, bounded generator, and no CWE/definitive verdict field. These are behavioral regression checks, **not** empirical TP/FP/TN/FN on binary truth labels.

## Synthetic benchmark

```text
$ python3 -m tools.research.r7.bench
```

30 single-call repeats each; synthetic eight-node independent chains; warmed process; graph construction excluded from timing; result includes index construction; only one call traced with Python tracemalloc, NOT RSS. Source input and exact numbers: `synthetic-benchmark.json`. Summary:

| Input operations | Selected synthetic sites | Median ms | p95 ms | tracemalloc KiB |
|---:|---:|---:|---:|---:|
| 128 | 8 | 0.0562 | 0.0709 | 35.74 |
| 1,024 | 8 | 0.3861 | 0.4314 | 262.70 |
| 4,096 | 8 | 1.8314 | 2.3387 | 1,036.01 |

These numbers are unrelated to real machine-code root-cause precision/recall and are not a speed claim for native Ghidra analysis.

## Remote / native acceptance boundaries

- Remote branch Actions: multiple earlier exact-head runs were auto-cancelled as subsequent commits were pushed. Latest observed on commit `c0fd0834b60eb5e9431f84d58b08dae7d54ba1a3` was **queued**, not passed or failed. Re-evaluate latest HEAD after the documentation/tracker updates. Check https://github.com/djshellshoxxx/patchtrace/pull/134/checks.
- Full repository Linux suite and Ruff: **not run** (no full local source checkout; local Ruff unavailable). No claim of passing.
- Windows source, packaging and native Ghidra/pyghidra: **not run**, research environment lacks the installed native backend.
- Production `program-ir/1` import, high P-code extraction, binary patch pairs, actual CFG control dependence, native RSS/timeout: **not measured**.
- R1–R6 open draft PR heads change independently. R3 PR #129 owns edits to `docs/qa.md` and `tasks/todo.md`; root QA was not overwritten because the GitHub connector returns truncated contents for `docs/qa.md` and rewriting it risks loss of unique work. R7 subdirectory record here is complete, and `tasks/todo.md` has a nonoverlapping R7 section added at its start.

## Failure/unknown invariants to maintain

1. Unknown data/control dependencies from alias/indirect call may never be silently treated as absence or safe equivalence.
2. The synthetic evidence scope contains syntactically valid SHA256/RVA **provided by the caller**. This does not verify bytes, output locations, compiler, run ownership or actual Ghidra SSA.
3. `status = bounded-within-supplied-graph` means only that the **supplied ephemeral graph** has no **recognized** missing dependencies; it does not prove full code coverage.
4. A changed guard and a memory sink are not enough to infer risk or CWE: source-to-sink link, path reachability and old/new behavior are unmeasured.
5. The small synthetic benchmark does not justify changing the main engine's `ChangeFacts`, model confidence, product claims or release gates.

## Next QA tasks

1. Reconcile exact-head PR #134 and identify result of Actions (do not equate queued or cancelled with pass).
2. Obtain a pinned native Ghidra GZF fixture and compare high P-code instruction-to-site provenance.
3. Build real x64 PE positives, tricky negatives, compiler noise controls and expert labels.
4. Add property/mutation tests plus real native program-analysis benchmarks (time/RSS/unknowns) and compare current semantic engine.
5. Inspect hostile parser/model inputs and report export injection/consent.
6. Run full Linux and Windows CI, including Ruff and native Ghidra; record all results with exact commit/version.
7. Coordinate root `docs/qa.md` update with R3 without reconstructing a truncated file or overwriting worker changes.

**Acceptance:** no R7 production or project completion claim until all required native, evidence, accuracy, CI and review gates have been observed.
