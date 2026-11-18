# WORKSTREAM J - Performance and scalability
Scope: tools/bench_enrichment.py, bench_search.py, tools/unified/bench.py, tools/research_qualification/perf_harness.py,
tools/qa_binexport_memcap.py, tests/stress/**, docs/specs/program-e/E6-test-performance-beta-plan.md,
docs/specs/kb/beta-budgets-help-and-acceptance-spec.md, performance sections of docs/qa.md
(`grep -n -i 'perf\| ms\b\|budget\|objective' <main checkout>/docs/qa.md | head -150`), tasks/plan.md ('cache-hit
objective 500 ms at 10k pairs; measured 3.1 s'), docs/research/ghidra-headless-large-pe.md,
docs/qa/ghidriff-timeout-20261106.md (PT-TIMEOUT-1..4).

List every documented performance objective/budget with: target, last measured value, date, evidence class, met / unmet /
unmeasured. Then profile-first candidates for the directive list: large binary ingestion; function matching complexity;
memory consumption; repeated analysis; caching; database query performance; parallel adapter execution; batch comparison
throughput; UI responsiveness; background worker scheduling.
You MAY run at most two short measurements (each < 90 s wall, single process) to refresh a number, e.g. the enrichment
cache-hit bench at a reduced size or a cProfile of one hot path on a synthetic input; record the command, the numbers and
that they are synthetic.
Identify concrete algorithmic hot spots from code reading (O(n^2) loops over functions, repeated JSON re-parsing, N+1 SQLite
queries, un-indexed lookups, re-hashing large files) with file:line.
actionable_now: optimizations with a measurable before/after that can be verified offline, each with its benchmark command
and the correctness test that guards it. Do not propose architectural rewrites for marginal gains.
