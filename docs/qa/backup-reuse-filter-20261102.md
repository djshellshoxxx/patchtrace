# Cached backup refusal before byte reads

Parent: published #151 `7d9dce5c228235cecb7a08f3b55895addeb05b86`.

The trust-only path previously rehashed every cached candidate, including failed SQLite verdicts and facts already incompatible with the required project, snapshot or tables. Four actual SQLite controls reproduced those unnecessary reads. The path now rejects those cached facts before reading bytes. Every eligible candidate still performs the existing full fresh hash and rechecks returned facts; the preparatory verification path still revalidates changed candidates. No new trust is inferred from metadata or a negative cache entry.

The spec also corrects “after rename” to exclusive hard-link publication. Fresh related verification:41 passed. Whole Ruff and whitespace checks passed after replacing an imported fixture that triggered F811 with an actual sample-project fixture. Initial wrong test filename collected zero tests; that log is retained separately. Four baseline failures, intermediate and final results are in the adjacent archive. Independent review pending. No throughput/native Windows or full-suite claim; the result bounds avoidable I/O, not a benchmark.

Independent review of94caeb1 found no blockers:52related checks and7additional real SQLite/cache-race/preservation controls passed. The byte-identical final4tests fail on publishedparent7d9dce5. Receipts and retained controls are adjacent.
