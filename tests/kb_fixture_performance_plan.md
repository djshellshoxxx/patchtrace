# KB fixture performance plan

This is a proposed measurement plan, not a claim that any budget has been measured or passed. All numeric targets below are UNVERIFIED until run on the reference Windows CI hardware defined by the integration owner.

| Workload | Proposed budget | Measurement boundary |
| --- | ---: | --- |
| Search 10,000 normalized KB/CVE/product rows in a warm in-memory index | p95 <= 2.0 s | Search call only, after fixture and index construction |
| Sort and page 100,000 pair candidates | p95 <= 5.0 s | Candidate selection and deterministic ordering; exclude PE parsing |
| Peak incremental memory for 100,000 metadata-only candidates | <= 256 MiB | Process RSS delta from before fixture load |
| Cancel a bounded in-process metadata operation | <= 250 ms | From cancellation signal to worker completion, measured with events |
| Render first page of 100,000 candidates | <= 100 ms | Windows GUI thread; virtualized model, first page only |

The source QA specification separately proposes a cached 1,000-row lookup under 500 ms and requires measured Windows responsiveness. These 10,000-row and 100,000-candidate values are initial engineering targets inferred by scaling the described workloads; ratify them before using them as release gates.

Use generated synthetic rows, not copied MSRC or Winbindex records. Record operating system, CPU, Python and Pydantic versions, commit, fixture digest, warm/cold state, wall time, peak memory and PASS/FAIL/BLOCKED/NOT_RUN status. Keep performance tests separate from correctness tests. Do not execute candidate PEs or package payloads.
