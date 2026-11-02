# Independent review: CG-1 shared path budget

No blocking findings in the bounded CG-1 shared path-budget repair.

- Source: `0a7e2ad6c1b4409d585179d185a9249a2d5d3784`
- Tree: `7751514e42c147e04e9b5913804fb48de37b18ce`
- Parent: `1367889d549a4db290b669df4ed97ac20b553428`

## Scope and reasoning

- One query-local _PathGraph charges the existing 200,000 budget before fetching each raw forward or reverse adjacency item across bidirectional shortest reachability, reverse-distance preparation and enumeration. Membership-rejected, dead-end and cyclic candidates consume the same budget.
- Lazy CSR iterators read existing ascending arrays without row slicing or rebuilding an induced graph. The existing immutable listed set filters intermediate nodes while explicit endpoints remain eligible; whole-program traversal uses no filter. Original node order preserves the previous monotone-remap tie order.
- Forward parent discovery processes complete FIFO layers and ascending adjacency, preserving lexicographic full prefixes. Reverse equal-distance parent selection chooses the smallest forward next hop, whose shorter suffix was settled in an earlier layer. Completed meeting layers compare full path candidates by length and tuple; incomplete layers publish no witness.
- When later preparation or enumeration exhausts the budget, returned paths remain a prefix of the deterministic shortest-first result; a completed shortest witness is retained only if enumeration has not produced a path. Partial results carry the existing truncated field plus an explicit work-limit note and CLI exit3.
- Cancellation is checked at query start and before each4,096th charged adjacency retrieval, independent of accepted neighbours or queue-pop progress. Existing standalone reach, shortest-distance, SCC and CSR APIs remain compatible; allowed is a new keyword-only internal path filter.
- No numerical limit, graph schema, persistent/global cache or snapshot remapping was added. The public results remain bounded by the existing requested path count and length.

## Independent validation

- 82 passed,3 deselected in2.66 seconds. Includes actual normalized graph and CLI partial behavior, phase boundaries, deterministic witnesses, existing NetworkX differential checks and schema equality.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_callgraph_path_budget.py tests/test_callgraph_algo.py tests/test_callgraph_csr.py tests/test_callgraph_leads.py tests/test_callgraph_cli.py tests/test_callgraph_schemas.py -k "not gate_60k and not deep_chain"`
- The one explicitly authorized serial60k/447k algorithm gate passed in2.22 seconds. Its existing nonempty-path assertion and20-second objective were unchanged. Root was notified immediately upon completion; no second large gate was run.
  Command: `QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q --tb=short tests/test_callgraph_algo.py::test_gate_60k_447k_algorithms_within_budget`
- Independent400 seeded2..8-node graphs at11 budgets, varied maximum lengths and membership filters:4,400 queries matched a separate BFS oracle;1,286 were partial and457 retained a valid oracle prefix. Direct raw CSR-array instrumentation rejected any over-budget retrieval or slice copy; neither occurred.
  Command: `PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python /workspace/scratch/142cb233d750/reviews-resume/callgraph_path_budget_controls.py`
- Cancellation callback raw-read counts were exactly[0,4095]; PT-GRAPH-CANCEL occurred before the4,096th raw read, including excluded membership candidates.
  Command: `Same independent script:5,001-edge excluded-candidate cancellation boundary`
- Passed; ten changed paths and clean frozen worktree.
  Command: `Ruff on changed Python files; git diff --check HEAD^ HEAD; clean source inventory`

## Limits

- The edge budget applies per source/destination query. Multiple CLI API-target identities each receive a budget; snapshot construction and target lookup remain outside it.
- The large gate is one local correctness/timing acceptance result, not a general throughput claim. Exact200,000-read instrumentation on that large graph is author evidence; independent raw-read instrumentation here covers the bounded oracle and cancellation controls.
- The other large CSR gate and deep-chain case were not rerun. No full suite, native Windows, native disassembler, or broad#105 closure claim.
- No repository source edits, target execution, remote mutation, or GitHub approval performed.

The JSON sibling binds every changed file and retained independent control/result artifact by SHA-256.
