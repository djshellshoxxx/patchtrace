# PW-02 terminal worker accounting correction

The narrow follow-up source `7259f86838c2181d6bdbcabe98c7a294a4499e8d`
passes **451 affected cases**, zero skips, in 1.63 seconds. The unchanged
independent five-case probe passes in that gate. No socket or child process
creation was attempted during tests, and every imported PatchTrace module came
from the exact owned checkout. Normal Ruff, package schema verification and
whitespace checks pass. Independent root re-review remains a separate gate.

## Source chain and confirmed issue

| Role | Exact commit |
| --- | --- |
| Original portable worker source | `eb50b0283cf7a46e7bd25ffc23cd78b18dfeb2e0` |
| Original immutable QA checkpoint / correction base | `f427186b9a9e3ba70dbdf90e18b63a5d90315313` |
| Appended specification and failing controls | `dcd2653fc7d79e457a02569edb8e461960f47080` |
| Four-line production correction | `7259f86838c2181d6bdbcabe98c7a294a4499e8d` |

The independent review observed that a failed terminal receipt with a pending
write exported zero confirmed bytes, but a later `complete_output(token, 1)` or
`complete_output(token, 3)` raised only after changing confirmed bytes. That
violated the terminal accounting contract. The review's positive controls
already showed that the failed parent could not continue or replay; no native
escape or unsafe project admission was demonstrated.

The original probe is retained at
`qa/pw02-worker-independent/test_terminal_accounting.py`, SHA-256
`5396faa2c3934dbabc4b889949c10695efe490fa318ecaa235643f7d3a4dcc29`.
Its independent initial packet remains unchanged:
`qa/pw02-worker-independent-20261118.zip`, SHA-256
`4e767d01a24b552c75503ff42dc02ed45fd84de15ba7060a9a3d8713240f1872`.
The original author worker packet also remains unchanged, archive SHA-256
`36c5ff29cf8fd31cc5a3c326445e32fc82c528c218f78dfea3bb593a3dc757c8`.

## Repair and controls

`complete_output` and `fail_output` now check the terminal marker before looking
up or changing output tokens, pending-entry counts or confirmed bytes. The
original first failure still propagates. Before terminal receipt emission,
completion continues to record known bytes even if cancellation or the original
deadline was already observed. Owned allocation cleanup remains permitted
after terminal failure. No new budget, retry, allowance, native action, wire
field or project behavior was added; generated schema bytes are unchanged.

The appended authored controls verify that partial/full late confirmations do
not add unreportable bytes, a rejected output-failure callback cannot consume
its still-recorded pending token, and preterminal completion preserves both
known bytes and the exact already-observed cancellation/deadline exception.
The token-registry assertion is an explicit resource-ownership oracle; it does
not stand in for native file or process evidence.

The spec-first gate at `dcd2653f` retained **5 failures / 5 positives** in 0.45
seconds: three new authored failures and the original two independent failures.
The five positives include preterminal cancellation/deadline accounting, owned
allocation cleanup and permanent parent refusal. No earlier test or assertion
was weakened. `red.log/xml/provenance.json` and `red-source/` preserve that state.

The final committed-source gate runs the five new cases, the unchanged five
independent cases and the earlier 441 affected cases. Its **451 passes** are in
`final.log/xml/provenance.json`; exact source captures are in `final-source/`.
The runner refuses overwrites, checks the original probe hash before execution,
pins the worktree's `src` and repository root, denies socket/process creation,
and uses a fresh system temporary directory outside any Git tree. The broad
runner and whole suite were not resumed.

```text
PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/3a6632a6e5ff/venv/bin/python \
  /workspace/scratch/c7a9e8d98848/qa/pw02-local-packages/worker-terminal/run_terminal.py final
```

Static commands, exact final Git/source comparisons, original probe/archive
hash verification and all ZIP member hashes are retained in this packet.
`manifest.json` identifies the archive and each immutable payload. The tracked
packet is under `docs/qa/autonomous-ci-20261118/pw02-worker-terminal/`.

This follow-up qualifies portable terminal accounting only. It does not execute
a worker, package, native decoder, target, network service or frozen executable.
Native Windows handles, inherited grants, process exit/cleanup, FDI writes,
source authenticity, KB/core composition and project admission remain separate
qualification work. All earlier unqualified native boundaries remain unchanged.
