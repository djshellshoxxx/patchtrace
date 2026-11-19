# First native L2 pilot: preserved MISS

## Outcome

The production scheduler and Rizin adapter completed one native analysis of the frozen ELF/GCC pair and accepted its strict JSON output. The producer emitted five matches, all with similarity 1.0. The existing research ranking therefore correctly returned an empty list. The frozen expected function, `http_parser_execute`, was absent from all native rows. The unchanged exact-name per-case comparator returned `MISS`; the research receipt records `FAIL`.

This is one source-backed matching pilot, one case and one project. No percentage or confidence bound was computed. It is not formal Windows/MSVC L2 acceptance, desktop acquisition qualification, vulnerability attribution accuracy, or L3 evidence. No target was executed. No candidate-specific settings, source, oracle, aliases, or score logic were changed. Exactly one candidate analysis ran.

## Frozen identities

- Root approval is recorded separately in `approval.json` before candidate analysis.
- Original source-oracle SHA-256: `bbd619b791a64d39ec48740eebe8aeed84b0bff3dbd561b61bc0ce9aaed941d1`.
- Pilot manifest canonical SHA-256: `6167e3d3ff06f0d67ba1ceef4468dbecaeeab20556d75336459dd0bcc3d4471f`.
- Plan file SHA-256: `d6a2dc2b5a1dc59304fc2a8279b6c186537be267448cf9bd0d700e6617e6dbef`.
- PatchTrace source: `9ac9cbeb8ba1947b5e0889e03dccad769a6d155b`.
- Source tree: `eba3ca64508f9989c63dcbe0f42a90cd668ffebd`; tracked source was clean and relevant module hashes were checked before and after analysis.
- `rz-diff` 0.9.1 executable SHA-256: `536987d5d0e5d2a35689f653502dc10f8be8751a46ef2ffd888e8d514ed9712e`.
- Older ELF SHA-256: `c3914b7f5f70b88dbfc25677211347ffa86ab38a833e065a5e51a0445c26133b`.
- Newer ELF SHA-256: `96bcb8a0b8f9201d12c81e30090d933e13e7679125c26d5d604ebb0f02028df0`.

The source pair, compiler receipt, tool acquisition, archive pin verification and authored PE smoke are in the adjacent preparation artifact `/workspace/scratch/e83fbf4505c3/l2-tool-preparation/20261118T080830Z-rizin091`.

## Raw observation

Frozen native argv: `rz-diff -C -j -t functions VERIFIED_OLDER_COPY VERIFIED_NEWER_COPY`.

The production scheduler made private, SHA-256-verified copies of both inputs. The observer used the supported runner parameter, delegated the unchanged arguments/settings to `jobs.run_process`, saved its exact captured bytes and returned the same `ProcessResult`. There were no injected results or alternate analysis commands. The scheduler's built-in version probe was unmodified; an additional supported preflight probe was recorded separately.

- Native return code: 0; production status: `ok`; no production error code.
- Native analysis elapsed time: 1.9091231989987136 seconds; total pilot: 2.12 seconds.
- Deadline: 120 seconds; default production stdout cap: 64 MiB; stderr cap: 2 MiB; cache disabled.
- Native stdout: 834 bytes, complete; SHA-256 `52a42e2045d1c4d3368ed319eaf8be4ad40b5c1087806ed643a3be1e4ae7dbb2`.
- Native stderr: 108 bytes, complete; SHA-256 `545d5ce5a474fbd397e64832256bccdea1e1e7d238fc68def7e2d4720788c0fc`.
- Stderr reports `Cannot determine entrypoint, using 0x00002080.` for each shared library. This is a diagnostic clue, not a proven cause.
- Emitted functions: `fcn.00002030`, `fcn.00002040`, `loc.imp.__cxa_finalize`, `sym.deregister_tm_clones`, and `sym.parse_url_char`.
- Pre-existing static compiler evidence lists exported ELF symbol `http_parser_execute` in both binaries. Its absence from the output is not an absence from the compiled input.

## Evidence

- `raw/01-analysis.stdout` and `raw/01-analysis.stderr`: unchanged native bytes.
- `receipts/01-analysis.json`: full argv, settings, environment fingerprint, exact byte counts, input-copy hashes before/after and tool hash after execution.
- `engine-run.json`: production run record.
- `secondary-match-set.json`: production accepted match set.
- `pilot-result.json`: existing ranking and exact per-case comparison, without aggregate metrics.
- `rq-l2-native-pilot-11dab64f1a054d61-20261118T082952699329Z.json`: validated immutable research receipt using the reviewed linked-worktree identity helper.
- `run_pilot.py`: exact instrumentation; source, oracle, plan, tool and input hashes are asserted before execution.

## Recorded invocation

Working directory: `/workspace/scratch/e83fbf4505c3/l2-native-pilot/20261118T082742Z-http-parser`.

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/repair-receipt-identity/src:/workspace/scratch/e83fbf4505c3/repair-receipt-identity QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python run_pilot.py
```

The invocation exited 1 because its existing per-case comparator returned MISS. Captures use exclusive creation; this first result is not overwritten by later diagnostics.

## Review of the receipt helper

Independent read-only review of `9ac9cbeb` found no blocking issue. Focused identity plus adjacent receipt, L1, L1-run and scorerun tests: 141 passed in 1.00 seconds. Twenty-five additional temporary controls checked the real linked checkout, all three private ref namespaces, no common fallback for private refs, malformed pointers/refnames and FIFO metadata. `subprocess.Popen` was forbidden during those helper calls. No product source was edited by this review.

## Follow-up boundary

Any source diagnosis or authored-control experiment is post-measurement and belongs in a separate artifact. The original MISS, ranking, expected function and native flags remain unchanged. This candidate cannot later be presented as held-out evidence for a repair informed by it.
