# Independent portability review

**APPROVE** `ca80cc0f310ad1a82174cd17ee1fa8443b016b73`, tree `9da4dcd465cc2bf8d245a58a714c7315831ef382`, against the previously reviewed parent `7dc6ab09aadf088faa0b34a0e8a5ca64963539e9`. No blocker found.

Review and tests used immutable Git objects plus separate snapshots at `/tmp/patchtrace-combined-review-7dc6ab09` and `/tmp/patchtrace-portability-review-ca80cc0`. No production edits or remote writes were made.

## Findings

- The callgraph subprocess test explicitly prepends the actual checkout's absolute `tests`, `src`, and root directories to a copied child environment, preserving inherited PYTHONPATH afterward with the platform path separator. It does not change production process policy. The pinned interpreter integer guard, real ingestion assertions, timeout, raw-identity checks, and exact-record precedence remain unchanged.
- `PurePosixPath` is appropriate for the compiler path inside the actual `ubuntu-latest` workflow job. Compiler/package pins and workflow execution are unchanged. Host Windows path semantics previously rejected this valid Linux path.
- Three explicit `text eol=lf` attributes preserve the already reviewed text bytes through autocrlf checkouts. The native harness implementation, its pin manifest, the Java source, and both synthetic C sources are byte-identical to the parent. No pin was recalculated or acceptance weakened.
- QA accurately distinguishes deterministic Linux checkout controls and constructed test data from native Windows/native tool acceptance.

## Independent evidence

Parent snapshot with `PYTHONPATH=src`:

```text
tests/test_callgraph_count_suffix_guard.py::test_guarded_counts_preserve_raw_text_and_exact_precedence_through_real_ingestion
1 failed in 0.60s
ModuleNotFoundError: No module named 'callgraph_graph_support'
```

Fixed snapshot:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 -m pytest -q \
  tests/test_callgraph_count_suffix_guard.py \
  tests/test_native_bindiff_harness.py \
  tests/test_unified_corpus_workflow.py
37 passed in 1.26s
```

Ruff passed on both changed Python files.

A separate temporary Git repository was staged with the parent attributes and unchanged LF source bytes, then restored using `git checkout-index -f` with `core.autocrlf=true`. After replacing only the attributes with this commit's version, the checkout was repeated:

| File | Before: CRLF lines / original pin | After: CRLF lines / original pin |
|---|---|---|
| `docs/qa/ExportBinExport20261102.java` | 38 / mismatch | 0 / match |
| `tests/fixtures/old.c` | 4 / mismatch | 0 / match |
| `tests/fixtures/new.c` | 5 / mismatch | 0 / match |

The actual workflow path `/usr/bin/x86_64-w64-mingw32-gcc-win32` is absolute under POSIX rules and not under Windows rules. Relative and Windows-drive negative controls remain nonabsolute under the target POSIX contract.

No compiler, JVM, exporter, BinDiff process, or compared target was run for this review. Fresh hosted/Windows checks remain separate final-integration gates.
