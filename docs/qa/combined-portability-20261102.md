# Combined candidate portability repairs — 2026-11-02

These changes follow local merge
`7dc6ab09aadf088faa0b34a0e8a5ca64963539e9` (tree
`fcf68b5cd75b11d9cd6718ca6def12e917c678f7`). They adjust test setup and Git text
checkout attributes; no production parser, tool pin, workflow compiler choice,
or native execution policy changes.

## Reproduced failures and repairs

1. The callgraph integer-guard subprocess test failed with
   `ModuleNotFoundError: callgraph_graph_support` when the parent pytest command
   used only `PYTHONPATH=src`. Pytest's test-directory import path does not
   propagate to the child. The test now supplies absolute paths to this checkout's
   `tests`, `src`, and root, then retains any inherited `PYTHONPATH`. The child
   still uses its explicitly pinned integer guard and the constructed ingestion
   checks. The production process environment is unchanged.
2. The corpus-workflow assertion interpreted the Linux job's compiler path with
   host-specific `Path`. The exact `/usr/bin/x86_64-w64-mingw32-gcc-win32` value is
   absolute under `PurePosixPath` and not absolute under `PureWindowsPath`. The
   assertion now uses the target job's POSIX path rules. The job remains
   `ubuntu-latest`, and both its compiler variant and package assertion are
   unchanged.
3. A clean Git index checkout with `core.autocrlf=true` converted the reviewed
   Java export script and both pinned synthetic C sources to CRLF. All three
   then failed their existing SHA-256 pins. Three explicit `text eol=lf`
   attributes preserve the reviewed bytes. Repeating the same Git checkout
   procedure produced zero CRLF lines and matched every original pin. The pin
   JSON is byte-for-byte unchanged.

| Pinned text | CRLF lines before attributes | Original SHA-256 matched after attributes |
|---|---:|---|
| `docs/qa/ExportBinExport20261102.java` | 38 | Yes |
| `tests/fixtures/old.c` | 4 | Yes |
| `tests/fixtures/new.c` | 5 | Yes |

The checkout control used a separate temporary repository containing the three
original files plus `.gitattributes`, staged those LF bytes, enabled
`core.autocrlf=true`, removed the working copies, and restored them with
`git checkout-index -f`. It repeated the restore after adding only the new
attributes. Both sets of actual/expected hashes are retained in the receipt
archive. This is a deterministic Git newline-conversion control on Linux;
it is not a native Windows test.

## Validation and remaining gates

- Before the helper fix: **1 failed** in 0.66 seconds, with the missing helper
  import preserved in the console and JUnit receipts.
- After all three repairs: **37 passed** in 1.29 seconds using
  `QT_QPA_PLATFORM=offscreen PYTHONPATH=src python3 -m pytest -q
  tests/test_callgraph_count_suffix_guard.py tests/test_native_bindiff_harness.py
  tests/test_unified_corpus_workflow.py`.
- Whole-tree `python3 -m ruff check src tests tools` and `git diff --check` passed.
- The harness tests use constructed data/mocked setup and no compiler, JVM,
  exporter, BinDiff process, or compared target binary is executed.
- Fresh Windows/hosted execution remains required. The Windows backup
  byte-integrity and wrapped-summary UI failures are not declared repaired here.
  Root integration owns the separate backup follow-up and the final immutable
  complete suite.

`combined-portability-20261102.tar.gz` retains the failed helper run, final
focused run, Ruff output, checkout hash controls, and target/host path comparison.
The tracker hash in the earlier recovery receipt refers to the completed merge
slice before these additional QA/tracker entries.
