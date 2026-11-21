# Parser integrity fixes — 2026-11-19

Base: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`. These are authored, portable
regression fixtures; they do not establish live BinDiff, Windows, native signing
or production-feed qualification. This change does not introduce a release.

## Changes and reproduction

- Winbindex raw JSON bypassed the decoded byte budget when `compressed=False`.
  The shared strict JSON boundary now rejects over-budget bytes before UTF-8
  decoding or JSON allocation; exact-limit documents remain eligible.
- BinDiff duplicate algorithm ids silently replaced earlier names, and SQLite
  REAL/TEXT values could alias integer identifiers. Pair/file/algorithm keys
  now require SQLite INTEGER values; duplicate algorithm ids are refused while
  unique unknown integer ids with valid names remain eligible.
- A virtual table's stored CREATE text can disguise its prefix with whitespace
  or comments. Independent review also demonstrated that an attacker can forge
  a positive `sqlite_master.rootpage`; that value is not authoritative. The
  importer now requires a bounded `PRAGMA main.table_list` inventory, rejects
  virtual/shadow tables and reconciles table names before result reads. SQLite
  versions lacking this classifier fail closed with a typed unsupported error.

The applicable acquisition and BinDiff specifications accompany the changes.

## Verification evidence

| Check | Actual result |
| --- | --- |
| Initial new regression/property selection | 33 passed in 11.98s |
| Same initial tests replayed against the base source after environment recovery | 29 failed, 4 passed in 8.32s |
| Initial broader acquisition/BinDiff/stress selection | 425 passed, 1 skipped in 68.87s |
| Independent forged-rootpage/classifier review controls before correction | 6 failed, 22 passed in 2.31s |
| Corrected parser and existing BinDiff boundary selection | 107 passed in 8.62s |
| Final broader acquisition/BinDiff/stress selection | 432 passed, 1 skipped in 61.86s |
| Whole-tree `ruff check src tests tools` after correction | Passed |
| `git diff --check` after correction | Passed |

The broader selection comprises `tests/test_acquisition*.py`,
`tests/test_winbindex_parser_bounds.py`, `tests/test_bindiff*.py`,
`tests/test_secondary_bindiff.py`, `tests/test_kbc_resolver_architecture.py`,
`tests/test_kbc_acquire_cli.py`, `tests/test_tier_w_corpus.py` and
`tests/stress/test_fuzz_feeds_and_ir.py`, with Qt offscreen. The final run used
Python 3.12 and SQLite 3.53.1; the absent-classifier path has an authored control.

An earlier broad-suite and baseline-replay attempt was interrupted when the
execution environment became unavailable. Its pending results are unknown;
the completed reruns above provide the replacement evidence. A complete
repository suite is an integration gate owned by the consolidation work, not
claimed by this narrow parser slice.
