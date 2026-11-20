# Generation 20 — Winbindex whole-container source-loss adversarial inspection

Reviewed baseline: draft PR330 head `e428a5bdb21e9d3501e08166b9c1c673e3842193`, branch `codex/patchtrace-winbindex-body-gap-20261120-g19`. It remains untouched. Candidate isolated branch: `codex/patchtrace-winbindex-container-gap-20261120-g20`.

## Original defect and source proof

In `src/patchtrace/acquisition/winbindex.py:_entry_rows`, source before repair:

```python
rows, bad = [], 0
windows = entry.get('windowsVersions')
for version_key, updates in (windows.items() if isinstance(windows, dict) else ()):
```

If an accepted SHA/fileInfo entry had an absent `windowsVersions` or a value such as `[]`, `None`, or a string, the loop never ran, `bad` remained **zero**, and no rows were returned. When a sibling entry produced one valid KB row, the index appeared to have zero coverage gaps despite this discarded entry. Generation19 forwards `parsed.skipped_bodies` to the resolver, but this missing counter was not populated for a malformed *outer* container.

Exact source/semantic checks: current `main` and the retained donor `work/winbindex-publication-20261105` use the same conditional expression in `_entry_rows`; the immediately preceding PR329/330 source does also. The earlier generation19 repair changes `wiring.py`, not this parser admission path. The tested variation is new relative to those sampled donors. This is a bounded comparison, **not** completion of the historical head census.

A local isolated standard-library reproduction of the conditional returned **0** for `[]`, `None`, an invalid string and missing key, where the contract requires **1**. This reproduces the algorithmic defect only: no original full repository test was run locally.

## Contract-first repair and tests

SPEC-31-D was committed at `38afc95eb52b97dc3742831d1ecc1cd4c1a000f6` before the tests and code. New synthetic regression tests at `tests/test_kbc_winbindex_container_gaps_20261120.py` were committed at `0d8ae7bd1f60b82aee97fe401e3eb536b54abcbb`. Parser implementation commit is `f5043094b6004e36d6b1e0774a786ad2f5cb8a6a`.

The code adds an early `return rows, 1` only when `windowsVersions` is missing or nonobject, leaving dictionary handling exactly as before. Tests cover four malformed container shapes, current workspace resolver gaps and imported receipt, an explicitly empty dict, one malformed top-level SHA entry with no double-count, and the independent `parse` acquisition candidate API. No source identity, timing, thresholds, files or raw data are changed.

## Executed evidence and limits

An eight-case local `pytest` check passed in **0.05 s** on a standard-library **standalone mirror** of the modified container admission expression. The baseline missing-counter observation and corrected behavior were included in that mirror. These are *not* tests importing the real `patchtrace` source; the checkout could not be cloned from this runtime (GitHub DNS unavailable). The new repository test file, full `QT_QPA_PLATFORM=offscreen python -m pytest -q`, repository-wide `python -m ruff check src tests tools`, schema validation, native tests, and Windows/Qt/package gates are **not** locally qualified. No empirical L1/L2/L3 accuracy finding follows from synthetic tests.

## Adversarial considerations and nonclaims

- Accepted `windowsVersions: {}` is an explicit observed empty container and must not be classified as malformed. This negative control is present.
- A rejected top-level `fileInfo` is counted only in `skipped`, never double-counted in `skipped_bodies`; there is an explicit regression.
- An entirely absent source file still results in no historical loss count under the generation16 reset; this patch does not change that.
- A whole container gap is one *discarded source unit*, **not** a claim about the number of missing KBs/builds. A source may actually have zero releases; the state is incomplete rather than proven negative.
- Upstream `parse` remains unchanged for acquisition candidates; no new network access, binary execution, unbounded read or import side effect is introduced.
- Full raw Winbindex entries/index population, exact resolver membership, latest-source ordinary-file replacement, Linux forced export, native Qt disposition and Windows trust remain separate blocked scopes.

**Reviewer independence:** This is the implementing coordinator's adversarial inspection; a separate independent human/worker signoff was not available and must not be inferred. Qualify exact combined source with hosted source-pinned tests and have an independent reviewer challenge the loss-count semantics and compatibility before integration. Do not merge/release from this record.
