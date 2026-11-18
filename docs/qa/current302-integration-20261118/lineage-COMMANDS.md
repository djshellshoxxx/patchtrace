# Executed review commands

Python: `/workspace/scratch/3a6632a6e5ff/venv/bin/python`.

Each source was checked out in a separate detached worktree. No used worktree was reset or modified:

| Source | Worktree |
| --- | --- |
| `6cc6b6b77564e12eaec2917877d94525a69c7102` | `/workspace/scratch/e83fbf4505c3/review-304-lineage-6cc6b6b7` |
| `121ffb0bcdd6af4f24e5035389d4709dffddf263` | `/workspace/scratch/e83fbf4505c3/review-302-lineage-121ffb0b` |
| `237d216f0784d429bfc5c61103100346576e0831` | `/workspace/scratch/e83fbf4505c3/review-integrated-237d216f` |

## Eight authored scenarios

Executed from `/workspace/scratch/e83fbf4505c3/lineage302-review-20261118`, once per source, with the source worktree substituted in `PYTHONPATH` and respectively `304-results.json`, `302-results.json`, and `237d-results.json` as output. The script uses exclusive creation and intentionally refuses to overwrite retained results. For replay, use a new output filename.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/review-integrated-237d216f/src:/workspace/scratch/e83fbf4505c3/review-integrated-237d216f QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python reproduce.py 237d-results.json
```

## Exact cross-head and helper-compatibility tests

The two files in `cross-head-tests` are unchanged copies of incoming tests. Explicit source and support-module paths make them test the selected production checkout. The incoming and previous sources were run separately for the copied files and for `test_predecessor_value_compat.py`; their JUnit filenames identify the source and test group. The integrated invocation combined the groups:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/workspace/scratch/e83fbf4505c3/review-integrated-237d216f/src:/workspace/scratch/e83fbf4505c3/review-integrated-237d216f:/workspace/scratch/e83fbf4505c3/review-integrated-237d216f/tests QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q -p no:cacheprovider -c /workspace/scratch/e83fbf4505c3/lineage302-review-20261118/pytest.ini --junitxml=/workspace/scratch/e83fbf4505c3/lineage302-review-20261118/237d-cross-head-and-compat.xml cross-head-tests test_predecessor_value_compat.py
```

## Focused repository tests

Executed once in the incoming worktree with `302-focused.xml` and once in the integrated worktree with `237d-focused.xml`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. QT_QPA_PLATFORM=offscreen /workspace/scratch/3a6632a6e5ff/venv/bin/python -m pytest -q -p no:cacheprovider --junitxml=/workspace/scratch/e83fbf4505c3/lineage302-review-20261118/237d-focused.xml tests/test_kbc_lineage.py tests/test_kbc_lineage_certainty.py tests/test_kbc_lineage_ambiguity.py tests/test_kbc_resolver.py tests/test_kbc_resolver_architecture.py tests/test_kbc_resolver_bounds.py tests/test_kbc_pairs_index.py tests/test_kbc_pairs.py tests/test_kbc_service.py tests/test_kbc_contracts.py
```

## Targeted lint

Executed in the integrated worktree; exit 0, `All checks passed!`:

```bash
PYTHONDONTWRITEBYTECODE=1 /workspace/scratch/3a6632a6e5ff/venv/bin/python -m ruff check --no-cache src/patchtrace/kbcorrelation/lineage.py src/patchtrace/kbcorrelation/resolver.py src/patchtrace/kbcorrelation/service.py tests/test_kbc_lineage_ambiguity.py tests/test_kbc_resolver_bounds.py tests/test_kbc_pairs_index.py
```

## Fixture-only proof

The exact commands, working directories, environment overrides, and 60-second bounds are stored in `237d-stale-fixtures-red.receipt.json` and `237d-corrected-fixtures-green.receipt.json`. The green invocation imports frozen integrated production source and executes the external copied files. Its only changes are the two false evidence flags in the resolution doubles; no production fallback or assertion changes were made.
