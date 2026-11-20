# Generation26 QA boundary — older-source ambiguity

Current main, #325, retained Winbindex donor and parent #336 all permit a first-matching older SHA/basename source row. Two synthetically conflicting historical source bodies (BASE and KB) reverse their reported KB identity when the list order is reversed, without a change in binary SHA.

Isolated `/tmp/patchtrace_g26_primitive.py` mirrored the production selector for deterministic bug reproduction, then the proposed guard. `PYTHONPATH=/tmp python -m pytest -q /tmp/test_patchtrace_g26_primitive.py` reported **6 passed in 0.06s**. This is **not** checked-out PatchTrace code; no full source suite or Ruff acceptance is claimed. Real repository tests in `tests/test_kbc_acquire_older_ambiguity_20261120.py` (eight cases) are authored and require an exact-source runner. Local Github DNS failed; Ruff is not installed. PR336 hosted checks were still active at last inspection, so no duplicate full-suite run was launched.

No observed native Windows, Qt, package, provider or empirical L1/L2/L3 improvement for this new source. Do not score `facts:unverified`. Preserve the original ASM threshold and interrupted aggregate's unknown cause.
