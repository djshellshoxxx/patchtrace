# CODEX-6 runnable cache-hit fixture qualification — bounded successor

Source parent: `658cc814aa74d1eaebf0d7e6dd4553d06aaef0eb` on the existing archive-integrity branch. This successor leaves that branch, PR #348, CODEX-14 and main unchanged.

## Change
Added `tests/test_corpus_archive_cache_hit_shell_20261121.py`. It extracts the **actual** named Bash install steps from `.github/workflows/corpus-tier-r.yml` and executes them with tiny authored xz and ZIP fixtures. Both cached-archive positive and tampered-archive refusal paths are parametrized for rizin and Ghidra. A fake curl executable refuses accidental network fetch; pre-existing destination files distinguish clean extraction from a premature/unsafe operation. The external Ghidriff pip installation is replaced by a no-op only inside the extracted test script (the workflow remains unchanged). No analyzed binary or native tool is executed.

## Status and acceptance boundary
- Test file published on isolated successor; exact-source repository pytest and Ruff **not executed** because no clone-backed source is available in the runtime. This is implemented test coverage, not a passing-run claim.
- For a supported Ubuntu checkout, run:
  `python -m pytest -q tests/test_corpus_archive_cache_hit_shell_20261121.py tests/test_corpus_cache_archive_integrity_20261121.py tests/test_codex_pkg_workflows.py`
  and `python -m ruff check src tests tools`.
- A separate reviewer must inspect test isolation, actual YAML step selection and failure assertions. A hosted Tier R job with pinned real archives and a repeated same-key cache hit remains required for CODEX-6 acceptance.
- PR #348 live QA/Windows: both full QA, all five Qt jobs and Linux packaging completed successfully; five native jobs completed successfully in its other workflow. Its Ubuntu 22.04 and 24.04 smoke jobs were in progress when inspected. These are **ancestor** checks, not acceptance of this test-only successor.
- This is **not** a claim of main-merge eligibility, frozen CLI completion or release readiness. CODEX-1/5, CODEX-14, raw provenance, Windows manual/trust/accessibility, historical donor reviews and L1/L2/L3 remain separate.
