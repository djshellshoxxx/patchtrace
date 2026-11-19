# Restricted Tier-R worker corpus-root repair

Recorded 2026-11-19 UTC. Base: PR #316 at
`f2b6827fc6270b96fb241b0722f2878de5a17361`.

## Confirmed defect

Windows advisory job `135257238250` fails each Tier-R case before building or
comparing anything. Its retained traceback follows `tier_r.cli` → `factory` →
`corpus`, where module-level `DEFAULT_ROOT = Path.home() / '.patchtrace-calibration'`
raises `RuntimeError: Could not determine home directory.` The shard supplies an
explicit `PATCHTRACE_CALIB_ROOT` but deliberately does not inherit `USERPROFILE`.
The unused fallback is evaluated before the explicit root can be selected.

`calib_root()` now resolves the home fallback only when no explicit corpus root is
configured. Corpus and Tier-R CLI imports do not inspect the user's home. The child
environment allowlist, root selection, `expanduser`, outside-worktree guard, native
engine acceptance and target-execution policy retain their existing behavior.
If the caller really requests the default and no home exists, the error remains.
There is no fallback into the repository or another guessed directory.

## Reproduction and verification

All commands run with Python 3.12.14, pytest 9.2.0 and `PYTHONPATH=src` against this
isolated source tree. The authored child controls remove home environment variables
and make `Path.home()` raise the same exception recorded by Windows. They verify
explicit root resolution and the real Tier-R CLI help/import path. These are
portable regression controls, not a native-Windows acceptance result.

Before the production repair:

```text
python -m pytest -q tests/test_calibration_corpus_home.py
4 failed in 19.03s
```

After the repair:

```text
python -m pytest -q tests/test_calibration_corpus_home.py tests/test_calibration_tools.py tests/test_tier_r_shard.py tests/test_tier_r_factory.py
73 passed, 5 skipped in 34.50s
python -m ruff check tools/calibration/corpus.py tests/test_calibration_corpus_home.py
All checks passed!
git diff --check
```

The five factory skips are explicitly **BLOCKED** native acceptance: required
clang, lld-link, llvm-pdbutil, llvm-dwarfdump, llvm-objdump, llvm-nm, llvm-strip and/or
MinGW tools are unavailable in this Linux environment. No native acceptance or
accuracy credit is inferred. Actual Windows advisory rerun remains required.

## Independent foundation review

Separately, unmodified PR #317 at
`88b0b52281dd314aa72f93819145a73135618bc4` was reviewed for saved-scope validation,
global revision admission before finite selection, recovery preflight and context
identity. No blocker was found in that examined repair. The following exact-source
regression selection passed:

```text
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q tests/test_kbc_saved_scope_validation.py tests/test_kbc_saved_scope_flow.py tests/test_kbc_saved_scope_revision_identity.py tests/test_kbc_card_context_sources.py
91 passed in 49.33s
```

That conclusion covers the examined foundation repair. Full required hosted checks
still control merge qualification; it is not a blanket audit or release approval.
