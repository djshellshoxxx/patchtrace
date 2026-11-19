# Native symbol-store setup exit handling

Recorded 2026-11-19 UTC. This is a CI prerequisite repair, not native acceptance.

## Source and failure

- Baseline: `4cdee5a26837802bd90b8b50c11696b039ac9335`.
- Specification and controls: `e4c73786`.
- Tested implementation: `eb65f7fe9991167fb77c6f620240c46edc6ac702`.
- Tested source tree: `ca32dc565d64c0a443cc1fd93953c0dc8cdfdf99`.

The symbol-enabled setup step ran `seed_symbol_cache.py`, ran plain Ghidriff
through a tail pipeline, then unconditionally cleared `LASTEXITCODE`. A seed
failure could therefore be followed by the engine, and an engine failure could
be reported as successful setup. The seeded-store acceptance checks did not
independently require that positive setup to have succeeded.

The pinned [Ghidriff engine source](https://github.com/clearbluejar/ghidriff/blob/4f5d895fcbb1eacd65efd81145922c15bb7e741d/ghidriff/ghidra_diff_engine.py)
was inspected from the previously retrieved exact-source file. Its
`setup_symbol_server` saves global preferences; the deliberate cached-PDB
exception in `setup_project` is under `no_symbols`. The preceding setup command
is symbol-enabled, so it is not the intentional negative reproduction.
[Source proof](source-proof.json) records the inspected source SHA-256 and
original workflow/seed blob identities. The archive retains those two original
repository files and the unmodified red test log/XML.

## Repair

The small CI-only `tools/live_symbol_store_setup.py` runs the existing seed
script, then the same symbol-enabled engine command. Each subprocess must exit
zero. The seed failure stops before engine launch; a nonzero engine result fails
the setup. Both use the selected Python interpreter, ordinary list argv and the
unchanged inherited setup environment. Child output streams directly to CI;
the former last-15-lines filter is removed with its exit-masking pipeline.

All five variants, directory/copy preparation, runtime pins and every other
workflow step are unchanged. In particular the later plain `--no-symbols`
reproduction still requires nonzero exit plus its specific cached-PDB message,
and resets its status only after that assertion. The new helper path is added
to both existing workflow path filters. Production backend and release gates
are unchanged.

## Observed checks

The baseline guard `test_seed_setup_does_not_clear_failed_child_status` failed:
**1 failed in 2.07 s**. This is a configuration regression control, not an
executed PowerShell or native failure. The retained baseline shows the defect
directly; no claim of a native reproduction is made.

After repair, **97 passed in 3.81 s**, with no errors or skips:

```sh
PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_live_symbol_store_setup.py \
  tests/test_live_primary_environment_check.py \
  tests/test_workflows.py tests/test_unified_live_tool.py \
  --junitxml=docs/qa/native-symbol-setup-20261119/green.xml
python -m ruff check src tests tools
git diff --check
```

The seven new controls cover the setup/negative-test distinction, preserved
matrix and triggers, successful real seed copies, symbol-enabled argv and
inherited environment, seed failure preventing launch, engine exits 1 and 23,
and invalid invocation. Process controls launch authored Python children;
their fixture DLLs are inert bytes and never executed. Existing H7, workflow
and unified controls are included in the 97 total, not additional native runs.
Whole-tree ordinary Ruff passed. Whitespace checks passed.

## Remaining qualification

PowerShell is unavailable on this Linux executor. Real Ghidriff/Ghidra Windows
setup, persisted preferences, the seeded-store variants and the intentional
negative reproduction remain **NOT RUN here** and require the exact candidate's
native matrix. Zero setup exits are necessary preconditions, not a new assertion
that global preference state was independently measured. Existing native H7,
cache, containment, packaging and release requirements remain separate.
