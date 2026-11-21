# CODEX-5 per-command pip audit — isolated continuation

Source base: completed C4 PR #350 head `f928a0cef29eac2b603d390c40fb86448111b91b`, which targets PR #349 `daee337c48c63dda8aeac149c407e900c79dcc86`. This is an independent unowned *audit precision* scope. Root837FE holds PR349 integration and qualification until explicit handoff or 08:30Z; neither PR349 nor PR350 was updated by this cycle.

## Implemented

- Amended the retained CODEX-5 audit contract **before** code.
- Added `tools/ci_pip_install_audit.py`, a source-only, stdlib-only scanner that inspects explicit `python -m pip install` and `pip install` invocations per shell command in GitHub Actions `run` values.
- Added `tests/test_codex5_command_audit_20261121.py`: 15 parameterized source fixtures, two additional controls and an expected-failure scan of the live workflow tree. The test distinguishes per-command flags from another install, an echo statement, a shell comment and adjacent commands.
- The existing `tests/test_codex_pkg_workflows.py` and its strict CODEX-5 xfail are **unchanged**, avoiding a conflict with the recent CODEX-1 owner changes. No workflow, package-lock, target runtime, remote-run ownership or release policy was modified.

## Actually executed / limitations

A local source-mirror under `/tmp/pt-codex5-audit` ran the same new parser and test logic against two **authored workflow fixtures** (one hashed, one unsafe): **17 passed, one CODEX-5 strict xfailed**, zero failures or ordinary skips. Python compileall succeeded. Two extra safe/unsafe standalone controls passed. This is *not* a source-bound checkout of the entire GitHub branch; the original 21 GitHub workflows were not mounted into that mirror. Exact checkout pytest/Ruff/pip, full hosted QA and an independent reviewer remain required. An attempted Ruff installation could not resolve the package index; no lint success is claimed.

Scanner bounds are deliberate: it is not a full POSIX/PowerShell interpreter or complete lock validator; indirect shell commands, environment-driven install flags and remote `--find-links` remain outside the proved contract. Treat unparseable matching commands as errors rather than success. The CODEX-5 broad package/hash-closure gate remains OPEN, and no existing xfail was removed. Pages wheel locking belongs to completed C4; this does not duplicate that implementation.

## Next worker / root handoff

1. Check the live PR349/PR350 ownership and SHA before any integration. Do not move their refs while Root837FE holds the lease.
2. Reproduce on a **full checkout of this exact source**: `python -m pytest -q tests/test_codex5_command_audit_20261121.py tests/test_codex_pkg_workflows.py`, `python -m ruff check src tests tools`, `python -m pip check`. Run the original full suite only under appropriate owned CI. All expected failures must remain strict and source-specific.
3. Give a truly separate reviewer the new scanner and tests; independently inspect quoted scalars, literal/folded blocks, comment parsing, in-line separators, zero false negatives for actual executable `pip install` in the 21 current workflows, and effect on inherited CODEX-5 semantics.
4. If reviewed, integrate this disjoint audit-only change only with root coordination and an expected-head guard; retain the existing CODEX-5 expected failure until every relevant package-install boundary is actually repaired. No automatic promotion to main/release/deploy.
5. Preserve exact-source hosted Pages, Intel Windows and all older failures, manual/native/accessibility, raw provenance, historical semantic and separate L1/L2/L3 acceptance gates.

No workers have been claimed to run in the background. No CI dispatch/retry, tag, release, deployment, main merge or branch deletion occurred.


## Post-publication exact-byte and negative-control receipt

The two locally mirrored **new Python files**, and only those files, were
independently compared using Git blob identity against connector-fetched remote
blobs: scanner `9c356458d14a6bb7e76d075868dae1cad94a7ce7`, tests
`0065c0510e179247b06ebd75910d558929080888`. Both match byte-for-byte.
The 17-pass/one-strict-xfail pytest fixture result therefore executes the
exact new scanner/test bytes, but **not** the complete remote workflow tree or
full checked-out repository. This removes ambiguity about source-mirror drift,
not the remaining hosted/peer acceptance requirements.

Three altered copies of the scanner were tested in isolation and restored
afterward. Removing shell-comment stripping, removing the `&&` boundary,
and disabling folded YAML joining each caused exactly its corresponding
parameterized test to fail (one failed, fourteen passed, three deselected per
mutation). The clean local scanner Git blob SHA was checked after restoration
and remained `9c356458...`. These are author-side mutation controls,
**not** a genuinely separate reviewer. Full raw record:
`docs/engineering/evidence/codex5-per-command-audit-20261121.json`.
