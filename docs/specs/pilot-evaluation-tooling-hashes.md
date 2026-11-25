# Pilot evaluation tooling hashes

## Scope and selected baseline

The advisory `.github/workflows/pilot-eval.yml` workflow runs manually on
Linux x86-64 with CPython 3.12. Its first install bootstraps pytest and
Hypothesis; its second install adds the editable application. This change
protects only the first command. The editable application and its build/runtime
dependencies remain a separate CODEX-5 gap.

Select pytest 9.2.0 and Hypothesis 6.170.17, with iniconfig 2.3.1,
packaging 26.3, pluggy 1.7.0, Pygments 2.21.0 and sortedcontainers 2.4.0.
These exact versions and wheel filenames were installed by successful Linux QA
job 136853186420 of run 44906524287 on source
`3a16290c0fcc4e0c21712fe10474a3ff33fad336`. This is a new, explicit
pilot-tooling baseline. Available Actions history contains no pilot workflow
run; do not claim a previous successful pilot run or version equivalence to one.

## Complete tooling installation

`tools/calibration/pilot/requirements-ci.lock` contains exactly those seven
distributions, each with an exact `==` version and a reviewed wheel SHA-256.
The Linux CPython 3.12 closure has five active edges: pytest requires iniconfig,
packaging, pluggy and Pygments; Hypothesis requires sortedcontainers. No extras
are requested. Windows-only, older-Python and optional-extra dependencies are
outside this Linux lane. The accepted Hypothesis artifact is its CPython 3.12
manylinux2014/manylinux_2_17 x86-64 wheel. This lock makes no Windows claim.

The workflow installs only this lock with `--require-hashes` and
`--only-binary=:all:`. Keep ordinary dependency resolution enabled: no
`--no-deps`, environment/configuration equivalent, disabled hashes, added
unpinned command argument or alternative index shortcut. An omitted required
transitive entry must cause refusal, not a silently incomplete installation.
The five pytest-related entries must match the already reviewed Pages lock
in exact version and wheel hash; do not add the unrelated site packages.

Verify all seven downloaded wheel files against version-specific PyPI metadata
and record source URLs, filenames, sizes, hashes and wheel-contained
`METADATA` requirements. Require wheel Name/Version, Python compatibility and
all active dependency edges to agree with the selected closure. Changes to
versions or accepted artifact hashes require fresh review and clean install
qualification. Preserve the earlier metadata-only assessment and its limits.

## Unchanged evaluation and wider gates

Keep the manual-only advisory trigger, read-only permissions, runner, timeout,
Action pins, second editable install, preregistration hashing, two existing
evaluation test modules, report command and aggregate-only artifact upload
unchanged. Frozen preregistration bytes, metric/gate semantics, report claims,
application dependencies and native analysis are outside this change.

The positive command census should reflect exactly one newly protected command:
the frozen starting source has 21 workflows, 203 run scalars, 42 explicit
installs, 1 protected and 41 unprotected commands; this candidate has the same
totals with 2 protected and 40 unprotected. Retain the dated starting census and
both repository-wide strict CODEX-5 expected failures unchanged.

## Qualification

- Verify the full seven-wheel identity and metadata set, then install into a
  fresh Python 3.12 environment using the normal resolver and require hashes.
- Use separate fresh environments for a wrong top-level hash, an omitted
  transitive entry with its wheel still available, and a wrong transitive hash.
  Each must fail for the intended integrity/closure reason. Installed packages,
  missing wheel files or suppressed dependency resolution must not mask it.
- Run the unchanged pilot evaluation tests and report writer on the exact
  candidate with the locked tooling and required application dependencies.
  Keep the clean tooling-only install evidence separate from application tests.
- Run affected source/workflow/registry tests, whole-tree Ruff and dependency
  checks. Preserve original failures and exact source/environment identities.
  Independent review, final-source hosted qualification, native/platform and
  release gates remain separate; this change authorizes no dispatch or release.

References: [pip hash checking](https://pip.pypa.io/en/stable/topics/secure-installs/),
[command audit](ci-pip-command-audit.md),
[PIL evaluation contract](program-e/PIL-integration-plan.md).
