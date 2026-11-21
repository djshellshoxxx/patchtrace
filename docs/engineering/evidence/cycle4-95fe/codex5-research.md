# CODEX-5: bounded Pages dependency lock research

Observed 2026-11-21 UTC. Investigator: cycle4_codex5_research. This is research and
source qualification only; no repository file, branch, PR, workflow run, release,
or deployment was changed by this worker.

## Decision

The smallest self-contained CI installation lane is **the Pages site build**.
Preserve its existing Segno 1.6.6 and Pillow 12.3.0, explicitly freeze the already
tested pytest 9.2.0, and lock its four active Linux dependencies. A seven-wheel
CPython 3.12/Linux x86_64 closure is now captured and independently checked against
fresh version-specific PyPI metadata. The exact wheel files are available locally
for an implementation worker's offline installation and refusal tests.

The existing trusted backend pin does not supply this closure. It covers
PyGhidra/JPype1/packaging and mdutils/Ghidriff source archives. Its packaging 25.0
is different from the site environment's tested packaging 26.3 and must not be
substituted silently. Reuse the backend pin only for a separately scoped backend
installation change.

This Pages slice closes **one pip installation run block**, not all CODEX-5.
The global strict expected-failure mark must remain. The source audit currently
finds **42 unhashed pip-install run blocks across 20 workflow files**; those counts
describe textual run blocks, not matrix job executions or all transitive fetches.

## Source identity and provenance

- Published reference: `11f51c105bf63946f59373ae605b937c4fee607a`.
- Inspected local reference: `43b7b99706b91d7320497d35fda8ee87e7195f3f`.
- Equal complete tree: `4939056ceb0e02b419c820b9e5748c869c40a857`.
- Repository stayed clean before and after the actual pytest observations.
- Exact file SHA-256 and Git blob identities are in
  `codex5-evidence/code-inspection.json`.

Primary repository sources at that published reference:

- [CODEX-5 test and run-script reader](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/tests/test_codex_pkg_workflows.py)
- [Original workflow audit](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/docs/audits/codex-workflows-1.md)
- [Pages workflow](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/.github/workflows/pages.yml)
- [Site requirements](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/tools/site/requirements.txt)
- [Shared pytest fixtures](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/tests/conftest.py)
- [Project dependencies and build backend](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/pyproject.toml)
- [Existing backend artifact pins](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/tools/backend_pin.json)
- [Existing backend hash-lock installer](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/tools/build_backend_bundle.py)
- [Backend wheelhouse contract](https://github.com/djshellshoxxx/PatchTrace/blob/11f51c105bf63946f59373ae605b937c4fee607a/docs/specs/program-e/BUNDLE-wheelhouse-and-pyghidra-spec.md)

## Confirmed prerequisite defect: site-only CI imports application dependencies

The Pages workflow deliberately installs only the site's dependencies plus
pytest. However, `tests/conftest.py::_no_real_kev_catalog` is unconditional and
imports `patchtrace.kbcorrelation.adapters.kev`. That reaches
`patchtrace.fabric.contracts`, which imports pydantic. A fresh site-only
environment therefore fails even a static site workflow test during fixture
setup, before its assertion executes.

Actual clean-source observations:

| Environment and command | Result |
| --- | --- |
| New venv; install the exact workflow requirements; run unchanged `test_triggers_are_push_to_main_on_site_paths_and_manual_dispatch` | **1 error**, `ModuleNotFoundError: No module named 'pydantic'`, through the unconditional KEV fixture |
| Same venv/source; run all seven site test files with `--noconftest` | **243 passed, 1 skipped** in 2.98 seconds |

The one skip is exactly
`tests.test_site_screens::test_renderer_draws_the_real_gui_offscreen`, with the
existing reason that the app GUI is needed to render screenshots. PySide6 is
deliberately absent from a site-only environment. This control does not establish
native GUI or hosted Pages acceptance.

A bounded repair can explicitly isolate this site's pytest invocation from the
application-wide conftest. Keep the full application suite's fixtures unchanged,
retain every site assertion and its selection, and document why the site build
does not require application/Qt dependencies. Do not fix the site-only contract
by installing the entire application merely to satisfy an unrelated autouse
fixture. The existing global application suite still exercises the site tests
with its ordinary fixtures; that is a separate qualification environment.

Receipts:

- `codex5-evidence/site-only-baseline.json`, `.log`, `.xml`.
- `codex5-evidence/site-only-isolated-conftest-control.json`, `.log`, `.xml`.
- `site-probe-install.log` records the exact successful environment installation.

## Verified seven-wheel closure

The selected versions equal those installed in the existing tested environment.
The site input preserves its two existing pins; explicitly pinning pytest and its
previously floating transitive dependencies makes the actual observed closure
reviewable.

| Distribution | Version | Active dependency relationship on Python 3.12/Linux |
| --- | --- | --- |
| segno | 1.6.6 | No active dependency; importlib-metadata marker applies only below Python 3.10 |
| pillow | 12.3.0 | No base dependency; extras are not requested |
| pytest | 9.2.0 | Requires the four distributions below |
| iniconfig | 2.3.1 | Satisfies pytest's `>=2` |
| packaging | 26.3 | Satisfies pytest's `>=24` |
| pluggy | 1.7.0 | Satisfies pytest's `>=1.6,<2` |
| pygments | 2.21.0 | Satisfies pytest's `>=2.15`; its Windows-terminal extra is not requested |

For every row, research fetched `https://pypi.org/pypi/NAME/VERSION/json`, selected
the compatible non-yanked wheel, freshly downloaded that exact URL, checked its
full size and SHA-256, read the wheel's METADATA without executing package code,
and checked Name, Version and active Requires-Dist closure. All seven artifacts
and all four active dependency edges verified successfully. The metadata and
byte-verification timestamps are recorded separately.

Files:

- `codex5-evidence/pypi-*.json`: seven original version-metadata responses.
- `codex5-evidence/site-wheel-metadata.json`: selected filenames, source URLs,
  SHA-256 values, sizes, Python requirements and upstream upload times.
- `codex5-evidence/site-wheel-verification.json`: actual byte checks, wheel
  metadata and evaluated closure; `complete: true`.
- `codex5-evidence/wheelhouse/`: the seven verified wheel files. Reuse these for
  local verification; there is no need to commit the binary payloads.

Six wheels are `py3-none-any`. Pillow is
`pillow-12.3.0-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`.
This is a Linux x86_64/CPython 3.12 lock, not a portable lock for Windows, macOS,
ARM, PyPy or other Python minor versions. A Windows pytest closure also requires
Colorama and a different Pillow wheel. Preserve the Linux lane's explicit scope.
This verifies committed-input suitability; newly captured hashes still require
review before becoming trusted repository lock material.

## Concrete implementation handoff

1. Add a short normative specification for the site-only seven-wheel lane,
   preserving versions, Python/platform scope, normal dependency checking,
   explicit pytest isolation and existing deployment controls.
2. Add a dedicated CI lock under `tools/site/`, with every selected package pinned
   using `==` and an explicit local SHA-256 from the verified receipt. Keep the
   original two-dependency site input useful for non-CI users. Avoid claiming the
   Linux lock covers other platforms.
3. Make the Pages install command use that lock with `--require-hashes` and
   `--only-binary=:all:`. Keep dependency resolution enabled so a missing closure
   entry is a refusal, not silently ignored. Remove the separate floating pytest
   argument. Keep this install in a separate run field from unrelated commands.
4. Make the site-only test invocation explicit with `--noconftest` over the same
   seven site test files. Preserve ordinary full application QA and global
   fixtures. Preserve the actual-head `[no deploy]` condition, job permissions,
   build/artifact order and the other session's Action pin changes.
5. Use the existing verified wheelhouse for a real clean-venv offline install with
   `--no-index --find-links ... --require-hashes --only-binary=:all: -r LOCK`.
   Run `pip check` and all site tests. Verify pydantic/PySide6 are not installed in
   this isolated environment and retain the expected screenshot skip separately.
6. Add focused refusal controls: an incorrect digest rejects installation; a
   missing active transitive requirement rejects installation; the production
   install command has no extra unpinned package argument; all seven local hashes
   and direct versions are present. These controls should exercise actual pip or
   the actual checked-in command where meaningful, not only search for a flag.
7. Leave CODEX-5's global strict expected failure in place. A successful bounded
   lane leaves 41 previously identified run blocks and broader runtime/build
   reproducibility issues to classify and repair separately.

No new lock-generation framework is needed for seven reviewed requirements.
The evidence receipt can deterministically produce a draft lock by sorting its
seven rows and writing `name==version --hash=sha256:DIGEST`. Review the resulting
file against both version-specific PyPI JSON and the independently hashed wheel
bytes, then commit it. Generation is a maintenance operation; CI consumes the
reviewed lock instead of deriving fresh trust from the index on every run.

## Separate audit-test blind spot

The current CODEX-5 check examines an entire run block and accepts it if the
string `--require-hashes` or `--no-index` occurs anywhere. Pure local controls
show a two-command block with one hashed install followed by an unhashed install
is accepted; a flag mentioned only in a comment is also accepted. The ordinary
all-unhashed control is detected. All three inputs/results are retained in
`code-inspection.json`.

This is a regression-test limitation, not evidence that a currently protected
workflow is compromised. Keep its repair as a separate follow-up if it would
expand the Pages slice. A replacement should check each actual install command
and validate the referenced lock, handle comments and multiline commands, and
fail on unfamiliar supported syntax rather than silently exempting it.
`--no-index` alone establishes no remote index lookup, not a wheel-content digest
check. Explicit local project install exceptions also need both `--no-deps` and
controlled build isolation, with build dependencies already verified.

## Primary packaging guidance checked

- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/):
  hash-checking requires local pinned hashes for all requirements and active
  dependencies. `--only-binary` excludes source distributions; multiple artifact
  hashes can cover multiple wheels. Mixing unhashable local/VCS requirements into
  that install is unsuitable; separate local-project installation from the
  third-party closure. Do not use `--no-require-hashes` to claim complete locking.
- [pip repeatable installs](https://pip.pypa.io/en/stable/topics/repeatable-installs/):
  version locks and artifact hashes serve different purposes; wheelhouses are
  commonly platform-specific. A private package mirror is unnecessary for this
  bounded reviewed lock.
- [pip build-system interface](https://pip.pypa.io/en/stable/reference/build-system/):
  default build isolation installs build-time requirements independently.
  `--no-deps` by itself does not close that separate fetch path. With
  `--no-build-isolation`, the caller must supply the verified build dependencies.

The source browser returned pip documentation v26.3. The research installation
used the environment's pip 25.0.1; no behavior specific to the newly documented
`--no-require-hashes` feature was used or required. No analyzed target binary was
executed, no existing CI was retried, and no workflow was dispatched.
