# Pages build isolation and dependency hashes

## Scope and existing failure

The Pages build uses Python 3.12 on the workflow's Linux x86-64 runner. It
installs site tooling and pytest only; installing the desktop application or
its dependencies is outside this job's contract. The existing invocation loads
the shared application `tests/conftest.py`, whose automatic KEV fixture imports
application modules. A clean site-only environment therefore fails before a
site test runs because `pydantic` is absent.

This change applies only to the Pages dependency-install and site-test commands.
Action references, push/path triggers, permissions, artifact upload, deployment
environment, and the `[no deploy]` condition retain their existing behavior.
The application's ordinary test invocation and shared fixtures stay unchanged.

## Dependency installation

`tools/site/requirements.txt` remains the portable build-only declaration for
Pillow 12.3.0 and Segno 1.6.6. A separate
`tools/site/requirements-ci.lock` contains the complete Pages test/build closure
for Linux x86-64 and CPython 3.12: those same build tools, pytest 9.2.0, and its
required dependencies. Each distribution is pinned with `==` and has a SHA-256
digest of an explicitly reviewed wheel. The workflow installs that lock with
both `--require-hashes` and `--only-binary=:all:`; no extra unpinned package is
appended to the command. Dependency resolution remains enabled so an omitted
transitive dependency is refused rather than silently ignored.

Hashes must come from freshly retrieved version-specific PyPI metadata and be
verified against downloaded wheel bytes. Preserve the filenames, source URLs,
metadata, sizes, hashes, and wheel `METADATA` requirements in the engineering
evidence. Changes to pinned versions or accepted wheels require review and a
fresh clean-environment installation. This lock qualifies only the named Linux
CI lane; other operating systems and the repository's other pip-install lanes
remain separate work. CODEX-5 remains open until those other lanes are resolved.

## Site test isolation

The Pages job continues to collect every `tests/test_site_*.py` file and runs
their existing assertions. Its pytest command uses `--noconftest` so the
application's automatic fixtures do not import desktop dependencies, and
`--disable-plugin-autoload` so unrelated installed plugins do not become an
implicit part of the declared site environment. Pytest's built-in fixtures
remain available. Do not add skip markers, suppress failures, or remove site
tests to achieve a passing job.

The existing screenshot-regeneration test requires the application GUI and
may report its existing PySide6-unavailable skip in a site-only environment.
This is separate from the site build and must remain visible in results;
site-only execution does not establish native GUI or screen-reader acceptance.

## Verification

- A clean environment installs only the locked distributions and passes
  `pip check`, the full site-test selection, and the real site build.
- A damaged SHA-256 and an omitted required transitive dependency must each
  make a fresh hashed pip installation fail. Controls use local wheels and
  never execute an analyzed target.
- Source checks require pinned, unique, hashed entries for the full declared
  closure, preserve the build-only version declarations, and verify the
  workflow's install/test commands without changing deployment behavior.
- Retain the original application-fixture failure, exact source identities,
  commands, logs, and explicit skips. Local tests do not prove a hosted Pages
  deployment; no dispatch or deployment is part of this change.

References: [pip hash-checking requirements](https://pip.pypa.io/en/stable/topics/secure-installs/),
[pytest command-line options](https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags),
[Pages deployment control](pages-deployment-control.md).
