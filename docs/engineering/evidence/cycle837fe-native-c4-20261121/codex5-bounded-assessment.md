# CODEX-5 bounded assessment checkpoint

Status: OPEN. No implementation or dependency installation attempted. The parent reprioritized an actual Windows native blocker and requested that this read-only pass stop promptly. This checkpoint preserves the concrete work for a later complete implementation.

## Exact source and scope

- Assessed local commit: `0a270822935fb372fc181f3e2573fe60d9a16a53`.
- Assessed complete tree: `6c2a8d018ccc00bf65ef074579604b40627f7658`.
- Published candidate supplied by parent: `daee337c48c63dda8aeac149c407e900c79dcc86` (PR #349). This assessment did not modify it, another worktree, a Git ref, or any global ledger/QA/index.
- Read AGENTS.md, relevant module-index entries, CODEX workflow and packaging audits, CODEX regression test, current pyproject and site requirements, bundle wheelhouse specification, current backend pin, and pertinent builder logic/test names.
- Current workflow census covers all 21 workflow files and preserves actual run scripts, runner selections, Python setup configuration, matrices, indirect tool references, and other download/install command lines.
- Historical scan covers all 364 captured available branch-head trees, unique lock-like file paths/blobs, and all 108 distinct historical workflow blobs. Scope does not include a semantic audit of every helper body or every commit between captured heads.

## Concrete result

There are 42 explicit pip-install steps/lines in 38 job definitions across 20 of the 21 workflows. Counts are static source counts, not matrix-expanded executions. Every observed Python setup in those installation jobs selects moving patch series `3.12`. Runner coverage includes Windows latest/2022 and Ubuntu latest/22.04/24.04. There is no separate Python minor-version matrix in the currently observed install jobs.

The full per-job census is `workflow-installation-census.json`; this table is a compact navigation aid:

| Workflow | Explicit pip install steps |
|---|---:|
| `backend-bundle.yml` | 3 |
| `corpus-tier-r.yml` | 6 |
| `diff-and-score.yml` | 1 |
| `live-backend.yml` | 1 |
| `live-bindiff.yml` | 1 |
| `live-capa.yml` | 1 |
| `live-intel-tools.yml` | 2 |
| `live-kbc.yml` | 1 |
| `live-kev.yml` | 1 |
| `live-nvd.yml` | 1 |
| `live-rizin.yml` | 1 |
| `live-unified.yml` | 2 |
| `nightly-fuzz.yml` | 2 |
| `optional-deps.yml` | 1 |
| `pages.yml` | 1 |
| `pilot-eval.yml` | 2 |
| `qa-windows.yml` | 4 |
| `unified-corpus.yml` | 3 |
| `unified-live-gates.yml` | 7 |
| `winbindex-pairs.yml` | 1 |

No committed full workflow dependency lock was found in the scanned historical head trees. The only lock/requirements-like path/blob pairs found by the documented filename scan were `tools/site/requirements.txt` and `docs/consolidation/evidence/dependency-current-requirements-after-bootstrap.txt`; these are not complete hash lock closures. None of the 108 distinct historical workflow bodies contained explicit `--require-hashes`, a requirements-lock reference, pip-compile, uv lock/sync, or poetry lock/install markers. This is bounded evidence against recovering a complete already-integrated workflow repair, not proof that no unconventional implementation exists anywhere in history. Five distinct historical backend builder blobs are recorded for later targeted comparison.

## Real reusable implementation already present

`tools/build_backend_bundle.py` already implements a strong private-bundle wheelhouse. It should be reused rather than replaced or described as absent:

- Per-platform CPython 3.12 Windows amd64 and Linux manylinux wheel selections.
- Downloaded artifacts verified against the current `tools/backend_pin.json`.
- A generated requirements lock containing every selected wheel's exact version and SHA-256.
- Installation uses `--require-hashes --no-index --find-links ... --no-deps --only-binary=:all:` with an explicit target/platform/ABI, and rehashes wheels before invoking pip.
- Ghidriff and mdutils source builds use verified source artifacts and `pip wheel --no-deps --no-index --no-build-isolation`; package-member byte comparisons and generated wheel hashes distinguish verified sources from locally produced wheel containers.
- Existing tests cover complete generated lock entries, Windows/Linux platform arguments, offline real-pip install, source-to-wheel comparison, and the backend metadata closure.

Current pin data is concrete: JPype1 1.5.2 per OS, pyghidra 3.0.2, packaging 25.0, mdutils 1.6.0 source archive, and Ghidriff commit `4f5d895fcbb1eacd65efd81145922c15bb7e741d`. Wheel/source digest provenance is recorded as PyPI JSON, vendor digest/listing, Sigstore verification, or deterministic git rebuild/member comparison. The Windows Python and Ghidriff source placeholders described by older module/spec prose are resolved in the actual current pin file; do not re-report them as current blockers. The current pin's `ci_lane_freeze` field still explicitly says the separate live-backend pip resolution was not captured and is unverified.

This private runtime closure does not lock the host interpreter's workflow bootstrap, application, dev tools, site tooling, signing verifier, or editable build requirements. The bundle's offline source-build path also depends on the host already having suitable builder packages installed, so those builders belong in the missing host/build lock.

## Minimum complete implementation scope on resumption

1. Preserve direct runtime choices from `pyproject.toml`: PySide6/shiboken6 6.12.0, pydantic 2.14.2, protobuf 7.36.2; preserve rapidfuzz 3.14.6, yara-x 1.21.0, iced-x86 1.21.0, PyInstaller 6.22.3, site segno 1.6.6/Pillow 12.3.0, and sigstore 4.5.0. Do not silently upgrade or unify versions between independent runtime closures.
2. Capture complete target-specific resolved closures for application/runtime, optional search/rules, dev/test/package tooling, site+pytest, pilot pytest+hypothesis, signing verifier, and each distinct external-engine policy. Current dev constraints contain ranges and the local build-system uses `setuptools>=75,<100`; exact selected transitive versions and artifact identities must be acquired rather than invented from requirement text.
3. Resolve and download approved artifact candidates separately for Windows amd64 CPython 3.12 and every materially different Linux/ABI lane. Use actual wheel metadata/markers to validate closure, preserve per-artifact filename, version, target tags, digest, source URL, provenance, and license evidence. A lock generated from Linux alone cannot establish Windows closure.
4. Explicitly handle current external-engine variants: full-SHA Ghidriff VCS installs, explicit pyghidra 3.0.2 combinations, dynamically selected `GHIDRIFF_VERSION` in diff-and-score, and completely unversioned Ghidriff in winbindex-pairs. Determine and preserve their intended selection policies before changing them. Reuse verified backend sources where they match the lane policy; otherwise produce separate reviewed source/artifact records. No casual version bump or licensing expansion.
5. Freeze/lock the builder bootstrap, including pip policy and required setuptools/wheel/build backend dependencies. Install that complete third-party closure from hash-verified wheel artifacts, then install the local checkout separately with `--no-deps --no-build-isolation` so PEP 517/660 isolation cannot download an unlocked backend. Ordinary local editable directories/VCS installs cannot be made into complete artifact locks merely by appending `--require-hashes`.
6. Wire every one of the 42 current explicit install sites, plus actual indirect installers, to its appropriate complete lock. The current workflow scripts and invoked helper inventory are retained for this work. Keep already hash-checked vendor native archives separate from pip closure. Evaluate setup-python/setup-java patch drift and runner/apt provisioning against the broader CODEX-5 reproducibility contract; apt/runner contents cannot be claimed reproducible from Python locks.
7. Retain an offline wheelhouse/install provenance receipt and resolved distribution inventory. Verify metadata closure, no missing dependencies, and no unexpected network/build-isolation fetch. Use clean native Windows and Linux runners for install/import and actual build/smoke gates. Qt/optional native extras, PyInstaller packaging, and external-engine runtime compatibility need real platform execution; lock parsing alone cannot prove them.
8. Replace the shallow regression only with meaningful full-coverage checks when the implementation exists. Test omitted transitive hashes, substituted artifact bytes, wrong target selection, open build isolation, changed direct requirements, unhandled workflow install sites, and local editable handling. Existing backend wheelhouse regressions can cover reused code rather than being duplicated.

## Existing check reproduced, without weakening it

Command: `/workspace/scratch/837fe19aae3a/combined-venv/bin/python -m pytest -q --runxfail tests/test_codex_pkg_workflows.py::test_pip_downloads_require_hashes`.

Result: exit 1, `1 failed in 0.56s`. The assertion reports unhashed workflow install scripts. `--runxfail` intentionally exposes the known CODEX-5 failure; the production strict-xfail marker remains unchanged. No full test suite, installs, target binaries, or native engines were run.

The existing test accepts any whole run script containing `--no-index` or `--require-hashes`, even if another command in that script is unlocked. Therefore making this one assertion pass is insufficient. `--no-index` alone does not authenticate artifacts; disabling hash enforcement, partially hashing a closure, or splitting strings to evade the checker is not a fix.

## Remaining blockers and handoff

No approved complete workflow transitive wheel closure, Windows resolution receipt, exact builder closure, or native install/build validation was acquired in this pass. No broad dependency resolution or network package installation was started. The assignment was deliberately checkpointed at the parent's request to release capacity for the observed Windows defect. A complete CODEX-5 repair is a distinct cross-platform dependency/reproducibility change, not a safely recoverable one-line workflow flag patch based on the evidence now available.

First follow-up should inspect the five recorded historical backend builder variants and the actual current helper install paths, then define minimal reusable target lock groups before spending time on artifact resolution. Continue preserving admission/tests, engine choices, license gates, and no-paid-call boundaries.

## Primary source verification

Official pip documentation was read during assessment:

- https://pip.pypa.io/en/stable/topics/secure-installs/ — complete hash checking requires pinned and hashed dependencies; multiple artifact hashes support multiple targets; local installs need a separate dependency-free step.
- https://pip.pypa.io/en/stable/topics/repeatable-installs/ — version pins alone do not authenticate package bytes; wheelhouses may be OS/architecture specific.

These are supporting methodology, not proof that any project dependency has been resolved. No package hash or target availability was inferred from documentation alone.

## Evidence files

- `workflow-installation-census.json`: exact workflow sources, source hashes, matrices, jobs, Python versions, install lines and referenced tools.
- `source-receipt.json`: source SHA/tree, important file hashes, current parsed pyproject, site requirement text, complete current backend pin.
- `historical-lock-inventory.json`: 364-head coverage, candidate file contents/blobs, 108-workflow-blob marker search, five backend builder variants, explicit scan scope.
- `manifest.sha256`: integrity of this checkpoint.
