# RapidFuzz dependency/cache audit — 2026-11-02

Read-only diagnosis of the six search failures in `/tmp/patchtrace-consolidation-full-failures-20261102.json`. No package was installed, and no RapidFuzz code was imported or executed; no source/test files were changed, and no network request or test run was performed.

## Dependency and failure diagnosis

`pyproject.toml` declares `search = ["rapidfuzz==3.14.6"]`. The `dev` extra does not include RapidFuzz. `.github/workflows/qa-windows.yml` installs `.[dev,search,rules]` with `--only-binary=:all:` in QA and Qt/package jobs, so a local environment with only the base/dev set is not equivalent to the CI dependency set.

Four failures are `tests.test_search_capability::test_rapidfuzz_backend_names[avx2|cpp|py|other]`. `monkeypatch.setattr('rapidfuzz.fuzz', ...)` must first import the parent module; all four traces fail with `ModuleNotFoundError: No module named 'rapidfuzz'` before testing the backend-name mapping.

The other two are `tests.test_search_synergy::test_typo_suggestions_and_rapidfuzz_absence` and `test_similar_mode_lists_suggestions_not_hits`. Both expect a `FormatLine` suggestion and receive an empty suggestion list. Production `SearchService._suggestions` explicitly returns an empty tuple with the unavailable warning when `fuzzy.available()` is false; similar mode is then `unsupported`. The recorded failures are consistent with the same missing dependency. A fresh-process focused rerun after restoring the pinned extra is still needed to confirm the complete disposition; no passing result is claimed here.

The seven relevant dependency/search/test files are byte-identical between `/tmp/patchtrace-final-20261102` and `/tmp/patchtrace-publish-20261102`. The reviewed pyproject SHA-256 is `beb9e3cd21a713510819a1f77276f540ee64baed75a7eabcbfbf9c6f102de490`.

## Existing cached wheel

- Path: `/root/.cache/pip/http-v2/b/8/6/1/0/b86108b8ebaafe675a219e480baa7a01a6b408483f9506fbb797cafe.body`
- Bytes: **3,168,023**.
- SHA-256: **`0debb5f43662ea84d2f0228a0c7407ff647f9c3d13f3b692efff0cde46eebce0`**.
- Metadata: **RapidFuzz 3.14.6**, requires Python >=3.11.
- Wheel tags: **cp312-cp312-manylinux_2_27_x86_64** and **cp312-cp312-manylinux_2_28_x86_64**; native Linux x86-64 wheel, not a Windows wheel.
- Installable filename derived from package metadata/tags: `rapidfuzz-3.14.6-cp312-cp312-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl`. The HTTP cache stores the body under its hash key rather than retaining the original wheel filename.

The adjacent pip `cc=4` cached response records HTTP 200, `x-pypi-file-project=rapidfuzz`, version 3.14.6, Python tag cp312, type `bdist_wheel`, and the same content length; response date is 2026-11-02 07:54:57 GMT. This is existing pip-cache provenance, not a new independent upstream signature/digest verification.

All **66 wheel RECORD hash/size entries** were verified with no mismatch. All 66 payload entries are byte-identical to the earlier pip-installed package in `/workspace/scratch/58b37459f316/patchtrace/.venv-continuation/lib/python3.12/site-packages/rapidfuzz` and matching dist-info. The installed distribution has 105 RECORD entries, 67 hashed entries, all verified; the extra hashed installed entry is installation metadata. Its RECORD SHA-256 is `6d1bfbc066394df4380b60165dcf455ffa43ba9fcf8f47da7f614080efb4f31b`.

## Handoff

The coordinator may copy this existing cache body to the derived `.whl` filename, verify the stated SHA-256, and install it offline into the isolated test venv. Do not install into the shared global runtime or use unrelated synthetic pytest wheel fixtures. Start a new Python/pytest process because the optional-dependency registry is populated at module import. Re-run the six unchanged failed nodes first; exact-head hosted QA remains the cross-platform qualification. No test weakening or repository dependency change is indicated by these six traces.
