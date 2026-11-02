# Native MSRC missing-field provenance recovery — 2026-11-02

This is fresh, offline author verification of a small reimplementation on base
`141f8176d4dbcebe23dada481a4fe8660a332dcb` (`codex/real-msrc-adapter-20261101`).
Previously unpublished local work was unavailable after the workspace reset; no old commit,
review result, or test count is used as evidence for this change.

## Scope

Three diagnostic seams in `sources/cvrf_msrc.py` now distinguish absent keys from present invalid
values. An absent `DocumentTracking.CurrentReleaseDate`, vulnerability `CVE`, or remediation `Type`
is diagnosed at the existing parent object, with the missing field named in the detail. A present
invalid value, including JSON null, keeps its exact field pointer. The source changes do not alter
acceptance, status interpretation, revision ordering, namespaces, network access, or persistence.
SPEC-31-B B3.1 records this locator rule.

The new `tests/test_kbc_msrc_provenance.py` uses the existing hash-pinned factual projection in
`tests/fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json`. Mutations are negative controls, not
additional vendor statements. Tests cover each omitted key, seven present-invalid values per key,
all public imported-document pointers, unaffected row filtering, and a closed/reopened workspace
whose decompressed stored bytes, SHA-256, source size, diagnostics, and imported records are retained.
The factual fixture is unchanged. Sockets are disabled by the existing test fixture.

## Fresh results

All commands used `/workspace/scratch/142cb233d750/venv/bin/python` from the isolated recovery
worktree, with `PYTHONPATH=.:src:tests`; pytest also used `QT_QPA_PLATFORM=offscreen`.

| Check | Actual result |
|---|---|
| New test file against unchanged adapter at the base commit | **6 failed, 22 passed in 1.41s**; the three omitted-key and three reload cases fail on nonexistent field pointers |
| New test file after the three source repairs | **28 passed in 0.65s** |
| Related parser/import/index/store selection below | **319 passed in 6.45s** |
| `python -m ruff check src tests tools` | **All checks passed** |
| `git diff --check` | **Passed** |

Focused command:

```sh
QT_QPA_PLATFORM=offscreen PYTHONPATH=.:src:tests /workspace/scratch/142cb233d750/venv/bin/python -m pytest -q tests/test_kbc_msrc_provenance.py tests/test_kbc_msrc_cvrf.py tests/test_kbc_cvrf.py tests/test_kbc_cvrf_fetch.py tests/test_kbc_index.py tests/test_kbc_store.py tests/test_kbc_csaf_bridge.py
```

The integration owner runs the required full suite on the combined source. No full-suite result,
independent review, current-head CI, Windows acceptance, live MSRC check, or expanded GT06 acceptance
is claimed by this author receipt. No target binaries were executed, and no remote writes occurred.

## Verified file content

| File | SHA-256 |
|---|---|
| `src/patchtrace/kbcorrelation/sources/cvrf_msrc.py` | `e451b845199f59e42f5e41a5479cb549b025e4b248a376942b066caa88d16835` |
| `tests/test_kbc_msrc_provenance.py` | `c7f67697f7e770b2a51c5e4855501966276cb721909f419cd520110473153c25` |
| `docs/specs/kb-cve/31-B-msrc-reverse-index.md` | `e96d9a8c2ea47dcc23471bf10c567e64300fa751e0da64be9765fb9b8ecf8420` |
