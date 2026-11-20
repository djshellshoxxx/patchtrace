# PE manifest DTD recovery and cache invalidation

## Scope and uniqueness

Baseline: PR #322, `f2458aae22ea6177be64cfc2fb439a79950f00ff`.
Main at discovery: `fdc2696c23bdbfe7668348f25e3b336ce33039f7`.

PR #315 contains a parser-level DTD refusal that is absent from this baseline.
The recovered runtime file is exactly the file from
`5f31e8adc7e53c5799cb9764f37ed33461529deb`; its original source is
`e1c5006e51606caedd773bf079c20c145d290861`. The 19-case boundary test is
recovered from `dfa40118` without changing its assertions. Broader #319/#320/#321
trees were not adopted. In particular, their older specification would remove
the newer metadata-cache integration, so only the applicable requirement was
ported into the current specification.

The original decoded-text screen misses leading-whitespace UTF-16BE declarations.
ElementTree reinterprets the NUL-bearing text and expands the authored entity.
The recovered tree-builder callback rejects every recognized doctype. The
pure-Python ElementTree fallback receives the same Expat handler. Refusal retains
the raw-byte digest and exposes no parsed manifest facts.

## Additional integration defect

The recovered parser alone does not invalidate metadata cached by the old parser.
The new real-SQLite regression writes a version 2 cache row with the exact expanded
facts returned for the authored malicious manifest, closes the project, reopens
it, and requests a normal inspection. Before the cache repair, the old row is
reused and bypasses the new parser boundary.

Metadata cache version 3 changes both key admission and envelope identity. The
current inspector reparses verified artifact bytes, reports the refused manifest,
and retains the healthy peer artifact. The old cache row is preserved byte for
byte as historical evidence. Public metadata shapes and native-trust behavior
are unchanged. No schema generator is required for this internal cache version.

## Verification

Environment: CPython 3.12.14, PySide6 6.12.0, Pydantic 2.14.2,
pydantic-core 2.50.2, pytest 9.2.0. Tests use the offscreen Qt platform.

| Check | Result | Evidence |
|---|---|---|
| Recovered boundary tests on unchanged #322 | 8 failed, 11 passed | `evidence/manifest-dtd-baseline.txt` |
| Parser recovery plus affected metadata/cache/Qt tests | 247 passed | `evidence/manifest-dtd-recovery.txt` |
| Persisted version 2 bypass with repaired parser | 1 failed | `evidence/manifest-cache-baseline.txt` |
| Parser and cache repair together | 249 passed | `evidence/manifest-cache-recovery.txt` |
| Whole-tree configured Ruff | Passed | `python -m ruff check src tests tools` |

Reproduction/verification command:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_pe_manifest_dtd_boundary.py tests/test_pe_manifest_cache_version.py \
  tests/test_pe_manifest.py tests/test_pe_parser_security_20261105.py \
  tests/test_pe_meta_compare.py tests/test_pe_metadata_cache.py \
  tests/test_pe_metadata_cache_qt.py
```

These focused results are not a full-suite, Windows, package, or native-trust
qualification. Independent review and aggregate integration gates are recorded
in the current generation handoff; the baseline failures remain immutable.
