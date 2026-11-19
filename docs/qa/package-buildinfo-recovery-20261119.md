# Packaged build-info producer recovery

Candidate parent: `8f4ef7a8` (reviewed incomplete-project retry included). This
record accompanies the first producer implementation; independent review and
actual frozen-package acceptance are separate follow-ups.

The existing strict consumer came from historical build-info source
`62b9a3de4d1036a6e4b9bd2618372f4042b15f7f`. The current builders now prepare bounded
source and dependency observations before freezing, reject observed source/Git
changes, exclusively install `_internal/patchtrace/build-info.json` before the
package inventory, and check the built executable's bounded version JSON before
archiving. Available Windows resource commit identity must agree with the actual
Git observation. Cleanliness remains unknown; no CI environment SHA is adopted
as source identity by the record producer.

## Author verification

- Initial helper selection: 39 passed in 2.10 s. Five ordinary Ruff E701 test
  formatting findings were corrected; no runtime validation was relaxed.
- Combined helper, source/version/filter, Windows resource, full-variant and
  unified packaging selection: **233 passed in 7.98 s**, no skips.
- Normal full `ruff check src tests tools` and `git diff --check` pass.
- Raw log/XML and normal Ruff output are retained under
  `docs/consolidation/evidence/package-buildinfo-*`.

Controls cover real source edits, foreign observer imports, moving Git, absent
dependency metadata, exact record types, missing/linked/replaced package roots,
exclusive output preservation, strict process JSON, Python boolean/integer
equality, output/time failure statuses, and an authored child using the real
consumer. The authored child sets a frozen layout explicitly; it is not a
PyInstaller build or native Windows result. Before/after source observations do
not lock source throughout compilation or attest bytecode, authenticity, signing
or release eligibility.

Reproduce from the containing commit:

```bash
QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q \
  tests/test_package_buildinfo.py tests/test_buildinfo.py tests/test_version_cli.py \
  tests/test_version_git_filters.py tests/test_windows_build_resources.py \
  tests/test_build_full_variants.py tests/test_unified_packaging.py
python -m ruff check src tests tools
```

## Independent provenance finding and correction

At immutable `4af75c62`, independent review passed the existing 39 controls in
1.77 s but reproduced a real source-root error: an untracked nested source tree
without `.git` inherited the unrelated enclosing repository's commit/description.
The original JSON counterexample is retained. A new regression using the original
`4af75c62` `git_info` function failed in 1.80 s; its negative log is retained.

The shared observer now binds bounded `rev-parse --show-toplevel` observations to
the selected ordinary root before and after object/ref queries and rechecks the
root identity. It still makes no worktree status call. Enclosing repositories
become unknown; a real detached worktree remains supported. Path comparison uses
the native path type, allowing Windows separator/case equivalence without making
a native-platform claim. Changed top-level and replaced-root controls are added.

Final author source/producer/version/filter selection: **70 passed in 5.55 s**;
normal full Ruff and source/specification diff checks pass. The original negative
pytest log retains its raw trailing whitespace. Its log/XML and the original
independent results are retained separately. Independent review of immutable
`442e3961` approved the correction; 43 producer/root controls passed in 2.85 s.

## Actual Linux frozen-consumer probe

A small PyInstaller 6.22.3 onedir probe ran on immutable source
`7e610c03043b4d2b3ba4893b133993fd7b020109`, tree
`3a77280f87714329e7f89339762b84250e1e52e7`, using Python 3.12.14 on Linux. It
imports the actual `buildinfo` consumer, with Qt and the desktop CLI excluded.
The builder prepared and exclusively installed the strict record, the real
frozen executable returned the exact expected record, and changing its metadata
digest caused the checker to refuse. Total observed duration: 7.99 s.

The exact entry source, PyInstaller command, source/tree identity, record and
executable digests, returned envelope and qualification are retained in
`package-buildinfo-linux-freeze-result.json`; the build log is retained beside it.
This is an actual Linux frozen-consumer control, not a full desktop package,
Windows acceptance, compiled-bytecode attestation or release qualification.
