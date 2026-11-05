# E1/E2 Winbindex record publication — 2026-11-05

Isolated branch `work/winbindex-publication-20261105`, worktree
`/tmp/pt-independent-index-publication-20261105`, coordinator base
`58cc60f752750a4455cd22f3b547db4a5b609c79`. Production scope is only
`kbcorrelation.wiring.save_winbindex_record` and its import of the existing
atomic writer. SPEC-31-D was amended before each guarantee change. The module
was already indexed; no shared module-index/tracker or source-adapter ownership
was changed.

## Reproduced defects and repair

The record importer staged into the predictable `<record>.tmp` path with
`Path.write_bytes`. A preexisting symlink or hardlink at that name caused a
successful import to overwrite unrelated foreign bytes. A preexisting regular
file was overwritten and published as the record, and a directory at that name
blocked an otherwise valid import. Failed replacement retained the overwritten
foreign temporary path; the old path had no fsync stage.

Initial authored controls: **6 failed / 2 passed in 1.08 s**. Invalid-record
preservation and ordinary explicit replacement were the passing controls.
The implementation now reuses `store.atomic_write`: exclusive unique
same-directory `mkstemp`, write/flush/fsync, atomic replace, attempt-stage
cleanup on failure. Preexisting fixed `.tmp` paths are untouched and never
published. No second atomic writer was introduced or the shared helper changed.
Intermediate focused result: 56 passed in 2.87 s.

Adjacent review reproduced a second defect: an existing `winbindex` directory
symlink sent successful metadata publication into an unrelated directory.
The added regression failed (**1 failed in 1.49 s**) before the directory
guard. Publication now refuses an observed symlink or Windows junction at
that workspace child before staging. The ordinary selected workspace root
retains its existing semantics.

## Completed validation

`env -u PYTEST_ADDOPTS PYTHONPATH="$PWD/src" QT_QPA_PLATFORM=offscreen python -m pytest -q tests/test_winbindex_publication_security_20261105.py tests/test_kbc_acquire_cli.py tests/test_kbc_pairs_index.py`

**57 passed in 2.64 s**, no skips. The new nine controls cover all four fixed
temporary collisions, injected fsync/replace failures with previous-record and
foreign-byte preservation, exclusive owned-stage cleanup, strict invalid JSON,
explicit same-name/date replacement preserving a prior hardlink's old bytes,
and directory-alias refusal. Existing CLI/pair selections exercise plain/gzip
replacement and recorded provenance. Socket-denial fixtures prevent live calls.
Whole-tree `python -m ruff check src tests tools` and `git diff --check` passed.

## Scope and limits

No source schema, model field, reason code, module or dependency changed. No
binary download, target execution, native compatibility, model training or
live provider evidence is claimed. Only authored metadata fixtures were used.
Native Windows junction/filesystem acceptance remains unrun. The guarantees
cover observed aliases and failures before record publication; existing
post-publication removal of the alternate plain/gzip representation remains
unchanged. Unique staging is not a sandbox against a hostile noncooperating
writer replacing parent/stage/final paths after checks. Independent review,
publication and exact-head full/Windows gates remain coordinator-owned.
Existing qualification/native worktrees, processes and logs were untouched.
