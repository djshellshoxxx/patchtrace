# Strings no-force source ownership — 2026-11-19

Base: `d436a7ec571efa75dcd627ca9835c65f60e09c74`, the selected combined
foundation before this repair. Its export implementation comes from
`e14331018d53370e9f4cdf70bd485349a3fec496` (#308 source). This is a scoped
no-force correction. It does not qualify forced overwrites or release packaging.

## Confirmed failure

The writer exclusively created a random stage, wrote and synced its bytes, then
closed its descriptor before publishing by pathname. Renaming that stage aside
and putting foreign bytes at the former name during the sync callback made
`write_atomic(force=False)` return success with the foreign bytes at the
destination. The originally written bytes remained in the moved stage. Raising
`KeyboardInterrupt` after the same replacement made cleanup unlink the foreign
replacement. Inputs were authored temporary files only.

The initial four-control regression run produced **2 failed, 2 passed** before
production changes. `red.log` and `red.xml` retain that run. Three further controls
were added for ordinary directory/symlink destinations and parent replacement.

## Scoped correction

No-force exports now call the existing `owned_publication.publish_bytes` with
an anchor for the already-existing destination parent. No content validator is
supplied: an existing identical file remains a refusal, not successful reuse.
The helper binds the original source and parent through publication, with Linux
anonymous staging and Windows native held handles. Failed cleanup closes or
discards only that held source. No new shared publication primitive was added.

Missing parents remain errors; the operation does not create directories.
Existing files, directories and destination links are preserved. Ordinary
non-reparse parents and supported ownership primitives are required; unsupported
filesystems/platforms fail with `PT-STR-EXPORT`. Parent-link traversal has no
fallback. Export content, redaction, hashes and CLI result shape are unchanged.

## Verification

Executed with Python 3.12.14, the shared project environment, and this worktree's
`src` explicitly selected:

```sh
PYTHONPATH=src QT_QPA_PLATFORM=offscreen python -m pytest -q \
  tests/test_strings_export_source_ownership.py \
  tests/test_strings_export_publication.py tests/test_strings_export.py \
  tests/test_strings_cli.py tests/test_owned_publication.py
python -m ruff check src tests tools
git diff --check
```

Observed: **47 passed in 3.98 s**; Ruff and whitespace checks passed. `green.log`,
`green.xml` and `ruff.log` retain the final focused receipts. The Windows branches
of source/ancestor-lock controls have not executed here. Linux execution and
portable native-call assertions do not certify native Windows behavior.

## Remaining forced-overwrite defect: BLOCKED

The current forced path remains behaviorally unchanged. Its existing test still
confirms ordinary `force=True` replacement. It still publishes through a stage
pathname and has unsafe cleanup under a substituted name. Do not describe #308
or all export publication as fully repaired.

`force_source_probe.py` executes the exact export source from the named Git
objects against authored temporary files, then probes the current source. It
records normal completion, injected `OSError`, and cancellation independently.
`force-source-proof.json` retains all twelve observations and the source digests.

| Source | Forced publication after stage replacement | OSError cleanup | Cancellation cleanup |
| --- | --- | --- | --- |
| Main `9c411ca3d7b47f950be5f0c6f01b3c54184554c6` | Returns success with foreign bytes | Deletes foreign stage | Preserves foreign stage |
| Foundation `88b0b52281dd314aa72f93819145a73135618bc4` | Same failure | Same failure | Preserves foreign stage |
| Selected #308 in base `d436a7ec571efa75dcd627ca9835c65f60e09c74` | Same failure | Same failure | Deletes foreign stage |
| This no-force correction | Forced path unchanged | Forced path unchanged | Forced path unchanged |

Main and foundation share export blob
`c642cc148f9f8d90373e679f81f46f8976c72537`; selected #308 has blob
`b6d7b2942afdeaac187fbdb9b2c031cdc92401bf`. The wrong-byte publication and
OSError cleanup failures are inherited. #308's wider `BaseException` cleanup
adds foreign-stage deletion on cancellation. These distinctions remain open
for integration review; passing no-force tests are not evidence against them.

Native Windows qualification, full integrated CI, and a preserving forced-source
repair are still required. No native engine, target binary or remote mutation
was performed for this work.
