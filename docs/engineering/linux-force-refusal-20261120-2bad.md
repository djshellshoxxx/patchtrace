# Linux Strings export: explicit replacement refusal

## Outcome and identity

The exported Linux operation now preserves an existing destination, including when
the caller passes `--force`. A new destination still succeeds through the existing
held-descriptor exclusive publisher. Windows retains its explicit held-source
replacement path. The CLI help and user guide describe this platform difference.

This is a conservative capability change, not a compatible Linux replacement
primitive. A strongly owned Linux overwrite operation remains unimplemented.
The previous final source-name rename is removed from the runtime. The failure
evidence in [the recovery report](security-force-recovery-20261119.md) and
[native primitive assessment](linux-force-primitive-assessment-20261119.md), including
both native result files, remains unchanged.

- Baseline: `67f7e08ea9bee61653f8ab5ad66048d3e7141810` (PR #344).
- Runtime/specification/test commit: `7f0af7cb4f6b5b0e9bd0f6a2f8af92ed365e2411`.
- Worker branch: `codex/publication-safety-20261120-2bad`.
- Root owns independent review, integration, the module index, and the authoritative ledger.

## Implementation and rationale

`strings/export.py::write_atomic` routes both Linux flag values through `_write_new`.
The existing `owned_publication.publish_linux` publishes directly from the held
anonymous source descriptor to the final name with exclusive link semantics. No
named source stage, pathname replacement, pre-deletion or rollback is used. An
existing or concurrently arriving destination returns `PT-STR-EXPORT` with:

> replacement is unavailable on Linux; choose a new destination

The default Linux collision message gives the same instruction instead of suggesting
an ineffective `--force` retry. New files still produce the ordinary export receipt;
refusals do not produce successful receipts. Redaction, formats, metadata, hashes,
scope and comparison behavior are unchanged. No persisted schema changes.

Moving Linux force onto the shared publisher also needs to preserve its earlier
cleanup guarantee. `owned_publication.py::_close_owned` carries over the existing
exception-aware close behavior. The shared Linux publisher registers its parent
and source descriptors with `ExitStack.push`, which passes the active operation
exception explicitly. A close failure adds a bounded exception-class note to that
exception. If there is no active operation failure, a fresh cleanup failure still
propagates; an unrelated exception handled by the caller cannot hide it. Native
Windows implementation and replacement flag handling are untouched.

## Verification and retained failures

All test selections used the checked-out repository under Python 3.12.14. Temporary
files were placed on `/tmp` after the initial attempt encountered a full workspace
filesystem before pytest could import `conftest.py`. Bytecode writing and pytest's
cache plugin were disabled. That environmental attempt is not a test result.

| Selection | Actual result | Meaning |
| --- | --- | --- |
| New refusal controls on unchanged baseline | 8 failed, 2 passed | Demonstrates the new preservation requirements were absent; not eight independent vulnerabilities. |
| Same controls after runtime repair | 10 passed | Linux existing/new/concurrent destination contract. |
| Original compatibility controls after runtime change | 26 failed, 51 passed | Retained failures from the old overwrite expectations and named-stage hooks. |
| Adapted compatibility selection | 1 failed, 91 passed | New help test incorrectly expected `cli.main` to raise `SystemExit`; the application returns 0 after help. |
| Final affected integration selection | **382 passed, 3 skipped in 9.30 seconds** | Seventeen maintained files, 385 unique cases. |
| Ruff on all changed Python files | Passed | No configuration changes or suppressed checks. |
| `git diff --check` | Passed | Source/specification/test patch hygiene. |

The three skips require native Windows: held-source replacement, held-ancestor and
stage sharing, and reparse mutation/rooted-open acceptance. Portable native-call
assertions passed but do not qualify the Windows filesystem. Counts overlap and
must not be summed. Full aggregate, exact integration-head CI, native acceptance
and release qualification remain root's separate gates.

The compatibility changes follow the explicit specification amendment:

- Prior successful Linux overwrite expectations now require refusal and unchanged
  bytes. Windows success expectations remain in their native paths.
- The historical final-rename test now fails if Linux export reaches any pathname
  replacement/removal primitive and proves the original destination remains intact.
- Named-stage substitution controls now exercise a concurrent final destination at
  the exclusive-link boundary, including a symlink, and prove it remains intact.
- Cancellation and I/O failures retain exception identity, closed descriptors,
  unrelated files, concurrent reports and absence of abandoned named stages.
- Source-byte mutation and final-parent substitution controls still refuse a false
  receipt. They explicitly retain externally modified or displaced-directory data.
- Cleanup double-failure controls now run with both flag values because the shared
  publisher owns that guarantee.

The regression suite does not claim that an external writer cannot edit a file
after publication. It preserves such bytes and refuses an observed incorrect
receipt; no immutable-file or rollback guarantee is inferred.

## Evidence and replay

[The evidence archive](evidence/linux-force-refusal-20261120-2bad.zip) contains the
original failure logs, all JUnit receipts, final Ruff output, baseline-relative
patch, the authored refusal-test source, exact runtime/test SHA-256 and Git blob
identities, and hashes of the unchanged historical race evidence.

Archive SHA-256: `05fc03772e198af290b5ebecdbee7b0b904a185cbae11e78670abf9c0e4ed5eb`.

Run from this commit in the declared development environment:

```sh
PYTHONDONTWRITEBYTECODE=1 QT_QPA_PLATFORM=offscreen PYTHONPATH=src python -m pytest -q -p no:cacheprovider \
  tests/test_strings_export.py tests/test_strings_export_publication.py \
  tests/test_strings_export_source_ownership.py tests/test_strings_export_metadata.py \
  tests/test_strings_export_force_ownership.py tests/test_strings_export_force_cancellation.py \
  tests/test_strings_export_force_cleanup.py tests/test_strings_export_linux_capability.py \
  tests/test_strings_cli.py tests/test_owned_publication.py tests/test_owned_publication_integrity.py \
  tests/test_owned_publication_replace.py tests/test_research_qualification_winpairs_publication.py \
  tests/test_kbc_acquisition_evidence.py tests/test_tier_r_output_persistence.py \
  tests/test_tier_r_credit_completion.py tests/test_project_cli.py
```

## Handoff

1. Independently review the Linux dispatch, exclusive destination semantics,
   cleanup exception ownership and the explicitly changed acceptance contract.
2. Integrate only after that review; update the module index and authoritative
   ledger to **mitigated by replacement refusal; Linux overwrite unavailable**.
3. Run required whole-tree Ruff and aggregate/native gates on the final combined
   source. Preserve native Windows skips until actual platform receipts exist.
4. Keep a future strongly owned Linux replacement capability separate. Do not
   restore name-based replacement, treat historical races as native acceptance,
   or weaken any existing release gate.

No remote branch mutation, merge, workflow dispatch, release or deployment was
performed by this worker. All filesystem controls used authored local report
bytes; no analyzed target binary was executed.
