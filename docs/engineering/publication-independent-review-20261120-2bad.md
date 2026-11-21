# Independent review: Linux Strings publication refusal

## Decision

**No blocking finding in the reviewed change.** The Linux export operation now
refuses replacement of an existing destination, including a force request, and
creates a new destination through the existing held-source exclusive publisher.
This mitigation removes the historical named-source replacement boundary from
the exported operation. It does not implement strongly owned Linux overwrite.

This is a fresh worker review of committed source, separate from the author.
The reviewer did not edit production code, specifications, maintained tests,
shared ledgers, remote refs, workflow configuration, or acceptance budgets.

- Reviewed source: `7f0af7cb4f6b5b0e9bd0f6a2f8af92ed365e2411`.
- Author baseline: `67f7e08ea9bee61653f8ab5ad66048d3e7141810`.
- Review worktree: `/tmp/PatchTrace-publication-review-2bad`.
- Review branch: `codex/publication-review-20261120-2bad`.
- Governing contract: [WB3 file publication](../specs/program-e/WB3-integration-plan.md#file-publication).

## Source conclusions

1. `strings/export.py::write_atomic` sends both Linux force values to `_write_new`.
   The old `_replace_linux` implementation and its named source, pathname rename,
   and associated cleanup are absent. No alternate Linux overwrite, pre-delete,
   rename, or rollback path was introduced.
2. `_write_new` captures the selected existing parent, then calls `publish_bytes`
   without a reuse validator. Existing content is refused even if identical.
   The final link chooses an open anonymous source descriptor and an already
   held destination directory. A concurrent destination causes refusal instead
   of being overwritten. The source-byte and parent checks remain active.
3. Linux collision text directs the user to a new filename and no longer
   suggests `--force`. The CLI help, normal typed/JSON error path, and user guide
   describe the capability restriction. Successful publication still supplies
   the ordinary export receipt; refused publication cannot reach that return.
4. The Windows dispatch still requests `publish_windows(..., replace=True)`.
   The native Windows publisher was not edited. Portable call tests establish
   dispatch and argument behavior only; they do not establish NTFS behavior.
5. `publish_linux` now gives both owned descriptors exception-aware ExitStack
   callbacks. A close failure with an active operation failure adds a bounded
   exception-class note and preserves that primary failure. With no operation
   failure, the first cleanup failure propagates; a second cleanup failure is
   attached to it. ExitStack supplies the active exception explicitly, so an
   unrelated exception being handled by the caller cannot hide a fresh failure.
6. The revised tests change obsolete overwrite/named-stage expectations to the
   explicitly amended preservation contract. They retain cancellation identity,
   source-byte checks, parent checks, concurrent-file preservation, closed-handle
   assertions, no unsafe unlink, and failure of incorrect success receipts.
   Windows replacement checks remain intact.

The existing destination can still be changed by another writer after publication.
No immutable-file, durable namespace lock, rollback, or Linux overwrite guarantee
is inferred from these checks. A failure observed after a successful exclusive
link may leave the new file in the held original directory; cleanup deliberately
does not unlink a mutable pathname. These are stated contract limits.

## Independently executed qualification

All commands used Python 3.12.14 from the existing declared project development
environment, explicit review `src` import paths, disabled bytecode/cache writes,
and separate tmpfs test directories. The checkout stayed at the same reviewed
runtime source throughout the tests.

| Check | Result | Scope |
| --- | --- | --- |
| Author's 17 maintained affected files, independently replayed | **382 passed, 3 skipped in 10.26 seconds** | Export, CLI, owned publisher, and affected persistence consumers |
| Newly authored independent boundary controls | **9 passed in 0.31 seconds** | Directories, hardlinks, FIFOs, cleanup exception precedence, Windows dispatch |
| Ruff on changed Python files and independent control source | Passed | Existing rules; no suppressions or configuration change |
| Historical race reports relative to baseline | Unchanged | Both report paths checked with Git diff |

The 382 maintained passes repeat the author's selection and must not be added to
that count. The nine independent controls are additional local review evidence,
not a full repository suite or native Windows qualification.

The three native Windows skips were:

- `tests.test_owned_publication_replace::test_native_windows_force_replaces_existing_destination_while_source_denies_substitution`
- `tests.test_research_qualification_winpairs_publication::test_windows_held_ancestors_and_stage_block_replacement_and_writes`
- `tests.test_research_qualification_winpairs_publication::test_windows_attribute_reparse_mutation_cannot_redirect_stage_creation`

The review introduced six preservation cases across both force values for
existing directories, hardlinks, and FIFOs. These assert the existing object's
identity/type and original bytes remain unchanged and no stage files survive.
Two direct shared-publisher cases assert exception identity when both owned
closes fail, both with an original interruption and after successful linking.
The final portable control verifies Windows force dispatch without pretending
that the stub writes a file.

## Exact source and evidence identities

| Path | Reviewed Git blob |
| --- | --- |
| `src/patchtrace/strings/export.py` | `9929e08b56498beb06f3dadd070100816e54ba64` |
| `src/patchtrace/owned_publication.py` | `16e1ae354662d88fbe10ed5793b6049e512f0950` |
| `src/patchtrace/strings/cli.py` | `14203c901d6ec36c0563b2cdca1d821f9c819dfc` |
| `docs/specs/program-e/WB3-integration-plan.md` | `f100045066c7dcc3dd2826ef327dd5448edd2c9c` |

The temporary evidence directory is
`/tmp/patchtrace-publication-review-2bad-evidence`. The independent test source is
also embedded below so the control definitions survive cleanup of that directory.
The coordinator may copy the raw logs/JUnit into the combined qualification archive.

| Evidence file | SHA-256 |
| --- | --- |
| `test_independent_publication.py` | `63cd275babbc6f64f14cf49809acfa0aa16bbf3a848909df74371cdc4a9ba628` |
| `peer.log` | `e5d5f1394812085dbd5763bfb60de5f0e2997a913674ff88d465f1f6436ceba9` |
| `peer.xml` | `087af7a25f83909185a5e984e1896c278664884aa895742fbfe9c076d67681a4` |
| `maintained.log` | `865062b208961ad03bccedcba77e9884453902cd0f248143cc01774193a4fcfd` |
| `maintained.xml` | `032e79614cc56b43468cee9c3544a92dce3d05c66e05816841d08daead2bc367` |

## Remaining gates and integration instructions

The coordinator must verify that the accepted source/test blobs remain unchanged
when combining this repair with other work. Run the required combined/full and
hosted/native gates on the final source. This scoped review does not qualify
Windows packaging, native/manual Windows acceptance, release readiness, historical
Java/cache failures, empirical accuracy, or unrelated branch contents. The
historical final-source-name race evidence stays preserved. The ledger disposition
should read **mitigated by replacement refusal; Linux overwrite unavailable**.

The maintained replay command was:

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

## Reproducible independent controls

Save this source as a temporary `test_independent_publication.py` file and execute
it with pytest against this exact review checkout's `src`. These controls use
local authored report bytes and temporary filesystem objects. No analyzed binary,
external service, network target, or exploit payload is executed.

```python
"""Independent local preservation/cleanup controls for publication source 7f0af7cb."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from patchtrace import owned_publication as owned
from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('kind', ['directory', 'hardlink', 'fifo'])
def test_existing_special_or_aliased_destination_survives(tmp_path, force, kind):
    target = tmp_path / 'report'
    original = tmp_path / 'original'
    original.write_bytes(b'preserved report')
    if kind == 'directory':
        target.mkdir()
        (target / 'child').write_bytes(b'preserved child')
    elif kind == 'hardlink':
        os.link(original, target)
    else:
        os.mkfifo(target)
    before = target.lstat()
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'candidate report', force=force)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'choose a new destination' in caught.value.message
    after = target.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    assert original.read_bytes() == b'preserved report'
    assert set(tmp_path.iterdir()) == {target, original}
    if kind == 'directory':
        assert (target / 'child').read_bytes() == b'preserved child'
    elif kind == 'hardlink':
        assert target.read_bytes() == b'preserved report'


def test_two_cleanup_failures_keep_original_interruption(tmp_path, monkeypatch):
    target = tmp_path / 'report'
    interruption = SystemExit(29)
    closing = []
    active = False
    real_close = os.close

    def stage_writer(_fd, _data):
        nonlocal active
        active = True
        raise interruption

    def close_then_fail(fd):
        real_close(fd)
        if active:
            closing.append(fd)
            raise OSError(5, 'authored close refusal')

    monkeypatch.setattr(owned.os, 'close', close_then_fail)
    with pytest.raises(SystemExit) as caught:
        owned.publish_linux(target, b'candidate', stage_writer=stage_writer)
    assert caught.value is interruption
    assert len(closing) == len(set(closing)) == 2
    assert interruption.__notes__ == ['Publication descriptor cleanup also failed: OSError'] * 2
    assert not target.exists()
    for fd in closing:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_successful_operation_reports_first_of_two_cleanup_failures(tmp_path, monkeypatch):
    target = tmp_path / 'report'
    held = []
    real_directory, real_stage, real_close = owned.linux_directory, owned.write_stage, os.close
    first = OSError(5, 'first owned close failure')
    second = RuntimeError('second owned close failure')
    closed = []

    def directory(*args, **kwargs):
        fd = real_directory(*args, **kwargs)
        if not held:
            held.append(fd)
        return fd

    def stage(fd, data):
        held.append(fd)
        return real_stage(fd, data)

    def close(fd):
        real_close(fd)
        if fd in held:
            closed.append(fd)
            raise first if fd == held[1] else second

    monkeypatch.setattr(owned, 'linux_directory', directory)
    monkeypatch.setattr(owned.os, 'close', close)
    with pytest.raises(OSError) as caught:
        owned.publish_linux(target, b'candidate', stage_writer=stage)
    assert caught.value is first
    assert first.__notes__ == ['Publication descriptor cleanup also failed: RuntimeError']
    assert closed == list(reversed(held))
    assert target.read_bytes() == b'candidate'


def test_windows_force_dispatch_still_requests_held_source_replacement(tmp_path, monkeypatch):
    target = tmp_path / 'report'
    target.write_bytes(b'prior')
    anchor = object()
    calls = []
    monkeypatch.setattr(export, 'sys', SimpleNamespace(platform='win32'))
    monkeypatch.setattr(export, 'os', SimpleNamespace(name='nt', path=os.path))
    monkeypatch.setattr(export, 'directory_anchor', lambda parent: anchor)
    monkeypatch.setattr(export, 'publish_windows', lambda *args, **kwargs: calls.append((args, kwargs)))
    export.write_atomic(target, b'candidate', force=True)
    assert calls == [((target, b'candidate'), {'anchor': anchor, 'replace': True})]
    assert target.read_bytes() == b'prior'  # Stub dispatch is not native Windows acceptance.
```
