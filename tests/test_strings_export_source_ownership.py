"""Publication must bind its bytes and cleanup to the actual export source."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


def _substitute_during_sync(tmp_path, monkeypatch, *, cancel=False):
    """Replace a name if possible; an anonymous/locked source must resist this."""
    sync = os.fsync
    replaced = []

    def substitute(descriptor):
        sync(descriptor)
        stages = list(tmp_path.glob('.*.tmp'))
        if stages:
            assert len(stages) == 1
            stage = stages[0]
            try:
                stage.rename(tmp_path / 'moved-owned-stage')
            except PermissionError:
                assert os.name == 'nt'  # a native held source denies rename
            else:
                stage.write_bytes(b'foreign replacement bytes')
                replaced.append(stage)
        else:
            assert sys.platform.startswith('linux')
            assert os.fstat(descriptor).st_nlink == 0  # no source pathname to replace
        if cancel:
            raise KeyboardInterrupt('controlled export cancellation')

    monkeypatch.setattr(os, 'fsync', substitute)
    return replaced


def test_stage_substitution_never_publishes_or_removes_foreign_bytes(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    replaced = _substitute_during_sync(tmp_path, monkeypatch)
    export.write_atomic(target, b'expected export bytes', force=False)
    assert target.read_bytes() == b'expected export bytes'
    for stage in replaced:
        assert stage.read_bytes() == b'foreign replacement bytes'


def test_cancel_never_removes_a_foreign_stage_replacement(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    replaced = _substitute_during_sync(tmp_path, monkeypatch, cancel=True)
    with pytest.raises(KeyboardInterrupt, match='controlled export cancellation'):
        export.write_atomic(target, b'expected export bytes', force=False)
    assert not target.exists()
    for stage in replaced:
        assert stage.read_bytes() == b'foreign replacement bytes'
    if not replaced:
        assert list(tmp_path.iterdir()) == []


def test_no_force_same_content_is_not_adopted(tmp_path):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    before = target.stat()
    with pytest.raises(StringsError) as raised:
        export.write_atomic(target, b'prior complete export', force=False)
    assert raised.value.code == 'PT-STR-EXPORT'
    assert target.read_bytes() == b'prior complete export'
    assert (target.stat().st_ino, target.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert list(tmp_path.iterdir()) == [target]


def test_no_force_missing_parent_remains_missing(tmp_path):
    target = tmp_path / 'missing' / 'report.json'
    with pytest.raises(StringsError) as raised:
        export.write_atomic(target, b'export', force=False)
    assert raised.value.code == 'PT-STR-EXPORT'
    assert not target.parent.exists()


@pytest.mark.parametrize('kind', ['directory', 'symlink'])
def test_no_force_preserves_nonordinary_destination(tmp_path, kind):
    target = tmp_path / 'report.json'
    outside = tmp_path / 'prior-export'
    outside.write_bytes(b'prior complete export')
    if kind == 'directory':
        target.mkdir()
        (target / 'marker').write_bytes(b'keep directory contents')
    else:
        target.symlink_to(outside)
    with pytest.raises(StringsError) as raised:
        export.write_atomic(target, b'new export', force=False)
    assert raised.value.code == 'PT-STR-EXPORT'
    assert outside.read_bytes() == b'prior complete export'
    if kind == 'directory':
        assert (target / 'marker').read_bytes() == b'keep directory contents'
    else:
        assert target.is_symlink() and target.resolve() == outside


def test_parent_replacement_cannot_redirect_export_or_cleanup(tmp_path, monkeypatch):
    parent = tmp_path / 'selected'
    moved = tmp_path / 'moved'
    parent.mkdir()
    target = parent / 'report.json'
    sync = os.fsync
    changed = []

    def replace_parent(descriptor):
        sync(descriptor)
        try:
            parent.rename(moved)
        except PermissionError:
            assert os.name == 'nt'  # the held native ancestor prevents replacement
        else:
            changed.append(True)
            parent.mkdir()
            (parent / 'foreign').write_bytes(b'preserve replacement directory')

    monkeypatch.setattr(os, 'fsync', replace_parent)
    try:
        export.write_atomic(target, b'new export', force=False)
    except StringsError as exc:
        assert changed and exc.code == 'PT-STR-EXPORT'
    else:
        assert not changed and target.read_bytes() == b'new export'
    if changed:
        assert (parent / 'foreign').read_bytes() == b'preserve replacement directory'
        assert not target.exists() and not (moved / 'report.json').exists()
        assert list(moved.iterdir()) == []


@pytest.mark.parametrize('boundary', ['directory_anchor', 'publish_bytes'])
def test_unavailable_publication_capability_is_a_bounded_typed_error(tmp_path, monkeypatch, boundary):
    target = tmp_path / 'report.json'

    def unavailable(*_args, **_kwargs):
        raise NotImplementedError(f'authored unavailable operation at {tmp_path}')

    monkeypatch.setattr(export, boundary, unavailable)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'authored export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'unavailable' in caught.value.message and str(tmp_path) not in caught.value.message
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('boundary', ['directory_anchor', 'publish_bytes'])
@pytest.mark.parametrize('error_type', [KeyboardInterrupt, SystemExit, RuntimeError])
def test_no_force_non_io_failure_preserves_the_original_exception(tmp_path, monkeypatch, boundary, error_type):
    failure = error_type('authored interruption')

    def interrupt(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(export, boundary, interrupt)
    with pytest.raises(error_type) as caught:
        export.write_atomic(tmp_path / 'report.json', b'authored export', force=False)
    assert caught.value is failure
    assert list(tmp_path.iterdir()) == []


def test_unsupported_platform_is_typed_without_a_pathname_fallback(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from patchtrace import owned_publication as owned

    monkeypatch.setattr(owned, 'sys', SimpleNamespace(platform='authored-unsupported-platform'))
    monkeypatch.setattr(owned, 'os', SimpleNamespace(name='authored-unsupported-platform', path=os.path))
    with pytest.raises(StringsError) as caught:
        export.write_atomic(tmp_path / 'report.json', b'authored export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux anonymous staging capability')
def test_missing_anonymous_staging_support_is_typed_without_a_named_fallback(tmp_path, monkeypatch):
    monkeypatch.delattr(os, 'O_TMPFILE')
    with pytest.raises(StringsError) as caught:
        export.write_atomic(tmp_path / 'report.json', b'authored export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert list(tmp_path.iterdir()) == []


def test_ancestor_replacement_before_publication_never_creates_a_foreign_parent(tmp_path, monkeypatch):
    selected = tmp_path / 'selected'
    parent = selected / 'leaf'
    parent.mkdir(parents=True)
    parked = tmp_path / 'parked-original'
    real_anchor = export.directory_anchor

    def capture_then_replace(path):
        anchor = real_anchor(path)
        selected.rename(parked)
        selected.mkdir()
        (selected / 'foreign-marker').write_bytes(b'preserve foreign contents')
        return anchor

    monkeypatch.setattr(export, 'directory_anchor', capture_then_replace)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(parent / 'report.json', b'authored export', force=False)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert [p.name for p in selected.iterdir()] == ['foreign-marker']
    assert (selected / 'foreign-marker').read_bytes() == b'preserve foreign contents'
    assert list((parked / 'leaf').iterdir()) == []
