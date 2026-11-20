"""Linux replacement refusal preserves existing and concurrently published reports."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux publication capability')


@pytest.mark.parametrize('kind', ['different', 'identical', 'symlink', 'dangling'])
def test_force_preserves_every_existing_destination(tmp_path, kind):
    target = tmp_path / 'report.json'
    foreign = tmp_path / 'other.json'
    foreign.write_bytes(b'other complete report')
    if kind in ('different', 'identical'):
        target.write_bytes(b'expected export' if kind == 'identical' else b'prior complete export')
    else:
        target.symlink_to(foreign if kind == 'symlink' else tmp_path / 'missing')
    original = target.lstat()
    content = target.readlink() if target.is_symlink() else target.read_bytes()

    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export', force=True)

    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'replacement is unavailable on Linux' in caught.value.message
    assert 'choose a new destination' in caught.value.message
    assert str(tmp_path) not in caught.value.message
    current = target.lstat()
    assert (current.st_ino, current.st_mtime_ns) == (original.st_ino, original.st_mtime_ns)
    assert (target.readlink() if target.is_symlink() else target.read_bytes()) == content
    assert foreign.read_bytes() == b'other complete report'
    assert set(tmp_path.iterdir()) == {target, foreign}


@pytest.mark.parametrize('force', [False, True])
def test_linux_collision_never_suggests_force_retry(tmp_path, force):
    target = tmp_path / 'report.json'
    target.write_bytes(b'preserve')
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export', force=force)
    assert 'pass --force' not in caught.value.message
    assert 'choose a new destination' in caught.value.message
    assert target.read_bytes() == b'preserve'


@pytest.mark.parametrize('force', [False, True])
def test_new_linux_destination_uses_no_pathname_replacement(tmp_path, monkeypatch, force):
    target = tmp_path / 'report.json'

    def forbidden(*_args, **_kwargs):
        pytest.fail('Linux export must not replace or remove a pathname')

    monkeypatch.setattr(os, 'replace', forbidden)
    monkeypatch.setattr(os, 'rename', forbidden)
    monkeypatch.setattr(os, 'unlink', forbidden)
    export.write_atomic(target, b'expected export', force=force)
    assert target.read_bytes() == b'expected export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize('force', [False, True])
def test_destination_arriving_at_final_link_is_preserved(tmp_path, monkeypatch, force):
    target = tmp_path / 'report.json'
    link = os.link

    def arrive(source, destination, **kwargs):
        assert destination == target.name
        assert str(source).startswith('/proc/self/fd/')
        target.write_bytes(b'concurrently completed report')
        return link(source, destination, **kwargs)

    monkeypatch.setattr(os, 'link', arrive)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export', force=force)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert target.read_bytes() == b'concurrently completed report'
    assert list(tmp_path.iterdir()) == [target]
