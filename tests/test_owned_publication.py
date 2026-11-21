"""Portable native-call assertions; these do not certify a Windows filesystem."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest
from test_research_qualification_winpairs_publication import (
    _portable_windows_open_calls,
    _sharing_compatible,
)

from patchtrace import owned_publication as owned


def test_shared_publisher_requires_only_the_standard_library():
    tree = ast.parse(Path(owned.__file__).read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split('.')[0] in sys.stdlib_module_names for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module.split('.')[0] in sys.stdlib_module_names


def _windows_calls():
    fixture, calls = _portable_windows_open_calls()
    win = owned.WindowsPublication.__new__(owned.WindowsPublication)
    win.__dict__.update(fixture.__dict__)
    return win, calls


def test_windows_existing_file_open_never_requests_creation_or_write_access():
    win, calls = _windows_calls()
    real_open, dispositions = win.nt.NtCreateFile, []

    def capture(*args):
        dispositions.append(args[7])
        return real_open(*args)

    win.nt.NtCreateFile = capture
    assert win.open_child(29, 'existing.gz', directory=False, create=False) == 1
    access, share, parent, options = calls[0]
    assert access == 0x100081 and share == 1 and parent == 29
    assert options & 0x200000 and options & 0x40
    assert dispositions == [1]  # FILE_OPEN cannot create or replace evidence
    for writer_or_renamer in (0x2, 0x4, 0x40000000, 0x10000):
        assert not _sharing_compatible(access, share, writer_or_renamer, 7)


@pytest.mark.parametrize('status', [0xC000050B, 0xC0000103, 0xC00000BA])
def test_windows_reparse_and_wrong_type_rejections_remain_verification_failures(status):
    win, _ = _windows_calls()
    win.nt.NtCreateFile = lambda *args: status - (1 << 32)
    with pytest.raises(owned.OwnedPublicationError, match='non-reparse'):
        win.open_child(29, 'existing.gz', directory=False, create=False)


def test_reuse_validator_failure_is_not_treated_as_permission_to_create(tmp_path):
    target = tmp_path / 'existing'
    target.write_bytes(b'previous evidence')

    def reject(data):
        assert data == b'previous evidence'
        raise FileNotFoundError('a dependency of the validator is missing')

    with pytest.raises(FileNotFoundError, match='dependency'):
        owned.publish_bytes(target, b'new bytes', validate_existing=reject, maximum=100)
    assert target.read_bytes() == b'previous evidence'


def test_unverified_anchor_ancestor_replacement_never_creates_foreign_children(tmp_path):
    selected = tmp_path / 'selected'
    leaf = selected / 'leaf'
    leaf.mkdir(parents=True)
    anchor = owned.directory_anchor(leaf)
    parked = tmp_path / 'parked-original'
    selected.rename(parked)
    selected.mkdir()
    marker = selected / 'foreign-marker'
    marker.write_bytes(b'preserve foreign directory contents')

    with pytest.raises((OSError, owned.OwnedPublicationError)):
        owned.publish_bytes(leaf / 'report.json', b'authored export', anchor=anchor)

    assert set(selected.iterdir()) == {marker}
    assert marker.read_bytes() == b'preserve foreign directory contents'
    assert (parked / 'leaf').is_dir() and list((parked / 'leaf').iterdir()) == []


def test_new_descendants_can_be_created_below_a_verified_anchor(tmp_path):
    selected = tmp_path / 'selected'
    selected.mkdir()
    anchor = owned.directory_anchor(selected)
    target = selected / 'new-child' / 'new-leaf' / 'report.json'
    assert owned.publish_bytes(target, b'authored export', anchor=anchor)
    assert target.read_bytes() == b'authored export'


def test_windows_creation_starts_only_below_the_verified_anchor():
    from contextlib import ExitStack
    from pathlib import PureWindowsPath

    win, _ = _windows_calls()
    opened = []
    real_open = win.open_child

    def observe(parent, name, *, directory, create):
        opened.append((name, create))
        return real_open(parent, name, directory=directory, create=create)

    win.open_child = observe
    anchor = owned.DirectoryAnchor(PureWindowsPath('C:/selected'), (1, 0, 2))
    with ExitStack() as stack:
        win.directory(PureWindowsPath('C:/selected/child/leaf'), stack, create=True, anchor=anchor)
    assert opened == [('selected', False), ('child', True), ('leaf', True)]
