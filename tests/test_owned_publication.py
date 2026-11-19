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
