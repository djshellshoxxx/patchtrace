"""Destination symlink admission regression, synthetic filesystem paths only."""
from __future__ import annotations

import pytest

from patchtrace.kbcorrelation.acquire import _check_directory
from patchtrace.kbcorrelation.store import KbcStoreError


@pytest.mark.parametrize("dangling", [False, True])
def test_project_destination_symlink_refused_before_staging(tmp_path, dangling):
    link = tmp_path / "project"
    target = tmp_path / "target"
    if not dangling:
        target.mkdir()
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symbolic links unavailable on this host: {exc}")

    with pytest.raises(KbcStoreError) as raised:
        _check_directory(str(link))
    assert raised.value.code == "PT-KBC-INPUT"
    assert link.is_symlink()
    assert target.exists() is not dangling


def test_absent_and_real_empty_project_directory_remain_admissible(tmp_path):
    project = tmp_path / "project"
    _check_directory(str(project))
    project.mkdir()
    _check_directory(str(project))


def test_nonempty_project_directory_remains_refused(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "foreign").write_bytes(b"preserve")
    with pytest.raises(KbcStoreError) as raised:
        _check_directory(str(project))
    assert raised.value.code == "PT-KBC-INPUT"
    assert (project / "foreign").read_bytes() == b"preserve"
