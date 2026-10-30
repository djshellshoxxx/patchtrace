"""Launcher report retention never follows an output link or trusts a pre-read size."""
from pathlib import Path
from types import SimpleNamespace

from patchtrace.backend import _keep_launcher_report


def test_report_growth_after_stat_is_bounded(tmp_path, monkeypatch):
    source, target = tmp_path / 'report.json', tmp_path / 'kept.json'
    source.write_bytes(b'x' * (64 * 1024 + 1))
    real_stat = Path.stat

    def changed_stat(path, *args, **kwargs):
        actual = real_stat(path, *args, **kwargs)
        return SimpleNamespace(st_size=1, st_mode=actual.st_mode) if path == source else actual

    monkeypatch.setattr(Path, 'stat', changed_stat)
    _keep_launcher_report(source, target)
    assert not target.exists()


def test_report_output_link_cannot_overwrite_another_file(tmp_path):
    source, target, other = (tmp_path / name for name in ('report.json', 'kept.json', 'other.json'))
    source.write_bytes(b'{"report":true}')
    other.write_bytes(b'keep me')
    try:
        target.symlink_to(other)
    except OSError:
        # Creating symlinks requires an extra Windows privilege; the bounded-read case runs everywhere.
        import pytest
        pytest.skip('symlink creation unavailable')
    _keep_launcher_report(source, target)
    assert other.read_bytes() == b'keep me'
    assert target.read_bytes() == source.read_bytes() and not target.is_symlink()
