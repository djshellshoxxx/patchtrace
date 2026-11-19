"""Bounded strict AnchorSet input for the existing Strings CLI."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from patchtrace.strings import cli
from patchtrace.strings.contracts import StringsError


def test_duplicate_anchor_identity_key_is_refused(tmp_path):
    path = tmp_path / 'anchors.json'
    path.write_bytes(b'{"cve":"CVE-2026-0001","cve":"CVE-2026-0002","anchors":[]}')
    with pytest.raises(StringsError, match='AnchorSet'):
        cli._load_anchors(path)


def test_anchor_byte_budget_does_not_depend_on_prior_path_stat(tmp_path, monkeypatch):
    path = tmp_path / 'anchors.json'
    path.write_bytes(b'{"cve":"CVE-2026-0001","limitations":["' + b'x' * 128 + b'"]}')
    real_stat = Path.stat
    monkeypatch.setattr(cli, 'MAX_ANCHOR_FILE', 64)
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **kw: SimpleNamespace(st_size=1) if p == path
                        else real_stat(p, *a, **kw))
    with pytest.raises(StringsError):
        cli._load_anchors(path)


def test_anchor_file_link_is_refused(tmp_path):
    path, link = tmp_path / 'anchors.json', tmp_path / 'link.json'
    path.write_bytes(b'{"cve":"CVE-2026-0001","anchors":[]}')
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip('symlink creation is unavailable')
    with pytest.raises(StringsError):
        cli._load_anchors(link)
