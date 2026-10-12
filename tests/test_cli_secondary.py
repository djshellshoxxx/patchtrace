"""CLI wiring for SPEC-10/11 secondary match sets (import, reconcile, orientation)."""
from __future__ import annotations

import json

import pytest

from patchtrace import cli
from patchtrace.service import ProjectService

from test_secondary_bindiff import build


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    root = service.root
    service.close()
    return root, sides


def test_import_bindiff_then_reconcile(project, tmp_path, capsys):
    root, sides = project
    db = build(tmp_path / 'x.BinDiff', hashes=(sides['older'], sides['newer']))
    assert cli.main(['secondary', 'import-bindiff', str(root), str(db), '--json']) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc['command'] == 'secondary import-bindiff' and doc['result']['matches'] == 2
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    report = json.loads(capsys.readouterr().out)['result']['reports'][0]
    assert report['engine'] == 'bindiff' and sum(report['counts'].values()) >= 1
    assert any('proof' in line.lower() or 'not' in line.lower() for line in report['limitations'])


def test_reversed_bindiff_rejected_as_environment_error(project, tmp_path, capsys):
    root, sides = project
    db = build(tmp_path / 'r.BinDiff', hashes=(sides['newer'], sides['older']))
    assert cli.main(['secondary', 'import-bindiff', str(root), str(db), '--json']) == 2
    assert 'ORIENTATION' in json.loads(capsys.readouterr().out)['error']


def test_reconcile_without_sets_exits_4(project, capsys):
    root, _ = project
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 4


def test_rzdiff_missing_executable_is_environment_error(project, capsys, tmp_path):
    root, _ = project
    assert cli.main(['secondary', 'rzdiff', str(root), '--rz-diff', str(tmp_path / 'absent-rz-diff')]) == 2
