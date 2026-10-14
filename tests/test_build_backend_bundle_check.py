"""Hermetic tests for `tools/build_backend_bundle.py check` (synthetic trees, no network)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'build_backend_bundle.py'
_spec = importlib.util.spec_from_file_location('build_backend_bundle_under_test', TOOL)
tool = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = tool
_spec.loader.exec_module(tool)

POSIX_ONLY = pytest.mark.skipif(sys.platform == 'win32', reason='name not creatable on Windows')


@pytest.mark.parametrize('path', [
    'ghidra/Ghidra/application.properties', 'jdk/bin/java.exe', 'python/Lib/site-packages/a-1.0.dist-info/RECORD',
    'ghidra/support/launch.sh', 'jdk/legal/java.base/ASSEMBLY_EXCEPTION', 'a/CONSOLE.txt', 'a/auxiliary',
], ids=['props', 'java', 'record', 'launch', 'legal', 'console', 'aux'])
def test_allowed_paths_have_no_reasons(path):
    assert tool.path_reasons(path) == []


@pytest.mark.parametrize(('path', 'reason'), [
    ('ghidra/nul.txt', 'windows-reserved-device-name'),
    ('ghidra/CON', 'windows-reserved-device-name'),
    ('ghidra/com1.log', 'windows-reserved-device-name'),
    ('ghidra/lpt².x', 'windows-reserved-device-name'),
    ('ghidra/aux.tar.gz', 'windows-reserved-device-name'),
    ('ghidra/trail.', 'trailing-space-or-dot'),
    ('ghidra/trail ', 'trailing-space-or-dot'),
    ('ghidra/a:b', 'windows-forbidden-character'),
    ('ghidra/a*b', 'windows-forbidden-character'),
    ('ghidra/a?b', 'windows-forbidden-character'),
    ('ghidra/a\x01b', 'control-character'),
    ('ghidra/a\\b', 'backslash'),
    ('ghidra//b', 'empty-or-dot-component'),
    ('ghidra/../b', 'empty-or-dot-component'),
    ('ghidra/' + 'x' * 520, 'path-over-512'),
    ('ghidra/\udcff', 'not-valid-utf8'),
], ids=['nul-ext', 'con', 'com1', 'lpt-sup', 'aux-multi', 'dot', 'space', 'colon', 'star', 'qmark',
        'ctrl', 'bslash', 'dslash', 'dotdot', 'long', 'utf8'])
def test_offending_paths_are_classified(path, reason):
    assert reason in tool.path_reasons(path)


@pytest.mark.parametrize('path', [
    'ghidra/nul.txt', 'ghidra/trail.', 'ghidra/a:b', 'ghidra//b', 'ghidra/x' * 1 + 'y' * 600,
], ids=['nul', 'dot', 'colon', 'dslash', 'long'])
def test_every_policy_rejection_is_reported(path):
    """Anything build_offline_bundle's validator rejects must be an offender here."""
    assert tool.path_reasons(path)


def make(root: Path, *names: str) -> Path:
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'x')
    return root


def test_clean_tree_is_clean(tmp_path):
    tree = make(tmp_path / 'g', 'Ghidra/application.properties', 'support/launch.sh')
    report = tool.check_tree(tree, prefix='ghidra')
    assert report.clean
    assert (report.files, report.directories, report.total_bytes) == (2, 2, 2)
    assert report.longest_path == len('ghidra/Ghidra/application.properties')


def test_prefix_changes_reported_names(tmp_path):
    tree = make(tmp_path / 't', 'a.txt')
    assert tool.check_tree(tree, prefix='/jdk/').longest_path == len('jdk/a.txt')
    assert tool.check_tree(tree).longest_path == len('a.txt')


@POSIX_ONLY
def test_reserved_and_trailing_names_listed(tmp_path):
    tree = make(tmp_path / 'g', 'ok.txt', 'nul.dat', 'sub/dir.')
    report = tool.check_tree(tree, prefix='ghidra')
    found = {(item.path, item.reason) for item in report.offenders}
    assert ('ghidra/nul.dat', 'windows-reserved-device-name') in found
    assert ('ghidra/sub/dir.', 'trailing-space-or-dot') in found
    assert not any(path == 'ghidra/ok.txt' for path, _ in found)


@POSIX_ONLY
def test_casefold_collision_listed(tmp_path):
    tree = make(tmp_path / 'g', 'Lib/Readme.txt', 'Lib/README.TXT')
    reasons = [item.reason for item in tool.check_tree(tree).offenders]
    assert any(reason.startswith('collides-with:') for reason in reasons)


@POSIX_ONLY
def test_unicode_normalization_collision_listed(tmp_path):
    tree = make(tmp_path / 'g', 'café.txt', 'café.txt')
    assert any(item.reason.startswith('collides-with:') for item in tool.check_tree(tree).offenders)


def test_long_path_over_backend_budget(tmp_path):
    deep = '/'.join(['d' * 30] * 5) + '/f.txt'
    tree = make(tmp_path / 'g', deep)
    report = tool.check_tree(tree, prefix='ghidra')
    assert any(item.reason.startswith('longer-than-150') for item in report.offenders)


def test_symlink_reported_and_not_followed(tmp_path):
    tree = make(tmp_path / 'g', 'real/f.txt')
    try:
        (tree / 'link').symlink_to(tree / 'real', target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable')
    report = tool.check_tree(tree)
    assert [item.reason for item in report.offenders] == ['symbolic-link']
    assert report.files == 1


def test_member_limit_enforced(tmp_path, monkeypatch):
    monkeypatch.setattr(tool.policy, 'MAX_MEMBERS', 2)
    tree = make(tmp_path / 'g', 'a', 'b', 'c')
    assert any(item.path == '(tree)' for item in tool.check_tree(tree).offenders)


def test_missing_or_file_root_rejected(tmp_path):
    with pytest.raises(NotADirectoryError):
        tool.check_tree(tmp_path / 'absent')
    (tmp_path / 'f').write_bytes(b'x')
    with pytest.raises(NotADirectoryError):
        tool.check_tree(tmp_path / 'f')


def test_cli_exit_codes_and_json(tmp_path, capsys):
    tree = make(tmp_path / 'g', 'a.txt')
    assert tool.main(['check', str(tree), '--prefix', 'jdk']) == tool.EXIT_OK
    assert capsys.readouterr().out.rstrip().endswith('clean')
    assert tool.main(['check', str(tmp_path / 'absent')]) == tool.EXIT_USAGE
    capsys.readouterr()
    assert tool.main(['check', str(tree), '--json']) == tool.EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document['schema'] == 'patchtrace-bundle-check/1'
    assert document['clean'] is True and document['offenders'] == []


@POSIX_ONLY
def test_cli_reports_offenders_with_exit_1(tmp_path, capsys):
    tree = make(tmp_path / 'g', 'aux.txt')
    assert tool.main(['check', str(tree), '--prefix', 'ghidra']) == tool.EXIT_OFFENDERS
    output = capsys.readouterr().out
    assert "OFFENDER windows-reserved-device-name: 'ghidra/aux.txt'" in output
    assert '1 offender(s)' in output


def test_check_is_read_only(tmp_path):
    tree = make(tmp_path / 'g', 'a.txt', 'b/c.txt')
    before = sorted(p.relative_to(tree).as_posix() for p in tree.rglob('*'))
    tool.check_tree(tree)
    assert sorted(p.relative_to(tree).as_posix() for p in tree.rglob('*')) == before
