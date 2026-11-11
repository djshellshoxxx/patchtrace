"""tools/dev/branch_inventory.py classifies branches of a temporary repository: merged, patch-equivalent,
superseded, docs-only, live, stale; clusters live branches by shared non-hub files. Offline; git only."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'dev' / 'branch_inventory.py'
NOW = datetime(2026, 11, 4, tzinfo=UTC)
OLD = '2026-10-01T00:00:00+00:00'
NEW = '2026-11-03T00:00:00+00:00'

pytestmark = pytest.mark.skipif(shutil.which('git') is None, reason='git not installed')


def _load():
    spec = importlib.util.spec_from_file_location('branch_inventory', TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules['branch_inventory'] = module
    spec.loader.exec_module(module)
    return module


class Repo:
    def __init__(self, path: Path):
        self.path = path
        self.env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
                    'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid',
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
        self.git('init', '-q', '-b', 'main')

    def git(self, *args: str, date: str = NEW) -> str:
        env = {**self.env, 'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date}
        return subprocess.run(['git', '-C', str(self.path), *args], env=env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, files: dict[str, str], message: str, date: str = NEW) -> str:
        for name, text in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding='utf-8', newline='\n')
            self.git('add', name)
        self.git('commit', '-q', '-m', message, date=date)
        return self.git('rev-parse', 'HEAD')

    def publish(self, branch: str) -> None:
        self.git('update-ref', f'refs/remotes/origin/{branch}', 'HEAD')


@pytest.fixture()
def inventory(tmp_path):
    tool = _load()
    r = Repo(tmp_path)
    r.commit({'src/a.py': 'a = 1\n', 'src/b.py': 'b = 1\n', 'docs/x.md': 'x\n'}, 'base', date=OLD)
    root = r.git('rev-parse', 'HEAD')
    r.publish('main')

    r.git('checkout', '-q', '-b', 'merged')
    r.publish('merged')

    r.git('checkout', '-q', '-b', 'equivalent', root)
    r.commit({'src/c.py': 'c = 1\n'}, 'add c')
    r.publish('equivalent')

    r.git('checkout', '-q', '-b', 'small', root)
    r.commit({'src/d.py': 'd = 1\n'}, 'add d')
    r.publish('small')
    r.commit({'src/e.py': 'e = 1\n'}, 'add e')
    r.publish('big')

    r.git('checkout', '-q', '-b', 'docs', root)
    r.commit({'docs/y.md': 'y\n', 'tasks/todo.md': 't\n'}, 'docs')
    r.publish('docs')

    r.git('checkout', '-q', '-b', 'hub', root)
    r.commit({'src/patchtrace/cli.py': 'x\n', 'src/f.py': 'f\n'}, 'hub edit')
    r.publish('hub')

    r.git('checkout', '-q', '-b', 'stale', root)
    r.commit({'src/a.py': 'a = 2\n'}, 'old edit of a', date=OLD)
    r.publish('stale')

    r.git('checkout', '-q', '-b', 'stale-with-pr', root)
    r.commit({'src/a.py': 'a = 3\n', 'src/g.py': 'g\n'}, 'old edit of a with PR', date=OLD)
    r.publish('stale-with-pr')

    # main moves on: picks up "add c" as an equivalent patch and rewrites src/a.py
    r.git('checkout', '-q', 'main')
    r.commit({'src/c.py': 'c = 1\n'}, 'add c (main)')
    r.commit({'src/a.py': 'a = 9\n'}, 'rewrite a')
    r.publish('main')

    prs = tmp_path / 'prs.json'
    prs.write_text(json.dumps([{'number': 7, 'head': 'stale-with-pr'}, {'number': 8, 'head': 'big'}]),
                   encoding='utf-8')
    out = tmp_path / 'inv.json'
    assert tool.main(['--repo', str(tmp_path), '--prs', str(prs), '--now', NOW.isoformat(), '--out', str(out)]) == 0
    data = json.loads(out.read_text(encoding='utf-8'))
    return data, {b['name']: b for b in data['branches']}


def test_each_branch_gets_the_expected_class(inventory):
    _, by_name = inventory
    assert {n: b['klass'] for n, b in by_name.items()} == {
        'big': 'LIVE', 'docs': 'DOCS', 'equivalent': 'EQUIVALENT', 'hub': 'LIVE', 'merged': 'MERGED',
        'small': 'SUPERSEDED', 'stale': 'STALE', 'stale-with-pr': 'LIVE'}
    assert 'main' not in by_name


def test_counts_and_cherry_details(inventory):
    data, by_name = inventory
    assert data['counts'] == {'DOCS': 1, 'EQUIVALENT': 1, 'LIVE': 3, 'MERGED': 1, 'STALE': 1, 'SUPERSEDED': 1}
    assert by_name['equivalent']['ahead'] == 1 and by_name['equivalent']['cherry_upstream'] == 1
    assert by_name['small']['superseded_by'] == 'big'
    assert by_name['big']['cherry_unique'] == 2 and by_name['big']['pr']['number'] == 8
    assert by_name['stale']['rewritten_on_base'] == ['src/a.py']
    assert by_name['merged']['behind'] == 2


def test_clusters_join_on_shared_code_but_not_on_hub_files(inventory):
    data, by_name = inventory
    assert by_name['stale']['cluster'] == by_name['stale-with-pr']['cluster']
    assert by_name['hub']['cluster'] != by_name['big']['cluster']
    joined = next(c for c in data['clusters'] if 'stale' in c['branches'])
    assert joined['branches'] == ['stale', 'stale-with-pr'] and joined['prs'] == [7]


def test_widely_shared_files_become_hubs_and_split_clusters(inventory, tmp_path):
    tool = _load()
    data, _ = inventory
    assert 'src/patchtrace/cli.py' in data['hub_files'] and 'src/a.py' not in data['hub_files']
    branches = [tool.Branch(name=n, head='', ahead=1, behind=0, merge_base='', last_commit=NEW, last_author='',
                            cherry_upstream=0, cherry_unique=1, files=files, klass='LIVE')
                for n, files in (('x', ['src/common.py', 'src/x.py']), ('y', ['src/common.py', 'src/y.py']))]
    joined, _ = tool.cluster_live(branches, threshold=3)
    split, hubs = tool.cluster_live(branches, threshold=2)
    assert len(joined) == 1 and len(split) == 2 and hubs == ['src/common.py']


def test_bad_pr_file_and_naive_now_are_rejected(tmp_path):
    tool = _load()
    bad = tmp_path / 'prs.json'
    bad.write_text('{"number": 1}', encoding='utf-8')
    with pytest.raises(SystemExit):
        tool.main(['--repo', str(tmp_path), '--prs', str(bad)])
    with pytest.raises(SystemExit):
        tool.main(['--repo', str(tmp_path), '--now', '2026-11-04T00:00:00'])


def test_git_failure_returns_exit_2(tmp_path, capsys):
    tool = _load()
    assert tool.main(['--repo', str(tmp_path), '--now', NOW.isoformat()]) == 2
    assert 'error:' in capsys.readouterr().err


@pytest.mark.parametrize('base', ['--output=pwned.txt', '-p', ''], ids=['opt-output', 'opt-short', 'empty'])
def test_option_like_base_is_rejected_before_reaching_git(inventory, tmp_path, base):
    tool = _load()
    victim = tmp_path / 'pwned.txt'
    with pytest.raises(SystemExit):
        tool.main(['--repo', str(tmp_path), f'--base={base}', '--now', NOW.isoformat(),
                   '--out', str(tmp_path / 'o.json')])
    assert not victim.exists() and not (Path.cwd() / 'pwned.txt').exists()


@pytest.mark.parametrize('remote', ['--all', 'a b', 'x/../y'], ids=['opt', 'space', 'dots'])
def test_bad_remote_name_is_rejected(tmp_path, remote):
    tool = _load()
    with pytest.raises(SystemExit):
        tool.main(['--repo', str(tmp_path), f'--remote={remote}', '--now', NOW.isoformat()])


def test_base_is_resolved_to_a_commit_sha(inventory):
    data, _ = inventory
    assert len(data['base_sha']) == 40 and all(c in '0123456789abcdef' for c in data['base_sha'])


def _outside_allowed_roots() -> Path:
    import tempfile
    anchor = Path(tempfile.gettempdir()).resolve().anchor
    return Path(anchor) / 'pt-branch-inventory-not-allowed' / 'x.json'


@pytest.mark.parametrize('flag', ['--out', '--prs', '--repo'], ids=['out', 'prs', 'repo'])
def test_file_arguments_outside_cwd_and_temp_are_refused(tmp_path, flag):
    tool = _load()
    outside = _outside_allowed_roots()
    args = {'--repo': str(tmp_path), '--now': NOW.isoformat(), flag: str(outside)}
    with pytest.raises(SystemExit):
        tool.main([item for pair in args.items() for item in pair])
    assert not outside.exists()


def test_dotdot_cannot_escape_the_temp_root(tmp_path):
    tool = _load()
    sneaky = tmp_path / ('../' * 40) / 'pt-branch-inventory-escape.json'
    with pytest.raises(SystemExit):
        tool.main(['--repo', str(tmp_path), '--now', NOW.isoformat(), '--out', str(sneaky)])
