"""tools/release_gate.py: the milestone rule behind the `release` job (windows-acceptance spec section 1.1).

Hermetic: synthetic commits and release JSON, fake tool classes, one throwaway local git repository, and text
checks of the workflow (no YAML library, like tests/test_workflows.py). Nothing here proves a live Actions run."""
from __future__ import annotations

import ast
import importlib.util
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'release_gate.py'
spec = importlib.util.spec_from_file_location('release_gate', TOOL)
gate = importlib.util.module_from_spec(spec)
sys.modules['release_gate'] = gate
spec.loader.exec_module(gate)

WORKFLOW = ROOT / '.github' / 'workflows' / 'qa-windows.yml'
TEXT = WORKFLOW.read_text(encoding='utf-8')


def sha(n: int) -> str:
    return f'{n:040x}'


ANCHOR = gate.Release('v0.1.0-beta.7', sha(0), '2026-10-14T10:00:00Z')
ANCHOR_COMMIT = gate.Commit(sha(0), (), 'Release build (#0)')
# A squash body. GitHub skips CI for a push whose head message has a skip marker on ANY line (PR #48 was skipped
# that way), so no build exists for such a commit.
SQUASH ='Add the matcher (#12)\n\n* matcher: first part\n* docs: notes [skip ci]\n* matcher: second part\n'


def history(*messages: str, base: int = 0) -> tuple[gate.Commit, list[gate.Commit]]:
    """Linear first-parent history above sha(base), messages oldest first: (head, commits newest first)."""
    commits = [gate.Commit(sha(base + i + 1), (sha(base + i),), text) for i, text in enumerate(messages)]
    commits.reverse()
    return commits[0], commits


def merges(count: int) -> list[str]:
    return [f'Wave {i} (#{i})' for i in range(count)]


def log_text(*commits: gate.Commit) -> str:
    """What `git log --format=%H%x1f%P%x1f%B%x1e` prints (tformat: a newline follows every record)."""
    return ''.join(f'{c.sha}\x1f{" ".join(c.parents)}\x1f{c.message}\x1e\n' for c in commits)


def release(tag: str, commit: str, published: str, *, draft: bool = False, prerelease: bool = True) -> dict:
    return {'tag_name': tag, 'target_commitish': commit, 'draft': draft, 'prerelease': prerelease,
            'created_at': published, 'published_at': published, 'name': f'PatchTrace {tag}'}


def releases_json(*items: dict) -> str:
    return json.dumps(list(items))


# ---------------------------------------------------------------- skip markers and counting

SKIPPING = {
    'skip-ci-subject': 'Docs only [skip ci]',
    'ci-skip-lead': '[ci skip] Docs only',
    'no-ci-body': 'Docs\n\nmore text [no ci]\n',
    'skip-actions-late': SQUASH.replace('[skip ci]', '[skip actions]'),
    'actions-skip-upper': 'Docs [ACTIONS SKIP]',
    'squash-late-line': SQUASH,
}
KEEPING = {
    'plain': 'Add the matcher (#12)',
    'no-brackets': 'skip ci',
    'one-word': '[skipci]',
    'dashed': '[skip-ci]',
    'other-bracket': '[skip]',
    'release-marker': 'Wave [release]',
    'empty': '',
}


@pytest.mark.parametrize('message', list(SKIPPING.values()), ids=list(SKIPPING))
def test_every_github_skip_marker_is_recognised_in_any_line_of_the_message(message):
    assert gate.skips_ci(message)


@pytest.mark.parametrize('message', list(KEEPING.values()), ids=list(KEEPING))
def test_text_that_only_looks_like_a_marker_does_not_skip(message):
    assert not gate.skips_ci(message)


def test_the_head_and_every_plain_commit_since_the_anchor_are_milestones():
    head, commits = history(*merges(3))
    assert gate.counted_merges(commits, head.sha) == 3


def test_a_skip_marker_in_the_subject_or_a_late_body_line_removes_the_commit_from_the_count():
    head, commits = history('Wave one (#1)', 'Docs only (#2) [skip ci]', SQUASH, 'Wave four (#4)')
    assert gate.counted_merges(commits, head.sha) == 2


def test_the_head_is_counted_even_when_its_message_has_a_marker_because_its_run_exists():
    head, commits = history('Wave one (#1)', SQUASH)
    assert head.message == SQUASH
    assert gate.counted_merges(commits, head.sha) == 2


def test_an_empty_range_counts_nothing():
    assert gate.counted_merges([], sha(0)) == 0


def test_the_range_reaches_the_anchor_only_when_the_oldest_commit_sits_directly_on_it():
    _, commits = history(*merges(2))
    assert gate.reaches(commits, sha(0))
    assert not gate.reaches(commits, sha(99))
    assert gate.reaches([], sha(0))
    assert not gate.reaches([gate.Commit(sha(1), (), 'root')], sha(0))


# ---------------------------------------------------------------- git log and release parsing

def test_git_log_output_round_trips_multi_line_bodies_merges_and_roots():
    merge = gate.Commit(sha(3), (sha(2), sha(9)), 'Merge side (#3)\n')
    squash = gate.Commit(sha(2), (sha(1),), SQUASH)
    root = gate.Commit(sha(1), (), 'Root\n')
    parsed = gate.parse_git_log(log_text(merge, squash, root))
    assert parsed == [merge, squash, root]
    assert gate.skips_ci(parsed[1].message) and not gate.skips_ci(parsed[0].message)


def test_empty_git_log_output_is_an_empty_list():
    assert gate.parse_git_log('') == []
    assert gate.parse_git_log('\n') == []


@pytest.mark.parametrize('text', [
    'nothing like a log\x1e\n',
    f'{sha(1)}\x1f{sha(0)}\x1e\n',
    f'xyz\x1f{sha(0)}\x1fmessage\x1e\n',
    f'{sha(1)}\x1fnot-a-sha\x1fmessage\x1e\n',
], ids=['prose', 'two-fields', 'bad-sha', 'bad-parent'])
def test_unexpected_git_log_output_is_an_error_not_a_guess(text):
    with pytest.raises(gate.GateError):
        gate.parse_git_log(text)


def test_the_latest_published_beta_prerelease_is_chosen_by_publication_time():
    text = releases_json(
        release('v0.1.0-beta.5', sha(5), '2026-10-12T09:00:00Z'),
        release('v0.1.0-beta.7', sha(7), '2026-10-14T10:00:00Z'),
        release('v0.1.0-beta.6', sha(6), '2026-10-13T09:00:00Z'))
    assert gate.latest_beta_prerelease(text) == gate.Release('v0.1.0-beta.7', sha(7), '2026-10-14T10:00:00Z')


def test_drafts_final_releases_other_tags_and_junk_never_anchor_the_count():
    text = json.dumps([
        release('v0.1.0-beta.9', sha(9), '2026-10-15T09:00:00Z', draft=True),
        release('v0.1.0-beta.8', sha(8), '2026-10-15T08:00:00Z', prerelease=False),
        release('v0.1.0-alpha.1', sha(4), '2026-10-15T07:00:00Z'),
        release('v0.2.0-beta.1', sha(3), '2026-10-15T06:00:00Z'),
        release('beta-v0.1.0-beta.1', sha(2), '2026-10-15T05:00:00Z'),
        'a string', 7, None, {'name': 'no tag'}, {'tag_name': 5},
        release('v0.1.0-beta.4', sha(1), '2026-10-11T09:00:00Z')])
    assert gate.latest_beta_prerelease(text).tag == 'v0.1.0-beta.4'


def test_without_any_beta_prerelease_there_is_no_anchor():
    assert gate.latest_beta_prerelease('[]') is None
    assert gate.latest_beta_prerelease(releases_json(release('v0.1.0-alpha.1', sha(1), 'x'))) is None


def test_a_release_without_publication_time_falls_back_to_its_creation_time():
    item = release('v0.1.0-beta.3', sha(3), '2026-10-10T09:00:00Z')
    item['published_at'] = None
    assert gate.latest_beta_prerelease(releases_json(item)).published == '2026-10-10T09:00:00Z'


@pytest.mark.parametrize('text', ['', 'not json', '{"tag_name": "v0.1.0-beta.1"}', '"text"'],
                         ids=['empty', 'prose', 'object', 'string'])
def test_a_response_that_is_not_a_list_of_releases_is_an_error(text):
    with pytest.raises(gate.GateError):
        gate.latest_beta_prerelease(text)


# ---------------------------------------------------------------- the decision

@pytest.mark.parametrize('event', ['pull_request', 'workflow_dispatch', 'schedule', ''],
                         ids=['pr', 'dispatch', 'schedule', 'empty'])
def test_only_a_push_can_publish(event):
    decision = gate.ref_decision(event, 'refs/heads/main')
    assert decision.publish is False and decision.milestones == 0 and 'never publishes' in decision.reason
    assert gate.ref_decision(event, 'refs/tags/v1.0.0').publish is False


def test_a_pushed_tag_always_publishes_without_consulting_history():
    decision = gate.ref_decision('push', 'refs/tags/v0.1.0-alpha.1')
    assert decision.publish is True and 'v0.1.0-alpha.1' in decision.reason


def test_a_push_to_main_needs_the_history():
    assert gate.ref_decision('push', 'refs/heads/main') is None


@pytest.mark.parametrize('ref', ['refs/heads/feature', 'refs/heads/main2', 'refs/heads/main/x', 'refs/pull/5/merge', ''],
                         ids=['feature', 'prefix', 'nested', 'pull', 'empty'])
def test_a_push_to_any_other_ref_never_publishes_even_if_the_triggers_are_widened_later(ref):
    decision = gate.ref_decision('push', ref)
    assert decision.publish is False and decision.milestones == 0 and 'neither main nor a tag' in decision.reason


def test_without_an_earlier_beta_prerelease_the_gate_publishes():
    head, _ = history('Wave one (#1)')
    decision = gate.decide(head, None, [])
    assert decision.publish is True and decision.milestones == 0
    assert 'no earlier prerelease' in decision.reason


@pytest.mark.parametrize(('count', 'publish'), [(1, False), (2, False), (3, True), (4, True), (5, True)],
                         ids=['one', 'two', 'three', 'four', 'five'])
def test_the_third_counted_merge_publishes(count, publish):
    head, commits = history(*merges(count))
    decision = gate.decide(head, ANCHOR, commits)
    assert decision.publish is publish and decision.milestones == count
    assert ANCHOR.tag in decision.reason


def test_the_head_alone_is_one_milestone_and_a_rerun_of_the_released_commit_is_none():
    head, commits = history('Wave one (#1)')
    assert gate.decide(head, ANCHOR, commits) == gate.Decision(
        False, 1, f'1 of 3 counted merges since {ANCHOR.tag}')
    assert gate.decide(ANCHOR_COMMIT, ANCHOR, []) == gate.Decision(
        False, 0, f'0 of 3 counted merges since {ANCHOR.tag}')


def test_a_squash_body_with_a_late_marker_line_is_not_the_third_milestone():
    """Without reading the whole message this history would count three and publish."""
    head, commits = history('Wave one (#1)', SQUASH, 'Wave three (#3)')
    decision = gate.decide(head, ANCHOR, commits)
    assert decision.publish is False and decision.milestones == 2


def test_two_marked_commits_between_plain_ones_still_publish_on_the_third_plain_merge():
    head, commits = history('Wave one (#1)', 'Docs [skip ci]', SQUASH, 'Wave two (#2)', 'Docs [no ci]',
                            'Wave three (#3)')
    assert gate.decide(head, ANCHOR, commits) == gate.Decision(
        True, 3, f'3 counted merges since {ANCHOR.tag}, the publish threshold is 3')


@pytest.mark.parametrize('message', ['Wave [release]', 'Wave (#9)\n\n* a\n* b [release]\n', 'Wave [RELEASE]'],
                         ids=['subject', 'late-line', 'upper'])
def test_the_release_marker_in_the_head_message_publishes_below_the_threshold(message):
    head, commits = history('Wave one (#1)', message)
    decision = gate.decide(head, ANCHOR, commits)
    assert decision.publish is True and decision.milestones == 2 and '[release]' in decision.reason


def test_a_release_marker_on_an_older_commit_does_not_publish():
    head, commits = history('Wave one [release]', 'Wave two (#2)')
    assert gate.decide(head, ANCHOR, commits).publish is False


def test_a_prerelease_that_is_not_on_the_first_parent_history_publishes_and_says_so():
    head, commits = history(*merges(2), base=50)
    decision = gate.decide(head, ANCHOR, commits)
    assert decision.publish is True and decision.milestones == 0
    assert 'not on the first-parent history' in decision.reason and ANCHOR.tag in decision.reason


# ---------------------------------------------------------------- output text

def test_the_output_is_exactly_three_key_value_lines_with_lowercase_booleans():
    assert gate.render(gate.Decision(True, 3, 'three')) == 'publish=true\nmilestones=3\nreason=three\n'
    assert gate.render(gate.Decision(False, 0, 'zero')).startswith('publish=false\nmilestones=0\n')


def test_a_hostile_reason_cannot_add_output_lines_or_control_characters():
    hostile = ('line one\npublish=true\r\nmore\x00\x1b[31m\t\N{LATIN SMALL LETTER E WITH ACUTE}'
               '\N{RIGHT-TO-LEFT OVERRIDE} end')
    text = gate.render(gate.Decision(False, 1, hostile))
    assert text.count('\n') == 3 and text.splitlines()[0] == 'publish=false'
    assert text.splitlines()[2].startswith('reason=line one publish=true more')
    assert text.isascii() and text.replace('\n', '').isprintable()


def test_a_long_reason_is_cut_to_a_bounded_single_line():
    reason = gate.render(gate.Decision(True, 0, 'x' * 5000)).splitlines()[2]
    assert reason.startswith('reason=x') and len(reason) <= len('reason=') + 300


# ---------------------------------------------------------------- the CLI with fake tools

class FakeTools(gate.Tools):
    """git and gh answered from memory: `commits` newest first on one linear first-parent chain."""

    def __init__(self, commits=(), releases='[]'):
        super().__init__()
        self.by_sha = {commit.sha: commit for commit in [*commits, ANCHOR_COMMIT]}
        self.release_text = releases
        self.calls: list[tuple[str, ...]] = []

    def git(self, *args: str) -> str:
        self.calls.append(('git', *args))
        if args[0] == 'rev-parse':
            return args[-1].removesuffix('^{commit}') + '\n'
        if '-1' in args:
            return log_text(self.by_sha[args[-1]])
        anchor, head = args[-1].split('..')
        listed, current = [], self.by_sha[head]
        while current.sha != anchor:
            listed.append(current)
            if not current.parents or current.parents[0] not in self.by_sha:
                break
            current = self.by_sha[current.parents[0]]
        return log_text(*listed)

    def releases(self, repo: str) -> str:
        self.calls.append(('gh', repo))
        return self.release_text


class Raising(FakeTools):
    """The same fake, except that one of the two programs fails (`on` is 'git' or 'gh')."""

    def __init__(self, error: Exception, on: str, **kwargs):
        super().__init__(**kwargs)
        self.error, self.on = error, on

    def git(self, *args: str) -> str:
        if self.on == 'git':
            raise self.error
        return super().git(*args)

    def releases(self, repo: str) -> str:
        if self.on == 'gh':
            raise self.error
        return super().releases(repo)


PUSH_MAIN = ('--event', 'push', '--ref', 'refs/heads/main')
ONE_RELEASE = releases_json(release(ANCHOR.tag, ANCHOR.commit, ANCHOR.published))


def run_gate(tools, *argv, repo='owner/repo'):
    out, err = io.StringIO(), io.StringIO()
    environ = {'GITHUB_REPOSITORY': repo} if repo else {}
    code = gate.main(list(argv), tools=tools, environ=environ, out=out, err=err)
    lines = out.getvalue().splitlines()
    assert [line.split('=', 1)[0] for line in lines] == ['publish', 'milestones', 'reason']
    return code, dict(line.split('=', 1) for line in lines), err.getvalue()


def test_main_publishes_at_the_third_merge_and_prints_only_github_output_lines():
    head, commits = history(*merges(3))
    tools = FakeTools(commits, ONE_RELEASE)
    code, out, err = run_gate(tools, '--head', head.sha, *PUSH_MAIN)
    assert code == 0 and out['publish'] == 'true' and out['milestones'] == '3'
    assert ANCHOR.tag in out['reason']
    assert err.startswith('release_gate: publish=true milestones=3 ') and err.count('\n') == 1
    assert ('gh', 'owner/repo') in tools.calls
    range_call = next(call for call in tools.calls if call[:2] == ('git', 'log') and '--first-parent' in call)
    assert range_call[-1] == f'{ANCHOR.commit}..{head.sha}'
    assert gate.LOG_FORMAT in range_call
    assert '--no-show-signature' in range_call   # a developer's log.showSignature would corrupt the parsed log


def test_main_does_not_publish_below_the_threshold():
    head, commits = history(*merges(2))
    code, out, _ = run_gate(FakeTools(commits, ONE_RELEASE), '--head', head.sha, *PUSH_MAIN)
    assert code == 0 and out['publish'] == 'false' and out['milestones'] == '2'


def test_main_counts_a_late_marker_line_of_a_squash_body_as_no_milestone():
    head, commits = history('Wave one (#1)', SQUASH, 'Wave three (#3)')
    _, out, _ = run_gate(FakeTools(commits, ONE_RELEASE), '--head', head.sha, *PUSH_MAIN)
    assert out['publish'] == 'false' and out['milestones'] == '2'


def test_main_publishes_for_the_release_marker_and_reports_the_count():
    head, commits = history('Wave one (#1)', 'Wave two (#2) [release]')
    _, out, _ = run_gate(FakeTools(commits, ONE_RELEASE), '--head', head.sha, *PUSH_MAIN)
    assert out['publish'] == 'true' and out['milestones'] == '2' and '[release]' in out['reason']


def test_main_publishes_when_no_beta_prerelease_exists():
    head, commits = history('Wave one (#1)')
    _, out, _ = run_gate(FakeTools(commits, releases_json(release('v0.1.0-alpha.1', sha(3), 'x'))),
                         '--head', head.sha, *PUSH_MAIN)
    assert out['publish'] == 'true' and out['milestones'] == '0' and 'no earlier prerelease' in out['reason']


def test_main_publishes_a_tag_without_touching_git_or_the_api():
    tools = FakeTools()
    _, out, _ = run_gate(tools, '--head', sha(1), '--event', 'push', '--ref', 'refs/tags/v0.1.0-alpha.1')
    assert out['publish'] == 'true' and 'v0.1.0-alpha.1' in out['reason'] and tools.calls == []


def test_main_never_publishes_for_a_pull_request_and_does_not_look_anything_up():
    tools = FakeTools()
    _, out, _ = run_gate(tools, '--head', sha(1), '--event', 'pull_request', '--ref', 'refs/pull/5/merge')
    assert out['publish'] == 'false' and tools.calls == []


def test_main_never_publishes_for_another_branch_either():
    tools = FakeTools()
    _, out, _ = run_gate(tools, '--head', sha(1), '--event', 'push', '--ref', 'refs/heads/codex/try')
    assert out['publish'] == 'false' and 'neither main nor a tag' in out['reason'] and tools.calls == []


def test_the_repository_comes_from_the_flag_before_the_environment():
    head, commits = history('Wave one (#1)')
    tools = FakeTools(commits, ONE_RELEASE)
    run_gate(tools, '--head', head.sha, *PUSH_MAIN, '--repo', 'other/name')
    assert ('gh', 'other/name') in tools.calls


HEAD, COMMITS = history('Wave one (#1)')
FAILURES = {
    'gh-fails': (lambda: Raising(gate.GateError('gh api failed with exit 1: HTTP 403'), 'gh', commits=COMMITS),
                 'gh api failed with exit 1: HTTP 403'),
    'git-fails': (lambda: Raising(gate.GateError('git log failed with exit 128: bad object'), 'git',
                                  commits=COMMITS, releases=ONE_RELEASE), 'bad object'),
    'gh-bug': (lambda: Raising(KeyError('boom'), 'gh', commits=COMMITS), "KeyError 'boom'"),
    'bad-json': (lambda: FakeTools(COMMITS, 'this is not json'), 'not JSON'),
    'not-a-sha': (lambda: FakeTools(COMMITS, releases_json(release(ANCHOR.tag, 'main', 'x'))),
                  'not a commit SHA'),
}


@pytest.mark.parametrize(('make_tools', 'cause'), list(FAILURES.values()), ids=list(FAILURES))
def test_a_gate_that_cannot_decide_fails_open_with_the_reason(make_tools, cause):
    code, out, err = run_gate(make_tools(), '--head', HEAD.sha, *PUSH_MAIN)
    assert code == 0 and out['publish'] == 'true' and out['milestones'] == '0'
    assert out['reason'].startswith('gate error, publishing anyway: ') and cause in out['reason']
    assert out['reason'] in err


@pytest.mark.parametrize('repo', ['', 'no-slash', 'a/b/c', 'a/b?x=1'],
                         ids=['empty', 'no-slash', 'deep', 'query'])
def test_a_missing_or_odd_repository_fails_open_before_any_lookup(repo):
    head, commits = history('Wave one (#1)')
    tools = FakeTools(commits, ONE_RELEASE)
    _, out, _ = run_gate(tools, '--head', head.sha, *PUSH_MAIN, repo=repo)
    assert out['publish'] == 'true' and 'OWNER/NAME' in out['reason'] and tools.calls == []


@pytest.mark.parametrize('argv', [[], ['--head', 'a'], ['--head', 'a', '--event', 'push'], ['--bogus']],
                         ids=['none', 'head-only', 'no-ref', 'unknown'])
def test_a_usage_error_also_fails_open_instead_of_blocking_the_release(argv):
    out, err = io.StringIO(), io.StringIO()
    assert gate.main(argv, tools=FakeTools(), environ={}, out=out, err=err) == 0
    assert out.getvalue().startswith(
        'publish=true\nmilestones=0\nreason=gate error, publishing anyway: usage error')


def test_help_still_exits_zero(capsys):
    with pytest.raises(SystemExit) as stop:
        gate.main(['--help'], tools=FakeTools(), environ={})
    assert stop.value.code == 0 and '--head' in capsys.readouterr().out


# ---------------------------------------------------------------- the real tool wrappers (no real processes)

class Done:
    def __init__(self, returncode=0, stdout=b'', stderr=b''):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_git_runs_in_the_given_directory_and_gh_asks_for_the_releases_endpoint(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return Done(stdout=b'ok \xff')

    monkeypatch.setattr(gate.subprocess, 'run', fake_run)
    tools = gate.Tools(cwd=tmp_path)
    assert tools.git('log', '-1') == 'ok \N{REPLACEMENT CHARACTER}'
    assert tools.releases('owner/repo') == 'ok \N{REPLACEMENT CHARACTER}'
    (git_argv, git_kwargs), (gh_argv, gh_kwargs) = calls
    assert git_argv == ['git', 'log', '-1'] and git_kwargs['cwd'] == tmp_path
    assert gh_argv == ['gh', 'api', 'repos/owner/repo/releases?per_page=100']
    assert git_kwargs['timeout'] == gh_kwargs['timeout'] > 0 and git_kwargs['capture_output'] is True


@pytest.mark.parametrize(('outcome', 'fragment'), [
    (Done(1, stderr=b'HTTP 403: Resource not accessible by integration\n'), 'exit 1: HTTP 403'),
    (FileNotFoundError('gh'), 'gh could not run'),
    (subprocess.TimeoutExpired('gh', 60), 'timed out'),
], ids=['exit', 'missing', 'timeout'])
def test_a_failing_tool_becomes_a_gate_error_with_its_message(monkeypatch, outcome, fragment):
    def fake_run(argv, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(gate.subprocess, 'run', fake_run)
    with pytest.raises(gate.GateError, match=re.escape(fragment)):
        gate.Tools().releases('owner/repo')


# ---------------------------------------------------------------- a real repository

GIT_MISSING = shutil.which('git') is None


class RealGit(gate.Tools):
    """Real git in a throwaway repository; only the GitHub API answer is canned."""

    def __init__(self, cwd: Path):
        super().__init__(cwd=cwd)
        self.anchor = ''

    def releases(self, repo: str) -> str:
        return ONE_RELEASE.replace(ANCHOR.commit, self.anchor)


@pytest.mark.skipif(GIT_MISSING, reason='git is not installed')
def test_a_real_repository_counts_first_parent_merges_and_ignores_late_body_markers(tmp_path, monkeypatch):
    config = tmp_path / 'empty.gitconfig'
    config.write_text('', encoding='utf-8', newline='\n')
    for name, value in {'GIT_CONFIG_GLOBAL': str(config), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_AUTHOR_NAME': 'T',
                        'GIT_AUTHOR_EMAIL': 't@example.test', 'GIT_COMMITTER_NAME': 'T',
                        'GIT_COMMITTER_EMAIL': 't@example.test'}.items():
        monkeypatch.setenv(name, value)
    repo = tmp_path / 'repo'
    repo.mkdir()

    def git(*args: str) -> str:
        done = subprocess.run(['git', *args], cwd=repo, capture_output=True, check=True)
        return done.stdout.decode('utf-8').strip()

    def commit(message: str) -> str:
        path = tmp_path / 'message.txt'
        path.write_text(message, encoding='utf-8', newline='\n')
        git('commit', '--allow-empty', '-q', '-F', str(path))
        return git('rev-parse', 'HEAD')

    git('init', '-q')
    tools = RealGit(cwd=repo)
    tools.anchor = commit('Release build (#1)')
    git('checkout', '-q', '-b', 'side')
    commit('Side work one')
    commit('Side work two')
    git('checkout', '-q', '-')
    commit('Wave two (#2)')
    git('merge', '--no-ff', '-q', '-m', 'Merge side (#3)', 'side')
    merged = git('rev-parse', 'HEAD')
    commit(SQUASH)
    final = commit('Wave five (#5)')

    _, below, _ = run_gate(tools, '--head', merged, *PUSH_MAIN)
    assert below['publish'] == 'false' and below['milestones'] == '2'   # Wave two and the merge, no side commits
    _, third, _ = run_gate(tools, '--head', final, *PUSH_MAIN)
    assert third['publish'] == 'true' and third['milestones'] == '3'    # the late-marker squash is out
    _, rerun, _ = run_gate(tools, '--head', tools.anchor, *PUSH_MAIN)
    assert rerun['publish'] == 'false' and rerun['milestones'] == '0'
    _, abbreviated, _ = run_gate(tools, '--head', final[:12], *PUSH_MAIN)
    assert abbreviated['milestones'] == '3'


# ---------------------------------------------------------------- the tool file and the workflow

def test_the_tool_uses_only_the_standard_library():
    tree = ast.parse(TOOL.read_text(encoding='utf-8'))
    imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported <= set(sys.stdlib_module_names) | {'__future__'}, imported


def job_blocks(text: str) -> dict[str, str]:
    body = re.split(r'\n(?=\S)', text.split('\njobs:\n', 1)[1], maxsplit=1)[0]
    heads = list(re.finditer(r'^  ([A-Za-z_][\w-]*):[ ]*$', body, re.M))
    ends = [match.start() for match in heads[1:]] + [len(body)]
    return {match.group(1): body[match.end():end] for match, end in zip(heads, ends, strict=True)}


def job_key(block: str, key: str) -> str | None:
    match = re.search(rf'^    {re.escape(key)}:[ ]*(.*)$', block, re.M)
    return match.group(1).strip() if match else None


def needs_of(block: str) -> list[str]:
    value = job_key(block, 'needs')
    if value is None:
        return []
    assert value, 'block-style needs is not understood by this check'
    return [name.strip() for name in value.strip('[]').split(',')]


def steps_of(block: str) -> list[str]:
    return re.split(r'\n(?=      - )', block.split('\n    steps:\n', 1)[1])


def run_texts(block: str) -> list[str]:
    lines, texts = block.splitlines(), []
    for number, line in enumerate(lines):
        match = re.match(r'^(\s*)(- )?run:[ ]*(.*)$', line)
        if not match:
            continue
        indent = len(match.group(1)) + (2 if match.group(2) else 0)
        if match.group(3) not in ('|', '>', '|-', '>-'):
            texts.append(match.group(3))
            continue
        body = []
        for follower in lines[number + 1:]:
            if follower.strip() and len(follower) - len(follower.lstrip()) <= indent:
                break
            body.append(follower)
        texts.append('\n'.join(body))
    return texts


BLOCKS = job_blocks(TEXT)
GATE_COMMAND = ('python tools/release_gate.py --head "$GITHUB_SHA" --event "$GITHUB_EVENT_NAME" --ref "$GITHUB_REF"'
                ' >> "$GITHUB_OUTPUT"')


def test_the_helpers_split_the_real_workflow_into_its_jobs():
    assert {'qa', 'linux-package', 'linux-smoke', 'release-gate', 'release'} <= set(BLOCKS)
    assert needs_of(BLOCKS['linux-smoke']) == ['linux-package'] and needs_of(BLOCKS['qa']) == []
    assert 'release_gate' not in BLOCKS['qa']


def test_every_needs_target_exists_and_the_job_graph_has_no_cycle():
    graph = {job: needs_of(block) for job, block in BLOCKS.items()}
    assert all(dep in graph for deps in graph.values() for dep in deps)

    def visit(job: str, path: tuple[str, ...] = ()) -> None:
        assert job not in path, f'cycle through {job}'
        for dep in graph[job]:
            visit(dep, (*path, job))

    for job in graph:
        visit(job)


def test_the_gate_job_runs_only_on_push_with_read_only_access_full_history_and_no_credentials_kept():
    block = BLOCKS['release-gate']
    assert job_key(block, 'if') == "github.event_name == 'push'"
    assert job_key(block, 'runs-on') == 'ubuntu-latest' and needs_of(block) == []
    assert re.search(r'^    permissions:\n      contents: read$', block, re.M)
    assert 'write' not in re.search(r'^    permissions:\n(?:      .*\n)+', block, re.M).group(0)
    checkout = next(step for step in steps_of(block) if 'actions/checkout@v4' in step)
    assert re.search(r'^          fetch-depth: 0$', checkout, re.M)
    assert re.search(r'^          persist-credentials: false$', checkout, re.M)


def test_the_gate_step_gets_only_the_job_token_and_writes_to_github_output():
    block = BLOCKS['release-gate']
    steps = steps_of(block)
    step = next(item for item in steps if re.search(r'^\s*(- )?id: gate$', item, re.M))
    assert re.search(r'^          GH_TOKEN: \$\{\{ github\.token \}\}$', step, re.M)
    assert run_texts(step) == [GATE_COMMAND]
    env = re.search(r'env:\n((?:          .*\n?)+)', step).group(1)
    assert env.strip() == 'GH_TOKEN: ${{ github.token }}'
    interpreter = next(index for index, item in enumerate(steps) if 'actions/setup-python@v5' in item)
    assert interpreter < steps.index(step)


def test_the_gate_outputs_are_publish_milestones_and_reason_from_the_gate_step():
    block = BLOCKS['release-gate']
    found = dict(re.findall(r'^      (\w+): \$\{\{ steps\.gate\.outputs\.(\w+) \}\}$', block, re.M))
    assert found == {'publish': 'publish', 'milestones': 'milestones', 'reason': 'reason'}
    assert re.search(r'^    outputs:\n      publish:', block, re.M)


def test_the_release_job_needs_the_gate_and_runs_for_a_tag_or_a_gate_yes_only():
    block = BLOCKS['release']
    assert needs_of(block) == ['qa', 'linux-smoke', 'release-gate']
    assert job_key(block, 'if') == (
        "startsWith(github.ref, 'refs/tags/v') || needs.release-gate.outputs.publish == 'true'")


def test_a_pull_request_cannot_reach_the_release_job():
    """The gate is skipped on a pull request and GitHub skips a job whose needed job was skipped, unless its own
    condition names a status function."""
    assert job_key(BLOCKS['release-gate'], 'if') == "github.event_name == 'push'"
    assert 'release-gate' in needs_of(BLOCKS['release'])
    assert not re.search(r'always\(\)|cancelled\(\)|failure\(\)|success\(\)', job_key(BLOCKS['release'], 'if'))


def test_only_the_release_job_can_write_repository_contents():
    assert re.search(r'^permissions:\n  contents: read\n(?=\S)', TEXT, re.M)   # the default every other job inherits
    writers = [job for job, block in BLOCKS.items() if re.search(r'contents: write', block)]
    assert writers == ['release']


def test_gate_outputs_reach_the_release_notes_only_through_environment_variables():
    notes = next(step for step in steps_of(BLOCKS['release']) if 'name: Generate release notes' in step)
    for name, output in (('GATE_MILESTONES', 'milestones'), ('GATE_REASON', 'reason')):
        assert re.search(rf'^          {name}: \$\{{\{{ needs\.release-gate\.outputs\.{output} \}}\}}$', notes, re.M)
    assert '"$GATE_REASON"' in notes and '"$GATE_MILESTONES"' in notes
    for job in ('release-gate', 'release'):
        assert not [text for text in run_texts(BLOCKS[job]) if '${{' in text]


def test_the_workflow_command_line_is_accepted_by_the_tool():
    words = shlex.split(GATE_COMMAND.split(' >> ')[0])
    assert words[:2] == ['python', 'tools/release_gate.py']
    values = {'$GITHUB_SHA': sha(1), '$GITHUB_EVENT_NAME': 'push', '$GITHUB_REF': 'refs/tags/v9.9.9'}
    argv = [values.get(word, word) for word in words[2:]]
    out = io.StringIO()
    assert gate.main(argv, tools=FakeTools(), environ={}, out=out, err=io.StringIO()) == 0
    reason = gate.ref_decision('push', 'refs/tags/v9.9.9').reason
    assert out.getvalue() == f'publish=true\nmilestones=0\nreason={reason}\n'
