"""Consent for the developer fetch paths (SPEC-42 rows 12 to 14, gaps F2 and F3): the calibration download and the
tier-R git fetch refuse without their explicit step, and the consent-checked opener is the only way out.

Hermetic: every test runs under the network guard (tests/network_guard.py). The git child of the tier-R fetch is a
process, so it is replaced by a recorder and observed by argv and environment."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from network_guard import Attempt, NetworkAttempt, network_guard_fixture  # noqa: F401

from patchtrace.acquisition import transport as acquisition
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.jobs import ProcessResult

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.calibration import corpus  # noqa: E402
from tools.calibration.contracts import load_manifest  # noqa: E402
from tools.calibration.tier_r import fetch as tier_r  # noqa: E402
from tools.calibration.tier_r.toolchain import Tool, Toolchain, ToolError  # noqa: E402

PAYLOADS = {'b001': b'payload-one', 'b002': b'payload-two'}
SECRETS = {'GITHUB_TOKEN': 'ghp_' + 'A1b2C3d4' * 5, 'GH_TOKEN': 'gho_' + 'Z9y8X7w6' * 5,
           'NVD_API_KEY': 'nvd-session-key-1234', 'OPENAI_API_KEY': 'sk-session-key-abcdef123456',
           'AWS_SECRET_ACCESS_KEY': 'aws-secret-value-98765', 'GIT_ASKPASS': '/opt/askpass',
           'SSH_AUTH_SOCK': '/run/agent.sock'}
PROXY = 'http://proxy.invalid:3128'


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def manifest_path(tmp_path, monkeypatch):
    monkeypatch.setenv(corpus.ROOT_ENV, str(tmp_path / 'calibration-root'))
    binaries = [{'id': name, 'tier': 'W', 'file_name': 'ntdll.dll', 'arch': 'x64', 'sha256': _sha(data),
                 'size': len(data), 'winbindex': {'timestamp': stamp, 'virtual_size': 4096},
                 'redistribution': 'none'} for (name, data), stamp in zip(PAYLOADS.items(), (1, 2), strict=True)]
    doc = {'contract': 'calibration-corpus/1', 'corpus_id': 'c-consent', 'created': '2026-10-14', 'tool_git': 'abc',
           'binaries': binaries, 'pairs': [],
           'lineages': [{'id': 'L-ntdll', 'members': list(PAYLOADS), 'cluster_rule': 'file-name',
                         'cluster_evidence_sha256': _sha(b'evidence')}],
           'split': {'salt': 'c9-v1', 'method': 'sha256'}}
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(doc), encoding='utf-8', newline='\n')
    return path


def _plan(manifest_path: Path) -> list[dict]:
    return corpus.fetch_plan(load_manifest(manifest_path.read_bytes()))


def _stored_files(tmp_path: Path) -> list[Path]:
    root = tmp_path / 'calibration-root'
    return sorted(root.rglob('*')) if root.exists() else []


# --- calibration download (row 13, gap F2) ------------------------------------------------------------------------

@pytest.mark.parametrize('command', ['fetch', 'fetch-plan'], ids=['fetch-without-flag', 'fetch-plan'])
def test_without_the_download_flag_the_plan_is_printed_and_nothing_is_requested(
        command, manifest_path, tmp_path, capsys, monkeypatch, network_guard):
    monkeypatch.setattr(corpus, '_urllib_download', lambda url: pytest.fail(f'requested {url} without --download'))
    assert corpus.main([command, str(manifest_path)]) == 0
    assert json.loads(capsys.readouterr().out) == _plan(manifest_path)
    assert _stored_files(tmp_path) == []
    assert network_guard.attempts == []


def test_with_the_download_flag_only_the_planned_urls_go_through_the_one_opener(
        manifest_path, tmp_path, capsys, monkeypatch, network_guard):
    served = {item['url']: PAYLOADS[item['id']] for item in _plan(manifest_path)}
    requested = []

    def opener(url):
        requested.append(url)
        return served[url]
    monkeypatch.setattr(corpus, '_urllib_download', opener)
    assert corpus.main(['fetch', str(manifest_path), '--download']) == 0
    assert requested == list(served)
    assert all(url.startswith('https://msdl.microsoft.com/download/symbols/') for url in requested)
    assert json.loads(capsys.readouterr().out)['stored'] == ['b001', 'b002']
    requested.clear()
    assert corpus.main(['fetch', str(manifest_path), '--download']) == 0  # already stored: nothing is requested again
    assert requested == [] and json.loads(capsys.readouterr().out)['present'] == ['b001', 'b002']
    assert network_guard.attempts == []


def test_a_failed_download_is_reported_and_stores_nothing(manifest_path, tmp_path, capsys, monkeypatch):
    def refused(url):
        raise OSError(f'connection to {url} refused')
    monkeypatch.setattr(corpus, '_urllib_download', refused)
    assert corpus.main(['fetch', str(manifest_path), '--download']) == 1
    failed = json.loads(capsys.readouterr().out)['failed']
    assert failed == ['b001: OSError', 'b002: OSError']  # the exception text, which may name a URL, is dropped
    assert [p for p in _stored_files(tmp_path) if p.is_file()] == []


@pytest.mark.parametrize('url', ['http://msdl.microsoft.com/download/symbols/a.dll/1/a.dll',
                                 'file:///etc/passwd', 'ftp://msdl.microsoft.com/a.dll', ''],
                         ids=['http', 'file', 'ftp', 'empty'])
def test_the_real_opener_refuses_anything_but_https_before_it_opens(url, network_guard):
    with pytest.raises(ValueError, match='https only'):
        corpus._urllib_download(url)
    assert network_guard.attempts == []


def test_the_real_opener_makes_one_https_request_for_the_planned_url_only(manifest_path, network_guard):
    url = _plan(manifest_path)[0]['url']
    with pytest.raises(NetworkAttempt):
        corpus._urllib_download(url)
    assert network_guard.claim() == [Attempt('urllib', url)]


class _Body:
    """What `urlopen` returns, with a body of `size` bytes."""

    def __init__(self, size):
        self.size = size

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit):
        return b'x' * min(self.size, limit)


def test_the_real_opener_keeps_its_timeout_and_size_cap(monkeypatch):
    seen = []

    def serve(size):
        def urlopen(url, timeout):
            seen.append((url, timeout))
            return _Body(size)
        monkeypatch.setattr('urllib.request.urlopen', urlopen)

    monkeypatch.setattr(corpus, 'MAX_DOWNLOAD', 8)
    serve(8)
    assert corpus._urllib_download('https://msdl.microsoft.com/x') == b'x' * 8
    assert seen == [('https://msdl.microsoft.com/x', 120)]
    serve(9)
    with pytest.raises(ValueError, match='too large'):
        corpus._urllib_download('https://msdl.microsoft.com/x')


# --- the consent-checked opener (row 2) ---------------------------------------------------------------------------

def test_calibration_plan_urls_pass_the_consent_checked_opener(manifest_path, network_guard):
    urls = [item['url'] for item in _plan(manifest_path)]
    seen = []

    class Found:
        status, headers = 302, {}

        def close(self):
            pass

    def opener(method, url, headers, timeout):
        seen.append((method, url))
        return Found()
    transport = acquisition.Transport(opener=opener)
    consent = acquisition.AcquisitionConsent.for_urls(urls)
    assert [transport.probe(url, consent) for url in urls] == [True, True]
    assert seen == [('HEAD', url) for url in urls]
    stray = urls[0].replace('000000011000', '000000019999')
    with pytest.raises(AcquisitionError) as refused:
        transport.probe(stray, consent)
    assert refused.value.code == 'PT-ACQ-CONFIG' and len(seen) == 2


# --- tier-R git fetch (row 12, gap F3) ----------------------------------------------------------------------------

URL = 'https://github.com/madler/zlib'
COMMIT = '0123456789abcdef0123456789abcdef01234567'
GIT_STEPS = ('init', 'fetch', 'checkout', 'rev-parse', 'show')


class FakeGit:
    """Stands in for `run_tool`: records each call and answers like git would for one clean fetch."""

    def __init__(self, head=COMMIT, fail_on=None):
        self.calls: list[tuple[list[str], dict]] = []
        self.head, self.fail_on = head, fail_on

    def step(self, argv):
        return next(word for word in argv[1:] if word in GIT_STEPS)

    def __call__(self, argv, *, cwd=None, env=None, timeout=None, check=False, **_):
        step = self.step(argv)
        self.calls.append((list(argv), {'cwd': cwd, 'env': dict(env or {}), 'step': step}))
        if step == self.fail_on:
            raise ToolError(f'git {step} failed (1): fatal: unable to access the repository')
        if step == 'init':
            (Path(argv[-1]) / '.git').mkdir(parents=True)
        elif step == 'fetch':
            (Path(cwd) / 'LICENSE').write_text('zlib licence\n', encoding='utf-8', newline='\n')
        elif step == 'rev-parse':
            return ProcessResult(0, self.head + '\n')
        elif step == 'show':
            return ProcessResult(0, '1700000000\nA. Author\nFix the thing\n')
        return ProcessResult(0, '')

    @property
    def steps(self):
        return [info['step'] for _argv, info in self.calls]


@pytest.fixture
def git(tmp_path, monkeypatch):
    fake = FakeGit()
    monkeypatch.setattr(tier_r, 'run_tool', fake)
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('HTTPS_PROXY', PROXY)
    return fake


@pytest.fixture
def toolchain(tmp_path):
    return Toolchain({'git': Tool('git', str(tmp_path / 'tools' / 'git'))})


def _dest(tmp_path) -> Path:
    return tmp_path / 'store' / 'src' / 'zlib' / 'checkout'


def _fetch(tmp_path, toolchain, url=URL, commit=COMMIT):
    return tier_r.fetch_commit(url, commit, _dest(tmp_path), toolchain)


REFUSED_URLS = [
    ('http://github.com/madler/zlib', 'http-scheme'),
    ('https://gitlab.com/madler/zlib', 'other-host'),
    ('https://github.com.evil.example/madler/zlib', 'suffix-host'),
    ('https://evilgithub.com/madler/zlib', 'prefix-host'),
    ('https://token@github.com/madler/zlib', 'userinfo'),
    ('https://github.com:8443/madler/zlib', 'port'),
    ('git@github.com:madler/zlib.git', 'scp-syntax'),
    ('ssh://git@github.com/madler/zlib', 'ssh-scheme'),
    ('file:///tmp/repo', 'file-scheme'),
    ('https://github.com/madler', 'no-repository'),
    ('https://github.com/madler/zlib?ref=main', 'query'),
    ('', 'empty'),
]
REFUSED_COMMITS = [('main', 'branch'), ('abc1234', 'abbreviated'), ('', 'empty'), ('A' * 40, 'uppercase'),
                   ('g' * 40, 'not-hex'), ('f' * 39, 'short'), ('f' * 41, 'long')]


@pytest.mark.parametrize(('url', 'commit'),
                         [(url, COMMIT) for url, _ in REFUSED_URLS] + [(URL, commit) for commit, _ in REFUSED_COMMITS],
                         ids=[f'url-{name}' for _, name in REFUSED_URLS]
                         + [f'commit-{name}' for _, name in REFUSED_COMMITS])
def test_an_unapproved_source_is_refused_before_any_process_or_directory(
        url, commit, git, tmp_path, toolchain, network_guard):
    with pytest.raises(tier_r.FetchError):
        _fetch(tmp_path, toolchain, url, commit)
    assert git.calls == [] and not (tmp_path / 'store').exists()
    assert network_guard.attempts == []


def test_one_pinned_commit_is_fetched_over_https_only_with_a_clean_environment(git, tmp_path, toolchain,
                                                                              network_guard):
    done = _fetch(tmp_path, toolchain)
    assert git.steps == list(GIT_STEPS)
    fetch_argv = git.calls[1][0]
    assert fetch_argv[-2:] == [URL, COMMIT] and fetch_argv[-5:-2] == ['--depth', '1', '--no-tags']
    pairs = [fetch_argv[i + 1] for i, word in enumerate(fetch_argv) if word == '-c']
    assert {'protocol.allow=never', 'protocol.https.allow=always', 'credential.helper=', 'core.symlinks=false',
            'submodule.recurse=false'} <= set(pairs)
    assert any(pair.startswith('core.hooksPath=') for pair in pairs)
    for _argv, info in git.calls:
        env = info['env']
        assert not set(SECRETS) & set(env) and not any(value in SECRETS.values() for value in env.values())
        assert env['GIT_TERMINAL_PROMPT'] == '0' and env['GIT_CONFIG_NOSYSTEM'] == '1'
        assert env['HOME'] != str(Path.home()) and env['GIT_CONFIG_GLOBAL'].startswith(env['HOME'])
        assert env['HTTPS_PROXY'] == PROXY  # the one deliberate network variable
    dest = _dest(tmp_path)
    assert done == tier_r.receipt(dest) and done['url'] == URL and done['commit'] == COMMIT and done['verified']
    assert (dest / 'LICENSE').is_file() and not (dest / '.git').exists()
    assert network_guard.attempts == []


def test_a_verified_checkout_is_not_fetched_again_and_a_new_pin_is(git, tmp_path, toolchain):
    first = _fetch(tmp_path, toolchain)
    calls = len(git.calls)
    assert _fetch(tmp_path, toolchain) == first and len(git.calls) == calls
    other = 'f' * 40
    git.head = other
    assert _fetch(tmp_path, toolchain, commit=other)['commit'] == other  # same directory, new pin: fetched again
    assert len(git.calls) == calls + len(GIT_STEPS)


@pytest.mark.parametrize('fail_on', ['init', 'fetch', 'checkout'], ids=['init', 'fetch', 'checkout'])
def test_a_failed_git_step_leaves_no_checkout_and_no_temporary_directory(fail_on, git, tmp_path, toolchain):
    git.fail_on = fail_on
    with pytest.raises(tier_r.FetchError, match=f'git {fail_on} failed'):
        _fetch(tmp_path, toolchain)
    store = tmp_path / 'store' / 'src' / 'zlib'
    assert list(store.iterdir()) == []


def test_a_checkout_that_is_not_the_pin_is_refused(git, tmp_path, toolchain):
    git.head = 'f' * 40
    with pytest.raises(tier_r.FetchError, match='does not equal the pin'):
        _fetch(tmp_path, toolchain)
    assert list((tmp_path / 'store' / 'src' / 'zlib').iterdir()) == []
