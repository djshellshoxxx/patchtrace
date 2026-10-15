"""`redact_log` covers Cookie, SAS, Slack, JWT and argv-style secrets, stays linear on hostile input, and the CLI uses it.

SPEC-42 R7. Slice CONSENT found that `redact_log` left Cookie and Set-Cookie values, Azure SAS `sig=` values, Slack
tokens, JWTs and `--password x` arguments visible, and that `cli.main` printed an unexpected exception unredacted.
Every secret below is synthetic. Hermetic: no network and no target execution; the one child process only imports
`patchtrace.diagnostics`, because a regex that never finishes cannot be interrupted from the thread that runs it."""
from __future__ import annotations

import json
import os
import string
import subprocess
import sys
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st

import patchtrace
from patchtrace import cli
from patchtrace.diagnostics import redact_log

JWT_PARTS = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0',
             'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
JWT = '.'.join(JWT_PARTS)
SLACK_TAIL = '123456789012-1234567890123-cvAbCdEfGhIjKlMnOpQrStUv'

# id: (line, secret fragments that must vanish, text that must stay). The surrounding lines are checked as well.
SHAPES = {
    'cookie': ('Cookie: sid=cvf3a9c1e5b2d4a7; JSESSIONID=cv0A1B2C3D4E5F60',
               ('cvf3a9c1e5b2d4a7', 'cv0A1B2C3D4E5F60'), ('Cookie: [redacted]',)),
    'cookie-lower': ('cookie: sid=cv9f2e7a1c4b8d60; theme=dark', ('cv9f2e7a1c4b8d60',), ('cookie: [redacted]',)),
    'set-cookie': ('Set-Cookie: session=cv5b2d4a60e1c8f3; Path=/; HttpOnly; Secure',
                   ('cv5b2d4a60e1c8f3',), ('Set-Cookie: [redacted]',)),
    'set-cookie-trace': ('< set-cookie: auth=cv9d1f7a8b20c3e4; Max-Age=3600',
                         ('cv9d1f7a8b20c3e4',), ('< set-cookie: [redacted]',)),
    'cookie-json': ('{"headers": {"Cookie": "sid=cv3c9d1f7a8b20e4; theme=dark"}}',
                    ('cv3c9d1f7a8b20e4',), ('{"headers": {"Cookie": [redacted]',)),
    'cookie-dict': ("headers={'Cookie': 'sid=cv62b8f3d1a7c4e9', 'Accept': '*/*'}",
                    ('cv62b8f3d1a7c4e9',), ("headers={'Cookie': [redacted]",)),
    'cookie-curl': ("curl -H 'Cookie: sid=cv8d2f6a1c4e90b3' https://mirror.invalid/",
                    ('cv8d2f6a1c4e90b3',), ("curl -H 'Cookie: [redacted]",)),
    'sas-url': ('GET https://acct.blob.core.windows.net/c/b.bin?sv=2022-11-02&sp=r&sig=cvAbCd%2Fe12Fg%2BhIj%3D'
                '&se=2026-12-31T00%3A00%3A00Z&spr=https', ('cvAbCd%2Fe12Fg%2BhIj%3D', 'cvAbCd'),
                ('?sv=2022-11-02&sp=r&sig=[redacted]&se=2026-12-31T00%3A00%3A00Z&spr=https',)),
    'sas-first': ('https://acct.file.core.windows.net/share/f?sig=cvQ7w3E9r1T5y2%3D&sv=2022-11-02',
                  ('cvQ7w3E9r1T5y2',), ('f?sig=[redacted]&sv=2022-11-02',)),
    'sas-raw': ('https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig=cv9f2e7a1c4b8d6035+aB/cD==&se=2026',
                ('cv9f2e7a1c4b8d6035', 'aB/cD=='), ('&sig=[redacted]&se=2026',)),
    'sas-xml': ('<Url>https://acct.blob.core.windows.net/c?sv=2022-11-02&amp;sig=cv1e5b2d4a60e1c8f3&amp;se=2026</Url>',
                ('cv1e5b2d4a60e1c8f3',), ('&amp;sig=[redacted]&amp;se=2026</Url>',)),
    'sas-json': ('{"url": "https://acct.blob.core.windows.net/c?sv=2022&sig=cv4a60e1c8f3d7b2%3D"}',
                 ('cv4a60e1c8f3d7b2',), ('&sig=[redacted]"}',)),
    **{f'slack-xox{kind}': (f'posting with xox{kind}-{SLACK_TAIL}', (SLACK_TAIL, 'cvAbCdEfGhIj'),
                            ('posting with [redacted]',)) for kind in 'abprs'},
    'jwt-bare': (f'session {JWT} expired', JWT_PARTS, ('session [redacted] expired',)),
    'jwt-json': (f'{{"jwt": "{JWT}", "ttl": 60}}', JWT_PARTS, ('{"jwt": "[redacted]", "ttl": 60}',)),
    'jwt-fragment': (f'GET /callback#jwt={JWT}&state=x', JWT_PARTS, ('#jwt=[redacted]&state=x',)),
    'jwt-escaped': (f'next=https%3A%2F%2Fapp.invalid%2Fcb%3Fjwt%3D{JWT}%26state%3Dx', JWT_PARTS,
                    ('%3Fjwt%3D[redacted]%26state%3Dx',)),
    'jwt-unsigned': ('unsecured eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9. accepted',
                     ('eyJhbGciOiJub25lIn0', 'eyJzdWIiOiJhZG1pbiJ9'), ('unsecured [redacted] accepted',)),
    'argv-password': ('ghidriff run --password cvHunter2-7d3f --user bob',
                      ('cvHunter2-7d3f',), ('--password [redacted] --user bob',)),
    'argv-token': ('worker --token cv-tok-8d2f6a1c4e90 --verbose',
                   ('cv-tok-8d2f6a1c4e90',), ('--token [redacted] --verbose',)),
    'argv-dquote': ('login --password "cv pass 91e4 spaces" --retry 3',
                    ('cv pass', '91e4 spaces'), ('--password [redacted] --retry 3',)),
    'argv-squote': ("login --token 'cv tok 62b8 spaces' --retry 3",
                    ('cv tok', '62b8 spaces'), ('--token [redacted] --retry 3',)),
    'argv-prefixed': ('--github-token cv7f3a9c1e5b2d4a --nvd-api-key cvnvd5e1c8a3f7b2 --out x',
                      ('cv7f3a9c1e5b2d4a', 'cvnvd5e1c8a3f7b2'),
                      ('--github-token [redacted] --nvd-api-key [redacted] --out x',)),
    'argv-repr': ("Command '['python', '-m', 'ghidriff', '--token', 'cvAbC123xyz', '--out', 'x']' returned non-zero "
                  'exit status 1.', ('cvAbC123xyz',),
                  ("'--token', [redacted], '--out'", 'returned non-zero exit status 1.')),
    'argv-open-quote': ('login --password "cvunterminated91e4', ('cvunterminated91e4',),
                        ('login --password [redacted]',)),
    'argv-glued': ('run --token [redacted]cvglued91e4c7a2 --x', ('cvglued91e4c7a2',), ('run --token [redacted] --x',)),
    # The userinfo rule was rewritten to be linear: a URL glued to a long prefix must still lose its credentials.
    'url-after-run': ('p' * 60 + 'https://analyst:cvUrlPw7d3f9b1e@mirror.invalid/x',
                      ('cvUrlPw7d3f9b1e',), ('https://[redacted]@mirror.invalid/x',)),
}

HEX = {'md5': '9e107d9d372bb6826bd81d3542a419d6', 'sha1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
       'sha256': '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'}
HEX['sha512'] = HEX['sha256'] + HEX['sha256'].upper()
# Text that mentions the same words and shapes without carrying a credential: it must come back byte for byte.
ORDINARY = {
    'cookie-prose': 'The cookie jar is empty; Set-Cookie headers are not logged and cookies expire at midnight.',
    'sig-prose': 'process killed with sig=15 after design&sigma=2 and ?sign=1 (sig_alg=rs256, signature_ok=true)',
    'slack-prose': 'xoxo from the Slack channel; xoxb-short is not a token and neither is xox-12345678901234',
    'jwt-prose': 'eyJhbGciOiJIUzI1NiJ9 is only a header; a.b.c and eyJ..eyJ are not tokens; eyJhbGci.notjson.sig',
    'flag-prose': 'pass --token-file keys.txt, --password-stdin, --max-tokens 100 and --secret-store vault',
    'url-plain': 'see https://example.com/a@b and https://example.com/x?sig_alg=rs256&sv=2022-11-02',
    **{f'digest-{name}': f'{name}: {digest}' for name, digest in HEX.items()},
    'commit': f'commit {HEX["sha1"]} fixed {HEX["md5"]} in function read_item at 0x1000',
}


@pytest.mark.parametrize(('line', 'secrets', 'kept'), list(SHAPES.values()), ids=list(SHAPES))
def test_each_credential_shape_is_redacted_and_the_rest_of_the_log_is_kept(line, secrets, kept):
    redacted = redact_log(f'before\n{line}\nafter')
    assert [secret for secret in secrets if secret in redacted] == []
    assert redacted.startswith('before\n') and redacted.endswith('\nafter') and '[redacted]' in redacted
    assert [text for text in kept if text not in redacted] == []
    assert redact_log(redacted) == redacted  # a second pass (an error redacted again upstream) changes nothing


@pytest.mark.parametrize('text', list(ORDINARY.values()), ids=list(ORDINARY))
def test_ordinary_prose_and_hex_digests_are_not_redacted(text):
    assert redact_log(text) == text


# --- generated secrets, idempotence, prose -----------------------------------------------------------------------------

BASE64URL = string.ascii_letters + string.digits + '_-'
PROPERTY = settings(max_examples=60, deadline=None, derandomize=True, database=None,
                    suppress_health_check=[HealthCheck.too_slow])


def secret_text(alphabet: str) -> st.SearchStrategy[str]:
    return st.text(alphabet=alphabet, min_size=12, max_size=64)  # too long to occur in the template or the marker


GENERATED = {
    'cookie': ('Cookie: sid={a}; JSESSIONID={b}', {'a': secret_text(BASE64URL), 'b': secret_text(BASE64URL)}),
    'set-cookie': ('Set-Cookie: session={a}; Path=/; HttpOnly', {'a': secret_text(BASE64URL)}),
    'sas': ('GET https://acct.blob.core.windows.net/c/b?sv=2022-11-02&sig={a}&se=2026',
            {'a': secret_text(BASE64URL + '%+/=')}),
    'slack': ('posting with xoxb-{a}', {'a': secret_text(string.ascii_letters + string.digits + '-')}),
    'jwt': ('session {a}.{b}.{c} expired', {'a': secret_text(BASE64URL).map('eyJ'.__add__),
                                            'b': secret_text(BASE64URL).map('eyJ'.__add__), 'c': secret_text(BASE64URL)}),
    'argv': ('ghidriff run --password {a} --user bob',
             {'a': secret_text(''.join(c for c in string.printable if not c.isspace() and c not in '"\''))}),
}


@pytest.mark.parametrize('name', list(GENERATED), ids=list(GENERATED))
@PROPERTY
@given(data=st.data())
def test_generated_secrets_never_survive(name, data):
    template, parts = GENERATED[name]
    secrets = data.draw(st.fixed_dictionaries(parts))
    redacted = redact_log(f'before\n{template.format(**secrets)}\nafter')
    assert [value for value in secrets.values() if value in redacted] == []
    assert redacted.startswith('before\n') and redacted.endswith('\nafter') and '[redacted]' in redacted


@PROPERTY
@given(st.lists(st.sampled_from([shape[0] for shape in SHAPES.values()] + list(ORDINARY.values())),
                min_size=1, max_size=8))
def test_redaction_is_idempotent(lines):
    once = redact_log('\n'.join(lines))
    assert redact_log(once) == once


WORDS = ('the', 'cookie', 'Cookie', 'cookies', 'Set-Cookie', 'jar', 'signature', 'sig', 'sigma', 'slack', 'xoxo', 'token',
         'tokens', 'password', 'passwords', 'secret', 'key', 'JWT', 'eyJ', 'header', 'payload', 'digest', 'commit',
         'verified', 'rotated', 'expired', 'and', 'is', 'ok')


@PROPERTY
@given(st.lists(st.one_of(st.sampled_from(WORDS), st.text(alphabet=string.hexdigits, min_size=32, max_size=128)),
                min_size=1, max_size=12))
def test_words_and_hex_digests_in_any_order_are_not_redacted(words):
    text = ' '.join(words)
    assert redact_log(text) == text


# --- hostile input: linear time ---------------------------------------------------------------------------------------

MEGABYTE = 1024 * 1024
BUDGET = 8.0  # seconds per input; a linear pass takes well under one second, a quadratic one takes hours
TIMEOUT = 180  # seconds for all inputs together
SRC = Path(patchtrace.__file__).resolve().parents[1]  # the module under test, not whichever copy is installed
# name: (head, unit). The input is the head followed by the unit repeated up to one MiB. Each opens a pattern's prefix
# and never completes it, or feeds a pattern a long run of its own character class, which is what makes a regex that
# rescans from every start position (quadratic) or backtracks (exponential) run for hours.
HOSTILE = {
    'run-a': ('', 'a'), 'run-dotted': ('', 'a.'), 'run-dashed': ('', 'a-'), 'spaces': ('', ' '),
    'newlines': ('', '\n'), 'slashes': ('', '/'), 'scheme': ('', 'a://'), 'userinfo': ('', '://a@'),
    'auth-header': ('', 'authorization: '), 'cookie-key': ('', 'cookie:'),
    'assign-dq': ('', 'password="'), 'assign-sq': ('', "token='"),
    'argv-flag': ('', '--token '), 'argv-dashes': ('', '--'), 'argv-dq': ('', '--token "'),
    'argv-repr': ('', "'--token', '"), 'sas-amp': ('', '&sig='), 'bearer': ('', 'bearer '),
    'github': ('', 'ghp_'), 'slack': ('', 'xoxb-'), 'jwt': ('', 'eyJ'), 'jwt-dotted': ('', 'eyJ.'),
    'jwt-triple': ('', 'eyJa.eyJa.'), 'jwt-escaped': ('', '%3DeyJa.eyJa'),
    'authorization-ws': ('authorization:', ' '), 'cookie-ws': ('Cookie:', ' '), 'token-ws': ('token', ' '),
    'argv-ws': ('--token', ' '), 'argv-open-dq': ('--token "', 'a'), 'assign-open-dq': ('password="', 'a'),
    'sas-fill': ('?sig=', 'a'), 'jwt-header': ('eyJ', 'a'), 'jwt-payload': ('eyJa.eyJ', 'a'),
    'jwt-signature': ('eyJa.eyJa.', 'a'), 'scheme-fill': ('://', 'a'), 'github-fill': ('ghp_', 'A'),
}
CHILD = '''\
import json, sys, time
from patchtrace.diagnostics import redact_log
for name, head, unit in json.load(sys.stdin):
    text = (head + unit * ({size} // len(unit) + 1))[:{size}]
    print(json.dumps([name, None]), flush=True)
    began = time.perf_counter()
    redact_log(text)
    print(json.dumps([name, time.perf_counter() - began]), flush=True)
'''


def seconds_in_child(cases: dict[str, tuple[str, str]]) -> dict[str, float]:
    """Seconds `redact_log` took per case, measured in a child that is killed, and the case named, on a hang."""
    path = os.pathsep.join(filter(None, [str(SRC), os.environ.get('PYTHONPATH')]))
    try:
        done = subprocess.run([sys.executable, '-c', CHILD.format(size=MEGABYTE)], capture_output=True, text=True,
                              input=json.dumps([[name, *case] for name, case in cases.items()]), encoding='utf-8',
                              env={**os.environ, 'PYTHONPATH': path}, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as hung:
        out = hung.stdout.decode('utf-8', 'replace') if isinstance(hung.stdout, bytes) else hung.stdout or ''
        started = [json.loads(line)[0] for line in out.splitlines()]
        pytest.fail(f'redact_log did not finish {len(cases)} one-MiB inputs in {TIMEOUT} s; stuck on {started[-1:]}')
    assert done.returncode == 0, done.stderr
    return {name: seconds for name, seconds in map(json.loads, done.stdout.splitlines()) if seconds is not None}


def test_hostile_megabyte_inputs_are_redacted_in_linear_time():
    timings = seconds_in_child(HOSTILE)
    assert sorted(timings) == sorted(HOSTILE)
    assert {name: round(seconds, 1) for name, seconds in timings.items() if seconds >= BUDGET} == {}


PUMPS = sorted({part for head, unit in HOSTILE.values() for part in (head, unit) if part})


@settings(max_examples=60, deadline=None, derandomize=True, database=None, phases=(Phase.generate,),
          suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.tuples(st.sampled_from(PUMPS), st.one_of(st.integers(1, 20), st.integers(4000, 30000))),
                min_size=1, max_size=4))
def test_random_mixtures_of_hostile_units_are_redacted_in_linear_time(parts):
    """The one-MiB inputs above run in a child; these stay at 64 KiB so that a regression fails, not hangs, the run."""
    text = ''.join(unit * count for unit, count in parts)[:64 * 1024]
    began = time.perf_counter()
    redact_log(text)
    assert time.perf_counter() - began < 2.0


# --- the CLI catch-all -------------------------------------------------------------------------------------------------

LEAKY_MESSAGE = '\n'.join([
    'GET https://acct.blob.core.windows.net/c?sv=2022-11-02&sig=cvSasSig%2Fe12Fg%3D&se=2026',
    'Set-Cookie: sid=cvCookie9f2e7a1c',
    'notify xo' + 'xb-123456789012-1234567890123-cvSlackAbCdEfGhIj failed',
    f'session {JWT} expired',
    'child: --password cvArgvPw91e4c7a2 --token cvArgvTok62b8f3d1',
])
LEAKED = ('cvSasSig', 'cvCookie9f2e7a1c', 'cvSlackAbCdEfGhIj', *JWT_PARTS, 'cvArgvPw91e4c7a2', 'cvArgvTok62b8f3d1')


def run_failing(monkeypatch, capsys, error: Exception, *flags: str):
    raised = []

    def explode(args, cancel):
        raised.append(True)
        raise error
    monkeypatch.setitem(cli.HANDLERS, 'rank', explode)
    code = cli.main(['rank', 'x', *flags])
    out, err = capsys.readouterr()
    assert raised == [True]  # the handler did run: a clean scan below cannot be a vacuous one
    return code, out, err


@pytest.mark.parametrize('flags', [('--json',), ()], ids=['json', 'text'])
def test_an_unexpected_exception_is_redacted_on_stderr_and_in_the_json_error(monkeypatch, capsys, flags):
    code, out, err = run_failing(monkeypatch, capsys, RuntimeError(LEAKY_MESSAGE), *flags)
    assert code == 3
    assert err.startswith('error: RuntimeError: ') and err.count('[redacted]') >= 5
    assert [secret for secret in LEAKED if secret in err] == []
    if flags:
        document = json.loads(out)
        assert (document['contract'], document['status'], document['result']) == ('enrichment-cli/1', 'failed', None)
        assert document['error'].startswith('RuntimeError: ') and document['error'].count('[redacted]') >= 5
        assert [secret for secret in LEAKED if secret in out] == []
    else:
        assert out == ''


@pytest.mark.parametrize('error, secret', [
    (subprocess.CalledProcessError(1, ['ghidriff', '--token', 'cvArgvTok62b8f3d1']), 'cvArgvTok62b8f3d1'),
    (OSError(5, 'refused, Cookie: sid=cvCookie9f2e7a1c'), 'cvCookie9f2e7a1c'),
    (ValueError('bad proxy https://analyst:cvUrlPw7d3f9b1e@proxy.invalid:3128/x'), 'cvUrlPw7d3f9b1e'),
], ids=['called-process', 'oserror', 'url-userinfo'])
def test_exceptions_that_quote_a_credential_exit_3_with_the_type_name_and_without_the_credential(
        monkeypatch, capsys, error, secret):
    code, out, err = run_failing(monkeypatch, capsys, error, '--json')
    document = json.loads(out)
    assert code == 3 and document['status'] == 'failed'
    assert document['error'].startswith(f'{type(error).__name__}: ') and '[redacted]' in document['error']
    assert secret not in out and secret not in err
