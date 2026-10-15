"""Endpoint validation of the AI provider configuration (SPEC-41 R8 to R11, section 3)."""
import ipaddress

import pytest

from patchtrace.providers import ProviderConfig, ProviderError

ACCEPT = [
    ('ollama', 'http://[::1]:11434'),
    ('ollama', 'http://LOCALHOST:11434'),
    ('ollama', 'http://127.0.0.2:11434'),
    ('ollama', 'https://localhost:11434'),
    ('openai', 'https://127.0.0.1:8443/v1'),
    ('openai', 'https://api.example.com/v1/'),
]
ACCEPT_IDS = ['ollama-v6-loopback', 'ollama-host-case', 'ollama-127-8', 'ollama-https', 'openai-loopback',
              'openai-slash']

REJECT = [
    ('ollama', 'http://127.1:11434'),
    ('ollama', 'http://0.0.0.0:11434'),
    ('ollama', 'http://[::ffff:127.0.0.1]:11434'),
    ('ollama', 'http://[::ffff:7f00:1]:11434'),
    ('ollama', 'http://[::ffff:8.8.8.8]:11434'),
    ('ollama', 'http://localhost:99999'),
    ('ollama', 'http://localhost:11434?x=1'),
    ('openai', 'http://localhost/v1'),
    ('openai', 'https://api.example.com/v1 '),
    ('vllm', 'https://api.example.com/v1'),
]
REJECT_IDS = ['ollama-short-v4', 'ollama-any-addr', 'ollama-mapped-dotted', 'ollama-mapped-hex',
              'ollama-mapped-public', 'ollama-bad-port', 'ollama-query', 'openai-http', 'openai-space',
              'unknown-kind']


@pytest.mark.parametrize('kind,endpoint', ACCEPT, ids=ACCEPT_IDS)
def test_endpoint_accept_matrix(kind, endpoint):
    assert ProviderConfig(kind, endpoint, 'fixture').endpoint == endpoint


@pytest.mark.parametrize('kind,endpoint', REJECT, ids=REJECT_IDS)
def test_endpoint_reject_matrix(kind, endpoint):
    with pytest.raises(ProviderError, match='PT-PROVIDER'):
        ProviderConfig(kind, endpoint, 'fixture')


def _loopback_cpython_312(address):
    return int(address) == 1


def _loopback_cpython_313(address):
    mapped = address.ipv4_mapped
    return mapped.is_loopback if mapped is not None else int(address) == 1


@pytest.fixture(params=[_loopback_cpython_312, _loopback_cpython_313], ids=['stdlib-312', 'stdlib-313'])
def stdlib_loopback(request, monkeypatch):
    """IPv6Address.is_loopback as each CPython line implements it (SPEC-41 R11, probe P1)."""
    monkeypatch.setattr(ipaddress.IPv6Address, 'is_loopback', property(request.param))


@pytest.mark.parametrize('host', ['::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:127.0.0.2'],
                         ids=['dotted', 'hex', 'other-127'])
def test_ipv4_mapped_loopback_rejected_on_every_python(stdlib_loopback, host):
    with pytest.raises(ProviderError, match='IPv4-mapped'):
        ProviderConfig('ollama', f'http://[{host}]:11434', 'fixture')


def test_ipv6_loopback_accepted_on_every_python(stdlib_loopback):
    assert ProviderConfig('ollama', 'http://[::1]:11434', 'fixture').endpoint == 'http://[::1]:11434'


OPENAI_URL = 'https://api.example.com/v1'


@pytest.mark.parametrize('key', [
    'k' * 4097, 'a\nb', 'a\r\nX-Evil: 1', 'a\x00b', 'a\x7fb', 'a\x80b', 'k\N{EURO SIGN}y',
    '\N{LATIN CAPITAL LETTER A WITH MACRON}', 'k\N{LATIN SMALL LETTER E WITH ACUTE}y', 'a\xffb',
    'k\N{NO-BREAK SPACE}y', 'k\N{RIGHT SINGLE QUOTATION MARK}y', 'k\N{ZERO WIDTH SPACE}y'],
    ids=['too-long', 'newline', 'crlf-header', 'nul', 'del', 'c1-control', 'euro', 'above-latin1', 'e-acute',
         'y-diaeresis', 'nbsp', 'smart-quote', 'zero-width'])
def test_credential_must_be_printable_ascii(key):
    """Probe P2 and audit RA-7: a non-ASCII key used to pass the constructor and fail later as an envelope
    error. The text is fixed, so the key is never echoed."""
    with pytest.raises(ProviderError) as error:
        ProviderConfig('openai', OPENAI_URL, 'fixture', key)
    assert str(error.value) == 'PT-PROVIDER: invalid credential'


@pytest.mark.parametrize('key', ['', 'k' * 4096, 'sk-proj_A.b~c', ''.join(map(chr, range(32, 127)))],
                         ids=['empty', 'max', 'typical', 'all-printable'])
def test_printable_ascii_credentials_accepted(key):
    assert ProviderConfig('openai', OPENAI_URL, 'fixture', key).api_key == key


@pytest.mark.parametrize('model', ['', '   ', 'm' * 201], ids=['empty', 'blank', 'too-long'])
def test_model_name_limits(model):
    with pytest.raises(ProviderError, match='model name'):
        ProviderConfig('ollama', 'http://localhost:11434', model)


def test_model_name_at_limit_accepted():
    assert ProviderConfig('ollama', 'http://localhost:11434', 'm' * 200).model == 'm' * 200
