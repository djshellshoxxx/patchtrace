"""API keys and tokens stay out of settings, files, logs and error text (SPEC-42 R3 and R7, SPEC-43 section 7).

Each test puts distinctive secrets where a real run meets them (the session key typed in the preview dialog, NVD and
GitHub tokens and a proxy password in the environment, credential lines in a child's output), runs the real code,
and scans every place the run writes or shows. A positive control proves the secret did reach the code under test,
so a clean scan cannot be a vacuous one. Hermetic: the network guard is armed throughout."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import sys
import threading
from collections.abc import Mapping
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from network_guard import network_guard_fixture  # noqa: F401
from PySide6.QtCore import QByteArray, QSettings
from PySide6.QtWidgets import QDialog

from patchtrace import backend, cli
from patchtrace.backend import BackendConfig, quarantine_failed_run, run_comparison
from patchtrace.diagnostics import describe_backend_exit, redact_log
from patchtrace.enrichment import intelligence
from patchtrace.models import Artifact, ComparisonProject
from patchtrace.providers import ProviderError
from patchtrace.service import ProjectService
from patchtrace.ui import ContextDialog, MainWindow, SetupDialog

FIXTURES = Path(__file__).parent / 'fixtures' / 'cve'
CVE_ID = 'CVE-2024-38063'

# SPEC-43 section 1: the 27 persisted keys.
SETTINGS_KEYS = (
    'analysis/profile', 'backend/python', 'backend/ghidra', 'backend/java_home', 'backend/allow_symbol_downloads',
    'backend/restrict_env', 'backend/env_passthrough', 'backend/timeout', 'desktop/font_size', 'desktop/sync',
    'desktop/geometry', 'desktop/workspace', 'desktop/vertical', 'desktop/code', 'provider/kind', 'provider/endpoint',
    'provider/model', 'provider/context_budget', 'recent/project', 'recent/projects', 'series/geometry',
    'evidence/geometry', 'evidence/filter', 'evidence/hide_agreed', 'evidence/show_index', 'engines/bindiff/path',
    'engines/bindiff/setup_open')
# Written by the flows below. The others are layout (evidence/geometry is legacy since the panel host), toggles and a probed engine path: nothing typed reaches them.
DRIVEN_KEYS = frozenset(SETTINGS_KEYS) - {'series/geometry', 'evidence/geometry', 'evidence/filter', 'evidence/hide_agreed',
                                          'evidence/show_index', 'engines/bindiff/path', 'engines/bindiff/setup_open'}

SESSION_KEY = 'sk-session-' + '4f9a2c7e1b8d3056'
ENV_SECRETS = {
    'NVD_API_KEY': 'nvd-env-5e1c8a3f7b2d4960',
    'GITHUB_TOKEN': 'ghp_' + 'K4m8N2p6R0s3' * 3,
    'OPENAI_API_KEY': 'sk-env-' + 'a1b2c3d4e5f6a7b8',
    'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'HTTPS_PROXY': 'http://analyst:proxy-pw-7d3f9b1e@proxy.invalid:3128',
}
# The part of each environment value that must never be written anywhere.
ENV_SECRET_PARTS = {**ENV_SECRETS, 'HTTPS_PROXY': 'proxy-pw-7d3f9b1e'}
# Credential lines of the shapes `redact_log` is specified to remove (SPEC-42 R7), as an analysis child may print.
LOG_LINES = {
    'bearer': ('Authorization: Bearer {}', 'tok-bearer-7f3a9c1e5b2d4a60'),
    'basic': ('Authorization: Basic {}', 'dXNlcjpwYXNzLWJhc2ljLTdmM2E5YzFl'),
    'token-scheme': ('Authorization: Token {}', 'tok-scheme-3e8b1d7a9c52'),
    'bare-bearer': ('retrying with bearer {}', 'tok-barebearer-8d2f6a1c4e90'),
    'api-key-header': ('X-Api-Key: {}', 'hdr-apikey-5b2d4a60e1c8'),
    'json-api-key': ('{{"apiKey": "{}"}}', 'json-apikey-3c9d1f7a8b20'),
    'password': ('password={}', 'pw-assign-91e4c7a2d5b8'),
    'url-userinfo': ('GET https://analyst:{}@mirror.invalid/symbols', 'pw-userinfo-62b8f3d1a7c4'),
    'github-token': ('seen {}', 'ghp_' + 'Q7w3E9r1T5y2' * 3),
    'github-fine-grained-token': ('seen {}', 'github_' + 'pat_11ABCDEFG0abcdefghijkl_0123456789abcdefghijklmnopqrstuvwxyz'),
    'openai-key': ('seen {}', 'sk-proj_9f2e7a1c4b8d6035e1a7'),
    'aws-key-id': ('seen {}', 'AKIAIOSFODNN7EXAMPLE'),
}
LOG_SECRETS = {name: secret for name, (_template, secret) in LOG_LINES.items()}
ALL_SECRETS = {**LOG_SECRETS, **{f'env-{name}': secret for name, secret in ENV_SECRET_PARTS.items()}}
KEYWORDS = re.compile(r'key|token|secret|password|credential|auth', re.IGNORECASE)


def scan(secrets: Mapping[str, str], surfaces: Mapping[str, str]) -> list[str]:
    return [f'{name} in {where}' for name, secret in secrets.items()
            for where, text in surfaces.items() if secret in text]


def files_under(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)): path.read_bytes().decode('utf-8', 'replace')
            for path in sorted(root.rglob('*')) if path.is_file()}


# --- a Ghidriff job: analysis.log, failure.txt, run.error, events -----------------------------------------------------

CHILD = '''\
import json, os, pathlib, sys
dump = [f'{{name}}={{os.environ[name]}}' for name in {names!r} if name in os.environ] + {lines!r}
text = chr(10).join(dump)
pathlib.Path({raw!r}).write_text(text, encoding='utf-8')
print(text)
print('java.lang.OutOfMemoryError: Java heap space')
if {fail!r}:
    sys.exit(7)
out = pathlib.Path(sys.argv[sys.argv.index('--output-path') + 1])
(out / 'json').mkdir(parents=True)
(out / 'json' / 'old-new.ghidriff.json').write_text(
    json.dumps({{'functions': {{'added': [], 'deleted': [], 'modified': []}}}}), encoding='utf-8')
'''


@pytest.fixture
def job(tmp_path, monkeypatch, network_guard):
    """run(fail) -> (run, events, project root, what the child printed before PatchTrace saw it)."""
    for name, value in ENV_SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: {
        'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': 'fake-test-only', 'available': True})
    root = tmp_path / 'case'
    root.mkdir()
    ghidra = tmp_path / 'ghidra'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
    (ghidra / 'ghidriff').mkdir()
    (ghidra / 'ghidriff' / '__init__.py').write_text('')
    artifacts = []
    for side, content in (('older', b'old-static-data'), ('newer', b'new-static-data')):
        (root / f'{side}.bin').write_bytes(content)
        artifacts.append(Artifact(side=side, name=f'{side}.bin', size=len(content),
                                  sha256=hashlib.sha256(content).hexdigest(), relative_path=f'{side}.bin'))
    project = ComparisonProject(name='secrets-fixture', artifacts=artifacts)
    raw = tmp_path / 'child-raw.txt'

    def run(fail: bool):
        lines = [template.format(secret) for template, secret in LOG_LINES.values()]
        (ghidra / 'ghidriff' / '__main__.py').write_text(
            CHILD.format(names=list(ENV_SECRETS), lines=lines, raw=str(raw), fail=fail), encoding='utf-8', newline='\n')
        events = []
        config = BackendConfig(str(Path(sys.executable).resolve()), str(ghidra))
        _path, result = run_comparison(config, project, root, threading.Event(), events.append)
        assert result.status == ('failed' if fail else 'completed'), result.error
        return result, events, root, raw.read_text(encoding='utf-8')
    return run


@pytest.mark.parametrize('fail', [False, True], ids=['completed', 'failed'])
def test_no_credential_reaches_the_log_the_failure_note_the_run_record_or_the_events(job, fail, network_guard):
    run, events, root, raw = job(fail)
    assert [name for name, secret in ALL_SECRETS.items() if secret not in raw] == []  # the child did print them all
    surfaces = {**files_under(root), 'run': run.model_dump_json(),
                **{f'event-{i}-{e.stage}': e.message for i, e in enumerate(events)}}
    assert scan(ALL_SECRETS, surfaces) == []
    log = next(text for where, text in surfaces.items() if where.endswith('analysis.log'))
    assert '[redacted]' in log and 'java.lang.OutOfMemoryError' in log  # redacted, not dropped
    if fail:
        assert run.error.startswith('PT-BACKEND:') and 'code 7' in run.error
        assert (root / 'runs' / f'quarantine-{run.id}' / 'failure.txt').read_text(encoding='utf-8') == run.error


REDACTION_CASES = {**{name: (template.format(secret), secret) for name, (template, secret) in LOG_LINES.items()},
                   **{f'env-{name}': (f'{name}={value}', ENV_SECRET_PARTS[name]) for name, value in ENV_SECRETS.items()}}


@pytest.mark.parametrize(('line', 'secret'), list(REDACTION_CASES.values()), ids=list(REDACTION_CASES))
def test_redact_log_removes_each_credential_shape(line, secret):
    redacted = redact_log(f'before\n{line}\nafter')
    assert secret not in redacted and redacted.startswith('before\n') and redacted.endswith('\nafter')


@pytest.mark.parametrize('failure', ['\njava.lang.OutOfMemoryError: Java heap space', ''],
                         ids=['classified', 'unclassified'])
def test_the_exit_hint_names_the_failure_without_echoing_any_log_text(failure):
    log = '\n'.join(template.format(secret) for template, secret in LOG_LINES.values())
    hint = describe_backend_exit(7, log + failure)
    assert scan(LOG_SECRETS, {'hint': hint}) == []
    assert hint.startswith('PT-BACKEND:') and 'code 7' in hint and ('memory' in hint) is bool(failure)


def test_the_error_note_of_a_run_quarantined_after_normalisation_is_redacted(job, tmp_path):
    run, _events, root, _raw = job(False)
    note = ' | '.join(template.format(secret) for template, secret in LOG_LINES.values())
    quarantined = quarantine_failed_run(root, run, 'normalisation failed: ' + note)
    surfaces = {**files_under(root), 'error': quarantined.error}
    assert scan(LOG_SECRETS, surfaces) == []
    assert quarantined.error.startswith('PT-SCHEMA:') and '[redacted]' in quarantined.error


# --- QSettings and the project after the flows that handle the session key ------------------------------------------

def stored(value) -> str:
    if isinstance(value, QByteArray):
        return bytes(value.data()).decode('latin-1')
    return ' '.join(map(str, value)) if isinstance(value, list) else str(value)


@pytest.fixture
def window(qtbot, tmp_path, monkeypatch, network_guard):
    for name, value in ENV_SECRETS.items():
        monkeypatch.setenv(name, value)
    service = ProjectService.sample(tmp_path / 'sample')
    view = MainWindow(service, QSettings(str(tmp_path / 'prefs' / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    yield view
    view.close()


@pytest.mark.parametrize('reply', ['malformed-reply', 'provider-error'])
def test_the_session_key_is_in_no_setting_file_log_or_error(window, qtbot, tmp_path, monkeypatch, reply,
                                                            network_guard):
    def fill_setup(dialog):
        dialog.python.setText('/opt/backend/python')
        dialog.ghidra.setText('/opt/ghidra')
        dialog.restrict_env.setChecked(True)
        dialog.env_passthrough.setText('CORP_PROXY_CA')
        dialog.allow_symbol_downloads.setChecked(True)
        dialog.timeout.setValue(600)
        return QDialog.DialogCode.Accepted

    def fill_preview(dialog):
        dialog.kind.setCurrentText('openai')
        dialog.endpoint.setText('https://llm.example.test/v1')
        dialog.model.setText('model-under-test')
        dialog.key.setText(SESSION_KEY)
        return QDialog.DialogCode.Accepted

    sent, errors = [], []

    def completion(config, system, payload, cancel):
        sent.append(config.api_key)
        if reply == 'provider-error':
            raise ProviderError('PT-PROVIDER: connection failed or timed out; check endpoint and server')
        return 'this is not json'

    monkeypatch.setattr(SetupDialog, 'exec', fill_setup)
    monkeypatch.setattr(ContextDialog, 'exec', fill_preview)
    monkeypatch.setattr('patchtrace.interpretation.request_completion', completion)
    monkeypatch.setattr(window, 'show_error', errors.append)

    window.set_service(ProjectService.sample(tmp_path / 'opened'))  # opening a project records it as recent
    window.setup()
    window.navigator.item(0).setSelected(True)
    window.preview_interpretation()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    shown = {'logs panel': window.logs.toPlainText(), 'status bar': window.statusBar().currentMessage(),
             'job label': window.job_label.text(), 'errors shown': '\n'.join(errors)}
    window.close()
    window.settings.sync()

    assert sent == [SESSION_KEY]  # the key did reach the transport
    assert errors and 'PT-PROVIDER' in errors[0]
    keys = set(window.settings.allKeys())
    assert DRIVEN_KEYS <= keys, sorted(DRIVEN_KEYS - keys)
    assert not [name for name in keys if KEYWORDS.search(name)]
    assert window.settings.value('provider/model') == 'model-under-test'
    surfaces = {**files_under(tmp_path), **shown, **{f'setting {key}': stored(window.settings.value(key))
                                                     for key in sorted(keys)}}
    assert scan({'session key': SESSION_KEY, **ALL_SECRETS}, surfaces) == []


# --- the NVD key on the command line ---------------------------------------------------------------------------------

NVD_KEY = 'nvd-session-key-7f3a9c1e5b2d'
KEY_VARIABLE = 'PT_CONSENT_NVD_KEY'


class Reply:
    def __init__(self, status=200, body=b''):
        self.status, self.headers, self._body = status, {}, body

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


class Opener:
    def __init__(self, outcome):
        self.outcome, self.calls = outcome, []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return Reply(200, self.outcome)


@pytest.fixture
def correlate(tmp_path, monkeypatch, capsys, network_guard):
    monkeypatch.setenv(KEY_VARIABLE, NVD_KEY)
    service = ProjectService.sample(tmp_path / 'case')
    project = service.root
    service.close()

    def run(outcome, *extra):
        opener = Opener(outcome)
        monkeypatch.setattr(intelligence, 'urllib_open', opener)
        code = cli.main(['correlate', str(project), '--cve', CVE_ID, '--fetch', '--providers', 'nvd',
                         '--consent-providers', 'nvd', '--api-key-env', KEY_VARIABLE, '--json', *extra])
        out, err = capsys.readouterr()
        return code, out, err, opener
    return run


def test_the_nvd_key_goes_only_into_the_request_header(correlate, tmp_path):
    body = (FIXTURES / f'nvd_{CVE_ID}.json').read_bytes()
    snapshot = tmp_path / 'snapshot.json'
    code, out, err, opener = correlate(body, '--save-snapshot', str(snapshot))
    assert code == 0 and json.loads(out)['status'] == 'complete'
    assert [(url, headers.get('apiKey')) for url, headers in opener.calls] == [
        (f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}', NVD_KEY)]
    assert snapshot.is_file()
    surfaces = {**files_under(tmp_path), 'stdout': out, 'stderr': err}
    assert scan({'nvd key': NVD_KEY}, surfaces) == []
    assert 'request: nvd https://services.nvd.nist.gov/' in err  # the request line is shown, without the key


@pytest.mark.parametrize('failure', [
    OSError(f'GET failed, headers={{"apiKey": "{NVD_KEY}"}}'),
    ConnectionResetError(f'peer reset while sending apiKey={NVD_KEY}'),
    http.client.BadStatusLine(f'apiKey: {NVD_KEY}'),
], ids=['oserror', 'reset', 'bad-status-line'])
def test_a_transport_error_that_quotes_the_key_is_reported_in_fixed_words(correlate, failure):
    code, out, err, opener = correlate(failure)
    assert code != 0 and len(opener.calls) == 1 and opener.calls[0][1]['apiKey'] == NVD_KEY
    assert scan({'nvd key': NVD_KEY}, {'stdout': out, 'stderr': err}) == []
    assert 'connection failed' in out + err


@pytest.mark.parametrize('bad', ['has a space', 'tab\there', 'kéy-with-accent'], ids=['space', 'tab', 'accent'])
def test_an_invalid_key_is_refused_before_any_request_without_echoing_it(correlate, monkeypatch, bad):
    monkeypatch.setenv(KEY_VARIABLE, bad)
    code, out, err, opener = correlate(b'{}')
    assert code != 0 and opener.calls == []
    assert scan({'invalid key': bad}, {'stdout': out, 'stderr': err}) == []
    assert 'invalid API key' in out + err
