"""CAP-11: consented 'Set up capa' download service. Hermetic: an injected fake opener replaces the network."""
from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import threading
import os
import zipfile
from pathlib import Path

import pytest

from patchtrace import ui_capabilities_setup as setup

EXE = b'MZ-fake-capa-executable'
URL = 'https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip'


def make_zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def pin_for(archive: bytes, exe: bytes = EXE, **over) -> dict:
    asset = {'name': 'capa-v9.4.0-windows.zip', 'url': URL, 'format': 'zip', 'size': len(archive),
             'sha256': hashlib.sha256(archive).hexdigest(), 'executable': 'capa.exe',
             'executable_size': len(exe), 'executable_sha256': hashlib.sha256(exe).hexdigest()}
    asset.update(over)
    return {'contract': 'intel-tools-pin/1', 'engines': {'capa': {'version': '9.4.0', 'assets': {'windows': asset}}}}


class FakeOpener:
    def __init__(self, payload: bytes):
        self.payload, self.opened = payload, []

    def __call__(self, url: str):
        self.opened.append(url)
        data = self.payload
        return iter([data[i:i + 7] for i in range(0, len(data), 7)])


def run(tmp_path, pin, payload, consent=True, cancel=None):
    plan = setup.plan_for('windows', pin)
    opener = FakeOpener(payload)
    token = setup.ConsentToken.for_plan(plan) if consent else None
    result = setup.install(plan, token, tmp_path / 'tools', opener, cancel or threading.Event())
    return plan, opener, result


def left_behind(tmp_path) -> list:
    tools = tmp_path / 'tools'
    return list(tools.iterdir()) if tools.exists() else []


def test_plan_shows_exact_url_size_and_sha256_before_any_byte():
    archive = make_zip({'capa.exe': EXE})
    plan = setup.plan_for('windows', pin_for(archive))
    assert isinstance(plan, setup.SetupPlan)
    text = plan.consent_text()
    for needle in (plan.url, str(plan.size), plan.sha256, 'capa 9.4.0'):
        assert needle in text
    assert 'never run' in text.lower() and 'only after you confirm' in text.lower()


def test_no_consent_means_no_network_and_no_files(tmp_path):
    archive = make_zip({'capa.exe': EXE})
    _plan, opener, result = run(tmp_path, pin_for(archive), archive, consent=False)
    assert (result.status, result.code) == ('refused', 'consent-required')
    assert opener.opened == [] and left_behind(tmp_path) == []


def test_consent_for_another_plan_is_refused(tmp_path):
    archive = make_zip({'capa.exe': EXE})
    plan = setup.plan_for('windows', pin_for(archive))
    other = setup.plan_for('windows', pin_for(archive, url=URL.replace('v9.4.0/capa', 'v9.4.1/capa')))
    opener = FakeOpener(archive)
    result = setup.install(plan, setup.ConsentToken.for_plan(other), tmp_path / 't', opener, threading.Event())
    assert result.code == 'consent-mismatch' and opener.opened == []


def test_happy_path_installs_verified_executable(tmp_path):
    archive = make_zip({'capa-dir/capa.exe': EXE, 'README': b'x'})
    plan, opener, result = run(tmp_path, pin_for(archive), archive)
    assert result.status == 'installed' and opener.opened == [plan.url]
    assert Path(result.path).read_bytes() == EXE
    assert [p.name for p in left_behind(tmp_path)] == ['capa.exe']


def bad_archive_bytes():
    good = make_zip({'capa.exe': EXE})
    return pin_for(good), good[:-1] + bytes([good[-1] ^ 1])


def oversize():
    good = make_zip({'capa.exe': EXE})
    return pin_for(good), good + b'0'


def wrong_exe():
    bad = make_zip({'capa.exe': EXE + b'!'})
    return pin_for(bad, exe=EXE), bad


def no_member():
    bad = make_zip({'other.exe': EXE})
    return pin_for(bad), bad


def two_members():
    bad = make_zip({'a/capa.exe': EXE, 'b/capa.exe': EXE})
    return pin_for(bad), bad


@pytest.mark.parametrize('case', [bad_archive_bytes, oversize, wrong_exe, no_member, two_members],
                         ids=['archive-bytes', 'oversize', 'exe-bytes', 'no-member', 'two-members'])
def test_verification_failures_install_nothing(tmp_path, case):
    pin, payload = case()
    _plan, _opener, result = run(tmp_path, pin, payload)
    assert result.status == 'failed' and result.path is None
    assert left_behind(tmp_path) == []


def test_cancel_stops_and_leaves_nothing(tmp_path):
    archive = make_zip({'capa.exe': EXE})
    cancel = threading.Event()
    cancel.set()
    _plan, _opener, result = run(tmp_path, pin_for(archive), archive, cancel=cancel)
    assert (result.status, result.code) == ('cancelled', 'cancelled')
    assert left_behind(tmp_path) == []


@pytest.mark.parametrize('mutation', [
    {'sha256': 'UNMEASURED'}, {'sha256': 'abc'}, {'url': 'http://github.com/a/b/releases/download/c'},
    {'url': 'https://evil.example/a/b/releases/download/c'}, {'executable': '../capa.exe'}, {'format': 'tar'}],
    ids=['unmeasured', 'short-digest', 'http', 'other-host', 'traversal', 'format'])
def test_untrusted_pin_entries_have_no_plan(mutation):
    plan = setup.plan_for('windows', pin_for(make_zip({'capa.exe': EXE}), **mutation))
    assert isinstance(plan, setup.Unavailable) and plan.reason


def test_unknown_os_has_manual_steps_only():
    plan = setup.plan_for('plan9', pin_for(make_zip({'capa.exe': EXE})))
    assert isinstance(plan, setup.Unavailable) and 'manual' in plan.reason.lower()


def test_size_cap_rejects_huge_declared_asset():
    plan = setup.plan_for('windows', pin_for(b'x', size=setup.MAX_ASSET + 1))
    assert isinstance(plan, setup.Unavailable)


def test_module_imports_no_qt():
    code = ('import sys, patchtrace.ui_capabilities_setup; '
            'sys.exit(any(m.startswith(("PySide", "PyQt")) for m in sys.modules))')
    src = str(Path(__file__).resolve().parents[1] / 'src')
    env = {**os.environ, 'PYTHONPATH': src}
    assert subprocess.run([sys.executable, '-c', code], check=False, env=env).returncode == 0
