"""Security regression: a traversal name inside a downloaded archive never chooses where bytes are written."""
from __future__ import annotations

import hashlib
import io
import threading
import zipfile
from pathlib import Path

from patchtrace import ui_capabilities_setup as setup

EXE = b'MZ-fake-capa-executable'
URL = 'https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip'


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _pin(archive: bytes) -> dict:
    asset = {'name': 'capa-v9.4.0-windows.zip', 'url': URL, 'format': 'zip', 'size': len(archive),
             'sha256': hashlib.sha256(archive).hexdigest(), 'executable': 'capa.exe',
             'executable_size': len(EXE), 'executable_sha256': hashlib.sha256(EXE).hexdigest()}
    return {'contract': 'intel-tools-pin/1', 'engines': {'capa': {'version': '9.4.0', 'assets': {'windows': asset}}}}


class _Opener:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __call__(self, url: str):
        return iter([self.payload])


def test_a_traversal_member_name_is_used_only_as_a_file_name(tmp_path):
    archive = _zip({'../../escape/capa.exe': EXE})
    plan = setup.plan_for('windows', _pin(archive))
    tools = tmp_path / 'tools'
    result = setup.install(plan, setup.ConsentToken.for_plan(plan), tools, _Opener(archive), threading.Event())
    assert result.status == 'installed'
    assert Path(result.path) == tools / 'capa.exe' and (tools / 'capa.exe').read_bytes() == EXE
    assert sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob('*')) == ['tools', 'tools/capa.exe']
