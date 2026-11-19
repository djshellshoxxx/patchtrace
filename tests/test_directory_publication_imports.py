"""Fresh-process import boundaries; no target, network or native Windows execution."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHILD = r'''
import errno
import importlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

blocked = ('ctypes', 'PySide6', 'subprocess', 'ssl', 'urllib.request', 'http.client')
assert not any(name in sys.modules for name in blocked)
class Block:
    def find_spec(self, name, path=None, target=None):
        if any(name == item or name.startswith(item + '.') for item in blocked):
            raise ImportError('blocked native/process/network dependency: ' + name)
sys.meta_path.insert(0, Block())
operation, root = sys.argv[1], Path(sys.argv[2])
if operation.startswith('import:'):
    importlib.import_module(operation.split(':', 1)[1])
else:
    publisher = importlib.import_module('patchtrace.directory_publication')
    stage, destination = root / 'stage', root / 'destination'
    stage.mkdir()
    (stage / 'payload').write_bytes(b'owned inert payload')
    identity = stage.stat()
    calls = []
    publisher.os.rename = lambda *args: calls.append(args)
    if operation == 'windows':
        publisher.sys = SimpleNamespace(platform='win32')
        publisher.publish_directory_no_replace(stage, destination)
        assert calls == [(stage, destination)]
    elif operation == 'unsupported':
        publisher.sys = SimpleNamespace(platform='other')
        try:
            publisher.publish_directory_no_replace(stage, destination)
        except OSError as error:
            assert error.errno == errno.ENOTSUP
        else:
            raise AssertionError('unsupported publication did not refuse')
        assert not calls
    elif operation == 'invalid-path':
        try:
            publisher.publish_directory_no_replace(stage, stage)
        except ValueError:
            pass
        else:
            raise AssertionError('identical source/destination did not refuse')
        assert not calls
    else:
        assert operation == 'linux-missing-ffi'
        publisher.sys = SimpleNamespace(platform='linux')
        try:
            publisher.publish_directory_no_replace(stage, destination)
        except ImportError as error:
            assert 'ctypes' in str(error)
        else:
            raise AssertionError('Linux operation bypassed unavailable native dependency')
        assert not calls
    after = stage.stat()
    assert (identity.st_dev, identity.st_ino) == (after.st_dev, after.st_ino)
    assert (stage / 'payload').read_bytes() == b'owned inert payload'
    assert not destination.exists()
assert not any(name in sys.modules for name in blocked)
print('boundary passed:', operation)
'''


@pytest.mark.parametrize('operation', [
    'import:patchtrace.directory_publication',
    'import:patchtrace.unified.ir.place',
    'windows', 'unsupported', 'invalid-path', 'linux-missing-ffi',
])
def test_publication_imports_only_the_native_dependency_it_needs(tmp_path, operation):
    result = subprocess.run([sys.executable, '-c', CHILD, operation, str(tmp_path)],
                            cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == f'boundary passed: {operation}'
