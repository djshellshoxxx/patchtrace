"""A deliberately failing pytest child must preserve equality and bounded reports."""
import os
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest
from byte_assertions import assert_bytes_equal


def test_large_mismatches_fail_with_bounded_console_and_junit_reports(tmp_path):
    source = textwrap.dedent('''
        import pytest
        from byte_assertions import assert_bytes_equal

        SIZE = 1024 * 1024 + 17

        def test_equal():
            assert_bytes_equal(b'x' * SIZE, bytes(bytearray(b'x' * SIZE)))

        @pytest.mark.parametrize('offset', [0, SIZE // 2, SIZE - 1])
        def test_changed(offset):
            changed = bytearray(b'x' * SIZE)
            changed[offset] = ord('y')
            assert_bytes_equal(bytes(changed), b'x' * SIZE)

        def test_all_changed():
            assert_bytes_equal(b'x' * SIZE, b'y' * SIZE)

        def test_shorter():
            assert_bytes_equal(b'x' * (SIZE - 1), b'x' * SIZE)

        def test_longer():
            assert_bytes_equal(b'x' * (SIZE + 1), b'x' * SIZE)

        def test_empty():
            assert_bytes_equal(b'', b'x' * SIZE)
    ''')
    (tmp_path / 'test_inner.py').write_text(source, encoding='utf-8', newline='\n')
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parent),
           'PYTEST_ADDOPTS': '', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    done = subprocess.run(
        [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=', '-p', 'no:cacheprovider',
         '--confcutdir', str(tmp_path), '--tb=long', '--showlocals', '--junitxml=results.xml',
         'test_inner.py'],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert done.returncode == 1, (done.stdout + done.stderr)[:1000]
    assert len(done.stdout) + len(done.stderr) < 10_000
    report = (tmp_path / 'results.xml').read_bytes()
    assert len(report) < 10_000
    suite = ET.fromstring(report).find('testsuite')
    assert suite is not None
    assert {key: suite.get(key) for key in ('tests', 'failures', 'errors', 'skipped')} == {
        'tests': '8', 'failures': '7', 'errors': '0', 'skipped': '0',
    }
    size = 1024 * 1024 + 17
    expected_offsets = {f'test_changed[{offset}]': offset for offset in (0, size // 2, size - 1)}
    expected_offsets.update(test_all_changed=0, test_shorter=size - 1, test_longer=size, test_empty=0)
    failures = {case.get('name'): case.find('failure') for case in suite.findall('testcase')
                if case.find('failure') is not None}
    assert failures.keys() == expected_offsets.keys()
    for name, offset in expected_offsets.items():
        message = failures[name].get('message', '').removeprefix('Failed: ')
        assert message.startswith(f'exact bytes differ: first_difference={offset}; ')
        assert len(message) < 512
        assert 'actual length=' in message and 'expected length=' in message
        assert message.count('sha256=') == 2


def test_equal_hashes_cannot_hide_unequal_bytes(monkeypatch):
    monkeypatch.setattr('byte_assertions.hashlib.sha256', lambda data: SimpleNamespace(hexdigest=lambda: '0' * 64))
    with pytest.raises(pytest.fail.Exception, match='first_difference=3;'):
        assert_bytes_equal(b'abc\x00', b'abc\x01')
