"""The reusable testing tools in ``tools/``: the synthetic KEV catalog always imports, and the suite runner reads
pytest's summary the way it is printed. Offline; no pytest subprocess is started here."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from patchtrace.kev.parse import parse_catalog

TOOLS = Path(__file__).resolve().parents[1] / 'tools'


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_make_kev_catalog_writes_a_catalog_the_production_parser_accepts(tmp_path, capsys):
    tool = _load('make_kev_catalog')
    out = tmp_path / 'kev.json'
    assert tool.main([str(out), '--cve', 'CVE-2099-20001@2099-02-12', '--cve', 'CVE-2099-20002',
                      '--ransomware', 'CVE-2099-20002', '--released', '2099-01-01T00:00:00Z']) == 0
    catalog = parse_catalog(out.read_bytes(), source='local-import', retrieved_at='2099-01-01T00:00:00Z')
    assert set(catalog.by_cve) == {'CVE-2099-20001', 'CVE-2099-20002'}
    assert catalog.by_cve['CVE-2099-20001'].date_added == '2099-02-12'
    assert catalog.by_cve['CVE-2099-20002'].ransomware_use == 'known'
    assert 'SYNTHETIC' in json.loads(out.read_text(encoding='utf-8'))['title']


def test_make_kev_catalog_rejects_a_malformed_cve(tmp_path, capsys):
    tool = _load('make_kev_catalog')
    with pytest.raises(SystemExit) as exc:
        tool.main([str(tmp_path / 'kev.json'), '--cve', 'CVE-12'])
    assert exc.value.code == 2 and not (tmp_path / 'kev.json').exists()


def test_run_test_suite_reads_failures_and_the_summary_line():
    tool = _load('run_test_suite')
    log = ('....F\n=== short test summary info ===\nFAILED tests/test_a.py::test_x - AssertionError: boom\n'
           'ERROR tests/test_b.py::test_y\nFAILED tests/test_a.py::test_x - again\n'
           '=== 1 failed, 3 passed, 1 error in 0.50s ===\n')
    assert tool.failing_ids(log) == ['tests/test_a.py::test_x', 'tests/test_b.py::test_y']
    assert tool.summary_line(log) == '1 failed, 3 passed, 1 error in 0.50s'
    assert tool.summary_line('nothing here') == '(no pytest summary line; see the log)'
    command = tool.pytest_command(1, ['-k', 'x'])
    assert command[1:6] == ['-m', 'pytest', '-q', '-p', 'no:cacheprovider'] and command[-2:] == ['-k', 'x']
