"""`tier_r vendoring` verb: records -> merge proposals, exit codes, no defaults (synthetic records, hermetic)."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import bodyrecord as BR  # noqa: E402
from tools.calibration.tier_r import cli  # noqa: E402


def h(n: int) -> str:
    return hashlib.sha256(f'body-{n}'.encode()).hexdigest()


@pytest.fixture(autouse=True)
def calib_root(tmp_path, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'calib'))


@pytest.fixture
def bodies(tmp_path):
    folder = tmp_path / 'bodies'
    BR.write_record(folder, 'zstd-a', [h(i) for i in range(10)])
    BR.write_record(folder, 'zstd-b', [h(i) for i in range(5, 15)])     # 5 shared of 10
    BR.write_record(folder, 'lua', [h(i) for i in range(100, 110)])
    return folder


def run(capsys, folder, *extra):
    out = folder.parent / 'out.json'
    code = cli.main(['vendoring', '--bodies', str(folder), '--out', str(out), *extra])
    text = capsys.readouterr().out
    return code, (json.loads(text) if text.strip() else {}), out


def test_proposes_merge_and_exits_findings(capsys, bodies):
    code, doc, out = run(capsys, bodies, '--threshold', '0.15', '--hub-max-lineages', '3')
    assert code == cli.FINDINGS and doc['merge_proposals'] == 1 and doc['lineages'] == 3
    written = json.loads(out.read_text(encoding='utf-8'))
    assert written['proposals'][0]['lineages'] == ['zstd-a', 'zstd-b']
    assert written['action'] == 'merge-only' and written['threshold'] == 0.15 and written['hub_max_lineages'] == 3
    assert b'\r' not in out.read_bytes()


def test_no_overlap_exits_ok(capsys, bodies):
    code, doc, _ = run(capsys, bodies, '--threshold', '0.9', '--hub-max-lineages', '3')
    assert code == cli.OK and doc['status'] == 'ok' and doc['merge_proposals'] == 0


def test_hub_bodies_are_not_merge_edges(capsys, tmp_path):
    folder = tmp_path / 'bodies'
    for name in ('a', 'b', 'c', 'd'):
        BR.write_record(folder, name, [h(1), h(2), h(ord(name) + 1000)])
    code, doc, _ = run(capsys, folder, '--threshold', '0.15', '--hub-max-lineages', '3')
    assert code == cli.OK and doc['hub_bodies'] == 2


def test_output_is_deterministic(capsys, bodies):
    _, _, out = run(capsys, bodies, '--threshold', '0.15', '--hub-max-lineages', '3')
    first = out.read_bytes()
    run(capsys, bodies, '--threshold', '0.15', '--hub-max-lineages', '3')
    assert out.read_bytes() == first


@pytest.mark.parametrize('argv', [
    ['--hub-max-lineages', '3'], ['--threshold', '0.15'], [],
], ids=['no-threshold', 'no-hub-max', 'no-defaults'])
def test_threshold_and_hub_max_are_required(capsys, bodies, argv):
    assert run(capsys, bodies, *argv)[0] == cli.USAGE


@pytest.mark.parametrize('argv', [
    ['--threshold', '0', '--hub-max-lineages', '3'],
    ['--threshold', '1.5', '--hub-max-lineages', '3'],
    ['--threshold', '0.15', '--hub-max-lineages', '0'],
], ids=['zero-threshold', 'big-threshold', 'zero-hub'])
def test_out_of_range_is_usage(capsys, bodies, argv):
    code, doc, _ = run(capsys, bodies, *argv)
    assert code == cli.USAGE and doc['status'] == 'error'


def test_missing_or_empty_folder_is_usage(capsys, tmp_path):
    (tmp_path / 'empty').mkdir()
    for name in ('empty', 'absent'):
        code, doc, _ = run(capsys, tmp_path / name, '--threshold', '0.15', '--hub-max-lineages', '3')
        assert code == cli.USAGE and 'no *.bodies.json' in doc['error']


def test_corrupt_record_is_usage(capsys, bodies):
    next(bodies.glob('lua*')).write_text('{"contract": "tier-r-bodies/1"}', encoding='utf-8', newline='\n')
    code, doc, _ = run(capsys, bodies, '--threshold', '0.15', '--hub-max-lineages', '3')
    assert code == cli.USAGE and doc['status'] == 'error'
