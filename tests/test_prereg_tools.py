"""Preregistration hash check (P-1) and corpus vendoring scan; hermetic, synthetic fixtures only."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import prereg, vendoring_scan  # noqa: E402


def h(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_prereg_sha_is_over_file_bytes(tmp_path):
    f = write(tmp_path / 'p.md', b'frozen\n')
    assert prereg.prereg_sha256(f) == hashlib.sha256(b'frozen\n').hexdigest()


def test_prereg_sha_refuses_crlf(tmp_path):
    f = write(tmp_path / 'p.md', b'frozen\r\n')
    with pytest.raises(prereg.PreregError):
        prereg.prereg_sha256(f)


def test_verify_match_and_mismatch(tmp_path):
    f = write(tmp_path / 'p.md', b'frozen\n')
    good = hashlib.sha256(b'frozen\n').hexdigest()
    assert prereg.verify(f, good)
    assert not prereg.verify(f, '0' * 64)
    with pytest.raises(prereg.PreregError):
        prereg.verify(f, good.upper())


def test_recorded_sha_reads_the_named_row():
    sha = h('x')
    qa = f'| C9-PREREG-v0 | {h("old")} |\n| C9-PREREG-v1 | commit abc | {sha} | 2026-10-20 |\n'
    assert prereg.recorded_sha(qa) == sha
    assert prereg.recorded_sha('| C9-PREREG-v1 | pending |\n') is None
    assert prereg.recorded_sha('nothing here') is None


@pytest.mark.parametrize('qa_row, code', [('{sha}', 0), ('{other}', 1), ('pending', 2)], ids=['match', 'differ', 'none'])
def test_cli_against_qa_row(tmp_path, capsys, qa_row, code):
    f = write(tmp_path / 'p.md', b'frozen\n')
    sha = hashlib.sha256(b'frozen\n').hexdigest()
    qa = write(tmp_path / 'qa.md', f'| C9-PREREG-v1 | {qa_row.format(sha=sha, other=h("o"))} |\n'.encode())
    assert prereg.main(['--file', str(f), '--qa', str(qa)]) == code
    assert capsys.readouterr().out.startswith(sha) or code == 2


def test_cli_prints_without_expectation_and_never_writes(tmp_path, capsys):
    f = write(tmp_path / 'p.md', b'frozen\n')
    assert prereg.main(['--file', str(f)]) == 0
    assert capsys.readouterr().out.strip() == hashlib.sha256(b'frozen\n').hexdigest()
    assert sorted(p.name for p in tmp_path.iterdir()) == ['p.md']
    assert f.read_bytes() == b'frozen\n'


def test_cli_missing_file_is_usage_error(tmp_path):
    assert prereg.main(['--file', str(tmp_path / 'absent.md')]) == 2


def test_repo_prereg_file_is_lf():
    assert len(prereg.prereg_sha256(prereg.DEFAULT_FILE)) == 64


# vendoring scan

def bodies(**lineages):
    return {k: [h(x) for x in v] for k, v in lineages.items()}


def test_scan_proposes_merge_for_shared_vendored_bodies():
    data = bodies(A=['z1', 'z2', 'z3', 'a1', 'a2', 'a3', 'a4'], B=['z1', 'z2', 'z3', 'b1', 'b2'], C=['c1', 'c2'])
    result = vendoring_scan.scan(data, threshold=0.5, hub_max_lineages=3)
    assert [p.lineages for p in result.proposals] == [('A', 'B')]
    assert result.proposals[0].shared_bodies == 3
    assert result.proposals[0].pairs == (('A', 'B', 0.6),)
    assert result.hub_bodies == ()


def test_scan_below_threshold_proposes_nothing():
    data = bodies(A=['z1', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6'], B=['z1', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6'])
    assert vendoring_scan.scan(data, threshold=0.5, hub_max_lineages=3).proposals == ()


def test_scan_hub_bodies_are_not_merge_edges():
    data = bodies(A=['crt', 'a1'], B=['crt', 'b1'], C=['crt', 'c1'], D=['crt', 'd1'])
    result = vendoring_scan.scan(data, threshold=0.1, hub_max_lineages=3)
    assert result.proposals == ()
    assert result.hub_bodies == (h('crt'),)


def test_scan_chains_into_one_proposal_and_is_transitive():
    data = bodies(A=['x1', 'x2'], B=['x1', 'x2', 'y1', 'y2'], C=['y1', 'y2'], D=['d1'])
    result = vendoring_scan.scan(data, threshold=0.9, hub_max_lineages=3)
    assert [p.lineages for p in result.proposals] == [('A', 'B', 'C')]


def test_scan_never_splits_and_is_order_independent():
    data = bodies(A=['x1', 'x2'], B=['x1', 'x2'], C=['q1'])
    flipped = dict(reversed(list(data.items())))
    first = vendoring_scan.scan(data, threshold=0.5, hub_max_lineages=3)
    assert first == vendoring_scan.scan(flipped, threshold=0.5, hub_max_lineages=3)
    assert all(len(p.lineages) >= 2 for p in first.proposals)
    assert set(vendoring_scan.to_json(first)) == {'proposals', 'hub_bodies', 'action'}
    assert vendoring_scan.to_json(first)['action'] == 'merge-only'


def test_scan_empty_lineage_is_ignored():
    assert vendoring_scan.scan({'A': [], 'B': []}, threshold=0.1, hub_max_lineages=3).proposals == ()


def test_load_bodies_accepts_mapping_and_records():
    as_map = vendoring_scan.load_bodies({'A': ['h1'], 'B': ['h1']})
    as_records = vendoring_scan.load_bodies([{'lineage': 'A', 'masked_sha256': 'h1'},
                                             {'lineage': 'B', 'masked_sha256': 'h1'}])
    assert as_map == as_records == {'A': ['h1'], 'B': ['h1']}
    with pytest.raises(ValueError):
        vendoring_scan.load_bodies('nope')


def test_cli_requires_explicit_hub_limit_and_emits_json(tmp_path, capsys):
    src = write(tmp_path / 'b.json', json.dumps(bodies(A=['x1', 'x2'], B=['x1', 'x2'])).encode())
    with pytest.raises(SystemExit):
        vendoring_scan.main([str(src), '--threshold', '0.15'])
    capsys.readouterr()
    assert vendoring_scan.main([str(src), '--threshold', '0.15', '--hub-max-lineages', '3']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['proposals'][0]['lineages'] == ['A', 'B']
