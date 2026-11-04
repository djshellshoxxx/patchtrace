"""irx audit: the output guard counts every file but the progress temp file (03 s3 "text files in out/ are capped by
L-05"); a `.part` suffix is no exemption. Also: the stderr scrub equals the shared `contracts` definition."""
from __future__ import annotations

from patchtrace.unified.contracts import strip_unsafe
from patchtrace.unified.extract import runner


def test_a_part_file_other_than_the_progress_temp_counts_towards_the_cap(tmp_path):
    guard = runner.OutputGuard(tmp_path, None, 100, 4096, 50)
    (tmp_path / 'ir.jsonl.part').write_bytes(b'x' * 101)
    assert guard() == 'output-limit'


def test_an_oversized_progress_temp_file_kills_the_child(tmp_path):
    guard = runner.OutputGuard(tmp_path, None, 10_000_000, 64, 50)
    (tmp_path / 'progress.json.part').write_bytes(b'x' * 64)
    assert guard() is None
    (tmp_path / 'progress.json.part').write_bytes(b'x' * 65)
    assert guard() == 'output-limit'


def test_stderr_scrub_hides_everything_the_shared_definition_hides():
    hostile = ''.join(chr(c) for c in (0x00, 0x7F, 0x85, 0xAD, 0x200B, 0x202E, 0x2066, 0x2060, 0xFEFF, 0xE0041))
    cleaned = runner.sanitize_stderr('a' + hostile + 'b\n\tc')
    assert cleaned == 'a' + '?' * len(hostile) + 'b\n\tc'
    assert strip_unsafe(cleaned, keep_layout=True) == cleaned
