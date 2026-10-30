"""Selected cJSON probe inputs are bounded regular files; raw receipts never clobber.

These unit regressions do not invoke Ghidra, rz-diff or target binaries and do not
add native evidence to the research receipts.
"""
from __future__ import annotations

import pytest

from tools.research import r2_cjson_probe as probe

ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def symlink(link, target):
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip('symlinks unavailable on this platform')


def test_digest_rejects_a_directory_before_attempting_to_read_it(tmp_path):
    with pytest.raises(ValueError, match='regular file'):
        probe.digest(tmp_path)


def test_digest_rejects_oversized_selected_input(tmp_path, monkeypatch):
    selected = tmp_path / 'selected.dll'
    selected.write_bytes(b'abcd')
    monkeypatch.setattr(probe, 'MAX_INPUT_BYTES', 3, raising=False)
    with pytest.raises(ValueError, match='size limit'):
        probe.digest(selected)
    assert selected.read_bytes() == b'abcd'


def test_stream_digest_matches_known_hash_and_accepts_regular_input_symlink(tmp_path):
    selected = tmp_path / 'selected.dll'
    selected.write_bytes(b'abc')
    assert probe.digest(selected) == ABC_SHA256
    link = tmp_path / 'selected-link.dll'
    symlink(link, selected)
    assert probe.digest(link) == ABC_SHA256
    assert selected.read_bytes() == b'abc' and link.is_symlink()


def test_review_input_rejects_directory_before_reading(tmp_path):
    with pytest.raises(ValueError, match='regular file'):
        probe.read_acceptance(tmp_path)


def test_review_input_rejects_oversize_even_when_json_is_valid(tmp_path, monkeypatch):
    selected = tmp_path / 'acceptance.json'
    selected.write_bytes(b'{"ok":true}')
    monkeypatch.setattr(probe, 'MAX_ACCEPTANCE_BYTES', 4, raising=False)
    with pytest.raises(ValueError, match='size limit'):
        probe.read_acceptance(selected)
    assert selected.read_bytes() == b'{"ok":true}'


def test_review_input_accepts_a_small_regular_json_file(tmp_path):
    selected = tmp_path / 'acceptance.json'
    selected.write_bytes(b'{"accepted_keys":[]}')
    assert probe.read_acceptance(selected) == {'accepted_keys': []}


@pytest.mark.parametrize('existing', ['regular', 'symlink', 'dangling-symlink'])
def test_raw_jsonl_sink_refuses_existing_leaf_without_clobbering_or_following(tmp_path, existing):
    target = tmp_path / 'outside.jsonl'
    leaf = tmp_path / 'older-native-ir.jsonl'
    if existing == 'regular':
        leaf.write_bytes(b'previous receipt\n')
    else:
        if existing == 'symlink':
            target.write_bytes(b'previous receipt\n')
        symlink(leaf, target)
    with pytest.raises(FileExistsError):
        probe.write_raw_jsonl(leaf, b'new receipt\n')
    if existing == 'regular':
        assert leaf.read_bytes() == b'previous receipt\n'
    elif existing == 'symlink':
        assert leaf.is_symlink() and target.read_bytes() == b'previous receipt\n'
    else:
        assert leaf.is_symlink() and not target.exists()


def test_raw_jsonl_sink_creates_fresh_receipt_with_exact_bytes(tmp_path):
    leaf = tmp_path / 'older-native-ir.jsonl'
    probe.write_raw_jsonl(leaf, b'{"type":"fn"}\n')
    assert leaf.read_bytes() == b'{"type":"fn"}\n'
