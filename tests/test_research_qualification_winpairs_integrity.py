"""Acquisition identity and immutable evidence regressions; authored bytes, no network."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from test_research_qualification_winpairs import (
    BIN_A,
    BIN_B,
    IDX_URL,
    URL_A,
    A,
    B,
    Fake,
    cli,
    entry,
    index,
    routes,
    sha,
)

from tools.research_qualification import winpairs as wp


def record():
    return wp.side_record('tcpip.sys', A['fileInfo'], 'one authored candidate')


@pytest.mark.parametrize('pin', [{'version': '10.0.22000.100'}, {'kb': 'KB1000001'}, {}])
def test_version_and_kb_do_not_resolve_distinct_hash_ambiguity(pin):
    left = entry(b'one', 1, 4096, '10.0.22000.100')
    right = entry(b'two', 9, 4096, '10.0.22000.100')
    selected, reason = wp.select_entry(index(left, right), wp.parse_ref({'file': 'tcpip.sys', **pin}))
    assert selected is None and 'ambiguous' in reason


def test_kb_shared_by_different_windows_versions_never_chooses_highest_build():
    left = entry(BIN_A, 1, 4096, '10.0.19041.1', 'KB1000001')
    right = entry(BIN_B, 9, 4096, '10.0.26100.1', 'KB1000001')
    right['windowsVersions'] = {'11-24H2': right['windowsVersions'].pop('21H2')}
    selected, reason = wp.select_entry(index(left, right), wp.parse_ref({'file': 'tcpip.sys', 'kb': 'KB1000001'}))
    assert selected is None and 'ambiguous' in reason


def test_version_comparison_is_not_a_prefix_match():
    longer = entry(BIN_A, 1, 4096, '10.0.22000.1000 (WinBuild)')
    selected, _ = wp.select_entry(index(longer), wp.parse_ref({'file': 'tcpip.sys', 'version': '10.0.22000.100'}))
    assert selected is None


def test_same_hash_with_conflicting_symbol_identity_is_ambiguous_even_with_hash_pin():
    changed = copy.deepcopy(A)
    changed['fileInfo']['timestamp'] += 1
    selected, reason = wp.select_entry({'first': A, 'second': changed},
                                        wp.parse_ref({'file': 'tcpip.sys', 'sha256': sha(BIN_A)}))
    assert selected is None and 'ambiguous' in reason


@pytest.mark.parametrize('digest', [None, '', 'not-a-hash', '0' * 63, True])
def test_unusable_source_hash_does_not_become_a_download_candidate(digest):
    malformed = copy.deepcopy(A)
    malformed['fileInfo']['sha256'] = digest
    selected, _ = wp.select_entry({'record': malformed}, wp.parse_ref({'file': 'tcpip.sys'}))
    assert selected is None


@pytest.mark.parametrize('response', [BIN_A, b'tampered', wp.Response(404)])
def test_existing_binary_survives_retry_without_another_request(tmp_path, response):
    destination = tmp_path / 'tcpip.sys'
    destination.write_bytes(BIN_A)
    before = destination.stat()
    fetch = Fake({URL_A: response})
    result = record()
    wp.download_side(fetch, result, destination, 'case/older/tcpip.sys')
    assert destination.read_bytes() == BIN_A
    assert destination.stat().st_mtime_ns == before.st_mtime_ns
    assert result['status'] == 'missing' and 'exist' in result['reason']
    assert fetch.calls == []


@pytest.mark.parametrize('body', [BIN_A, b'tampered'])
def test_concurrent_binary_publication_wins_even_if_fetch_validation_fails(tmp_path, body):
    destination = tmp_path / 'tcpip.sys'

    def fetch(*_):
        destination.write_bytes(b'concurrent prior evidence')
        return wp.Response(200, body)

    result = record()
    wp.download_side(fetch, result, destination, 'case/older/tcpip.sys')
    assert destination.read_bytes() == b'concurrent prior evidence'
    assert result['status'] == 'missing'
    assert list(tmp_path.iterdir()) == [destination]


def test_binary_size_must_match_the_selected_index_record(tmp_path):
    result = record()
    result['expected_size'] += 1
    wp.download_side(Fake({URL_A: BIN_A}), result, tmp_path / 'tcpip.sys', 'case/older/tcpip.sys')
    assert result['status'] == 'missing' and 'size' in result['reason']
    assert not (tmp_path / 'tcpip.sys').exists()


@pytest.mark.parametrize('error', [OSError('disk full'), KeyboardInterrupt()])
def test_interrupted_binary_publication_exposes_no_partial_file(tmp_path, monkeypatch, error):
    destination = tmp_path / 'tcpip.sys'
    result = record()

    def stop(_fd):
        assert not destination.exists()
        raise error

    monkeypatch.setattr(os, 'fsync', stop)
    if isinstance(error, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    else:
        wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
        assert result['status'] == 'missing'
    assert list(tmp_path.iterdir()) == []


def test_binary_is_complete_before_exclusive_publication(tmp_path, monkeypatch):
    destination = tmp_path / 'tcpip.sys'
    real_link = os.link
    published = []

    def observe(source, target, **kwargs):
        assert not destination.exists()
        assert Path(source).read_bytes() == BIN_A
        real_link(source, target, **kwargs)
        published.append(Path(target))

    monkeypatch.setattr(os, 'link', observe)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert published == [destination]
    assert result['status'] == 'found' and result['sha256_verified']
    assert destination.read_bytes() == BIN_A and list(tmp_path.iterdir()) == [destination]


@pytest.mark.parametrize('concurrent', [False, True])
def test_exclusive_publication_never_falls_back_to_replacement(tmp_path, monkeypatch, concurrent):
    destination = tmp_path / 'tcpip.sys'
    real_link = os.link

    def unavailable(source, target, **kwargs):
        if concurrent:
            destination.write_bytes(b'concurrent complete artifact')
            return real_link(source, target, **kwargs)
        raise OSError('hard-link publication unsupported')

    monkeypatch.setattr(os, 'link', unavailable)
    result = record()
    wp.download_side(Fake({URL_A: BIN_A}), result, destination, 'case/older/tcpip.sys')
    assert result['status'] == 'missing'
    if concurrent:
        assert destination.read_bytes() == b'concurrent complete artifact'
        assert list(tmp_path.iterdir()) == [destination]
    else:
        assert list(tmp_path.iterdir()) == []


def test_existing_manifest_refuses_before_network_and_keeps_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prior = tmp_path / 'pm.json'
    prior.write_bytes(b'original immutable receipt')
    fetch = Fake(routes(index(A, B)))
    assert cli(tmp_path, fetch) == 2
    assert fetch.calls == []
    assert prior.read_bytes() == b'original immutable receipt'
    assert not (tmp_path / 'o').exists()


def test_concurrent_manifest_wins_and_downloaded_sides_remain_available(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    prior = tmp_path / 'pm.json'
    base = Fake(routes(index(A, B)))

    def fetch(*args):
        if args[0] == IDX_URL:
            prior.write_bytes(b'concurrent receipt')
        return base(*args)

    assert cli(tmp_path, fetch) == 2
    assert prior.read_bytes() == b'concurrent receipt'
    assert (tmp_path / 'o/c1/older/tcpip.sys').read_bytes() == BIN_A
    assert (tmp_path / 'o/c1/newer/tcpip.sys').read_bytes() == BIN_B


@pytest.mark.parametrize('error', [OSError('disk full'), KeyboardInterrupt()])
def test_manifest_publication_failure_keeps_no_partial_receipt(tmp_path, monkeypatch, error):
    monkeypatch.chdir(tmp_path)

    def stop(_fd):
        assert not (tmp_path / 'pm.json').exists()
        raise error

    monkeypatch.setattr(os, 'fsync', stop)
    if isinstance(error, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            cli(tmp_path, Fake(routes(index(A, B))), '--resolve-only')
    else:
        assert cli(tmp_path, Fake(routes(index(A, B))), '--resolve-only') == 2
    assert not (tmp_path / 'pm.json').exists()
    assert not list(tmp_path.glob('.winpairs-*'))


def test_existing_link_is_never_followed_or_removed(tmp_path):
    target = tmp_path / 'prior'
    target.write_bytes(b'prior')
    destination = tmp_path / 'tcpip.sys'
    try:
        destination.symlink_to(target)
    except OSError:
        pytest.skip('runner cannot create symlinks')
    fetch = Fake({URL_A: BIN_A})
    result = record()
    wp.download_side(fetch, result, destination, 'case/older/tcpip.sys')
    assert destination.is_symlink() and target.read_bytes() == b'prior'
    assert result['status'] == 'missing' and fetch.calls == []


def test_linked_binary_parent_is_refused_before_download(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    linked = tmp_path / 'linked'
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip('runner cannot create symlinks')
    fetch = Fake({URL_A: BIN_A})
    result = record()
    wp.download_side(fetch, result, linked / 'tcpip.sys', 'case/older/tcpip.sys')
    assert list(outside.iterdir()) == [] and linked.is_symlink()
    assert result['status'] == 'missing' and fetch.calls == []


def test_dangling_manifest_link_does_not_create_its_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / 'not-created'
    destination = tmp_path / 'pm.json'
    try:
        destination.symlink_to(target)
    except OSError:
        pytest.skip('runner cannot create symlinks')
    fetch = Fake(routes(index(A, B)))
    assert cli(tmp_path, fetch, '--resolve-only') == 2
    assert destination.is_symlink() and not target.exists() and fetch.calls == []


def test_successful_resolve_only_receipt_remains_strict_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli(tmp_path, Fake(routes(index(A, B))), '--resolve-only') == 0
    document = json.loads((tmp_path / 'pm.json').read_bytes())
    assert document['schema'] == wp.OUT_SCHEMA and document['cases'][0]['status'] == 'found'
    assert not list(tmp_path.glob('.winpairs-*'))
