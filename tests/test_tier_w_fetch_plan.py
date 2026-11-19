"""Saved fetch previews over self-made PE/PDB fixtures; no requests or target execution."""
from __future__ import annotations

import hashlib
import json
import socket

import pytest
from tier_w_builders import TIER_W_FIXTURES, gz, tiny_winbindex_doc

from tools.calibration.tier_w import fetch_plan as F
from tools.calibration.tier_w.catalogue import build_catalogue
from tools.calibration.tier_w.contracts import load_fetch_plan
from tools.calibration.tier_w.pairs import PairParams, build_corpus
from tools.calibration.tier_w.paths import TierWError, dumps


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        pytest.fail('saved-plan controls must not open a network socket')
    monkeypatch.setattr(socket, 'create_connection', refuse)
    monkeypatch.setattr(socket.socket, 'connect', refuse)


def sources():
    catalogue = build_catalogue(gz(tiny_winbindex_doc()), 'tiny.dll', '2026-10-01', family='usermode-dll')
    _manifest, pairs = build_corpus([catalogue], PairParams(), corpus_id='tier-w-test', created='', allow_incomplete=True)
    selected = [pair.id for pair in pairs.pairs]
    return pairs, [catalogue], selected


def binary_plan(**kwargs):
    return F.build_binary_plan(*sources(), **kwargs)


def place(root, plan):
    fixtures = {hashlib.sha256(path.read_bytes()).hexdigest(): path
                for path in TIER_W_FIXTURES.glob('tiny_v*.pe')}
    for item in plan.entries:
        path = root / 'binaries' / item.sha256 / item.file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixtures[item.sha256].read_bytes())


def test_canonical_plan_and_exact_saved_confirmation(tmp_path):
    plan = binary_plan()
    path = tmp_path / 'saved.json'
    digest = F.save_plan(plan, path)
    assert digest == F.plan_sha256(plan) == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(plan.entries) == 2 and all(item.pair_ids == plan.selected_pairs for item in plan.entries)
    calls = []

    def recompute():
        calls.append(True)
        return binary_plan()

    restored, actual, consent = F.confirm_plan(path, digest, recompute, consent_hosts=['msdl.microsoft.com'])
    assert calls == [True] and restored == plan and actual == digest
    assert consent.hosts == frozenset({'msdl.microsoft.com'})
    assert consent.urls == frozenset(item.source_url for item in plan.entries)
    assert F.save_plan(plan, path) == digest  # exact existing evidence may be reused


@pytest.mark.parametrize('damage', ['mixed', 'foreign-url', 'query', 'newline', 'cap', 'bool-size',
                                   'unselected-pair', 'duplicate-entry', 'record-missing', 'device-name'])
def test_plan_contract_refuses_unbound_or_ambiguous_requests(damage):
    raw = binary_plan().model_dump(mode='json')
    item = raw['entries'][0]
    if damage == 'mixed':
        item['guid'] = '0' * 8 + '-0000-0000-0000-' + '0' * 12
    elif damage == 'foreign-url':
        item['source_url'] = item['source_url'].replace('msdl.microsoft.com', 'foreign.example')
    elif damage == 'query':
        item['source_url'] += '?download=1'
    elif damage == 'newline':
        item['source_url'] += '\n'
    elif damage == 'cap':
        item['cap_bytes'] += 1
    elif damage == 'bool-size':
        item['size'] = True
    elif damage == 'unselected-pair':
        item['pair_ids'] = ['tw.foreign']
    elif damage == 'duplicate-entry':
        raw['entries'].append(dict(item))
    elif damage == 'record-missing':
        item['record_sha256'] = None
    else:
        item['file_name'] = 'con.dll'
    with pytest.raises(TierWError):
        load_fetch_plan(dumps(raw))


@pytest.mark.parametrize('damage', ['digest', 'source', 'hosts', 'extra-host', 'canonical'])
def test_saved_confirmation_refuses_changed_preview_before_any_request(tmp_path, damage):
    plan = binary_plan()
    path = tmp_path / 'saved.json'
    digest = F.save_plan(plan, path)
    current = plan
    hosts = ['msdl.microsoft.com']
    if damage == 'digest':
        digest = '0' * 64
    elif damage == 'source':
        pairs, catalogues, selected = sources()
        current = F.build_binary_plan(pairs.model_copy(update={'created': 'changed'}), catalogues, selected)
    elif damage == 'hosts':
        hosts = []
    elif damage == 'extra-host':
        hosts.append('winbindex.m417z.com')
    else:
        path.write_bytes(json.dumps(plan.model_dump(mode='json')).encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(TierWError):
        F.confirm_plan(path, digest, lambda: current, consent_hosts=hosts)


def test_plan_save_preserves_conflicting_existing_file(tmp_path):
    path = tmp_path / 'saved.json'
    path.write_bytes(b'prior separate evidence')
    with pytest.raises(TierWError):
        F.save_plan(binary_plan(), path)
    assert path.read_bytes() == b'prior separate evidence'


@pytest.mark.parametrize('damage', ['duplicate-pair', 'duplicate-binary', 'duplicate-catalogue', 'foreign-record',
                                   'foreign-filename', 'missing-binary'])
def test_binary_planning_revalidates_source_ownership(damage):
    pairs, catalogues, selected = sources()
    if damage == 'duplicate-pair':
        pairs = pairs.model_copy(update={'pairs': (*pairs.pairs, pairs.pairs[0])})
    elif damage == 'duplicate-binary':
        pairs = pairs.model_copy(update={'binaries': (*pairs.binaries, pairs.binaries[0])})
    elif damage == 'duplicate-catalogue':
        catalogues *= 2
    elif damage == 'foreign-record':
        changed = pairs.binaries[0].model_copy(update={'record_sha256': '0' * 64})
        pairs = pairs.model_copy(update={'binaries': (changed, *pairs.binaries[1:])})
    elif damage == 'foreign-filename':
        changed = pairs.binaries[0].model_copy(update={'file_name': 'other.dll'})
        pairs = pairs.model_copy(update={'binaries': (changed, *pairs.binaries[1:])})
    else:
        pairs = pairs.model_copy(update={'binaries': pairs.binaries[1:]})
    with pytest.raises(TierWError):
        F.build_binary_plan(pairs, catalogues, selected)


def test_max_files_and_caps_are_strict_and_deferred_entries_are_explicit():
    plan = binary_plan(max_files=1)
    assert len(plan.entries) == 1 and len(plan.exclusions) == 1
    assert plan.exclusions[0].reason == 'deferred'
    for limit in (False, 0, -1, 100_001, 1.0):
        with pytest.raises(TierWError):
            binary_plan(max_files=limit)


def test_pdb_plan_uses_verified_local_pe_snapshot_and_binds_binary_plan(tmp_path):
    binary = binary_plan()
    root = tmp_path / 'corpus'
    place(root, binary)
    plan = F.build_pdb_plan(root, binary, pdb_cap_mib=1)
    assert len(plan.entries) == 2 and plan.operation == 'pdb'
    assert plan.input_plan_sha256 == F.plan_sha256(binary)
    assert {item.file_name for item in plan.entries} == {'tiny_v1.pdb', 'tiny_v2.pdb'}
    assert all(item.binary_size and item.cap_bytes == 2**20 and item.guid and item.age == 1 for item in plan.entries)
    assert load_fetch_plan(F.plan_bytes(plan)) == plan


@pytest.mark.parametrize('cap', [False, True, 0, -1, 2049, 1.0, float('inf'), float('nan'), '1'])
def test_pdb_plan_cap_is_a_strict_integer_with_a_typed_plan_error(tmp_path, cap):
    with pytest.raises(TierWError) as caught:
        F.build_pdb_plan(tmp_path, binary_plan(), pdb_cap_mib=cap)
    assert caught.value.code == 'PT-TIERW-INPUT'


@pytest.mark.parametrize('damage', ['bytes', 'link', 'size'])
def test_pdb_planning_refuses_missing_or_changed_binary_identity(tmp_path, damage):
    binary = binary_plan()
    root = tmp_path / 'corpus'
    place(root, binary)
    item = binary.entries[0]
    path = root / 'binaries' / item.sha256 / item.file_name
    if damage == 'bytes':
        path.write_bytes(b'X' * item.size)
    elif damage == 'size':
        path.write_bytes(path.read_bytes() + b'X')
    else:
        target = path.with_name('original')
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError:
            pytest.skip('symlink unavailable for this account')
    with pytest.raises(TierWError):
        F.build_pdb_plan(root, binary)


def test_plan_byte_limit_is_applied_to_reads_and_generated_previews(tmp_path, monkeypatch):
    plan = binary_plan()
    path = tmp_path / 'saved.json'
    F.save_plan(plan, path)
    monkeypatch.setattr(F, 'FETCH_PLAN_LIMIT', 32)
    with pytest.raises(TierWError):
        F.read_plan(path)
    with pytest.raises(TierWError, match='budget'):
        F.plan_bytes(plan)
