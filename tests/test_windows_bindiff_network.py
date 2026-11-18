"""Windows network acceptance contract controls; authored data, no native or live-network credit."""
from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path

import pytest

SOURCE = 'a' * 40
TREE = 'b' * 40
HELPER = 'c' * 64
EXE = 'd' * 64
NONCE = 'e' * 32
SID = 'S-1-15-2-1-2-3-4-5-6-7'
CASES = ('tcp4-loopback', 'tcp6-loopback', 'udp4-loopback', 'udp6-loopback', 'tcp4-external')


@pytest.fixture
def net():
    return importlib.import_module('tools.windows_bindiff_network')


def match_set():
    from patchtrace.secondary.contracts import SecondaryMatch, SecondaryMatchSet
    row = SecondaryMatch(engine='bindiff', engine_version='8', older_address=1, newer_address=2,
                         older_name='old', newer_name='new', similarity_milli=750, similarity_text='0.75',
                         confidence_milli=500, confidence_text='0.5', flags=('G',), algorithm='name',
                         match_type='function', basicblocks=3)
    return SecondaryMatchSet(engine='bindiff', engine_version='8', older_sha256='1' * 64,
                             newer_sha256='2' * 64, file_sha256='3' * 64, matches=(row,))


def chain(blocked=False, start=100):
    return [{'pid': start + depth, 'parent_pid': start + depth - 1, 'depth': depth, 'nonce': NONCE,
             'appcontainer': blocked, 'sid': SID if blocked else '', 'capability_count': 0,
             'cases': [{'case': case, 'status': 'denied' if blocked else 'connected',
                        'error': 10013 if blocked else 0} for case in CASES]}
            for depth in range(3)]


def evidence(net):
    semantic = net.semantic_fingerprint(match_set())
    return {
        'contract': 'bindiff-network/1', 'native': True, 'nonce': NONCE,
        'source': {'commit': SOURCE, 'tree': TREE},
        'helper_sha256': HELPER, 'executable_sha256': EXE,
        'profile': {'name': 'PatchTrace.Acceptance.' + NONCE, 'sid': SID, 'capability_count': 0},
        'probes': {'before': chain(), 'denied': chain(True, 200), 'after': chain(start=300)},
        'launches': [{'purpose': purpose, 'pid': 400 + index, 'sid': SID, 'capability_count': 0,
                      'appcontainer': True, 'suspended': True, 'job_before_resume': True,
                      'token_before_resume': True, 'handles': ['nul', 'pipe', 'pipe'],
                      'tree_empty': True, 'executable_sha256': EXE}
                     for index, purpose in enumerate(('probe-version', 'probe-help', 'diff'))],
        'lifecycle': {'cancel': True, 'timeout': True, 'owner_exit': True},
        'adapter': {'status': 'passed', 'matches': 1, 'semantic_sha256': semantic,
                    'output_sha256': 'f' * 64, 'acceptance': 'C3 accept_binexport'},
        'cleanup': {'profile_deleted': True, 'tree_removed': True, 'process_tree_empty': True},
        'elapsed_s': 1.0,
    }


def validate(net, doc):
    return net.validate_evidence(doc, source_sha=SOURCE, source_tree=TREE, helper_sha=HELPER,
                                 executable_sha=EXE, nonce=NONCE, baseline_count=1,
                                 baseline_semantic=net.semantic_fingerprint(match_set()))


def test_complete_authored_evidence_is_accepted(net):
    validate(net, evidence(net))


@pytest.mark.parametrize('field', ['contract', 'native', 'nonce', 'source', 'helper_sha256',
                                  'executable_sha256', 'profile', 'probes', 'launches', 'lifecycle',
                                  'adapter', 'cleanup', 'elapsed_s'])
def test_missing_receipt_component_is_refused(net, field):
    doc = evidence(net)
    validate(net, doc)
    del doc[field]
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('phase', ['before', 'denied', 'after'])
@pytest.mark.parametrize('change', ['missing', 'child', 'duplicate', 'nonce', 'capability', 'identity',
                                   'case', 'timeout', 'unexpected_success', 'bool_pid'])
def test_probe_controls_fail_closed(net, phase, change):
    doc = evidence(net)
    validate(net, doc)
    rows = doc['probes'][phase]
    if change == 'missing':
        del doc['probes'][phase]
    elif change == 'child':
        rows.pop()
    elif change == 'duplicate':
        rows[1]['pid'] = rows[0]['pid']
    elif change == 'nonce':
        rows[2]['nonce'] = '0' * 32
    elif change == 'capability':
        rows[1]['capability_count'] = 1
    elif change == 'identity':
        rows[1]['sid'] = 'S-1-15-2-99' if phase == 'denied' else SID
    elif change == 'case':
        rows[1]['cases'].pop()
    elif change == 'timeout':
        rows[0]['cases'][0].update(status='timeout', error=10060)
    elif change == 'unexpected_success':
        rows[2]['cases'][0]['status'] = 'connected' if phase == 'denied' else 'denied'
    else:
        rows[0]['pid'] = True
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('key,value', [('appcontainer', False), ('suspended', False),
                                     ('job_before_resume', False), ('token_before_resume', False),
                                     ('capability_count', 1), ('handles', ['nul', 'pipe', 'socket']),
                                     ('sid', 'S-1-15-2-99'), ('tree_empty', False),
                                     ('executable_sha256', '0' * 64), ('pid', True)])
def test_each_native_launch_requires_actual_containment(net, key, value):
    doc = evidence(net)
    validate(net, doc)
    doc['launches'][1][key] = value
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('section,key', [('cleanup', 'profile_deleted'), ('cleanup', 'tree_removed'),
                                      ('cleanup', 'process_tree_empty'), ('lifecycle', 'cancel'),
                                      ('lifecycle', 'timeout'), ('lifecycle', 'owner_exit')])
def test_incomplete_cleanup_and_lifecycle_fail(net, section, key):
    doc = evidence(net)
    validate(net, doc)
    doc[section][key] = False
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('key', ['commit', 'tree'])
def test_other_source_is_not_qualified(net, key):
    doc = evidence(net)
    validate(net, doc)
    doc['source'][key] = '0' * 40
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('key', ['helper_sha256', 'executable_sha256'])
def test_other_build_is_not_qualified(net, key):
    doc = evidence(net)
    validate(net, doc)
    doc[key] = '0' * 64
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('field,value', [('older_address', 4), ('newer_address', 5),
                                      ('older_name', 'different'), ('newer_name', 'different'),
                                      ('similarity_milli', 500), ('similarity_text', '0.7500'),
                                      ('confidence_milli', 700), ('confidence_text', '0.5000'),
                                      ('flags', ('I',)), ('algorithm', 'hash'),
                                      ('match_type', 'other'), ('basicblocks', 4)])
def test_equal_count_different_match_semantics_is_refused(net, field, value):
    original = match_set()
    changed = original.model_copy(update={'matches': (original.matches[0].model_copy(update={field: value}),)})
    assert len(changed.matches) == len(original.matches)
    assert net.semantic_fingerprint(changed) != net.semantic_fingerprint(original)
    doc = evidence(net)
    validate(net, doc)
    doc['adapter']['semantic_sha256'] = net.semantic_fingerprint(changed)
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('field,value', [('older_sha256', '4' * 64), ('newer_sha256', '5' * 64),
                                      ('image_base_subtracted', 'yes'), ('limitations', ('gap',)),
                                      ('engine_version', '9')])
def test_fingerprint_covers_set_semantics(net, field, value):
    original = match_set()
    assert net.semantic_fingerprint(original.model_copy(update={field: value})) != net.semantic_fingerprint(original)


def test_fingerprint_ignores_only_execution_identity_and_row_order(net):
    original = match_set().model_copy(update={'contract': 'secondary/2', 'run_id': 'first'})
    other = original.matches[0].model_copy(update={'older_address': 3, 'newer_address': 4})
    original = original.model_copy(update={'matches': (*original.matches, other)})
    changed = original.model_copy(update={'file_sha256': '9' * 64, 'run_id': 'second',
                                          'matches': tuple(reversed(original.matches))})
    assert net.semantic_fingerprint(changed) == net.semantic_fingerprint(original)


@pytest.mark.parametrize('number', ['NaN', 'Infinity', '-Infinity', '1e999', '-1e999'])
def test_nonfinite_receipt_refused(net, number):
    raw = json.dumps(evidence(net)).replace('"elapsed_s": 1.0', '"elapsed_s": ' + number).encode()
    with pytest.raises(net.NetworkEvidenceError):
        net.read_evidence_bytes(raw)


def test_duplicate_json_keys_refused(net):
    with pytest.raises(net.NetworkEvidenceError):
        net.read_evidence_bytes(b'{"native":true,"native":false}')


def test_bound_for_receipt_bytes(net):
    with pytest.raises(net.NetworkEvidenceError):
        net.read_evidence_bytes(b' ' * (2 * 1024 * 1024 + 1))


def test_replaced_owned_directory_is_not_deleted(net, tmp_path):
    own = tmp_path / 'owned'
    own.mkdir()
    identity = net.directory_identity(own)
    own.rename(tmp_path / 'original')
    own.mkdir()
    sentinel = own / 'unrelated.txt'
    sentinel.write_text('keep')
    with pytest.raises(net.NetworkEvidenceError):
        net.remove_owned_tree(own, identity)
    assert sentinel.read_text() == 'keep'


def test_owned_directory_cleanup_positive(net, tmp_path):
    own = tmp_path / 'owned'
    own.mkdir()
    (own / 'file').write_text('authored')
    net.remove_owned_tree(own, net.directory_identity(own))
    assert not own.exists()


def test_network_workflow_builds_and_keeps_evidence():
    text = (Path(__file__).resolve().parents[1] / '.github/workflows/live-bindiff.yml').read_text()
    assert 'windows_bindiff_network.py build' in text
    assert 'tools/windows_network/**' in text
    assert 'tests/test_windows_bindiff_network.py' in text
    assert 'if: always()' in text


def test_no_network_harness_uses_complete_semantic_baseline():
    text = (Path(__file__).with_name('test_live_bindiff.py')).read_text()
    assert 'semantic_fingerprint(match_set)' in text
    assert 'baseline_semantic' in text
    assert 'probe_runner=runner' in text and 'runner=runner' in text


def test_mutation_fixtures_do_not_alias():
    a = chain(True)
    b = copy.deepcopy(a)
    b[0]['cases'][0]['status'] = 'connected'
    assert a[0]['cases'][0]['status'] == 'denied'
