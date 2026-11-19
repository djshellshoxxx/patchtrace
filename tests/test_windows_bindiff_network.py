"""Windows network acceptance contract controls; authored data, no native or live-network credit."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = 'a' * 40
TREE = 'b' * 40
HELPER = 'c' * 64
PROBE = '6' * 64
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
    return [{'pid': start + depth, 'parent_pid': start + depth - 1, 'created': str(start + depth + 1000),
             'depth': depth, 'nonce': NONCE,
             'appcontainer': blocked, 'sid': SID if blocked else '', 'capability_count': 0,
             'cases': [{'case': case, 'status': 'denied' if blocked else 'connected',
                        'error': 10013 if blocked else 0} for case in CASES]}
            for depth in range(3)]


def evidence(net):
    semantic = net.semantic_fingerprint(match_set())
    def launch(pid, image):
        return {'owner_pid': pid - 1, 'pid': pid, 'created': str(pid + 1000), 'sid': SID,
                'capability_count': 0, 'appcontainer': True, 'suspended': True, 'job_before_resume': True,
                'token_before_resume': True, 'image_locked': True, 'handles': ['nul', 'pipe', 'pipe'],
                'tree_empty': True, 'executable_sha256': image}

    lifecycle = {}
    for index, (name, reason) in enumerate((('cancel', 'cancelled'), ('timeout', 'timeout'),
                                           ('owner_exit', 'owner-exit'))):
        pid = 500 + 10 * index
        rows = chain(True, pid)
        for row in rows:
            row['cases'] = []
        lifecycle[name] = {'reason': reason, 'owner_exit_code': 1, 'processes': rows,
                           'launch': launch(pid, PROBE), 'observed': {'alive': [], 'uncertain': False}}
    return {
        'contract': 'bindiff-network/1', 'native': True, 'nonce': NONCE,
        'source': {'commit': SOURCE, 'tree': TREE},
        'helper_sha256': HELPER, 'probe_sha256': PROBE, 'executable_sha256': EXE,
        'profile': {'name': 'PatchTrace.Acceptance.' + NONCE, 'sid': SID, 'capability_count': 0},
        'probes': {'before': chain(), 'denied': chain(True, 200), 'after': chain(start=300)},
        'probe_launch': launch(200, PROBE),
        'launches': [{'purpose': purpose, **launch(400 + index, EXE)}
                     for index, purpose in enumerate(('probe-version', 'probe-help', 'diff'))],
        'lifecycle': lifecycle,
        'adapter': {'status': 'passed', 'matches': 1, 'semantic_sha256': semantic,
                    'output_sha256': 'f' * 64, 'acceptance': 'C3 accept_binexport'},
        'cleanup': {'profile_deleted': True, 'tree_removed': True, 'process_tree_empty': True},
        'elapsed_s': 1.0,
    }


def validate(net, doc):
    return net.validate_evidence(doc, source_sha=SOURCE, source_tree=TREE, helper_sha=HELPER, probe_sha=PROBE,
                                 executable_sha=EXE, nonce=NONCE, baseline_count=1,
                                 baseline_semantic=net.semantic_fingerprint(match_set()))


def test_complete_authored_evidence_is_accepted(net):
    validate(net, evidence(net))


@pytest.mark.parametrize('field', ['contract', 'native', 'nonce', 'source', 'helper_sha256',
                                  'executable_sha256', 'probe_sha256', 'profile', 'probes', 'probe_launch',
                                  'launches', 'lifecycle',
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


@pytest.mark.parametrize('key', ['helper_sha256', 'probe_sha256', 'executable_sha256'])
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


def test_file_reads_do_not_treat_access_time_as_content_mutation(net, tmp_path):
    payload = tmp_path / 'data'
    payload.write_bytes(b'{"authored":true}\n')
    os.utime(payload, (1, 2))
    assert net._read(payload) == {'authored': True}
    os.utime(payload, (1, 2))
    assert len(net._sha(payload)) == 64


def test_lifecycle_booleans_without_observations_are_not_evidence(net):
    doc = evidence(net)
    doc['lifecycle'] = {'cancel': True, 'timeout': True, 'owner_exit': True}
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


def test_partial_probe_stdout_is_seen_before_owner_exit(net, tmp_path):
    """Real short pipe writes, fake native identity/containment; no Windows credit."""
    work = tmp_path / 'work'
    work.mkdir()
    receipt = tmp_path / 'start.json'
    rows = chain(True)
    for row in rows:
        row['cases'] = []
        row['created'] = str(row['pid'] + 1000)
    script = ('import json,os,time; from pathlib import Path; '
              f'Path({str(receipt)!r}).write_text(json.dumps({{"owner_pid":os.getpid(),"pid":100}})); '
              f'rows=json.loads({json.dumps(rows)!r}); '
              '[print(json.dumps(r),flush=True) for r in rows]; time.sleep(30)')

    class FakeContext:
        stage = output = tmp_path
        nonce = NONCE
        profile = {'sid': SID}

        def launch_args(self, argv, label, timeout):
            return [sys.executable, '-u', '-c', script], receipt

        def started(self, _receipt):
            return json.loads(receipt.read_text()), []

        def gone(self, _rows, _label):
            return {'alive': [], 'uncertain': False}

    started = time.monotonic()
    assert net._owner_exit(FakeContext(), [Path(sys.executable).resolve()],
                           {**os.environ, 'PYTHONPATH': str(Path(__file__).parents[1] / 'src')})
    assert time.monotonic() - started < 5


@pytest.mark.parametrize('change', ['hash', 'size', 'version', 'bool_size'])
def test_native_tool_must_match_existing_repository_pin(net, tmp_path, monkeypatch, change):
    image = tmp_path / 'bindiff.exe'
    image.write_bytes(b'authored inert tool bytes')
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    pin = {'contract': 'bindiff-pin/1', 'version_text': 'BinDiff 8', 'assets': {'windows': {
        'executable_size': image.stat().st_size, 'executable_sha256': digest}}}
    monkeypatch.setattr(net, '_read', lambda _path: pin)
    assert net._pinned_executable(image, '8') == digest
    if change == 'hash':
        pin['assets']['windows']['executable_sha256'] = '0' * 64
    elif change == 'size':
        pin['assets']['windows']['executable_size'] += 1
    elif change == 'bool_size':
        pin['assets']['windows']['executable_size'] = True
    else:
        pin['version_text'] = 'BinDiff 9'
    with pytest.raises(net.NetworkEvidenceError):
        net._pinned_executable(image, '8')


@pytest.mark.parametrize('field', ['processes', 'observed', 'launch', 'reason', 'owner_exit_code'])
def test_lifecycle_raw_observation_is_required(net, field):
    doc = evidence(net)
    validate(net, doc)
    del doc['lifecycle']['owner_exit'][field]
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('field,value', [('owner_pid', 9999), ('created', '999999'),
                                      ('executable_sha256', '0' * 64), ('pid', 9999)])
def test_denied_probe_matches_its_actual_launch(net, field, value):
    doc = evidence(net)
    validate(net, doc)
    doc['probe_launch'][field] = value
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


def test_outer_timeout_precedes_native_failsafe(net, tmp_path, monkeypatch):
    from patchtrace.jobs import ProcessResult
    image = tmp_path / 'inert.exe'
    image.write_bytes(b'authored inert bytes')
    context = net.NativeContext(tmp_path, tmp_path, tmp_path, NONCE, image)
    context.profile = {'sid': SID}
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return ProcessResult(1, '', 'timeout')

    monkeypatch.setattr('patchtrace.jobs.run_process', fake_run)
    monkeypatch.setattr(context, 'started', lambda _path: ({}, []))
    result, _receipt = context.wrapped([image], 'timeout-control', cwd=tmp_path, timeout=2)
    assert result.reason == 'timeout'
    argv, kwargs = calls[0]
    assert int(argv[4]) > kwargs['timeout_seconds'] * 1000
    assert int(argv[4]) <= 120000


@pytest.mark.parametrize('record', [
    {'error': 0x800700B7},
    {'created': True, 'name': 'different-profile', 'sid': SID, 'capability_count': 0, 'folder': 'unused'},
])
def test_foreign_or_colliding_profile_is_never_deleted(net, tmp_path, monkeypatch, record):
    context = net.NativeContext(tmp_path, tmp_path, tmp_path, NONCE, tmp_path / 'inert.exe')
    calls = []

    def command(argv, _name):
        calls.append(argv)
        return SimpleNamespace(log_tail=json.dumps(record), stderr_tail='', reason=None,
                               returncode=125 if 'error' in record else 0)

    monkeypatch.setattr(context, '_command', command)
    with pytest.raises(net.NetworkEvidenceError):
        context.create()
    assert context.close() is True
    assert calls == [['profile-create', context.name]]


@pytest.mark.parametrize('change', ['case_type', 'elapsed_huge', 'pid_bool', 'created_huge', 'cleanup_number'])
def test_malformed_observations_refuse_with_controlled_error(net, change):
    doc = evidence(net)
    validate(net, doc)
    if change == 'case_type':
        doc['probes']['before'][0]['cases'][0]['case'] = []
    elif change == 'elapsed_huge':
        doc['elapsed_s'] = 10 ** 1000
    elif change == 'pid_bool':
        doc['probes']['before'][0]['pid'] = True
    elif change == 'created_huge':
        doc['probes']['before'][0]['created'] = '9' * 5000
    else:
        doc['cleanup']['profile_deleted'] = 1
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


def test_untracked_acceptance_implementation_cannot_claim_an_older_tree(net, tmp_path, monkeypatch):
    """A clean unrelated Git tree is not proof for newly added helper code."""
    (tmp_path / 'README').write_bytes(b'authored source ownership control\n')
    for args in (['init', '-q'], ['config', 'core.autocrlf', 'false'], ['add', 'README'],
                 ['-c', 'user.name=Authored Control', '-c', 'user.email=control@example.invalid',
                  'commit', '-qm', 'authored source [no release]']):
        subprocess.run(['git', *args], cwd=tmp_path, check=True, capture_output=True, timeout=15)
    monkeypatch.setattr(net, 'ROOT', tmp_path)
    with pytest.raises(net.NetworkEvidenceError):
        net._source()


def test_untracked_source_refusal_survives_host_git_normalization(net, tmp_path, monkeypatch):
    config = tmp_path / 'authored.gitconfig'
    config.write_bytes(b'[core]\n\tautocrlf = true\n\teol = crlf\n')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(config))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    original = Path.write_text

    def write(path, data, *args, **kwargs):
        if kwargs.get('newline') is None:
            kwargs['newline'] = '\r\n'
        return original(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, 'write_text', write)
    root = tmp_path / 'repo'
    root.mkdir()
    # The original assertion must still reach the untracked implementation
    # refusal, not an earlier working-tree size mismatch from its fixture.
    test_untracked_acceptance_implementation_cannot_claim_an_older_tree(net, root, monkeypatch)
    assert (root / 'README').read_bytes() == b'authored source ownership control\n'
    assert subprocess.check_output(['git', '-C', str(root), 'config', '--local', '--get',
                                    'core.autocrlf']).strip() == b'false'


def test_actual_adapter_routes_both_probe_and_diff_through_selected_runner(tmp_path, monkeypatch):
    """Real adapter/scheduler and authored fake child; not real BinDiff evidence."""
    import test_live_bindiff as live
    from fake_bindiff import launcher_names, make_fake_bindiff
    from test_bindiff_inputs import accepted

    from patchtrace.jobs import run_process
    from patchtrace.secondary import bindiff_probe
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    older, newer = tmp_path / 'older.artifact', tmp_path / 'newer.artifact'
    older.write_bytes(b'MZ authored older')
    newer.write_bytes(b'MZ authored newer')
    old_sha, new_sha = (hashlib.sha256(path.read_bytes()).hexdigest() for path in (older, newer))
    exports = tmp_path / 'exports'
    exports.mkdir()
    inputs = live.Inputs(accepted(exports, 'older', old_sha), accepted(exports, 'newer', new_sha),
                         old_sha, new_sha, older, newer, 'AUTHORED MOCK', 'known fake identity', True)
    executable = make_fake_bindiff(tmp_path / 'fake')
    calls = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        return run_process(argv, **kwargs)

    observed = live._end_to_end(str(executable), inputs, tmp_path / 'adapter', None, runner=runner,
                                evidence_dir=tmp_path / 'evidence')
    assert observed['status'] == 'passed', observed
    assert observed['matches'] == 2 and len(observed['semantic_sha256']) == 64
    assert calls[0][1:] == ['--version']
    assert calls[1][1:] == ['--nologo', '--help']
    assert len(calls) == 3 and '--output_format=bin' in calls[2]
    assert (tmp_path / 'evidence' / 'bindiff-live.BinDiff').is_file()


@pytest.mark.parametrize('same_semantics,expected', [(True, 'passed'), (False, 'failed')])
def test_linux_count_parity_does_not_replace_semantic_parity(tmp_path, monkeypatch, same_semantics, expected):
    """Mocked namespace/adapter observations test the acceptance decision only."""
    import test_live_bindiff as live

    from patchtrace.jobs import ProcessResult
    monkeypatch.setattr(live, 'os', SimpleNamespace(name='posix'))
    monkeypatch.setattr(live.shutil, 'which', lambda *_args, **_kwargs: '/authored/unshare')
    monkeypatch.setattr(live, 'run_process', lambda *_args, **_kwargs: ProcessResult(0, ''))
    monkeypatch.setattr(live, '_end_to_end', lambda *_args, **_kwargs: {
        'status': 'passed', 'matches': 2, 'semantic_sha256': 'a' * 64 if same_semantics else 'b' * 64})
    result = live._no_network(SimpleNamespace(path='/authored/bindiff', version='8'), None, None,
                              tmp_path / 'nonet', 2, 'a' * 64)
    assert result['status'] == expected


def test_serial_launch_pid_reuse_requires_distinct_creation_identity(net):
    doc = evidence(net)
    validate(net, doc)
    second = doc['launches'][1]
    second.update(pid=doc['launches'][0]['pid'], owner_pid=900)
    validate(net, doc)  # terminated process IDs may be reused in a later launch
    second['created'] = doc['launches'][0]['created']
    with pytest.raises(net.NetworkEvidenceError):
        validate(net, doc)


@pytest.mark.parametrize('change', ['missing_bytes', 'truncated', 'invalid_utf8'])
def test_native_probe_requires_complete_strict_byte_capture(net, change):
    from patchtrace.jobs import ProcessResult
    raw = b'{"authored":true}\n'
    result = ProcessResult(0, raw.decode(), log_bytes=raw, stdout_total=len(raw))
    assert net._probe_rows(result) == [{'authored': True}]
    if change == 'missing_bytes':
        result = replace(result, log_bytes=None)
    elif change == 'truncated':
        result = replace(result, stdout_total=len(raw) + 100)
    else:
        bad = b'{"authored":"\xff"}\n'
        result = replace(result, log_bytes=bad, log_tail=bad.decode('utf-8', errors='replace'), stdout_total=len(bad))
    with pytest.raises(net.NetworkEvidenceError):
        net._probe_rows(result)


CREATION_LOCATIONS = (
    'probe-before', 'probe-denied', 'probe-after', 'probe-version', 'probe-help', 'diff',
    'cancel-root', 'cancel-child', 'timeout-root', 'timeout-child', 'owner_exit-root', 'owner_exit-child',
)


def _creation_records(doc, location):
    """Mutate linked records together so ordinary ownership equality still holds."""
    if location in ('probe-version', 'probe-help', 'diff'):
        return [next(row for row in doc['launches'] if row['purpose'] == location)]
    if location.startswith('probe-'):
        phase = location.removeprefix('probe-')
        return [doc['probes'][phase][0], *([doc['probe_launch']] if phase == 'denied' else [])]
    label, depth = location.rsplit('-', 1)
    record = doc['lifecycle'][label]
    return [record['processes'][0], record['launch']] if depth == 'root' else [record['processes'][2]]


@pytest.mark.parametrize('location', CREATION_LOCATIONS)
@pytest.mark.parametrize('spelling', ['leading-zero', 'unicode-decimal', 'mixed-decimal'])
def test_every_receipt_creation_identity_requires_canonical_native_spelling(net, location, spelling):
    doc = evidence(net)
    validate(net, doc)
    records = _creation_records(doc, location)
    original = records[0]['created']
    if spelling == 'leading-zero':
        disguised = '0' + original
    elif spelling == 'unicode-decimal':
        disguised = ''.join(chr(0x660 + int(digit)) for digit in original)
    else:
        disguised = original[:-1] + chr(0xFF10 + int(original[-1]))
    assert disguised != original and int(disguised) == int(original)
    for row in records:
        row['created'] = disguised
    decoded = net.read_evidence_bytes(json.dumps(doc, ensure_ascii=False).encode('utf-8'))
    with pytest.raises(net.NetworkEvidenceError, match='creation'):
        validate(net, decoded)


_MISSING_CREATION = object()
MALFORMED_CREATIONS = [
    pytest.param(_MISSING_CREATION, id='missing'), pytest.param(None, id='null'),
    pytest.param(True, id='boolean'), pytest.param(1100, id='integer'), pytest.param('', id='empty'),
    pytest.param('0', id='zero'), pytest.param('00', id='zeroes'), pytest.param('01100', id='leading-zero'),
    pytest.param('\u0661\u0661\u0660\u0660', id='unicode-decimal'),
    pytest.param('11\uff100', id='mixed-decimal'), pytest.param('+1100', id='sign'),
    pytest.param(' 1100', id='whitespace'), pytest.param('1100\n', id='newline'),
    pytest.param('1.1', id='fraction'), pytest.param('1e3', id='exponent'),
    pytest.param(str(1 << 64), id='overflow'), pytest.param('9' * 5000, id='overlong'),
    pytest.param('1\x00', id='nul'),
]


def _native_identity_context(net, tmp_path, monkeypatch, created):
    context = net.NativeContext(tmp_path, tmp_path, tmp_path, NONCE, tmp_path / 'inert.exe')
    context.profile = {'sid': SID}
    start = dict(evidence(net)['launches'][0], phase='started')
    if created is _MISSING_CREATION:
        del start['created']
    else:
        start['created'] = created
    monkeypatch.setattr(net, '_lines', lambda _path: [start])
    calls = []

    def command(argv, label):
        calls.append((argv, label))
        return SimpleNamespace(log_tail='{"alive":[],"uncertain":false}', stderr_tail='',
                               reason=None, returncode=0)

    monkeypatch.setattr(context, '_command', command)
    return context, start, calls


@pytest.mark.parametrize('created', MALFORMED_CREATIONS)
@pytest.mark.parametrize('entry_point', ['started', 'gone'])
def test_native_creation_identity_is_refused_before_admission_or_liveness_query(
        net, tmp_path, monkeypatch, created, entry_point):
    context, start, calls = _native_identity_context(net, tmp_path, monkeypatch, created)
    with pytest.raises(net.NetworkEvidenceError, match='creation'):
        if entry_point == 'started':
            context.started(tmp_path / 'authored-start.ndjson')
        else:
            context.gone([start], 'authored')
    assert calls == []  # malformed identities never reach the native liveness helper


@pytest.mark.parametrize('created', ['1', '1100', str((1 << 64) - 1)])
@pytest.mark.parametrize('entry_point', ['started', 'gone'])
def test_canonical_native_creation_bounds_remain_usable(net, tmp_path, monkeypatch, created, entry_point):
    context, start, calls = _native_identity_context(net, tmp_path, monkeypatch, created)
    if entry_point == 'started':
        admitted, _rows = context.started(tmp_path / 'authored-start.ndjson')
        assert admitted['created'] == created and calls == []
    else:
        assert context.gone([start], 'authored') == {'alive': [], 'uncertain': False}
        assert calls == [(['alive', str(start['pid']) + ':' + created], 'authored-alive')]


@pytest.mark.parametrize('created', ['1', str((1 << 64) - 1)])
def test_all_receipt_locations_accept_canonical_creation_bounds(net, created):
    doc = evidence(net)
    for location in CREATION_LOCATIONS:
        for row in _creation_records(doc, location):
            row['created'] = created
    validate(net, doc)
