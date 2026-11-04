"""SPEC-28 §17: native receipts (RB-03) built from the live producers' status documents.

The documents here are synthetic, with the keys `tools/live_rzdiff_check.py` and `tests/test_live_bindiff.py`
write today; none of this is live evidence. The one harness test drives the live BinDiff test with the fake
BinDiff (declared mocked) only to prove the producer records the two hash pairs the receipt needs.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from bindiff_live_pair import write_pair
from fake_bindiff import make_fake_bindiff

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'native_receipt.py'
sys.path.insert(0, str(ROOT / 'tools'))

import native_receipt  # noqa: E402

HEAD = '0123456789abcdef0123456789abcdef01234567'
ENV = {'PATCHTRACE_SOURCE_HEAD': HEAD, 'GITHUB_REPOSITORY': 'owner/patchtrace', 'GITHUB_RUN_ID': '123',
       'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_OS': 'Linux'}
OLDER, NEWER, OUT, ARCHIVE, EXE = ('1' * 64, '2' * 64, '3' * 64, '4' * 64, '5' * 64)
BX_OLDER, BX_NEWER = '6' * 64, '7' * 64
SYNTHETIC = 'synthetic fixture pair; not real-binary evidence'
ZERO_RZ = 'AssertionError: rz-diff produced zero function matches'
_PIN_TEXT = json.loads((ROOT / 'tools' / 'bindiff_pin.json').read_text(encoding='utf-8'))['version_text']
BINDIFF_PIN = _PIN_TEXT.removeprefix('BinDiff ')
BLOCKED_REASON = 'PATCHTRACE_BINDIFF is not set: no BinDiff installed or provisioned on this machine'


def rz_doc(**over) -> dict:
    """A passing `live-rzdiff-<os>.json` exactly as tools/live_rzdiff_check.py writes it."""
    doc = {'kind': 'live-rzdiff', 'mocked': False, 'os': 'Linux', 'pin': '0.9.1', 'archive_sha256': ARCHIVE,
           'status': 'passed', 'errors': [], 'fixture_sha256': {'older': OLDER, 'newer': NEWER},
           'rizin_version': '0.9.1', 'help_flags': {'-C': True, '-j': True, '-t': True},
           'engine_run': {'status': 'ok', 'error_code': None, 'argv_digest': '8' * 64},
           'match_count': 4, 'output_sha256': OUT, 'duration_seconds': 1.25}
    doc.update(over)
    return doc


def _passed(reason: str, **details) -> dict:
    return {'status': 'passed', 'reason': reason, **details}


def bd_doc(**over) -> dict:
    """A passing `bindiff.json` as tests/test_live_bindiff.py records it on the synthetic route."""
    doc = {'engine': 'bindiff', 'status': 'passed', 'reason': 'all live checks passed', 'mocked': False,
           'input': 'SYNTHETIC tests/bindiff_live_pair.py (20/21 functions; not real-driver evidence)',
           'acceptance': 'C3 accept_binexport inside BinDiffAdapter (production path)',
           'source_pair_sha256': {'older': OLDER, 'newer': NEWER},
           'input_pair_sha256': {'older': BX_OLDER, 'newer': BX_NEWER},
           'checks': {
               'probe': _passed('supported', version=BINDIFF_PIN, untested_version=False, executable_sha256=EXE),
               'pinned_version': _passed(f'probe version {BINDIFF_PIN!r}, pin {BINDIFF_PIN!r}'),
               'reversed_refused': _passed('reversed .BinExport pair refused before any spawn'),
               'end_to_end': _passed('end-to-end run imported and validated', matches=20, engine_version='8',
                                     output_sha256=OUT, duration_ms=812, bindiff_summary=None,
                                     algorithms=['function: hash matching']),
               'cancel_at_first_output': _passed('cancelled discarded the partial output unread'),
               'timeout_mid_run': _passed('timeout discarded the partial output unread'),
               'no_network': _passed('identical result inside unshare -rn', matches=20)}}
    doc.update(over)
    return doc


def write(path: Path, doc: dict | str | bytes) -> Path:
    if isinstance(doc, bytes):
        path.write_bytes(doc)
    else:
        text = doc if isinstance(doc, str) else json.dumps(doc, indent=2, sort_keys=True)
        path.write_text(text, encoding='utf-8', newline='\n')
    return path


def receipt_for(tmp_path: Path, doc, name: str = 'live-rzdiff-Linux.json', env: dict | None = None) -> dict:
    receipt = native_receipt.build_receipt(write(tmp_path / name, doc), ENV if env is None else env)
    assert native_receipt.validate(receipt) == [], receipt   # every receipt the converter emits is well-formed
    return receipt


def check(receipt: dict, name: str) -> dict:
    (found,) = [c for c in receipt['checks'] if c['name'] == name]
    return found


def gate_checks(**reasons) -> list[dict]:
    return [{'name': f'gate.{name}', 'status': 'passed', 'reason': reason} for name, reason in reasons.items()]


def test_rzdiff_mapping_golden(tmp_path):
    path = write(tmp_path / 'live-rzdiff-Linux.json', rz_doc())
    receipt = native_receipt.build_receipt(path, ENV)
    assert receipt == {
        'contract': 'secondary-native-receipt/1', 'gate': 'RB-03', 'engine': 'rz-diff',
        'repository': 'owner/patchtrace', 'head_sha': HEAD, 'workflow_run_id': 123, 'run_attempt': 1,
        'platform': 'Linux', 'mocked': False, 'engine_version': '0.9.1', 'pin': '0.9.1', 'tool_sha256': ARCHIVE,
        'source_pair_sha256': {'older': OLDER, 'newer': NEWER}, 'input_pair_sha256': None,
        'output_sha256': OUT, 'match_count': 4,
        'checks': gate_checks(
            source='strict JSON live-rzdiff document', head_sha='exact head from PATCHTRACE_SOURCE_HEAD',
            not_mocked='live run (mocked is false)', pinned_version='engine version equals the pin',
            distinct_sources='older and newer source digests differ',
            identity='live_rzdiff_check asserted the match-set hashes equal the fixture pair') + [
            {'name': 'rz-diff.help_flags', 'status': 'passed', 'reason': 'rz-diff -h declares -C, -j, -t'},
            {'name': 'rz-diff.engine_run', 'status': 'passed', 'reason': 'run_engines status ok'},
            {'name': 'rz-diff.verdict', 'status': 'passed', 'reason': 'live_rzdiff_check passed'}],
        'case_count': 3, 'evaluated_count': 3, 'passed_count': 3, 'failed_count': 0, 'blocked_count': 0,
        'outcome': 'PASS', 'limitations': [SYNTHETIC], 'source_file': 'live-rzdiff-Linux.json',
        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    assert native_receipt.validate(receipt) == []


def test_bindiff_mapping_golden(tmp_path):
    path = write(tmp_path / 'bindiff.json', bd_doc())
    receipt = native_receipt.build_receipt(path, ENV)
    cases = [{'name': f'bindiff.{name}', 'status': 'passed', 'reason': c['reason']}
             for name, c in sorted(bd_doc()['checks'].items())]
    assert receipt == {
        'contract': 'secondary-native-receipt/1', 'gate': 'RB-03', 'engine': 'bindiff',
        'repository': 'owner/patchtrace', 'head_sha': HEAD, 'workflow_run_id': 123, 'run_attempt': 1,
        'platform': 'Linux', 'mocked': False, 'engine_version': BINDIFF_PIN, 'pin': BINDIFF_PIN,
        'tool_sha256': EXE, 'source_pair_sha256': {'older': OLDER, 'newer': NEWER},
        'input_pair_sha256': {'older': BX_OLDER, 'newer': BX_NEWER}, 'output_sha256': OUT, 'match_count': 20,
        'checks': gate_checks(
            source='strict JSON bindiff live-status document', head_sha='exact head from PATCHTRACE_SOURCE_HEAD',
            not_mocked='live run (mocked is false)', pinned_version='engine version equals the pin',
            distinct_sources='older and newer source digests differ',
            identity='end_to_end bound the match set to the source pair') + cases,
        'case_count': 7, 'evaluated_count': 7, 'passed_count': 7, 'failed_count': 0, 'blocked_count': 0,
        'outcome': 'PASS', 'limitations': [SYNTHETIC], 'source_file': 'bindiff.json',
        'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def test_real_export_label_adds_no_synthetic_limitation(tmp_path):
    receipt = receipt_for(tmp_path, bd_doc(input='real exports from pair'), 'bindiff.json')
    assert receipt['outcome'] == 'PASS' and receipt['limitations'] == []


def _zero_bindiff() -> dict:
    doc = bd_doc(status='failed', reason='end_to_end: zero matches')
    doc['checks']['end_to_end'].update(status='failed', reason='zero matches', matches=0)
    return doc


@pytest.mark.parametrize('doc,name', [
    (rz_doc(status='failed', errors=[ZERO_RZ], match_count=0), 'live-rzdiff-Linux.json'),
    (_zero_bindiff(), 'bindiff.json'),
], ids=['rz', 'bd'])
def test_zero_matches_is_insufficient_data(tmp_path, doc, name):
    receipt = receipt_for(tmp_path, doc, name)
    assert receipt['match_count'] == 0 and receipt['failed_count'] == 0
    assert receipt['outcome'] == 'INSUFFICIENT_DATA'


def test_zero_matches_does_not_hide_another_problem_in_the_same_check(tmp_path):
    doc = _zero_bindiff()
    doc['checks']['end_to_end']['reason'] = 'zero matches; raw .BinDiff not preserved exactly once'
    receipt = receipt_for(tmp_path, doc, 'bindiff.json')
    assert receipt['outcome'] == 'FAIL'
    assert check(receipt, 'bindiff.end_to_end') == {'name': 'bindiff.end_to_end', 'status': 'failed',
                                                     'reason': 'raw .BinDiff not preserved exactly once'}


def test_passed_status_with_nothing_evaluated_is_never_pass(tmp_path):
    doc = {'engine': 'binexport2', 'status': 'passed', 'reason': 'ok', 'mocked': False, 'engine_version': '1',
           'pin': '1', 'source_pair_sha256': {'older': OLDER, 'newer': NEWER}, 'match_count': 5, 'checks': {}}
    receipt = receipt_for(tmp_path, doc, 'binexport2.json')
    assert (receipt['case_count'], receipt['evaluated_count']) == (0, 0)
    assert receipt['outcome'] == 'INSUFFICIENT_DATA'
    bare = {key: doc[key] for key in ('engine', 'status', 'reason', 'mocked')}
    assert receipt_for(tmp_path, bare, 'binexport2.json')['outcome'] == 'BLOCKED'   # nothing recorded at all


@pytest.mark.parametrize('doc,name', [(rz_doc(mocked=True), 'live-rzdiff-Linux.json'),
                                      (bd_doc(mocked=True), 'bindiff.json'),
                                      ({k: v for k, v in bd_doc().items() if k != 'mocked'}, 'bindiff.json')],
                         ids=['rz', 'bd', 'bd-unset'])
def test_mocked_or_unrecorded_mock_flag_is_never_pass(tmp_path, doc, name):
    receipt = receipt_for(tmp_path, doc, name)
    assert receipt['outcome'] != 'PASS'
    assert check(receipt, 'gate.not_mocked')['status'] != 'passed'


def test_mocked_true_fails(tmp_path):
    receipt = receipt_for(tmp_path, rz_doc(mocked=True))
    assert receipt['outcome'] == 'FAIL' and receipt['mocked'] is True


@pytest.mark.parametrize('head', [{}, {'PATCHTRACE_SOURCE_HEAD': HEAD[:12]}, {'PATCHTRACE_SOURCE_HEAD': HEAD.upper()},
                                  {'PATCHTRACE_SOURCE_HEAD': HEAD + '0'},
                                  {'PATCHTRACE_SOURCE_HEAD': 'x' * 40, 'GITHUB_SHA': HEAD}],
                         ids=['absent', 'short', 'upper', 'long', 'no-fallback'])
def test_short_or_absent_head_fails(tmp_path, head):
    env = {**{k: v for k, v in ENV.items() if k != 'PATCHTRACE_SOURCE_HEAD'}, **head}
    receipt = receipt_for(tmp_path, rz_doc(), env=env)
    assert receipt['outcome'] == 'FAIL' and check(receipt, 'gate.head_sha')['status'] == 'failed'


def test_github_sha_is_the_head_fallback(tmp_path):
    env = {**{k: v for k, v in ENV.items() if k != 'PATCHTRACE_SOURCE_HEAD'}, 'GITHUB_SHA': HEAD}
    receipt = receipt_for(tmp_path, rz_doc(), env=env)
    assert receipt['outcome'] == 'PASS' and receipt['head_sha'] == HEAD


def test_version_not_equal_to_pin_fails(tmp_path):
    produced = rz_doc(status='failed', errors=['AssertionError: version 0.9.2 != pin 0.9.1'], rizin_version='0.9.2')
    for key in ('help_flags', 'engine_run', 'match_count', 'output_sha256'):
        del produced[key]                         # the producer stops at the pin assertion
    receipt = receipt_for(tmp_path, produced)
    assert receipt['outcome'] == 'FAIL'
    assert check(receipt, 'gate.pinned_version') == {'name': 'gate.pinned_version', 'status': 'failed',
                                                     'reason': "engine version '0.9.2' is not the pin '0.9.1'"}
    doc = bd_doc()
    doc['checks']['probe']['version'] = '7.1'      # the gate check holds even if the producer missed it
    assert receipt_for(tmp_path, doc, 'bindiff.json')['outcome'] == 'FAIL'


def test_identical_sources_fail(tmp_path):
    receipt = receipt_for(tmp_path, rz_doc(fixture_sha256={'older': OLDER, 'newer': OLDER}))
    assert receipt['outcome'] == 'FAIL' and check(receipt, 'gate.distinct_sources')['status'] == 'failed'


def test_unbound_match_set_fails_identity(tmp_path):
    doc = bd_doc(status='failed')
    doc['checks']['end_to_end'].update(status='failed',
                                       reason='match set is not bound to the project artifact hashes')
    receipt = receipt_for(tmp_path, doc, 'bindiff.json')
    assert receipt['outcome'] == 'FAIL' and check(receipt, 'gate.identity')['status'] == 'failed'


def test_blocked_bindiff_keeps_its_reason(tmp_path):
    doc = {'engine': 'bindiff', 'status': 'blocked', 'reason': BLOCKED_REASON, 'mocked': False}
    receipt = receipt_for(tmp_path, doc, 'bindiff.json')
    assert receipt['outcome'] == 'BLOCKED'
    assert check(receipt, 'bindiff.status') == {'name': 'bindiff.status', 'status': 'blocked',
                                                'reason': BLOCKED_REASON}
    assert (receipt['case_count'], receipt['evaluated_count'], receipt['blocked_count']) == (1, 0, 1)


def test_partially_blocked_run_is_blocked_not_pass(tmp_path):
    doc = bd_doc(status='blocked', reason='no_network: Linux-only check')
    doc['checks']['no_network'] = {'status': 'blocked', 'reason': 'Linux-only check (unshare -rn)'}
    assert receipt_for(tmp_path, doc, 'bindiff.json')['outcome'] == 'BLOCKED'


def test_status_that_disagrees_with_its_checks_fails(tmp_path):
    receipt = receipt_for(tmp_path, bd_doc(status='failed', reason='something'), 'bindiff.json')
    assert receipt['outcome'] == 'FAIL' and check(receipt, 'bindiff.status')['status'] == 'failed'


@pytest.mark.parametrize('content', [
    '{"kind": "live-rzdiff", "match_count": NaN}', '{"kind": "live-rzdiff", "kind": "live-rzdiff"}',
    '{not json', '[]', b'\xef\xbb\xbf{}', b'\xff\xfe{', None,
    json.dumps({'engine': 'bindiff', 'status': 'great', 'reason': 'x'}),
    json.dumps(rz_doc(errors='none')), json.dumps(bd_doc(checks={'Bad Name': {'status': 'passed', 'reason': ''}})),
    '{"kind": "live-rzdiff", "match_count": 1e400}', '[' * 200_000, '{"kind": "live-rzdiff", "n": ' + '9' * 5000 + '}',
], ids=['nan', 'dup', 'trunc', 'list', 'bom', 'bytes', 'missing', 'status', 'errors', 'name', 'inf', 'deep', 'bigint'])
def test_malformed_input_becomes_a_fail_receipt(tmp_path, content):
    path = tmp_path / 'live-rzdiff-Linux.json'
    if content is not None:
        write(path, content)
    receipt = native_receipt.build_receipt(path, ENV)
    assert native_receipt.validate(receipt) == []
    assert receipt['outcome'] == 'FAIL' and check(receipt, 'gate.source')['status'] == 'failed'
    assert receipt['source_file'] == 'live-rzdiff-Linux.json'
    assert receipt['source_sha256'] == (None if content is None else hashlib.sha256(path.read_bytes()).hexdigest())


def test_unrecognisable_input_is_an_unknown_engine_fail(tmp_path):
    receipt = receipt_for(tmp_path, {'hello': 1}, 'other.json')
    assert (receipt['engine'], receipt['outcome']) == ('unknown', 'FAIL')


def test_hostile_text_is_bounded_and_escaped(tmp_path):
    doc = {'engine': 'bindiff', 'status': 'blocked', 'reason': 'a b\x1b[31m\n' + 'x' * 5000, 'mocked': False}
    receipt = receipt_for(tmp_path, doc, 'bindiff.json')
    reason = check(receipt, 'bindiff.status')['reason']
    assert len(reason) <= 300 and reason.startswith('a b [31m ')
    assert all(ch.isprintable() for ch in reason)


def run_build(tmp_path: Path, out: Path, *inputs: Path, env: dict | None = None) -> int:
    argv = ['build', '--out', str(out)] + [arg for path in inputs for arg in ('--input', str(path))]
    return native_receipt.main(argv, environ=ENV if env is None else env)


def test_binexport2_without_input_is_blocked(tmp_path):
    out = tmp_path / 'receipts'
    assert run_build(tmp_path, out, write(tmp_path / 'live-rzdiff-Linux.json', rz_doc())) == 0
    assert sorted(p.name for p in out.iterdir()) == ['binexport2-Linux.json', 'rz-diff-Linux.json']
    receipt = json.loads((out / 'binexport2-Linux.json').read_text(encoding='utf-8'))
    assert native_receipt.validate(receipt) == []
    assert receipt['outcome'] == 'BLOCKED' and receipt['source_file'] is None
    assert check(receipt, 'gate.source') == {'name': 'gate.source', 'status': 'blocked',
                                             'reason': 'no Ghidra/IDA-produced .BinExport, C3-7'}


def test_binexport2_status_file_replaces_the_absent_receipt(tmp_path):
    out = tmp_path / 'receipts'
    doc = {'engine': 'binexport2', 'status': 'blocked', 'reason': 'Ghidra export not provisioned', 'mocked': False}
    assert run_build(tmp_path, out, write(tmp_path / 'binexport2.json', doc)) == 0
    assert [p.name for p in out.iterdir()] == ['binexport2-Linux.json']
    receipt = json.loads((out / 'binexport2-Linux.json').read_text(encoding='utf-8'))
    assert receipt['source_file'] == 'binexport2.json' and receipt['outcome'] == 'BLOCKED'


def test_rebuild_is_byte_identical_canonical_json(tmp_path):
    inputs = [write(tmp_path / 'live-rzdiff-Linux.json', rz_doc()), write(tmp_path / 'bindiff.json', bd_doc()),
              write(tmp_path / 'live-rzdiff-Windows.json', rz_doc(os='Windows')), tmp_path / 'gone.json']
    first, second = tmp_path / 'a', tmp_path / 'b'
    assert run_build(tmp_path, first, *inputs) == 0 and run_build(tmp_path, second, *inputs) == 0
    names = sorted(p.name for p in first.iterdir())
    assert names == ['bindiff-Linux.json', 'binexport2-Linux.json', 'rz-diff-Linux.json', 'rz-diff-Windows.json',
                     'unknown-Linux.json']
    for name in names:
        raw = (first / name).read_bytes()
        assert raw == (second / name).read_bytes() and b'\r' not in raw and raw.endswith(b'}\n')
        assert raw.decode('ascii') == json.dumps(json.loads(raw), indent=2, sort_keys=True) + '\n'


def test_colliding_names_get_a_suffix(tmp_path):
    out = tmp_path / 'receipts'
    one, two = tmp_path / 'one', tmp_path / 'two'
    one.mkdir()
    two.mkdir()
    rz = rz_doc()
    assert run_build(tmp_path, out, write(one / 'r.json', rz), write(two / 'r.json', rz)) == 0
    assert sorted(p.name for p in out.iterdir()) == ['binexport2-Linux.json', 'rz-diff-Linux-2.json',
                                                     'rz-diff-Linux.json']


def _built(tmp_path: Path, doc: dict, name: str) -> Path:
    out = tmp_path / f'out-{name}'
    assert run_build(tmp_path, out, write(tmp_path / name, doc)) == 0
    (receipt,) = [p for p in out.iterdir() if not p.name.startswith('binexport2')]
    return receipt


def test_check_exit_codes(tmp_path, capsys):
    passing = _built(tmp_path, rz_doc(), 'live-rzdiff-Linux.json')
    blocked = _built(tmp_path, {'engine': 'bindiff', 'status': 'blocked', 'reason': 'absent', 'mocked': False},
                     'bindiff.json')
    assert native_receipt.main(['check', str(passing), '--require-pass'], environ=ENV) == 0
    assert native_receipt.main(['check', str(passing), str(blocked)], environ=ENV) == 0
    assert native_receipt.main(['check', str(passing), str(blocked), '--require-pass'], environ=ENV) == 3
    wrong_head = {**ENV, 'PATCHTRACE_SOURCE_HEAD': 'f' * 40}
    assert native_receipt.main(['check', str(passing), '--require-pass'], environ=wrong_head) == 3
    assert native_receipt.main(['check', str(tmp_path / 'missing.json')], environ=ENV) == 2
    assert native_receipt.main(['check', str(blocked), str(tmp_path / 'missing.json'), '--require-pass'],
                               environ=ENV) == 2      # malformed outranks not-PASS
    assert 'wrong head' in capsys.readouterr().out
    with pytest.raises(SystemExit) as raised:
        native_receipt.main(['build', '--out', str(tmp_path / 'x')], environ=ENV)
    assert raised.value.code == 2


def _forge(path: Path, edit) -> Path:
    receipt = json.loads(path.read_text(encoding='utf-8'))
    edit(receipt)
    forged = path.with_name('forged-' + path.name)
    forged.write_text(native_receipt.render(receipt), encoding='utf-8', newline='\n')
    return forged


def _clear_mocked_flag(receipt: dict) -> None:
    receipt['mocked'] = False


def _promote_outcome(receipt: dict) -> None:
    receipt['outcome'] = 'PASS'


def _pass_every_check(receipt: dict) -> None:
    for item in receipt['checks']:
        item['status'] = 'passed'
    receipt.update(failed_count=0, passed_count=receipt['case_count'], evaluated_count=receipt['case_count'],
                   outcome='PASS')


def _drop_gate(receipt: dict) -> None:
    receipt['checks'] = [c for c in receipt['checks'] if c['name'] != 'gate.identity']


def _extra_key(receipt: dict) -> None:
    receipt['verified'] = True


def _bool_count(receipt: dict) -> None:
    receipt['match_count'] = True


@pytest.mark.parametrize('edit', [_clear_mocked_flag, _promote_outcome, _pass_every_check, _drop_gate, _extra_key,
                                  _bool_count], ids=['mock', 'outcome', 'checks', 'gate', 'key', 'bool'])
def test_check_rejects_forged_receipts(tmp_path, edit):
    mocked = _built(tmp_path, rz_doc(mocked=True), 'live-rzdiff-Linux.json')
    assert native_receipt.main(['check', str(mocked)], environ=ENV) == 0
    assert native_receipt.main(['check', str(_forge(mocked, edit))], environ=ENV) == 2


def test_check_rejects_non_canonical_serialisation(tmp_path):
    passing = _built(tmp_path, rz_doc(), 'live-rzdiff-Linux.json')
    data = json.loads(passing.read_text(encoding='utf-8'))
    for name, text in (('compact.json', json.dumps(data, sort_keys=True)),
                       ('crlf.json', native_receipt.render(data).replace('\n', '\r\n'))):
        (tmp_path / name).write_bytes(text.encode('utf-8'))
        assert native_receipt.main(['check', str(tmp_path / name)], environ=ENV) == 2


def test_script_entry_point(tmp_path):
    out = tmp_path / 'receipts'
    source = write(tmp_path / 'live-rzdiff-Linux.json', rz_doc())
    env = {**{k: v for k, v in os.environ.items() if not k.startswith(('PATCHTRACE_', 'GITHUB_', 'RUNNER_'))},
           **ENV}
    built = subprocess.run([sys.executable, str(TOOL), 'build', '--input', str(source), '--out', str(out)],
                           env=env, capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stderr
    checked = subprocess.run([sys.executable, str(TOOL), 'check', str(out / 'rz-diff-Linux.json'), '--require-pass'],
                             env=env, capture_output=True, text=True, timeout=120)
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_live_bindiff_records_source_and_input_pairs(tmp_path):
    """Producer contract: the live test's status JSON carries both hash pairs (fake BinDiff, declared mocked)."""
    status = tmp_path / 'status'
    exe = make_fake_bindiff(tmp_path / 'bd')
    base = {k: v for k, v in os.environ.items() if not k.startswith('PATCHTRACE_')}
    env = {**base, 'PATCHTRACE_LIVE_STATUS_DIR': str(status), 'PATCHTRACE_LIVE_MOCKED': '1',
           'PATCHTRACE_BINDIFF': str(exe), 'PATCHTRACE_LIVE_SYNTHETIC_PAIR': '1'}
    subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                    str(ROOT / 'tests' / 'test_live_bindiff.py')], cwd=ROOT, env=env, capture_output=True,
                   text=True, timeout=600)
    record = json.loads((status / 'bindiff.json').read_text(encoding='utf-8'))
    receipt = native_receipt.build_receipt(status / 'bindiff.json', ENV)
    assert native_receipt.validate(receipt) == [] and receipt['outcome'] == 'FAIL'   # mocked is never PASS
    if os.name == 'nt':  # the .cmd launcher is (correctly) not an accepted BinDiff executable name
        assert record['status'] == 'blocked' and 'source_pair_sha256' not in record
        return
    pair = write_pair(tmp_path / 'expected')
    assert record['source_pair_sha256'] == {'older': pair.older_sha256, 'newer': pair.newer_sha256}
    assert record['input_pair_sha256'] == {'older': pair.older.summary.file_sha256,
                                           'newer': pair.newer.summary.file_sha256}
    assert receipt['source_pair_sha256'] == record['source_pair_sha256']
    assert receipt['input_pair_sha256'] == record['input_pair_sha256']
    assert receipt['limitations'] == [SYNTHETIC]
