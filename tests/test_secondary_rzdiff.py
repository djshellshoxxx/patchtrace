"""SPEC-11: rz-diff probe, supervised run via fake executables, and strict parser."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest
from fake_exe import make_fake_exe

from patchtrace.jobs import ProcessResult
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.rzdiff import parse_output, parse_version, probe, run_rzdiff

OLD, NEW = 'a' * 64, 'b' * 64
FIXTURE = Path(__file__).parent / 'fixtures' / 'secondary' / 'rzdiff-functions.json'
# Retained native rz-diff stdout (another session's capture, see the fixture's `source`); nothing here runs rz-diff.
SHAPES = json.loads(FIXTURE.with_name('rzdiff-singleton-shapes.json').read_text(encoding='utf-8'))
REFUSED = [s for s in SHAPES['shapes'] if s['expect'] == 'refused']
PARSED = [s for s in SHAPES['shapes'] if s['expect'] == 'parsed']


def fake(tmp_path, body: str) -> Path:
    return make_fake_exe(tmp_path, 'rz-diff', f'import sys, time, os\n{body}\n')


def cap(path='/opt/rz-diff', version='0.9.1'):
    return Capability(engine='rz-diff', supported=True, version=version, path=str(path), supports_json=True)


def artifacts(tmp_path):
    older, newer = tmp_path / 'old.sys', tmp_path / 'new.sys'
    older.write_bytes(b'MZ1')
    newer.write_bytes(b'MZ2')
    return older, newer


def test_fixture_parses_with_one_sided_records():
    result = parse_output(FIXTURE.read_text(), '0.9.1', OLD, NEW)
    assert result.engine == 'rz-diff' and len(result.matches) == 4
    full, partial, removed, added = result.matches
    assert (full.similarity_milli, full.match_type) == (1000, 'COMPLETE')
    assert (partial.similarity_milli, partial.similarity_text) == (963, '0.962963')
    assert partial.older_address == 0x140001008 and partial.algorithm == 'levenshtein-bytes'
    assert partial.confidence_milli is None and partial.flags == ()
    assert removed.newer_address is None and removed.older_address == 0x140002000
    assert added.older_address is None and added.newer_name == 'fcn.140003000'
    assert any('Levenshtein' in text for text in result.limitations)


ENTRY = {'similarity': 0.5, 'type': 'PARTIAL', 'original': {'addr': 1, 'name': 'f', 'size': 1},
         'modified': {'addr': 2, 'name': 'g', 'size': 1}}


def variant(**over):
    entry = {**ENTRY, **over}
    return json.dumps([{k: v for k, v in entry.items() if v != '<drop>'}])


SECOND = {'similarity': 1.0, 'type': 'COMPLETE', 'original': {'addr': 3, 'name': 'h', 'size': 1},
          'modified': {'addr': 4, 'name': 'h', 'size': 1}}


def accepted(**over):
    """`variant` plus a second newer function: a one-row document is refused (SPEC-11 section 9)."""
    return json.dumps([{**ENTRY, **over}, SECOND])


@pytest.mark.parametrize('text', [
    '', '   \n', 'not json', '{"a": 1}', '[1]', 'null',
    variant(similarity=1.01), variant(similarity=-0.1), variant(similarity='0.5'), variant(similarity=True),
    variant(type='OTHER'), variant(original='<drop>'), variant(extra=1),
    variant(original={'addr': -1, 'name': 'f', 'size': 1}),
    variant(original={'addr': 2**64, 'name': 'f', 'size': 1}),
    variant(original={'addr': '1', 'name': 'f', 'size': 1}),
    variant(original={'addr': 1.0, 'name': 'f', 'size': 1}),
    variant(original={'addr': 1, 'name': 5, 'size': 1}),
    variant(original={'addr': 1, 'name': 'f'}),
    variant(original=None, modified=None),
    '[{"similarity": NaN, "type": "UNLIKE", "original": null, "modified": {"addr":1,"name":"f","size":1}}]',
    '[{"similarity": 0.5, "similarity": 0.6, "type": "PARTIAL", "original": null, "modified": null}]',
    FIXTURE.read_text() + 'trailing',
])
def test_malformed_output_rejected(text):
    with pytest.raises(SecondaryError):
        parse_output(text, '0.9.1', OLD, NEW)


def test_empty_array_is_valid_but_empty():
    assert parse_output('[]', '0.9.1', OLD, NEW).matches == ()


@pytest.mark.parametrize('text, expected', [
    ('rz-diff 0.9.1 @ linux-x86-64\ncommit: c3a90e92', ('0.9.1', (0, 9, 1))),
    ('rz-diff 0.10.0 @ windows-x86-64', ('0.10.0', (0, 10, 0))),
    ('rizin 0.9.1', None), ('', None),
])
def test_parse_version(text, expected):
    assert parse_version(text) == expected


def runner_returning(log, code=0, reason=None, seen=None):
    def run(argv, **kwargs):
        if seen is not None:
            seen.append((argv, kwargs))
        return ProcessResult(code, log, reason)
    return run


@pytest.mark.parametrize('log, code, supported, version', [
    ('rz-diff 0.9.1 @ linux-x86-64\n', 0, True, '0.9.1'),
    ('rz-diff 0.9.0 @ linux-x86-64\n', 0, True, '0.9.0'),
    ('rz-diff 0.8.2 @ linux-x86-64\n', 0, False, '0.8.2'),
    ('garbage', 0, False, None),
    ('rz-diff 0.9.1', 1, False, None),
])
def test_probe(log, code, supported, version):
    seen = []
    result = probe(Path('/opt/rz-diff'), {}, runner=runner_returning(log, code, seen=seen))
    assert (result.supported, result.version, result.supports_json) == (supported, version, supported)
    assert seen[0][0] == [str(Path('/opt/rz-diff')), '-v']  # platform path spelling


def test_probe_relative_path_is_unsupported():
    assert probe(Path('rz-diff'), dict(os.environ)).supported is False


def test_run_uses_argv_list_private_cwd_and_limits(tmp_path):
    older, newer = artifacts(tmp_path)
    seen = []
    result = run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
                        runner=runner_returning(FIXTURE.read_text(), seen=seen))
    argv, kwargs = seen[0]
    assert argv == ['/opt/rz-diff', '-C', '-j', '-t', 'functions', str(older.resolve()), str(newer.resolve())]
    assert kwargs['timeout_seconds'] == 1800 and kwargs['log_limit'] == 64 * 1024 * 1024 + 1
    assert kwargs['cwd'].name.startswith('patchtrace-rzdiff-') and not kwargs['cwd'].exists()
    assert len(result.matches) == 4


@pytest.mark.parametrize('timeout', [59, 86_401, 60.5, True])
def test_timeout_range(tmp_path, timeout):
    older, newer = artifacts(tmp_path)
    with pytest.raises(SecondaryError, match='timeout'):
        run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(), timeout_seconds=timeout,
                   runner=runner_returning('[]'))


def test_unsupported_capability_refused(tmp_path):
    older, newer = artifacts(tmp_path)
    bad = Capability(engine='rz-diff', supported=False, version='0.8.2', path='/x', supports_json=False,
                     reason='old')
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(bad, older, newer, OLD, NEW, env={}, cancel=threading.Event())
    assert info.value.code == 'PT-SECONDARY-UNSUPPORTED'


@pytest.mark.parametrize('log, code, reason, error', [
    ('', 0, None, 'PT-SECONDARY-INPUT'),
    ('ERROR: rz-diff: error, cannot open file', 1, None, 'PT-SECONDARY-RUN'),
    ('[]', 0, 'timeout', 'PT-SECONDARY-RUN'),
    ('[]', -1, 'cancelled', 'PT-SECONDARY-CANCEL'),
    ('x' * (64 * 1024 * 1024 + 1), 0, None, 'PT-SECONDARY-LIMIT'),
    ('[{"similarity":0.5,"type":"PARTIAL","original":null,"modified":{"addr":1,"name":"\ufffd","size":1}}]',
     0, None, 'PT-SECONDARY-INPUT'),
], ids=['empty', 'exit-1', 'timeout', 'cancelled', 'over-64MiB', 'invalid-utf8'])
# Explicit ids: pytest would otherwise build a 64 MiB test id from the oversized log and stall
# writing it to a Windows console.
def test_run_failures(tmp_path, log, code, reason, error):
    older, newer = artifacts(tmp_path)
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
                   runner=runner_returning(log, code, reason))
    assert info.value.code == error
    if code == 1:
        assert 'cannot open file' in info.value.message


def test_real_fake_executable_end_to_end(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, f'''
if sys.argv[1:] == ["-v"]:
    print("rz-diff 0.9.1 @ linux-x86-64")
    sys.exit(0)
assert sys.argv[1:5] == ["-C", "-j", "-t", "functions"], sys.argv
assert os.getcwd() != {str(tmp_path)!r}
sys.stdout.write(open({str(FIXTURE)!r}).read())
''')
    capability = probe(exe, dict(os.environ))
    assert capability.supported and capability.version == '0.9.1'
    result = run_rzdiff(capability, older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert len(result.matches) == 4


def test_fake_exit_zero_empty_stdout_is_error(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'sys.exit(0)')
    with pytest.raises(SecondaryError, match='no output'):
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())


def test_fake_cancel_kills_child(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'time.sleep(60)')
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=cancel)
    assert info.value.code == 'PT-SECONDARY-CANCEL'
    assert time.monotonic() - started < 10


def test_fake_timeout(tmp_path, monkeypatch):
    from patchtrace.secondary import rzdiff
    monkeypatch.setattr(rzdiff, 'TIMEOUT_RANGE', (1, 86_400))
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'time.sleep(60)')
    with pytest.raises(SecondaryError, match='timeout'):
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event(),
                   timeout_seconds=1)


def test_stderr_diagnostics_do_not_corrupt_json(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, f'''
sys.stderr.write("WARNING: rz-diff: symbol table missing\\n")
sys.stdout.write(open({str(FIXTURE)!r}).read())
sys.stderr.write("INFO: done\\n")
''')
    result = run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert len(result.matches) == 4


def test_nonzero_exit_reports_stderr_not_stdout(tmp_path):
    older, newer = artifacts(tmp_path)
    exe = fake(tmp_path, 'sys.stdout.write("partial"); sys.stderr.write("ERROR: cannot open file"); sys.exit(1)')
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert info.value.code == 'PT-SECONDARY-RUN' and 'cannot open file' in info.value.message


def test_run_requests_separate_streams(tmp_path):
    older, newer = artifacts(tmp_path)
    seen = []
    run_rzdiff(cap(), older, newer, OLD, NEW, env={}, cancel=threading.Event(),
               runner=runner_returning(FIXTURE.read_text(), seen=seen))
    assert seen[0][1]['separate_streams'] is True


@pytest.mark.parametrize('over', [{'type': ['COMPLETE']}, {'type': {'a': 1}}, {'similarity': 10 ** 400}],
                         ids=['type-array', 'type-object', 'huge-int'])
def test_malformed_entries_raise_structured_error(over):
    with pytest.raises(SecondaryError):
        parse_output(variant(**over), '0.9.1', OLD, NEW)


@pytest.mark.parametrize('text', [
    variant(original={'addr': 1, 'name': '\ud800', 'size': 1}),
    variant(original={'addr': 1, 'name': '\udfff', 'size': 1}),
    '[' * 20_000 + '0' + ']' * 20_000,
], ids=['high-surrogate', 'low-surrogate', 'excessive-depth'])
def test_hostile_json_never_escapes_as_an_unserializable_set(text):
    with pytest.raises(SecondaryError) as info:
        parse_output(text, '0.9.1', OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-INPUT'


def test_valid_unicode_name_round_trips_without_changing_evidence_hash():
    import hashlib

    text = accepted(original={'addr': 1, 'name': 'café_𝄞', 'size': 1})
    result = parse_output(text, '0.9.1', OLD, NEW)
    assert result.matches[0].older_name == 'café_𝄞'
    assert json.loads(result.model_dump_json())['matches'][0]['older_name'] == 'café_𝄞'
    assert result.file_sha256 == hashlib.sha256(text.encode('utf-8')).hexdigest()


@pytest.mark.parametrize('text', [' ' * 257, 'é' * 129], ids=['ascii-limit', 'utf8-byte-limit'])
def test_parser_entry_point_enforces_output_byte_limit(text, monkeypatch):
    from patchtrace.secondary import rzdiff

    monkeypatch.setattr(rzdiff, 'STDOUT_LIMIT', 256)
    with pytest.raises(SecondaryError) as info:
        parse_output(text, '0.9.1', OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-LIMIT'


@pytest.mark.parametrize('version', [
    '١.٩.١', '０.９.１', '9' * 5000 + '.0.0',
], ids=['arabic-digits', 'fullwidth-digits', 'oversized-component'])
def test_malformed_version_is_unsupported_without_raising(version):
    assert parse_version('rz-diff ' + version) is None
    result = probe(Path('/opt/rz-diff'), {}, runner=runner_returning('rz-diff ' + version))
    assert not result.supported
    assert result.version is None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def rows(*pairs) -> str:
    """Synthetic document from (original addr | None, modified addr | None) pairs."""
    side = lambda addr: None if addr is None else {'addr': addr, 'name': f'fcn.{addr}', 'size': 1}  # noqa: E731
    return json.dumps([{'similarity': 0.5, 'type': 'PARTIAL', 'original': side(o), 'modified': side(m)}
                       for o, m in pairs])


def test_singleton_fixture_is_the_retained_evidence():
    assert [s['id'] for s in REFUSED] == ['stock-elf-1-1', 'stock-elf-1-2', 'stock-elf-2-1',
                                          'stock-o-1-1', 'stock-o-1-2', 'stock-o-2-1']
    assert [s['id'] for s in PARSED] == ['stock-elf-2-2', 'corrected-elf-1-2', 'stock-o-2-2', 'corrected-o-1-2']
    for shape in SHAPES['shapes']:
        assert sha256_text(shape['stdout']) == shape['stdout_sha256'], shape['id']
    assert sha256_text(SHAPES['no_functions']['stderr']) == SHAPES['no_functions']['stderr_sha256']


def test_retained_one_to_two_output_reports_a_newer_function_as_original():
    """The defect itself: the newer-only helper (size 22) sits under `original`; the two-to-one output has the
    same structure, so nothing in the document says which of the two was swapped."""
    by_id = {s['id']: json.loads(s['stdout']) for s in SHAPES['shapes']}
    swapped, ordinary, corrected = by_id['stock-elf-1-2'], by_id['stock-elf-2-1'], by_id['corrected-elf-1-2']
    assert swapped[1]['original'] == {'name': 'sym.helper', 'addr': 4198419, 'size': 22}
    assert corrected[1]['modified'] == swapped[1]['original']
    shape = lambda doc: [(e['original']['addr'], e['modified']['addr']) for e in doc]  # noqa: E731
    assert shape(swapped) == shape(ordinary)


@pytest.mark.parametrize('shape', REFUSED, ids=[s['id'] for s in REFUSED])
def test_singleton_shape_is_refused_never_swapped(shape):
    with pytest.raises(SecondaryError) as info:
        parse_output(shape['stdout'], '0.9.1', OLD, NEW)
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-ORIENTATION', 'rzdiff-singleton-ownership')
    message = info.value.message
    assert 'not stored' in message and 'use another engine' in message and 'may be fine' in message
    assert '\n' not in message and len(message) <= 200  # the evidence view shows the first 200 characters


@pytest.mark.parametrize('shape', PARSED, ids=[s['id'] for s in PARSED])
def test_two_newer_functions_parse_byte_identically_to_main(shape):
    result = parse_output(shape['stdout'], '0.9.1', OLD, NEW)
    assert sha256_text(result.model_dump_json()) == shape['main_parse_sha256']
    assert result.file_sha256 == shape['stdout_sha256']
    document = json.loads(shape['stdout'])
    assert [(m.older_address, m.newer_address) for m in result.matches] == \
        [(e['original']['addr'], e['modified']['addr']) for e in document]


@pytest.mark.parametrize('text', [
    rows((1, None)), rows((1, None), (None, 2)), rows((1, 9), (2, 9), (3, None)), rows((None, 2)),
], ids=['older-only-rows', 'one-newer-only-row', 'many-to-one', 'single-newer-only'])
def test_at_most_one_distinct_newer_function_is_refused(text):
    """Synthetic boundary cases of the SPEC-11 section 9 condition."""
    with pytest.raises(SecondaryError) as info:
        parse_output(text, '0.9.1', OLD, NEW)
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-ORIENTATION', 'rzdiff-singleton-ownership')


@pytest.mark.parametrize('text, count', [
    (rows((1, 8), (None, 9)), 2), (rows((1, None), (None, 8), (None, 9)), 3), (rows((1, 8), (1, 9)), 2),
], ids=['matched-plus-newer-only', 'only-one-sided', 'one-older-two-newer'])
def test_two_distinct_newer_functions_are_accepted(text, count):
    assert len(parse_output(text, '0.9.1', OLD, NEW).matches) == count


def test_malformed_singleton_document_is_still_an_input_error():
    with pytest.raises(SecondaryError) as info:
        parse_output(variant(similarity=1.01), '0.9.1', OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-INPUT' and info.value.kind is None


# ---- SPEC-11 section 10: byte-exact stdout and the no-functions failure kind ----------------------------

def named(name: bytes) -> bytes:
    """Two-row document (so section 9 does not apply) whose first older name is the raw bytes `name`."""
    return (b'[{"similarity":0.5,"type":"PARTIAL","original":{"name":"' + name + b'","addr":1,"size":1},'
            b'"modified":{"name":"g","addr":2,"size":1}},' + json.dumps(SECOND).encode('ascii') + b']\r\n')


def bytes_runner(data: bytes, stderr: str = ''):
    """A runner as `jobs.run_process` answers: lossy text plus the exact captured bytes."""
    def run(argv, **kwargs):
        return ProcessResult(0, data.decode('utf-8', errors='replace'), None, stderr, log_bytes=data)
    return run


def test_valid_replacement_character_is_accepted(tmp_path):
    data = named('caf\u00e9_\ufffd'.encode('utf-8'))
    for result in (parse_output(data, '0.9.1', OLD, NEW),
                   run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(),
                              runner=bytes_runner(data))):
        assert result.matches[0].older_name == 'caf\u00e9_\ufffd'
        assert result.file_sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize('name, offset', [(b'ab\xffcd', 58), (b'ab\xe2\x82', 58), (b'\xed\xa0\x80', 56)],
                         ids=['stray-byte', 'truncated-sequence', 'encoded-surrogate'])
def test_invalid_utf8_bytes_are_rejected_with_offset(tmp_path, name, offset):
    data = named(name)
    assert data.index(name) + name.index(name.lstrip(b'ab')) == offset
    for call in (lambda: parse_output(data, '0.9.1', OLD, NEW),
                 lambda: run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(),
                                    runner=bytes_runner(data))):
        with pytest.raises(SecondaryError) as info:
            call()
        assert info.value.code == 'PT-SECONDARY-INPUT'
        assert info.value.message == f'rz-diff output is not valid UTF-8 at byte offset {offset}'


def test_digest_is_of_the_captured_bytes_not_of_the_lossy_text(tmp_path):
    data = named(b'f')
    assert data.endswith(b'\r\n')

    def runner(argv, **kwargs):  # the text differs from the bytes; only the bytes are evidence
        return ProcessResult(0, data.decode('ascii').strip(), None, log_bytes=data)

    result = run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(), runner=runner)
    assert result.file_sha256 == hashlib.sha256(data).hexdigest()


def test_byte_input_enforces_the_output_limit(monkeypatch):
    from patchtrace.secondary import rzdiff

    monkeypatch.setattr(rzdiff, 'STDOUT_LIMIT', 256)
    with pytest.raises(SecondaryError) as info:
        parse_output(b' ' * 257, '0.9.1', OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-LIMIT'


@pytest.mark.parametrize('stderr, side', [
    (SHAPES['no_functions']['stderr'], 'older'),  # retained native stderr
    ('ERROR: rz-diff: No functions found in file1.\n', 'newer'),  # synthetic: inferred from the same message
], ids=['file0-retained', 'file1-synthetic'])
def test_no_functions_is_classified(tmp_path, stderr, side):
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(),
                   runner=bytes_runner(b'', stderr))
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-INPUT', 'no-functions')
    assert f'reported no functions in the {side} file' in info.value.message
    assert 'use another engine' in info.value.message and len(info.value.message) <= 200


@pytest.mark.parametrize('stdout, stderr', [(b'', 'WARNING: something else\n'), (b'', '')],
                         ids=['other-stderr', 'silent'])
def test_empty_stdout_without_the_marker_stays_a_generic_input_error(tmp_path, stdout, stderr):
    with pytest.raises(SecondaryError, match='no output') as info:
        run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(),
                   runner=bytes_runner(stdout, stderr))
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-INPUT', None)


def test_marker_next_to_a_document_does_not_hide_the_document(tmp_path):
    result = run_rzdiff(cap(), *artifacts(tmp_path), OLD, NEW, env={}, cancel=threading.Event(),
                        runner=bytes_runner(named(b'f'), SHAPES['no_functions']['stderr']))
    assert len(result.matches) == 2


def test_real_fake_executable_bytes_end_to_end(tmp_path):
    """Through the real `jobs.run_process`: the child's exact bytes reach the parser and the digest."""
    older, newer = artifacts(tmp_path)
    data = named('\ufffd'.encode('utf-8'))
    exe = fake(tmp_path, f'sys.stdout.buffer.write({data!r})')
    result = run_rzdiff(cap(exe), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert result.matches[0].older_name == '\ufffd' and result.file_sha256 == hashlib.sha256(data).hexdigest()
    bad = fake(tmp_path / 'bad', f'sys.stdout.buffer.write({named(bytes([255]))!r})')
    with pytest.raises(SecondaryError, match='byte offset 56'):
        run_rzdiff(cap(bad), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    silent = fake(tmp_path / 'silent', f'sys.stderr.write({SHAPES["no_functions"]["stderr"]!r})')
    with pytest.raises(SecondaryError) as info:
        run_rzdiff(cap(silent), older, newer, OLD, NEW, env=dict(os.environ), cancel=threading.Event())
    assert info.value.kind == 'no-functions'
