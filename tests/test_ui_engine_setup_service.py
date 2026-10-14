"""Track G pure service tests (multi-engine-evidence-panel.md section 16): messages, pin status, probe,
BinExport validation, adapter reuse and run-registry selection. No Qt.

Evidence labels: probes run the FAKE `bindiff` launcher (tests/fake_bindiff.py, mocked); BinExport validation
runs the REAL C3 `accept_binexport` worker on the committed SYNTHETIC fixtures (tests/fixtures/binexport), which
is real acceptance code on synthetic input, never live-compatibility evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
import threading
from pathlib import Path

import pytest
from fake_bindiff import launcher_names, make_fake_bindiff, write_fake_binexport
from test_evidence_view import assert_no_banned

from patchtrace.sample import synthetic_pe
from patchtrace.secondary import bindiff_probe, cli_bindiff, scheduler
from patchtrace.secondary import evidence_panel_service as svc
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import REGISTRY, BinDiffAdapter

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'binexport'
OLDER = FIXTURES / 'synthetic-older.BinExport'
NEWER = FIXTURES / 'synthetic-newer.BinExport'
MD5_OLDER = FIXTURES / 'synthetic-older-md5id.BinExport'
OLD_SHA = hashlib.sha256(synthetic_pe(0)).hexdigest()
NEW_SHA = hashlib.sha256(synthetic_pe(1)).hexdigest()
C3_SLUGS = (  # SPEC-10b section 7 plus the build additions of section 15
    'protobuf_missing', 'protobuf_not_upb', 'protobuf_too_old', 'descriptor_mismatch', 'worker_unavailable',
    'unreadable', 'not_regular_file', 'empty_file', 'file_changed_during_read', 'lookalike_sqlite', 'lookalike_json',
    'lookalike_zip', 'lookalike_pe', 'lookalike_elf', 'lookalike_pdf', 'wire_malformed', 'wire_truncated',
    'group_wire_type', 'wire_type_mismatch', 'duplicate_singleton', 'unknown_fields_excess', 'parse_failed',
    'trailing_bytes', 'meta_missing', 'meta_field_empty', 'meta_field_invalid', 'callgraph_missing', 'callgraph_empty',
    'vertex_unsorted_or_duplicate', 'vertex_type_invalid', 'call_edge_incomplete', 'index_oob:operand',
    'range_invalid', 'block_empty', 'expression_cycle', 'expression_depth', 'self_parent', 'operand_arity',
    'entry_not_in_graph', 'edge_endpoint_not_in_graph', 'coverage_amplification', 'string_too_long',
    'string_total_bytes', 'utf8_invalid', 'section_wraps', 'md_index_invalid', 'executable_id_md5',
    'executable_id_empty', 'executable_id_other', 'executable_id_mismatch', 'identical_pair', 'same_file_twice',
    'address_basis_mixed', 'orientation_swapped', 'too_large', 'record_too_large', 'count_cap:vertex', 'memory_cap',
    'worker_timeout', 'worker_oom', 'worker_crash', 'worker_bad_result', 'cancelled', 'call_target_arity',
    'block_ranges_excess', 'flow_edge_incomplete', 'reference_incomplete', 'name_invalid')
C3_CODE = {'protobuf_missing': 'UNSUPPORTED', 'protobuf_not_upb': 'UNSUPPORTED', 'protobuf_too_old': 'UNSUPPORTED',
           'descriptor_mismatch': 'UNSUPPORTED', 'worker_unavailable': 'UNSUPPORTED', 'executable_id_mismatch': 'PAIR',
           'identical_pair': 'PAIR', 'same_file_twice': 'PAIR', 'address_basis_mixed': 'PAIR',
           'orientation_swapped': 'ORIENTATION', 'too_large': 'LIMIT', 'record_too_large': 'LIMIT',
           'count_cap:vertex': 'LIMIT', 'memory_cap': 'LIMIT', 'worker_timeout': 'RUN', 'worker_oom': 'RUN',
           'worker_crash': 'RUN', 'worker_bad_result': 'RUN', 'cancelled': 'CANCEL'}


@pytest.fixture(autouse=True)
def _probe_names(monkeypatch):
    bindiff_probe.clear_probe_cache()
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    monkeypatch.delenv('PATCHTRACE_BINDIFF', raising=False)
    yield
    bindiff_probe.clear_probe_cache()


@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    """Route tempfile into an empty folder so leftovers of a validation are visible."""
    folder = tmp_path / 'tmp'
    folder.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(folder))
    return folder


def request(older=OLDER, newer=NEWER, **kw) -> svc.ValidationRequest:
    return svc.ValidationRequest(Path(older), Path(newer), OLD_SHA, NEW_SHA, **kw)


def built_binexport(path: Path, sha: str, architecture: str | None = None) -> Path:
    from binexport_builder import raw, valid
    message = valid(sha)
    if architecture is not None:
        message.meta_information.architecture_name = architecture
    path.write_bytes(raw(message))
    return path


# ---- texts and pins ------------------------------------------------------------------------------------


def test_pin_constant_matches_the_pin_file():
    pin = json.loads((ROOT / 'tools' / 'bindiff_pin.json').read_text(encoding='utf-8'))
    assert pin['version_text'] == 'BinDiff ' + svc.PINNED_BINDIFF_VERSION


def test_every_fixed_text_is_plain_and_free_of_banned_words():
    texts = [*svc.PROBE_TEXT.values(), *svc.VALIDATION_TEXT.values(), *svc.PIN_NOTES.values(),
             *svc.SETUP_REASON.values(), svc.RUN_PREVIEW_BINDIFF, *svc.BINDING_TEXT.values()]
    for text in texts:
        assert text and '<' not in text and '>' not in text, text
        assert_no_banned(text)


def test_problem_messages_cover_every_kind_and_slug():
    kinds = {
        'binexport-orientation': ('ORIENTATION', 'swapped'), 'binexport-wrong-artifact': ('PAIR', 'different file'),
        'binexport-same-file': ('PAIR', 'same .BinExport'), 'binexport-arch-mismatch': ('PAIR', 'architectures'),
        'binexport-unbound': ('INPUT', 'does not record a SHA-256'), 'binexport-unsupported': (
            'UNSUPPORTED', 'not available in this build'), 'binexport-invalid': ('INPUT', 'not a valid BinExport2'),
        'binexport-too-large': ('LIMIT', '256 MiB'), 'identical-pair': ('PAIR', 'identical'),
        'workdir-error': ('RUN', 'working folder')}
    for kind, (code, phrase) in kinds.items():
        problem = svc.describe_problem(SecondaryError(f'PT-SECONDARY-{code}', 'x', kind=kind), 'older')
        assert phrase in problem.message, (kind, problem.message)
        assert f'Kind: {kind}' in problem.technical
        assert problem.unbound == (kind == 'binexport-unbound')
    for slug in C3_SLUGS:
        code = C3_CODE.get(slug, 'INPUT')
        problem = svc.describe_problem(SecondaryError(f'PT-SECONDARY-{code}', 'label 3', reason=slug), 'newer')
        assert problem.message and '{' not in problem.message, slug
        if '_' in slug or ':' in slug:  # machine slugs stay in the technical details only
            assert slug not in problem.message, slug
        assert f'Reason: {slug}' in problem.technical and 'Side: newer' in problem.technical
        assert_no_banned(problem.message)
        assert problem.unbound == (slug.startswith('executable_id_') and slug != 'executable_id_mismatch'), slug


@pytest.mark.parametrize('slug,phrase', [
    ('executable_id_md5', 'records only an MD5 hash'), ('executable_id_empty', 'records no hash'),
    ('executable_id_other', 'an id that is not a SHA-256'), ('lookalike_sqlite', 'SQLite database'),
    ('too_large', 'larger than the 256 MiB limit'), ('address_basis_mixed', 'Subtract Imagebase'),
    ('worker_crash', 'stopped unexpectedly'), ('worker_oom', 'more memory'), ('worker_timeout', 'time limit'),
    ('parse_failed', 'not a valid BinExport2 file'), ('protobuf_not_upb', 'not available in this build'),
])
def test_slug_phrases(slug, phrase):
    code = C3_CODE.get(slug, 'INPUT')
    assert phrase in svc.describe_problem(SecondaryError(f'PT-SECONDARY-{code}', 'x', reason=slug), 'older').message


def test_problem_never_shows_worker_stderr_or_paths():
    error = SecondaryError('PT-SECONDARY-RUN', 'BinExport worker failed (exit 1)', reason='worker_crash')
    error.diagnostics = 'Traceback /home/secret/token.py <b>boom</b>'
    problem = svc.describe_problem(error, 'older')
    for text in (problem.message, problem.technical):
        assert 'secret' not in text and 'Traceback' not in text and '<b>' not in text
    side_less = svc.describe_problem(SecondaryError('PT-SECONDARY-INPUT', 'The newer .BinExport does not record a '
                                                    'SHA-256', kind='binexport-unbound'))
    assert side_less.side == 'newer' and side_less.message.startswith('The newer .BinExport')


# ---- probe ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize('case', ['ok', 'v7', 'opt', 'nover', 'v9', 'v8b'])
def test_probe_states(tmp_path, case):
    setups = {'ok': ('ok', None), 'v7': ('ok', 'BinDiff 7 (@1)'), 'opt': ('missing-option', None),
              'nover': ('no-version', None), 'v9': ('ok', 'BinDiff 9 (@abc)'), 'v8b': ('ok', 'BinDiff 8 (@1, Jan 1 2026)')}
    mode, version = setups[case]
    exe = make_fake_bindiff(tmp_path / 'bd', mode, **({'version': version} if version else {}))
    view = svc.probe_bindiff(str(exe), threading.Event())
    expected = {'ok': (True, 'pinned', None), 'v7': (False, 'unsupported', 'unsupported-version'),
                'opt': (False, 'unsupported', 'missing-option'), 'nover': (False, 'unsupported', 'probe-failed'),
                'v9': (True, 'untested-newer', None), 'v8b': (True, 'tested', None)}[case]
    assert (view.supported, view.pin, view.kind) == expected
    assert str(tmp_path) not in view.message and str(tmp_path) not in view.technical
    assert_no_banned(view.message)
    if case == 'ok':
        assert view.message == ('Usable: BinDiff 8 (@568181968, Sep 25 2023). Version check: the BinDiff 8 build '
                                'PatchTrace was tested with.')
    elif case == 'v7':
        assert view.message == 'Not usable: BinDiff 7 (@1) is older than the supported version 8.'
    elif case == 'opt':
        assert '--logo' in view.message and view.message.startswith('Not usable: ')
    elif case == 'v9':
        assert 'newer than the tested BinDiff 8' in view.message and 'untested version' in view.message


def test_probe_never_runs_relative_or_empty_paths():
    def runner(*args, **kwargs):
        raise AssertionError('nothing may be executed')
    relative = svc.probe_bindiff('bindiff', threading.Event(), runner=runner)
    assert not relative.supported and relative.kind == 'not-found'
    empty = svc.probe_bindiff('   ', threading.Event(), runner=runner)
    assert not empty.supported and empty.kind == 'not-configured'
    assert empty.message.startswith('Not usable: BinDiff is not configured.')


# ---- validation with the REAL C3 acceptance (synthetic fixtures) ------------------------------------------


def test_validate_real_pair_ok(private_tmp):
    steps = []
    result = svc.validate_binexports(request(), threading.Event(), progress=steps.append)
    assert result.status == 'ok', result.problem
    assert steps == ['older', 'newer', 'pair']
    assert (result.older.functions, result.newer.functions) == (3, 4)
    assert result.older.architecture == 'x86-64' and result.older.id_binding == 'sha256'
    assert result.binding == 'sha256' and result.key == request().key
    assert result.message.splitlines() == [
        svc.VALIDATION_TEXT['ok'],
        'Older: 3 functions, architecture x86-64, executable id SHA-256, matches the older file.',
        'Newer: 4 functions, architecture x86-64, executable id SHA-256, matches the newer file.']
    assert list(private_tmp.iterdir()) == []  # snapshots are private and removed


def test_validate_real_swapped(private_tmp):
    result = svc.validate_binexports(request(NEWER, OLDER), threading.Event())
    assert result.status == 'failed' and result.problem.kind == 'binexport-orientation'
    assert result.message == 'Not accepted: ' + result.problem.message and 'swapped' in result.message
    assert list(private_tmp.iterdir()) == []


def test_validate_real_foreign_sha256(tmp_path, private_tmp):
    foreign = built_binexport(tmp_path / 'foreign.BinExport', 'c' * 64)
    result = svc.validate_binexports(request(foreign, NEWER), threading.Event())
    assert result.status == 'failed' and result.problem.reason == 'executable_id_mismatch'
    assert "different file than this project's older file" in result.problem.message
    assert not result.problem.unbound


def test_validate_real_unbound_then_override(private_tmp):
    refused = svc.validate_binexports(request(MD5_OLDER, NEWER), threading.Event())
    assert refused.status == 'failed' and refused.problem.unbound
    assert refused.problem.reason == 'executable_id_md5' and 'only an MD5 hash' in refused.problem.message
    accepted = svc.validate_binexports(request(MD5_OLDER, NEWER, accept_unbound=True), threading.Event())
    assert accepted.status == 'ok', accepted.problem
    assert accepted.older.id_binding == 'md5' and accepted.binding == 'asserted:older=md5,newer=sha256'
    assert accepted.message.splitlines()[0] == svc.VALIDATION_TEXT['ok-asserted']
    assert 'MD5 only, accepted on your confirmation (not checked)' in accepted.message
    assert accepted.key != refused.key


def test_validate_same_file_before_any_worker(tmp_path, private_tmp):
    calls = []

    def factory(directory):
        calls.append(directory)
        return None
    copy = tmp_path / 'copy.BinExport'
    copy.write_bytes(OLDER.read_bytes())
    for older, newer in ((OLDER, OLDER), (OLDER, copy)):
        result = svc.validate_binexports(request(older, newer), threading.Event(), acceptor_factory=factory)
        assert result.status == 'failed' and result.problem.kind == 'binexport-same-file', result.problem
        assert 'same .BinExport was chosen for both sides' in result.problem.message
    assert calls == []


def test_validate_real_oversized(tmp_path, private_tmp):
    big = tmp_path / 'big.BinExport'
    with open(big, 'wb') as handle:
        handle.truncate(256 * 1024 * 1024 + 1)  # sparse where supported; never read (size check first)
    result = svc.validate_binexports(request(big, NEWER), threading.Event())
    assert result.status == 'failed' and result.problem.reason == 'too_large'
    assert result.problem.message == 'The older .BinExport is larger than the 256 MiB limit.'


def test_validate_real_architecture_mismatch(tmp_path, private_tmp):
    newer = built_binexport(tmp_path / 'arm.BinExport', NEW_SHA, 'AARCH64-64')
    result = svc.validate_binexports(request(OLDER, newer), threading.Event())
    assert result.status == 'failed' and result.problem.kind == 'binexport-arch-mismatch', result.problem


def test_validate_cancelled_before_start_runs_nothing(private_tmp):
    cancel = threading.Event()
    cancel.set()
    calls = []
    result = svc.validate_binexports(request(), cancel, acceptor_factory=lambda d: calls.append(d))
    assert result.status == 'cancelled' and calls == [] and result.message == svc.VALIDATION_TEXT['cancelled']


def test_validate_without_binexport_runtime_is_unsupported(private_tmp):
    result = svc.validate_binexports(request(), threading.Event(), acceptor_factory=lambda d: None)
    assert result.status == 'failed' and result.problem.kind == 'binexport-unsupported'


def test_validate_unexpected_error_reports_class_only(private_tmp):
    def factory(directory):
        def accept(*a, **k):
            raise RuntimeError('secret-token /home/x')
        return accept
    result = svc.validate_binexports(request(), threading.Event(), acceptor_factory=factory)
    assert result.status == 'failed' and 'RuntimeError' in result.message and 'secret' not in result.message


# ---- capability, adapter reuse, run registry -------------------------------------------------------------


def probe_view(supported=True, version='8 (@568181968, Sep 25 2023)', reason=None):
    cap = Capability(engine='bindiff', supported=supported, version=version, path='/x/bindiff', supports_json=False,
                     reason=reason)
    return svc.probe_view('/x/bindiff', bindiff_probe.ProbeReport(cap, None if supported else 'not-found', 8))


def test_setup_capability_states():
    key = request().key
    assert svc.setup_capability(None, None, key) is None
    bad = probe_view(False, None, 'PT-SECONDARY-UNSUPPORTED: nope')
    assert svc.setup_capability(bad, None, key) == bad.capability
    good = probe_view()
    waiting = svc.setup_capability(good, None, key)
    assert not waiting.supported and waiting.reason == ('PT-SECONDARY-UNSUPPORTED: BinDiff 8 (@568181968, Sep 25 '
                                                        '2023) is usable; choose and validate both .BinExport files '
                                                        'in BinDiff setup.')
    failed = svc.BinExportValidation('failed', key, problem=svc.describe_problem(
        SecondaryError('PT-SECONDARY-ORIENTATION', 'x', kind='binexport-orientation'), 'older'))
    rejected = svc.setup_capability(good, failed, key)
    assert not rejected.supported and 'were not accepted: The two .BinExport files are swapped' in rejected.reason
    ok = svc.BinExportValidation('ok', key, binding='sha256')
    assert svc.setup_capability(good, ok, key).supported
    assert not svc.setup_capability(good, ok, request(accept_unbound=True).key).supported  # stale validation


def test_bindiff_adapter_is_the_cli_construction(tmp_path, monkeypatch):
    seen = []

    def factory(raw_dir):
        seen.append(raw_dir)
        return 'acceptor'
    monkeypatch.setattr(cli_bindiff, 'c3_acceptor', factory)
    monkeypatch.setenv('PATCHTRACE_BINDIFF', str(tmp_path / 'from-env' / 'bindiff'))  # the GUI field alone counts
    setup = svc.BinDiffSetup(str(tmp_path / 'bd' / 'bindiff'), OLDER, NEWER, accept_unbound=True)
    adapter = svc.bindiff_adapter(setup, tmp_path / 'raw')
    namespace = argparse.Namespace(bindiff=setup.executable, older_binexport=OLDER, newer_binexport=NEWER,
                                   accept_unbound_binexport=True)
    cli = cli_bindiff.adapter_from_args(namespace, tmp_path / 'raw', environ={})
    assert isinstance(adapter, BinDiffAdapter)
    fields = ('executable', 'older', 'newer', 'raw_dir', 'accept_unbound', 'acceptor')
    assert [getattr(adapter, f) for f in fields] == [getattr(cli, f) for f in fields]
    assert adapter.executable == str(tmp_path / 'bd' / 'bindiff') and seen == [tmp_path / 'raw'] * 2


def test_run_request_needs_raw_dir_for_bindiff(tmp_path):
    base = dict(project_id='p', revision=0, generation=1, engines=('bindiff',), max_parallel=1, timeout_s=60,
                older_path=tmp_path, newer_path=tmp_path, older_sha256=OLD_SHA, newer_sha256=NEW_SHA)
    setup = svc.BinDiffSetup('/x/bindiff', OLDER, NEWER)
    with pytest.raises(ValueError):
        svc.RunRequest(**base, bindiff=setup)
    assert svc.RunRequest(**base, bindiff=setup, bindiff_raw_dir=tmp_path).bindiff == setup
    assert svc.RunRequest(**base).bindiff is None  # C6 shape unchanged


def test_execute_run_registry_selection(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(scheduler, 'run_engines', lambda *a, **k: seen.append(k['registry']) or ())
    base = dict(project_id='p', revision=0, generation=1, max_parallel=1, timeout_s=60, older_path=tmp_path,
                newer_path=tmp_path, older_sha256=OLD_SHA, newer_sha256=NEW_SHA)
    setup = svc.BinDiffSetup(str(tmp_path / 'bindiff'), OLDER, NEWER)
    svc.execute_run(svc.RunRequest(**base, engines=('rz-diff',)), threading.Event(), env={})
    svc.execute_run(svc.RunRequest(**base, engines=('rz-diff',), bindiff=setup, bindiff_raw_dir=tmp_path),
                    threading.Event(), env={})
    svc.execute_run(svc.RunRequest(**base, engines=('bindiff',), bindiff=setup, bindiff_raw_dir=tmp_path),
                    threading.Event(), env={})
    custom = {'bindiff': object()}
    svc.execute_run(svc.RunRequest(**base, engines=('bindiff',), bindiff=setup, bindiff_raw_dir=tmp_path),
                    threading.Event(), env={}, registry=custom)
    assert seen[0] is REGISTRY and seen[1] is REGISTRY and seen[3] is custom
    assert isinstance(seen[2]['bindiff'], BinDiffAdapter) and seen[2]['bindiff'].executable == setup.executable
    assert seen[2]['bindiff'].raw_dir == tmp_path


def fake_acceptor_factory(private_dir: Path):
    """C3 stand-in for FAKE-BINEXPORT text inputs (the fake `bindiff` cannot read protobuf). Mocked."""
    from types import SimpleNamespace

    def accept(path, *, artifact_sha256, role, accept_unbound, cancel, other_sha256=None):
        data = Path(path).read_bytes()
        ident = data.split(b'\n', 1)[0].split()[1].decode()
        kind = 'sha256' if re.fullmatch('[0-9a-f]{64}', ident) else 'md5'
        if kind != 'sha256' and not accept_unbound:
            raise SecondaryError('PT-SECONDARY-INPUT', 'x', reason=f'executable_id_{kind}')
        summary = SimpleNamespace(file_sha256=hashlib.sha256(data).hexdigest(), executable_id=ident, id_binding=kind,
                                  architecture_name='x86-64', function_addresses=(1, 2), address_basis='unknown',
                                  warnings=())
        return SimpleNamespace(snapshot_path=Path(path), summary=summary)
    return accept


def test_execute_run_with_setup_runs_fake_bindiff_end_to_end(tmp_path):
    exe = make_fake_bindiff(tmp_path / 'bd')
    older = write_fake_binexport(tmp_path / 'older.BinExport', OLD_SHA)
    newer = write_fake_binexport(tmp_path / 'newer.BinExport', NEW_SHA)
    run = svc.RunRequest('p', 0, 1, ('bindiff',), 1, 60, tmp_path / 'o', tmp_path / 'n', OLD_SHA, NEW_SHA,
                         bindiff=svc.BinDiffSetup(str(exe), older, newer), bindiff_raw_dir=tmp_path / 'raw')
    [outcome] = svc.execute_run(run, threading.Event(), env={}, acceptor_factory=fake_acceptor_factory)
    assert outcome.run.status == 'ok', outcome.error
    assert outcome.run.provenance['binexport_binding'] == 'sha256'
    assert len(list((tmp_path / 'raw').glob('bindiff-*.BinDiff'))) == 1
