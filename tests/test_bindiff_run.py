"""SPEC-29 §4-§6, §9.1: BinDiff execution through the registry adapter and scheduler with fake executables.

Mocked evidence only (fake `bindiff`, fake BinExport inputs); the live job is separate (§9.4/§10).
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest
from fake_bindiff import launcher_names, make_fake_bindiff, spy_calls
from liveness_support import heartbeat_stopped
from test_bindiff_inputs import Accepted, Summary, accepted

from patchtrace.jobs import run_process
from patchtrace.secondary import bindiff_probe, bindiff_run
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import BinDiffAdapter
from patchtrace.secondary.runs import sanitize_stderr
from patchtrace.secondary.scheduler import ProjectRef, run_engines

OLD, NEW = 'a' * 64, 'b' * 64
SECRETS = {'AWS_SECRET_ACCESS_KEY': 'sentinel-secret', 'JAVA_TOOL_OPTIONS': '-javaagent:evil.jar',
           'LD_PRELOAD': '/evil.so', 'HTTPS_PROXY': 'http://proxy', 'GITHUB_TOKEN': 'ghp_sentinel',
           'FLAGS_ui': 'true', 'FLAGS_flagfile': '/evil/flags', 'FLAGS_output_dir': '/evil'}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    bindiff_probe.clear_probe_cache()
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    yield
    bindiff_probe.clear_probe_cache()


def project(tmp_path: Path) -> ProjectRef:
    older, newer = tmp_path / 'old.sys', tmp_path / 'new.sys'
    older.write_bytes(b'MZ old')
    newer.write_bytes(b'MZ new')
    return ProjectRef(older, newer, OLD, NEW)


def go(tmp_path: Path, mode: str = 'ok', *, older_id: str = OLD, newer_id: str = NEW, timeout: float = 60.0,
       cancel: threading.Event | None = None, older_name: str = 'o', **adapter_kwargs):
    inputs = tmp_path / 'inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    exe = make_fake_bindiff(tmp_path / 'bd', mode)
    adapter = BinDiffAdapter(exe, older=accepted(inputs, older_name, older_id), newer=accepted(inputs, 'n', newer_id),
                             raw_dir=tmp_path / 'raw' / 'secondary', **adapter_kwargs)
    (out,) = run_engines(project(tmp_path), ['bindiff'], cancel=cancel or threading.Event(), env={},
                         registry={'bindiff': adapter}, per_engine_timeout={'bindiff': timeout})
    return out, adapter


def run_calls(tmp_path: Path) -> list[dict]:
    return [c for c in spy_calls(tmp_path / 'bd') if c['argv'] not in (['--version'], ['--nologo', '--help'])]


def test_ok_run_end_to_end(tmp_path):
    out, adapter = go(tmp_path)
    assert out.run.status == 'ok' and out.error is None and len(out.match_set.matches) == 2
    assert out.match_set.contract == 'secondary/2' and out.match_set.run_id == out.run.run_id
    (call,) = run_calls(tmp_path)
    workdir = Path(call['cwd']).parent
    assert call['argv'] == ['--nologo', '--output_format=bin', f'--output_dir={workdir / "out"}',
                            f'--config={workdir / "bindiff.json"}', f'--primary={workdir / "in" / "older.BinExport"}',
                            f'--secondary={workdir / "in" / "newer.BinExport"}']
    assert not any(a.split('=')[0] in bindiff_run.FORBIDDEN_FLAGS for a in call['argv'])
    assert call['config'] == '{}'  # exactly the two bytes, no BOM: resets user and machine config (§4.1)
    assert Path(call['cwd']).name == 'cwd' and workdir.name.startswith('patchtrace-bindiff-')
    expected_env = bindiff_probe.build_env(Path(adapter._report.capability.path), workdir)
    if os.name == 'nt':
        # Windows reports environment variable names upper-cased (SystemRoot -> SYSTEMROOT); names are case-insensitive.
        assert {k.upper() for k in expected_env} <= {k.upper() for k in call['env']}
    else:
        assert call['env'] == expected_env
    assert not set(SECRETS) & set(call['env'])
    assert not workdir.exists()  # private workdir removed
    kept = tmp_path / 'raw' / 'secondary' / f'bindiff-{out.match_set.file_sha256}.BinDiff'
    assert kept.is_file() and bindiff_run.sha256_file(kept) == out.run.output_sha256
    prov = out.run.provenance
    assert prov['binexport_binding'] == 'sha256' and prov['config_sha256'] == bindiff_run.CONFIG_SHA256
    assert prov['older_binexport_sha256'] == adapter._pair.older.file_sha256
    assert 'matched=2' in prov['bindiff_summary'] and 'failure_kind' not in prov


def test_argv_allowlist_rejects_forbidden_unknown_and_positional_arguments(tmp_path):
    argv = bindiff_run.build_argv('/opt/bindiff/bin/bindiff', tmp_path)
    assert bindiff_run.check_argv(argv) == argv
    for flag in ('--flagfile', '--fromenv', '--tryfromenv', '--undefok', '--ui', '--export', '--ls', '--md_index',
                 '--print_config', '--helpfull', '--version', '--help'):
        assert flag in bindiff_run.FORBIDDEN_FLAGS
        for bad in (flag, f'{flag}=x'):
            with pytest.raises(ValueError, match='not allowed'):
                bindiff_run.check_argv([*argv, bad])
    for bad in ('--output_format=log', '--secondary_dir=x', 'positional.BinExport', '-v', '--nologo=false'):
        with pytest.raises(ValueError, match='not allowed'):
            bindiff_run.check_argv([*argv, bad])


def test_run_executes_the_resolved_executable_path(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    real = make_fake_bindiff(tmp_path / 'bd')
    link = tmp_path / 'links' / real.name
    link.parent.mkdir()
    try:
        link.symlink_to(real)
        selected = link
    except (OSError, NotImplementedError):  # no symlink privilege: the selected path is the real file
        selected = real
    calls: list = []

    def recording(argv, **kwargs):
        calls.append(list(argv))
        return run_process(argv, **kwargs)

    adapter = BinDiffAdapter(selected, older=accepted(inputs, 'o', OLD), newer=accepted(inputs, 'n', NEW),
                             raw_dir=tmp_path / 'raw', probe_runner=recording)
    (out,) = run_engines(project(tmp_path), ['bindiff'], cancel=threading.Event(), env={},
                         registry={'bindiff': adapter}, runner=recording)
    assert out.run.status == 'ok' and len(calls) == 3  # --version, --help, the diff
    assert {c[0] for c in calls} == {str(real.resolve())}


def test_cache_key_depends_on_binexport_hashes(tmp_path):
    first, _ = go(tmp_path / 'a')
    second, _ = go(tmp_path / 'b', older_name='o2')
    again, _ = go(tmp_path / 'c')
    assert first.run.argv_digest == second.run.argv_digest == again.run.argv_digest
    assert first.run.cache_key == again.run.cache_key  # same inputs, same key (workdir is a placeholder)
    # Different BinExport bytes for the same artifact pair -> different cache key.
    assert first.run.cache_key != second.run.cache_key


@pytest.mark.parametrize('mode, code, kind', [
    ('exit-1-error', 'PT-SECONDARY-RUN', 'nonzero-exit'),
    ('exit-0-no-file', 'PT-SECONDARY-RUN', 'output-missing'),
    ('two-files', 'PT-SECONDARY-RUN', 'output-ambiguous'),
    ('wrong-name', 'PT-SECONDARY-RUN', 'output-ambiguous'),
    ('zero-size', 'PT-SECONDARY-INPUT', 'output-invalid'),
    ('wrong-hashes', 'PT-SECONDARY-PAIR', 'output-pair-mismatch'),
    ('reversed-hashes', 'PT-SECONDARY-ORIENTATION', 'output-pair-mismatch'),
    ('trigger-in-db', 'PT-SECONDARY-INPUT', 'output-invalid'),
    ('claims-matches-empty-db', 'PT-SECONDARY-INPUT', 'output-invalid'),
])
def test_failure_kinds(tmp_path, mode, code, kind):
    out, _ = go(tmp_path, mode)
    assert out.run.status == 'failed' and out.run.error_code == code
    assert out.error.kind == kind and out.run.provenance['failure_kind'] == kind
    assert str(tmp_path) not in out.error.message and '/secret' not in out.error.message
    assert not Path(run_calls(tmp_path)[0]['cwd']).parent.exists()  # private workdir removed on failure too


def test_nonzero_exit_message_is_one_sanitized_line(tmp_path):
    out, _ = go(tmp_path, 'exit-1-error')
    assert 'Error: could not load older.BinExport' in out.error.message and '\x1b' not in out.error.message
    assert '/secret/home' not in out.error.message


def test_symlink_output_is_ambiguous(tmp_path):
    probe_link = tmp_path / 'probe-link'
    try:
        probe_link.symlink_to(tmp_path)
    except (OSError, NotImplementedError):
        out, _ = go(tmp_path, 'two-files')  # no symlink privilege: the ambiguous-output path is still covered
        assert out.error.kind == 'output-ambiguous'
        return
    out, _ = go(tmp_path, 'symlink-output')
    assert out.run.status == 'failed' and out.error.kind == 'output-ambiguous'
    assert not list(tmp_path.joinpath('raw').rglob('*.BinDiff'))  # nothing preserved from a rejected output


def test_zero_matches_is_ok_not_error(tmp_path):
    out, _ = go(tmp_path, 'empty')
    assert out.run.status == 'ok' and out.match_set.matches == ()


def test_stderr_flood_and_writes_outside_out_do_not_break_result(tmp_path):
    out, _ = go(tmp_path / 'f', 'stderr-flood')
    assert out.run.status == 'ok' and len(out.run.stderr_tail) <= 64 * 1024
    stray, _ = go(tmp_path / 's', 'writes-outside-out')
    assert stray.run.status == 'ok'
    assert not Path(run_calls(tmp_path / 's')[0]['cwd']).exists()


def test_output_limit(tmp_path):
    out, _ = go(tmp_path, 'huge-output', output_limit=1024 * 1024)
    assert (out.run.status, out.run.error_code, out.error.kind) == ('failed', 'PT-SECONDARY-LIMIT', 'output-limit')


def test_timeout_kills_tree_and_records_kind(tmp_path):
    started = time.monotonic()
    out, _ = go(tmp_path, 'spawn-grandchild', timeout=3.0)
    assert out.run.status == 'timeout' and out.run.provenance['failure_kind'] == 'timeout'
    assert time.monotonic() - started < 60
    beat = tmp_path / 'bd' / 'heartbeat.txt'
    assert beat.exists(), 'grandchild never started within the timeout'     # else "stopped growing" is vacuous
    assert heartbeat_stopped(beat, settle=0.6)                             # grandchild is dead: heartbeat stopped


def test_cancel_stops_run(tmp_path):
    cancel = threading.Event()
    threading.Timer(2.0, cancel.set).start()
    out, _ = go(tmp_path, 'hang', cancel=cancel)
    assert out.run.status == 'cancelled' and out.run.error_code == 'PT-SECONDARY-CANCEL'
    assert not (tmp_path / 'raw').exists() or not list((tmp_path / 'raw').rglob('*.BinDiff'))


def test_reversed_binexports_rejected_before_spawn(tmp_path):
    out, _ = go(tmp_path, older_id=NEW, newer_id=OLD)
    assert out.run.status == 'failed' and out.run.error_code == 'PT-SECONDARY-ORIENTATION'
    assert out.run.provenance['failure_kind'] == 'binexport-orientation'
    assert run_calls(tmp_path) == []


def test_unbound_refused_then_explicit_override_recorded(tmp_path):
    refused, _ = go(tmp_path / 'r', older_id='1' * 32)
    assert refused.run.error_code == 'PT-SECONDARY-INPUT' and refused.error.kind == 'binexport-unbound'
    assert run_calls(tmp_path / 'r') == []
    allowed, _ = go(tmp_path / 'a', older_id='1' * 32, accept_unbound=True)
    assert allowed.run.status == 'ok' and len(allowed.match_set.matches) == 2
    assert (allowed.match_set.older_sha256, allowed.match_set.newer_sha256) == (OLD, NEW)
    assert allowed.run.provenance['binexport_binding'] == 'asserted:older=md5,newer=sha256'


def test_input_changed_after_validation_is_workdir_error(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    good = accepted(inputs, 'o', OLD)
    tampered = Accepted(good.snapshot_path, Summary('f' * 64, OLD, 'sha256'))  # recorded hash != bytes
    adapter = BinDiffAdapter(make_fake_bindiff(tmp_path / 'bd'), older=tampered, newer=accepted(inputs, 'n', NEW),
                             raw_dir=tmp_path / 'raw')
    (out,) = run_engines(project(tmp_path), ['bindiff'], cancel=threading.Event(), env={},
                         registry={'bindiff': adapter})
    assert out.run.error_code == 'PT-SECONDARY-RUN' and out.error.kind == 'workdir-error'
    assert run_calls(tmp_path) == []


def test_unsupported_probe_and_missing_inputs(tmp_path):
    out, _ = go(tmp_path / 'v', 'missing-option')
    assert out.run.status == 'unsupported' and out.run.provenance['failure_kind'] == 'missing-option'
    adapter = BinDiffAdapter(make_fake_bindiff(tmp_path / 'm'))
    (missing,) = run_engines(project(tmp_path), ['bindiff'], cancel=threading.Event(), env={},
                             registry={'bindiff': adapter})
    assert missing.run.status == 'unsupported' and missing.run.provenance['failure_kind'] == 'binexport-missing'


def test_paths_without_acceptor_are_unsupported_not_guessed(tmp_path):
    adapter = BinDiffAdapter(make_fake_bindiff(tmp_path / 'bd'), older=tmp_path / 'o.BinExport',
                             newer=tmp_path / 'n.BinExport', raw_dir=tmp_path / 'raw')
    (out,) = run_engines(project(tmp_path), ['bindiff'], cancel=threading.Event(), env={},
                         registry={'bindiff': adapter})
    assert out.run.status == 'unsupported' and out.error.kind == 'binexport-unsupported'


def test_spawn_failure_is_contained_failure(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    cap = Capability(engine='bindiff', supported=True, version='8', path=str(tmp_path / 'bindiff'), supports_json=False)
    from patchtrace.secondary.bindiff_inputs import bind_pair
    pair = bind_pair(accepted(inputs, 'o', OLD), accepted(inputs, 'n', NEW), OLD, NEW)

    def refuse(*args, **kwargs):
        raise RuntimeError('PT-BACKEND: containment failed')

    with pytest.raises(SecondaryError) as info:
        bindiff_run.execute(cap, pair, tmp_path / 'raw', cancel=threading.Event(), timeout_seconds=5, runner=refuse,
                            parent_dir=tmp_path)
    assert info.value.kind == 'spawn-failed' and not list(tmp_path.glob('patchtrace-bindiff-*'))


def test_standalone_run_bindiff_and_timeout_validation(tmp_path):
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    from patchtrace.secondary.bindiff_inputs import bind_pair
    pair = bind_pair(accepted(inputs, 'o', OLD), accepted(inputs, 'n', NEW), OLD, NEW)
    cap = bindiff_probe.probe(make_fake_bindiff(tmp_path / 'bd'))
    result = bindiff_run.run_bindiff(cap, pair, tmp_path / 'raw', OLD, NEW, cancel=threading.Event(),
                                     timeout_seconds=60)
    assert len(result.match_set.matches) == 2 and result.version_consistent
    for bad in (59, 86_401, True, 60.5):
        with pytest.raises(SecondaryError):
            bindiff_run.validate_timeout(bad)


@pytest.mark.parametrize('text, expected', [
    ('matched: 2 of 3/3 (primary/secondary, 3/3 non-library)\nSimilarity: 81.2% (Confidence: 95.0%)\n',
     {'matched': '2', 'primary_functions': '3', 'secondary_functions': '3', 'similarity': '81.2',
      'confidence': '95.0'}),
    ('nothing here', {}),
    ('matched: 99999999999 of 1/1', {}),
])
def test_parse_summary(text, expected):
    assert bindiff_run.parse_summary(text) == expected


def test_out_guard(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    assert bindiff_run.out_guard(out) is None
    for index in range(5):
        (out / f'{index}.x').write_bytes(b'x')
    assert bindiff_run.out_guard(out) == 'output-limit'
    other = tmp_path / 'o2'
    other.mkdir()
    (other / 'big').write_bytes(b'x' * 100)
    assert bindiff_run.out_guard(other, max_bytes=50) == 'output-limit'
    (other / 'sub').mkdir()
    assert bindiff_run.out_guard(other) == 'output-unexpected'


def test_transient_journal_is_tolerated_while_running(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    (out / bindiff_run.EXPECTED_NAME).write_bytes(b'SQLite format 3\x00')
    (out / f'{bindiff_run.EXPECTED_NAME}-journal').write_bytes(b'\xd9\xd5\x05\xf9')
    assert bindiff_run.out_guard(out) is None
    ok, _ = go(tmp_path / 'run', 'journal-transient')
    assert ok.run.status == 'ok' and len(ok.match_set.matches) == 2


def test_journal_left_after_exit_0_is_ambiguous(tmp_path):
    out, _ = go(tmp_path, 'journal-left')
    assert out.run.status == 'failed' and out.error.kind == 'output-ambiguous'
    assert not list((tmp_path / 'raw').rglob('*.BinDiff'))


def test_exit_0_with_usage_text_is_output_missing(tmp_path):
    out, _ = go(tmp_path, 'usage-exit-0')
    assert out.run.status == 'failed' and out.error.kind == 'output-missing'
    assert 'usage text' in out.error.message


def _spy_import(monkeypatch) -> list:
    calls: list = []
    real = bindiff_run.import_bindiff

    def spy(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(bindiff_run, 'import_bindiff', spy)
    return calls


def _cancel_when_partial_output_appears(spy_dir: Path, cancel: threading.Event, seen: list) -> threading.Thread:
    def watch():
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not cancel.is_set():
            runs = [c for c in spy_calls(spy_dir) if c['argv'] not in (['--version'], ['--nologo', '--help'])]
            if runs:
                out = Path(runs[0]['cwd']).parent / 'out'
                names = sorted(p.name for p in out.iterdir()) if out.is_dir() else []
                # one listing decides both the condition and the evidence (a second listing raced the journal's removal)
                if bindiff_run.EXPECTED_NAME in names and f'{bindiff_run.EXPECTED_NAME}-journal' in names:
                    seen.append(names)
                    cancel.set()
                    return
            time.sleep(0.02)
    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread


def test_cancel_after_partial_output_discards_it_unread(tmp_path, monkeypatch):
    imported = _spy_import(monkeypatch)
    cancel, seen = threading.Event(), []
    watcher = _cancel_when_partial_output_appears(tmp_path / 'bd', cancel, seen)
    out, _ = go(tmp_path, 'partial-then-hang', cancel=cancel)
    watcher.join(5)
    assert seen and seen[0] == [bindiff_run.EXPECTED_NAME, f'{bindiff_run.EXPECTED_NAME}-journal']
    assert out.run.status == 'cancelled' and out.match_set is None and out.run.output_sha256 is None
    assert imported == [] and not list(tmp_path.joinpath('raw').rglob('*.BinDiff'))
    assert not Path(run_calls(tmp_path)[0]['cwd']).parent.exists()


def test_timeout_after_partial_output_discards_it_unread(tmp_path, monkeypatch):
    imported = _spy_import(monkeypatch)
    out, _ = go(tmp_path, 'partial-then-hang', timeout=3.0)
    assert out.run.status == 'timeout' and out.match_set is None
    assert imported == [] and not list(tmp_path.joinpath('raw').rglob('*.BinDiff'))
    assert not Path(run_calls(tmp_path)[0]['cwd']).parent.exists()


def test_abnormal_exit_after_partial_output_discards_it_unread(tmp_path, monkeypatch):
    imported = _spy_import(monkeypatch)
    out, _ = go(tmp_path, 'partial-then-kill')
    assert out.run.status == 'failed' and out.error.kind == 'nonzero-exit' and out.match_set is None
    if os.name != 'nt':
        assert 'signal 9' in out.error.message
    assert imported == [] and not list(tmp_path.joinpath('raw').rglob('*.BinDiff'))
    assert not Path(run_calls(tmp_path)[0]['cwd']).parent.exists()


def test_output_path_over_250_characters_fails_closed_before_spawn(tmp_path):
    # <workdir>/out/older_vs_newer.BinDiff adds 27 characters to the workdir path; BinDiff's cap is 250.
    assert bindiff_run.output_path_fits(Path('/tmp/patchtrace-bindiff-x'))
    assert bindiff_run.output_path_fits(Path('/' + 'd' * 222))
    assert not bindiff_run.output_path_fits(Path('/' + 'd' * 223))
    assert not bindiff_run.output_path_fits(Path('/' + 'é' * 120))  # measured in encoded bytes
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    from patchtrace.secondary.bindiff_inputs import bind_pair
    pair = bind_pair(accepted(inputs, 'o', OLD), accepted(inputs, 'n', NEW), OLD, NEW)
    cap = Capability(engine='bindiff', supported=True, version='8', path=str(tmp_path / 'bindiff'),
                     supports_json=False)
    deep = tmp_path / ('p' * max(1, 236 - len(str(tmp_path))))
    try:
        deep.mkdir()
    except OSError:  # a host path limit already prevents it; the guard is covered by the pure checks above
        pass
    called = []
    with pytest.raises(SecondaryError) as info:
        bindiff_run.execute(cap, pair, tmp_path / 'raw', cancel=threading.Event(), timeout_seconds=5,
                            runner=lambda *a, **k: called.append(a), parent_dir=deep)
    assert info.value.kind == 'workdir-error' and not called
    assert not deep.exists() or not list(deep.glob('patchtrace-bindiff-*'))


def test_windows_status_exit_code_is_reported_in_hex(tmp_path):
    from patchtrace.jobs import ProcessResult
    from patchtrace.secondary.bindiff_inputs import bind_pair
    inputs = tmp_path / 'inputs'
    inputs.mkdir()
    pair = bind_pair(accepted(inputs, 'o', OLD), accepted(inputs, 'n', NEW), OLD, NEW)
    cap = Capability(engine='bindiff', supported=True, version='8', path=str(tmp_path / 'bindiff'),
                     supports_json=False)
    with pytest.raises(SecondaryError) as info:
        bindiff_run.execute(cap, pair, tmp_path / 'raw', cancel=threading.Event(), timeout_seconds=5,
                            runner=lambda *a, **k: ProcessResult(0xC0000409, '', None, ''), parent_dir=tmp_path)
    assert info.value.kind == 'nonzero-exit' and '0xC0000409' in info.value.message


def test_stored_stderr_is_sanitized(tmp_path):
    out, _ = go(tmp_path, 'exit-1-error')
    assert out.run.stderr_tail == sanitize_stderr(out.run.stderr_tail)
