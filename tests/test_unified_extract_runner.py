"""SPEC-31 S1: the extractor runner (extract/runner.py) against fake interpreters (tests/fake_exe.py).

The fake interpreter receives exactly the argv the runner builds (`-B -X utf8 <script> --request <file>`), so these
tests run the real process supervision (`jobs.run_process`) without Ghidra. Nothing here executes a target binary."""
from __future__ import annotations

import dataclasses
import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest
from fake_exe import make_fake_exe
from unified_extract_builder import SHA, document_set, function, pe_view, write_jsonl

from patchtrace.backend import BackendConfig
from patchtrace.jobs import ProcessResult
from patchtrace.unified import extract, keys
from patchtrace.unified.extract import runner
from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError

FAKE = r'''
import json, os, subprocess, sys, time
from pathlib import Path
MODE = '@MODE@'
args = sys.argv[1:]
script = Path(args[3])
if args[4] == '--self-check':
    if MODE == 'selfcheck-ok':
        print(json.dumps({'self_check': {'ok': True, 'missing': [], 'versions': {'ghidra': '12.0.4'}}}))
        sys.exit(0)
    if MODE == 'selfcheck-missing':
        print(json.dumps({'self_check': {'ok': False, 'missing': ['ghidra.base.project.GhidraProject']}}))
        sys.exit(4)
    sys.exit(1)
request = json.loads(Path(args[5]).read_text(encoding='utf-8'))
out, work = Path(request['out_dir']), Path(request['work_dir'])
print(json.dumps({'probe': {'ghidra': '12.0.4', 'pyghidra': '3.0.2', 'java': '21.0.1', 'python': '3.12.1',
                            'script_sha256': 'f' * 64}}), flush=True)
if MODE == 'inspect':
    import hashlib
    info = {'argv': sys.argv[1:], 'script_dir': sorted(os.listdir(script.parent)),
            'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(), 'request': request,
            'cwd': os.getcwd(), 'work_listing': sorted(os.listdir(script.parent.parent)),
            'env': {k: os.environ.get(k) for k in ('XDG_CONFIG_HOME', 'GHIDRA_INSTALL_DIR', 'PYTHONPATH',
                                                   'PYTHONHOME', 'PYTHONIOENCODING', 'JAVA_HOME')}}
    (out / 'inspect.json').write_text(json.dumps(info), encoding='utf-8')
if MODE in ('ok', 'inspect'):
    (work / 'project.gpr').write_text('x')
    (out / 'ir.jsonl').write_text('{"type":"header"}\n', encoding='utf-8')
    if request['mode'] == 'analyze':
        (out / 'program.gzf').write_bytes(b'gzf')
    sys.stderr.write('note \x1b[31mred\x1b[0m\n')
    sys.exit(0)
if MODE.startswith('error:'):
    _, code, reason = MODE.split(':')
    sys.stderr.write('SECRET-TOKEN in /home/victim/.ssh\n')
    print(json.dumps({'error': {'reason': reason}}), flush=True)
    sys.exit(int(code))
if MODE == 'crash':
    sys.stderr.write('Traceback: SECRET-TOKEN \x1b[31mred\x1b[0m ‮ evil\n')
    sys.exit(1)
if MODE == 'hang':
    time.sleep(120)
if MODE == 'grandchild':
    beat = os.environ['PT_TEST_BEAT']
    code = 'import time\nf=open(%r,"ab",buffering=0)\nfor _ in range(400):\n    f.write(b"x")\n    time.sleep(0.05)\n' % beat
    subprocess.Popen([sys.executable, '-c', code])
    time.sleep(120)
if MODE == 'big-output':
    (out / 'ir.jsonl').write_bytes(b'x' * 65536)
    time.sleep(120)
if MODE == 'big-gzf':
    (out / 'program.gzf').write_bytes(b'x' * 65536)
    time.sleep(120)
if MODE == 'subdir-output':
    (out / 'nested').mkdir()
    time.sleep(120)
if MODE == 'progress':
    def put(phase, done, total):
        (out / 'progress.json').write_text(json.dumps({'phase': phase, 'done': done, 'total': total}))
    put('import', 0, None); time.sleep(0.5)
    put('functions', 10, 100); time.sleep(0.5)
    put('functions', 100, 100); time.sleep(0.5)
    (out / 'ir.jsonl').write_text('{"type":"header"}\n', encoding='utf-8')
    sys.exit(0)
if MODE == 'progress-bad':
    for text in ('not json', '{"phase": "Bad Phase", "done": 1, "total": 2}', '{"phase": "x", "done": -1, "total": 2}',
                 '{"phase": "x", "done": true, "total": 2}', '[1,2]', '{"phase": "x"}', 'x' * 8192):
        (out / 'progress.json').write_text(text)
        time.sleep(0.2)
    (out / 'ir.jsonl').write_text('{"type":"header"}\n', encoding='utf-8')
    sys.exit(0)
if MODE == 'no-output':
    sys.exit(0)
if MODE == 'flood-then-error':
    for _ in range(4000):
        print('x' * 100)
    print(json.dumps({'error': {'reason': 'program-hash'}}), flush=True)
    sys.exit(3)
sys.exit(99)
'''


def fake_python(tmp_path: Path, mode: str) -> Path:
    return make_fake_exe(tmp_path / 'bin', 'fakepython', FAKE.replace('@MODE@', mode))


def backend_for(tmp_path: Path, mode: str, **overrides) -> BackendConfig:
    ghidra = tmp_path / 'ghidra-install'
    (ghidra / 'Ghidra').mkdir(parents=True, exist_ok=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4\n', encoding='utf-8')
    return BackendConfig(python_executable=str(fake_python(tmp_path, mode)), ghidra_dir=str(ghidra), **overrides)


def job_for(tmp_path: Path, mode: str = 'ok', *, extract_mode='analyze', **overrides) -> runner.ExtractJob:
    artifact = tmp_path / 'older' / 'sample.dll'
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_bytes(b'MZ')
    fields = dict(side='older', artifact_path=artifact, artifact_sha256=SHA, backend=backend_for(tmp_path, mode),
                  mode=extract_mode)
    if extract_mode == 'gzf':
        gzf = tmp_path / 'older.gzf'
        gzf.write_bytes(b'gzf')
        fields.update(gzf_path=gzf, gzf_sha256='cd' * 32)
    fields.update(overrides)
    return runner.ExtractJob(**fields)


@pytest.fixture(autouse=True)
def private_tempdir(tmp_path, monkeypatch):
    """Every private directory the runner creates lands under tmp_path, so leftovers are countable per test."""
    root = tmp_path / 'tmp'
    root.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(root))
    return root


def leftovers(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir())


# --- argv, environment, private directory -------------------------------------------------------------------------

def test_runner_builds_argv_without_shell_and_absolute_python(tmp_path):
    job = job_for(tmp_path, 'inspect')
    output = runner.extract_side(job)
    info = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))
    assert info['argv'][:3] == ['-B', '-X', 'utf8'] and info['argv'][4] == '--request'
    script = Path(info['argv'][3])
    assert script.name == extract.PRIVATE_SCRIPT_NAME and script.parent == output.work_dir / 'script'
    assert Path(info['argv'][5]) == output.work_dir / 'request.json'
    assert Path(job.backend.python_executable).is_absolute() and os.path.samefile(info['cwd'], output.work_dir)
    output.cleanup()


def test_runner_copies_script_into_empty_private_dir(tmp_path):
    output = runner.extract_side(job_for(tmp_path, 'inspect'))
    info = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))
    # sys.path[0] of the child is this directory: only the verified script, nothing else is importable from it
    assert info['script_dir'] == [extract.PRIVATE_SCRIPT_NAME]
    assert info['script_sha256'] == extract.script_sha256() == output.script_sha256
    assert 'ghidra' in info['work_listing'] and 'request.json' in info['work_listing']
    output.cleanup()


def test_runner_request_matches_the_s0a_contract(tmp_path):
    job = job_for(tmp_path, 'inspect', total_ram_bytes=12 * 1024 ** 3)
    output = runner.extract_side(job)
    request = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))['request']
    assert request['contract'] == 'ir-extract-request/1' and request['mode'] == 'analyze'
    assert request['analysis_options'] == {'PDB Universal': 'false'} and request['gzf_path'] is None
    assert request['max_heap_mb'] == 6144 and request['artifact_sha256'] == SHA and request['decompile_rvas'] == []
    assert request['out_dir'] == str(output.work_dir / 'out') and request['work_dir'] == str(output.work_dir / 'ghidra')
    assert set(request['limits']) == set(runner.REQUEST_LIMIT_KEYS)
    assert output.analysis_options_digest == extract.analysis_options_digest('analyze', {'PDB Universal': 'false'})
    output.cleanup()


def test_gzf_mode_request_carries_the_retained_program_and_no_options(tmp_path):
    job = job_for(tmp_path, 'inspect', extract_mode='gzf')
    output = runner.extract_side(job)
    request = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))['request']
    assert request['mode'] == 'gzf' and request['gzf_sha256'] == 'cd' * 32 and request['analysis_options'] == {}
    assert Path(request['gzf_path']) == job.gzf_path and output.gzf is None   # a gzf-mode run packs no new GZF
    output.cleanup()


def test_runner_env_has_private_settings_dir_and_no_pythonpath(tmp_path, monkeypatch):
    monkeypatch.setenv('PYTHONPATH', str(tmp_path / 'evil'))
    monkeypatch.setenv('PYTHONHOME', str(tmp_path / 'evil'))
    output = runner.extract_side(job_for(tmp_path, 'inspect'))
    env = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))['env']
    assert env['PYTHONPATH'] is None and env['PYTHONHOME'] is None and env['PYTHONIOENCODING'] == 'utf-8'
    assert Path(env['XDG_CONFIG_HOME']) == output.work_dir / 'ghidra-settings'
    assert Path(env['GHIDRA_INSTALL_DIR']) == Path(tmp_path / 'ghidra-install').resolve()
    output.cleanup()


def test_runner_never_sets_memory_limit_for_jvm(tmp_path):
    seen = {}

    def spy(argv, **kwargs):
        seen.update(kwargs, argv=argv)
        (Path(kwargs['cwd']) / 'out' / 'ir.jsonl').write_text('{}\n', encoding='utf-8')
        return ProcessResult(0, '', None, '')

    output = runner.extract_side(job_for(tmp_path), runner=spy)
    assert 'memory_limit_bytes' not in seen and seen['separate_streams'] is True
    assert isinstance(seen['cancel'], threading.Event) and callable(seen['check_output'])
    assert seen['timeout_seconds'] == float(DEFAULT_LIMITS.l04_analyze_timeout_s)
    assert seen['argv'][0] == os.path.abspath(job_for(tmp_path).backend.python_executable)
    output.cleanup()


def test_timeout_defaults_follow_the_mode_and_explicit_values_are_range_checked(tmp_path):
    seen = []

    def spy(argv, **kwargs):
        seen.append(kwargs['timeout_seconds'])
        (Path(kwargs['cwd']) / 'out' / 'ir.jsonl').write_text('{}\n', encoding='utf-8')
        return ProcessResult(0, '', None, '')

    runner.extract_side(job_for(tmp_path, extract_mode='gzf'), runner=spy).cleanup()
    runner.extract_side(job_for(tmp_path, timeout_seconds=600), runner=spy).cleanup()
    assert seen == [float(DEFAULT_LIMITS.l04_gzf_timeout_s), 600.0]
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, timeout_seconds=5), runner=spy)
    assert caught.value.code == 'PT-UNIFIED-INPUT' and caught.value.reason == 'timeout-range'


def test_gzf_mode_never_carries_analysis_options(tmp_path):
    job = job_for(tmp_path, 'inspect', extract_mode='gzf', analysis_options={'Some Option': 'true'})
    assert runner.effective_options(job) == {}
    output = runner.extract_side(job)
    request = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))['request']
    assert request['analysis_options'] == {}
    assert output.analysis_options_digest == extract.analysis_options_digest('gzf', {})
    output.cleanup()


def test_heap_follows_ram_and_unknown_ram_is_4096(tmp_path):
    job = job_for(tmp_path)
    assert runner.heap_mb(job) == 4096
    assert runner.heap_mb(dataclasses.replace(job, total_ram_bytes=8 * 1024 ** 3)) == 4096
    assert runner.heap_mb(dataclasses.replace(job, total_ram_bytes=64 * 1024 ** 3)) == 16384
    assert runner.heap_mb(dataclasses.replace(job, total_ram_bytes=1 * 1024 ** 3)) == 512
    assert runner.heap_mb(dataclasses.replace(job, max_heap_mb=2048)) == 2048


# --- success, cleanup, request validity ---------------------------------------------------------------------------

def test_success_returns_output_and_drops_the_ghidra_project(tmp_path, private_tempdir):
    output = runner.extract_side(job_for(tmp_path, 'ok'))
    assert output.jsonl == output.work_dir / 'out' / 'ir.jsonl' and output.jsonl.read_text(encoding='utf-8')
    assert output.gzf == output.work_dir / 'out' / 'program.gzf' and output.mode == 'analyze'
    assert output.probe == {'ghidra': '12.0.4', 'pyghidra': '3.0.2', 'java': '21.0.1', 'python': '3.12.1',
                            'script_sha256': 'f' * 64}
    assert '\x1b' not in output.stderr_tail and 'note' in output.stderr_tail
    assert not (output.work_dir / 'ghidra').exists() and not (output.work_dir / 'ghidra-settings').exists()
    output.cleanup()
    assert leftovers(private_tempdir) == []


def test_no_output_file_is_an_ir_error_and_removes_the_directory(tmp_path, private_tempdir):
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, 'no-output'))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-IR', 'no-output')
    assert leftovers(private_tempdir) == []


def test_dot_prefixed_private_directory_is_refused_before_spawning(tmp_path, monkeypatch, private_tempdir):
    hidden = tmp_path / '.hidden'
    hidden.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(hidden))
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'request-invalid')
    assert list(hidden.iterdir()) == []


def test_overlong_artifact_path_is_refused(tmp_path, private_tempdir):
    artifact = tmp_path.joinpath(*(['d' * 40] * 7)) / 'sample.dll'            # never created: only the string is checked
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, artifact_path=artifact))
    assert caught.value.reason == 'request-invalid' and leftovers(private_tempdir) == []


def test_gzf_mode_without_a_gzf_is_refused(tmp_path):
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(dataclasses.replace(job_for(tmp_path), mode='gzf'))
    assert caught.value.code == 'PT-UNIFIED-INPUT' and caught.value.reason == 'request-invalid'


def test_missing_backend_is_unsupported_without_spawning(tmp_path, private_tempdir):
    config = BackendConfig(python_executable=str(tmp_path / 'nope'), ghidra_dir=str(tmp_path / 'nothing'))
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(dataclasses.replace(job_for(tmp_path), backend=config))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-UNSUPPORTED', 'no-backend')
    assert leftovers(private_tempdir) == []


# --- failure classification -----------------------------------------------------------------------------------------

@pytest.mark.parametrize('exit_code,reason,code,expected', [
    (3, 'artifact-hash', 'PT-UNIFIED-PAIR', 'artifact-hash'),
    (3, 'program-hash', 'PT-UNIFIED-PAIR', 'program-hash'),
    (3, 'gzf-not-analyzed', 'PT-UNIFIED-EXTRACT', 'gzf-not-analyzed'),
    (4, 'unsupported-language', 'PT-UNIFIED-UNSUPPORTED', 'unsupported-language'),
    (4, 'pyghidra-missing', 'PT-UNIFIED-UNSUPPORTED', 'pyghidra-missing'),
    (4, 'ghidra-version', 'PT-UNIFIED-UNSUPPORTED', 'ghidra-version'),
    (4, 'operand-flags', 'PT-UNIFIED-UNSUPPORTED', 'operand-flags'),
    (2, 'bad-option', 'PT-UNIFIED-INPUT', 'bad-option'),
    (2, 'bad-request', 'PT-UNIFIED-INTERNAL', 'bad-request'),
    (5, 'cancelled', 'PT-UNIFIED-CANCEL', 'cancelled'),
    (1, 'crash', 'PT-UNIFIED-EXTRACT', 'crash'),
    (1, 'surprise-slug', 'PT-UNIFIED-EXTRACT', 'crash'),
], ids=['artifact', 'program', 'notanalyzed', 'language', 'pyghidra', 'version', 'flags', 'option', 'request',
        'cancelled', 'crash', 'unknown'])
def test_child_error_slugs_map_to_typed_errors(tmp_path, private_tempdir, exit_code, reason, code, expected):
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, f'error:{exit_code}:{reason}'))
    assert (caught.value.code, caught.value.reason) == (code, expected)
    assert 'SECRET-TOKEN' not in str(caught.value) and leftovers(private_tempdir) == []
    assert 'SECRET-TOKEN' in caught.value.diagnostics            # the sanitised stderr tail is for the log only


def test_untrusted_slug_text_never_reaches_the_error(tmp_path):
    result = ProcessResult(4, '{"error":{"reason":"../../etc/passwd SECRET"}}\n', None, '')
    error = runner.classify(result)
    assert error.code == 'PT-UNIFIED-EXTRACT' and error.reason == 'crash' and 'SECRET' not in str(error)


@pytest.mark.parametrize('result,code,reason', [
    (ProcessResult(-1, '', 'cancelled'), 'PT-UNIFIED-CANCEL', 'cancelled'),
    (ProcessResult(-9, '', 'timeout'), 'PT-UNIFIED-TIMEOUT', 'timeout'),
    (ProcessResult(-9, '', 'output-limit'), 'PT-UNIFIED-LIMIT', 'output-limit'),
    (ProcessResult(-9, '', 'something'), 'PT-UNIFIED-EXTRACT', 'crash'),
    (ProcessResult(-9, '', None), 'PT-UNIFIED-EXTRACT', 'crash'),
    (ProcessResult(139, 'garbage', None), 'PT-UNIFIED-EXTRACT', 'crash'),
    (ProcessResult(3, '', None), 'PT-UNIFIED-PAIR', 'artifact-hash'),
    (ProcessResult(4, '', None), 'PT-UNIFIED-UNSUPPORTED', 'ghidra-version'),
], ids=['cancel', 'timeout', 'limit', 'other', 'signal', 'segv', 'exit3', 'exit4'])
def test_classify_table(result, code, reason):
    error = runner.classify(result)
    assert (error.code, error.reason) == (code, reason)
    assert isinstance(error, BudgetExhausted) == (code in ('PT-UNIFIED-CANCEL', 'PT-UNIFIED-TIMEOUT'))


def test_gzf_not_analyzed_falls_back(tmp_path, private_tempdir):
    """A GZF Ghidriff saved after a failed analysis is refused by the script (exit 3); the runner reports a recoverable
    EXTRACT error so the pipeline can run that side (and, by F1, both sides) in `analyze` mode."""
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, 'error:3:gzf-not-analyzed', extract_mode='gzf'))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-EXTRACT', 'gzf-not-analyzed')
    assert caught.value.recoverable and leftovers(private_tempdir) == []


def test_success_classification_is_none():
    assert runner.classify(ProcessResult(0, '', None)) is None


def test_crash_diagnostics_are_sanitised_but_the_message_is_fixed(tmp_path):
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, 'crash'))
    assert caught.value.reason == 'crash' and 'SECRET-TOKEN' not in caught.value.message
    assert 'SECRET-TOKEN' in caught.value.diagnostics
    assert '\x1b' not in caught.value.diagnostics and '‮' not in caught.value.diagnostics


def test_a_stdout_flood_before_the_error_line_is_still_classified(tmp_path):
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job_for(tmp_path, 'flood-then-error'))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-PAIR', 'program-hash')


def test_sanitize_stderr_strips_controls_bidi_and_bounds_the_tail():
    text = 'a\x1b[31mb‮c⁦d\x00e\r\nf\tg'
    assert runner.sanitize_stderr(text) == 'a?[31mb?c?d?e\nf\tg'
    long = 'x' * 100_000 + 'END'
    assert runner.sanitize_stderr(long, 1000).endswith('END') and len(runner.sanitize_stderr(long, 1000)) <= 1000


# --- progress and output guard --------------------------------------------------------------------------------------

def test_progress_file_drives_stage_events_and_bad_file_is_ignored(tmp_path):
    events = []
    output = runner.extract_side(job_for(tmp_path, 'progress'), emit=events.append)
    stages = [(e.stage, e.done, e.total) for e in events]
    assert stages[0] == ('import', 0, None) and ('functions', 10, 100) in stages
    assert all(isinstance(e, runner.ExtractProgress) for e in events)
    assert len(stages) == len(set(stages))                           # a repeated file content is one event
    output.cleanup()
    ignored = []
    runner.extract_side(job_for(tmp_path, 'progress-bad'), emit=ignored.append).cleanup()
    assert ignored == []                                             # malformed, hostile or oversized files


def test_a_raising_progress_listener_does_not_interrupt_the_run(tmp_path):
    def boom(_event):
        raise RuntimeError('listener bug')

    output = runner.extract_side(job_for(tmp_path, 'progress'), emit=boom)
    assert output.jsonl.is_file()
    output.cleanup()


@pytest.fixture
def out_dir(tmp_path):
    directory = tmp_path / 'guarded'
    directory.mkdir()
    return directory


def write_progress(directory: Path, document) -> None:
    (directory / 'progress.json').write_text(document if isinstance(document, str) else json.dumps(document),
                                             encoding='utf-8')


def test_guard_reports_progress_once_per_change_and_validates_fields(out_dir):
    events = []
    guard = runner.OutputGuard(out_dir, events.append, 1000, 4096)
    write_progress(out_dir, {'phase': 'functions', 'done': 5, 'total': None})
    assert guard() is None and guard() is None
    write_progress(out_dir, {'phase': 'functions', 'done': 6, 'total': 10})
    guard()
    for bad in ({'phase': 'Bad', 'done': 1, 'total': 2}, {'phase': 'x', 'done': -1, 'total': 2},
                {'phase': 'x', 'done': 1.5, 'total': 2}, {'phase': 'x', 'done': True, 'total': 2},
                {'phase': 'x', 'done': 1, 'total': -3}, {'phase': 'x' * 60, 'done': 1, 'total': 2}, '{', '[]', ''):
        write_progress(out_dir, bad)
        guard()
    assert [(e.stage, e.done, e.total) for e in events] == [('functions', 5, None), ('functions', 6, 10)]


def test_guard_without_a_listener_never_reads_the_progress_file(out_dir):
    write_progress(out_dir, {'phase': 'x', 'done': 1, 'total': 2})
    assert runner.OutputGuard(out_dir, None, 1000, 4096)() is None


def test_output_guard_kills_on_size_cap_and_symlink(out_dir):
    guard = runner.OutputGuard(out_dir, None, 100, 4096, 50)
    assert guard() is None
    (out_dir / 'ir.jsonl').write_bytes(b'x' * 100)
    (out_dir / 'ir.jsonl.part').write_bytes(b'x' * 10_000)          # temp files are not counted
    assert guard() is None
    (out_dir / 'ir.jsonl').write_bytes(b'x' * 101)
    assert guard() == 'output-limit'
    (out_dir / 'ir.jsonl').write_bytes(b'x')
    (out_dir / runner.OutputGuard.GZF_NAME).write_bytes(b'x' * 50)   # the GZF has its own cap (L-36)
    assert guard() is None
    (out_dir / runner.OutputGuard.GZF_NAME).write_bytes(b'x' * 51)
    assert guard() == 'output-limit'
    (out_dir / runner.OutputGuard.GZF_NAME).unlink()
    (out_dir / 'nested').mkdir()
    assert guard() == 'output-limit'
    (out_dir / 'nested').rmdir()
    try:
        os.symlink(out_dir / 'ir.jsonl', out_dir / 'link')
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not available here')
    assert guard() == 'output-limit'


def test_guard_ignores_a_missing_directory(out_dir):
    assert runner.OutputGuard(out_dir / 'gone', None, 100, 4096)() is None


@pytest.mark.parametrize('mode,limits', [('big-output', {'l05_output_bytes': 1000}),
                                         ('big-gzf', {'l36_retained_gzf_bytes': 1000}),
                                         ('subdir-output', {})], ids=['text', 'gzf', 'subdir'])
def test_runaway_output_is_killed_and_removed(tmp_path, private_tempdir, mode, limits):
    job = job_for(tmp_path, mode, limits=dataclasses.replace(DEFAULT_LIMITS, **limits))
    started = time.monotonic()
    with pytest.raises(UnifiedError) as caught:
        runner.extract_side(job)
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-LIMIT', 'output-limit')
    assert time.monotonic() - started < 60 and leftovers(private_tempdir) == []


# --- cancel and timeout kill the tree ---------------------------------------------------------------------------------

def heartbeat_stopped(beat: Path) -> bool:
    deadline = time.monotonic() + 15
    while not beat.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    time.sleep(1.0)
    size = beat.stat().st_size if beat.exists() else 0
    time.sleep(0.6)
    return beat.exists() and (beat.stat().st_size if beat.exists() else 0) == size


@pytest.mark.parametrize('how', ['cancel', 'timeout'])
def test_cancel_and_timeout_kill_tree_and_remove_private_dir(tmp_path, monkeypatch, private_tempdir, how):
    beat = tmp_path / 'beat.txt'
    monkeypatch.setenv('PT_TEST_BEAT', str(beat))
    cancel = threading.Event()
    if how == 'cancel':
        threading.Timer(2.0, cancel.set).start()
        budget, expected = Budget(None, cancel), ('PT-UNIFIED-CANCEL', 'cancelled')
    else:
        budget, expected = Budget.after(3.0), ('PT-UNIFIED-TIMEOUT', 'timeout')
    started = time.monotonic()
    with pytest.raises(BudgetExhausted) as caught:
        runner.extract_side(job_for(tmp_path, 'grandchild'), budget)
    assert (caught.value.code, caught.value.reason) == expected
    assert time.monotonic() - started < 60 and leftovers(private_tempdir) == []
    assert heartbeat_stopped(beat), 'the grandchild survived'


def test_an_expired_budget_is_refused_before_spawning(tmp_path, private_tempdir):
    with pytest.raises(BudgetExhausted) as caught:
        runner.extract_side(job_for(tmp_path, 'hang'), Budget(deadline=time.monotonic() - 1))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-TIMEOUT', 'deadline')
    assert leftovers(private_tempdir) == []


def test_a_cancelled_budget_never_starts_the_child(tmp_path, private_tempdir):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BudgetExhausted) as caught:
        runner.extract_side(job_for(tmp_path, 'hang'), Budget(None, cancel))
    assert caught.value.code == 'PT-UNIFIED-CANCEL' and leftovers(private_tempdir) == []


# --- self-check ---------------------------------------------------------------------------------------------------------

def test_self_check_returns_the_script_report(tmp_path, private_tempdir):
    report = runner.self_check(backend_for(tmp_path, 'selfcheck-ok'))
    assert report['ok'] is True and report['missing'] == [] and leftovers(private_tempdir) == []


def test_runner_self_check_reports_missing_classes(tmp_path, private_tempdir):
    with pytest.raises(UnifiedError) as caught:
        runner.self_check(backend_for(tmp_path, 'selfcheck-missing'))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-UNSUPPORTED', 'self-check')
    assert 'ghidra.base.project.GhidraProject' in caught.value.diagnostics and leftovers(private_tempdir) == []


def test_self_check_without_a_backend_is_unsupported(tmp_path):
    with pytest.raises(UnifiedError) as caught:
        runner.self_check(BackendConfig(python_executable='', ghidra_dir=''))
    assert caught.value.reason == 'no-backend'


# --- keys ------------------------------------------------------------------------------------------------------------------

def test_predicted_ir_key_equals_the_key_ingest_derives_from_the_header(tmp_path):
    job = job_for(tmp_path)
    inputs, predicted = runner.predict_ir_key(job, ghidra_version='12.0.4', pyghidra_version='3.0.2',
                                              python_version='3.12.10')
    options = runner.effective_options(job)
    assert options == {'PDB Universal': 'false'} and inputs.symbols == 'none' and inputs.mode == 'analyze'
    documents = document_set(function(0x1000, [('mov',), ('ret',)], name='f'), script=extract.script_sha256(),
                             options=extract.analysis_options_digest('analyze', options))
    path = write_jsonl(tmp_path / 'ir.jsonl', documents)
    out = tmp_path / 'built'
    out.mkdir()
    result = ingest(path, ExpectedSide('older', SHA, pe_view(), mode='analyze'), out_dir=out)
    assert result.manifest.ir_key == predicted == keys.ir_key(inputs)


def test_predicted_ir_key_changes_with_mode_options_versions_and_limits(tmp_path):
    job = job_for(tmp_path)
    base = runner.predict_ir_key(job, ghidra_version='12.0.4', pyghidra_version='3.0.2', python_version='3.12.10')[1]
    versions = dict(ghidra_version='12.0.4', pyghidra_version='3.0.2', python_version='3.12.10')
    different = {
        'ghidra': runner.predict_ir_key(job, **{**versions, 'ghidra_version': '12.0.5'})[1],
        'pyghidra': runner.predict_ir_key(job, **{**versions, 'pyghidra_version': '3.0.3'})[1],
        'python': runner.predict_ir_key(job, **{**versions, 'python_version': '3.13.0'})[1],
        'options': runner.predict_ir_key(dataclasses.replace(job, analysis_options={}), **versions)[1],
        'gzf': runner.predict_ir_key(job_for(tmp_path, extract_mode='gzf'), **versions)[1],
        'limits': runner.predict_ir_key(
            dataclasses.replace(job, limits=dataclasses.replace(DEFAULT_LIMITS, l01_functions_per_side=10)),
            **versions)[1],
    }
    assert len({base, *different.values()}) == 1 + len(different)


def test_default_options_per_mode():
    assert runner.default_analysis_options('analyze') == {'PDB Universal': 'false'}
    assert runner.default_analysis_options('gzf') == {}
