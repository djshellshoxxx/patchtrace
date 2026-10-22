"""SPEC-31 S3b: the decompile entry of the extractor runner (`runner.decompile_side`) against fake interpreters.

The fake interpreter receives exactly the argv the runner builds (`-B -X utf8 <script> --request <file>`), so the real
process supervision (`jobs.run_process`) runs without Ghidra. Nothing here executes a target binary."""
from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path

import pytest
from fake_exe import make_fake_exe

from patchtrace.backend import BackendConfig
from patchtrace.jobs import ProcessResult
from patchtrace.unified import extract
from patchtrace.unified.extract import runner
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError

SHA, GZF_SHA = 'ab' * 32, 'cd' * 32
FAKE = r'''
import json, os, sys, time
from pathlib import Path
MODE = '@MODE@'
args = sys.argv[1:]
script = Path(args[3])
request = json.loads(Path(args[5]).read_text(encoding='utf-8'))
out = Path(request['out_dir'])
print(json.dumps({'probe': {'ghidra': '12.0.4', 'pyghidra': '3.0.2', 'java': '21.0.1', 'python': '3.12.1',
                            'script_sha256': 'f' * 64}}), flush=True)
rvas = request['decompile_rvas']


def line(rva, status='ok', code=None, side=None):
    return json.dumps({'side': side or request['side'], 'rva': rva, 'status': status,
                       'code': code if status == 'ok' else None}) + '\n'


if MODE == 'inspect':
    info = {'request': request, 'script_dir': sorted(os.listdir(script.parent)), 'argv': sys.argv[1:],
            'env': {k: os.environ.get(k) for k in ('XDG_CONFIG_HOME', 'GHIDRA_INSTALL_DIR', 'PYTHONPATH')}}
    (out / 'inspect.json').write_text(json.dumps(info), encoding='utf-8')
if MODE in ('ok', 'inspect'):
    Path(request['work_dir']).joinpath('project.gpr').write_text('x')
    (out / 'decomp.jsonl').write_text(''.join(line(r, code='int f_%d(void);' % r) for r in rvas), encoding='utf-8')
    sys.stderr.write('note \x1b[31mred\x1b[0m\n')
    sys.exit(0)
if MODE == 'mixed':
    states = ['ok', 'timeout', 'failed']
    (out / 'decomp.jsonl').write_text(''.join(line(r, states[i % 3], 'code %d' % r) for i, r in enumerate(rvas)),
                                      encoding='utf-8')
    sys.exit(0)
if MODE == 'progress':
    (out / 'progress.json').write_text(json.dumps({'phase': 'decompile', 'done': 1, 'total': len(rvas)}))
    time.sleep(0.6)
    (out / 'decomp.jsonl').write_text(''.join(line(r, code='c') for r in rvas), encoding='utf-8')
    sys.exit(0)
if MODE == 'foreign-rva':
    (out / 'decomp.jsonl').write_text(line(rvas[0], code='c') + line(0x7fff0000, code='x'), encoding='utf-8')
    sys.exit(0)
if MODE == 'foreign-side':
    (out / 'decomp.jsonl').write_text(''.join(line(r, code='c', side='newer') for r in rvas), encoding='utf-8')
    sys.exit(0)
if MODE == 'missing':
    (out / 'decomp.jsonl').write_text(line(rvas[0], code='c'), encoding='utf-8')
    sys.exit(0)
if MODE == 'no-output':
    sys.exit(0)
if MODE.startswith('error:'):
    _, code, reason = MODE.split(':')
    sys.stderr.write('SECRET-TOKEN in /home/victim/.ssh\n')
    print(json.dumps({'error': {'reason': reason}}), flush=True)
    sys.exit(int(code))
if MODE == 'hang':
    time.sleep(120)
sys.exit(99)
'''


def backend_for(tmp_path: Path, mode: str, **overrides) -> BackendConfig:
    ghidra = tmp_path / 'ghidra-install'
    (ghidra / 'Ghidra').mkdir(parents=True, exist_ok=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4\n', encoding='utf-8')
    fake = make_fake_exe(tmp_path / 'bin', 'fakepython', FAKE.replace('@MODE@', mode))
    return BackendConfig(python_executable=str(fake), ghidra_dir=str(ghidra), **overrides)


def job_for(tmp_path: Path, mode: str = 'ok', rvas=(0x1000, 0x1100), **overrides) -> runner.DecompileJob:
    artifact = tmp_path / 'older' / 'sample.dll'
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_bytes(b'MZ')
    gzf = tmp_path / 'older.gzf'
    gzf.write_bytes(b'gzf')
    fields = dict(side='older', artifact_path=artifact, artifact_sha256=SHA, backend=backend_for(tmp_path, mode),
                  gzf_path=gzf, gzf_sha256=GZF_SHA, rvas=tuple(rvas))
    fields.update(overrides)
    return runner.DecompileJob(**fields)


@pytest.fixture(autouse=True)
def private_tempdir(tmp_path, monkeypatch):
    """Every private directory the runner creates lands under tmp_path, so leftovers are countable per test."""
    root = tmp_path / 'tmp'
    root.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(root))
    return root


def leftovers(root: Path) -> list[str]:
    return sorted(p.name for p in root.iterdir())


# --- the request, the output, the cleanup -------------------------------------------------------------------------------

def test_the_request_is_a_decompile_request_over_the_retained_gzf(tmp_path):
    job = job_for(tmp_path, 'inspect', rvas=(0x1100, 0x1000, 0x1100), total_ram_bytes=12 * 1024 ** 3)
    output = runner.decompile_side(job)
    info = json.loads((output.work_dir / 'out' / 'inspect.json').read_text(encoding='utf-8'))
    request = info['request']
    assert request['contract'] == 'ir-extract-request/1' and request['mode'] == 'decompile' and request['side'] == 'older'
    assert request['decompile_rvas'] == [0x1000, 0x1100]                       # sorted, unique
    assert Path(request['gzf_path']) == job.gzf_path and request['gzf_sha256'] == GZF_SHA
    assert request['artifact_sha256'] == SHA and request['analysis_options'] == {} and request['max_heap_mb'] == 6144
    assert set(request['limits']) == set(runner.DECOMPILE_LIMIT_KEYS)
    assert request['limits']['l41_decompile_fn_s'] == DEFAULT_LIMITS.l41_decompile_fn_s == 60
    assert request['out_dir'] == str(output.work_dir / 'out') and request['work_dir'] == str(output.work_dir / 'ghidra')
    assert info['script_dir'] == [extract.PRIVATE_SCRIPT_NAME]                 # nothing else is importable
    assert Path(info['env']['XDG_CONFIG_HOME']) == output.work_dir / 'ghidra-settings' and info['env']['PYTHONPATH'] is None
    output.cleanup()


def test_success_returns_the_validated_records_and_drops_the_ghidra_project(tmp_path, private_tempdir):
    output = runner.decompile_side(job_for(tmp_path))
    assert output.jsonl == output.work_dir / 'out' / 'decomp.jsonl' and list(output.records) == [0x1000, 0x1100]
    assert output.records[0x1000].code == 'int f_4096(void);' and output.records[0x1100].status == 'ok'
    assert output.probe['ghidra'] == '12.0.4' and output.script_sha256 == extract.script_sha256()
    assert '\x1b' not in output.stderr_tail and 'note' in output.stderr_tail
    assert not (output.work_dir / 'ghidra').exists() and not (output.work_dir / 'ghidra-settings').exists()
    output.cleanup()
    assert leftovers(private_tempdir) == []


def test_timeouts_and_failures_are_records_not_errors(tmp_path):
    output = runner.decompile_side(job_for(tmp_path, 'mixed', rvas=(0x1000, 0x1100, 0x1200)))
    assert [(r.rva, r.status, r.code) for r in output.records.values()] == [
        (0x1000, 'ok', 'code 4096'), (0x1100, 'timeout', None), (0x1200, 'failed', None)]
    output.cleanup()


def test_progress_of_the_decompile_phase_is_forwarded(tmp_path):
    events = []
    runner.decompile_side(job_for(tmp_path, 'progress'), emit=events.append).cleanup()
    assert ('decompile', 1, 2) in [(e.stage, e.done, e.total) for e in events]


@pytest.mark.parametrize('mode,reason', [('foreign-rva', 'bad-decomp-rva'), ('foreign-side', 'bad-decomp-keys'),
                                         ('missing', 'bad-decomp-missing'), ('no-output', 'no-decomp')])
def test_an_output_that_fails_validation_is_an_extract_error_and_leaves_nothing(tmp_path, private_tempdir, mode, reason):
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path, mode))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-EXTRACT', reason)
    assert leftovers(private_tempdir) == []


@pytest.mark.parametrize('exit_code,reason,code', [
    (4, 'decompiler-unavailable', 'PT-UNIFIED-UNSUPPORTED'), (3, 'program-hash', 'PT-UNIFIED-PAIR'),
    (3, 'gzf-not-analyzed', 'PT-UNIFIED-EXTRACT'), (4, 'ghidra-version', 'PT-UNIFIED-UNSUPPORTED'),
    (5, 'cancelled', 'PT-UNIFIED-CANCEL'), (2, 'bad-request', 'PT-UNIFIED-INTERNAL')])
def test_child_error_slugs_map_to_typed_errors(tmp_path, private_tempdir, exit_code, reason, code):
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path, f'error:{exit_code}:{reason}'))
    assert (caught.value.code, caught.value.reason) == (code, reason)
    assert 'SECRET-TOKEN' not in str(caught.value) and leftovers(private_tempdir) == []
    assert 'SECRET-TOKEN' in caught.value.diagnostics                 # the sanitised stderr tail is for the log only


# --- inputs --------------------------------------------------------------------------------------------------------------

def test_the_set_of_functions_is_bounded_by_l41(tmp_path, private_tempdir):
    for rvas in ((), tuple(range(65))):
        with pytest.raises(UnifiedError) as caught:
            runner.decompile_side(job_for(tmp_path, rvas=rvas))
        assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'request-invalid')
    runner.decompile_side(job_for(tmp_path, rvas=tuple(range(64)))).cleanup()
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path, rvas=(-1,)))
    assert caught.value.reason == 'request-invalid' and leftovers(private_tempdir) == []


def test_a_missing_backend_is_unsupported_without_spawning(tmp_path, private_tempdir):
    config = BackendConfig(python_executable=str(tmp_path / 'nope'), ghidra_dir=str(tmp_path / 'nothing'))
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path, backend=config))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-UNSUPPORTED', 'no-backend')
    assert leftovers(private_tempdir) == []


def test_a_hidden_private_directory_is_refused_before_spawning(tmp_path, monkeypatch):
    hidden = tmp_path / '.hidden'
    hidden.mkdir()
    monkeypatch.setattr(tempfile, 'tempdir', str(hidden))
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-INPUT', 'request-invalid')
    assert list(hidden.iterdir()) == []


# --- timeouts, cancel, budget -----------------------------------------------------------------------------------------------

def spy_runner(seen):
    def spy(argv, **kwargs):
        seen.append(kwargs['timeout_seconds'])
        request = json.loads(Path(argv[-1]).read_text(encoding='utf-8'))
        out = Path(kwargs['cwd']) / 'out'
        (out / 'decomp.jsonl').write_text(''.join(
            json.dumps({'side': 'older', 'rva': r, 'status': 'failed', 'code': None}) + '\n'
            for r in request['decompile_rvas']), encoding='utf-8')
        return ProcessResult(0, '', None, '')
    return spy


def test_the_process_timeout_is_the_l41_run_budget_plus_the_start_overhead(tmp_path):
    seen = []
    runner.decompile_side(job_for(tmp_path), runner=spy_runner(seen)).cleanup()
    runner.decompile_side(job_for(tmp_path, timeout_seconds=900), runner=spy_runner(seen)).cleanup()
    assert seen == [float(DEFAULT_LIMITS.l41_decompile_run_s + runner.DECOMPILE_OVERHEAD_S), 900.0]
    with pytest.raises(UnifiedError) as caught:
        runner.decompile_side(job_for(tmp_path, timeout_seconds=5), runner=spy_runner(seen))
    assert caught.value.code == 'PT-UNIFIED-INPUT' and caught.value.reason == 'timeout-range'


def test_the_deadline_of_the_run_caps_the_timeout(tmp_path):
    seen = []
    runner.decompile_side(job_for(tmp_path), Budget.after(30.0), runner=spy_runner(seen)).cleanup()
    assert 0 < seen[0] <= 30.0 + 1e-6  # float rounding of deadline - clock() at a large monotonic reading


def test_a_hung_child_is_killed_at_the_timeout_and_nothing_is_left(tmp_path, private_tempdir):
    started = time.monotonic()
    with pytest.raises(BudgetExhausted) as caught:
        runner.decompile_side(job_for(tmp_path, 'hang'), Budget.after(3.0))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-TIMEOUT', 'timeout')
    assert time.monotonic() - started < 60 and leftovers(private_tempdir) == []


def test_cancel_kills_the_child_and_removes_the_directory(tmp_path, private_tempdir):
    cancel = threading.Event()
    threading.Timer(2.0, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(BudgetExhausted) as caught:
        runner.decompile_side(job_for(tmp_path, 'hang'), Budget(None, cancel))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-CANCEL', 'cancelled')
    assert time.monotonic() - started < 60 and leftovers(private_tempdir) == []


def test_an_expired_budget_is_refused_before_spawning(tmp_path, private_tempdir):
    with pytest.raises(BudgetExhausted) as caught:
        runner.decompile_side(job_for(tmp_path, 'hang'), Budget(deadline=time.monotonic() - 1))
    assert (caught.value.code, caught.value.reason) == ('PT-UNIFIED-TIMEOUT', 'deadline')
    assert leftovers(private_tempdir) == []

