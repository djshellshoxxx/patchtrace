"""`patchtrace compare` (docs/specs/cli-project-compare.md section 4): the primary analysis for one pair.

The backend is the fake runtime of tests/test_jobs.py with the fake Ghidriff of tests/test_nway_series.py: a small
script stands in for `python -m ghidriff`, so the real `backend.run_comparison`, the real service and the real
project files are exercised but no Ghidra runs. Evidence class: mocked, never live.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime, write_backend  # noqa: F401  (fixture reuse: never real Ghidra)
from test_nway_series import FAKE_GHIDRIFF

from patchtrace import backend, cli
from patchtrace.cli_commands import discover
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

SRC = Path(cli.__file__).resolve().parents[1]
LOCK = '.patchtrace.lock'
# A result Ghidriff could have written for some other pair: the backend accepts its shape, the service refuses it.
FOREIGN_RESULT = ('raw = {"old_meta": {"SHA256": "a" * 64}, "new_meta": {"SHA256": "b" * 64},\n'
                  '       "functions": {"added": [], "deleted": [], "modified": []}}\n'
                  '(out/"json"/"a-b.ghidriff.json").write_text(json.dumps(raw))\n')


def run(args, capsys):
    code = cli.main([str(a) for a in args])
    out, err = capsys.readouterr()
    return code, out, err


def jrun(args, capsys):
    code, out, err = run([*args, '--json'], capsys)
    assert out.count('\n') == 1 and out.endswith('\n'), out  # exactly one document
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'] == 'compare'
    return code, doc, err


def tree(root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file()
            else 'dir' for path in sorted(root.rglob('*')) if path.name != LOCK}


def new_project(tmp: Path, name: str = 'proj', variants: tuple[int, int] = (0, 1)) -> Path:
    files = []
    for side, variant in zip(('older', 'newer'), variants, strict=True):
        path = tmp / f'{name}-{side}.dll'
        path.write_bytes(synthetic_pe(variant))
        files.append(path)
    ProjectService.create(files[0], files[1], name, tmp / name).close()
    return tmp / name


def runs_of(root: Path):
    with ProjectService.open(root, maintenance=False) as service:
        return service.project.model_copy(deep=True)


@pytest.fixture
def runtime(fake_runtime):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, FAKE_GHIDRIFF)
    root = new_project(tmp)
    return root, package, ['--python', config.python_executable, '--ghidra-dir', config.ghidra_dir]


# --- success ------------------------------------------------------------------------------------------------

def test_the_verb_is_discovered_and_has_help(capsys):
    verbs, failed = discover()
    assert 'compare' in verbs and 'compare' not in failed
    code, out, err = run(['compare', '--help'], capsys)
    assert code == 0 and err == '' and 'usage: patchtrace compare' in out
    for flag in ('--python', '--ghidra-dir', '--timeout', '--cache-dir', '--symbols', '--symbol-dir',
                 '--consent-online-symbols', '--force', '--json'):
        assert flag in out
    assert 'for --run' not in out  # the shared symbol help is written for `series create --run`


def test_compare_runs_one_pair_with_a_fake_backend(runtime, capsys):
    """F-D01: the single-pair analysis runs headless; `rank` then works on the same project."""
    root, _, flags = runtime
    code, doc, err = jrun(['compare', root, *flags], capsys)
    assert code == 0 and doc['status'] == 'complete' and doc['warnings'] == []
    result = doc['result']
    project = runs_of(root)
    [recorded] = project.runs
    assert result == {
        'ran': True, 'forced': False, 'run_id': recorded.id, 'status': 'completed', 'backend': 'ghidriff',
        'backend_version': 'fake-test-only', 'raw_path': recorded.raw_path, 'raw_sha256': recorded.raw_sha256,
        'revision': 1, 'matches': {'total': 1, 'by_category': {
            'modified': 1, 'added': 0, 'removed': 0, 'unmatched': 0, 'ambiguous': 0, 'split': 0, 'merged': 0,
            'unchanged': 0}}}
    assert recorded.status == 'completed' and (root / recorded.raw_path).is_file()
    assert hashlib.sha256((root / recorded.raw_path).read_bytes()).hexdigest() == recorded.raw_sha256
    assert [m.category for m in project.matches] == ['modified'] and project.matches[0].run_id == recorded.id
    stages = [line.split(': ')[1] for line in err.splitlines() if line.startswith('compare: ')]
    assert stages[0] == 'preflight' and stages[-1] == 'completed'
    code, ranked, _ = jrun_rank(root, capsys)
    assert code == 0 and ranked['status'] == 'complete'
    assert [entry['function'] for entry in ranked['result']['entries']] == ['f']
    code, listing, _ = run(['project', 'runs', root], capsys)
    assert code == 0 and f'* {recorded.id}  completed' in listing


def jrun_rank(root, capsys):
    code, out, err = run(['rank', root, '--json'], capsys)
    return code, json.loads(out), err


def test_compare_text_output(runtime, capsys):
    root, _, flags = runtime
    code, out, err = run(['compare', root, *flags], capsys)
    run_id = runs_of(root).runs[0].id
    assert code == 0 and out.splitlines()[0] == f'compared: run {run_id} completed (ghidriff fake-test-only)'
    assert 'matches: 1 (modified 1)' in out and 'compare: preflight: ' in err


def test_a_compared_project_is_a_no_op_unless_forced(runtime, capsys):
    root, _, flags = runtime
    assert run(['compare', root, *flags], capsys)[0] == 0
    first = runs_of(root)
    before = tree(root)
    code, doc, err = jrun(['compare', root, *flags], capsys)
    assert code == 0 and doc['status'] == 'complete'
    assert doc['result'] == {'ran': False, 'forced': False, 'run_id': first.runs[0].id, 'status': 'completed',
                             'revision': 1, 'matches': doc['result']['matches']}
    assert doc['result']['matches']['total'] == 1 and 'compare: ' not in err
    assert tree(root) == before
    code, out, _ = run(['compare', root, *flags], capsys)
    assert code == 0 and 'nothing was run' in out and '--force' in out
    code, doc, _ = jrun(['compare', root, *flags, '--force'], capsys)
    assert code == 0 and doc['result']['ran'] is True and doc['result']['forced'] is True
    again = runs_of(root)
    assert [r.status for r in again.runs] == ['completed', 'completed']
    assert again.runs[0] == first.runs[0] and again.runs[1].id == doc['result']['run_id'] != first.runs[0].id
    assert (root / first.runs[0].raw_path).is_file()  # the earlier raw result is kept
    assert {m.run_id for m in again.matches} == {again.runs[1].id} and again.revision == 2


def test_identical_inputs_are_a_no_op_that_says_so(fake_runtime, capsys):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, 'sys.exit(9)\n')  # would fail if it ran
    root = new_project(tmp, 'same', (0, 0))
    code, doc, _ = jrun(['compare', root, '--python', config.python_executable, '--ghidra-dir', config.ghidra_dir],
                        capsys)
    assert code == 0 and doc['result']['ran'] is False and doc['result']['status'] == 'identical'
    code, out, _ = run(['compare', root, '--python', config.python_executable, '--ghidra-dir', config.ghidra_dir],
                       capsys)
    assert code == 0 and 'identical' in out


# --- failure and cancellation -------------------------------------------------------------------------------

def test_a_backend_failure_records_the_run_keeps_its_output_and_exits_3(runtime, capsys):
    root, package, flags = runtime
    write_backend(package, '(out/"partial.txt").write_text("keep me")\nsys.exit(7)\n')
    code, doc, err = jrun(['compare', root, *flags], capsys)
    assert code == 3 and doc['status'] == 'failed'
    result = doc['result']
    project = runs_of(root)
    [recorded] = project.runs
    assert recorded.status == 'failed' and recorded.error.startswith('PT-BACKEND')
    assert result == {'ran': True, 'forced': False, 'run_id': recorded.id, 'status': 'failed',
                      'error': recorded.error, 'error_code': 'PT-BACKEND',
                      'output_dir': f'runs/quarantine-{recorded.id}'}
    quarantine = root / 'runs' / f'quarantine-{recorded.id}'
    assert (quarantine / 'raw' / 'partial.txt').read_text() == 'keep me'
    assert (quarantine / 'failure.txt').read_text(encoding='utf-8') == recorded.error
    assert project.matches == [] and project.revision == 0
    assert f'error: {recorded.error}'[:60] in err and 'Traceback' not in err
    code, listing, _ = run(['project', 'runs', root, '--json'], capsys)
    assert code == 0 and json.loads(listing)['result']['runs'][0]['quarantined'] is True
    # A failed run is not a result: the next compare runs again without --force.
    write_backend(package, FAKE_GHIDRIFF)
    code, doc, _ = jrun(['compare', root, *flags], capsys)
    assert code == 0 and doc['result']['ran'] is True
    assert [r.status for r in runs_of(root).runs] == ['failed', 'completed']


def test_a_result_the_service_rejects_is_quarantined_and_exits_3(runtime, capsys):
    root, package, flags = runtime
    write_backend(package, FOREIGN_RESULT)
    code, doc, _ = jrun(['compare', root, *flags], capsys)
    assert code == 3 and doc['status'] == 'failed'
    [recorded] = runs_of(root).runs
    assert recorded.status == 'failed' and doc['result']['error_code'] == 'PT-SCHEMA'
    assert 'diff input hash does not match this project' in doc['result']['error']
    assert recorded.raw_path.startswith(f'runs/quarantine-{recorded.id}/') and (root / recorded.raw_path).is_file()
    assert not (root / 'runs' / recorded.id).exists()


def test_a_cancelled_comparison_exits_5_and_records_a_cancelled_run(runtime, capsys, monkeypatch):
    root, _, flags = runtime
    original = threading.Event

    class Preset(original):
        def __init__(self):
            super().__init__()
            self.set()
    monkeypatch.setattr(cli.threading, 'Event', Preset)
    code, doc, _ = jrun(['compare', root, *flags], capsys)
    assert code == 5 and doc['status'] == 'cancelled'
    [recorded] = runs_of(root).runs
    assert recorded.status == 'cancelled' and recorded.error.startswith('PT-CANCEL')
    assert doc['result']['run_id'] == recorded.id and doc['result']['error_code'] == 'PT-CANCEL'
    assert doc['result']['status'] == 'cancelled'


def test_the_first_ctrl_c_during_a_comparison_cancels_it_cleanly(runtime, capsys, monkeypatch):
    """Ctrl+C sets the cancel event instead of unwinding, so the backend stops and the cancelled run is recorded."""
    root, _, flags = runtime
    real = backend.run_comparison
    previous = signal.getsignal(signal.SIGINT)
    seen = {}

    def interrupted(config, project, project_root, cancel, on_event):
        signal.raise_signal(signal.SIGINT)  # the analyst presses Ctrl+C while the backend runs
        seen['cancel'] = cancel.is_set()
        seen['restored'] = signal.getsignal(signal.SIGINT) is previous  # a second Ctrl+C interrupts as usual
        return real(config, project, project_root, cancel, on_event)
    monkeypatch.setattr(backend, 'run_comparison', interrupted)
    code, doc, _ = jrun(['compare', root, *flags], capsys)
    assert seen == {'cancel': True, 'restored': True}
    assert code == 5 and doc['status'] == 'cancelled'
    assert [r.status for r in runs_of(root).runs] == ['cancelled']
    assert signal.getsignal(signal.SIGINT) is previous


# --- preflight: exit 2 before anything is written -----------------------------------------------------------

def _bad_flags(tmp: Path, good: list[str]) -> dict[str, tuple[list[str], str]]:
    python, ghidra = good[1], good[3]
    return {
        'python-missing': (['--python', str(tmp / 'no-python'), '--ghidra-dir', ghidra], 'PT-BACKEND: select the '
                           'absolute path to an installed external Python executable'),
        'python-relative': (['--python', 'python3', '--ghidra-dir', ghidra], 'PT-BACKEND: select the absolute path'),
        'ghidra-not-a-root': (['--python', python, '--ghidra-dir', str(tmp)],
                              'PT-BACKEND: Ghidra/application.properties is missing'),
        'no-python-flag': (['--ghidra-dir', ghidra], '--python'),
        'no-ghidra-flag': (['--python', python], '--ghidra-dir'),
        'timeout-too-small': ([*good, '--timeout', '9'], '--timeout must be between 10 and 86400 seconds'),
        'timeout-too-large': ([*good, '--timeout', '86401'], '--timeout must be between 10 and 86400 seconds'),
        'online-without-consent': ([*good, '--symbols', 'online'], 'PT-SYMBOL-NETWORK-REFUSED'),
        'symbol-dir-without-local': ([*good, '--symbol-dir', str(tmp)], 'PT-SYMBOL-MODE'),
    }


BAD_FLAG_CASES = ('python-missing', 'python-relative', 'ghidra-not-a-root', 'no-python-flag', 'no-ghidra-flag',
                  'timeout-too-small', 'timeout-too-large', 'online-without-consent', 'symbol-dir-without-local')


@pytest.mark.parametrize('case', BAD_FLAG_CASES, ids=list(BAD_FLAG_CASES))
def test_an_invalid_runtime_exits_2_before_anything_is_written(case, runtime, capsys, monkeypatch):
    root, _, good = runtime
    flags, message = _bad_flags(root.parent, good)[case]
    monkeypatch.setattr(backend, 'run_comparison', lambda *a, **k: pytest.fail('the backend must not start'))
    before = tree(root)
    code, out, err = run(['compare', root, *flags, '--json'], capsys)
    doc = json.loads(out)
    assert code == 2 and doc['status'] == 'failed' and message in doc['error'] and 'Traceback' not in err
    assert tree(root) == before and not (root / 'runs').exists() and runs_of(root).runs == []


def test_a_refused_compare_does_not_even_open_the_project(runtime, capsys):
    root, _, good = runtime
    lock = (root / LOCK).read_bytes()
    assert run(['compare', root, '--python', 'python3', '--ghidra-dir', good[3]], capsys)[0] == 2
    assert (root / LOCK).read_bytes() == lock  # every opener rewrites the lock file; this one never opened


def test_a_project_held_open_elsewhere_exits_3_and_names_the_lock(runtime, capsys):
    root, _, flags = runtime
    before = tree(root)
    holder = ProjectService.open(root)
    try:
        code, doc, err = jrun(['compare', root, *flags], capsys)
    finally:
        holder.close()
    assert code == 3 and doc['status'] == 'failed'
    assert doc['error'].startswith('PT-STORAGE: project is locked by another writer or lock is inaccessible')
    assert LOCK in doc['error'] and 'Traceback' not in err and tree(root) == before


def test_a_path_that_is_not_a_project_exits_2(runtime, capsys):
    root, _, flags = runtime
    code, doc, _ = jrun(['compare', root.parent / 'absent', *flags], capsys)
    assert code == 2 and doc['error'] == 'PT-STORAGE: project directory does not exist'


# --- one source of truth with `series create --run` ---------------------------------------------------------

def _comparable(project) -> dict:
    """What a recorded project must share between the two paths: everything but ids and timestamps."""
    return {'revision': project.revision,
            'runs': [(r.status, r.backend, r.backend_version, r.settings, r.raw_sha256,
                      (r.raw_path or '').replace(r.id, '<id>'), r.error) for r in project.runs],
            'matches': [(m.category, m.match_types, m.quality, [f.name for f in m.older], [f.name for f in m.newer],
                         [f.code for f in m.older + m.newer]) for m in project.matches]}


@pytest.mark.parametrize('body', [FAKE_GHIDRIFF, 'sys.exit(7)\n', FOREIGN_RESULT],
                         ids=['completed', 'backend-failure', 'rejected-result'])
def test_compare_records_what_the_series_pair_runner_records(body, fake_runtime, capsys):  # noqa: F811
    tmp, package, _, config = fake_runtime
    write_backend(package, body)
    via_series, via_compare = new_project(tmp, 'a'), new_project(tmp, 'b')
    series_config = backend.BackendConfig(python_executable=config.python_executable, ghidra_dir=config.ghidra_dir,
                                          timeout_seconds=3600, allow_symbol_downloads=False, symbol_mode='off',
                                          symbol_pdb_dirs=(), cache_dir='')
    error = cli._run_pair(series_config, via_series, threading.Event())
    code, doc, _ = jrun(['compare', via_compare, '--python', config.python_executable, '--ghidra-dir',
                         config.ghidra_dir], capsys)
    assert (code == 0) == (error is None)
    assert _comparable(runs_of(via_compare)) == _comparable(runs_of(via_series))
    kept = [[p.name.startswith('quarantine-') for p in (root / 'runs').iterdir()] for root in (via_compare, via_series)]
    assert kept[0] == kept[1] == [error is not None]  # one run directory each, quarantined alike
    if error is not None:
        assert doc['result']['error'] == error


def test_compare_builds_the_backend_config_exactly_as_series_create_run_does(runtime, tmp_path, capsys,
                                                                            monkeypatch):
    root, _, flags = runtime
    pdbs = tmp_path / 'pdbs'
    pdbs.mkdir()
    shared = [*flags, '--timeout', '120', '--cache-dir', tmp_path / 'raw-cache', '--symbols', 'local',
              '--symbol-dir', pdbs]
    seen = {}
    monkeypatch.setattr(cli, '_run_pair', lambda config, path, cancel: seen.setdefault('series', config) and None)

    def record(config, *rest):
        seen['compare'] = config
        raise RuntimeError('stop here')
    monkeypatch.setattr(backend, 'run_comparison', record)
    builds = []
    for index in range(3):
        builds.append(tmp_path / f'b{index}.dll')
        builds[-1].write_bytes(synthetic_pe(index + 2))
    assert run(['series', 'create', '--builds', *builds, '--root', tmp_path / 'series', '--run', *shared],
               capsys)[0] == 0
    assert run(['compare', root, *shared], capsys)[0] == 3  # the stand-in raised: reported, never a traceback
    assert seen['compare'] == seen['series'] and seen['compare'].timeout_seconds == 120
    assert seen['compare'].symbol_mode == 'local' and seen['compare'].cache_dir == str((tmp_path / 'raw-cache').resolve())


# --- import cleanliness -------------------------------------------------------------------------------------

def test_the_compare_verb_never_imports_qt(tmp_path):
    ghidra = tmp_path / 'ghidra'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4', encoding='utf-8')
    root = tmp_path / 'demo'
    code = ('import sys\nfrom patchtrace import backend, cli\n'
            'def no_probe(*_):\n    raise RuntimeError("PT-BACKEND: dependency probe disabled in this test")\n'
            'backend._probe_backend = no_probe\n'
            f'made = cli.main(["project", "sample", "--project", {str(root)!r}])\n'
            f'flags = ["--python", sys.executable, "--ghidra-dir", {str(ghidra)!r}]\n'
            f'noop = cli.main(["compare", {str(root)!r}, *flags])\n'
            f'failed = cli.main(["compare", {str(root)!r}, *flags, "--force", "--json"])\n'
            'import patchtrace.compare_cli\n'
            'bad = sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui")))\n'
            'print([made, noop, failed], bad, file=sys.stderr)')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, PYTHONPATH=str(SRC)))
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip().splitlines()[-1] == '[0, 0, 3] []'
    doc = json.loads(result.stdout.strip().splitlines()[-1])
    assert doc['command'] == 'compare' and doc['result']['error_code'] == 'PT-BACKEND'
