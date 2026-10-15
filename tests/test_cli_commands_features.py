"""F1b adapters for kb, search, graph, strings and build-env: help, one offline run per verb, exit codes, no Qt."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover, names
from patchtrace.service import ProjectService

VERBS = ('kb', 'search', 'graph', 'strings', 'build-env')
# verb -> (argv template with {proj}/{ws}, expected exit code, expected envelope command prefix)
RUNS = {
    'kb': (['kb', 'search', 'KB5099777', '--workspace', '{ws}', '--json'], 3, 'kb'),  # empty workspace: not searched
    'search': (['search', '{proj}', '--status', '--json'], 0, 'search'),
    'graph': (['graph', 'leads', '{proj}', '--json'], 0, 'graph leads'),
    'strings': (['strings', 'scan', '{proj}', '--builtin', '--json'], 0, 'strings scan'),
    'build-env': (['build-env', 'show', '{proj}', '--json'], 0, 'build-env show'),
}
BAD = {
    'kb': ['kb', 'bogus-action'],
    'search': ['search', '{missing}', '--json'],
    'graph': ['graph', 'leads', '{missing}'],
    'strings': ['strings', 'scan', '{missing}', '--builtin'],
    'build-env': ['build-env', 'show', '{missing}'],
}


@pytest.fixture(scope='module')
def paths(tmp_path_factory):
    base = tmp_path_factory.mktemp('features')
    service = ProjectService.sample(base / 'proj')
    proj = service.root
    service.close()
    return {'proj': str(proj), 'ws': str(base / 'kbws'), 'missing': str(base / 'no' / 'such')}


def _argv(template: list[str], paths: dict) -> list[str]:
    return [part.format(**paths) for part in template]


def test_all_five_verbs_are_discovered_and_loadable():
    verbs, failed = discover()
    assert not set(failed) & {'kb', 'search', 'graph', 'strings', 'build_env'}
    assert set(VERBS) <= set(verbs) and set(VERBS) <= set(names())


@pytest.mark.parametrize('verb', VERBS, ids=list(VERBS))
def test_help_exits_zero_with_usage(verb, capsys):
    assert cli.main([verb, '--help']) == 0
    assert 'usage:' in capsys.readouterr().out


@pytest.mark.parametrize('verb', VERBS, ids=list(VERBS))
def test_one_offline_run_passes_its_exit_code_and_envelope(verb, paths, capsys):
    template, code, command = RUNS[verb]
    assert cli.main(_argv(template, paths)) == code
    doc = json.loads(capsys.readouterr().out)
    assert doc['contract'] == 'enrichment-cli/1' and doc['command'].startswith(command)


@pytest.mark.parametrize('verb', VERBS, ids=list(VERBS))
def test_bad_input_is_exit_2_without_a_traceback(verb, paths, capsys):
    assert cli.main(_argv(BAD[verb], paths)) == 2
    assert 'Traceback' not in capsys.readouterr().err


@pytest.mark.parametrize('verb', VERBS, ids=list(VERBS))
def test_help_and_run_paths_import_no_qt(verb, paths):
    code = ('import sys\nfrom patchtrace import cli\n'
            'rc = cli.main(sys.argv[1:])\n'
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))]\n'
            'raise SystemExit(90 if bad else rc)\n')
    help_run = subprocess.run([sys.executable, '-c', code, verb, '--help'], capture_output=True, text=True)
    assert help_run.returncode == 0, help_run.stderr
    template, expected, _ = RUNS[verb]
    run = subprocess.run([sys.executable, '-c', code, *_argv(template, paths)], capture_output=True, text=True)
    assert run.returncode == expected, run.stderr


def test_adapters_stay_within_25_lines_and_import_no_feature_at_module_level():
    package = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'cli_commands'
    for module in ('kb', 'search', 'graph', 'strings', 'build_env'):
        source = (package / f'{module}.py').read_text(encoding='utf-8')
        assert len(source.splitlines()) <= 25, module
        assert not any(line.startswith(('from patchtrace.', 'import patchtrace')) for line in source.splitlines())
