"""GUI plan 8.12, slice F1b: the CLI-extension registry (`patchtrace.cli_commands`) and its `cli.py` seam.

Fake verbs are files in a temporary directory appended to the real package's `__path__`, so discovery, import,
parser building and dispatch run exactly as they do for a real adapter. Nothing here proves the frozen Windows
exe: that is the Windows CI step (`tools/frozen_smoke.py` A1 over `names()`); the opt-in freeze at the end
covers Linux only.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
from argparse import Namespace
from pathlib import Path

import pytest

from patchtrace import cli, cli_commands
from patchtrace.cli_commands import CliCommand, discover, names

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
PACKAGE = SRC / 'patchtrace' / 'cli_commands'
HOOK = ROOT / 'tools' / 'pyinstaller_hooks' / 'hook-patchtrace.cli_commands.py'
CLI_BASELINE_LINES = 894  # cli.py before the seam (869) plus audit fixes WP-01, CLI-B-01, CLI-B-02 (JSON envelope on usage errors); budget is baseline + 6 (8.12)
BUILTINS = ('rank', 'flags', 'correlate', 'cache', 'acquire', 'series', 'secondary', 'intelligence',
            'unified', 'intel-tools', 'backend')
UNAVAILABLE = 'unavailable (could not be loaded)'


def declare(name: str, summary: str = 'fine') -> str:
    return ('from patchtrace.cli_commands import CliCommand\n'
            f'COMMAND = CliCommand({name!r}, {summary!r}, lambda sub: None, lambda args, cancel: 0)\n')


def good_source(verb: str, log: Path, summary: str = 'a fake verb') -> str:
    """A well-formed verb: logs its build, takes --json, answers with the standard envelope."""
    return textwrap.dedent(f'''\
        from pathlib import Path

        from patchtrace.cli_commands import OK, CliCommand, emit


        def _build(sub):
            with Path({str(log)!r}).open('a', encoding='utf-8', newline='\\n') as handle:
                handle.write('build:' + {verb!r} + '\\n')
            parser = sub.add_parser({verb!r}, help={summary!r})
            parser.add_argument('--json', action='store_true')
            return parser


        def _run(args, cancel):
            emit(args, args.command_label, 'complete', {{'verb': args.command}}, [], 'ran ' + args.command)
            return OK


        COMMAND = CliCommand({verb!r}, {summary!r}, _build, _run)
        ''')


def probe_source(log: Path) -> str:
    """A file that is not a verb but records each import of itself (proves what was and was not imported)."""
    return ('from pathlib import Path\n'
            f"Path({str(log)!r}).open('a', encoding='utf-8', newline='\\n').write('imported\\n')\n")


NESTED = '''
from patchtrace.cli_commands import OK, CliCommand, emit


def _build(sub):
    parser = sub.add_parser('zz-nest', help='nested actions')
    actions = parser.add_subparsers(dest='action', required=True)
    for name, label in (('leaf', 'zz-nest leaf'), ('plain', None)):
        leaf = actions.add_parser(name)
        leaf.add_argument('--json', action='store_true')
        if label:
            leaf.set_defaults(command_label=label)
    return parser


def _run(args, cancel):
    emit(args, args.command_label, 'complete', {'action': args.action}, [], 'ok')
    return OK


COMMAND = CliCommand('zz-nest', 'nested actions', _build, _run)
'''

EXITING = '''
from patchtrace.cli_commands import CliCommand, CliError


def _build(sub):
    parser = sub.add_parser('zz-exit', help='exits with --code, or raises with --raise-code')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--code', type=int, default=0)
    parser.add_argument('--raise-code', type=int, default=0)
    return parser


def _run(args, cancel):
    if args.raise_code:
        raise CliError(args.raise_code, 'boom')
    return args.code


COMMAND = CliCommand('zz-exit', 'exits with --code, or raises with --raise-code', _build, _run)
'''


class Verbs:
    """Writes fake verb files into a directory that extends the real package, and reads their event log."""

    def __init__(self, directory: Path, log: Path):
        self.directory, self.log = directory, log

    def write(self, module: str, source: str) -> None:
        (self.directory / f'{module}.py').write_text(textwrap.dedent(source), encoding='utf-8', newline='\n')
        importlib.invalidate_caches()

    def good(self, module: str, summary: str = 'a fake verb') -> str:
        verb = module.replace('_', '-')
        self.write(module, good_source(verb, self.log, summary))
        return verb

    @property
    def events(self) -> list[str]:
        return self.log.read_text(encoding='utf-8').split() if self.log.exists() else []


@pytest.fixture
def verbs(tmp_path, monkeypatch):
    directory = tmp_path / 'fake_verbs'
    directory.mkdir()
    before = set(sys.modules)
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)  # a rewritten file must never hit a stale pyc
    monkeypatch.setattr(cli_commands, '__path__', [*cli_commands.__path__, str(directory)])
    yield Verbs(directory, tmp_path / 'events.log')
    for name in set(sys.modules) - before:
        if name.startswith('patchtrace.cli_commands.'):
            del sys.modules[name]
            vars(cli_commands).pop(name.rpartition('.')[2], None)
    importlib.invalidate_caches()


def run(argv, capsys):
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def choices_of(parser):
    return next(a for a in parser._actions if getattr(a, 'choices', None)).choices


# --- discovery ----------------------------------------------------------------------------------------------

BAD_FILES = {
    'import-error': ('zz_bad', 'import no_such_module_zz\n', 'ModuleNotFoundError'),
    'syntax-error': ('zz_bad', 'def broken(:\n', 'SyntaxError'),
    'no-command': ('zz_bad', 'X = 1\n', 'AttributeError'),
    'not-a-command': ('zz_bad', 'COMMAND = 42\n', 'ValueError'),
    'name-differs-from-file': ('zz_bad', declare('zz-other'), 'ValueError'),
    'name-uppercase': ('zz_bad', declare('ZZ-BAD'), 'ValueError'),
    'name-digit-first': ('9zz_bad', declare('9zz-bad'), 'ValueError'),
    'name-too-long': ('zz_' + 'x' * 22, declare('zz-' + 'x' * 22), 'ValueError'),
    'summary-too-long': ('zz_bad', declare('zz-bad', 'x' * 81), 'ValueError'),
    'summary-non-ascii': ('zz_bad', declare('zz-bad', 'café'), 'ValueError'),
    'summary-empty': ('zz_bad', declare('zz-bad', ''), 'ValueError'),
    'summary-control': ('zz_bad', declare('zz-bad', 'a\tb'), 'ValueError'),
}


@pytest.mark.parametrize(('module', 'source', 'error'), list(BAD_FILES.values()), ids=list(BAD_FILES))
def test_one_bad_file_is_isolated_and_never_hides_a_good_one(verbs, module, source, error):
    good = verbs.good('zz_good')
    verbs.write(module, source)
    found, failed = discover()
    assert good in found
    assert failed[module] == error and module.replace('_', '-') not in found
    assert module.replace('_', '-') in names()  # listed, so that the smoke A1 check fails loudly


def test_a_summary_of_exactly_80_ascii_characters_is_valid(verbs):
    verbs.write('zz_edge', declare('zz-edge', 'x' * 80))
    found, failed = discover()
    assert 'zz-edge' in found and 'zz_edge' not in failed


def test_private_modules_are_skipped_everywhere(verbs):
    verbs.write('_zz_private', 'raise RuntimeError("must never be imported")\n')
    found, failed = discover()
    assert '_zz_private' not in failed and not any('private' in name for name in found)
    assert not any('private' in name for name in names())
    assert not any('private' in name for name in choices_of(cli._parser()))


def test_a_built_in_verb_name_is_never_overridden(verbs, capsys):
    verbs.write('rank', declare('rank'))
    assert discover()[1]['rank'] == 'ValueError'
    assert names().count('rank') == 1
    assert run(['rank', '--help'], capsys)[0] == 0
    assert cli.HANDLERS['rank'] is cli.cmd_rank


def test_two_files_claiming_one_verb_are_both_unavailable(verbs, capsys):
    verbs.write('zz_dup', declare('zz-dup'))
    verbs.write('zz-dup', declare('zz-dup'))
    found, failed = discover()
    assert 'zz-dup' not in found
    assert {k: v for k, v in failed.items() if 'dup' in k} == {'zz-dup': 'ValueError', 'zz_dup': 'ValueError'}
    assert names().count('zz-dup') == 1
    assert run(['zz-dup'], capsys)[0] == 3


def test_discover_is_sorted_by_verb(verbs):
    for module in ('zz_b', 'zz_a2', 'zz_a_1', 'zz_c'):
        verbs.good(module)
    found, _ = discover()
    ours = [name for name in found if name.startswith('zz-')]
    assert ours == sorted(ours) == ['zz-a-1', 'zz-a2', 'zz-b', 'zz-c']


def test_the_real_package_loads_cleanly():
    found, failed = discover()
    assert failed == {}, failed
    assert not set(found) & set(cli.COMMANDS)


def test_cli_command_validates_at_construction():
    with pytest.raises(ValueError):
        CliCommand('Bad_Name', 'summary', lambda sub: None, lambda args, cancel: 0)
    with pytest.raises(AttributeError):  # frozen: a loaded declaration cannot be changed
        CliCommand('fine', 'summary', lambda sub: None, lambda args, cancel: 0).name = 'other'


def test_reexports_are_the_cli_objects():
    assert cli_commands.CliError is cli.CliError and cli_commands.emit is cli._emit
    assert (cli_commands.OK, cli_commands.ENVIRONMENT, cli_commands.RUNTIME, cli_commands.NO_RESULTS,
            cli_commands.CANCELLED) == (cli.OK, cli.ENVIRONMENT, cli.RUNTIME, cli.NO_RESULTS, cli.CANCELLED)


# --- names() ------------------------------------------------------------------------------------------------

def test_names_are_the_builtins_then_the_sorted_discovered_verbs_without_importing_them(verbs):
    for module in ('zz_b', 'zz_a'):
        verbs.write(module, probe_source(verbs.log))
    listed = names()
    assert listed[:len(BUILTINS)] == BUILTINS == cli.COMMANDS
    assert [name for name in listed if name.startswith('zz-')] == ['zz-a', 'zz-b']
    assert verbs.events == []
    assert len(set(listed)) == len(listed)


def test_names_over_twenty_verbs_is_fast_and_imports_none_of_them(verbs):
    for i in range(20):
        verbs.write(f'zz_many_{i:02d}', probe_source(verbs.log))
    started = time.perf_counter()
    listed = names()
    elapsed = time.perf_counter() - started
    assert [name for name in listed if name.startswith('zz-many-')] == [f'zz-many-{i:02d}' for i in range(20)]
    assert verbs.events == []
    assert elapsed <= 0.125  # budget 25 ms with 5x CI slack (plan 8.12); names() does no import at all


# --- parsers, dispatch, envelopes ---------------------------------------------------------------------------

def test_only_the_invoked_verbs_parser_is_built_and_the_rest_are_bare_listings(verbs):
    for module in ('zz_a', 'zz_b', 'zz_c'):
        verbs.good(module)
    parser = cli._parser(['zz-b', '--help'])
    assert verbs.events == ['build:zz-b']
    choices = choices_of(parser)
    assert {'--json'} <= {opt for action in choices['zz-b']._actions for opt in action.option_strings}
    for bare in ('zz-a', 'zz-c'):
        assert [a.dest for a in choices[bare]._actions] == ['help']
    assert set(BUILTINS) | {'zz-a', 'zz-b', 'zz-c'} <= set(choices)


def test_a_discovered_verbs_help_is_the_a1_smoke_contract(verbs, capsys):
    verbs.good('zz_a')
    verbs.good('zz_b')
    code, out, err = run(['zz-b', '--help'], capsys)
    assert code == 0 and 'usage: patchtrace zz-b' in out and err == ''
    assert verbs.events == ['build:zz-b']


def test_parser_choices_equal_names_even_with_broken_clashing_and_duplicate_files(verbs):
    verbs.good('zz_ok')
    verbs.write('zz_broken', 'import no_such_module_zz\n')
    verbs.write('rank', declare('rank'))
    verbs.write('zz_dup', declare('zz-dup'))
    verbs.write('zz-dup', declare('zz-dup'))
    assert set(choices_of(cli._parser())) == set(names())  # the invariant behind test_acceptance_smoke


@pytest.mark.parametrize('argv', [[], ['--help'], ['rank', '--help'], ['no-such-verb']],
                         ids=['empty', 'help', 'builtin', 'unknown'])
def test_no_discovered_parser_is_built_unless_its_verb_is_invoked(verbs, argv):
    verbs.good('zz_a')
    cli._parser(argv)
    assert verbs.events == []


def test_top_level_help_lists_every_summary_and_marks_unavailable_verbs(verbs, capsys):
    verbs.good('zz_a', 'does the first fake thing')
    verbs.good('zz_pct', 'covers 100% of the fakes')
    verbs.write('zz_broken', 'import no_such_module_zz\n')
    code, out, _ = run(['--help'], capsys)
    text = ' '.join(out.split())
    assert code == 0 and verbs.events == []
    assert 'zz-a does the first fake thing' in text and 'zz-pct covers 100% of the fakes' in text
    assert f'zz-broken {UNAVAILABLE}' in text
    assert all(name in text for name in BUILTINS)


def test_a_discovered_verb_runs_with_the_standard_envelope(verbs, capsys):
    verbs.good('zz_a')
    code, out, err = run(['zz-a', '--json'], capsys)
    assert code == 0 and err == '' and out.count('\n') == 1
    assert json.loads(out) == {'contract': 'enrichment-cli/1', 'command': 'zz-a', 'status': 'complete',
                               'result': {'verb': 'zz-a'}, 'warnings': []}
    assert run(['zz-a'], capsys)[1] == 'ran zz-a\n'


def test_a_nested_leaf_may_set_the_command_label(verbs, capsys):
    verbs.write('zz_nest', NESTED)
    doc = json.loads(run(['zz-nest', 'leaf', '--json'], capsys)[1])
    assert doc['command'] == 'zz-nest leaf' and doc['result'] == {'action': 'leaf'}
    default = json.loads(run(['zz-nest', 'plain', '--json'], capsys)[1])
    assert default['command'] == 'zz-nest'  # no leaf label: the verb is the default


@pytest.mark.parametrize('code', [0, 2, 3, 4, 5],
                         ids=['ok', 'environment', 'runtime', 'no-results', 'cancelled'])
def test_the_exit_code_of_a_discovered_verb_is_passed_through(verbs, capsys, code):
    verbs.write('zz_exit', EXITING)
    assert run(['zz-exit', '--code', str(code)], capsys)[0] == code


@pytest.mark.parametrize('code', [2, 3], ids=['environment', 'runtime'])
def test_cli_error_from_a_discovered_verb_keeps_its_code_and_failed_envelope(verbs, capsys, code):
    verbs.write('zz_exit', EXITING)
    exit_code, out, err = run(['zz-exit', '--raise-code', str(code), '--json'], capsys)
    assert exit_code == code and 'error: boom' in err
    assert json.loads(out) == {'contract': 'enrichment-cli/1', 'command': 'zz-exit', 'status': 'failed',
                               'result': None, 'warnings': [], 'error': 'boom'}


def test_argument_errors_of_a_discovered_verb_exit_2(verbs, capsys):
    verbs.write('zz_exit', EXITING)
    code, _, err = run(['zz-exit', '--code', 'not-a-number'], capsys)
    assert code == 2 and 'zz-exit' in err and 'Traceback' not in err


@pytest.mark.parametrize('flags', [[], ['--help']], ids=['plain', 'help'])
def test_a_broken_verb_exits_3_with_and_without_help_while_the_others_still_run(verbs, capsys, flags):
    verbs.good('zz_good')
    verbs.write('zz_broken', 'import no_such_module_zz\n')
    code, out, err = run(['zz-broken', *flags], capsys)
    assert code == 3 and out == ''
    assert 'PT-CLI-COMMAND: zz-broken could not be loaded (ModuleNotFoundError)' in err
    assert 'Traceback' not in err
    assert run(['zz-good', '--json'], capsys)[0] == 0
    assert run(['cache', '--help'], capsys)[0] == 0


def test_the_builtin_envelope_names_are_unchanged(tmp_path, capsys):
    assert cli._command_name(Namespace(command='cache', action='status')) == 'cache'
    assert cli._command_name(Namespace(command='rank')) == 'rank'
    for command in ('acquire', 'series', 'secondary', 'intelligence', 'unified', 'intel-tools', 'backend'):
        assert cli._command_name(Namespace(command=command, action='x')) == f'{command} x'
    labelled = Namespace(command='cache', action='status', command_label='cache status')
    assert cli._command_name(labelled) == 'cache status'
    cache = tmp_path / 'cache'
    cache.mkdir()
    status = json.loads(run(['cache', 'status', '--cache-dir', str(cache), '--json'], capsys)[1])
    assert status['command'] == 'cache'  # the positional `action` is not part of this envelope name
    missing = tmp_path / 'series.json'
    doc = json.loads(run(['series', 'chains', str(missing), '--json'], capsys)[1])
    assert doc['command'] == 'series chains' and doc['status'] == 'failed'


# --- budgets, adapters, smoke list --------------------------------------------------------------------------

def test_cli_seam_budget():
    lines = (SRC / 'patchtrace' / 'cli.py').read_text(encoding='utf-8').splitlines()
    grown = len(lines) - CLI_BASELINE_LINES
    assert grown <= 6, f'cli.py grew by {grown} lines (cap 6)'
    assert cli.COMMANDS == BUILTINS  # a new verb is a cli_commands/<verb>.py file, not an edit of this tuple
    assert sum('cli_commands' in line for line in lines) == 1  # the one function-level import
    assert len((PACKAGE / '__init__.py').read_text(encoding='utf-8').splitlines()) <= 90


def adapter_problems(source: str) -> list[str]:
    """Rule violations of an adapter: over 25 lines, or a module-level import beyond `.` and the stdlib."""
    stdlib = sys.stdlib_module_names
    problems = [f'{len(source.splitlines())} lines'] if len(source.splitlines()) > 25 else []

    def module_level(node):
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                yield child
                yield from module_level(child)

    for node in module_level(ast.parse(source)):
        if isinstance(node, ast.Import):
            problems += [f'import {a.name}' for a in node.names if a.name.split('.')[0] not in stdlib]
        elif isinstance(node, ast.ImportFrom):
            if node.level > 1 or (node.level == 0 and (node.module or '').split('.')[0] not in stdlib):
                problems.append(f'from {"." * node.level}{node.module or ""} import')
    return problems


ADAPTER = '''\
from __future__ import annotations

from argparse import ArgumentParser

from . import CliCommand


def _build(sub):
    from ..search.cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..search.cli import run
    return run(args, cancel)


COMMAND = CliCommand('search', 'full-text search over a project', _build, _run)
'''


@pytest.mark.parametrize(('source', 'problems'), [
    (ADAPTER, []),
    ('X = 1\n' * 26, ['26 lines']),
    ('import pydantic\n', ['import pydantic']),
    ('from PySide6.QtCore import QObject\n', ['from PySide6.QtCore import']),
    ('from ..search.cli import add_parser\n', ['from ..search.cli import']),
    ('try:\n    import yara_x\nexcept ImportError:\n    yara_x = None\n', ['import yara_x']),
    ('import json, os.path\nfrom . import CliCommand\nfrom .other import x\n', []),
], ids=['card-example', 'too-long', 'heavy-import', 'qt-import', 'parent-import', 'guarded-import',
        'stdlib-and-dot'])
def test_the_adapter_rule_checker(source, problems):
    assert adapter_problems(source) == problems


def test_every_real_adapter_is_thin_and_imports_only_the_package_and_the_stdlib():
    adapters = sorted(PACKAGE.glob('[!_]*.py'))
    bad = {path.name: adapter_problems(path.read_text(encoding='utf-8')) for path in adapters}
    assert {name: problems for name, problems in bad.items() if problems} == {}


def test_the_registry_and_discovery_never_import_qt_or_pydantic():
    code = ('import sys\nimport patchtrace.cli_commands as c\nc.discover()\nc.names()\n'
            'print(sorted(m for m in sys.modules if m.startswith(("PySide6", "pydantic", "patchtrace.ui"))))')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                            env=dict(os.environ, PYTHONPATH=str(SRC)))
    assert result.returncode == 0 and result.stdout.strip() == '[]', result.stderr


def test_the_frozen_smoke_list_is_derived_from_the_registry():
    spec = importlib.util.spec_from_file_location('frozen_smoke_registry', ROOT / 'tools' / 'frozen_smoke.py')
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    assert smoke.COMMANDS == names()
    assert 'COMMANDS = names()' in (ROOT / 'tools' / 'frozen_smoke.py').read_text(encoding='utf-8')


# --- the PyInstaller collect hook ---------------------------------------------------------------------------

def run_hook(hook: Path) -> subprocess.CompletedProcess:
    """Execute the hook file like PyInstaller does; its isolated child must resolve THIS tree: PYTHONPATH."""
    code = 'import json, runpy, sys\nprint(json.dumps(runpy.run_path(sys.argv[1])["hiddenimports"]))'
    return subprocess.run([sys.executable, '-c', code, str(hook)], capture_output=True, text=True,
                          timeout=180, env=dict(os.environ, PYTHONPATH=str(SRC)))


def test_the_hook_collects_exactly_the_registry_package_and_its_files():
    pytest.importorskip('PyInstaller')
    result = run_hook(HOOK)
    assert result.returncode == 0, result.stderr[-600:]
    expected = ['patchtrace.cli_commands', *(f'patchtrace.cli_commands.{p.stem}' for p in PACKAGE.glob('*.py')
                                             if p.stem != '__init__')]
    assert json.loads(result.stdout.strip().splitlines()[-1]) == sorted(expected)


def test_the_hook_refuses_a_build_that_would_miss_a_verb_file_but_accepts_an_empty_registry(tmp_path):
    pytest.importorskip('PyInstaller')
    hook = tmp_path / 'tools' / 'pyinstaller_hooks' / HOOK.name
    hook.parent.mkdir(parents=True)
    shutil.copyfile(HOOK, hook)
    registry = tmp_path / 'src' / 'patchtrace' / 'cli_commands'  # the tree being built (the child sees SRC)
    registry.mkdir(parents=True)
    assert run_hook(hook).returncode == 0
    (registry / 'zz_orphan.py').write_text('', encoding='utf-8')
    refused = run_hook(hook)
    assert refused.returncode != 0 and 'patchtrace.cli_commands.zz_orphan' in refused.stderr


# --- opt-in: a real freeze (Linux evidence only; Windows is the CI step) ------------------------------------

@pytest.mark.skipif(not os.environ.get('PATCHTRACE_TOY_FREEZE'),
                    reason='opt-in nightly check (about 30 s): set PATCHTRACE_TOY_FREEZE=1')
def test_a_frozen_cli_finds_discovered_verbs_through_the_collect_hook(tmp_path):
    pytest.importorskip('PyInstaller')
    tree = tmp_path / 'tree'
    shutil.copytree(SRC / 'patchtrace', tree / 'src' / 'patchtrace',
                    ignore=shutil.ignore_patterns('__pycache__'))
    (tree / 'tools' / 'pyinstaller_hooks').mkdir(parents=True)
    shutil.copyfile(HOOK, tree / 'tools' / 'pyinstaller_hooks' / HOOK.name)
    registry = tree / 'src' / 'patchtrace' / 'cli_commands'
    (registry / 'zz_hello.py').write_text(good_source('zz-hello', tmp_path / 'events.log'), encoding='utf-8')
    (registry / 'zz_broken.py').write_text('import no_such_module_zz\n', encoding='utf-8')
    entry = tree / 'entry.py'
    entry.write_text('from patchtrace.cli import main\nraise SystemExit(main())\n', encoding='utf-8')
    build = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--name', 'toy',
         '--exclude-module', 'PySide6', '--additional-hooks-dir', str(tree / 'tools' / 'pyinstaller_hooks'),
         '--paths', str(tree / 'src'), '--distpath', str(tree / 'dist'), '--workpath', str(tree / 'build'),
         '--specpath', str(tree), str(entry)],
        capture_output=True, text=True, timeout=600, env=dict(os.environ, PYTHONPATH=str(tree / 'src')))
    assert build.returncode == 0, build.stderr[-800:]
    exe = tree / 'dist' / 'toy' / ('toy.exe' if os.name == 'nt' else 'toy')

    def frozen(*args):
        return subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=120)

    listing = ' '.join(frozen('--help').stdout.split())
    assert 'zz-hello a fake verb' in listing and f'zz-broken {UNAVAILABLE}' in listing
    hello = frozen('zz-hello', '--json')
    assert hello.returncode == 0 and json.loads(hello.stdout)['result'] == {'verb': 'zz-hello'}
    broken = frozen('zz-broken')
    assert broken.returncode == 3 and 'PT-CLI-COMMAND: zz-broken could not be loaded' in broken.stderr
    assert frozen('rank', '--help').returncode == 0
