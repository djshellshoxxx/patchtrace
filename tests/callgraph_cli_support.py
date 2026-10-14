"""Builders for the `graph` CLI tests (WB2 G4/G7): real synthetic projects on disk and a harness that runs the
dispatcher through a parser built like `patchtrace.cli`'s. Everything is invented; no Microsoft data."""
from __future__ import annotations

import copy
import io
import json
import threading
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from callgraph_fixtures import build_fixture

from patchtrace import cli
from patchtrace.callgraph import cli as graph_cli
from patchtrace.models import AnalysisRun
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def make_project(root: Path, raw: dict, seed: int = 0, older: Path | None = None, newer: Path | None = None) -> Path:
    """A project directory whose completed run preserves `raw` (build hashes patched to the project's)."""
    scratch = root.parent / f'{root.name}-input'
    scratch.mkdir(parents=True, exist_ok=True)
    older, newer = older or scratch / 'older.dll', newer or scratch / 'newer.dll'
    if not older.exists():
        older.write_bytes(synthetic_pe(seed))
    if not newer.exists():
        newer.write_bytes(synthetic_pe(seed + 1))
    service = ProjectService.create(older, newer, root.name, root)
    try:
        raw = copy.deepcopy(raw)
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        raw['old_meta']['Executable SHA256'], raw['new_meta']['Executable SHA256'] = sides['older'], sides['newer']
        file = scratch / 'raw.json'
        file.write_text(json.dumps(raw), encoding='utf-8')
        service.apply_analysis(file, AnalysisRun(status='completed', backend='synthetic', backend_version='1'))
    finally:
        service.close()
    return root


def match_id(root: Path, label: str, side: str = 'newer') -> str:
    service = ProjectService.open(root, maintenance=False)
    try:
        for match in service.project.matches:
            if label in [f.name for f in getattr(match, side)]:
                return match.id
    finally:
        service.close()
    raise KeyError(label)


def svc_project(root: Path) -> Path:
    return make_project(root, build_fixture('svc_pair'))


def _graph_parser():
    parser = cli._Parser(prog='patchtrace')
    sub = parser.add_subparsers(dest='command', required=True, parser_class=cli._Parser)

    def common(p):
        p.add_argument('--json', action='store_true')
        return p
    handlers: dict = {}
    graph_cli.register(sub, common, handlers)
    return parser, handlers


def _function(name: str, address: int, called=()) -> dict:
    return {'name': name, 'fullname': name, 'address': f'{address:x}', 'code': f'code-{address:x}',
            'calling': [], 'called': list(called), 'sig': f'int {name}(void)'}


def _import_pair(path: Path, old: dict, new: dict, names: dict) -> None:
    with ProjectService.open(path) as service:
        sides = {a.side: a.sha256 for a in service.project.artifacts}
        raw = {'old_meta': {'SHA256': sides['older']}, 'new_meta': {'SHA256': sides['newer']},
               'functions': {'added': [], 'deleted': [], 'modified': [
                   {'old': old, 'new': new, 'diff': '', 'diff_type': ['called'], 'ratio': 0.5,
                    'match_types': ['SymbolsHash']}]},
               'matches': {'name_matches': {k: [[v, ['SymbolsHash']]] for k, v in names.items()}, 'address_matches': {}}}
        file = path.parent / f'{path.name}.raw.json'
        file.write_text(json.dumps(raw), encoding='utf-8')
        service.import_diff(file)
        file.unlink()


def _create_series(inputs: list[Path], root: Path) -> dict:
    out = io.StringIO()
    with redirect_stdout(out):
        assert cli.main(['series', 'create', '--builds', *map(str, inputs), '--root', str(root), '--json']) == 0
    return json.loads(out.getvalue())['result']


def series_root(root: Path) -> tuple[Path, str]:
    """Three builds; F calls X in b0 and b1 and drops it in b2; Y is new in b1. Returns (root, chain id)."""
    inputs = []
    for i in range(3):
        path = root.parent / f'{root.name}-in' / f'b{i}.dll'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(synthetic_pe(i))
        inputs.append(path)
    first, second = (root / p['path'] for p in _create_series(inputs, root)['pair_projects'])
    names = {'X': 'X', 'Y': 'Y'}
    _import_pair(first, _function('F', 0x1000, ['X']), _function('F', 0x1010, ['X', 'Y']), names)
    _import_pair(second, _function('F', 0x1010, ['X', 'Y']), _function('F', 0x1020, ['Y']), names)
    _create_series(inputs, root)
    from patchtrace.nway import series as store
    return root, store.load(root / store.SERIES_FILE).chains[0].chain_id


class Result:
    def __init__(self, code: int, out: str, err: str) -> None:
        self.code, self.out, self.err = code, out, err

    @property
    def document(self) -> dict:
        return json.loads(self.out)


def run(*argv: str, cancel: threading.Event | None = None) -> Result:
    """`patchtrace graph ...` through the dispatcher with `cli.main`'s error mapping for CliError."""
    parser, handlers = _graph_parser()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            args = parser.parse_args(['graph', *argv])
            code = handlers['graph'](args, cancel or threading.Event())
        except cli.CliError as exc:
            print(f'error: {exc}', file=err)
            code = exc.code
    return Result(code, out.getvalue(), err.getvalue())
