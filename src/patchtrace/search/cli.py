"""`patchtrace search` (WB1 section 8; slice S5). Qt-free; reads only the project's saved data and a derived cache.

``main(argv)`` takes the arguments after ``search``. One ``enrichment-cli/1`` document on stdout with ``--json``;
progress and errors go to stderr. Exit codes: 0 usable result (or probe ran), 2 invalid query or arguments, no FTS5
or a locked project, 3 runtime or store failure or absence unproven, 4 no results with every requested group
indexed, 5 cancelled.

Hook for ``patchtrace/cli.py`` (integrator; ``search`` parses its own arguments, like ``kb``):

    from .search import cli as search_cli              # with the other dispatcher imports
    COMMANDS = (..., 'backend', 'search')               # the command tuple
    if argv[:1] == ['search']:                          # in main(), right after the stdout/stderr reconfigure loop
        return search_cli.main(argv[1:])
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Callable
from pathlib import Path

CLI_CONTRACT = 'enrichment-cli/1'
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
KINDS = ('function', 'code', 'asm', 'string', 'import', 'export', 'capability', 'rule', 'build', 'advisory', 'cve',
         'cwe', 'kb', 'note', 'finding')
MODES = ('auto', 'words', 'exact', 'prefix', 'substring', 'similar')
SORTS = ('relevance', 'change', 'name', 'address')
LOCKED = 'the project is open in another PatchTrace window or process; close the desktop and try again'
NO_ANCHORS = 'anchor search is not available in this build'
Opener = Callable[[Path], tuple[object, object]]  # path -> (ProjectService-shaped, attention port or None)


class SearchUsage(Exception):
    """Invalid arguments: exit 2."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SearchUsage(f'{self.prog}: {message}')


def _limit(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 200:
        raise argparse.ArgumentTypeError('must be between 1 and 200')
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog='patchtrace search', description='Search a project\'s saved data: names, strings, APIs, '
                     'code, notes and advisories. Offline; nothing is uploaded and no target is run.')
    parser.add_argument('project', nargs='?', type=Path, metavar='PROJECT')
    parser.add_argument('--query', metavar='TEXT')
    parser.add_argument('--kind', action='append', default=[], choices=KINDS, metavar='K')
    parser.add_argument('--side', choices=('older', 'newer', 'both'), default='both')
    parser.add_argument('--scope', choices=('indexed', 'changed'), default='indexed')
    parser.add_argument('--mode', choices=MODES, default='auto')
    parser.add_argument('--sort', choices=SORTS, default='relevance')
    parser.add_argument('--limit', type=_limit, default=50, metavar='N')
    parser.add_argument('--cursor', metavar='C')
    parser.add_argument('--no-group', action='store_true', help='one row per document, not per pairing')
    parser.add_argument('--no-expand', action='store_true', help='skip live pair expansion')
    parser.add_argument('--rebuild', action='store_true', help='rebuild the index segments first')
    parser.add_argument('--no-index-build', action='store_true', help='search finished segments only')
    parser.add_argument('--cache-dir', type=Path, metavar='D')
    parser.add_argument('--status', action='store_true', help='coverage, segment digests and staleness')
    parser.add_argument('--probe', action='store_true', help='runtime capabilities; needs no project')
    parser.add_argument('--anchors-from', metavar='CVE-ID')
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    return parser


def _emit(out, args, status: str, result, warnings=(), text: str = '') -> None:
    if args.json:
        doc = {'contract': CLI_CONTRACT, 'command': 'search', 'status': status, 'result': result,
               'warnings': list(warnings)}
        out.write(json.dumps(doc, sort_keys=True) + '\n')
    else:
        out.write(text + ('\n' if text and not text.endswith('\n') else ''))


def _open_project(path: Path) -> tuple[object, object]:
    from patchtrace.enrichment.pipeline import load_default
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.service import ProjectService
    try:
        service = ProjectService.open(path)
    except ValueError as exc:
        raise SearchUsage(LOCKED if 'locked' in str(exc) else 'the project cannot be opened') from None
    store = EnrichmentStore(service.store)
    return service, lambda project: load_default(store, project)


def _query_text(args) -> str:
    parts = [args.query or '', *(f'kind:{k}' for k in dict.fromkeys(args.kind))]
    if args.side != 'both':
        parts.append(f'side:{args.side}')
    if args.scope == 'changed':
        parts.append('scope:changed')
    return ' '.join(p for p in parts if p)


# --------------------------------------------------------------------------------------------- verbs

def _probe(args, out) -> int:
    from patchtrace.search import paths
    from patchtrace.search.capability import probe_capability
    from patchtrace.search.errors import SearchError
    capability = probe_capability()
    try:
        paths.ensure_writable(args.cache_dir or paths.default_cache_root())
        writable = True
    except SearchError:
        writable = False
    result = {**dataclasses.asdict(capability), 'usable': capability.usable, 'cache_root_writable': writable}
    text = (f'search-runtime: {"ok" if capability.usable else "FAIL"} sqlite={capability.sqlite_version} '
            f'fts5={capability.fts5} unicode61={capability.unicode61} trigram={capability.trigram} '
            f'rapidfuzz={capability.rapidfuzz_version or "absent"}/{capability.rapidfuzz_backend or "-"} '
            f'cache-writable={writable}')
    _emit(out, args, 'ok', result, text=text)
    return OK


def _status(args, out, service) -> int:
    rows = [row.model_dump(mode='json') for row in service.coverage()]
    result = {'index_key': service.build_request().index_key, 'coverage': rows}
    lines = [f'{r["group"]:<18} {r["status"]:<12} docs={r["docs"]} digest={r["digest16"] or "-"}' for r in rows]
    _emit(out, args, 'ok', result, text='\n'.join(lines))
    return OK


def _requested_indexed(result, plan) -> bool:
    """Every coverage entry the query asked about is indexed (an unavailable kind counts only when named)."""
    for entry in result.coverage:
        if plan.kinds and not set(entry.kinds) & set(plan.kinds):
            continue
        if plan.sides and entry.side and entry.side not in plan.sides:
            continue
        if entry.status == 'indexed' or (entry.status in ('unavailable', 'not-applicable') and not plan.kinds):
            continue
        return False
    return True


def exit_for(result, plan) -> int:
    """The section 8 table: absence is proven (4) only when every requested group is indexed."""
    status = result.status
    if status == 'cancelled':
        return CANCELLED
    if status == 'unsupported':
        return ENVIRONMENT
    if status in ('ok', 'too-broad', 'stale') or (status == 'partial' and result.hits):
        return OK
    if status == 'no-results' and _requested_indexed(result, plan):
        return NO_RESULTS
    return RUNTIME


def _text(result) -> str:
    lines = [f'{result.status}: {result.interpreted_as}']
    for hit in result.hits:
        first = hit.evidence[0]
        lines.append(f'{first.kind:<10} {first.side or "-":<7} {first.title}  [{first.locator.scheme}]')
    lines += [f'warning: {w}' for w in result.warnings]
    if result.cursor:
        lines.append(f'next page: --cursor {result.cursor}')
    return '\n'.join(lines)


def _search(args, out, err, service) -> int:
    from patchtrace.search.contracts import SearchRequest
    from patchtrace.search.errors import SearchError
    from patchtrace.search.query import parse_query
    if args.anchors_from:
        try:
            import patchtrace.search.anchors  # noqa: F401  (slice S10 adds the module)
        except ImportError:
            raise SearchError('PT-SEARCH-CAPABILITY', NO_ANCHORS) from None
    if not (args.query or args.kind):
        raise SearchError('PT-SEARCH-QUERY', 'give --query, or browse with --kind')
    plan = parse_query(_query_text(args), mode=args.mode)
    request = SearchRequest(plan=plan, sort=args.sort, limit=args.limit, cursor=args.cursor,
                            group=not args.no_group, expand=not args.no_expand)
    if args.rebuild and not args.no_index_build:
        print('indexing...', file=err)
        service.build(rebuild=True)
    result = service.search(request, build=not args.no_index_build)
    _emit(out, args, result.status, result.model_dump(mode='json'), result.warnings, _text(result))
    return exit_for(result, plan)


# ----------------------------------------------------------------------------------------------- main

def _run(args, out, err, opener: Opener, extra_specs) -> int:
    from patchtrace.search import paths
    from patchtrace.search.service import SearchService
    if args.probe:
        return _probe(args, out)
    if args.project is None:
        raise SearchUsage('a PROJECT is required (or use --probe)')
    if args.status and (args.query or args.kind):
        raise SearchUsage('--status takes no query')
    handle, attention = opener(args.project)
    try:
        cache = (paths.validate_cache_root(args.cache_dir.resolve(), Path(handle.root)) if args.cache_dir
                 else paths.default_cache_root())
        service = SearchService(handle, cache, attention=attention, extra_specs=extra_specs)
        return _status(args, out, service) if args.status else _search(args, out, err, service)
    finally:
        close = getattr(handle, 'close', None)
        if close is not None:
            close()


def main(argv: list[str] | None = None, *, opener: Opener | None = None, extra_specs=None,
         stdout=None, stderr=None) -> int:
    """Run ``search ...``. ``opener`` and ``extra_specs`` replace the production ports (tests)."""
    from patchtrace.search.errors import SearchError
    argv = list(sys.argv[1:] if argv is None else argv)
    out, err = stdout or sys.stdout, stderr or sys.stderr
    try:
        args = build_parser().parse_args(argv)
        return _run(args, out, err, opener or _open_project, extra_specs)
    except SearchUsage as exc:
        return _fail(out, err, argv, ENVIRONMENT, str(exc))
    except SearchError as exc:
        return _fail(out, err, argv, exc.exit_code, f'{exc.code}: {exc.message}')
    except KeyboardInterrupt:
        return _fail(out, err, argv, CANCELLED, 'cancelled', 'cancelled')
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    except Exception as exc:  # contract: an unexpected failure is a runtime error, never a traceback
        return _fail(out, err, argv, RUNTIME, type(exc).__name__)


def _fail(out, err, argv, code: int, message: str, status: str = 'failed') -> int:
    print(message if status == 'cancelled' else f'error: {message}', file=err)
    if '--json' in argv:
        doc = {'contract': CLI_CONTRACT, 'command': 'search', 'status': status, 'result': None, 'warnings': []}
        if status == 'failed':
            doc['error'] = message
        out.write(json.dumps(doc, sort_keys=True) + '\n')
    return code
