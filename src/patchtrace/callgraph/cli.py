"""`patchtrace graph neighbours|delta|leads|paths|export|series` (WB2 section 8.1). Qt-free, read-only.

`patchtrace/cli.py` only registers this module (`register`) and dispatches to it (`dispatch`). Output uses the
`enrichment-cli/1` envelope; exit codes: 0 results, 2 invalid arguments or environment (an unknown or unindexed
function included), 3 runtime failure or a truncated/partial result, 4 complete with zero entries, 5 cancelled.
Everything heavy is imported when a verb runs."""
from __future__ import annotations

import threading
from pathlib import Path

from .limits import GraphError
from .text import one_line

VERBS = ('neighbours', 'delta', 'leads', 'paths', 'export', 'series')
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
MAX_JSON_BYTES = 16 * 1024 * 1024  # GL-13
_DIRECTIONS = {'callers': 'in', 'callees': 'out', 'both': 'both'}
_EXIT = {'PT-GRAPH-INPUT': ENVIRONMENT, 'PT-GRAPH-CANCEL': CANCELLED}
NOTE = ('Call lists are the distinct direct calls recorded by Ghidra for the changed functions. Missing is '
        'unknown, not removed.')


def _int_range(low: int, high: int):
    def parse(value: str) -> int:
        import argparse
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f'must be {low}..{high}')
        return number
    parse.__name__ = f'int_{low}_{high}'
    return parse


def register(sub, common, handlers) -> None:
    """Add the `graph` command to the top-level parser and its handler to `handlers`."""
    graph = sub.add_parser('graph', help='call-graph explorer over stored Ghidriff call lists (read-only)')
    actions = graph.add_subparsers(dest='action', required=True, parser_class=type(graph),
                                   metavar='{' + ','.join(VERBS) + '}')
    nb = common(actions.add_parser('neighbours', help='callers and callees around one function'))
    nb.add_argument('project', type=Path)
    which = nb.add_mutually_exclusive_group(required=True)
    which.add_argument('--match', metavar='ID')
    which.add_argument('--function', metavar='ID')
    which.add_argument('--name', metavar='LABEL')
    nb.add_argument('--side', choices=('older', 'newer', 'both'), default='both')
    nb.add_argument('--direction', choices=tuple(_DIRECTIONS), default='both')
    nb.add_argument('--depth', type=_int_range(1, 4), default=1)
    nb.add_argument('--max-nodes', type=_int_range(1, 500), default=100)
    nb.add_argument('--max-edges', type=_int_range(1, 2000), default=250)
    delta = common(actions.add_parser('delta', help='callee changes of modified pairs'))
    delta.add_argument('project', type=Path)
    delta.add_argument('--match', action='append', default=[], metavar='ID')
    delta.add_argument('--limit', type=_int_range(1, 100_000), default=100)
    leads = common(actions.add_parser('leads', help='ordinal graph signals per changed function'))
    leads.add_argument('project', type=Path)
    leads.add_argument('--limit', type=_int_range(1, 100_000), default=50)
    paths = common(actions.add_parser('paths', help='observed call paths over the stored call lists'))
    paths.add_argument('project', type=Path)
    paths.add_argument('--from', dest='source', required=True, metavar='FUNCTION')
    paths.add_argument('--to', dest='target', required=True, metavar='API|FUNCTION')
    paths.add_argument('--side', choices=('older', 'newer'), default='newer')
    paths.add_argument('--max-paths', type=_int_range(1, 5), default=5)
    export = common(actions.add_parser('export', help='write one match neighbourhood as DOT or JSON'))
    export.add_argument('project', type=Path)
    export.add_argument('--match', required=True, metavar='ID')
    export.add_argument('--format', choices=('dot', 'json'), required=True)
    export.add_argument('--output', type=Path, required=True, metavar='FILE')
    export.add_argument('--overwrite', action='store_true')
    export.add_argument('--depth', type=_int_range(1, 4), default=1)
    series = common(actions.add_parser('series', help='how a function neighbourhood changes across a series'))
    series.add_argument('root', type=Path)
    series.add_argument('--chain', required=True, metavar='ID')
    handlers['graph'] = dispatch


def dispatch(args, cancel: threading.Event) -> int:
    handler = {'neighbours': _neighbours, 'delta': _delta, 'leads': _leads, 'paths': _paths, 'export': _export,
               'series': _series}[args.action]
    try:
        return handler(args, cancel)
    except GraphError as error:
        raise _cli_error(error) from None


def _cli_error(error: GraphError):
    from ..cli import CliError
    return CliError(_EXIT.get(error.code, RUNTIME), f'{error.code}: {error.message}')


def _finish(args, partial: bool, result: dict, warnings: list[str], text: str, empty: bool = False) -> int:
    import json

    from ..cli import CliError, _emit
    if len(json.dumps(result, sort_keys=True)) > MAX_JSON_BYTES:
        raise CliError(RUNTIME, 'PT-GRAPH-LIMIT: the result exceeds 16 MiB; use --limit')
    status = 'partial' if partial else 'complete'
    _emit(args, f'graph {args.action}', status, result, warnings, text)
    return RUNTIME if partial else NO_RESULTS if empty else OK


def _analysis(args, cancel: threading.Event):
    from .cli_ports import Analysis
    return Analysis(args.project, cancel.is_set)


def _dump(models) -> list[dict]:
    return [m.model_dump(mode='json') for m in models]


def _t(value: object) -> str:
    return one_line(value)


def _focus_nodes(args, analysis, side: str) -> list[str]:
    """Node ids to centre on for one side, from --match, --function or --name."""
    from .query import find_node
    snap, data = analysis.snapshot, analysis.data
    if args.name is not None:
        try:
            return [find_node(snap, side, args.name).id]
        except GraphError as error:
            if 'share the label' in error.message:
                raise
            return []
    if args.match is not None:
        labels = [e.label for e in data.side_entries(side) if e.match_id == args.match]
    else:
        labels = [e.label for e in data.side_entries(side) if e.function_id == args.function]
    return [find_node(snap, side, label).id for label in labels[:1]]


def _neighbours(args, cancel) -> int:
    from .query import neighbourhood
    analysis = _analysis(args, cancel)
    sides = ('older', 'newer') if args.side == 'both' else (args.side,)
    views = []
    for side in sides:
        focus = _focus_nodes(args, analysis, side)
        if focus:
            views.append(neighbourhood(analysis.snapshot, side, focus, _DIRECTIONS[args.direction], args.depth,
                                       args.max_nodes, args.max_edges, cancel.is_set))
    if not views:
        raise GraphError('PT-GRAPH-INPUT', 'function-not-indexed: the function is not in the stored change set, '
                         'so no call lists are stored for it')
    edges = sum(len(v.edges) for v in views)
    lines = [f'{v.side}: {len(v.nodes)} nodes, {len(v.edges)} edges' + (' (capped)' if v.truncated else '')
             for v in views]
    for view in views:
        names = {n.id: _t(n.label) for n in view.nodes}
        lines += [f'  {view.side}: {names[e.src]} -> {names[e.dst]}' for e in view.edges]
    return _finish(args, any(v.truncated for v in views), {'views': _dump(views)}, [NOTE], '\n'.join(lines),
                 empty=edges == 0)


def _delta(args, cancel) -> int:
    from .delta import compute_delta, compute_deltas
    from .groups import build_groups
    analysis = _analysis(args, cancel)
    snap, ctx = analysis.snapshot, analysis.context
    deltas = ([compute_delta(snap, match, ctx) for match in dict.fromkeys(args.match)] if args.match
              else list(compute_deltas(snap, ctx, cancel.is_set)))
    shown = deltas[:args.limit]
    lines = [f'{len(shown)} of {len(deltas)} deltas']
    for item in shown:
        counts = sum(c.cls != 'same-link' for c in item.changes)
        lines.append(f'  {_t(item.newer_label or item.older_label)}: {item.state}, {counts} changed callees'
                     + (f', {item.downgrade}' if item.downgrade != 'none' else ''))
    result = {'total': len(deltas), 'shown': len(shown), 'deltas': _dump(shown),
              'groups': _dump(build_groups(deltas))}
    return _finish(args, False, result, [NOTE], '\n'.join(lines), empty=not deltas)


def _leads(args, cancel) -> int:
    from .delta import compute_deltas
    from .leads import build_leads
    analysis = _analysis(args, cancel)
    deltas = compute_deltas(analysis.snapshot, analysis.context, cancel.is_set)
    leads = build_leads(analysis.snapshot, deltas, analysis.entries, cancel.is_set)
    shown = leads[:args.limit]
    names = {d.match_id: _t(d.newer_label or d.older_label) for d in deltas}
    lines = [f'{len(shown)} of {len(leads)} leads']
    lines += [f'  {names.get(lead.match_id, lead.match_id)}: {lead.signals[0].meaning}' for lead in shown]
    return _finish(args, False, {'total': len(leads), 'shown': len(shown), 'leads': _dump(shown)}, [NOTE],
                 '\n'.join(lines), empty=not leads)


def _targets(analysis, side: str, target: str) -> list[str]:
    """Node ids for `--to`: an exact function label, else every import whose API name equals `target`."""
    from .labels import parse_external
    from .query import find_node
    graph = analysis.snapshot.side(side)
    try:
        return [find_node(analysis.snapshot, side, target).id]
    except GraphError as error:
        if 'share the label' in error.message:
            raise
    found = [n for n in graph.nodes if n.kind == 'external' and (parsed := parse_external(n.label)) is not None
             and target in {parsed.name, parsed.key}]
    return [n.id for n in sorted(found, key=lambda n: (n.label, n.id))]


def _paths(args, cancel) -> int:
    from .paths import find_paths
    from .query import find_node
    analysis = _analysis(args, cancel)
    source = find_node(analysis.snapshot, args.side, args.source).id
    targets = _targets(analysis, args.side, args.target)
    if not targets:
        raise GraphError('PT-GRAPH-INPUT', 'function-not-indexed: no function or import has that name in the '
                         'stored call lists')
    results = []
    for target in targets:
        found = find_paths(analysis.snapshot, args.side, source, target, cancel.is_set)
        results.append(found.model_copy(update={'paths': found.paths[:args.max_paths]}))
    count = sum(len(r.paths) for r in results)
    lines = [f'{count} observed paths']
    for result in results:
        lines += [f'  {" -> ".join(_t(result.labels[n]) for n in path)}' for path in result.paths]
        lines.append(f'  {result.note}')
    return _finish(args, any(r.truncated for r in results), {'results': _dump(results)}, [NOTE], '\n'.join(lines),
                 empty=count == 0)


def _export(args, cancel) -> int:
    from .dot import render_dot
    from .export_json import build_export, to_json, write_export
    analysis = _analysis(args, cancel)
    export = build_export(analysis.snapshot, args.match, args.depth, cancel.is_set)
    text = render_dot(export) if args.format == 'dot' else to_json(export)
    target = write_export(args.output, text, args.format, args.overwrite)
    nodes = sum(len(v.nodes) for v in (export.older, export.newer) if v)
    edges = sum(len(v.edges) for v in (export.older, export.newer) if v)
    result = {'path': target.name, 'format': args.format, 'bytes': len(text.encode('utf-8')), 'nodes': nodes,
              'edges': edges, 'correspondence': len(export.correspondence), 'truncated': export.truncated}
    return _finish(args, export.truncated, result, [NOTE], f'wrote {target.name}: {nodes} nodes, {edges} edges')


def _series(args, cancel) -> int:
    from .cli_ports import evolution_for_chain
    evolution, warnings = evolution_for_chain(Path(args.root), args.chain, cancel.is_set)
    lines = [f'{len(evolution.lineages)} callee lineages across {len(evolution.builds)} builds']
    lines += [f'  {"  ".join(_t(label) if label else "-" for label in item.labels_by_ordinal)}'
              f'  [{" ".join(item.cells)}]' for item in evolution.lineages]
    partial = evolution.truncated or bool(warnings)
    return _finish(args, partial, {'evolution': evolution.model_dump(mode='json')}, [NOTE, *warnings],
                 '\n'.join(lines), empty=not evolution.lineages)
