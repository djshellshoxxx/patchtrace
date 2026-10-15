"""`patchtrace unified run|show|explain|status` and the hidden `_worker` (07 s10, s12).

`patchtrace/cli.py` only registers this module (`register`) and dispatches to it (`dispatch`). Importing it is cheap
(argparse only) because the parser is built on every CLI call; everything else is imported when a verb runs. Never
imports Qt. Exit codes follow the existing contract: 0 ok, 2 invalid argument or environment or nothing runnable,
3 runtime failure or a partial result, 4 zero rows after filtering (or `run --fail-on-none`), 5 cancelled. In
`--json` mode stdout carries exactly one `enrichment-cli/1` document and the first warning is the standing note
that unified results are experimental, derived and ordinal.

`show` and `explain` print what the Unified tab shows: both go through the Qt-free read model (`read_model`,
`read_text`), so the order (contested, material, review, ...), the badges, the per-source cells and the section texts
are the window's, and the default view collapses unchanged and structurally proven cosmetic rows with a visible
count (U-03; `--all` or `--change` lists them).
"""
from __future__ import annotations

import argparse
import re
import sys
import threading
from pathlib import Path

LABEL = 'experimental, derived, ordinal'
NOTE = 'Unified results are experimental, derived and ordinal; the Ghidriff result stays the primary record.'
NO_EXTRACT = ('extraction is not available in this build; the result uses stored engine outputs only '
              '(no instruction-level facts)')    # said when no ProgramIR is placed for the project (S0 mode)
SOURCES = ('ghidriff', 'bindiff', 'rz-diff', 'manual')
DECISIONS = ('matched', 'tentative', 'candidate', 'contested', 'ambiguous', 'older-only', 'newer-only', 'unknown')
MATERIALITIES = ('unchanged', 'cosmetic', 'material', 'review', 'unknown', 'not-applicable')
CLASSES = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref', 'struct-offset',
           'cfg', 'block-added', 'block-removed', 'string', 'size-only', 'refcount-only', 'address-only',
           'register-only', 'layout-only', 'name-only', 'frame', 'eh', 'unknown')
VERBS = ('run', 'show', 'explain', 'status')
PREFIX_MIN = 8
SOURCE_ID = re.compile(r'[a-z][a-z0-9-]{1,31}')
NATIVE_NOTE = 'Native values are engine-specific and never combined.'
TIMEOUT_MIN, TIMEOUT_MAX = 60, 86_400    # L-34, copied so that argparse can refuse early; a test keeps them equal
EXIT_CODES = ('Exit codes: 0 ok; 2 invalid argument or environment, or nothing runnable; 3 runtime failure or '
              'partial result; 5 cancelled.')
JSON_NOTE = 'With --json stdout carries exactly one enrichment-cli/1 document, also when the command fails.'


def _source_id(text: str) -> str:
    if not SOURCE_ID.fullmatch(text):
        raise argparse.ArgumentTypeError('a source id is lower-case letters, digits and hyphens, for example bindiff')
    return text


def _check_timeout(seconds: int) -> None:
    from ..cli import ENVIRONMENT, CliError
    if not TIMEOUT_MIN <= seconds <= TIMEOUT_MAX:
        raise CliError(ENVIRONMENT, f'--timeout must be {TIMEOUT_MIN} to {TIMEOUT_MAX} seconds')


def register(sub, common, handlers) -> None:
    """Add the `unified` command to the top-level parser and its handler to `handlers`."""
    unified = sub.add_parser('unified', help=f'unified match analysis ({LABEL}); the Ghidriff result stays primary',
                             description=f'Derived, ordinal fusion of the stored engine outputs ({LABEL}). It never '
                                         'changes the project, the Ghidriff results or any other stored result. '
                                         f'{EXIT_CODES} 4 is for `show` with no row listed. {JSON_NOTE}')
    actions = unified.add_subparsers(dest='action', required=True, parser_class=type(unified),
                                     metavar='{' + ','.join(VERBS) + '}')
    run = common(actions.add_parser('run', help='compute and store the unified result for this project',
                                    epilog=f'{EXIT_CODES} 4 only with --fail-on-none. {JSON_NOTE}'))
    run.add_argument('project', type=Path)
    run.add_argument('--no-extract', action='store_true',
                     help='S0 mode: use the stored engine outputs only, even when a ProgramIR is placed for the '
                          'project (the ladder and the instruction-level facts need one)')
    run.add_argument('--no-residual', action='store_true',
                     help='backup B-07: skip the residual passes P16-P19 of the ladder (another result, another id)')
    run.add_argument('--no-decompile', action='store_true',
                     help='skip the on-demand decompile of review pairs (the constant-only pairs stay in review)')
    run.add_argument('--python', default='', help='external Python executable of the extractor (with --ghidra-dir '
                                                   'it enables the decompile of review pairs)')
    run.add_argument('--ghidra-dir', default='', help='Ghidra installation root (with --python)')
    run.add_argument('--sources', default=','.join(SOURCES), metavar='LIST',
                     help='comma list of ' + ', '.join(SOURCES) + ' (default: all)')
    isolation = run.add_mutually_exclusive_group()
    isolation.add_argument('--isolate', dest='isolate', action='store_true', default=True,
                           help='run the worker as a capped child process (default)')
    isolation.add_argument('--in-process', dest='isolate', action='store_false',
                           help='run in this process (tests and debugging)')
    run.add_argument('--timeout', type=int, default=3600, help=f'worker seconds ({TIMEOUT_MIN}..{TIMEOUT_MAX})')
    run.add_argument('--refresh', action='store_true', help='recompute even when a stored result has these inputs')
    run.add_argument('--fail-on-none', action='store_true', help='exit 4 when no row is material or review')
    show = common(actions.add_parser('show', help='list rows of the current unified result, most important first',
                                     epilog=f'{EXIT_CODES} 4 no row listed after filtering. {JSON_NOTE}'))
    show.add_argument('project', type=Path)
    show.add_argument('--decision', action='append', choices=DECISIONS, default=[], metavar='DECISION')
    show.add_argument('--change', action='append', choices=MATERIALITIES, default=[], metavar='CHANGE',
                      help='materiality: ' + ', '.join(MATERIALITIES) + ' (listing one always shows its rows)')
    show.add_argument('--class', dest='classes', action='append', choices=CLASSES, default=[], metavar='CLASS')
    show.add_argument('--source', action='append', type=_source_id, default=[], metavar='SOURCE',
                      help='only rows with a record from this source (repeatable)')
    show.add_argument('--search', default='', metavar='TEXT',
                      help='function names or hexadecimal RVAs, with or without 0x')
    show.add_argument('--all', action='store_true',
                      help='also list the unchanged rows and the cosmetic rows with a structural proof, which are '
                           'collapsed by default')
    show.add_argument('--limit', type=int, default=200, help='rows printed (default 200; totals are always given)')
    explain = common(actions.add_parser('explain', help='atoms, contest, facts and provenance of one row'))
    explain.add_argument('project', type=Path)
    explain.add_argument('--row', required=True, metavar='ROW_ID', help='a row id or a prefix of at least 8 digits')
    status = common(actions.add_parser('status', help='current result, staleness, sources and recent runs'))
    status.add_argument('project', type=Path)
    worker = actions.add_parser('_worker')  # no `help=`: argparse then leaves it out of every help listing
    worker.add_argument('--request')
    worker.add_argument('--result-dir')
    worker.add_argument('--self-check', action='store_true')
    handlers['unified'] = dispatch


def dispatch(args, cancel: threading.Event) -> int:
    if args.action == '_worker':
        return _worker(args)
    from .limits import UnifiedError
    handler = {'run': _run, 'show': _show, 'explain': _explain, 'status': _status}[args.action]
    try:
        return handler(args, cancel)
    except UnifiedError as error:
        raise _cli_error(error) from None


def _cli_error(error):
    from ..cli import CliError
    reason = f' [{error.reason}]' if error.reason else ''
    return CliError(error.exit_code, f'{error.code}: {error.message}{reason}')


def _worker(args) -> int:
    from . import worker
    if args.self_check:
        return worker.main(['--self-check'])
    if not args.request or not args.result_dir:
        print(worker.USAGE, file=sys.stderr)
        return worker.EXIT_USAGE
    return worker.main(['--request', args.request, '--result-dir', args.result_dir])


def _t(value: object, limit: int = 200) -> str:
    """Untrusted text for a terminal: controls and bidi characters removed, one line, bounded."""
    from ..secondary.evidence_view import sanitize_text
    return sanitize_text(str('' if value is None else value).replace('\n', ' ').replace('\t', ' '), limit)


def _sources(text: str) -> tuple[str, ...]:
    from ..cli import ENVIRONMENT, CliError
    chosen = tuple(dict.fromkeys(part.strip() for part in text.split(',') if part.strip()))
    bad = [s for s in chosen if s not in SOURCES]
    if not chosen or bad:
        raise CliError(ENVIRONMENT, f'--sources takes a comma list of {", ".join(SOURCES)}')
    return chosen


def _progress(event) -> None:
    total = '' if event.total is None else f'/{event.total}'
    print(f'unified: {event.stage} {event.done}{total}', file=sys.stderr)


def _counts_text(counts) -> str:
    decisions = counts.decisions.model_dump()
    changes = counts.materiality.model_dump()
    return (f'rows: {sum(decisions.values())} ('
            + ', '.join(f'{k.replace("_", "-")} {v}' for k, v in decisions.items() if v) + ')\n'
            + 'change: ' + ', '.join(f'{k.replace("_", "-")} {v}' for k, v in changes.items() if v))


# --- run ------------------------------------------------------------------------------------------------------------

def _run(args, cancel) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, _emit, _open
    from . import pipeline
    from .limits import UnifiedError
    _check_timeout(args.timeout)
    if bool(args.python) != bool(args.ghidra_dir):
        raise CliError(ENVIRONMENT, '--python and --ghidra-dir go together')
    backend = None
    if args.python:
        from ..backend import BackendConfig
        backend = BackendConfig(python_executable=args.python, ghidra_dir=args.ghidra_dir, timeout_seconds=args.timeout)
    options = pipeline.UnifiedOptions(sources=_sources(args.sources), isolate=args.isolate, timeout_s=args.timeout,
                                      refresh=args.refresh, use_ir=not args.no_extract,
                                      residual=not args.no_residual, decompile=not args.no_decompile,
                                      backend=backend)
    service = _open(args.project)
    try:
        try:
            report = pipeline.run_unified(service, options, cancel=cancel, emit=_progress)
        except UnifiedError as error:
            if error.code == 'PT-UNIFIED-CANCEL':
                _emit(args, 'unified run', 'cancelled', None, [NOTE], '')
                return CANCELLED
            raise
    finally:
        service.close()
    result = {'result_id': report.result_id, 'status': report.result_status, 'cached': report.status == 'cached',
              'mode': report.mode, 'counts': report.counts.model_dump(mode='json'),
              'stages': [{'stage': s.stage, 'status': s.status, 'duration_ms': s.duration_ms} for s in report.stages],
              'limitations': list(report.limitations), 'sources': list(report.sources),
              'selected_sources': list(report.selected), 'stale': False}
    text = (f'unified run: {report.result_status}{" (stored result reused)" if report.status == "cached" else ""} '
            f'({LABEL})\nresult: {report.result_id[:16]}\n{_counts_text(report.counts)}\n'
            f'sources: {", ".join(report.sources)}\nlimitations: {", ".join(report.limitations) or "none"}')
    extra = [NO_EXTRACT] if report.mode == 's0' and not args.no_extract else []
    _emit(args, 'unified run', report.result_status, result, [NOTE, *extra, *report.warnings], text)
    material = report.counts.materiality.material + report.counts.materiality.review
    if report.result_status == 'partial':
        return RUNTIME
    return NO_RESULTS if args.fail_on_none and not material else OK


# --- reading verbs --------------------------------------------------------------------------------------------------

def _plan_or_none(service):
    from . import pipeline
    from .limits import UnifiedError
    try:
        return pipeline.make_plan(service), None
    except UnifiedError as error:
        return None, error


def _changed_inputs(loaded, plan) -> list[str]:
    from . import read_model
    return read_model.changed_inputs(loaded, plan)


def _require_result(loaded, args) -> list[str]:
    """Warnings for a stale result; a missing or unusable one is an error (exit 2 or 3)."""
    from ..cli import ENVIRONMENT, RUNTIME, CliError
    if loaded.state == 'none':
        raise CliError(ENVIRONMENT, f'no unified result yet: run `patchtrace unified run {args.project}` first')
    if loaded.state == 'invalid' or loaded.manifest is None or loaded.directory is None:
        raise CliError(RUNTIME, f'the stored unified result is unusable [{loaded.reason or "invalid"}]: run again '
                                'with --refresh')
    return ['the stored result is stale: its inputs changed; run again to refresh it'] if loaded.state == 'stale' else []


def _open_request(args):
    """Open the project, read the plan and the stored pointer row (the only database access), and close it again."""
    from ..cli import RUNTIME, CliError, _open
    from . import read_model
    service = _open(args.project)
    try:
        request = read_model.request_from_service(service)
    finally:
        service.close()
    if request.error:
        raise CliError(RUNTIME, request.error)
    return request, _require_result(request.loaded, args)


def _load_view(request, cancel):
    """The read model of the stored result: an unusable one is a runtime error (3), a cancel is exit 5."""
    from ..cli import RUNTIME, CliError
    from . import read_model
    try:
        vm = read_model.load_unified(request, cancel.is_set)
    except read_model.Cancelled:
        raise KeyboardInterrupt from None
    if vm.error:
        raise CliError(RUNTIME, vm.error)
    return vm


def _side_json(side) -> list[dict]:
    return [{'rva': s.rva, 'name': _t(s.name, 256) if s.name else None, 'kind': s.kind} for s in side]


def _row_json(row) -> dict:
    return {'row_id': row.row_id, 'decision': row.decision, 'materiality': row.materiality,
            'older': _side_json(row.older), 'newer': _side_json(row.newer),
            'change_classes': list(row.change_classes), 'support': [{'component': s.component, 'tier': s.tier}
                                                                    for s in row.support],
            'contest': None if row.contest is None else row.contest.strength,
            'hints': [_t(h) for h in row.hints], 'flags': list(row.flags)}


def _view_json(vm, row) -> dict:
    """What the read model adds to a stored row: labels, badge words, the change text and each source's own cell."""
    return {'function': row.function_label, 'addresses': row.address_label, 'decision_text': row.decision_text,
            'glyph': row.glyph, 'change_text': row.change_text, 'proof': row.proof, 'tier': row.tier or None,
            'edit_group': row.edit_group, 'collapsed': row.collapsed,
            'cells': [{'source': info.source, 'kind': cell.kind, 'text': cell.text}
                      for info, cell in zip(vm.sources, row.cells, strict=True)]}


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[:max(0, width - 3)] + '...'


def _table(vm, rows) -> list[str]:
    """Aligned text table: the id prefix to give to `explain --row`, the badge, the change, then one column per
    present source with that source's own words (never merged)."""
    from . import read_model
    head = ['ROW', 'DECISION', 'CHANGE', 'FUNCTION', 'ADDRESSES', *(info.display.upper() for info in vm.sources)]
    body = [[r.row_id[:12], read_model.BADGES[r.decision], r.change_text, r.function_label, r.address_label,
             *(cell.text for cell in r.cells)] for r in rows]
    widths = [12, 15, 34, 30, 26, *(26 for _ in vm.sources)]
    return [' '.join(_fit(cell, w).ljust(w) for cell, w in zip(line, widths, strict=True)).rstrip()
            for line in [head, *body]]


def _select(args, vm) -> tuple[list[int], int]:
    """(indices of the rows to list, rows left out only because they are collapsed by default). `--all` and an
    explicit `--change` list collapsed rows, so nothing is then left out."""
    from . import read_model

    def matching(collapsed: bool) -> list[int]:
        return read_model.filter_rows(vm.rows, decisions=args.decision or None, materialities=args.change or None,
                                      classes=args.classes or None, sources=args.source or None, search=args.search,
                                      show_collapsed=collapsed)
    listed = matching(args.all)
    return listed, len(matching(True)) - len(listed)


def _show(args, cancel) -> int:
    from ..cli import ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, _emit
    from . import read_model
    if args.limit < 0:
        raise CliError(ENVIRONMENT, '--limit takes a whole number of rows, 0 or more')
    request, warnings = _open_request(args)
    vm = _load_view(request, cancel)
    listed, hidden = _select(args, vm)
    shown = [vm.rows[i] for i in listed[:max(0, args.limit)]]
    records = read_model.records_for(vm, shown)       # a damaged part is a typed error: exit 3 through `dispatch`
    if len(records) != len(shown):
        raise CliError(RUNTIME, 'a listed row could not be read [row-missing]: run again with --refresh')
    manifest, total = vm.manifest, vm.counts['rows']
    result = {'result_id': manifest.result_id, 'state': request.loaded.state, 'stale': request.loaded.state == 'stale',
              'changed_inputs': list(request.changed_inputs), 'status': manifest.status, 'total': total,
              'filtered': len(listed), 'hidden': hidden, 'counts': dict(vm.counts),
              'evidence_classes': dict(vm.evidence_classes),
              'sources': [{'source': i.source, 'display': i.display, 'unit': i.unit_caption, 'version': i.version}
                          for i in vm.sources],
              'rows': [_row_json(records[r.row_id].match) | _view_json(vm, r) for r in shown]}
    lines = [f'unified show: result {manifest.result_id[:16]} {manifest.status}, {total} rows, {len(listed)} match, '
             f'{len(shown)} shown ({LABEL})', read_model.summary_text(vm, show_collapsed=bool(args.all or args.change)),
             read_model.header_text(vm), '', *_table(vm, shown)]
    if hidden:
        lines.append(f'{hidden} more rows are collapsed by default (unchanged, or cosmetic with a structural proof); '
                     'list them with --all or --change')
    if len(listed) > len(shown):
        lines.append(f'{len(listed) - len(shown)} more rows match; raise --limit to list them')
    _emit(args, 'unified show', manifest.status, result, [NOTE, *warnings], '\n'.join([*lines, NATIVE_NOTE]))
    return OK if listed else NO_RESULTS


def _explain(args, cancel) -> int:
    from ..cli import ENVIRONMENT, OK, CliError, _emit
    from . import read_model, read_text
    prefix = args.row.strip().lower()
    if len(prefix) < PREFIX_MIN or any(c not in '0123456789abcdef' for c in prefix):
        raise CliError(ENVIRONMENT, f'--row takes at least {PREFIX_MIN} hexadecimal digits of a row id')
    request, warnings = _open_request(args)
    loaded = request.loaded
    manifest = loaded.manifest
    records = read_text.SidecarRecords(loaded.directory, manifest)   # a damaged part is a typed error: exit 3
    found = records.find(prefix, None)
    if not found:
        raise CliError(ENVIRONMENT, f'no row starts with {_t(prefix, 70)}')
    if len(found) > 1:
        raise CliError(ENVIRONMENT, f'{len(found)} rows start with {_t(prefix, 70)}: give more digits')
    record = records.get(found)[found[0]]
    notes = ([read_text.STALE_NOTE.format(reason=read_model.stale_reason_text(request.changed_inputs))]
             if loaded.state == 'stale' else [])
    match, facts = record.match, record.facts
    provenance = {'result_id': manifest.result_id, 'status': manifest.status, 'engine_version': manifest.engine_version,
                  'sources': [{'source': s.source, 'version': _t(s.version, 64)} for s in manifest.sources],
                  'limitations': [_t(x) for x in manifest.limitations]}
    detail = read_text.detail_text(manifest, record, notes=notes)
    result = {'row': match.model_dump(mode='json'), 'facts': None if facts is None else facts.model_dump(mode='json'),
              'provenance': provenance, 'state': loaded.state, 'detail': detail}
    text = f'row {match.row_id[:16]}: {match.decision}, change {match.materiality} ({LABEL})\n{detail}'
    _emit(args, 'unified explain', manifest.status, result, [NOTE, *warnings], text)
    return OK


def _ir_status(manifest) -> dict:
    """The ProgramIR the current result was computed from (S0 mode has none)."""
    if manifest is None or manifest.ir_older is None:
        return {'available': False, 'reason': 's0-mode'}
    def side(ref) -> dict:
        return {'ir_key': ref.ir_key, 'functions': ref.functions, 'producer_mode': ref.producer_mode}
    return {'available': True, 'older': side(manifest.ir_older), 'newer': side(manifest.ir_newer)}


def _status(args, cancel) -> int:
    from ..cli import OK, _emit, _open
    from . import keys, pipeline
    service = _open(args.project)
    try:
        plan, plan_error = _plan_or_none(service)
        loaded = pipeline.load_current(service, plan)
        runs = pipeline.recent_runs(service, 5)
        changed = _changed_inputs(loaded, plan)
    finally:
        service.close()
    manifest = loaded.manifest
    result = {
        'state': loaded.state, 'reason': loaded.reason, 'result_id': None if manifest is None else manifest.result_id,
        'status': None if manifest is None else manifest.status,
        'counts': None if manifest is None else manifest.counts.model_dump(mode='json'),
        'sources': [] if manifest is None else [{'source': s.source, 'version': _t(s.version, 64)}
                                                for s in manifest.sources],
        'limitations': [] if manifest is None else [_t(x) for x in manifest.limitations],
        'changed_inputs': changed, 'planned_result_id': None if plan is None else plan.result_id,
        'plan_error': None if plan_error is None else (plan_error.reason or plan_error.code),
        'ir': _ir_status(manifest), 'engine_version': keys.ENGINE_VERSION,
        'runs': [{'started_utc': r.started_utc, 'status': r.status, 'error_code': r.error_code,
                  'result_id': r.result_id} for r in runs]}
    lines = [f'unified status: {loaded.state}' + (f' [{loaded.reason}]' if loaded.reason else '') + f' ({LABEL})']
    if manifest is not None:
        lines += [f'result: {manifest.result_id[:16]} {manifest.status}', _counts_text(manifest.counts),
                  'sources: ' + ', '.join(f'{s.source} {_t(s.version, 64)}' for s in manifest.sources),
                  'limitations: ' + (', '.join(_t(x) for x in manifest.limitations) or 'none')]
    if changed:
        lines.append('inputs changed since that result: ' + ', '.join(changed))
    if plan_error is not None:
        lines.append(f'planning: {plan_error.code} [{plan_error.reason}]')
    ir = result['ir']
    lines.append('instruction-level data: ProgramIR of both sides ('
                 f'{ir["older"]["functions"]} and {ir["newer"]["functions"]} functions)' if ir['available']
                 else 'instruction-level data: not extracted in this mode')
    lines += [f'run {r.started_utc} {r.status}' + (f' {r.error_code}' if r.error_code else '') for r in runs]
    _emit(args, 'unified status', 'complete', result, [NOTE], '\n'.join(lines))
    return OK
