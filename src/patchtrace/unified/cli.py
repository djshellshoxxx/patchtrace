"""`patchtrace unified run|show|explain|status` and the hidden `_worker` (07 s10, s12).

`patchtrace/cli.py` only registers this module (`register`) and dispatches to it (`dispatch`). Importing it is cheap
(argparse only) because the parser is built on every CLI call; everything else is imported when a verb runs. Never
imports Qt. Exit codes follow the existing contract: 0 ok, 2 invalid argument or environment or nothing runnable,
3 runtime failure or a partial result, 4 zero rows after filtering (or `run --fail-on-none`), 5 cancelled. In
`--json` mode stdout carries exactly one `enrichment-cli/1` document and the first warning is the standing note
that unified results are experimental, derived and ordinal.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

LABEL = 'experimental, derived, ordinal'
NOTE = 'Unified results are experimental, derived and ordinal; the Ghidriff result stays the primary record.'
NO_EXTRACT = ('extraction is not available in this build; the result uses stored engine outputs only '
              '(no instruction-level facts)')
SOURCES = ('ghidriff', 'bindiff', 'rz-diff', 'manual')
DECISIONS = ('matched', 'tentative', 'candidate', 'contested', 'ambiguous', 'older-only', 'newer-only', 'unknown')
MATERIALITIES = ('unchanged', 'cosmetic', 'material', 'review', 'unknown', 'not-applicable')
CLASSES = ('constant', 'comparison', 'condition', 'callee', 'call-added', 'call-removed', 'data-ref', 'struct-offset',
           'cfg', 'block-added', 'block-removed', 'string', 'size-only', 'refcount-only', 'address-only',
           'register-only', 'layout-only', 'name-only', 'frame', 'eh', 'unknown')
VERBS = ('run', 'show', 'explain', 'status')
PREFIX_MIN = 8
NAME_WIDTH = 40


def register(sub, common, handlers) -> None:
    """Add the `unified` command to the top-level parser and its handler to `handlers`."""
    unified = sub.add_parser('unified', help=f'unified match analysis ({LABEL}); the Ghidriff result stays primary',
                             description=f'Derived, ordinal fusion of the stored engine outputs ({LABEL}). It never '
                                         'changes the project, the Ghidriff results or any other stored result.')
    actions = unified.add_subparsers(dest='action', required=True, parser_class=type(unified),
                                     metavar='{' + ','.join(VERBS) + '}')
    run = common(actions.add_parser('run', help='compute and store the unified result for this project'))
    run.add_argument('project', type=Path)
    run.add_argument('--no-extract', action='store_true', help='S0 mode: no instruction-level extraction (the only '
                                                                'mode in this build)')
    run.add_argument('--no-decompile', action='store_true', help='accepted for later modes; no effect in S0 mode')
    run.add_argument('--sources', default=','.join(SOURCES), metavar='LIST',
                     help='comma list of ' + ', '.join(SOURCES) + ' (default: all)')
    isolation = run.add_mutually_exclusive_group()
    isolation.add_argument('--isolate', dest='isolate', action='store_true', default=True,
                           help='run the worker as a capped child process (default)')
    isolation.add_argument('--in-process', dest='isolate', action='store_false',
                           help='run in this process (tests and debugging)')
    run.add_argument('--timeout', type=int, default=3600, help='worker seconds (60..86400)')
    run.add_argument('--refresh', action='store_true', help='recompute even when a stored result has these inputs')
    run.add_argument('--fail-on-none', action='store_true', help='exit 4 when no row is material or review')
    show = common(actions.add_parser('show', help='list rows of the current unified result'))
    show.add_argument('project', type=Path)
    show.add_argument('--decision', action='append', choices=DECISIONS, default=[], metavar='DECISION')
    show.add_argument('--change', action='append', choices=MATERIALITIES, default=[], metavar='CHANGE',
                      help='materiality: ' + ', '.join(MATERIALITIES))
    show.add_argument('--class', dest='classes', action='append', choices=CLASSES, default=[], metavar='CLASS')
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
    from ..cli import CANCELLED, NO_RESULTS, OK, RUNTIME, _emit, _open
    from . import pipeline
    from .limits import UnifiedError
    options = pipeline.UnifiedOptions(sources=_sources(args.sources), isolate=args.isolate, timeout_s=args.timeout,
                                      refresh=args.refresh)
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
    extra = [] if args.no_extract else [NO_EXTRACT]
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
    from . import keys
    if plan is None or loaded.manifest is None or loaded.manifest.result_id == plan.result_id:
        return []
    return list(keys.changed_inputs(keys.result_key_inputs(loaded.manifest), plan.identity.key_inputs))


def _require_result(loaded, args) -> list[str]:
    """Warnings for a stale result; a missing or unusable one is an error (exit 2 or 3)."""
    from ..cli import ENVIRONMENT, RUNTIME, CliError
    if loaded.state == 'none':
        raise CliError(ENVIRONMENT, f'no unified result yet: run `patchtrace unified run {args.project}` first')
    if loaded.state == 'invalid' or loaded.manifest is None or loaded.directory is None:
        raise CliError(RUNTIME, f'the stored unified result is unusable [{loaded.reason or "invalid"}]: run again '
                                'with --refresh')
    return ['the stored result is stale: its inputs changed; run again to refresh it'] if loaded.state == 'stale' else []


def _side_json(side) -> list[dict]:
    return [{'rva': s.rva, 'name': _t(s.name, 256) if s.name else None, 'kind': s.kind} for s in side]


def _row_json(row) -> dict:
    return {'row_id': row.row_id, 'decision': row.decision, 'materiality': row.materiality,
            'older': _side_json(row.older), 'newer': _side_json(row.newer),
            'change_classes': list(row.change_classes), 'support': [{'component': s.component, 'tier': s.tier}
                                                                    for s in row.support],
            'contest': None if row.contest is None else row.contest.strength,
            'hints': [_t(h) for h in row.hints], 'flags': list(row.flags)}


def _side_text(side) -> str:
    if not side:
        return '-'
    parts = [f'0x{s.rva:X}' + (f' {_t(s.name, NAME_WIDTH)}' if s.name else '') for s in side[:2]]
    return ', '.join(parts) + (f' (+{len(side) - 2})' if len(side) > 2 else '')


def _show(args, cancel) -> int:
    from ..cli import NO_RESULTS, OK, RUNTIME, CliError, _emit, _open
    from . import pipeline
    from .limits import UnifiedError
    service = _open(args.project)
    try:
        plan, _ = _plan_or_none(service)
        loaded = pipeline.load_current(service, plan)
        warnings = _require_result(loaded, args)
        decisions, changes, classes = set(args.decision), set(args.change), set(args.classes)
        total = filtered = 0
        shown = []
        try:
            for row in pipeline.read_rows(loaded):
                total += 1
                if ((decisions and row.decision not in decisions) or (changes and row.materiality not in changes)
                        or (classes and not classes & set(row.change_classes))):
                    continue
                filtered += 1
                if len(shown) < max(0, args.limit):
                    shown.append(row)
        except UnifiedError as error:
            raise CliError(RUNTIME, f'{error.code}: {error.message} [{error.reason}]') from None
        changed = _changed_inputs(loaded, plan)
    finally:
        service.close()
    result = {'result_id': loaded.manifest.result_id, 'state': loaded.state, 'stale': loaded.state == 'stale',
              'changed_inputs': changed, 'status': loaded.manifest.status, 'total': total, 'filtered': filtered,
              'rows': [_row_json(r) for r in shown]}
    lines = [f'unified show: result {loaded.manifest.result_id[:16]} {loaded.manifest.status}, {total} rows, '
             f'{filtered} match, {len(shown)} shown ({LABEL})']
    lines += [f'{r.decision:<11} {r.materiality:<14} {_side_text(r.older):<{NAME_WIDTH + 12}} '
              f'{_side_text(r.newer):<{NAME_WIDTH + 12}} {",".join(r.change_classes) or "-"}' for r in shown]
    _emit(args, 'unified show', loaded.manifest.status, result, [NOTE, *warnings], '\n'.join(lines))
    return OK if filtered else NO_RESULTS


def _find_row(loaded, prefix: str):
    from ..cli import ENVIRONMENT, CliError
    from . import pipeline
    found = [row for row in pipeline.read_rows(loaded) if row.row_id.startswith(prefix)]
    if not found:
        raise CliError(ENVIRONMENT, f'no row starts with {_t(prefix, 70)}')
    if len(found) > 1:
        raise CliError(ENVIRONMENT, f'{len(found)} rows start with {_t(prefix, 70)}: give more digits')
    return found[0]


def _facts_for(loaded, row_id: str):
    from . import pipeline
    return next((f for f in pipeline.read_facts(loaded) if f.row_id == row_id), None)


def _atom_text(index: int, atom) -> str:
    older = '-' if atom.older_rva is None else f'0x{atom.older_rva:X}'
    newer = '-' if atom.newer_rva is None else f'0x{atom.newer_rva:X}'
    native = ''.join(f' {_t(k, 32)}={_t(v, 120)}' for k, v in atom.native)
    return (f'  [{index}] {atom.source} {_t(atom.step, 64)} tier {atom.tier} {atom.cls} {atom.cardinality} '
            f'{older} -> {newer}{native}')


def _facts_text(facts) -> list[str]:
    if facts is None:
        return ['facts: none (not a pair that gets change facts)']
    lines = [f'facts: verdict {facts.verdict}' + (f', proof {facts.proof}' if facts.proof else '')
             + (f', second channel {facts.second_channel}' if facts.second_channel else ''),
             '  channels: ' + ', '.join(f'{c} {s}' for c, s in facts.channels)]
    for delta in facts.deltas:
        older = '-' if delta.older_rva is None else f'0x{delta.older_rva:X}'
        newer = '-' if delta.newer_rva is None else f'0x{delta.newer_rva:X}'
        change = '' if delta.old is None and delta.new is None else f' {_t(delta.old, 120)} -> {_t(delta.new, 120)}'
        lines.append(f'  delta {delta.cls} ({delta.channel}) {older} -> {newer}{change}')
    if facts.deltas_omitted:
        lines.append(f'  {facts.deltas_omitted} more deltas not listed')
    if facts.limits_hit:
        lines.append('  limits: ' + ', '.join(facts.limits_hit))
    return lines


def _explain(args, cancel) -> int:
    from ..cli import ENVIRONMENT, OK, RUNTIME, CliError, _emit, _open
    from . import pipeline
    from .limits import UnifiedError
    prefix = args.row.strip().lower()
    if len(prefix) < PREFIX_MIN or any(c not in '0123456789abcdef' for c in prefix):
        raise CliError(ENVIRONMENT, f'--row takes at least {PREFIX_MIN} hexadecimal digits of a row id')
    service = _open(args.project)
    try:
        plan, _ = _plan_or_none(service)
        loaded = pipeline.load_current(service, plan)
        warnings = _require_result(loaded, args)
        try:
            row = _find_row(loaded, prefix)
            facts = _facts_for(loaded, row.row_id)
        except UnifiedError as error:
            raise CliError(RUNTIME, f'{error.code}: {error.message} [{error.reason}]') from None
    finally:
        service.close()
    manifest = loaded.manifest
    provenance = {'result_id': manifest.result_id, 'status': manifest.status, 'engine_version': manifest.engine_version,
                  'sources': [{'source': s.source, 'version': _t(s.version, 64)} for s in manifest.sources],
                  'limitations': [_t(x) for x in manifest.limitations]}
    result = {'row': row.model_dump(mode='json'), 'facts': None if facts is None else facts.model_dump(mode='json'),
              'provenance': provenance, 'state': loaded.state}
    lines = [f'row {row.row_id[:16]}: {row.decision}, change {row.materiality} ({LABEL})',
             f'older: {_side_text(row.older)}', f'newer: {_side_text(row.newer)}']
    if row.support:
        lines.append('support: ' + ', '.join(f'{s.component} tier {s.tier} (atom {s.atom_index})'
                                              for s in row.support))
    if row.contest is not None:
        lines.append(f'contest: {row.contest.strength} against atoms {", ".join(map(str, row.contest.against))}')
    lines.append(f'atoms ({len(row.atoms)}):')
    lines += [_atom_text(i, a) for i, a in enumerate(row.atoms)]
    lines += _facts_text(facts)
    lines.append('classes: ' + (", ".join(row.change_classes) or "none"))
    lines.append('hints: ' + (", ".join(_t(h) for h in row.hints) or "none"))
    lines.append(f'provenance: result {manifest.result_id[:16]} {manifest.status}, sources '
                 + ', '.join(f'{s.source} {_t(s.version, 64)}' for s in manifest.sources))
    _emit(args, 'unified explain', manifest.status, result, [NOTE, *warnings], '\n'.join(lines))
    return OK


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
        'ir': {'available': False, 'reason': 's0-mode'}, 'engine_version': keys.ENGINE_VERSION,
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
    lines.append('instruction-level data: not extracted in this mode')
    lines += [f'run {r.started_utc} {r.status}' + (f' {r.error_code}' if r.error_code else '') for r in runs]
    _emit(args, 'unified status', 'complete', result, [NOTE], '\n'.join(lines))
    return OK
