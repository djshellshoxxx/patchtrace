"""Secondary CLI orchestration; domain work remains in existing services.

CLI presentation helpers are imported only on dispatch, keeping module import independent
of the CLI registry and Qt. Public command behavior and exit contracts are unchanged.
"""
from __future__ import annotations

from pathlib import Path


def _secondary_run(args, cancel, service, store, run, sides) -> int:
    from ..cli import ENVIRONMENT, RUNTIME, CliError, _emit
    from ..enrichment.contracts import EnrichmentError
    from . import cli_bindiff, cli_run
    bindiff = cli_bindiff.adapter_from_args(args, service.root / 'runs' / run.id / 'raw' / 'secondary')
    if not cli_run.TIMEOUT_RANGE[0] <= args.timeout <= cli_run.TIMEOUT_RANGE[1]:
        raise CliError(ENVIRONMENT, '--timeout must be between 60 and 86400 seconds')
    try:
        report = cli_run.execute(service, store, run, sides, args.engine, rz_diff=args.rz_diff,
                                 max_parallel=args.max_parallel, timeout=args.timeout,
                                 use_cache=not args.no_cache, cancel=cancel, bindiff=bindiff)
    except EnrichmentError as exc:
        raise CliError(RUNTIME, str(exc)) from None
    _emit(args, f'secondary {args.action}', report.status, report.result, report.warnings, report.text)
    return report.exit_code


def dispatch(args, cancel) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, _emit, _open
    from . import cli_binexport
    if args.action in cli_binexport.ACTIONS:
        return cli_binexport.dispatch(args, cancel)
    from ..enrichment.contracts import EnrichmentError
    from ..enrichment.storage import EnrichmentStore, Guard
    from . import load_secondary
    from .contracts import SecondaryError
    from .reconcile import reconcile
    if args.action == 'import-bindiff':
        try:
            source = Path(args.bindiff)
            if not source.is_file():
                raise OSError('not a regular input file')
            with source.open('rb') as handle:
                handle.read(0)
        except OSError as exc:
            raise CliError(ENVIRONMENT, f'PT-SECONDARY-INPUT: Cannot read BinDiff input '
                           f'({type(exc).__name__}).') from None
    service = _open(args.project)
    try:
        project = service.project
        run = next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)
        sides = {a.side: a for a in project.artifacts}
        store = EnrichmentStore(service.store)
        if args.action == 'reconcile':
            from .store import select_current
            pair = (sides['older'].sha256, sides['newer'].sha256) if {'older', 'newer'} <= sides.keys() else None
            chosen, superseded = select_current(load_secondary(store), pair)
            sets = [m for _, m in chosen]
            if not sets:
                _emit(args, 'secondary reconcile', 'complete', {'reports': []}, superseded,
                      'No usable secondary match sets stored.')
                return NO_RESULTS
            reports = [reconcile(project.matches, m) for m in sets]
            from .evidence import assess_reports
            try:
                assessment = assess_reports(tuple(reports))
            except ValueError as exc:
                raise CliError(RUNTIME, f'PT-SECONDARY-RUN: {exc}') from None
            result = {'reports': [{'engine': r.engine, 'engine_version': r.engine_version, 'counts': r.counts(),
                                   'secondary_only': len(r.secondary_only), 'limitations': list(r.limitations)}
                                  for r in reports],
                      'match_evidence': [{'match_id': e.match_id, 'verdict': e.verdict, 'tier': e.tier,
                                          'evidence_index': e.evidence_index,
                                          'supporting_engines': list(e.supporting_engines),
                                          'contradicting_engines': list(e.contradicting_engines),
                                          'missing_engines': list(e.missing_engines),
                                          'limitations': list(e.limitations),
                                          'explanation': e.explanation}
                                         for e in assessment.rows],
                      'evidence_warnings': list(assessment.warnings)}
            text = '\n'.join(f'{r.engine} {r.engine_version}: {r.counts()} secondary-only {len(r.secondary_only)}'
                             for r in reports) + '\n' + '\n'.join(
                                 f'{e.match_id[:12]}: {e.verdict} ({e.tier}; index {e.evidence_index})'
                                 for e in assessment.rows)
            text += '\nEvidence index is NOT a calibrated probability of match correctness or vulnerability.'
            _emit(args, 'secondary reconcile', 'complete', result, superseded, text)
            return OK
        if run is None:
            raise CliError(ENVIRONMENT, 'project has no completed analysis run to attach secondary matches to')
        try:
            if args.action == 'import-bindiff':
                from .bindiff import import_bindiff
                match_set = import_bindiff(args.bindiff, sides['older'].sha256, sides['newer'].sha256,
                                           preserve_dir=Path(service.root) / 'runs' / run.id / 'raw' / 'secondary')
            else:
                return _secondary_run(args, cancel, service, store, run, sides)
        except SecondaryError as exc:
            code = CANCELLED if 'CANCEL' in exc.code else (
                ENVIRONMENT if exc.code in {'PT-SECONDARY-INPUT', 'PT-SECONDARY-UNSUPPORTED', 'PT-SECONDARY-PAIR',
                                            'PT-SECONDARY-ORIENTATION', 'PT-SECONDARY-FORMAT'} else RUNTIME)
            raise CliError(code, str(exc)) from None
        from .cli_run import record_import
        guard = Guard(project.id, run.id, run.raw_sha256, match_set.file_sha256)
        try:
            entry = record_import(store, guard, project.revision, match_set)
        except EnrichmentError as exc:
            raise CliError(RUNTIME, str(exc)) from None
        report = reconcile(project.matches, match_set)
        result = {'engine': match_set.engine, 'matches': len(match_set.matches), 'entry': entry.id,
                  'counts': report.counts(), 'limitations': list(report.limitations)}
        _emit(args, f'secondary {args.action}', 'complete', result, [],
              f'{match_set.engine}: {len(match_set.matches)} matches stored; {report.counts()}')
        return OK if match_set.matches else NO_RESULTS
    finally:
        service.close()

