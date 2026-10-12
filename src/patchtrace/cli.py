"""Headless PatchTrace commands (SPEC-07 §11). Never imports Qt or patchtrace.ui.

Exit codes: 0 success, 2 invalid arguments/config/environment, 3 runtime failure,
4 legitimate no-results (complete evidence, zero entries), 5 cancellation.
In --json mode stdout carries exactly one document; diagnostics go to stderr.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

COMMANDS = ('rank', 'flags', 'correlate', 'cache')
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
CLI_CONTRACT = 'enrichment-cli/1'


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse default is exit 2 with usage; keep 2 but route via CliError
        raise CliError(ENVIRONMENT, f'{self.prog}: {message}')


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog='patchtrace', description='PatchTrace headless enrichment commands. '
                     'Launch without arguments to open the desktop.')
    sub = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)

    def common(p):
        p.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return p

    def cached(p):
        p.add_argument('--cache-dir', type=Path, help='global derived-stage cache (default: no cache)')
        p.add_argument('--refresh', action='store_true', help='recompute cached stages (no network implied)')
        return p

    rank = common(sub.add_parser('rank', help='rank changed functions by attention/1 change signals'))
    rank.add_argument('project', type=Path)
    cached(rank)
    rank.add_argument('--run', help='analysis run ID (default: latest completed)')
    rank.add_argument('--weights', type=Path, help='JSON object of detector weights (integers 0..100)')
    rank.add_argument('--disable', action='append', default=[], metavar='DETECTOR')
    rank.add_argument('--limit', type=int, default=0, help='show at most N entries (0 = all)')
    rank.add_argument('--dry-run', action='store_true', help='do not persist results in the project')

    flags = common(sub.add_parser('flags', help='list WIL feature-flag transitions'))
    flags.add_argument('project', type=Path)
    cached(flags)
    flags.add_argument('--run')
    flags.add_argument('--feature-id', type=int, action='append', default=None)
    flags.add_argument('--dry-run', action='store_true')

    corr = common(sub.add_parser('correlate', help='rerank with CVE context (base ranking unchanged)'))
    corr.add_argument('project', type=Path)
    cached(corr)
    corr.add_argument('--cve', action='append', required=True, metavar='CVE-YYYY-NNNN')
    corr.add_argument('--snapshot', type=Path, action='append', default=[],
                      help='previously saved CVE snapshot JSON (offline)')
    corr.add_argument('--fetch', action='store_true', help='retrieve from providers (requires consent)')
    corr.add_argument('--consent-providers', default='', help='comma list, e.g. nvd,msrc; must match --providers')
    corr.add_argument('--providers', default='nvd,msrc')
    corr.add_argument('--api-key-env', default='', help='environment variable holding an NVD API key')
    corr.add_argument('--save-snapshot', type=Path, help='write normalized snapshots to this JSON file')
    corr.add_argument('--run')
    corr.add_argument('--dry-run', action='store_true')

    cache = common(sub.add_parser('cache', help='inspect or maintain the global derived/raw cache'))
    cache.add_argument('action', choices=['status', 'verify', 'prune'])
    cache.add_argument('--cache-dir', type=Path, required=True)
    cache.add_argument('--target-bytes', type=int, default=None)
    return parser


def _emit(args, command: str, status: str, result, warnings: list[str], text: str) -> None:
    if getattr(args, 'json', False):
        sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': command, 'status': status,
                                     'result': result, 'warnings': warnings}, sort_keys=True) + '\n')
    else:
        for warning in warnings:
            print(f'warning: {warning}', file=sys.stderr)
        sys.stdout.write(text + ('\n' if text and not text.endswith('\n') else ''))


def _config(args):
    from .enrichment.contracts import DEFAULT_WEIGHTS, DETECTOR_IDS, RankingConfig
    weights = dict(DEFAULT_WEIGHTS)
    if args.weights:
        try:
            from .persistence import strict_json
            loaded = strict_json(args.weights.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise CliError(ENVIRONMENT, f'cannot read weights file: {exc}') from None
        unknown = set(loaded) - set(DETECTOR_IDS)
        if unknown:
            raise CliError(ENVIRONMENT, f'unknown detector IDs in weights: {sorted(unknown)}')
        weights.update(loaded)
    bad = set(getattr(args, 'disable', []) or []) - set(DETECTOR_IDS)
    if bad:
        raise CliError(ENVIRONMENT, f'unknown detector IDs: {sorted(bad)}')
    try:
        return RankingConfig(weights=weights, enabled=tuple(d for d in DETECTOR_IDS
                                                            if d not in set(getattr(args, 'disable', []) or [])))
    except ValueError as exc:
        raise CliError(ENVIRONMENT, f'invalid ranking configuration: {exc}') from None


def _open(project: Path):
    from .service import ProjectService
    try:
        return ProjectService.open(project)
    except ValueError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None


def _with_cache(args, options):
    if not getattr(args, 'cache_dir', None):
        if getattr(args, 'refresh', False):
            raise CliError(ENVIRONMENT, '--refresh requires --cache-dir')
        return options
    import dataclasses

    from .enrichment.cache import CacheConfig, DerivedCache
    from .enrichment.contracts import EnrichmentError
    try:
        cache = DerivedCache(CacheConfig(root=args.cache_dir.resolve(), refresh_stages=frozenset(
            {'signals', 'wil'} if args.refresh else ())))
    except EnrichmentError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    return dataclasses.replace(options, cache=cache)


def _run_pipeline(args, cancel, options):
    from .enrichment import pipeline
    options = _with_cache(args, options)
    from .enrichment.contracts import EnrichmentError
    from .enrichment.storage import EnrichmentStore
    service = _open(args.project)
    try:
        try:
            result = pipeline.run(service.project, options, cancel,
                                  lambda message: print(message, file=sys.stderr))
        except EnrichmentError as exc:
            code = CANCELLED if exc.code == 'PT-ENRICH-CANCEL' else (
                ENVIRONMENT if exc.code in {'PT-ENRICH-INPUT', 'PT-ENRICH-CONFIG'} else RUNTIME)
            raise CliError(code, str(exc)) from None
        warnings = []
        if not args.dry_run:
            try:
                written = pipeline.publish(EnrichmentStore(service.store), service.project, result)
                if any(e.stale for e in written):
                    warnings.append('project changed during enrichment; results stored as stale')
            except EnrichmentError as exc:
                warnings.append(f'results not persisted: {exc}')
        return result, warnings
    finally:
        service.close()


def _stage_warnings(result) -> list[str]:
    return [f'stage {s.stage}: {s.status}' + (f' ({s.message})' if s.message else '')
            for s in result.status.stages if s.status not in {'complete'}]


def cmd_rank(args, cancel) -> int:
    from .enrichment.pipeline import PipelineOptions
    result, warnings = _run_pipeline(args, cancel, PipelineOptions(config=_config(args), run_id=args.run))
    warnings += _stage_warnings(result)
    if result.status.status == 'cancelled':
        _emit(args, 'rank', 'cancelled', None, warnings, '')
        return CANCELLED
    if result.ranking is None:
        _emit(args, 'rank', result.status.status, None, warnings, 'Ranking unavailable.')
        return RUNTIME
    entries = result.ranking.entries[:args.limit or None]
    names = {m.match_id: ' / '.join(sorted({f.name for f in m.older + m.newer})) for m in result.views.matches}
    payload = result.ranking.model_dump(mode='json')
    payload['entries'] = [e.model_dump(mode='json') | {'function': names.get(e.match_id, '')} for e in entries]
    lines = [f'{"rank":>4} {"score":>5} {"raw":>3} {"groups":>6} {"evidence":<11} function',
             *(f'{e.rank:>4} {e.score:>5} {e.raw:>3} {len(e.groups):>6} {e.evidence:<11} '
               f'{names.get(e.match_id, "")}' for e in entries)]
    lines.append(f'formula {result.ranking.formula}; config {result.ranking.config_digest[:12]}; '
                 'attention scores prioritize research and do not establish exploitability.')
    status = result.status.status
    _emit(args, 'rank', status, payload, warnings, '\n'.join(lines))
    if not result.ranking.entries and status == 'complete':
        return NO_RESULTS
    return OK


def cmd_flags(args, cancel) -> int:
    from .enrichment.pipeline import PipelineOptions
    ids = frozenset(args.feature_id) if args.feature_id else None
    if ids and any(not 0 <= i <= 4_294_967_295 for i in ids):
        raise CliError(ENVIRONMENT, 'feature IDs must be unsigned 32-bit integers')
    result, warnings = _run_pipeline(args, cancel, PipelineOptions(run_id=args.run, feature_ids=ids))
    warnings += _stage_warnings(result)
    wil_stage = next(s for s in result.status.stages if s.stage == 'wil')
    items = [t.model_dump(mode='json') for t in result.transitions]
    text = '\n'.join(f'Feature_{t.feature_id if t.feature_id is not None else "?"} {t.kind:<26} '
                     f'{t.confidence:<9} {"qualifies" if t.qualifies else "context only"}'
                     for t in result.transitions) or 'No feature-flag transitions found.'
    _emit(args, 'flags', wil_stage.status, {'transitions': items}, warnings, text)
    if wil_stage.status == 'cancelled':
        return CANCELLED
    if wil_stage.status != 'complete':
        return RUNTIME
    return NO_RESULTS if not items else OK


def cmd_correlate(args, cancel) -> int:
    import os

    from .enrichment import cve
    from .enrichment.contracts import CveSnapshot, EnrichmentError
    from .enrichment.pipeline import PipelineOptions
    snapshots: list[CveSnapshot] = []
    requested = set(args.cve)
    for path in args.snapshot:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            items = data if isinstance(data, list) else [data]
            snapshots += [CveSnapshot.model_validate_json(json.dumps(item)) for item in items]
        except (OSError, ValueError) as exc:
            raise CliError(ENVIRONMENT, f'cannot load snapshot {path.name}: {exc}') from None
    warnings: list[str] = []
    if args.fetch:
        from datetime import UTC, datetime

        from .enrichment import intelligence
        providers = tuple(p for p in args.providers.split(',') if p)
        consent = tuple(p for p in args.consent_providers.split(',') if p)
        if not consent or set(consent) != set(providers):
            raise CliError(ENVIRONMENT, '--fetch requires --consent-providers naming exactly the providers used')
        try:
            plan = intelligence.plan_requests(sorted(requested), providers)
        except EnrichmentError as exc:
            raise CliError(ENVIRONMENT, str(exc)) from None
        for request in plan:
            print(f'request: {request.provider} {request.url}', file=sys.stderr)
        key = os.environ.get(args.api_key_env) if args.api_key_env else None
        try:
            responses = intelligence.fetch(plan, intelligence.FetchConsent.for_plan(plan), api_key=key,
                                           cancel=cancel)
            now = datetime.now(UTC).isoformat()
            for cve_id in sorted(requested):
                bodies = {provider: r.body for provider, r in responses.get(cve_id, {}).items()}
                if bodies:
                    snapshots.append(cve.normalize(cve_id, bodies, now))
                else:
                    warnings.append(f'{cve_id}: no provider response')
        except EnrichmentError as exc:
            if exc.code == 'PT-ENRICH-CANCEL':
                raise CliError(CANCELLED, str(exc)) from None
            raise CliError(RUNTIME, str(exc)) from None
    snapshots = [s for s in snapshots if s.cve_id in requested]
    missing = requested - {s.cve_id for s in snapshots}
    warnings += [f'{c}: no snapshot available; base ranking retained' for c in sorted(missing)]
    if args.save_snapshot and snapshots:
        args.save_snapshot.write_text(json.dumps([s.model_dump(mode='json') for s in snapshots], indent=2),
                                      encoding='utf-8')
    result, more = _run_pipeline(args, cancel, PipelineOptions(run_id=args.run, snapshots=tuple(snapshots)))
    warnings += more + _stage_warnings(result)
    if result.contextual is None:
        _emit(args, 'correlate', 'unavailable', None, warnings, 'Contextual ranking unavailable.')
        return RUNTIME if snapshots else NO_RESULTS
    names = {m.match_id: ' / '.join(sorted({f.name for f in m.older + m.newer})) for m in result.views.matches}
    text = '\n'.join(f'{e.context_rank:>4} ctx {e.context_score:>3} base {e.base_score:>3} (#{e.base_rank}) '
                     f'+{e.adjustment:<2} {names.get(e.match_id, "")}' for e in result.contextual.entries)
    _emit(args, 'correlate', result.contextual.status, result.contextual.model_dump(mode='json'), warnings,
          text + '\nContext descriptions never prove code behavior; base scores are unchanged.')
    return OK


def cmd_cache(args, cancel) -> int:
    from .enrichment.cache import CacheConfig, DerivedCache
    from .enrichment.contracts import EnrichmentError
    try:
        cache = DerivedCache(CacheConfig(root=args.cache_dir.resolve()))
        if args.action == 'status':
            result = cache.status()
        elif args.action == 'verify':
            result = cache.verify()
        else:
            result = cache.prune(args.target_bytes)
    except EnrichmentError as exc:
        raise CliError(ENVIRONMENT if exc.code == 'PT-ENRICH-CONFIG' else RUNTIME, str(exc)) from None
    _emit(args, 'cache', 'complete', result, [], json.dumps(result, indent=2, sort_keys=True))
    return OK


HANDLERS = {'rank': cmd_rank, 'flags': cmd_flags, 'correlate': cmd_correlate, 'cache': cmd_cache}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    cancel = threading.Event()
    args = None
    try:
        args = _parser().parse_args(argv)
        return HANDLERS[args.command](args, cancel)
    except CliError as exc:
        print(f'error: {exc}', file=sys.stderr)
        if args is not None and getattr(args, 'json', False):
            sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': args.command, 'status': 'failed',
                                         'result': None, 'warnings': [], 'error': str(exc)}, sort_keys=True) + '\n')
        return exc.code
    except KeyboardInterrupt:
        cancel.set()
        print('cancelled', file=sys.stderr)
        return CANCELLED
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
