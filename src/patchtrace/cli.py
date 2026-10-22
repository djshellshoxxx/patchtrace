"""Headless PatchTrace commands (SPEC-07 §11). Never imports Qt or patchtrace.ui.

Exit codes: 0 success, 2 invalid arguments/config/environment, 3 runtime failure,
4 legitimate no-results (complete evidence, zero entries), 5 cancellation.
In --json mode stdout carries exactly one document; diagnostics go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
from pathlib import Path

from .backend_cli import cmd_backend
from .backend_cli import register as register_backend
from .diagnostics import redact_log
from .hostile_text import escape_text
from .intelligence import cli as intelligence_cli
from .intelligence.tools import cli as intel_tools_cli  # SPEC-29 tools dispatcher (cheap import)
from .symbols import cli_args as symbol_args

COMMANDS = ('rank', 'flags', 'correlate', 'cache', 'acquire', 'series', 'secondary', 'intelligence', 'unified',
            'intel-tools', 'backend')
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
CLI_CONTRACT = 'enrichment-cli/1'


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse default is exit 2 with usage; keep 2 but route via CliError
        raise CliError(ENVIRONMENT, f'{self.prog}: {message}')


def _non_negative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be 0 or greater')
    return number


_CVE_ID = re.compile(r'CVE-\d{4}-\d{4,19}', re.ASCII)


def _cve_id(value: str) -> str:
    if not _CVE_ID.fullmatch(value):
        raise argparse.ArgumentTypeError('must look like CVE-YYYY-NNNN')
    return value


def _parser(argv=()) -> argparse.ArgumentParser:
    parser = _Parser(prog='patchtrace', description='PatchTrace headless enrichment commands. '
                     'Launch without arguments to open the desktop.')
    sub = parser.add_subparsers(dest='command', required=True, parser_class=_Parser)

    def common(p):
        p.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return p

    def profiled(p):
        p.add_argument('--profile', metavar='NAME|FILE',
                       help='analysis profile name from the desktop profiles directory, or a profile JSON file')
        return p

    def cached(p):
        p.add_argument('--cache-dir', type=Path,
                       help='global derived-stage cache (default: the profile cache_dir, else no cache)')
        p.add_argument('--refresh', action='store_true', help='recompute cached stages (no network implied)')
        return p

    rank = common(sub.add_parser('rank', help='rank changed functions by attention/1 change signals'))
    rank.add_argument('project', type=Path)
    cached(rank)
    profiled(rank)
    rank.add_argument('--run', help='analysis run ID (default: latest completed)')
    rank.add_argument('--weights', type=Path, help='JSON object of detector weights (integers 0..100)')
    rank.add_argument('--disable', action='append', default=[], metavar='DETECTOR')
    rank.add_argument('--limit', type=_non_negative, default=0, help='show at most N entries (0 = all)')
    rank.add_argument('--dry-run', action='store_true', help='do not persist results in the project')

    flags = common(sub.add_parser('flags', help='list WIL feature-flag transitions'))
    flags.add_argument('project', type=Path)
    cached(flags)
    profiled(flags)
    flags.add_argument('--run')
    flags.add_argument('--feature-id', type=int, action='append', default=None)
    flags.add_argument('--dry-run', action='store_true')

    corr = common(sub.add_parser('correlate', help='rerank with CVE context (base ranking unchanged)'))
    corr.add_argument('project', type=Path)
    cached(corr)
    profiled(corr)
    corr.add_argument('--cve', action='append', required=True, metavar='CVE-YYYY-NNNN', type=_cve_id)
    corr.add_argument('--snapshot', type=Path, action='append', default=[],
                      help='previously saved CVE snapshot JSON (offline)')
    corr.add_argument('--fetch', action='store_true', help='retrieve from providers (requires consent)')
    corr.add_argument('--consent-providers', default='', help='comma list, e.g. nvd,msrc; must match --providers')
    corr.add_argument('--providers', default=None, help='comma list (default: profile cve_providers, else nvd,msrc)')
    corr.add_argument('--api-key-env', default='', help='environment variable holding an NVD API key')
    corr.add_argument('--save-snapshot', type=Path, help='write normalized snapshots to this JSON file')
    corr.add_argument('--run')
    corr.add_argument('--dry-run', action='store_true')

    cache = common(sub.add_parser('cache', help='inspect or maintain the global derived/raw cache'))
    cache.add_argument('action', choices=['status', 'verify', 'prune'])
    cache.add_argument('--cache-dir', type=Path, required=True)
    cache.add_argument('--target-bytes', type=int, default=None)

    acquire = sub.add_parser('acquire', help='download two builds from the Microsoft symbol server (SPEC-08)')
    acq = acquire.add_subparsers(dest='action', required=True, parser_class=_Parser)
    search = common(acq.add_parser('search', help='list Winbindex x64 build candidates (metadata only)'))
    search.add_argument('name', help='lowercase file name, e.g. afd.sys')
    search.add_argument('--consent-hosts', default='', help='must be exactly winbindex.m417z.com')
    fetch = common(acq.add_parser('fetch', help='download, verify and create a two-artifact project'))
    fetch.add_argument('name')
    fetch.add_argument('--older', required=True, metavar='SHA256')
    fetch.add_argument('--newer', required=True, metavar='SHA256')
    fetch.add_argument('--project', type=Path, required=True, help='new project directory')
    fetch.add_argument('--project-name', default='')
    fetch.add_argument('--consent-hosts', default='',
                       help='must be exactly winbindex.m417z.com,msdl.microsoft.com')

    series = sub.add_parser('series', help='N-way build series over adjacent pair projects (SPEC-09)')
    ser = series.add_subparsers(dest='action', required=True, parser_class=_Parser)
    create = common(ser.add_parser('create', help='create/reuse adjacent pair projects and write series.json'))
    create.add_argument('--builds', type=Path, nargs='+', required=True, metavar='FILE',
                        help='3-8 builds in analyst order, oldest first (order is never inferred)')
    create.add_argument('--root', type=Path, required=True, help='directory holding series.json and pair projects')
    create.add_argument('--labels', nargs='+', default=None, metavar='LABEL')
    create.add_argument('--direct', action='store_true',
                        help='also create a first-to-last pair project used to confirm/contradict chains')
    create.add_argument('--replace-corrupt', action='store_true',
                        help='if series.json is damaged, keep a series.json.corrupt-* copy and replace it')
    create.add_argument('--run', action='store_true',
                        help='run Ghidriff for pair projects without a completed run (otherwise none runs)')
    create.add_argument('--python', default='', help='external Python executable for --run')
    create.add_argument('--ghidra-dir', default='', help='Ghidra installation root for --run')
    create.add_argument('--timeout', type=int, default=3600, help='per-pair analysis timeout seconds')
    create.add_argument('--cache-dir', type=Path, default=None, help='raw-output cache for --run')
    symbol_args.add_arguments(create)
    secondary = sub.add_parser('secondary', help='second-opinion match sets: BinDiff import, rz-diff (SPEC-10/11)')
    sec = secondary.add_subparsers(dest='action', required=True, parser_class=_Parser)
    imp = common(sec.add_parser('import-bindiff', help='import a genuine .BinDiff result for this exact pair'))
    imp.add_argument('project', type=Path)
    imp.add_argument('bindiff', type=Path)
    run = common(sec.add_parser('run', help='run secondary engines on the project artifacts (SPEC-28)'))
    run.add_argument('project', type=Path)
    run.add_argument('--engine', action='append', choices=('rz-diff', 'bindiff'), default=None,
                     help='repeatable; default: every engine that probes as supported')
    run.add_argument('--rz-diff', default='rz-diff', help='rz-diff executable (absolute path or on PATH)')
    run.add_argument('--bindiff', default=None, help='absolute path of the BinDiff 8 `bindiff` executable')
    from .secondary.cli_bindiff import add_arguments as add_bindiff_arguments
    add_bindiff_arguments(run)
    run.add_argument('--max-parallel', type=int, choices=(1, 2), default=1)
    run.add_argument('--timeout', type=int, default=1800, help='per-engine seconds (60..86400)')
    run.add_argument('--no-cache', action='store_true', help='ignore stored engine runs')
    rz = common(sec.add_parser('rzdiff', help='alias for `secondary run --engine rz-diff`'))
    rz.add_argument('project', type=Path)
    rz.add_argument('--rz-diff', default='rz-diff', help='rz-diff executable (absolute path or on PATH)')
    rz.add_argument('--timeout', type=int, default=1800)
    rz.set_defaults(engine=['rz-diff'], bindiff=None, max_parallel=1, no_cache=False)
    rec = common(sec.add_parser('reconcile', help='compare stored secondary match sets with Ghidriff matches'))
    rec.add_argument('project', type=Path)
    from .secondary import cli_binexport  # SPEC-10b: binexport-check + hidden worker
    cli_binexport.register(sec, common)
    chains = common(ser.add_parser('chains', help='list chain hypotheses from series.json'))
    chains.add_argument('series_json', type=Path)
    which = chains.add_mutually_exclusive_group()
    which.add_argument('--function', metavar='NAME')
    which.add_argument('--address', metavar='HEX')
    intelligence_cli.register(sub, common)
    from .unified import cli as cli_unified  # SPEC-31 S0b: run/show/explain/status + the hidden worker
    cli_unified.register(sub, common, HANDLERS)
    intel_tools_cli.register(sub, common)
    register_backend(sub, common)
    from .cli_commands import register_all  # GUI plan 8.12: a new verb is a file there, not an edit here
    register_all(sub, argv[0] if argv else None)
    return parser


def _api_key(env_name: str) -> str | None:
    """NVD key from the named environment variable; unset, empty or blank means no key."""
    return (os.environ.get(env_name, '').strip() or None) if env_name else None


def _emit(args, command: str, status: str, result, warnings: list[str], text: str) -> None:
    if getattr(args, 'json', False):
        sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': command, 'status': status,
                                     'result': result, 'warnings': warnings}, sort_keys=True) + '\n')
    else:
        for warning in warnings:
            print(f'warning: {escape_text(warning)}', file=sys.stderr)
        text = escape_text(text, keep='\n')  # names and evidence are untrusted: no ESC or bidi controls reach a terminal
        sys.stdout.write(text + ('\n' if text and not text.endswith('\n') else ''))


def _terminal_text(value: object, limit: int | None = 300) -> str:
    """Untrusted text (symbol names from the target) for a terminal: controls and bidi marks become escapes."""
    from .intelligence.reports import plain_text
    return plain_text(value, limit)


def _match_names(matches) -> dict:
    return {m.match_id: _terminal_text(' / '.join(sorted({f.name for f in m.older + m.newer}))) for m in matches}


def _profile(args):
    """The selected AnalysisProfile, or None when --profile is absent. Explicit per-run options
    that the profile also defines are rejected rather than silently merged."""
    value = getattr(args, 'profile', None)
    if value is None:
        return None
    conflicts = [flag for flag, given in (('--weights', getattr(args, 'weights', None)),
                                          ('--disable', getattr(args, 'disable', None)),
                                          ('--feature-id', getattr(args, 'feature_id', None))) if given]
    if conflicts:
        raise CliError(ENVIRONMENT, f'--profile cannot be combined with {", ".join(conflicts)}')
    from .enrichment import profiles
    try:
        return profiles.resolve(value, profiles.ProfileStore(profiles.default_profiles_dir()))
    except profiles.ProfileError as exc:
        raise CliError(ENVIRONMENT, f'invalid profile: {exc}') from None


def _profile_info(profile) -> dict | None:
    if profile is None:
        return None
    from .enrichment.profiles import profile_digest
    return {'name': profile.name, 'digest': profile_digest(profile)}


def _config(args):
    from .enrichment.contracts import DEFAULT_WEIGHTS, DETECTOR_IDS, RankingConfig
    weights = dict(DEFAULT_WEIGHTS)
    if args.weights:
        try:
            from .persistence import strict_json
            loaded = strict_json(args.weights.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise CliError(ENVIRONMENT, f'cannot read weights file: {exc}') from None
        if not isinstance(loaded, dict):
            raise CliError(ENVIRONMENT, 'weights file must be a JSON object of detector IDs to integers')
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
    except OSError as exc:  # e.g. a path that is too long: no absolute directory in the message
        raise CliError(ENVIRONMENT, f'PT-STORAGE: project cannot be opened ({exc.strerror or type(exc).__name__})') from None


def _with_cache(args, options, profile=None):
    budget = None
    if not getattr(args, 'cache_dir', None) and profile is not None and profile.cache_dir:
        args.cache_dir = Path(profile.cache_dir)
        budget = profile.cache_budget_gib * 1024 ** 3
    elif getattr(args, 'cache_dir', None) and profile is not None:
        budget = profile.cache_budget_gib * 1024 ** 3
    if not getattr(args, 'cache_dir', None):
        if getattr(args, 'refresh', False):
            raise CliError(ENVIRONMENT, '--refresh requires --cache-dir')
        return options
    if args.cache_dir.exists() and not args.cache_dir.is_dir():
        raise CliError(ENVIRONMENT, f'cache directory {args.cache_dir} is not a directory; no cache was used')
    import dataclasses

    from .enrichment.cache import CacheConfig, DerivedCache
    from .enrichment.contracts import EnrichmentError
    try:
        cache = DerivedCache(CacheConfig(root=args.cache_dir.resolve(), refresh_stages=frozenset(
            {'signals', 'wil'} if args.refresh else ()), **({'budget_bytes': budget} if budget else {})))
    except EnrichmentError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    return dataclasses.replace(options, cache=cache)


def _run_pipeline(args, cancel, options, profile=None):
    from .enrichment import pipeline
    options = _with_cache(args, options, profile)
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
    profile = _profile(args)
    options = PipelineOptions(config=_config(args), run_id=args.run) if profile is None else PipelineOptions(
        config=profile.ranking_config(), feature_ids=profile.feature_filter(), run_id=args.run,
        max_age_days=profile.snapshot_max_age_days)
    result, warnings = _run_pipeline(args, cancel, options, profile)
    warnings += _stage_warnings(result)
    if result.status.status == 'cancelled':
        _emit(args, 'rank', 'cancelled', None, warnings, '')
        return CANCELLED
    if result.ranking is None:
        _emit(args, 'rank', result.status.status, None, warnings, 'Ranking unavailable.')
        return RUNTIME
    entries = result.ranking.entries[:args.limit or None]
    names = _match_names(result.views.matches)
    payload = result.ranking.model_dump(mode='json')
    payload['entries'] = [e.model_dump(mode='json') | {'function': names.get(e.match_id, '')} for e in entries]
    payload['profile'] = _profile_info(profile)
    lines = [f'{"rank":>4} {"score":>5} {"raw":>3} {"groups":>6} {"evidence":<11} function',
             *(f'{e.rank:>4} {e.score:>5} {e.raw:>3} {len(e.groups):>6} {e.evidence:<11} '
               f'{names.get(e.match_id, "")}' for e in entries)]
    if profile is not None:
        lines.append(f'profile {profile.name} ({_profile_info(profile)["digest"][:12]})')
    lines.append(f'formula {result.ranking.formula}; config {result.ranking.config_digest[:12]}; '
                 'attention scores prioritize research and do not establish exploitability.')
    status = result.status.status
    _emit(args, 'rank', status, payload, warnings, '\n'.join(lines))
    if not result.ranking.entries and status == 'complete':
        return NO_RESULTS
    return OK


def cmd_flags(args, cancel) -> int:
    from .enrichment.pipeline import PipelineOptions
    profile = _profile(args)
    ids = frozenset(args.feature_id) if args.feature_id else None
    if ids and any(not 0 <= i <= 4_294_967_295 for i in ids):
        raise CliError(ENVIRONMENT, 'feature IDs must be unsigned 32-bit integers')
    options = PipelineOptions(run_id=args.run, feature_ids=ids) if profile is None else PipelineOptions(
        config=profile.ranking_config(), feature_ids=profile.feature_filter(), run_id=args.run,
        max_age_days=profile.snapshot_max_age_days)
    result, warnings = _run_pipeline(args, cancel, options, profile)
    warnings += _stage_warnings(result)
    wil_stage = next(s for s in result.status.stages if s.stage == 'wil')
    items = [t.model_dump(mode='json') for t in result.transitions]
    text = '\n'.join(f'Feature_{t.feature_id if t.feature_id is not None else "?"} {t.kind:<26} '
                     f'{t.confidence:<9} {"qualifies" if t.qualifies else "context only"}'
                     for t in result.transitions) or 'No feature-flag transitions found.'
    _emit(args, 'flags', wil_stage.status, {'transitions': items, 'profile': _profile_info(profile)}, warnings, text)
    if wil_stage.status == 'cancelled':
        return CANCELLED
    if wil_stage.status != 'complete':
        return RUNTIME
    return NO_RESULTS if not items else OK


def _normalize_available(cve, cve_id: str, bodies: dict, now: str, warnings: list[str]) -> list:
    """Normalize all bodies together; if that fails, keep each provider that is valid on its own,
    so one malformed or wrong-ID response does not discard a valid one (partial semantics)."""
    from .enrichment.contracts import EnrichmentError
    try:
        return [cve.normalize(cve_id, bodies, now)]
    except EnrichmentError as combined:
        if len(bodies) == 1:
            raise
        kept = {}
        for provider, body in sorted(bodies.items()):
            try:
                cve.normalize(cve_id, {provider: body}, now)
                kept[provider] = body
            except EnrichmentError as exc:
                warnings.append(f'{cve_id}: provider {provider} response rejected ({exc.code}); '
                                'normalized the remaining provider responses')
        if not kept:
            raise combined
        return [cve.normalize(cve_id, kept, now)]


def cmd_correlate(args, cancel) -> int:

    from .enrichment import cve
    from .enrichment.contracts import CveSnapshot, EnrichmentError
    from .enrichment.pipeline import PipelineOptions
    profile = _profile(args)
    if args.providers is None:
        args.providers = ','.join(profile.cve_providers) if profile is not None else 'nvd,msrc'
    snapshots: list[CveSnapshot] = []
    unverified: set[str] = set()
    requested = set(args.cve)
    for path in args.snapshot:
        try:
            with path.open('rb') as handle:  # never read more than the cap, whatever the file claims to be
                loaded = cve.parse_snapshots(handle.read(cve.MAX_SNAPSHOT_BYTES + 1))
            # A saved file cannot be re-verified against provider bodies: drop claims that
            # normalization never derives (feature IDs) and flag the snapshot as unverified.
            snapshots += [s.model_copy(update={'feature_ids': ()}) for s in loaded]
            unverified.update(s.snapshot_id for s in loaded)
        except (OSError, ValueError, EnrichmentError) as exc:
            raise CliError(ENVIRONMENT, f'cannot load snapshot {path.name}: {exc}') from None
    warnings: list[str] = []
    fetch_failed = False
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
        key = _api_key(args.api_key_env)
        duration = intelligence.describe_duration(plan, key is not None)
        if duration:
            print(duration, file=sys.stderr)
        try:
            responses, failures = intelligence.fetch_all(plan, intelligence.FetchConsent.for_plan(plan),
                                                         api_key=key, cancel=cancel)
            if failures and not responses:
                raise next(iter(failures.values()))
            for (cve_id, provider), exc in sorted(failures.items()):
                fetch_failed = True
                warnings.append(f'{cve_id}: provider {provider} failed ({exc.code}); '
                                'normalized the remaining provider responses')
            now = datetime.now(UTC).isoformat()
            for cve_id in sorted(requested):
                bodies = {provider: r.body for provider, r in responses.get(cve_id, {}).items()}
                if bodies:
                    before = len(warnings)
                    snapshots.extend(_normalize_available(cve, cve_id, bodies, now, warnings))
                    fetch_failed = fetch_failed or len(warnings) > before
                else:
                    warnings.append(f'{cve_id}: no provider response')
        except EnrichmentError as exc:
            if exc.code == 'PT-ENRICH-CANCEL':
                raise CliError(CANCELLED, str(exc)) from None
            raise CliError(RUNTIME, str(exc)) from None
    snapshots = [s for s in snapshots if s.cve_id in requested]
    try:
        kept, ignored = cve.select_latest(snapshots)
    except EnrichmentError as exc:
        raise CliError(ENVIRONMENT, f'invalid snapshot: {exc}') from None
    # A merged snapshot has a new id; it is unverified when any file-loaded snapshot of that CVE exists.
    unverified_cves = {s.cve_id for s in snapshots if s.snapshot_id in unverified}
    snapshots = list(kept)
    unverified.update(s.snapshot_id for s in snapshots if s.cve_id in unverified_cves)
    warnings += [f'{s.cve_id}: ignored older/duplicate snapshot retrieved {s.retrieved_at}; '
                 'using the most recently retrieved one' for s in ignored]
    missing = requested - {s.cve_id for s in snapshots}
    warnings += [f'{c}: no snapshot available; base ranking retained' for c in sorted(missing)]
    if args.save_snapshot and snapshots:
        args.save_snapshot.write_text(json.dumps([s.model_dump(mode='json') for s in snapshots], indent=2),
                                      encoding='utf-8')
    options = PipelineOptions(run_id=args.run, snapshots=tuple(snapshots)) if profile is None else PipelineOptions(
        config=profile.ranking_config(), feature_ids=profile.feature_filter(), run_id=args.run,
        snapshots=tuple(snapshots), max_age_days=profile.snapshot_max_age_days)
    result, more = _run_pipeline(args, cancel, options, profile)
    warnings += more + _stage_warnings(result)
    if result.status.status == 'cancelled':
        _emit(args, 'correlate', 'cancelled', None, warnings, '')
        return CANCELLED
    if result.contextual is None:
        _emit(args, 'correlate', 'unavailable', None, warnings, 'Contextual ranking unavailable.')
        return RUNTIME if snapshots else NO_RESULTS
    warnings += [f'{c}: snapshot loaded from file is unverified (provider bodies unavailable); '
                 'feature-ID claims ignored' for c in sorted({s.cve_id for s in snapshots if s.snapshot_id in unverified})]
    warnings += [f'{c}: CVE snapshot is stale; check its retrieval date' for c in result.contextual.stale_snapshots]
    status = 'partial' if (result.contextual.stale_snapshots or fetch_failed) \
        and result.contextual.status == 'complete' else result.contextual.status
    names = _match_names(result.views.matches)
    text = '\n'.join(f'{e.context_rank:>4} ctx {e.context_score:>3} base {e.base_score:>3} (#{e.base_rank}) '
                     f'+{e.adjustment:<2} {names.get(e.match_id, "")}' for e in result.contextual.entries)
    _emit(args, 'correlate', status, result.contextual.model_dump(mode='json') | {'profile': _profile_info(profile)},
          warnings,
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
    if 'error' in result:
        raise CliError(ENVIRONMENT, f'cache at {args.cache_dir} is unusable ({result["error"]}); check the path and permissions')
    _emit(args, 'cache', 'complete', result, [], json.dumps(result, indent=2, sort_keys=True))
    return OK


def _consent_hosts(args, required: set[str]) -> None:
    given = {h.strip() for h in args.consent_hosts.split(',') if h.strip()}
    if given != required:
        raise CliError(ENVIRONMENT, f'--consent-hosts must name exactly: {",".join(sorted(required))}')


def _acq_error(exc) -> CliError:
    code = {'PT-ACQ-CANCEL': CANCELLED, 'PT-ACQ-NOTFOUND': NO_RESULTS, 'PT-ACQ-INPUT': ENVIRONMENT,
            'PT-ACQ-CONFIG': ENVIRONMENT, 'PT-ACQ-UNSUPPORTED': ENVIRONMENT}.get(exc.code, RUNTIME)
    return CliError(code, str(exc))


def _candidates(args, transport, warnings: list[str]):
    from .acquisition import winbindex
    from .acquisition.transport import AcquisitionConsent
    url = winbindex.metadata_url(args.name)
    print(f'request: GET {url}', file=sys.stderr)
    response = transport.fetch_metadata(args.name, AcquisitionConsent.for_urls([url]))
    parsed = winbindex.parse(response.body, args.name, response.data_date)
    warnings.extend(parsed.warnings)
    if response.last_modified is None:
        warnings.append('Winbindex data date unknown (no Last-Modified); retrieval date used')
    return parsed.candidates


def _acquire_transport(factory, cancel):
    # Seam for tests to inject a fake opener; production always uses the hardened default.
    return factory(cancel=cancel)


def cmd_acquire(args, cancel) -> int:
    from .acquisition.contracts import AUTHENTICITY_NOTE, AcquisitionError, validate_file_name
    from .acquisition.transport import Transport
    command = f'acquire {args.action}'
    try:
        validate_file_name(args.name)
    except AcquisitionError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    transport = _acquire_transport(Transport, cancel)
    warnings: list[str] = []
    if args.action == 'search':
        _consent_hosts(args, {'winbindex.m417z.com'})
        try:
            candidates = _candidates(args, transport, warnings)
        except AcquisitionError as exc:
            raise _acq_error(exc) from None
        rows = [c.model_dump(mode='json') for c in candidates]
        usable = [c for c in candidates if c.x64 and c.download != 'unavailable']
        text = '\n'.join(f'{c.sha256[:16]} {c.version or "?":<44} '
                         f'{",".join(k.kb for k in c.kbs) or "-":<24} '
                         f'{min((k.release_date for k in c.kbs if k.release_date), default="-"):<10} '
                         f'{c.download if c.x64 else "not-x64"}' for c in candidates) or 'No candidates.'
        _emit(args, command, 'complete', {'candidates': rows, 'downloadable': len(usable)}, warnings, text)
        return OK if usable else NO_RESULTS
    _consent_hosts(args, {'winbindex.m417z.com', 'msdl.microsoft.com'})
    older_sha, newer_sha = args.older.lower(), args.newer.lower()
    if older_sha == newer_sha:
        raise CliError(ENVIRONMENT, '--older and --newer must differ')
    if (args.project / 'project.sqlite3').exists():
        raise CliError(ENVIRONMENT, 'project directory already contains a project')
    from .acquisition import quarantine, winbindex
    from .acquisition.transport import AcquisitionConsent
    staging = None
    try:
        by_sha = {c.sha256: c for c in _candidates(args, transport, warnings)}
        chosen = []
        for side, sha in (('older', older_sha), ('newer', newer_sha)):
            if sha not in by_sha:
                raise CliError(ENVIRONMENT, f'{side} SHA-256 is not in the Winbindex record for {args.name}')
            chosen.append(by_sha[sha])
        urls = []
        for candidate in chosen:
            if not candidate.x64:
                raise CliError(ENVIRONMENT, f'{candidate.sha256[:12]} is not an x64 build')
            if candidate.download == 'direct':
                urls.append(winbindex.direct_url(candidate))
            elif candidate.download == 'candidates':
                probes = winbindex.candidate_urls(candidate)
                for url in probes:
                    print(f'request: HEAD {url}', file=sys.stderr)
                urls.append(transport.resolve(probes, AcquisitionConsent.for_urls(probes)))
            else:
                raise AcquisitionError('PT-ACQ-NOTFOUND', f'{candidate.sha256[:12]} is update-package only')
        plan = quarantine.make_plan(chosen[0], chosen[1], urls[0], urls[1])
        consent = AcquisitionConsent.for_urls(d.url for d in plan.downloads)
        staging = quarantine.create_staging()
        acquired = []
        for planned in plan.downloads:
            print(f'request: GET {planned.url} (one redirect to *.blob.core.windows.net allowed)',
                  file=sys.stderr)
            acquired.append(quarantine.acquire(planned, consent, staging, transport))
        try:
            service = quarantine.promote(acquired[0], acquired[1], args.project_name or
                                         f'{args.name} (symbol server)', args.project)
        except ValueError as exc:
            raise CliError(RUNTIME, str(exc)) from None
        root = str(service.root)
        service.close()
    except AcquisitionError as exc:
        raise _acq_error(exc) from None
    finally:
        if staging is not None:
            quarantine.remove_staging(staging)
    result = {'project': root, 'artifacts': [a.model_dump(mode='json', exclude={'path'}) for a in acquired],
              'authenticity': AUTHENTICITY_NOTE}
    text = '\n'.join(f'{a.side}: {a.file_name} {a.sha256} ({a.size} bytes) verified' for a in acquired)
    _emit(args, command, 'complete', result, warnings, f'{text}\nproject: {root}\n{AUTHENTICITY_NOTE}')
    return OK


def _nway_error(exc) -> CliError:
    # Every PT-NWAY failure is an input/config/lock problem the analyst must correct.
    return CliError(ENVIRONMENT, str(exc))


def _run_pair(config, path: Path, cancel) -> str | None:
    """Run one pair through the same backend/apply path the desktop uses; return an error or None."""
    from .backend import quarantine_failed_run, run_comparison
    service = _open(path)
    try:
        if any(run.status in {'completed', 'identical'} for run in service.project.runs):
            return None  # reuse the existing directional result
        snapshot = service.project.model_copy(deep=True)
        raw_path, run = run_comparison(config, snapshot, service.root, cancel,
                                       lambda event: print(f'{path.name}: {event.stage}: {event.message}',
                                                           file=sys.stderr))
        if run.status == 'completed':
            try:
                if cancel.is_set():
                    raise ValueError('PT-CANCEL: cancelled before normalization')
                service.apply_import(service.prepare_analysis(raw_path, run))
                return None
            except Exception as exc:
                run = quarantine_failed_run(service.root, run, str(exc))
                if cancel.is_set():
                    run = run.model_copy(update={'status': 'cancelled'})
        service.record_terminal_run(run)
        return None if run.status == 'identical' else (run.error or f'comparison {run.status}')
    finally:
        service.close()


def _chain_row(chain, series, stale) -> dict:
    return chain.model_dump(mode='json') | {'stale': stale.chain_stale(chain, len(series.builds) - 1)}


def cmd_series(args, cancel) -> int:
    from .nway import series as store
    from .nway.contracts import NwayError
    command = f'series {args.action}'
    warnings: list[str] = []
    if args.action == 'create':
        config = None
        if args.run:
            from .backend import BackendConfig
            if not args.python or not args.ghidra_dir:
                raise CliError(ENVIRONMENT, '--run requires --python and --ghidra-dir')
            config = BackendConfig(python_executable=args.python, ghidra_dir=args.ghidra_dir,
                                   timeout_seconds=args.timeout, **symbol_args.backend_kwargs(args),
                                   cache_dir=str(args.cache_dir.resolve()) if args.cache_dir else '')
        elif args.python or args.ghidra_dir or args.cache_dir or symbol_args.given(args):
            raise CliError(ENVIRONMENT, '--python/--ghidra-dir/--cache-dir apply only with --run')
        try:
            plan = store.prepare(args.builds, args.root, args.labels, args.direct)
        except NwayError as exc:
            raise _nway_error(exc) from None
        failed = False
        warnings += [f'skipped sibling {s.name}: {s.reason}' for s in plan.skipped]
        if config is not None:
            for path in [*plan.pair_paths, *([plan.direct_path] if plan.direct_path else [])]:
                if cancel.is_set():
                    raise CliError(CANCELLED, 'cancelled; completed pair results are preserved')
                error = _run_pair(config, path, cancel)
                if error:
                    failed = True
                    warnings.append(f'{path.name}: {error}')
            if cancel.is_set():
                raise CliError(CANCELLED, 'cancelled; completed pair results are preserved')
        try:
            series = store.compute(plan)
            target = plan.root / store.SERIES_FILE
            store.save(series, target, replace_corrupt=args.replace_corrupt)
        except NwayError as exc:
            raise _nway_error(exc) from None
        except OSError as exc:
            raise CliError(RUNTIME, f'cannot write series.json: {exc}') from None
        refs = [*series.pair_projects, *([series.direct_project] if series.direct_project else [])]
        warnings += [f'{ref.path}: {note}' for ref in refs for note in ref.notes]
        unrun = [p.path for p in series.pair_projects if p.run_id is None]
        if unrun:
            warnings.append(f'pair projects without a completed run (no edges): {", ".join(unrun)}; '
                            're-run with --run')
        result = {'series': str(target), 'series_id': series.series_id, 'created': [p.name for p in plan.created],
                  'pair_projects': [p.model_dump(mode='json') for p in series.pair_projects],
                  'direct_project': series.direct_project.model_dump(mode='json') if series.direct_project else None,
                  'chains': len(series.chains), 'node_count': series.node_count}
        text = (f'series {series.series_id[:12]}: {len(series.builds)} builds, {len(series.chains)} chains, '
                f'{series.node_count} nodes\nwritten: {target}\n'
                'Chains are inferred hypotheses across independent pairwise results.')
        status = 'partial' if failed else 'complete'
        _emit(args, command, status, result, warnings, text)
        return RUNTIME if failed else OK
    try:
        series = store.load(args.series_json)
        stale = store.staleness(series, args.series_json)
    except NwayError as exc:
        raise _nway_error(exc) from None
    chains = list(series.chains)
    if args.function is not None:
        chains = [c for c in chains if any(n.name == args.function for n in c.nodes)]
    if args.address is not None:
        from .nway.graph import parse_address
        address = parse_address(args.address.strip())
        if address is None:
            raise CliError(ENVIRONMENT, '--address must be a hexadecimal address')
        chains = [c for c in chains if any(n.address == address for n in c.nodes)]
    warnings += [f'stale: {reason}; re-run `series create` to recompute' for reason in stale.reasons]
    rows = [_chain_row(c, series, stale) for c in chains]
    labels = {b.ordinal: b.label for b in series.builds}
    text = '\n'.join(
        f'{c.status:<12} {"STALE " if r["stale"] else ""}{c.weakest_match_type:<28} '
        + ' -> '.join(f'[{_terminal_text(labels[n.ordinal])}] {_terminal_text(n.name) if n.name else "?"}' + (f'@{n.address:x}' if n.address is not None else '')
                      for n in c.nodes)
        + ''.join(f' ({e.kind}@{labels[e.ordinal]})' for e in c.events)
        + (f' gaps:{",".join(labels[g] for g in c.gaps)}' if c.gaps else '')
        for c, r in zip(chains, rows, strict=True)) or 'No chains.'
    status = 'stale' if stale.reasons else 'complete'
    _emit(args, command, status, {'series_id': series.series_id,
                                  'builds': [b.model_dump(mode='json') for b in series.builds],
                                  'stale_pairs': sorted(stale.pairs), 'direct_stale': stale.direct,
                                  'chains': rows}, warnings,
          text + '\nChains are inferred hypotheses unless confirmed by a direct first-to-last pair.')
    return OK if rows or stale.reasons else NO_RESULTS


def _secondary_run(args, cancel, service, store, run, sides) -> int:
    from .enrichment.contracts import EnrichmentError
    from .secondary import cli_bindiff, cli_run
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


def cmd_secondary(args, cancel) -> int:
    from .secondary import cli_binexport
    if args.action in cli_binexport.ACTIONS:
        return cli_binexport.dispatch(args, cancel)
    from .enrichment.contracts import EnrichmentError
    from .enrichment.storage import EnrichmentStore, Guard
    from .secondary import load_secondary
    from .secondary.contracts import SecondaryError
    from .secondary.reconcile import reconcile
    service = _open(args.project)
    try:
        project = service.project
        run = next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)
        sides = {a.side: a for a in project.artifacts}
        store = EnrichmentStore(service.store)
        if args.action == 'reconcile':
            from .secondary.store import select_current
            pair = (sides['older'].sha256, sides['newer'].sha256) if {'older', 'newer'} <= sides.keys() else None
            chosen, superseded = select_current(load_secondary(store), pair)
            sets = [m for _, m in chosen]
            if not sets:
                _emit(args, 'secondary reconcile', 'complete', {'reports': []}, [], 'No secondary match sets stored.')
                return NO_RESULTS
            reports = [reconcile(project.matches, m) for m in sets]
            from .secondary.evidence import assess_reports
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
                from .secondary.bindiff import import_bindiff
                match_set = import_bindiff(args.bindiff, sides['older'].sha256, sides['newer'].sha256,
                                           preserve_dir=Path(service.root) / 'runs' / run.id / 'raw' / 'secondary')
            else:
                return _secondary_run(args, cancel, service, store, run, sides)
        except SecondaryError as exc:
            code = CANCELLED if 'CANCEL' in exc.code else (
                ENVIRONMENT if exc.code in {'PT-SECONDARY-INPUT', 'PT-SECONDARY-UNSUPPORTED', 'PT-SECONDARY-PAIR',
                                            'PT-SECONDARY-ORIENTATION', 'PT-SECONDARY-FORMAT'} else RUNTIME)
            raise CliError(code, str(exc)) from None
        from .secondary.cli_run import record_import
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


HANDLERS = {'rank': cmd_rank, 'flags': cmd_flags, 'correlate': cmd_correlate, 'cache': cmd_cache,
            'acquire': cmd_acquire, 'series': cmd_series, 'secondary': cmd_secondary,
            'intel-tools': intel_tools_cli.dispatch,
            'backend': cmd_backend}
HANDLERS['intelligence'] = intelligence_cli.dispatch


def _command_name(args) -> str:
    base = f'{args.command} {args.action}' if args.command in {'acquire', 'series', 'secondary', 'intelligence', 'unified', 'intel-tools', 'backend'} else args.command
    return getattr(args, 'command_label', None) or base


def _json_envelope(args, argv: list[str]) -> tuple[bool, str]:
    """Whether to emit a JSON envelope and its command label; before parsing finishes both come from argv."""
    if args is not None:
        return bool(getattr(args, 'json', False)), _command_name(args)
    return '--json' in argv, argv[0] if argv and argv[0] in COMMANDS else 'patchtrace'


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    cancel = threading.Event()
    args = None
    try:
        args = _parser(argv).parse_args(argv)
        return (getattr(args, 'handler', None) or HANDLERS[args.command])(args, cancel)
    except CliError as exc:
        message = redact_log(str(exc))
        print(f'error: {_terminal_text(message, 4000)}', file=sys.stderr)
        as_json, label = _json_envelope(args, argv)
        if as_json:
            status = 'cancelled' if exc.code == CANCELLED else 'failed'
            sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': label, 'status': status,
                                         'result': None, 'warnings': [], 'error': message}, sort_keys=True) + '\n')
        return exc.code
    except KeyboardInterrupt:
        cancel.set()
        print('cancelled', file=sys.stderr)
        as_json, label = _json_envelope(args, argv)
        if as_json:
            sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': label, 'status': 'cancelled',
                                         'result': None, 'warnings': []}, sort_keys=True) + '\n')
        return CANCELLED
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    except Exception as exc:  # contract: unexpected failures are runtime errors (3), never a bare traceback
        message = f'{type(exc).__name__}: {redact_log(str(exc))}'  # an exception may quote a header, URL or argv
        print(f'error: {_terminal_text(message, 4000)}', file=sys.stderr)
        if args is not None and getattr(args, 'json', False):
            sys.stdout.write(json.dumps({'contract': CLI_CONTRACT, 'command': _command_name(args), 'status': 'failed',
                                         'result': None, 'warnings': [], 'error': message}, sort_keys=True) + '\n')
        return RUNTIME
