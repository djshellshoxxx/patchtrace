"""`patchtrace intel-tools probe|run|delta` (SPEC-29 tools T8). Own dispatcher; `cli.py` only registers and routes.

Envelope `enrichment-cli/1`, exit codes 0/2/3/4/5, no Qt. Executables come from the options or `PATCHTRACE_*`
environment variables and must be absolute: PATH is never searched. Output shows basenames, never stderr excerpts or
local paths, and redacts secret-looking strings unless `--show-secrets`. Importing this module is cheap (heavy
imports happen inside the handlers) because the parser is built on every CLI call.
"""
from __future__ import annotations

import argparse
import os
import threading
from pathlib import Path

ACTIONS = ('probe', 'run', 'delta')
ENGINES = ('capa', 'floss', 'diec')
ENV = {'capa': 'PATCHTRACE_CAPA', 'floss': 'PATCHTRACE_FLOSS', 'diec': 'PATCHTRACE_DIEC',
       'diec_db': 'PATCHTRACE_DIEC_DB', 'diec_lib': 'PATCHTRACE_DIEC_LIB', 'capa_rules': 'PATCHTRACE_CAPA_RULES',
       'capa_sigs': 'PATCHTRACE_CAPA_SIGS'}


def _engines(value: str) -> tuple[str, ...]:
    items = tuple(part.strip() for part in value.split(',') if part.strip())
    if not items or any(item not in ENGINES for item in items):
        raise argparse.ArgumentTypeError(f'must be a comma list of {",".join(ENGINES)}')
    return items


def _tool_options(p) -> None:
    p.add_argument('--capa', type=Path, metavar='EXE')
    p.add_argument('--floss', type=Path, metavar='EXE')
    p.add_argument('--diec', type=Path, metavar='EXE')
    p.add_argument('--diec-db', type=Path, metavar='DIR')
    p.add_argument('--diec-lib', type=Path, metavar='DIR')
    p.add_argument('--capa-rules', type=Path, metavar='DIR')
    p.add_argument('--capa-sigs', type=Path, metavar='DIR')
    for engine in ENGINES:
        p.add_argument(f'--{engine}-accept-untested', action='store_true',
                       help=f'accept a {engine} build that is not the pinned release (recorded as untested)')


def register(sub, common) -> None:
    parser = sub.add_parser('intel-tools', help='capa / FLOSS / Detect It Easy evidence (SPEC-29; static, no execution)')
    act = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    probe = common(act.add_parser('probe', help='verify the configured tool executables (runs --version / --help)'))
    _tool_options(probe)
    run = common(act.add_parser('run', help='run the profile engines on both artifacts and store the evidence'))
    run.add_argument('project', type=Path)
    run.add_argument('--profile', choices=('basic', 'context', 'full'), default='basic')
    run.add_argument('--engines', type=_engines, default=None, help='subset of the profile, e.g. capa,floss')
    run.add_argument('--floss-deobfuscate', action='store_true',
                     help='also run FLOSS stack/tight/decoded extraction (CPU emulator; prints the consent text)')
    run.add_argument('--floss-min-length', type=int, default=None, metavar='N')
    run.add_argument('--floss-large-file', action='store_true', help='pass -L (emulate files above 16 MiB)')
    run.add_argument('--diec-heuristic', action='store_true')
    run.add_argument('--capa-backend', choices=('vivisect', 'ghidra'), default='vivisect')
    run.add_argument('--ghidra-dir', type=Path)
    run.add_argument('--java-home', type=Path)
    run.add_argument('--timeout', type=int, default=None, help='seconds per job (10..86400)')
    run.add_argument('--memory-mb', type=int, default=None, help='per-process memory cap in MiB (default: FLOSS '
                     'emulation 4096, otherwise none)')
    run.add_argument('--max-parallel', type=int, choices=(1, 2), default=1)
    run.add_argument('--no-cache', action='store_true')
    run.add_argument('--scratch', type=Path, help='parent folder for the private per-job scratch directories')
    _tool_options(run)
    delta = common(act.add_parser('delta', help='compare stored older/newer evidence (never runs a tool)'))
    delta.add_argument('project', type=Path)
    delta.add_argument('--engines', type=_engines, default=None)
    delta.add_argument('--show-secrets', action='store_true')


def _path(args, name: str, env_key: str) -> Path | None:
    from ...cli import ENVIRONMENT, CliError
    value = getattr(args, name, None) or (Path(os.environ[ENV[env_key]]) if os.environ.get(ENV[env_key]) else None)
    if value is not None and not Path(value).is_absolute():
        raise CliError(ENVIRONMENT, f'--{name.replace("_", "-")} / {ENV[env_key]} must be an absolute path '
                       '(PATH is never searched)')
    return Path(value) if value is not None else None


def build_setup(args):
    from . import capa, diec, floss
    from .runner import Setup
    exe = {engine: _path(args, engine, engine) for engine in ENGINES}
    accept = {engine: getattr(args, f'{engine}_accept_untested', False) for engine in ENGINES}
    deobfuscate = getattr(args, 'floss_deobfuscate', False)
    return Setup(
        capa=capa.CapaConfig(exe['capa'], backend=getattr(args, 'capa_backend', 'vivisect'),
                             rules_dir=_path(args, 'capa_rules', 'capa_rules'),
                             sigs_dir=_path(args, 'capa_sigs', 'capa_sigs'), ghidra_dir=getattr(args, 'ghidra_dir', None),
                             java_home=getattr(args, 'java_home', None), accept_untested=accept['capa'])
        if exe['capa'] else None,
        floss=floss.FlossConfig(exe['floss'], deobfuscate=deobfuscate,
                                consent_sha256=floss.EMULATION_CONSENT_SHA256 if deobfuscate else None,
                                min_length=getattr(args, 'floss_min_length', None),
                                large_file=getattr(args, 'floss_large_file', False),
                                accept_untested=accept['floss']) if exe['floss'] else None,
        diec=diec.DiecConfig(exe['diec'], database=_path(args, 'diec_db', 'diec_db'),
                             library_path=_path(args, 'diec_lib', 'diec_lib'),
                             heuristic=getattr(args, 'diec_heuristic', False),
                             accept_untested=accept['diec']) if exe['diec'] else None)


def _manifest_row(manifest) -> dict:
    return {'engine': manifest.engine, 'supported': manifest.supported, 'version': manifest.version,
            'pin_status': manifest.pin_status, 'untested_version': manifest.untested_version,
            'executable': Path(manifest.cli_path).name if manifest.cli_path else None,
            'rules_source': manifest.rules_source, 'capabilities': list(manifest.capabilities),
            'reason': manifest.reason}


def _probe(args, cancel: threading.Event) -> int:
    from ...cli import ENVIRONMENT, OK, _emit
    from .runner import probe_engine
    setup = build_setup(args)
    configured = [e for e in ENGINES if setup.config(e) is not None] or list(ENGINES)
    manifests = [probe_engine(e, setup.config(e), cancel, _runner()) for e in configured]
    rows = [_manifest_row(m) for m in manifests]
    text = '\n'.join(f'{r["engine"]}: ' + (f'supported {r["version"]} ({r["pin_status"]})' if r['supported']
                                           else f'not usable - {r["reason"]}') for r in rows)
    _emit(args, 'intel-tools probe', 'complete', {'engines': rows}, [], text)
    return OK if any(m.supported for m in manifests) else ENVIRONMENT


def _runner():
    from ...jobs import run_process
    return run_process


def _artifacts(service):
    from .runner import ArtifactRef
    return tuple(ArtifactRef(a.side, service.root / a.relative_path, a.sha256, a.size)
                 for a in service.project.artifacts)


def _run_exit(results, cancelled: bool) -> tuple[int, str]:
    from ...cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME
    if cancelled or any(r.run.status == 'cancelled' for r in results):
        return CANCELLED, 'cancelled'
    if all(r.run.status in ('absent', 'unsupported') for r in results):
        return ENVIRONMENT, 'failed'
    produced = [r for r in results if r.run.status in ('ok', 'none-found')]
    if len(produced) != len(results):
        return RUNTIME, 'partial' if produced else 'failed'
    return (OK, 'complete') if all(r.run.evidence_count for r in results) else (
        (NO_RESULTS, 'complete') if not any(r.run.evidence_count for r in results) else (RUNTIME, 'partial'))


def _run(args, cancel: threading.Event) -> int:
    from ...cli import ENVIRONMENT, RUNTIME, CliError, _emit, _open
    from ...enrichment.storage import EnrichmentStore
    from . import floss
    from .common import ToolError
    from .runner import RunRequest, run_tools
    from .store import ToolStore
    setup = build_setup(args)
    if args.floss_deobfuscate:
        import sys
        print('FLOSS deobfuscation consent text:\n' + floss.EMULATION_CONSENT, file=sys.stderr)
    memory = args.memory_mb * 1024 * 1024 if args.memory_mb else None
    service = _open(args.project)
    try:
        project = service.project
        if len(project.artifacts) != 2:
            raise CliError(ENVIRONMENT, 'the project needs an older and a newer artifact')
        ts = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
        request = RunRequest(_artifacts(service), setup, profile=args.profile, engines=args.engines,
                             scratch_root=args.scratch, max_parallel=args.max_parallel, use_cache=not args.no_cache,
                             timeout=args.timeout, memory_limit_bytes=memory)
        try:
            results = run_tools(request, ts, cancel)
        except ToolError as exc:
            raise CliError(ENVIRONMENT if exc.code in ('PT-TOOL-INPUT', 'PT-TOOL-CONSENT') else RUNTIME,
                           str(exc)) from None
        code, status = _run_exit(results, cancel.is_set())
        rows = [{'engine': r.run.engine, 'side': r.run.side, 'status': r.run.status, 'error_code': r.run.error_code,
                 'error': r.run.error, 'run_id': r.run.run_id, 'cache_hit': r.run.cache_hit,
                 'evidence': r.run.evidence_count, 'elapsed_ms': r.run.elapsed,
                 'executable': Path(r.run.manifest.cli_path).name or None,
                 'pin_status': r.run.manifest.pin_status} for r in results]
        text = '\n'.join(f'{r["engine"]:<6} {r["side"]:<6} {r["status"]:<11} evidence {r["evidence"]}'
                         + (' (cache)' if r['cache_hit'] else '') + (f' [{r["error_code"]}] {r["error"]}'
                                                                      if r['error_code'] else '') for r in rows)
        _emit(args, 'intel-tools run', status, {'profile': args.profile, 'runs': rows}, [], text)
        return code
    finally:
        service.close()


def _delta(args, cancel: threading.Event) -> int:
    from ...cli import NO_RESULTS, OK, RUNTIME, CliError, _emit, _open
    from ...enrichment.storage import EnrichmentStore
    from . import delta as delta_mod
    from .common import ToolError
    from .normalize import FunctionPairing
    from .store import ToolStore
    service = _open(args.project)
    try:
        project = service.project
        ts = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
        engines = args.engines or tuple(e for e in ENGINES if ts.runs(e))
        if not engines:
            _emit(args, 'intel-tools delta', 'complete', {'deltas': [], 'missing': list(ENGINES)}, [],
                  'No stored tool evidence: run `intel-tools run` first.')
            return 2
        latest = {(e, s): ts.latest(e, s) for e in engines for s in ('older', 'newer')}

        def evidence(engine, side):
            found = latest[(engine, side)]
            return found[1] if found else None
        flags = delta_mod.quality_flags((evidence('diec', 'older'), evidence('diec', 'newer')) if 'diec' in engines
                                        else (None, None),
                                        (evidence('capa', 'older'), evidence('capa', 'newer')) if 'capa' in engines
                                        else (None, None))
        deltas, missing, rejected = [], [], []
        for engine in engines:
            old, new = latest[(engine, 'older')], latest[(engine, 'newer')]
            if old is None or new is None:
                missing.append(engine)
                continue
            base = {s: evidence(engine, s).image_base for s in ('older', 'newer')}
            if project.matches and all(base.values()):
                pairing = FunctionPairing.from_project(project.matches, None, older_base=base['older'],
                                                       newer_base=base['newer'])
            else:
                pairing = FunctionPairing.empty()
            try:
                result = delta_mod.compute(old[0], old[1], new[0], new[1], pairing=pairing, flags=flags,
                                           show_secrets=args.show_secrets)
            except ToolError as exc:
                raise CliError(RUNTIME, str(exc)) from None
            if not result.comparable:
                rejected.append(engine)
            deltas.append(result)
        changed = any(d.comparable and delta_mod.has_changes(d) for d in deltas)
        if rejected:
            code, status = RUNTIME, 'partial'
        elif missing:
            code, status = 2, 'partial' if deltas else 'failed'
        else:
            code, status = (OK if changed else NO_RESULTS), 'complete'
        payload = {'deltas': [d.model_dump(mode='json') for d in deltas], 'missing': missing, 'rejected': rejected}
        lines = [f'{d.engine}: ' + ('not comparable - ' + '; '.join(d.reasons) if not d.comparable else
                                    f'{len(d.capabilities)} capability rows, {len(d.strings)} string rows, '
                                    f'{len(d.environment)} environment rows, {len(d.flags)} flags')
                 for d in deltas] + [f'{e}: evidence missing for a side' for e in missing]
        _emit(args, 'intel-tools delta', status, payload, [], '\n'.join(lines))
        return code
    finally:
        service.close()


def dispatch(args, cancel: threading.Event) -> int:
    return {'probe': _probe, 'run': _run, 'delta': _delta}[args.action](args, cancel)
