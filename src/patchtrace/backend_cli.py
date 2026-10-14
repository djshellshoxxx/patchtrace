"""`patchtrace backend ...`: bundled-runtime status, verification, selftest and diagnose.

BUNDLE plan section 8. Own dispatcher module; ``cli.py`` only registers it. Output uses the
``enrichment-cli/1`` envelope. Exit codes: 0 success, 2 invalid arguments/environment, 3 backend
failure, 4 no result (status/verify: no bundle; selftest: expectation not met), 5 bundle
verification failure or cancellation. Never imports Qt and never executes a target binary; the
only process ``selftest`` and ``diagnose`` start is the bundled Python through ``backend``.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

ACTIONS = ('status', 'verify', 'selftest', 'diagnose')
OK, USAGE, BACKEND_FAILED, NO_RESULT, BUNDLE_FAILED = 0, 2, 3, 4, 5
TIMEOUT_RANGE = (10, 86400)
AUTHENTICITY = ('integrity only: the manifest proves the files are intact and complete, '
                'not who published them')


def register(sub, common) -> None:
    """Add ``backend`` and its subcommands to the cli subparsers (``common`` adds --json)."""
    backend = sub.add_parser('backend', help='bundled analysis runtime: status, verify, selftest, diagnose')
    actions = backend.add_subparsers(dest='action', required=True, parser_class=type(backend))

    def leaf(name: str, help_text: str):
        parser = common(actions.add_parser(name, help=help_text))
        parser.add_argument('--bundle-dir', type=Path, metavar='DIR',
                            help='directory that contains backend/ (default: next to the executable)')
        parser.add_argument('--work-dir', type=Path, metavar='DIR',
                            help='per-user writable work directory (default: the platform user state directory)')
        return parser

    leaf('status', 'report the bundle next to PatchTrace after a fast file check (starts no process)')
    verify = leaf('verify', 'verify the bundle files against backend/manifest.json')
    verify.add_argument('--full', action='store_true', help='also hash every file (slow, cancellable)')
    selftest = leaf('selftest', 'run a real comparison through the bundled runtime and check the result')
    selftest.add_argument('--older', type=Path, required=True, help='older PE x64 artifact (never executed)')
    selftest.add_argument('--newer', type=Path, required=True, help='newer PE x64 artifact (never executed)')
    selftest.add_argument('--expect-function', action='append', required=True, metavar='NAME',
                          help='function name that must appear in the result (repeatable)')
    selftest.add_argument('--project-dir', type=Path, metavar='DIR',
                          help='new empty project directory (default: under the work directory)')
    selftest.add_argument('--timeout', type=int, default=3600, help='analysis timeout seconds (10..86400)')
    leaf('diagnose', 'run the backend dependency diagnosis with the bundled runtime')


def cmd_backend(args, cancel: threading.Event) -> int:
    return {'status': _status, 'verify': _verify, 'selftest': _selftest, 'diagnose': _diagnose}[args.action](
        args, cancel)


def _out(args, status: str, result, text: str, warnings: list[str] | None = None) -> None:
    from .cli import _emit
    _emit(args, f'backend {args.action}', status, result, warnings or [], text)


def _problem_docs(problems) -> list[dict]:
    return [{'code': p.code, 'path': p.path} for p in problems]


def _work_dir(args) -> Path:
    from .runtime_discovery import bundle_work_dir
    return Path(args.work_dir) if args.work_dir else bundle_work_dir()


def _find(args):
    """(BundleRef | None, BundleStatus | None): the status is set when nothing usable was found."""
    from .backend_bundle import BundleError, BundleProblem, find_bundled_runtime
    from .runtime_discovery import BundleStatus
    try:
        ref = find_bundled_runtime(args.bundle_dir)
    except BundleError as exc:
        return None, BundleStatus(None, (BundleProblem(exc.code, str(exc).partition(': ')[2] or 'backend'),))
    return ref, None


def _versions(ref) -> dict:
    from .backend_bundle import BundleError, _load_manifest
    try:
        data = _load_manifest(ref.manifest_path, ref.platform)[0]
    except BundleError:
        return {}
    versions = data.get('versions')
    return dict(versions) if isinstance(versions, dict) else {}


def _no_bundle(args) -> int:
    _out(args, 'no-results', {'bundle': {'found': False}},
         'No bundled runtime found next to PatchTrace (no backend/manifest.json).')
    return NO_RESULT


def _failed(args, status, extra: dict | None = None) -> int:
    result = {'bundle': {'found': True, 'runtime_id': status.runtime_id, 'fast_check': 'failed',
                         'problems': _problem_docs(status.problems)}} | (extra or {})
    _out(args, 'failed', result, status.line())
    return BUNDLE_FAILED


def _status(args, cancel) -> int:
    from .backend_bundle import BundleCancelled, is_full_verified
    from .runtime_discovery import check_bundle
    try:
        status = check_bundle(args.bundle_dir, cancel=cancel)
    except BundleCancelled:
        return _cancelled(args)
    if status is None:
        return _no_bundle(args)
    if status.ref is None or not status.ok:
        return _failed(args, status)
    ref = status.ref
    versions = _versions(ref)
    full = is_full_verified(ref, _work_dir(args))
    doc = {'found': True, 'runtime_id': ref.runtime_id, 'platform': ref.platform, 'root': str(ref.root),
           'manifest_sha256': ref.manifest_sha256, 'versions': versions, 'fast_check': 'ok',
           'files': status.files, 'bytes': status.bytes, 'full_verified': full, 'problems': [],
           'authenticity': AUTHENTICITY}
    shown = ', '.join(f'{k} {v}' for k, v in sorted(versions.items()))
    text = '\n'.join([status.line(), f'  {ref.platform}; {shown}',
                      f'  {status.files:,} files, {status.bytes:,} bytes',
                      '  full hash verification: ' + ('recorded for this manifest' if full else 'not yet run'),
                      f'  {AUTHENTICITY}'])
    _out(args, 'complete', {'bundle': doc}, text)
    return OK


def _cancelled(args) -> int:
    _out(args, 'cancelled', None, 'cancelled')
    return BUNDLE_FAILED


def _verify(args, cancel) -> int:
    from .backend_bundle import BundleCancelled, verify_bundle
    ref, failed = _find(args)
    if failed is not None:
        return _failed(args, failed)
    if ref is None:
        return _no_bundle(args)
    mode = 'full' if args.full else 'fast'
    try:
        report = verify_bundle(ref, mode=mode, cancel=cancel, work_dir=_work_dir(args),
                               event=lambda message: print(message, file=sys.stderr))
    except BundleCancelled:
        return _cancelled(args)
    doc = {'mode': mode, 'ok': report.ok, 'runtime_id': ref.runtime_id, 'files': report.checked,
           'bytes': report.bytes, 'problems': _problem_docs(report.problems), 'truncated': report.truncated}
    if report.ok:
        _out(args, 'complete', {'verify': doc},
             f'Bundled runtime {ref.runtime_id}: {mode} verification ok '
             f'({report.checked:,} files, {report.bytes:,} bytes)\n{AUTHENTICITY}')
        return OK
    lines = [str(p) for p in report.problems] + (['... more problems not shown'] if report.truncated else [])
    _out(args, 'failed', {'verify': doc},
         f'Bundled runtime {ref.runtime_id}: {mode} verification failed - extract the complete ZIP again\n'
         + '\n'.join(lines))
    return BUNDLE_FAILED


def _config(args, ref, **overrides):
    from .backend import BackendConfig
    from .backend_bundle import bundle_backend_kwargs
    kwargs = bundle_backend_kwargs(ref, _work_dir(args))
    kwargs.pop('cache_dir')  # a cached result must never stand in for a real run
    return BackendConfig(**kwargs, allow_symbol_downloads=False, **overrides)


def _diagnose(args, cancel) -> int:
    from .backend import diagnose
    from .backend_bundle import BundleError
    from .runtime_discovery import check_bundle
    status = check_bundle(args.bundle_dir, cancel=cancel)
    if status is None:
        _out(args, 'failed', {'bundle': {'found': False}}, 'No bundled runtime found next to PatchTrace.')
        return USAGE
    if status.ref is None or not status.ok:
        return _failed(args, status)
    try:
        lines = diagnose(_config(args, status.ref))
    except BundleError as exc:
        from .cli import CliError
        raise CliError(USAGE, str(exc)) from None
    problems = [line for line in lines if line.startswith('PT-')]
    bundle_failed = any(line.startswith('PT-BUNDLE-') for line in problems)
    _out(args, 'failed' if problems else 'complete', {'lines': lines, 'problems': problems}, '\n'.join(lines))
    return BUNDLE_FAILED if bundle_failed else (BACKEND_FAILED if problems else OK)


def _event_printer(event) -> None:
    print(f'selftest: {event.stage}: {event.message}', file=sys.stderr)


def _selftest(args, cancel) -> int:
    from .backend_bundle import BundleError, check_work_dir
    from .cli import CliError
    from .runtime_discovery import check_bundle
    if not TIMEOUT_RANGE[0] <= args.timeout <= TIMEOUT_RANGE[1]:
        raise CliError(USAGE, '--timeout must be between 10 and 86400 seconds')
    for label, path in (('--older', args.older), ('--newer', args.newer)):
        if not Path(path).is_file():
            raise CliError(USAGE, f'{label} must be an existing file')
    status = check_bundle(args.bundle_dir, cancel=cancel)
    if status is None:
        raise CliError(USAGE, 'no bundled runtime found next to PatchTrace (backend/manifest.json is missing)')
    if status.ref is None or not status.ok:
        return _failed(args, status)
    ref = status.ref
    try:
        work = check_work_dir(ref, _work_dir(args))
        if args.project_dir is not None:
            check_work_dir(ref, args.project_dir)
        config = _config(args, ref, timeout_seconds=args.timeout)
    except BundleError as exc:
        raise CliError(USAGE, str(exc)) from None
    root = _project_root(args, work)
    return _run_selftest(args, cancel, config, ref, root)


def _project_root(args, work: Path) -> Path:
    from .cli import CliError
    from .models import uid
    root = Path(args.project_dir) if args.project_dir else work / 'selftest' / uid()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise CliError(USAGE, f'project directory must be new or empty: {root}')
    return root


def _run_selftest(args, cancel, config, ref, root: Path) -> int:
    from . import backend
    from .cli import CliError
    from .service import ProjectService
    try:
        service = ProjectService.create(args.older, args.newer, 'bundle selftest', root)
    except (OSError, ValueError) as exc:
        raise CliError(USAGE, f'cannot create the selftest project: {exc}') from None
    try:
        if any(run.status == 'identical' for run in service.project.runs):
            raise CliError(USAGE, 'the older and newer artifacts are identical; use two different builds')
        snapshot = service.project.model_copy(deep=True)
        raw_path, run = backend.run_comparison(config, snapshot, service.root, cancel, _event_printer)
        error = None
        if run.status == 'completed':
            try:
                service.apply_import(service.prepare_analysis(raw_path, run))
            except Exception as exc:  # noqa: BLE001 - normalization failure is a backend result problem
                error = str(exc)
                run = backend.quarantine_failed_run(service.root, run, error)
        else:
            error = run.error or f'comparison {run.status}'
        base = {'runtime_id': ref.runtime_id, 'project_dir': str(service.root), 'run_status': run.status}
        if error is not None or run.status != 'completed':
            _out(args, 'cancelled' if run.status == 'cancelled' else 'failed', base | {'error': error},
                 f'selftest failed ({run.status}): {error}')
            return BUNDLE_FAILED if run.status == 'cancelled' else BACKEND_FAILED
        return _expectations(args, service, base)
    finally:
        service.close()


def _expectations(args, service, base: dict) -> int:
    names: set[str] = set()
    for match in service.project.matches:
        for function in (*match.older, *match.newer):
            names.add(function.name)
            upstream = function.metadata.get('upstream_name')
            if isinstance(upstream, str):
                names.add(upstream)
    expected = {name: name in names for name in args.expect_function}
    result = base | {'matches': len(service.project.matches), 'expected_functions': expected}
    if all(expected.values()):
        _out(args, 'complete', result,
             f'selftest passed: {len(service.project.matches)} matches; expected functions found: '
             + ', '.join(expected))
        return OK
    missing = [name for name, found in expected.items() if not found]
    _out(args, 'no-results', result, 'selftest ran but the expected function(s) were not in the result: '
         + ', '.join(missing))
    return NO_RESULT
