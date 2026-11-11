"""`patchtrace doctor`: one machine-readable health report (docs/specs/cli-profile-doctor-runtime.md section 3). No Qt.

Reports only facts that need no process and no network: the version, the interpreter, the optional dependencies, the
verb files, the fast check of a bundled runtime, the runtime candidates that discovery finds, and whether the per-user
directories can be written. It never calls `backend.diagnose`; a candidate is not a verified runtime and the report
says so. The `platform` module is not used because it can start `uname`.

Envelope `enrichment-cli/1`, result `doctor/1`. Exit codes: 0 no check is a problem (warnings never change the code);
4 at least one check is a problem (the command worked; the positive result, a healthy installation, is missing);
2 invalid arguments; 5 cancelled during the bundle walk.
"""
from __future__ import annotations

import os
import sys
import tempfile
from argparse import ArgumentParser, Namespace
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event

from .hostile_text import escape_text

SUMMARY = 'health report: version, dependencies, verbs, bundle, runtime candidates'
CONTRACT = 'doctor/1'
STATUSES = ('ok', 'warning', 'problem', 'not-applicable')
MAX_LINE = 400    # characters of one detail or remedy; file names in them come from disk
MAX_SHOWN = 3     # candidate paths of one kind, or failed verb files, named in a detail line
HINTS = (('PATCHTRACE_BACKEND_PYTHON', 'python'), ('GHIDRA_INSTALL_DIR', 'ghidra'))
NEXT_STEP = ('Not checked here because it starts the runtime: run `patchtrace backend diagnose` for a bundled '
             'runtime, or Diagnose dependencies in the desktop Setup dialog.')


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    status: str   # one of STATUSES
    detail: str   # one line
    remedy: str = ''  # one line; empty when nothing needs doing


def add_parser(sub) -> ArgumentParser:
    parser = sub.add_parser('doctor', help=SUMMARY, description='Health report of this PatchTrace installation. '
                            'Starts no process and uses no network; exit 4 when a check is a problem.')
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    parser.add_argument('--bundle-dir', type=Path, metavar='DIR',
                        help='directory that contains backend/ (default: next to the executable)')
    parser.add_argument('--work-dir', type=Path, metavar='DIR',
                        help='per-user writable work directory (default: the platform user state directory)')
    parser.add_argument('--profiles-dir', type=Path, metavar='DIR',
                        help='profile folder (default: the folder the desktop uses)')
    return parser


def _line(text: object) -> str:
    """One bounded line: whitespace runs collapse and control or bidi characters are spelled, not printed."""
    flat = escape_text(' '.join(str(text).split()))
    return flat if len(flat) <= MAX_LINE else flat[:MAX_LINE] + '...'


def python_check(bits: int) -> Check:
    build = 'frozen executable' if getattr(sys, 'frozen', False) else 'source install'
    detail = f'Python {".".join(map(str, sys.version_info[:3]))} ({sys.implementation.name}, {bits}-bit, {build})'
    if bits < 64:
        return Check('python', 'problem', f'{detail}; a 32-bit interpreter cannot hold the files PatchTrace reads',
                     'use the 64-bit PatchTrace build, or a 64-bit Python 3.12 or newer')
    return Check('python', 'ok', detail)


def _machine(environ: Mapping[str, str]) -> str:
    return os.uname().machine if hasattr(os, 'uname') else environ.get('PROCESSOR_ARCHITECTURE', '') or 'unknown'


def _optional_check() -> tuple[Check, list[dict]]:
    from . import optional_deps
    capabilities = list(optional_deps.probe().values())
    missing = sorted({f'pip install "patchtrace[{cap.extra}]"' for cap in capabilities if not cap.available})
    facts = [{'name': cap.name, 'extra': cap.extra, 'available': cap.available, 'version': cap.version}
             for cap in capabilities]
    detail = optional_deps.summary_line().removeprefix('optional-deps: ')  # the check id already says it
    return Check('optional-deps', 'warning' if missing else 'ok', detail, '; '.join(missing)), facts


def _verbs_check() -> tuple[Check, dict]:
    from .cli_commands import discover
    verbs, failed = discover()
    facts = {'loaded': len(verbs), 'failed': dict(failed)}
    if not failed:
        return Check('cli-verbs', 'ok', f'all {len(verbs)} verb files load'), facts
    shown = ', '.join(f'{module} ({error})' for module, error in list(failed.items())[:MAX_SHOWN])
    more = f' and {len(failed) - MAX_SHOWN} more' if len(failed) > MAX_SHOWN else ''
    return Check('cli-verbs', 'problem', _line(f'{len(failed)} verb file(s) cannot be loaded: {shown}{more}'),
                 'reinstall or update PatchTrace: a verb file is damaged or one of its imports is missing'), facts


def _bundle_check(bundle_dir: Path | None, environ: Mapping[str, str], cancel: Event):
    """(check, facts, BundleStatus | None). BundleCancelled becomes exit 5."""
    from .backend_bundle import BundleCancelled
    from .cli_commands import CANCELLED, CliError
    from .runtime_discovery import EXTRACT_AGAIN, check_bundle
    try:
        status = check_bundle(bundle_dir, environ, cancel=cancel)
    except BundleCancelled:
        raise CliError(CANCELLED, 'cancelled') from None
    if status is None:
        return Check('bundle', 'not-applicable', 'no bundled runtime next to PatchTrace (no backend directory)'), None, None
    facts = {'runtime_id': status.runtime_id, 'ok': status.ok, 'code': status.code, 'files': status.files,
             'bytes': status.bytes}
    if status.ok:
        detail = f'{status.line()} ({status.files:,} files, {status.bytes:,} bytes; presence and size only, no hashing)'
        return Check('bundle', 'ok', _line(detail)), facts, status
    more = f' (and {len(status.problems) - 1} more)' if len(status.problems) > 1 else ''
    return Check('bundle', 'problem', _line(f'{status.problems[0]}{more}'),
                 f'{EXTRACT_AGAIN}; `patchtrace backend verify` lists every problem'), facts, status


def _accepted(hint: str, candidates: Sequence[Path]) -> bool:
    try:
        wanted = os.path.normcase(str(Path(hint).resolve()))
    except (OSError, RuntimeError, ValueError):
        return False
    return any(os.path.normcase(str(candidate)) == wanted for candidate in candidates)


def _shown(label: str, paths: Sequence[Path]) -> str:
    more = f' (+{len(paths) - MAX_SHOWN} more)' if len(paths) > MAX_SHOWN else ''
    return f'{label}: {", ".join(map(str, paths[:MAX_SHOWN]))}{more}' if paths else ''


def _runtimes_check(bundle_dir: Path | None, environ: Mapping[str, str], bundle_status) -> tuple[Check, dict]:
    from .runtime_discovery import discover_local_runtimes, exclude_bundle
    found = discover_local_runtimes(environ, bundle_exe_dir=bundle_dir)
    if bundle_status is not None and not bundle_status.ok:
        found = exclude_bundle(found)  # as in Setup: an unusable bundle is never offered
    kinds = {'python': found.python_executables, 'ghidra': found.ghidra_roots}
    facts = {'python': [str(p) for p in kinds['python']], 'ghidra': [str(p) for p in kinds['ghidra']],
             'bindiff': [str(p) for p in found.bindiff_executables],
             'bundle_roots': [str(p) for p in found.bundle_roots], 'verified': False}
    pythons, ghidras = len(kinds['python']), len(kinds['ghidra'])
    rejected = [name for name, kind in HINTS if environ.get(name) and not _accepted(environ[name], kinds[kind])]
    count = f'{pythons} Python and {ghidras} Ghidra candidate{"" if ghidras == 1 else "s"}'
    paths = '; '.join(filter(None, (_shown('Python', kinds['python']), _shown('Ghidra', kinds['ghidra']))))
    if rejected:
        return Check('runtimes', 'warning', _line(f'{" and ".join(rejected)} is set but was not accepted as a '
                     f'candidate; {count} found' + (f' ({paths})' if paths else '')),
                     'point the variable at an existing regular file (Python) or at a Ghidra directory that '
                     'contains Ghidra/application.properties (not a link), or unset it'), facts
    if not pythons and not ghidras:
        return Check('runtimes', 'warning', 'no Python and no Ghidra candidate found; comparing two files needs an '
                     'analysis runtime, everything else works without one',
                     'install an offline backend ZIP or set the paths in the desktop Setup dialog '
                     '(Install offline backend ZIP)'), facts
    if not pythons or not ghidras:
        return Check('runtimes', 'warning', _line(f'{count} found; a runtime needs both ({paths})'),
                     'install the missing part, or an offline backend ZIP from the desktop Setup '
                     'dialog'), facts
    return Check('runtimes', 'ok', _line(f'{count} found, not verified (no process was started); {paths}')), facts


def _writable(path: Path) -> tuple[bool, str]:
    """Probe `path`, or its nearest existing ancestor when it is absent, with one unnamed temporary file."""
    path = Path(os.path.abspath(path))
    target = next((item for item in (path, *path.parents) if os.path.lexists(item)), path)
    if not target.is_dir():
        return False, f'{target} is not a directory'
    try:
        with tempfile.TemporaryFile(dir=target):
            pass
    except OSError as exc:
        return False, exc.strerror or type(exc).__name__
    return True, 'is writable' if target == path else f'does not exist yet and can be created under {target}'


def _directory_check(check_id: str, path: Path, flag: str, when_blocked: str) -> Check:
    writable, wording = _writable(path)
    if writable:
        return Check(check_id, 'ok', _line(f'{path} {wording}'))
    return Check(check_id, when_blocked, _line(f'{path} is not writable: {wording}'),
                 f'fix the permissions of the directory, or name another one with {flag} DIR')


def collect(args: Namespace, environ: Mapping[str, str], cancel: Event) -> tuple[list[Check], dict]:
    """Every check in the documented order, and the structured facts behind them."""
    from . import __version__
    from .enrichment.profiles import default_profiles_dir
    from .runtime_discovery import bundle_work_dir
    bits = 64 if sys.maxsize > 2 ** 32 else 32
    machine = _line(_machine(environ))
    optional, optional_facts = _optional_check()
    verbs, verb_facts = _verbs_check()
    bundle, bundle_facts, bundle_status = _bundle_check(args.bundle_dir, environ, cancel)
    runtimes, runtime_facts = _runtimes_check(args.bundle_dir, environ, bundle_status)
    work = Path(args.work_dir) if args.work_dir is not None else bundle_work_dir(environ)
    profiles = Path(args.profiles_dir) if args.profiles_dir is not None else default_profiles_dir()
    checks = [
        Check('version', 'ok', f'PatchTrace {__version__}'),
        python_check(bits),
        Check('platform', 'ok', f'{sys.platform} ({os.name}), {machine}'),
        optional, verbs, bundle, runtimes,
        _directory_check('work-dir', work, '--work-dir', 'problem'),
        _directory_check('profiles-dir', profiles, '--profiles-dir', 'warning'),  # profiles are optional
    ]
    facts = {
        'version': __version__,
        'python': {'version': '.'.join(map(str, sys.version_info[:3])), 'implementation': sys.implementation.name,
                   'bits': bits, 'frozen': bool(getattr(sys, 'frozen', False))},
        'platform': {'system': sys.platform, 'os': os.name, 'machine': machine},
        'optional_deps': optional_facts, 'verbs': verb_facts, 'bundle': bundle_facts,
        'runtime_candidates': runtime_facts, 'directories': {'work': str(work), 'profiles': str(profiles)},
    }
    return checks, facts


def run(args: Namespace, cancel: Event) -> int:
    from .cli_commands import NO_RESULTS, OK, emit
    checks, facts = collect(args, os.environ, cancel)
    summary = {status: sum(check.status == status for check in checks) for status in STATUSES}
    healthy = summary['problem'] == 0
    result = {'contract': CONTRACT, 'healthy': healthy, 'summary': summary,
              'checks': [asdict(check) for check in checks], 'facts': facts}
    lines = [f'{check.status:<14}  {check.id}: {check.detail}' + (f' - remedy: {check.remedy}' if check.remedy else '')
             for check in checks]
    counts = ', '.join(f'{summary[status]} {status}' for status in STATUSES)
    problems = summary['problem']
    verdict = 'no problem found' if healthy else f'{problems} problem{"" if problems == 1 else "s"} found'
    lines += [f'doctor: {verdict} ({counts})', NEXT_STEP]
    emit(args, 'doctor', 'complete' if healthy else 'no-results', result, [], '\n'.join(lines))
    return OK if healthy else NO_RESULTS
