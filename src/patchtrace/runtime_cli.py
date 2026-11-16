"""Headless offline archive inspection/installation; no runtime execution or download."""
from __future__ import annotations

import os
import re
import stat
import sys
from argparse import ArgumentParser
from pathlib import Path

from . import backend_bundle, offline_bundle
from .cli_commands import CANCELLED, ENVIRONMENT, OK, RUNTIME, CliError, emit

AUTHENTICITY = 'SHA-256 verifies archive integrity, not publisher authenticity.'
SUMMARY = 'inspect or install a local offline runtime archive'


def add_parser(sub) -> ArgumentParser:
    parser = sub.add_parser('runtime', help=SUMMARY)
    leaves = parser.add_subparsers(dest='action', required=True)
    for name in ('inspect-zip', 'install-zip'):
        leaf = leaves.add_parser(name, help='verify archive' if name == 'inspect-zip' else 'install verified archive')
        leaf.set_defaults(command_label=f'runtime {name}')
        leaf.add_argument('file', type=Path)
        leaf.add_argument('--sha256', required=name == 'install-zip', metavar='HEX')
        leaf.add_argument('--json', action='store_true')
        if name == 'install-zip':
            leaf.add_argument('--confirm', action='store_true', help='required: install the verified archive')
            leaf.add_argument('--runtimes-dir', type=Path, metavar='DIR')
    return parser


def _root(args) -> Path:
    if args.runtimes_dir is not None:
        root = args.runtimes_dir
    else:
        key = 'LOCALAPPDATA' if os.name == 'nt' else 'HOME'
        value = os.environ.get(key)
        if not value:
            raise CliError(ENVIRONMENT, f'PT-OFFLINE: {key} is unset; supply --runtimes-dir')
        root = Path(value) / ('PatchTrace/runtimes' if os.name == 'nt' else '.local/share/patchtrace/runtimes')
    if not root.is_absolute():
        raise CliError(ENVIRONMENT, 'PT-OFFLINE: --runtimes-dir must be absolute')
    return root


def _cleanup(created) -> None:
    for path, recorded in reversed(created):
        try:
            current = path.lstat()
            if stat.S_ISDIR(current.st_mode) and os.path.samestat(current, recorded):
                path.rmdir()  # never recurse: a concurrent/committed runtime keeps its ancestors
        except OSError:
            pass


def _inspect(plan, expected) -> dict:
    host = backend_bundle.host_platform() if sys.platform in ('linux', 'win32') else sys.platform
    return {'contract': 'runtime-cli/1', 'archive': plan.archive.name, 'sha256': plan.sha256,
            'sha256_expected': expected, 'sha256_matched': True if expected else None,
            'runtime_id': plan.runtime_id, 'platform': plan.platform, 'architecture': plan.manifest['architecture'],
            'versions': dict(plan.manifest['versions']), 'files': plan.file_count, 'bytes': plan.total_bytes,
            'python': plan.python_relative, 'ghidra': plan.ghidra_relative, 'java': plan.java_relative,
            'host_platform': host,
            'installable_here': plan.platform == host, 'authenticity': AUTHENTICITY}


def run(args, cancel) -> int:
    installing = args.action == 'install-zip'
    if installing and not args.confirm:
        raise CliError(ENVIRONMENT, 'PT-OFFLINE: --confirm is required; nothing was read or installed')
    if installing and sys.platform not in ('linux', 'win32'):
        raise CliError(ENVIRONMENT, 'PT-OFFLINE: runtime installation supports Linux and Windows hosts only')
    expected = args.sha256
    if expected is not None:
        if not re.fullmatch(r'[0-9a-fA-F]{64}', expected):
            raise CliError(ENVIRONMENT, 'PT-OFFLINE: --sha256 must be 64 hexadecimal characters')
        expected = expected.lower()
    root = _root(args) if installing else None
    try:
        plan = offline_bundle.inspect_offline_bundle(
            args.file, expected_sha256=expected, cancel=cancel,
            platforms=(backend_bundle.host_platform(),) if installing else ('windows', 'linux'))
    except offline_bundle.OfflineBundleCancelled as exc:
        raise CliError(CANCELLED, str(exc)) from None
    except offline_bundle.OfflineBundleError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    if not installing:
        result = _inspect(plan, expected)
        text = (f'Verified {plan.runtime_id}: {plan.file_count} files, {plan.total_bytes} bytes; '
                f'platform {plan.platform}.\n{AUTHENTICITY}\nNo runtime was installed or executed.')
    else:
        destination = root / plan.runtime_id
        if os.path.lexists(destination):
            raise CliError(ENVIRONMENT, 'PT-OFFLINE: runtime already installed; existing files were not overwritten')
        created = []
        try:
            installed = offline_bundle.install_offline_bundle(plan, root, cancel=cancel, created_directories=created)
        except offline_bundle.OfflineBundleCancelled as exc:
            raise CliError(CANCELLED, str(exc)) from None
        except offline_bundle.OfflineBundleError as exc:
            raise CliError(RUNTIME, str(exc)) from None
        except OSError as exc:
            raise CliError(RUNTIME, f'PT-OFFLINE: runtime installation failed ({type(exc).__name__})') from None
        except KeyboardInterrupt:
            # Publication may already have succeeded. Cleanup below never deletes a populated runtime.
            if destination.is_dir():
                raise CliError(CANCELLED, 'PT-CANCEL: interrupted; the runtime destination exists and was retained; '
                               'inspect it before retrying') from None
            raise
        finally:
            _cleanup(created)
        result = {'contract': 'runtime-cli/1', 'runtime_id': plan.runtime_id, 'platform': plan.platform,
                  'root': str(installed.root), 'python_executable': str(installed.python_executable),
                  'ghidra_dir': str(installed.ghidra_dir), 'java_home': str(installed.java_home),
                  'manifest': str(installed.manifest_path), 'archive_sha256': installed.archive_sha256,
                  'files': plan.file_count, 'bytes': plan.total_bytes, 'authenticity': AUTHENTICITY}
        text = (f'Installed {plan.runtime_id} at {installed.root}.\nPython: {installed.python_executable}\n'
                f'Ghidra: {installed.ghidra_dir}\nJava: {installed.java_home}\n{AUTHENTICITY}\n'
                'Installation is not a compatibility check; diagnose the runtime before relying on it.')
    emit(args, f'runtime {args.action}', 'complete', result, [], text)
    return OK
