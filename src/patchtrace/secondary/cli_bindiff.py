"""`secondary run --engine bindiff` arguments and adapter construction (SPEC-29 §8). No Qt.

The BinDiff executable is an explicit absolute path (`--bindiff` or `PATCHTRACE_BINDIFF`); it is never looked
up on PATH and discovery never runs it. `.BinExport` inputs are accepted through C3's `accept_binexport`
when that module is present; otherwise BinDiff stays `unsupported` ("BinExport validation is unavailable").
"""
from __future__ import annotations

import argparse
import os
import threading
from collections.abc import Callable
from pathlib import Path

from .bindiff_inputs import AcceptedBinExportLike
from .contracts import SecondaryError
from .registry import BinDiffAdapter

ENV_VAR = 'PATCHTRACE_BINDIFF'


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--older-binexport', type=Path, default=None,
                        help='.BinExport of the older artifact (BinDiff primary)')
    parser.add_argument('--newer-binexport', type=Path, default=None,
                        help='.BinExport of the newer artifact (BinDiff secondary)')
    parser.add_argument('--accept-unbound-binexport', action='store_true',
                        help='I confirm these .BinExport files belong to this project\'s artifacts even though they '
                             'record no SHA-256 executable id (recorded in provenance)')


def c3_acceptor(private_dir: Path) -> Callable[..., AcceptedBinExportLike] | None:
    """Wrap C3 `accept_binexport` (binexport2-support.md §4); None only if the BinExport2 runtime is unavailable."""
    try:
        from . import binexport_run
    except ImportError:  # defensive: a build without the protobuf runtime keeps BinDiff `unsupported`
        return None
    accept = getattr(binexport_run, 'accept_binexport', None)
    if accept is None:
        return None

    def acceptor(path: Path, *, artifact_sha256: str, role: str, accept_unbound: bool, cancel: threading.Event,
                 other_sha256: str | None = None):
        inputs = private_dir / 'inputs'  # C3 creates its snapshot folder inside an existing private_dir
        try:
            inputs.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SecondaryError('PT-SECONDARY-RUN', f'Could not prepare a private working folder '
                                 f'({type(exc).__name__}).', kind='workdir-error') from None
        kwargs = dict(role=role, private_dir=inputs, cancel=cancel, accept_unbound=accept_unbound)
        try:
            return accept(path, artifact_sha256=artifact_sha256, **kwargs)
        except SecondaryError as exc:
            if exc.code == 'PT-SECONDARY-PAIR' and other_sha256 and \
                    getattr(exc, 'reason', None) == 'executable_id_mismatch':
                try:  # C3 reports any id mismatch as PAIR; a match with the other artifact means swapped files
                    accept(path, artifact_sha256=other_sha256, **kwargs)
                except SecondaryError:
                    raise exc from None
                raise SecondaryError('PT-SECONDARY-ORIENTATION', 'The .BinExport files are swapped: older and '
                                     'newer are reversed.', kind='binexport-orientation') from None
            raise
    return acceptor


def adapter_from_args(args: argparse.Namespace, raw_dir: Path, *,
                      environ: dict[str, str] | None = None,
                      acceptor_factory: Callable[[Path], Callable | None] | None = None) -> BinDiffAdapter | None:
    """None keeps the default (unconfigured) adapter, so runs without BinDiff options are unchanged."""
    env = os.environ if environ is None else environ
    executable = getattr(args, 'bindiff', None) or env.get(ENV_VAR) or None
    if executable is not None:  # an explicit path typed by the user; relative means "from here", never PATH
        executable = str(Path(executable).absolute())
    older, newer = getattr(args, 'older_binexport', None), getattr(args, 'newer_binexport', None)
    if executable is None and older is None and newer is None:
        return None
    return BinDiffAdapter(executable, older=older, newer=newer, raw_dir=raw_dir,
                          accept_unbound=bool(getattr(args, 'accept_unbound_binexport', False)),
                          acceptor=(acceptor_factory or c3_acceptor)(raw_dir))
