"""CLI flags for the symbol modes (SPEC-53 section 8), kept out of `cli.py` (its seam budget is 6 lines)."""
from __future__ import annotations

import argparse
from pathlib import Path


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--symbols', choices=('off', 'local', 'online'), default='off',
                        help='Ghidra symbols for --run: off (default), local (PDB folders, no network) or online')
    parser.add_argument('--symbol-dir', action='append', type=Path, default=[],
                        help='folder searched for PDBs by CodeView name in --symbols local (repeatable, at most 16)')
    parser.add_argument('--consent-online-symbols', action='store_true',
                        help='required with --symbols online: Ghidra may contact its configured symbol servers')


def given(args: argparse.Namespace) -> bool:
    """True when any symbol flag was used (they apply only with --run)."""
    return args.symbols != 'off' or bool(args.symbol_dir) or args.consent_online_symbols


def backend_kwargs(args: argparse.Namespace) -> dict:
    """BackendConfig keyword arguments for the flags; invalid combinations exit 2 with a PT-SYMBOL-* code."""
    from ..cli import ENVIRONMENT, CliError  # call-time import: cli.py imports this module
    if args.symbols == 'online' and not args.consent_online_symbols:
        raise CliError(ENVIRONMENT, 'PT-SYMBOL-NETWORK-REFUSED: --symbols online requires --consent-online-symbols')
    if args.symbol_dir and args.symbols != 'local':
        raise CliError(ENVIRONMENT, 'PT-SYMBOL-MODE: --symbol-dir applies only with --symbols local')
    return {'allow_symbol_downloads': args.symbols == 'online', 'symbol_mode': args.symbols,
            'symbol_pdb_dirs': tuple(str(d.resolve()) for d in args.symbol_dir)}
