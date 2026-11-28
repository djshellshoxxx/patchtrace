"""Read the identity of one local cabinet source."""
from pathlib import Path

from ..cli_commands import CANCELLED, ENVIRONMENT, OK, RUNTIME, CliError, emit
from ..cli_commands._support import common


def add_parser(sub):
    parser = sub.add_parser('package-source', help='inspect a local CAB or CAB-form MSU source')
    parser.add_argument('file', type=Path, help='local Windows cabinet source')
    return common(parser)


def run(args, cancel):
    from .contracts import AcquisitionError
    from .package_source import inspect_source

    try:
        source = inspect_source(args.file, cancel=cancel)
    except AcquisitionError as exc:
        code = {'PT-ACQ-INPUT': ENVIRONMENT, 'PT-ACQ-UNSUPPORTED': ENVIRONMENT,
                'PT-ACQ-CANCEL': CANCELLED}.get(exc.code, RUNTIME)
        raise CliError(code, str(exc)) from None
    emit(args, 'package-source', 'complete', source.model_dump(mode='json'), [],
         f'{source.display_name} ({source.size} bytes)\nSHA-256: {source.sha256}\nSignature: unknown')
    return OK
