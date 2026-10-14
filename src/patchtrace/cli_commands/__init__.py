"""CLI-extension registry (GUI plan 8.12): a verb is one file `cli_commands/<verb>.py` that exports `COMMAND`.

Stdlib only, no Qt. The file name is the verb (`build_env.py` -> `build-env`). Discovery imports every file to
read its summary, so an adapter imports only this package and the stdlib at module level and loads its feature
inside `build` and `run`. A broken file never hides the others: it is listed as unavailable and exits 3.
"""
from __future__ import annotations

import pkgutil
import re
import threading
from argparse import ArgumentParser, Namespace, _SubParsersAction
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module

from ..cli import CANCELLED, COMMANDS, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError
from ..cli import _emit as emit

__all__ = ['CANCELLED', 'ENVIRONMENT', 'NO_RESULTS', 'OK', 'RUNTIME', 'CliCommand', 'CliError', 'discover',
           'emit', 'names', 'register_all']
UNAVAILABLE = 'unavailable (could not be loaded)'


@dataclass(frozen=True, slots=True)
class CliCommand:
    name: str     # the file name with `_` as `-`; ^[a-z][a-z0-9-]{1,23}$; not one of cli.COMMANDS
    summary: str  # 1..80 printable ASCII characters, listed by `patchtrace --help`
    build: Callable[[_SubParsersAction], ArgumentParser]  # adds and returns the full parser
    run: Callable[[Namespace, threading.Event], int]      # exit 0/2/3/4/5; raise CliError for 2 and 3

    def __post_init__(self):
        if not re.fullmatch(r'[a-z][a-z0-9-]{1,23}', self.name):
            raise ValueError(f'bad command name {self.name!r}')
        if not (0 < len(self.summary) <= 80 and self.summary.isascii() and self.summary.isprintable()):
            raise ValueError(f'{self.name}: the summary must be 1..80 printable ASCII characters')


def _verb(module: str) -> str:
    return module.replace('_', '-')


def _modules() -> list[str]:
    """Public module names of the package sorted by verb. A directory listing only: nothing is imported."""
    found = (info.name for info in pkgutil.iter_modules(__path__) if not info.name.startswith('_'))
    return sorted(found, key=_verb)


def _load(module: str) -> CliCommand:
    command = import_module(f'{__name__}.{module}').COMMAND
    if not isinstance(command, CliCommand) or command.name != _verb(module):
        raise ValueError(f'{module}: COMMAND must be a CliCommand named {_verb(module)!r}')
    return command


def discover() -> tuple[dict[str, CliCommand], dict[str, str]]:
    """(verbs by name, {module: exception class} for every file that cannot be a verb); both sorted."""
    modules = _modules()
    claims = Counter(map(_verb, modules))
    verbs, failed = {}, {}
    for module in modules:
        try:
            if _verb(module) in COMMANDS or claims[_verb(module)] > 1:
                raise ValueError(f'{module}: built-in or duplicate verb')
            verbs[_verb(module)] = _load(module)
        except Exception as exc:  # one broken file must never hide the others
            failed[module] = type(exc).__name__
    return verbs, failed


def names() -> tuple[str, ...]:
    """cli.COMMANDS, then every discovered verb, unavailable ones too: the list for smoke A1 and tests."""
    return COMMANDS + tuple(dict.fromkeys(name for name in map(_verb, _modules()) if name not in COMMANDS))


def register_all(sub: _SubParsersAction, invoked: str | None) -> None:
    """Full parser for the `invoked` verb only, bare listings for the rest (so `--help` loads no feature)."""
    verbs, failed = discover()
    broken = {_verb(module): error for module, error in failed.items()}
    for name in sorted({*verbs, *broken} - set(COMMANDS)):
        if name == invoked and name in verbs:
            command = verbs[name]
            command.build(sub).set_defaults(handler=command.run, command_label=name)
        elif name == invoked:
            raise CliError(RUNTIME, f'PT-CLI-COMMAND: {name} could not be loaded ({broken[name]})')
        else:
            summary = verbs[name].summary if name in verbs else UNAVAILABLE
            sub.add_parser(name, help=summary.replace('%', '%%'))  # argparse %-formats help text
