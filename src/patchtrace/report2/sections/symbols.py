"""`symbols` from the persisted settings of the latest analysis run (GHR). Servers appear only for `online`."""
from __future__ import annotations

import re
from typing import Protocol

from pydantic import ValidationError

from .. import text
from ..contracts import StagedPdb, Symbols
from . import Built, bounded, refuse

_SERVER = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,127}')
_VERSION = re.compile(r'[0-9][A-Za-z0-9_.+ -]{0,99}')


class RunSettingsPort(Protocol):
    def latest_settings(self) -> dict | None:
        """Settings of the newest completed run, or None when no run exists."""


def build_symbols(port: RunSettingsPort | None) -> Built | None:
    settings = None if port is None else port.latest_settings()
    if not isinstance(settings, dict) or settings.get('symbol_mode') not in ('off', 'local', 'online'):
        return None  # a run without a recorded mode leaves the mode unknown, never "off"
    mode = settings['symbol_mode']
    servers = settings.get('symbol_servers') or []
    launcher = settings.get('launcher_version')
    try:
        section = Symbols(
            mode=mode,
            servers=[bounded(s, text.CAP_NAME)[0] for s in servers if mode == 'online' and isinstance(s, str)
                     and _SERVER.fullmatch(s)],
            staged=[StagedPdb(pdb_name=bounded(row['name'].replace('\\', '/').split('/')[-1], text.CAP_NAME)[0],
                              guid_age=row['guid_age'], sha256=row['sha256'])
                    for row in settings.get('staged_symbols') or [] if isinstance(row, dict)],
            launcher_version=launcher if isinstance(launcher, str) and _VERSION.fullmatch(launcher) else None)
    except (ValidationError, KeyError, AttributeError, TypeError) as exc:
        raise refuse('symbols', exc) from None
    return Built(section)
