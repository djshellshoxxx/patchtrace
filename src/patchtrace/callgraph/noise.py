"""Hub registry (hub-registry/1): names whose calls are build plumbing, plus the fan-in rule (GL-11)."""
from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Literal

from .contracts import Model

HUB_FAN_IN = 64


class HubRule(Model):
    pattern: str  # case-sensitive glob over the name part of a label
    family: Literal['trace-helper', 'security-cookie', 'cfg-dispatch']
    source: str
    retrieved: str


class HubRegistry(Model):
    contract: Literal['hub-registry/1'] = 'hub-registry/1'
    version: str
    rules: tuple[HubRule, ...]


def _rule(pattern: str, family: str, source: str) -> HubRule:
    return HubRule(pattern=pattern, family=family, source=source, retrieved='2026-10-14')  # type: ignore[arg-type]


_F17 = 'unified F17 trace-helper table'
_CFG = 'WB2 plan 7.1 (spelling unverified; owner review)'
DEFAULT_HUBS = HubRegistry(version='1', rules=(
    _rule('EtwWrite*', 'trace-helper', _F17), _rule('WmiTraceMessage*', 'trace-helper', _F17),
    _rule('TraceMessage*', 'trace-helper', _F17), _rule('TraceLogging*', 'trace-helper', _F17),
    _rule('_tlgWrite*', 'trace-helper', _F17),
    _rule('__security_check_cookie', 'security-cookie', 'WB2 plan 7.1'),
    _rule('_guard_check_icall*', 'cfg-dispatch', _CFG), _rule('_guard_dispatch_icall*', 'cfg-dispatch', _CFG),
    _rule('__guard_check_icall*', 'cfg-dispatch', _CFG), _rule('__guard_dispatch_icall*', 'cfg-dispatch', _CFG),
))


def hub_flags(registry: HubRegistry, label: str, fan_in: int) -> tuple[str, ...]:
    """`hub` when the name is registered or has fan-in >= 64; `trace-helper` additionally for that family."""
    name = label.rpartition('::')[2]
    families = {r.family for r in registry.rules if fnmatchcase(name, r.pattern)}
    flags = ['hub'] if families or fan_in >= HUB_FAN_IN else []
    if 'trace-helper' in families:
        flags.append('trace-helper')
    return tuple(flags)
