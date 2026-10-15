"""Capability ids, states and the `requires` check of a panel (GUI plan 7 and 8.2). Pure: no Qt, no probing.

A panel names what it needs (`project`, `tool:capa`, ...). The host answers each id with a `CapabilityState` and the
panel opens in a blocked state, with the reason and a remedy, when any answer is not `available`. Probing that runs
a program is an explicit user action and never happens here.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from .text import LABEL_LIMIT, sanitize_text

CAP_CODE = 'PT-GUI-CAP'
KINDS = ('available', 'missing', 'unsupported', 'unchecked', 'policy')
SIMPLE = frozenset({'project', 'run', 'idle'})
KNOWN_TOOLS = frozenset({'capa', 'floss', 'diec', 'yara-x'})
KNOWN_ENGINES = frozenset({'bindiff', 'rzdiff'})
_FLAG = re.compile(r'[a-z][a-z0-9_-]{0,31}')
_DEFAULT_REASON = {'missing': '{id} is not available.', 'unsupported': '{id} is not supported here.',
                   'unchecked': '{id} has not been checked yet.', 'policy': '{id} is turned off.'}


def is_capability_id(text: object) -> bool:
    """`project`, `run`, `idle`, `tool:<known tool>`, `engine:<known engine>`, `feature:<flag>` or `os:windows`.
    The tool and engine names are closed on purpose: a typo would otherwise block a panel forever."""
    if not isinstance(text, str):
        return False
    if text in SIMPLE:
        return True
    head, _, name = text.partition(':')
    return ((head == 'tool' and name in KNOWN_TOOLS) or (head == 'engine' and name in KNOWN_ENGINES)
            or (head == 'feature' and _FLAG.fullmatch(name) is not None) or text == 'os:windows')


@dataclass(frozen=True, slots=True)
class CapabilityState:
    kind: str = 'available'
    reason: str = ''
    remedy_command: str | None = None  # shown to the user, never run by the framework

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f'unknown capability state {self.kind!r:.40}')
        object.__setattr__(self, 'reason', sanitize_text(self.reason, LABEL_LIMIT))
        if self.remedy_command is not None:
            object.__setattr__(self, 'remedy_command', sanitize_text(self.remedy_command, LABEL_LIMIT))


@dataclass(frozen=True, slots=True)
class Availability:
    """Whether something can be used now; `reason` and `remedy_command` explain a no (`code` is then PT-GUI-CAP)."""

    enabled: bool = True
    reason: str = ''
    remedy_command: str | None = None
    code: str | None = None


class CapabilityProvider(Protocol):
    def capability(self, capability_id: str) -> CapabilityState: ...


def check(requires: Iterable[str], provider: CapabilityProvider) -> Availability:
    """Available when every requirement is; otherwise the first blocker in `requires` order (later ones are not
    asked, so one missing tool is reported alone)."""
    for capability_id in requires:
        if not is_capability_id(capability_id):
            return Availability(False, sanitize_text(f'Unknown requirement {capability_id}.'), None, CAP_CODE)
        state = provider.capability(capability_id)
        if state.kind != 'available':
            reason = state.reason or _DEFAULT_REASON[state.kind].format(id=capability_id)
            return Availability(False, reason, state.remedy_command, CAP_CODE)
    return Availability(True)
