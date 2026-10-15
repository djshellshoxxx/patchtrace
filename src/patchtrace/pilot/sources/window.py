"""The confounded-window count (PIL-integration-plan.md s7 tier step 4 and open question 7).

A shape that fits an advisory's expected change may belong to ANOTHER CVE fixed in the same update. With two or more
CVEs fixed on the newer build, shape-only leads are held at tentative unless a function-name locality isolates one of
them. This module counts those CVEs: the CSAF-derived ones (a CVE whose gate says this pair fixes it, `applies` or
`asserted`) plus, when the KB track provides it, the CVEs of the updates between the two builds.

A CVE that is unverified, conflicting or not applicable is not counted: whether it was fixed here is unknown, not a
negative vote. Only a COMPLETE KB window can say `no`: the imported documents are a partial list, so fewer than the
threshold CVEs found in them leave the window `unknown` (no cap, but the caption says so).

The KB track is not built yet; `KbWindowSource` is the port it will fill.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, get_args, runtime_checkable

from ..contracts import MAX_WINDOW_CVES, Confounding, ContextGate
from ..limits import PilotError

FIXED_HERE = frozenset({'applies', 'asserted'})
_GATES = frozenset(get_args(ContextGate))
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}')  # the shape of contracts.CveId (ASCII digits only)
_MAX_CVE = 24
_SHA256 = re.compile(r'[0-9a-f]{64}')


def _is_cve(value: object) -> bool:
    return isinstance(value, str) and len(value) <= _MAX_CVE and _CVE.fullmatch(value) is not None


def _refused(message: str, reason: str) -> PilotError:
    return PilotError('PT-PILOT-INPUT', message, reason=reason)


@dataclass(frozen=True)
class KbWindow:
    """The KB track's view of the updates between the two builds.

    `cves` are the CVEs it links to those updates (sorted, unique); `complete` says that every intervening update is
    known, so the list is the whole window; `link_digest` is the `PilotInputs.kb_link_digest` of the links used."""
    cves: tuple[str, ...]
    complete: bool
    link_digest: str

    def __post_init__(self) -> None:
        if type(self.cves) is not tuple or not all(_is_cve(c) for c in self.cves) \
                or list(self.cves) != sorted(set(self.cves)):
            raise _refused('A KB window lists sorted, unique CVE ids', 'kb-window')
        if type(self.complete) is not bool:
            raise _refused('A KB window says whether it is complete', 'kb-window')
        if not isinstance(self.link_digest, str) or not _SHA256.fullmatch(self.link_digest):
            raise _refused('A KB window carries the SHA-256 digest of its links', 'kb-window')


@runtime_checkable
class KbWindowSource(Protocol):
    def window(self) -> KbWindow | None:
        """The window between the two builds, or None when the KB holds no link for them."""
        ...


def confounding(gates: Mapping[str, str], *, min_cves: int = 2, kb: KbWindowSource | None = None) -> Confounding:
    """Whether `min_cves` or more CVEs are fixed on the newer build. `gates` maps every loaded CVE to its context
    gate (`PilotConfig.confounded_min_cves` is the threshold)."""
    if type(min_cves) is not int or min_cves < 2:
        raise _refused('The window threshold is an int of at least 2', 'window-threshold')
    fixed = set()
    for cve, gate in gates.items():
        if not _is_cve(cve):
            raise _refused('A window gate is keyed by a CVE id', 'window-cve')
        if not isinstance(gate, str) or gate not in _GATES:
            raise _refused('A window gate is a CVE context gate', 'window-gate')
        if gate in FIXED_HERE:
            fixed.add(cve)
    linked = kb.window() if kb is not None else None
    if linked is not None:
        fixed.update(linked.cves)
    cves = tuple(sorted(fixed))
    if len(cves) > MAX_WINDOW_CVES:
        raise PilotError('PT-PILOT-LIMIT', f'A window lists at most {MAX_WINDOW_CVES} CVEs', reason='window-cves')
    if len(cves) >= min_cves:
        return Confounding(state='yes', cves=cves)
    if linked is not None and linked.complete:
        return Confounding(state='no', cves=cves)
    return Confounding(state='unknown')
