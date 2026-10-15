"""Ghidriff call labels as `call:added` / `call:removed` observations, with the PE import delta as a second witness
(PIL-integration-plan.md s4 "import/API", s9 PIL-A3).

A callee name in a Ghidriff function record is a label: a decompiler's name for a call target, which can be wrong or
reused. Such an observation therefore always has verification `label-only`, whatever else is known about the API, and
supports at most a tentative lead. What PatchTrace parsed from the file bytes is separate evidence: when the newer file's
import table gained (or the older one's lost) exactly the API that a function's call labels name, that fact is added as
its own observation (`verified-bytes`, origin `D_pe_tables`), so the two count as two independent witnesses. The import
fact is module-wide; only the label ties it to a function. IR call keys (typed calls) are not read here.

Only 1:1 pairs are compared: one-sided and group rows have no counterpart call list, which is unknown, not unchanged.
Default decompiler labels (`FUN_<address>`) change in every build and are not call changes.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from ..contracts import ChannelStatus, Nav, Observation, clean_line
from ..limits import Budget
from ..ports import OriginRegistry
from .code import (
    DEFAULT_REGISTRY,
    MAX_PER_CANDIDATE,
    GhidriffRows,
    build_observation,
    channel_status,
    lookup,
    settle,
)
from .pe import ImportDelta

_AUTO_LABEL = re.compile(r'(?:thunk_)?(?:FUN|sub)_[0-9A-F]+', re.IGNORECASE)
_ANCHOR_SAFE = re.compile(r'[\x21-\x7e]{1,200}')  # what an anchor id can carry after `api:`
_SIDE = {'added': 'newer', 'removed': 'older'}
_VERB = {'added': 'gained', 'removed': 'dropped'}


def _plain(raw: str) -> str:
    """A call label as plain text; printable ASCII (nearly every API name) is already what `clean_line` returns."""
    return (raw if raw.isascii() and raw.isprintable() and len(raw) <= 256 else clean_line(raw, 256)).strip()


def _labels(callees: Iterable[str]) -> set[str]:
    """Distinct plain-text call labels of a function, without default decompiler names."""
    return {name for raw in callees if (name := _plain(raw)) and not _AUTO_LABEL.fullmatch(name)}


class GhidriffCalls:
    """`CallDeltaSource` over the callee lists of Ghidriff function records, optionally corroborated by an `ImportDelta`."""

    def __init__(self, rows: GhidriffRows, imports: ImportDelta | None = None, *,
                 registry: OriginRegistry = DEFAULT_REGISTRY, budget: Budget | None = None):
        self._rows, self._imports, self._registry = rows, imports, registry
        self._groups = self._cut = 0
        self._table: dict[str, tuple[Observation, ...]] = {}
        for row in rows.rows:
            if budget is not None:
                budget.tick()
            pair = row.pair()
            if pair is None:
                self._groups += bool(row.older and row.newer)
                continue
            (old_rva, old), (new_rva, new) = pair
            if old.callees == new.callees:
                continue  # the usual case: the same list cleans to the same labels
            old_names, new_names = _labels(old.callees), _labels(new.callees)
            found = [o for name in sorted(new_names - old_names) for o in self._observe('added', new_rva, name)]
            found += [o for name in sorted(old_names - new_names) for o in self._observe('removed', old_rva, name)]
            if found:
                self._table[row.candidate_key], cut = settle(found)
                self._cut += cut

    def _observe(self, change: str, rva: int, name: str) -> list[Observation]:
        side = _SIDE[change]
        anchor = f'api:{name}' if _ANCHOR_SAFE.fullmatch(name) else None
        out = [build_observation(
            self._registry, source='call-label', channel='calls', kind=f'call:{change}', role='shape',
            verification='label-only', evidence_class='E-CALL', ref_kind='call-label', ref_id=name,
            detail=f'call to {name} {change} (label only)', nav=Nav(side=side, rva=rva),
            anchors=[anchor] if anchor else [])]
        qualified = None if self._imports is None else self._imports.qualify(side, name)
        if qualified is not None and qualified in (self._imports.added if change == 'added' else self._imports.removed):
            out.append(build_observation(
                self._registry, source='pe-import', channel='calls', kind=f'call:{change}', role='shape',
                verification='verified-bytes', evidence_class='E-NAME', ref_kind='pe-import', ref_id=qualified,
                detail=f'module import table {_VERB[change]} {qualified}',
                anchors=[f'api:{qualified}'] if _ANCHOR_SAFE.fullmatch(qualified) else []))
        return out

    def status(self) -> ChannelStatus:
        rows = self._rows
        if not rows.rows:
            return channel_status('calls', 'unsupported' if rows.state == 'unsupported' else 'not-run',
                                  rows.reason or 'there are no Ghidriff rows')
        if not any(record.callees for row in rows.rows for _, record in (*row.older, *row.newer)):
            return channel_status('calls', 'unsupported', 'Ghidriff recorded no callee list for any function')
        notes = ['Ghidriff call labels only (no import keys from ProgramIR)']
        if self._imports is None:
            notes.append('no PE import delta')
        elif self._imports.state != 'available':
            notes.append(f'PE import delta {self._imports.state}: {self._imports.reason}')
        if self._groups:
            notes.append(f'{self._groups} group row(s) not assessed')
        if self._cut:
            notes.append(f'{self._cut} call change(s) beyond the cap of {MAX_PER_CANDIDATE} per candidate not listed')
        return channel_status('calls', 'partial', '; '.join(notes))

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        return lookup(self._table, candidate_keys)
