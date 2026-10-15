"""Target and rename oracles (WBQ S8): what the run knows about the names a mark would otherwise mask. Pure.

Two kinds of name change when code moves or the decompiler renumbers, and a token mark mutes both: an address-derived
name (`FUN_140001000`) and a temporary (`uVar1`). Muting is only honest while nothing contradicts it, so the mark
engine asks an oracle first:

* `TargetOracle.target_state(old, new)`: do the two targets belong together? `mapped` (the run pairs them),
  `unmapped` (no evidence either way: the default, and what "target not verified" means) or `conflict` (one of them is
  paired with something else, so the call really goes elsewhere in the other build). A conflict is a `changed` mark.
* `RenameOracle.rename_state(old, new)`: is a temporary's new name a consistent rename over the whole function
  (`consistent`), a contradiction such as a swapped variable (`conflict`), or unknown? A conflict is a `changed` mark;
  `consistent` is still only "decompiler-relative", so the mark stays `rename-maybe` and only its wording changes.

Neither oracle is evidence. `NullOracle` and `NullRenameOracle` know nothing and are the defaults, so a mark never
claims more than the text shows.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, NamedTuple, Protocol

TargetKind = Literal['function', 'label', 'data']
TargetState = Literal['mapped', 'unmapped', 'conflict']
RenameState = Literal['consistent', 'conflict', 'unknown']


class Target(NamedTuple):
    kind: TargetKind
    address: int  # the integer the name or number carries: a Ghidra address, image base included


class TargetOracle(Protocol):
    def target_state(self, old: Target, new: Target) -> TargetState: ...


class RenameOracle(Protocol):
    def rename_state(self, old: str, new: str) -> RenameState: ...


class NullOracle:
    """No evidence about any target: every pair is `unmapped`."""

    def target_state(self, old: Target, new: Target) -> TargetState:
        return 'unmapped'


class NullRenameOracle:
    def rename_state(self, old: str, new: str) -> RenameState:
        return 'unknown'


class MatchPairOracle:
    """Function targets resolved through the matched pairs of the current run (older address, newer address).

    Pass only pairs the run treats as matched: a merely plausible pair would turn an honest `unmapped` into a
    `conflict`. Only `function` targets are resolved; a label or data target has no pairing evidence here (a data map
    is the unified engine's), so it stays `unmapped`. A function that appears in several pairs is paired with each of
    them, so one of those pairs is `mapped` and any other partner is a `conflict`."""

    def __init__(self, pairs: Iterable[tuple[int, int]]) -> None:
        self._pairs = frozenset(pairs)
        self._older = frozenset(old for old, _ in self._pairs)
        self._newer = frozenset(new for _, new in self._pairs)

    def target_state(self, old: Target, new: Target) -> TargetState:
        if old.kind != 'function' or new.kind != 'function':
            return 'unmapped'
        if (old.address, new.address) in self._pairs:
            return 'mapped'
        if old.address in self._older or new.address in self._newer:
            return 'conflict'
        return 'unmapped'
