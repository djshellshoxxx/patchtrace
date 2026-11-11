"""Build-environment timeline over a series of 3-8 builds (DIE plan s8, slice D7). Pure: no Qt, no I/O.

Cells show firm facts only (heuristics never fill one); a build without a stored row is `not-run`, a build whose row
has no fact of the family is `unknown`. Only adjacent builds are compared, and a hop whose two rows come from
different Detect It Easy setups shows "tool versions differ" instead of a comparison. The attention score of a hop is
never read or changed.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from .contracts import BuildEnvError, BuildFact, BuildFingerprint, FactKey, Side
from .copy import ROW_CHIP, TIMELINE_TOOLS_DIFFER
from .delta import FIRM, compute_delta

MIN_BUILDS, MAX_BUILDS = 3, 8  # the series limits (nway.contracts); kept local so this module needs no nway import
FAMILY_KEYS: dict[str, tuple[FactKey, ...]] = {
    'toolchain': ('compiler', 'compiler_version', 'linker', 'linker_rich', 'build_tool', 'rich_signature',
                  'linker_field'),
    'runtime': ('runtime_family', 'language', 'target_os'),
    'packing': ('packer', 'protector', 'obfuscator', 'installer'),
    'managed': ('managed',),
    'options': ('gs_cookie', 'cfg', 'aslr', 'repro', 'debug_entry_types')}
FAMILIES = tuple(FAMILY_KEYS)
CellState = Literal['value', 'unknown', 'not-run']
HopVerdict = Literal['same', 'differs', 'unknown', 'not-run', 'tools-differ']
_NOTES: dict[str, str] = {'differs': ROW_CHIP, 'tools-differ': TIMELINE_TOOLS_DIFFER}


class BuildLike(Protocol):
    ordinal: int
    label: str
    artifact_sha256: str


class BuildEnvReader(Protocol):
    """Port over the stored `build-env` rows (`BuildEnvStore.latest` fits); None when no row exists."""
    def fingerprint(self, sha256: str, side: Side) -> BuildFingerprint | None: ...


@dataclass(frozen=True, slots=True)
class TimelineBuild:
    ordinal: int
    label: str
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class Cell:
    state: CellState
    text: str = ''


@dataclass(frozen=True, slots=True)
class FamilyRow:
    family: str
    title: str
    cells: tuple[Cell, ...]  # one per build, in series order


@dataclass(frozen=True, slots=True)
class Hop:
    from_ordinal: int
    to_ordinal: int
    verdict: HopVerdict
    note: str  # '' unless the hop earns a note beside its attention score


@dataclass(frozen=True, slots=True)
class TimelineView:
    builds: tuple[TimelineBuild, ...]
    rows: tuple[FamilyRow, ...]
    hops: tuple[Hop, ...]

    @property
    def change_after(self) -> tuple[int, ...]:
        """Ordinals after which the toolchain differs (adjacent hops only)."""
        return tuple(h.from_ordinal for h in self.hops if h.verdict == 'differs')


def _cell(fp: BuildFingerprint | None, keys: tuple[FactKey, ...]) -> Cell:
    if fp is None:
        return Cell('not-run')
    facts: list[BuildFact] = [f for f in fp.facts if f.key in keys and f.certainty in FIRM]
    if not facts:
        return Cell('unknown')
    labels = dict.fromkeys(f.label() for f in sorted(facts, key=lambda f: keys.index(f.key)))
    return Cell('value', '; '.join(labels)[:200])


def _hop(older: BuildLike, newer: BuildLike, reader: BuildEnvReader) -> Hop:
    before = reader.fingerprint(older.artifact_sha256, 'older')
    after = reader.fingerprint(newer.artifact_sha256, 'newer')
    if before is None or after is None:
        verdict: HopVerdict = 'not-run'
    else:
        delta = compute_delta(before, after)
        verdict = 'tools-differ' if 'die-versions-differ' in delta.reasons else delta.toolchain
    return Hop(older.ordinal, newer.ordinal, verdict, _NOTES.get(verdict, ''))


def build_timeline(builds: Sequence[BuildLike], reader: BuildEnvReader) -> TimelineView:
    """Cells per fact family and one hop per adjacent pair; a pure function of the stored rows."""
    if len(builds) < MIN_BUILDS:
        raise BuildEnvError('PT-BUILD-INPUT', f'a timeline needs at least {MIN_BUILDS} builds')
    if len(builds) > MAX_BUILDS:
        raise BuildEnvError('PT-BUILD-LIMIT', f'a timeline shows at most {MAX_BUILDS} builds')
    rows_of = [reader.fingerprint(b.artifact_sha256, 'newer') or reader.fingerprint(b.artifact_sha256, 'older')
               for b in builds]
    return TimelineView(
        builds=tuple(TimelineBuild(b.ordinal, b.label, b.artifact_sha256) for b in builds),
        rows=tuple(FamilyRow(family, family.capitalize(), tuple(_cell(fp, keys) for fp in rows_of))
                   for family, keys in FAMILY_KEYS.items()),
        hops=tuple(_hop(a, b, reader) for a, b in zip(builds, builds[1:], strict=False)))
