"""Rule candidates for ONE accepted changed-function pair (YRX-integration-plan section 7, "Candidate generation").

`propose` turns the evidence that crosses the ports (strings, imports, capabilities; bytes windows in R4) into at most
`candidates_per_direction` candidates for each build, and states for every one of them which checks it passed. Nothing is
stored and nothing is published: the result is a proposal the analyst reads and accepts, rejects or defers.

What a candidate is. Per direction, the features that exist only in that build (delta, not inventory). Defaults: the
capabilities of the change become metadata; an import is a gate when a capability of the change points at it (an import
that merely differs between the files stays an unticked offer: it may belong to another function); strings that are only
file-level (added or removed somewhere in the file, not tied to the changed code by a decoded reference) anchor a rule
only when there is no byte window to anchor it, at most four, the longest first. A rule needs at least one condition (a
string, an import or a byte window); metadata alone is no rule. Everything else is offered unticked, and ticking one is a
new candidate (a revision), never free text.

Bytes (R4). With a `BytesSource` each direction first asks for byte windows of the changed function: every window that
passed its own checks anchors one candidate (at most `candidates_per_direction`), carries its call pins, and makes the
file-level strings the changed code reads (`xref`) default-ticked; file-level strings that nothing in the code reads stay
offers. A direction whose bytes are unavailable (no verified function extent, an invalid instruction, a packed build) is
reported as a `bytes-unavailable` rejection and still gets the candidate the other channels can make.

Where the pieces live. The rule text is made by a `RuleRenderer` (`synth_renderer`, R1's closed-grammar `synth`, is the
default; tests pass an oracle to compare against); this module never builds rule text by itself, so no string of evidence can reach a rule except through that grammar). The
compile and separation checks need the engine, so they come from a `PairChecker`: `RunnerChecker` runs them in the hidden
worker; tests inject one that calls the engine in-process. A check the pair could not be scanned for is `unknown`, and an
unknown or failed blocking gate keeps the candidate out of the proposal (the reason is reported, not hidden).
"""
from __future__ import annotations

import os
import re
import threading
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from ..enrichment.identity import domain_id
from ..intelligence.tools.common import secret_kind
from . import gates as g
from . import runner, synth
from .contracts import (
    BytesFeature,
    CellResult,
    Direction,
    EngineStamp,
    Feature,
    Gate,
    ImportFeature,
    LintResult,
    PairSource,
    RuleCandidate,
    Side,
    StringFeature,
    WorkerRule,
    WorkerTarget,
    rule_name_for,
    rule_text_sha256,
)
from .errors import RuleError
from .features import (
    Built,
    canonical_order,
    capability_features,
    feature_identity,
    import_features,
    import_key,
    referenced_imports,
    string_features,
    unescape_text,
    with_included,
)
from .limits import DEFAULT_LIMITS, RuleLimits
from .ports import CapabilitySource, Coverage, ImportSource, StringSource
from .window import WindowSet

DIRECTIONS: tuple[Direction, ...] = ('older', 'newer')
DEFAULT_TEXT_PATTERNS = 4   # grammar yrx-gen/1 writes at most four text patterns
FILE_LEVEL_ANCHOR = 'features'
_OPPOSITE: dict[str, Side] = {'older': 'newer', 'newer': 'older'}
_UNAVAILABLE = Coverage('unavailable', 'unavailable')
_WARNING_CODE = re.compile(r'(?:E[0-9]{3}|[a-z][a-z0-9_]{1,63})')
BYTES_ERRORS = frozenset({'PT-RULE-MASK', 'PT-RULE-DECODE', 'PT-RULE-LIMIT', 'PT-RULE-UNAVAILABLE'})
BLOCKED_BUILDS = frozenset({'packed', 'protected'})   # DiE: the bytes of a packed build say nothing about the program


# --- seams -----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleSpec:
    """What the renderer needs to write one rule: the pair, the direction, the lineage (the rule name derives from it) and
    the INCLUDED features in canonical order. The rest of the candidate (gates, hashes) does not belong in rule text."""
    source: PairSource
    direction: Direction
    lineage_id: str
    features: tuple[Feature, ...]
    version: int = 1

    @property
    def rule_name(self) -> str:
        return rule_name_for(self.lineage_id, self.direction)


class RuleRenderer(Protocol):
    def __call__(self, spec: RuleSpec) -> str:
        """Rule text in grammar `yrx-gen/1`: LF-only printable ASCII that defines `spec.rule_name`."""
        ...


def synth_renderer(spec: RuleSpec) -> str:
    """The production `RuleRenderer`: grammar `yrx-gen/1` by `synth.render_rule` (no label or advisory ids yet: those come
    with the analyst's accept decision)."""
    return synth.render_rule(spec.source, lineage_id=spec.lineage_id, direction=spec.direction, version=spec.version,
                             features=spec.features)


@dataclass(frozen=True)
class PairCheck:
    """One rule text, compiled with the linters and scanned over the two builds of the pair."""
    engine: EngineStamp
    lint: LintResult
    own: CellResult      # against the build the rule describes
    other: CellResult    # against the other build


class PairChecker(Protocol):
    def __call__(self, name: str, text: str, pair: PairSource, direction: Direction) -> PairCheck: ...


def _sha(pair: PairSource, side: Side) -> str:
    return pair.older_sha256 if side == 'older' else pair.newer_sha256


class RunnerChecker:
    """`PairChecker` through the hidden worker: one child lints the rule and scans both builds, so the engine never loads
    in this process. `builds` maps a side to the path of that build's verified file."""

    def __init__(self, builds: Mapping[Side, str | os.PathLike], *, timeout_s: int | None = None,
                 cancel: threading.Event | None = None, limits: RuleLimits = DEFAULT_LIMITS,
                 scratch_dir: Path | None = None):
        self._builds = dict(builds)
        self._timeout_s, self._cancel, self._limits, self._scratch = timeout_s, cancel, limits, scratch_dir

    def __call__(self, name: str, text: str, pair: PairSource, direction: Direction) -> PairCheck:
        try:
            targets = tuple(
                WorkerTarget(target_id=role, path=str(Path(self._builds[side]).resolve()), sha256=_sha(pair, side),
                             size=Path(self._builds[side]).stat().st_size)
                for role, side in (('own', direction), ('other', _OPPOSITE[direction])))
        except (KeyError, OSError, ValidationError):
            raise RuleError('PT-RULE-STALE', 'A build of the pair cannot be read', reason='build-missing') from None
        outcome = runner.scan((WorkerRule(name=name, text=text),), targets, timeout_s=self._timeout_s,
                              cancel=self._cancel, limits=self._limits, scratch_dir=self._scratch)
        return PairCheck(outcome.engine, outcome.lint[0], outcome.cells[0], outcome.cells[1])


class BytesSource(Protocol):
    def windows(self, pair: PairSource, direction: Direction) -> WindowSet:
        """Byte windows of the pair's function on `direction`'s side (`window.BytesWindows`). Raises `RuleError` with a
        code of `BYTES_ERRORS` when the bytes are unavailable, and `PT-RULE-STALE` when a build no longer fits the pair."""
        ...


@dataclass(frozen=True)
class Sources:
    """The evidence ports. A port that is absent is an unavailable channel (reported), never an empty one."""
    strings: StringSource | None = None
    capabilities: CapabilitySource | None = None
    imports: ImportSource | None = None
    bytes: BytesSource | None = None


# --- results ---------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ChannelCoverage:
    channel: str            # 'strings' | 'capabilities' | 'imports'
    coverage: Coverage


@dataclass(frozen=True)
class Rejection:
    """A rule that was not proposed, and why: `no-feature` (nothing separates this build), `gate` (the first blocking gate
    that did not pass) or `bytes-unavailable` (no verified function extent or decoder: `detail` holds the error code)."""
    direction: Direction
    reason: str
    gate: Gate | None = None
    detail: str = ''

    def sentence(self) -> str:
        if self.gate is not None:
            return g.sentence(self.gate)
        if self.reason == 'no-feature':
            return f'No feature separates the {self.direction} build'
        return f'Bytes are unavailable ({self.detail})'


@dataclass(frozen=True)
class Proposal:
    candidates: tuple[RuleCandidate, ...]
    rejected: tuple[Rejection, ...]
    coverage: tuple[ChannelCoverage, ...]
    notes: tuple[str, ...]      # what was held back, as `reason:count` (secret strings, oversize strings, ...)

    def first_failure(self) -> str | None:
        """The R5 state text's "{first failing check}" when no candidate passed, else None."""
        if self.candidates:
            return None
        return self.rejected[0].sentence() if self.rejected else None


# --- helpers ---------------------------------------------------------------------------------------------------------

def lineage_id(pair: PairSource, direction: Direction, anchor: str) -> str:
    """The family of versions of one rule: this pair of builds, this match, this build, this anchor. Ticking a feature
    changes the candidate, never the lineage."""
    return domain_id('rule-lineage', 1, {'project': pair.project_id, 'older': pair.older_sha256,
                                         'newer': pair.newer_sha256, 'match': pair.match_id,
                                         'direction': direction, 'anchor': anchor})


def _gather(pair: PairSource, sources: Sources, limits: RuleLimits):
    """Features of every channel, for both builds, and what each channel could and could not say."""
    string_channel = sources.strings.strings(pair) if sources.strings is not None else None
    cap_channel = sources.capabilities.capabilities(pair) if sources.capabilities is not None else None
    tables = {side: sources.imports.imports(pair, side) if sources.imports is not None else None
              for side in ('older', 'newer')}
    strings = string_features(string_channel.items if string_channel else (), limits=limits, detect_secret=secret_kind)
    caps = capability_features(cap_channel.items if cap_channel else ())
    imports = import_features(tables['older'], tables['newer'], referenced_imports(caps.features))
    coverage = (
        ChannelCoverage('strings', string_channel.coverage if string_channel else _UNAVAILABLE),
        ChannelCoverage('capabilities', cap_channel.coverage if cap_channel else _UNAVAILABLE),
        ChannelCoverage('imports', Coverage(*('complete' if tables[side] is not None else 'unavailable'
                                              for side in ('older', 'newer')))))
    return strings, imports, caps, coverage


def _compose(direction: Direction, strings: Built, imports: Built, caps: Built, anchor: Sequence[Feature],
             limits: RuleLimits) -> tuple[tuple[Feature, ...], tuple[str, ...]] | None:
    """The features of one candidate with their default ticks, or `None` when nothing could make a condition."""
    own_only = f'{direction}-only'
    own_caps = [f for f in caps.features if f.separation == own_only]
    gated = referenced_imports(own_caps)
    own_imports = [f for f in imports.features
                   if f.separation == own_only or (f.separation == 'both-sides' and import_key(f) in gated)]
    own_strings = [f for f in strings.features if f.side == direction and f.separation in (own_only, 'unknown')]
    anchors = [f for f in own_strings if f.separation == own_only
               and (f.linked_by == 'xref' or (not anchor and f.length >= g.MIN_LITERAL_RUN))]
    text_ticks = sorted(anchors, key=lambda f: (-f.length, f.offset))[:DEFAULT_TEXT_PATTERNS]

    def ticked(feature: Feature) -> bool:
        if isinstance(feature, StringFeature):
            return feature in text_ticks
        if isinstance(feature, ImportFeature):
            return feature.separation == own_only and import_key(feature) in gated
        return True   # the byte window and its pins; capabilities (metadata)

    features = [with_included(f, ticked(f)) for f in (*anchor, *own_strings, *own_imports, *own_caps)]
    if not any(f.included and isinstance(f, BytesFeature | StringFeature | ImportFeature) for f in features):
        return None
    notes: tuple[str, ...] = ()
    if len(features) > limits.features_per_candidate:
        features.sort(key=lambda f: not f.included)   # stable: the ticked features survive the cut
        notes = (f'features-cut:{len(features) - limits.features_per_candidate}',)
        features = features[:limits.features_per_candidate]
    return canonical_order(features), notes


def _warning_codes(lint: LintResult) -> tuple[str, ...]:
    return tuple(sorted({w.code if _WARNING_CODE.fullmatch(w.code) else 'unknown' for w in lint.warnings}))


def _worst(gates: Iterable[Gate]) -> Gate:
    """The first gate that did not pass, else the first."""
    gates = list(gates)
    return next((gate for gate in gates if not g.passed(gate)), gates[0])


def _gates(pair: PairSource, features: Sequence[Feature], check: PairCheck, flags: Collection[str] | None
           ) -> tuple[Gate, ...]:
    """The candidate's checks in canonical order. A check that does not apply (no pattern, no byte window) is absent
    rather than shown as passed."""
    used = [f for f in features if f.included]
    windows = [f for f in used if isinstance(f, BytesFeature)]
    texts = [f for f in used if isinstance(f, StringFeature)]
    out = [g.eligibility(pair.materiality, pair.analyst_confirmed_material)]
    if windows or texts:
        literal = sum(f.literal for f in windows) + sum(f.length for f in texts)
        run = max([f.longest_run for f in windows] + [f.length for f in texts])
        out.append(g.long_enough(literal, run))
    if windows:
        out.append(g.not_mostly_wildcards(sum(f.length for f in windows), sum(f.literal for f in windows)))
        out.append(_worst(g.one_place(f.source_hits) for f in windows))
    out.append(g.separates(check.own, check.other, windows[0].window_rva if windows else None))
    out.append(g.compiles(check.lint))
    out.append(g.no_secret((unescape_text(f.text) for f in texts), secret_kind))
    out.append(g.one_toolchain(flags))
    return tuple(out)


def _candidate(pair: PairSource, direction: Direction, lineage: str, features: tuple[Feature, ...], text: str,
               check: PairCheck, engine: EngineStamp, gates: tuple[Gate, ...]) -> RuleCandidate:
    digest = rule_text_sha256(text)
    identity = {'lineage': lineage, 'rule_sha256': digest, 'source': pair.model_dump(mode='json'),
                'features': [[feature_identity(f), f.included] for f in features],
                'engine': engine.model_dump(mode='json')}
    try:
        return RuleCandidate(
            candidate_id=domain_id('rule-candidate', 1, identity), lineage_id=lineage, direction=direction,
            source=pair, features=features, rule_name=rule_name_for(lineage, direction), rule_text=text,
            rule_sha256=digest, gates=gates, compile_warnings=_warning_codes(check.lint), engine=engine,
            unvetted=pair.materiality != 'material')
    except ValidationError:   # the renderer broke its own grammar contract: a bug, not a property of the pair
        raise RuleError('PT-RULE-COMPILE', 'The generated rule does not satisfy the candidate contract',
                        reason='candidate-invalid') from None


def _windows(source: BytesSource | None, pair: PairSource, direction: Direction, flags: Collection[str] | None
             ) -> tuple[WindowSet | None, Rejection | None]:
    """Windows of one direction, or why there are none. Only the errors that mean "no bytes for this function" are turned
    into a rejection; a stale build or a bug still stops the proposal."""
    if source is None:
        return None, None
    if flags and BLOCKED_BUILDS & set(flags):
        return None, Rejection(direction, 'bytes-unavailable', detail='the build is packed or protected')
    try:
        return source.windows(pair, direction), None
    except RuleError as error:
        if error.code not in BYTES_ERRORS:
            raise
        return None, Rejection(direction, 'bytes-unavailable', detail=f'{error.code} {error.reason or ""}'.strip())


def _link_strings(strings: Built, direction: Direction, found: WindowSet | None) -> Built:
    """A string at an offset the changed function reads through a RIP-relative operand is `xref`-linked to the code."""
    if found is None or not found.referenced_offsets:
        return strings
    linked = tuple(f.model_copy(update={'linked_by': 'xref'}) if f.side == direction
                   and f.offset in found.referenced_offsets else f for f in strings.features)
    return Built(linked, strings.notes)


def _stamp(engine: EngineStamp, found: WindowSet | None) -> EngineStamp:
    """The engine that scanned, plus the decoder that made the masks of a candidate that has a byte window."""
    if found is None:
        return engine
    return EngineStamp(version=engine.version, version_source=engine.version_source, decoder=found.decoder[0],
                       decoder_version=found.decoder[1])


def _applicable(pair: PairSource, directions: Iterable[Direction]) -> tuple[Direction, ...]:
    asked = set(directions)
    found = tuple(d for d in DIRECTIONS if d in asked and (pair.older if d == 'older' else pair.newer) is not None)
    if not found:
        raise RuleError('PT-RULE-INPUT', 'The pair has no function in the requested build', reason='direction')
    return found


# --- the proposal ----------------------------------------------------------------------------------------------------

def propose(pair: PairSource, sources: Sources, *, check: PairChecker, render: RuleRenderer = synth_renderer,
            directions: Iterable[Direction] = DIRECTIONS, flags: Collection[str] | None = None,
            limits: RuleLimits = DEFAULT_LIMITS) -> Proposal:
    """Candidates for one accepted pair. `flags` are the DiE quality-flag codes of the pair (`None`: DiE did not run).

    Raises `PT-RULE-INPUT` for a change that is not reviewed as material and not confirmed by the analyst
    (`not-material`) and for a direction the pair has no function for (`direction`). Every other outcome is a proposal,
    possibly with no candidate, whose `rejected` list says why."""
    if g.eligibility(pair.materiality, pair.analyst_confirmed_material).state == 'fail':
        raise RuleError('PT-RULE-INPUT', 'The change is not reviewed as material; confirm it to propose rules',
                        reason='not-material')
    wanted = _applicable(pair, directions)
    strings, imports, caps, coverage = _gather(pair, sources, limits)
    notes = [*strings.notes, *imports.notes, *caps.notes]
    unknown = sum(1 for f in imports.features if f.separation == 'unknown')
    if unknown:   # an import of a build whose other table is unavailable: no side to tick it for
        notes.append(f'imports-unknown:{unknown}')
    candidates: list[RuleCandidate] = []
    rejected: list[Rejection] = []
    reached: set[Direction] = set()
    for direction in wanted:
        found, refusal = _windows(sources.bytes, pair, direction, flags)
        if refusal is not None:
            rejected.append(refusal)
        elif found is not None:
            reached.add(direction)
            if not found.windows and found.failures:   # the best attempt failed a check: say which
                rejected.append(Rejection(direction, 'gate', found.failures[0]))
        linked = _link_strings(strings, direction, found)
        anchors = [(window,) for window in found.windows[:limits.candidates_per_direction]] if found else []
        for anchor in anchors or [()]:
            composed = _compose(direction, linked, imports, caps, anchor, limits)
            if composed is None:
                rejected.append(Rejection(direction, 'no-feature'))
                continue
            features, cut = composed
            notes.extend(cut)
            lineage = lineage_id(pair, direction, f'bytes:{anchor[0].window_rva:x}' if anchor else FILE_LEVEL_ANCHOR)
            text = render(RuleSpec(pair, direction, lineage, tuple(f for f in features if f.included)))
            verdict = check(rule_name_for(lineage, direction), text, pair, direction)
            gates = _gates(pair, features, verdict, flags)
            blocked = g.first_blocking(gates)
            if blocked is not None:
                rejected.append(Rejection(direction, 'gate', blocked))
                continue
            candidates.append(_candidate(pair, direction, lineage, features, text, verdict,
                                         _stamp(verdict.engine, found if anchor else None), gates))
    seen = Coverage(*('complete' if side in reached else 'unavailable' for side in DIRECTIONS))
    return Proposal(tuple(candidates), tuple(rejected), (*coverage, ChannelCoverage('bytes', seen)),
                    tuple(sorted(notes)))
