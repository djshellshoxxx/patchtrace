"""B2 WIL controlled-feature evidence (SPEC-07 §7). Pure: no Qt, network or I/O.

What is observed: a `Feature_<uint32>` identifier (or a public WIL wrapper naming
one) at an exact source line. What is inferred: whether that flag *gates* nearby
code. Without CFG evidence the strongest claim made here is `lexical-enclosure` —
the site sits in an `if (...)` condition whose braces or indentation enclose
lines. That is a text heuristic: braces inside strings/comments, macros, gotos and
decompiler restructuring can all mislead it, so it never yields `cfg-dominance`
and never exceeds `moderate` confidence.

All patterns are anchored, have bounded quantifiers and no nested repetition, so
matching is linear in the input length.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

from . import identity
from .contracts import UINT32_MAX, ChangeSignal, FeatureSite, FeatureTransition, SourceLocation
from .signals import _clean as clean_lines
from .signals import edit_group_key, normalized_text, semantic_hunk_ordinals
from .views import FunctionView, MatchView

DETECTOR_VERSION = 1
MAX_CHARS = 2_000_000
MAX_SITES = 4_096
_MAX_CONDITION = 4_096  # chars scanned for a condition's closing paren
_ADJACENT_LINES = 3
QUALIFYING = frozenset({'introduced', 'removed', 'condition-changed', 'guarded-behavior-changed'})

# Normative identifier regex (§7). 11+ digit runs cannot match at all, so they are
# rejected like 10-digit values above UINT32_MAX.
_IDENT = re.compile(r'(?<![A-Za-z0-9_])Feature_(\d{1,10})(?![A-Za-z0-9_])')
# Public WIL wrapper spellings. These embed the identifier after/before `_`, which
# the boundary regex deliberately refuses, so they are recognized explicitly.
_DEVICE_USAGE = re.compile(r'(?<![A-Za-z0-9_])(Feature_(\d{1,10})__private_IsEnabledDeviceUsage)(?![A-Za-z0-9_])')
_IMPL = re.compile(r'wil::details::FeatureImpl<([^<>\n]{1,200})>::__private_IsEnabled(?![A-Za-z0-9_])')
_IMPL_ARG = re.compile(r'(?:^|_)Feature_(\d{1,10})$')
_IS_ENABLED = re.compile(r'\s*::\s*IsEnabled(?![A-Za-z0-9_])')
_IF = re.compile(r'(?<![A-Za-z0-9_])if\s*\(')
_WS = re.compile(r'\s+')


@dataclass(frozen=True)
class _Gate:
    cond_start: int  # offsets into joined text; cond is (start, end) exclusive of parens
    cond_end: int
    cond_lines: tuple[int, int]  # 1-based inclusive
    body: tuple[int, int] | None  # 1-based inclusive enclosed lines


@dataclass(frozen=True)
class _Site:
    site: FeatureSite
    offset: int
    gate: _Gate | None


@dataclass(frozen=True)
class _Scan:
    sites: tuple[_Site, ...]
    text: str
    truncated: bool
    site_limit: bool


def _matches(text: str) -> dict[int, tuple[str, int | None, str]]:
    """offset -> (identifier, feature_id, wrapper). Overflowing values yield nothing."""
    found: dict[int, tuple[str, int | None, str]] = {}
    for m in _IDENT.finditer(text):
        value = int(m.group(1))
        if value > UINT32_MAX:
            continue
        tail = _IS_ENABLED.match(text, m.end())
        found[m.start()] = (m.group(0), value, m.group(0) + '::IsEnabled' if tail else '')
    for m in _DEVICE_USAGE.finditer(text):
        value = int(m.group(2))
        if value <= UINT32_MAX:
            found[m.start()] = ('Feature_' + m.group(2), value, m.group(1))
    for m in _IMPL.finditer(text):
        arg = m.group(1).strip()
        number = _IMPL_ARG.search(arg)
        if number is None:
            # Recognized WIL wrapper whose flag number is not printed (e.g. a named
            # traits type): keep the site but do not invent an ID.
            found[m.start()] = (arg[:64] or 'FeatureImpl', None, m.group(0))
        elif int(number.group(1)) <= UINT32_MAX:
            found[m.start()] = ('Feature_' + number.group(1), int(number.group(1)), m.group(0))
    return found


def _pairs(text: str, open_ch: str, close_ch: str) -> dict[int, int]:
    """Single-pass bracket matching; unbalanced brackets are simply unmatched."""
    stack: list[int] = []
    out: dict[int, int] = {}
    for i, ch in enumerate(text):
        if ch == open_ch:
            stack.append(i)
        elif ch == close_ch and stack:
            out[stack.pop()] = i
    return out


def _gates(text: str, starts: list[int], lines: tuple[str, ...]) -> list[_Gate]:
    def line_of(offset: int) -> int:
        return bisect_right(starts, offset)

    def indent(line: str) -> int:
        return len(line) - len(line.lstrip())

    parens, braces = _pairs(text, '(', ')'), _pairs(text, '{', '}')
    gates = []
    for m in _IF.finditer(text):
        open_paren = m.end() - 1
        close = parens.get(open_paren)
        if close is None or close - open_paren > _MAX_CONDITION:
            continue
        cond_lines = (line_of(open_paren), line_of(close))
        rest = len(text) - len(text[close + 1:].lstrip())
        body = None
        if rest < len(text) and text[rest] == '{' and rest in braces:
            first, last = line_of(rest), line_of(braces[rest])
            if last - first >= 2:
                body = (first + 1, last - 1)
            elif text[rest + 1:braces[rest]].strip():
                body = (first, last)
        elif rest < len(text) and line_of(rest) > cond_lines[1]:
            # Brace-less statement: only trusted when indentation shows nesting.
            nxt = line_of(rest)
            if indent(lines[nxt - 1]) > indent(lines[cond_lines[0] - 1]):
                body = (nxt, nxt)
        gates.append(_Gate(open_paren + 1, close, cond_lines, body))
    return gates


def _scan(function: FunctionView) -> _Scan:
    lines = function.code or ()
    total, kept = 0, []
    truncated = function.truncated
    for line in lines:
        if total + len(line) + 1 > MAX_CHARS:
            truncated = True
            break
        total += len(line) + 1
        kept.append(line)
    # Blank comments and string/char literal contents (line numbers kept) so a flag name
    # quoted in a log message or comment is never a site; locations still hash raw lines.
    lines = tuple(clean_lines(tuple(kept)))
    text = '\n'.join(lines)
    starts, pos = [], 0
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    found = _matches(text)
    gates = _gates(text, starts, lines) if found else []
    out: list[_Site] = []
    limit = False
    for offset in sorted(found):
        if len(out) >= MAX_SITES:
            limit = True
            break
        ident, value, wrapper = found[offset]
        line_no = bisect_right(starts, offset)
        # Innermost enclosing condition: the latest-opening gate containing the offset.
        gate = None
        for g in gates:
            if g.cond_start <= offset < g.cond_end and (gate is None or g.cond_start > gate.cond_start):
                gate = g
        if gate is not None and gate.body is not None:
            control, loc = 'lexical-enclosure', function.location(gate.cond_lines[0], gate.cond_lines[1])
        else:
            near = any(abs(g.cond_lines[0] - line_no) <= _ADJACENT_LINES for g in gates)
            control = 'adjacent' if gate is None and near else 'unknown'
            loc = function.location(line_no, line_no)
            gate = None
        out.append(_Site(FeatureSite(identifier=ident, feature_id=value, side=function.side, location=loc,
                                     control=control, wrapper=wrapper[:200]), offset, gate))
    return _Scan(tuple(out), text, truncated, limit)


def find_sites(function: FunctionView) -> tuple[FeatureSite, ...]:
    """Every recognized site in source order; duplicates at distinct lines are kept."""
    if function.code is None:
        return ()
    return tuple(s.site for s in _scan(function).sites)


def _changed(view: MatchView) -> list[tuple[int, tuple[int, int], tuple[int, int]]]:
    """(ordinal, old 1-based half-open, new 1-based half-open) for non-equal hunks that
    carry a semantic edit (B1's noise rule: whitespace/comment/rename-only hunks never qualify)."""
    changed = [h for h in view.hunks if h.operation != 'equal']
    keep = semantic_hunk_ordinals(view) if changed else frozenset()
    return [(i, (h.old_start + 1, h.old_end + 1), (h.new_start + 1, h.new_end + 1))
            for i, h in enumerate(changed) if i in keep]


def _hits(lo: int, hi: int, rng: tuple[int, int]) -> bool:
    return rng[0] < rng[1] and rng[0] <= hi and lo < rng[1]


def _region(gate: _Gate) -> tuple[int, int]:
    """Whole if-statement: condition plus enclosed body (body is non-None for gates kept)."""
    assert gate.body is not None
    return gate.cond_lines[0], max(gate.cond_lines[1], gate.body[1])


def _cond_text(scan: _Scan, site: _Site) -> str:
    if site.gate is None:
        return ''
    # Temporaries are renumbered between builds; a rename alone is not a condition change.
    return normalized_text(scan.text[site.gate.cond_start:site.gate.cond_end])


def _loc_key(site: FeatureSite) -> dict:
    loc = site.location
    return {'side': loc.side, 'function_id': loc.function_id, 'start': loc.start_line, 'end': loc.end_line,
            'excerpt': loc.excerpt_sha256, 'identifier': site.identifier}


def _transition(view, feature_id, kind, older, newer, confidence, qualifies, symbol_status, notes):
    tid = identity.domain_id('wil-transition', 1, {
        'pairing_id': view.pairing_id, 'feature_id': feature_id, 'kind': kind,
        'older': identity.sorted_unique(_loc_key(s) for s in older),
        'newer': identity.sorted_unique(_loc_key(s) for s in newer)})
    return FeatureTransition(transition_id=tid, pairing_id=view.pairing_id, match_id=view.match_id,
                             feature_id=feature_id, kind=kind, older_sites=tuple(older),
                             newer_sites=tuple(newer), confidence=confidence, qualifies=qualifies,
                             symbol_status=symbol_status, notes=tuple(sorted(set(notes))))


def _qualifying_hunk(view: MatchView, older: list[_Site], newer: list[_Site], changed=None):
    """First (ordinal, side, site, (lo, hi)) where a changed hunk lies in an enclosed region.
    Pass `changed` (from _changed) when calling per transition: recomputing it re-parses
    both functions and makes many-site functions quadratic."""
    for ordinal, old_rng, new_rng in (_changed(view) if changed is None else changed):
        for side, sites, rng in (('newer', newer, new_rng), ('older', older, old_rng)):
            for s in sites:
                if s.gate is not None and _hits(*_region(s.gate), rng):
                    lo, hi = _region(s.gate)
                    return ordinal, side, s, (max(lo, rng[0]), min(hi, rng[1] - 1))
    return None


def _scans(view: MatchView):
    older = _scan(view.older[0]) if len(view.older) == 1 and view.older[0].code is not None else None
    newer = _scan(view.newer[0]) if len(view.newer) == 1 and view.newer[0].code is not None else None
    return older, newer


def analyze(view: MatchView, symbol_status: str = 'absent') -> tuple[FeatureTransition, ...]:
    """Per-feature transitions for one pairing, deterministic order (feature id, None last)."""
    base_notes: list[str] = ['lexical-heuristic-no-cfg']
    one_to_one = len(view.older) == 1 and len(view.newer) == 1
    older_sites: list[_Site] = []
    newer_sites: list[_Site] = []
    older_scan = newer_scan = None
    unavailable = False
    budget = MAX_SITES
    for side, functions, bucket in (('older', view.older, older_sites), ('newer', view.newer, newer_sites)):
        for function in functions:
            if function.code is None:
                unavailable = True
                continue
            scan = _scan(function)
            if scan.truncated:
                base_notes.append('function-too-large')
            if scan.site_limit or len(scan.sites) > budget:
                base_notes.append('site-limit')
            bucket.extend(scan.sites[:budget])
            budget -= min(budget, len(scan.sites))
            if one_to_one:
                if side == 'older':
                    older_scan = scan
                else:
                    newer_scan = scan
    if unavailable:
        base_notes.append('code-unavailable')
    if not view.two_sided:
        base_notes.append('one-sided-pairing')
    elif not one_to_one:
        base_notes.append('pairing-ambiguous')
    elif view.manual:
        base_notes.append('manual-match')
    reliable = view.two_sided and one_to_one and not unavailable and not view.manual

    ids = sorted({s.site.feature_id for s in older_sites + newer_sites}, key=lambda v: (v is None, v or 0))
    shared = set()
    for sites in (older_sites, newer_sites):
        per_gate: dict[int, set] = {}
        for s in sites:
            if s.gate is not None:
                per_gate.setdefault(s.gate.cond_start, set()).add(s.site.feature_id)
        shared |= {fid for fids in per_gate.values() if len(fids) > 1 for fid in fids}
    changed = _changed(view) if reliable else []

    out = []
    for fid in ids:
        olds = [s for s in older_sites if s.site.feature_id == fid]
        news = [s for s in newer_sites if s.site.feature_id == fid]
        notes = list(base_notes)
        if fid in shared:
            notes.append('shared-condition')
        if len({s.site.identifier for s in olds + news}) > 1:
            notes.append('identifier-spellings-differ')
        enclosed = [s for s in olds + news if s.site.control == 'lexical-enclosure']
        if not enclosed and any(s.site.control == 'adjacent' for s in olds + news):
            notes.append('adjacent-only')
        osites, nsites = [s.site for s in olds], [s.site for s in news]
        if fid is None:
            notes.append('feature-id-not-derivable')
            out.append(_transition(view, None, 'unknown', osites, nsites, 'weak', False, symbol_status, notes))
            continue
        if olds and not news:
            kind = 'removed'
        elif news and not olds:
            kind = 'introduced'
        elif not reliable:
            kind = 'unknown'
        elif sorted(_cond_text(older_scan, s) for s in olds) != sorted(_cond_text(newer_scan, s) for s in news):
            kind = 'condition-changed'
        elif any(s.gate is not None and _hits(s.gate.body[0], s.gate.body[1], rng)
                 for _, old_rng, new_rng in changed
                 for sites, rng in ((olds, old_rng), (news, new_rng)) for s in sites):
            kind = 'guarded-behavior-changed'
        else:
            kind = 'unchanged-around-change'
            if not changed:
                notes.append('no-changed-hunks')
        qualifies = reliable and kind in QUALIFYING and _qualifying_hunk(view, olds, news, changed) is not None
        if kind in QUALIFYING and reliable and not qualifies:
            notes.append('change-outside-enclosed-region')
        confidence = 'moderate' if qualifies and olds and news else 'weak'
        out.append(_transition(view, fid, kind, osites, nsites, confidence, qualifies, symbol_status, notes))
    return tuple(out)


def _norm(lines) -> str:
    return _WS.sub(' ', '\n'.join(lines)).strip()


def wil_signals(view: MatchView, transitions) -> tuple[ChangeSignal, ...]:
    """One WIL signal per qualifying transition.

    group_key = domain_id('edit', 1, {'pairing_id', 'hunk_ordinal', 'side', 'text'}) where
    `hunk_ordinal` counts non-equal hunks from 0, `side` is the side whose enclosed
    region contains the hunk (newer preferred), and `text` is that side's changed
    lines inside the region, joined by '\\n' with whitespace runs collapsed to one
    space and stripped. B1 shares the group only if it derives this same payload.
    """
    qualifying = [t for t in transitions if t.qualifies and t.pairing_id == view.pairing_id]
    if not qualifying:
        return ()
    older_scan, newer_scan = _scans(view)
    if older_scan is None or newer_scan is None:
        return ()
    signals = []
    changed = _changed(view)
    for t in qualifying:
        olds = [s for s in older_scan.sites if s.site.feature_id == t.feature_id]
        news = [s for s in newer_scan.sites if s.site.feature_id == t.feature_id]
        hit = _qualifying_hunk(view, olds, news, changed)
        if hit is None:
            continue
        ordinal, side, site, (lo, hi) = hit
        function = view.newer[0] if side == 'newer' else view.older[0]
        # Same edit identity as B1 (signals.edit_group_key): whole changed hunk, newer side
        # preferred, so a WIL signal and a B1 signal on this hunk form one ranking group.
        hunk = [h for h in view.hunks if h.operation != 'equal'][ordinal]
        if hunk.new_end > hunk.new_start:
            group = edit_group_key(view, ordinal, 'newer', view.newer[0].code[hunk.new_start:hunk.new_end])
        else:
            group = edit_group_key(view, ordinal, 'older', view.older[0].code[hunk.old_start:hunk.old_end])
        locations: list[SourceLocation] = [s.location for s in t.older_sites + t.newer_sites]
        locations.append(function.location(lo, hi))
        unique = {identity.canonical_json(loc.model_dump()): loc for loc in locations}
        locations = [unique[k] for k in sorted(unique)]
        sid = identity.signal_id(view.pairing_id, 'WIL', DETECTOR_VERSION, group,
                                 [loc.model_dump() for loc in locations])
        both = bool(t.older_sites) and bool(t.newer_sites)
        rationale = (f'Feature_{t.feature_id} {t.kind}: a changed hunk lies inside an if-statement whose '
                     f'condition references the flag (lexical enclosure, heuristic; no CFG evidence). '
                     f'Symbol status: {t.symbol_status}.')
        signals.append(ChangeSignal(
            signal_id=sid, pairing_id=view.pairing_id, match_id=view.match_id, detector='WIL',
            detector_version=DETECTOR_VERSION, confidence='moderate' if both else 'weak', group_key=group,
            locations=tuple(locations), rationale=rationale,
            limitations=('lexical-enclosure-heuristic', 'no-cfg-evidence', f'symbols-{t.symbol_status}')))
    return tuple(sorted(signals, key=lambda s: s.signal_id))
