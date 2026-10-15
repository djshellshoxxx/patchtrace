"""Anchors: the one way a panel points at something another panel (or the code panes) can show (GUI plan 7, 8.2).

An `AnchorRef` is a value, never a callback; the router checks that it is still current, finds the one handler
declared for its kind and records where the analyst has been. There is no fallback target: an anchor that is stale,
missing, ambiguous or unhandled says so and navigates nowhere. Pure: the host injects what actually gets shown.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace

from .projection import MatchIndex, ProjectKey
from .text import LABEL_LIMIT, sanitize_text

ANCHOR_KINDS = ('function', 'match', 'string', 'import', 'address', 'capability', 'rule', 'build_fact',
                'advisory_phrase', 'cve', 'kb', 'cwe')
SIDES = ('older', 'newer', 'both')
KEY_LIMIT = 256
MAX_CANDIDATES = 20
NAV_HISTORY = 50
NAV_STATUSES = ('shown', 'not-found', 'stale', 'ambiguous', 'blocked')
CODE_KINDS = ('function', 'match')  # opened by the main window's code panes rather than by a panel

STALE_TEXT = 'The project changed after this link was created. Open it again from the source panel.'


@dataclass(frozen=True, slots=True)
class AnchorRef:
    """A place in the analysis. Equal when kind, key, side and run agree; the rest is display and provenance.

    `key` is opaque and belongs to its producer. `side` is explicit ('both' or None means no particular side).
    `run_id` and `revision` pin the link to what the producer saw; `pinned(key)` fills both from a `ProjectKey`."""

    kind: str
    key: str
    side: str | None = None
    run_id: str | None = None
    label: str = field(default='', compare=False)
    origin: str | None = field(default=None, compare=False)
    revision: int | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if self.kind not in ANCHOR_KINDS:
            raise ValueError(f'unknown anchor kind {self.kind!r:.40}')
        if not isinstance(self.key, str) or not 0 < len(self.key) <= KEY_LIMIT:
            raise ValueError(f'an anchor key is 1 to {KEY_LIMIT} characters')
        if self.side is not None and self.side not in SIDES:
            raise ValueError(f'unknown anchor side {self.side!r:.40}')
        object.__setattr__(self, 'label', sanitize_text(self.label, LABEL_LIMIT))

    def pinned(self, key: ProjectKey | None) -> AnchorRef:
        return self if key is None else replace(self, run_id=key.run_id, revision=key.revision)


@dataclass(frozen=True, slots=True)
class NavResult:
    status: str
    message: str = ''
    candidates: tuple[AnchorRef, ...] = ()
    code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in NAV_STATUSES:
            raise ValueError(f'unknown navigation status {self.status!r:.40}')
        if len(self.candidates) > MAX_CANDIDATES:
            raise ValueError(f'at most {MAX_CANDIDATES} candidates')
        object.__setattr__(self, 'message', sanitize_text(self.message, LABEL_LIMIT))

    @classmethod
    def shown(cls) -> NavResult:
        return cls('shown')

    @classmethod
    def stale(cls) -> NavResult:
        return cls('stale', STALE_TEXT, code='PT-GUI-NAV-STALE')

    @classmethod
    def not_found(cls, label: str, run_id: str | None) -> NavResult:
        where = f' in run {sanitize_text(run_id)}' if run_id else ''
        return cls('not-found', f'Not found{where}: {sanitize_text(label)}.', code='PT-GUI-NAV-NOTFOUND')

    @classmethod
    def ambiguous(cls, label: str, candidates: Iterable[AnchorRef]) -> NavResult:
        found = tuple(candidates)
        return cls('ambiguous', f'{len(found)} candidates match {sanitize_text(label)}. Choose one.',
                   found[:MAX_CANDIDATES], 'PT-GUI-NAV-AMBIGUOUS')

    @classmethod
    def blocked(cls, title: str, reason: str) -> NavResult:
        return cls('blocked', f'{sanitize_text(title)} is unavailable: {sanitize_text(reason)}',
                   code='PT-GUI-NAV-BLOCKED')


def is_stale(anchor: AnchorRef, key: ProjectKey | None) -> bool:
    """True when the project is gone, or moved on from what the anchor was pinned to (another run, or any
    revision since: a manual correction and an orientation swap both bump it)."""
    if key is None:
        return True
    if anchor.run_id is not None and anchor.run_id != key.run_id:
        return True
    return anchor.revision is not None and anchor.revision != key.revision


def locate_match(anchor: AnchorRef, index: MatchIndex) -> str | NavResult:
    """The id of the match a function or match anchor opens, or the NavResult that explains why none does.

    A function listed by several matches is ambiguous and yields candidates, never the first. An explicit side
    that does not hold the function is a miss, not a guess."""
    if anchor.kind not in CODE_KINDS:
        raise ValueError(f'{anchor.kind} anchors are not code anchors')
    run_id = anchor.run_id or (None if index.key is None else index.key.run_id)
    missing = NavResult.not_found(anchor.label or anchor.key, run_id)
    if anchor.kind == 'match':
        return anchor.key if index.has_match(anchor.key) else missing
    sides: dict[str, str] = {}
    for hit in index.functions_for(anchor.key):
        if anchor.side in (None, 'both', hit.side):
            sides.setdefault(hit.match_id, hit.side)
    if not sides:
        return missing
    if len(sides) == 1:
        return next(iter(sides))
    return NavResult.ambiguous(anchor.label or anchor.key, [
        AnchorRef('match', match_id, side, anchor.run_id, anchor.label, anchor.origin, anchor.revision)
        for match_id, side in sides.items()])


class NavHistory:
    """Back and forward over the anchors the analyst has been to (Alt+Left, Alt+Right); newest entries are kept."""

    def __init__(self, limit: int = NAV_HISTORY) -> None:
        self._limit = max(1, limit)
        self._entries: list[AnchorRef] = []
        self._cursor = -1

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def current(self) -> AnchorRef | None:
        return self._entries[self._cursor] if self._entries else None

    def push(self, anchor: AnchorRef) -> None:
        if self.current == anchor:
            return
        del self._entries[self._cursor + 1:]  # going somewhere new forgets the forward trail
        self._entries.append(anchor)
        del self._entries[:-self._limit]
        self._cursor = len(self._entries) - 1

    def back(self) -> AnchorRef | None:
        if self._cursor <= 0:
            return None
        self._cursor -= 1
        return self._entries[self._cursor]

    def forward(self) -> AnchorRef | None:
        if self._cursor >= len(self._entries) - 1:
            return None
        self._cursor += 1
        return self._entries[self._cursor]


class AnchorRouter:
    """Stale check, then the handler declared for the anchor's kind, then the host's `show`.

    `key()` is the current ProjectKey, `handler(kind)` the id of the one target that opens that kind (the host builds
    it from the `anchors_in` of the specs), and `show(target, anchor)` builds and reveals the target and returns its
    NavResult. GUI thread only."""

    def __init__(self, key: Callable[[], ProjectKey | None], handler: Callable[[str], str | None],
                 show: Callable[[str, AnchorRef], NavResult], limit: int = NAV_HISTORY) -> None:
        self._key, self._handler, self._show = key, handler, show
        self.history = NavHistory(limit)

    def navigate(self, anchor: AnchorRef) -> NavResult:
        result = self._open(anchor)
        if result.status == 'shown':
            self.history.push(anchor)
        return result

    def back(self) -> NavResult | None:
        previous = self.history.back()
        return None if previous is None else self._open(previous)

    def forward(self) -> NavResult | None:
        following = self.history.forward()
        return None if following is None else self._open(following)

    def _open(self, anchor: AnchorRef) -> NavResult:
        if is_stale(anchor, self._key()):
            return NavResult.stale()
        target = self._handler(anchor.kind)
        if target is None:
            return NavResult.blocked('Navigation', f'no panel opens {anchor.kind} links')
        return self._show(target, anchor)
