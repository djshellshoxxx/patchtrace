"""Panel service (slice R6a): turns a `RuleStore` and a few facts about the session into the view models of `view`. Read-only
and Qt-free: proposing, testing and accepting stay in the CLI orchestration; the panel's worker thread calls those and then
asks this service to re-read. Nothing here scans, compiles or imports the engine."""
from __future__ import annotations

from dataclasses import dataclass

from . import view
from .contracts import PairSource, RuleCandidate
from .errors import RuleError
from .limits import DEFAULT_LIMITS, RuleLimits
from .store import RuleStore


@dataclass(frozen=True)
class Session:
    """What the panel knows besides the store: all optional, all supplied by the controller."""
    project_open: bool = True
    engine_available: bool = True
    selected: PairSource | None = None
    busy: str | None = None          # 'propose' or 'test'
    busy_rules: int = 0
    busy_files: int = 0
    error: RuleError | None = None
    stale_reason: str | None = None
    blocked_by: str | None = None    # the first failing check of the last proposal that produced no candidate


class PanelService:
    def __init__(self, rules: RuleStore | None, *, engine_version: str = '', limits: RuleLimits = DEFAULT_LIMITS):
        self.rules = rules
        self.engine_version = engine_version
        self.limits = limits

    def status(self, session: Session) -> view.Status:
        """The one state that applies, in the order of the plan's table: no project, failure, work in progress, engine,
        selection, stale, size, then empty or ready."""
        if not session.project_open or self.rules is None:
            return view.status('R0')
        if session.error is not None:
            return view.status('R7', code=session.error.code, message=session.error.message)
        if session.busy == 'propose':
            return view.status('R4p')
        if session.busy == 'test':
            return view.status('R4t', rules=session.busy_rules, files=session.busy_files)
        if not session.engine_available:
            return view.status('R1')
        if session.selected is None:
            return view.status('R2')
        if session.stale_reason:
            return view.status('R6', reason=session.stale_reason)
        if session.blocked_by:
            return view.status('R5', reason=session.blocked_by)
        return view.status('R3') if not self.candidates(session.selected) else view.Status('ready', '')

    def too_large(self, cells: int) -> view.Status | None:
        return view.status('R8', count=cells) if cells > self.limits.cells else None

    def _for_pair(self, source: PairSource | None) -> list[RuleCandidate]:
        if self.rules is None:
            return []
        found = self.rules.candidates()
        if source is None:
            return found
        return [c for c in found if (c.source.older_sha256, c.source.newer_sha256) ==
                (source.older_sha256, source.newer_sha256)]

    def candidates(self, source: PairSource | None = None) -> tuple[view.CandidateRow, ...]:
        if self.rules is None:
            return ()
        versions = self.rules.versions()
        return tuple(view.candidate_row(c, self.rules.decisions(c.candidate_id), versions)
                     for c in self._for_pair(source))

    def detail(self, candidate_id: str) -> tuple[tuple[view.FeatureRow, ...], tuple[view.CheckRow, ...], str] | None:
        """Features, checks and the stored rule text, exactly as saved (the panel copies this string unchanged)."""
        found = self.rules.candidate(candidate_id) if self.rules is not None else None
        if found is None:
            return None
        return view.feature_rows(found), view.check_rows(found.gates), found.rule_text

    def saved(self) -> tuple[view.SavedRow, ...]:
        if self.rules is None:
            return ()
        return view.saved_rows(self.rules.versions(), self.rules.decisions(), self.rules.tests(), self.engine_version)

    def grid(self, run_id: str | None = None) -> view.GridView | None:
        """The newest test (or the named one) as a grid; columns are named after the candidate's rule name."""
        if self.rules is None:
            return None
        runs = self.rules.tests()
        run = next((r for r in runs if run_id in (None, r.run_id)), None)
        if run is None:
            return None
        names = []
        for rule in run.rules:
            version = self.rules.version(rule.version_id)
            candidate = self.rules.candidate(version.candidate_id) if version is not None else None
            names.append(candidate.rule_name if candidate is not None else rule.version_id[:12])
        return view.GridView(run, names)
