"""Builders for the R5 tests (store, matrix, export, CLI): a real candidate of the SYNTHETIC `capa-api` pair, the accept path
as the CLI takes it, a project to keep rows in, and an in-process stand-in for the worker so the grid tests need no child.
Nothing here is live evidence; the stand-in calls the REAL YARA-X (the tests skip when it is not installed)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import rules_fixtures as rf
from test_rules_synergy import capa_sources

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.persistence import ProjectStore
from patchtrace.rules import candidates as cd
from patchtrace.rules import runner, store
from patchtrace.rules.contracts import RuleCandidate, RuleDecision, RuleVersion, WorkerRule
from patchtrace.rules.store import RuleStore
from patchtrace.service import ProjectService

DECIDED = '2026-10-14T09:00:00+00:00'
PROJECT_ID = 'proj-r5'


def candidate_of(bench: rf.Bench, which: str = 'term', project_id: str = PROJECT_ID, *, name: str | None = None
                 ) -> RuleCandidate:
    """The one candidate of a changed function of the `capa-api` pair, made by the real proposal path. `name` is a function
    name the pair carries (from symbols, in real life) on the side that has the function."""
    pair = rf.capa_pair(bench, which).model_copy(update={'project_id': project_id})
    if name is not None:
        side = 'older' if pair.older is not None else 'newer'
        pair = pair.model_copy(update={side: getattr(pair, side).model_copy(update={'name': name})})
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    (candidate,) = cd.propose(pair, capa_sources(bench), check=check).candidates
    return candidate


def accepted(candidate: RuleCandidate, label: str = 'Terminate removed', *, previous: RuleVersion | None = None,
             decided_at: str = DECIDED, **advisories) -> tuple[RuleDecision, RuleVersion]:
    decision = store.decision_for(candidate, 'accept', decided_at, label=label, **advisories)
    number = 1 if previous is None else previous.version + 1
    text = store.accepted_text(candidate, decision, number)
    return decision, store.version_for(candidate, decision, previous, text)


def rule_store(root: Path, project_id: str = PROJECT_ID, revision: int = 1) -> RuleStore:
    """A store over a bare project database (no snapshot is needed to keep rule rows)."""
    project = ProjectStore(Path(root) / 'project', create=True)
    return RuleStore(EnrichmentStore(project), project.root, project_id, revision)


def project_of(bench: rf.Bench, root: Path) -> ProjectService:
    """A real project over the two `capa-api` images, so its artifacts are the anchors of the pair."""
    older, newer = root / 'older.exe', root / 'newer.exe'
    older.write_bytes(bench.build('capa-api', 'older').data)
    newer.write_bytes(bench.build('capa-api', 'newer').data)
    return ProjectService.create(older, newer, 'rules r5', root / 'case')


def engine_scan(rules, targets, *, timeout_s=None, cancel=None, limits=None, scratch_dir=None) -> runner.ScanOutcome:
    """`runner.scan` in this process: the same checks as the worker's (a file that is gone, changed or too large is
    `not-scanned`, never a miss) and the real engine."""
    from patchtrace.rules import engine
    compiled = engine.RuleSet.compile(tuple(WorkerRule(name=r.name, text=r.text) for r in rules))
    cells = []
    for target in targets:
        try:
            data = Path(target.path).read_bytes()
        except OSError:
            cells.extend(compiled.skip('unreadable'))
            continue
        if len(data) != target.size or (target.sha256 and hashlib.sha256(data).hexdigest() != target.sha256):
            cells.extend(compiled.skip('file-changed'))
            continue
        cells.extend(compiled.scan(data))
    return runner.ScanOutcome(engine.stamp(), compiled.lint, tuple(cells))
