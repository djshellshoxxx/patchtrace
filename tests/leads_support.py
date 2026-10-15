"""Builders for the Leads panel tests (PIL-C2): a synthetic stored assessment that has every lead class, a tie and a
hostile function name, fake panel ports that record what the panel did, and a real localized assessment of the sample
project for the tests that go through the project database. Synthetic data only; nothing here is live evidence."""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from types import SimpleNamespace

from pilot_localize_support import (
    CVE_A,
    CVE_B,
    advisory_entry,
    build,
    candidate,
    context,
    hypothesis,
    observation,
    run,
    sha,
)

from patchtrace.gui.anchors import NavResult
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.pilot import contracts as c
from patchtrace.pilot import keys, store
from patchtrace.pilot.panel import PANEL

HOSTILE = '<b>x</b>&amp;{0}%s javascript:alert(1)'
KEV = c.Kev(state='listed', date_added='2099-01-02', snapshot_id=sha('kev'))


def sample_assessment(*, hostile: str = HOSTILE, kev: c.Kev = KEV, gate_b: str = 'unverified',
                      channels: dict | None = None) -> c.PilotAssessment:
    """CVE_A (KEV listed): two fits, one needs-review (contested pairing); CVE_B: all partial; code-only list with a
    tie. Candidate 3 carries the hostile name."""
    cands = [candidate(0, 'read_item'), candidate(1, 'copy_block'), candidate(2, 'get_version'),
             candidate(3, hostile, identity='contested')]
    evidence = [(cands[0], observation('b1:BND', ref='s1', line=14)), (cands[0], observation('b1:SIZE', ref='s2', line=20)),
                (cands[1], observation('b1:BND', ref='s3', line=3)), (cands[2], observation('cf:comparison', ref='s4', line=2)),
                (cands[3], observation('b1:BND', ref='s5', line=3))]
    hyps = {CVE_A: (hypothesis('R-MEMORY-READ', 'CWE-125'),), CVE_B: (hypothesis('R-MEMORY-WRITE', 'CWE-787', cve=CVE_B),)}
    inputs = build(cands, evidence, cves=hyps, contexts=[context(CVE_A, kev=kev), context(CVE_B, gate=gate_b)],
                   entries={CVE_A: (advisory_entry(CVE_A),), CVE_B: (advisory_entry(CVE_B),)}, **(channels or {}))
    return run(inputs, clock=lambda: datetime(2099, 1, 1, tzinfo=UTC))


def lead_of(assessment: c.PilotAssessment, name: str, cve: str | None) -> c.Lead:
    return next(lead for lead in assessment.leads if lead.cve == cve and lead.newer and lead.newer[0].name == name)


def loaded_of(assessment: c.PilotAssessment, state: str = 'current', changed: tuple[str, ...] = ()) -> store.Loaded:
    return store.Loaded(state, None if state == 'current' else 'inputs-changed', assessment=assessment, changed=changed)


class FakeProject:
    """The `ProjectPort` of a panel test: an optional project, a key and the service the panel reads."""

    def __init__(self, service=None, *, run_id: str | None = 'run-1', open: bool = True) -> None:  # noqa: A002
        self.service = service or SimpleNamespace(root='root', store=None)
        self.run_id, self.is_open = run_id, open
        self.matches: list = []

    def project(self):
        if not self.is_open:
            return None
        real = getattr(self.service, 'project', None)
        return real or SimpleNamespace(id='p', revision=1, matches=self.matches, artifacts=[], runs=[])

    def key(self):
        project = self.project()
        return ProjectKey('root', 'p', 1, self.run_id, sha('o'), sha('n')) if project else None

    def busy(self) -> bool:
        return False


class FakeNav:
    def __init__(self) -> None:
        self.selected: list[str] = []
        self.revealed: list[tuple] = []
        self.anchors: list = []
        self.accept = True

    def select_match(self, match_id: str, clear_filters: bool = False) -> bool:
        self.selected.append(match_id)
        return self.accept

    def reveal_lines(self, function_id: str, start: int, end: int):
        self.revealed.append((function_id, start, end))

    def navigate(self, anchor):
        self.anchors.append(anchor)
        return NavResult.shown()


class FakeShell:
    def __init__(self, tasks: TaskRunner) -> None:
        self.tasks, self.settings, self.theme = tasks, None, None
        self.announced: list[tuple[str, bool]] = []
        self.copied: list[str] = []

    def announce(self, text: str, *, assertive: bool = False) -> None:
        self.announced.append((text, assertive))

    def copy_text(self, text: str) -> bool:
        self.copied.append(text)
        return True

    def status(self, text: str) -> None: ...


def make_context(project: FakeProject | None = None) -> tuple[PanelContext, FakeNav, FakeShell]:
    nav, shell = FakeNav(), FakeShell(TaskRunner(reraise=True))
    ctx = PanelContext(PANEL, project or FakeProject(), SimpleNamespace(), nav, shell)
    return ctx, nav, shell


def stored_of(assessment: c.PilotAssessment | None, state: str = 'current', changed: tuple[str, ...] = (),
              reviews: dict | None = None):
    from patchtrace.ui_leads import Stored
    loaded = store.Loaded('none', 'no-result') if assessment is None else loaded_of(assessment, state, changed)
    return Stored(loaded, reviews or {})


def no_collect(_service, _token):
    return object()


def no_rank(_collected, _token, _report):
    return None


def no_publish(_service, _assessment, _token) -> None: ...


def no_matches(_root, _snapshot, _token):
    return {}


def real_assessment(service, name: str = 'read_item') -> tuple[c.PilotAssessment, c.PilotConfig]:
    """A localized assessment of the sample project that its store accepts (its pair, run and raw output)."""
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    last = service.project.runs[-1]
    cand = c.Candidate(candidate_key=keys.candidate_key(sides['older'], sides['newer'], [0x1000], [0x1080]),
                       older=(c.FunctionRef(rva=0x1000, name=name),), newer=(c.FunctionRef(rva=0x1080, name=name),),
                       identity='unassessed')
    inputs = build([cand], [(cand, observation('b1:BND', ref='signal-1', line=14))],
                   cves={CVE_A: (hypothesis('R-MEMORY-READ', 'CWE-125'),)}, entries={CVE_A: (advisory_entry(CVE_A),)})
    inputs = dataclasses.replace(inputs, project_id=service.project.id, revision=service.project.revision,
                                 older_sha256=sides['older'], newer_sha256=sides['newer'],
                                 ghidriff_run_id=last.id, raw_sha256=last.raw_sha256)
    return run(inputs, clock=lambda: datetime(2099, 1, 1, tzinfo=UTC)), keys.default_config()
