"""Owner-thread current evidence for PIL reads/publication; no ranking, Qt, network or second project open.

The immutable capture compares each assessment separately: above P-03 a stored
assessment can legitimately cover an explicit CVE subset. Advisory identity uses
the same tracking groups as StoredAdvisorySource, including withdrawing revisions.
Unavailable sources stay distinguishable from intentionally empty local inputs.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from pydantic import ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore
from ..intelligence.contracts import AdvisorySource, IntelError
from ..intelligence.hypotheses import rules_digest
from ..intelligence.lexicon import lexicon_digest
from ..intelligence.storage import SOURCE_KIND, AdvisoryStore
from ..kev import store as kev_store
from ..kev.contracts import KevError
from . import store
from .contracts import PilotAssessment
from .limits import DEFAULT_LIMITS
from .origins import DefaultOriginRegistry
from .rules.data import pilot_rules_digest
from .tiers import TIERS_VERSION


@dataclass(frozen=True, slots=True)
class AdvisoryIdentity:
    facts_id: str
    group: tuple[str, str]
    cves: frozenset[str]


@dataclass(frozen=True, slots=True)
class CurrentInputs:
    project_id: str | None
    revision: int | None
    project_current: bool
    known: tuple[tuple[str, object], ...]
    advisories: tuple[AdvisoryIdentity, ...] | None
    kev_available: bool

    def changed(self, assessment: PilotAssessment) -> tuple[str, ...]:
        """Pure check: names of changed or unverifiable required inputs, without changing history."""
        changed = [name for name, value in self.known if getattr(assessment.inputs, name) != value]
        if assessment.project_id != self.project_id:
            changed.append('project_id')
        if not self.project_current or assessment.revision != self.revision:
            changed.append('project_revision')
        if not self._same_advisories(assessment):
            changed.append('advisory_facts_ids')
        if not self.kev_available:
            changed.append('kev_snapshot_id')
        return tuple(dict.fromkeys(changed))

    def _same_advisories(self, assessment: PilotAssessment) -> bool:
        if self.advisories is None:
            return False
        have = {cve for advisory in self.advisories for cve in advisory.cves}
        selected = {context.cve for context in assessment.cves}
        if len(have) <= DEFAULT_LIMITS.p03_cves:
            if selected != have:
                return False
        elif not selected or not selected <= have:
            return False
        # Match StoredAdvisorySource.facts_ids: a later revision may withdraw all
        # selected CVEs and must still invalidate its earlier tracking-group facts.
        groups = {item.group for item in self.advisories if item.cves & selected}
        facts = tuple(sorted({item.facts_id for item in self.advisories if item.group in groups}))
        return assessment.inputs.advisory_facts_ids == facts


def _advisories(service, enrichment: EnrichmentStore, project) -> tuple[AdvisoryIdentity, ...] | None:
    """Require every retained source to be accounted for; verified facts-cache recovery is allowed."""
    try:
        corrupt = []
        rows = enrichment.entries(SOURCE_KIND, on_corrupt=corrupt.append)
        expected = set()
        for entry in rows:
            if not isinstance(entry.body, dict) or entry.guard.project_id != project.id:
                return None
            source = AdvisorySource.model_validate_json(json.dumps(entry.body.get('source')))
            if entry.guard.raw_sha256 != source.sha256:
                return None
            expected.add(source.sha256)
        if corrupt:
            return None
        advisories, _warnings = AdvisoryStore(service.root, enrichment, project.id, project.revision).advisories()
        if expected != {item.source.sha256 for item in advisories}:
            return None  # a source was skipped; an old revision cannot silently become current again
        return tuple(AdvisoryIdentity(item.facts.facts_id,
                                     (item.facts.publisher_namespace, item.facts.tracking_id),
                                     frozenset(item.facts.cves())) for item in advisories)
    except (IntelError, EnrichmentError, ValidationError, sqlite3.Error, OSError, ValueError, TypeError,
            AttributeError):
        return None


def _kev() -> tuple[str | None, bool]:
    try:
        status = kev_store.KevStore(kev_store.default_kev_dir()).status()
        if status.current is not None:
            return status.current.snapshot_id, True  # includes the store's verified recovery fallback
        return None, not status.notes
    except (KevError, OSError, ValueError):
        return None, False


def capture(service, enrichment: EnrichmentStore, project=None) -> CurrentInputs:
    """Read on the existing connection's owner thread. Workers receive no connection or service."""
    project = service.project if project is None else project
    project_id, revision = store.project_owner(enrichment)
    sides = {artifact.side: artifact.sha256 for artifact in project.artifacts}
    run = store.completed_run(project)
    kev_id, kev_available = _kev()
    known = (
        ('older_sha256', sides.get('older')), ('newer_sha256', sides.get('newer')),
        ('ghidriff_run_id', run.id if run else None), ('raw_sha256', run.raw_sha256 if run else None),
        ('kev_snapshot_id', kev_id), ('lexicon_digest', lexicon_digest()), ('rules_digest', rules_digest()),
        ('pilot_rules_digest', pilot_rules_digest()), ('origins_digest', DefaultOriginRegistry().digest()),
        ('tiers_version', TIERS_VERSION))
    return CurrentInputs(project_id, revision, (project.id, project.revision) == (project_id, revision), known,
                         _advisories(service, enrichment, project), kev_available)
