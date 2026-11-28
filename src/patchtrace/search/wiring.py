"""Production stored-source ports captured on the project-store owner thread.

Workers receive only project/root/source values. Missing output and unreadable
output remain different; no capture runs a tool, provider or analyzed file.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from weakref import WeakKeyDictionary

from pydantic import BaseModel

from ..enrichment.contracts import CveSnapshot
from ..enrichment.cve import parse_snapshots
from ..enrichment.identity import domain_id
from ..enrichment.storage import Guard
from ..intelligence.contracts import AdvisorySource, IntelError
from ..intelligence.storage import FACTS_DIR, FACTS_KIND, GUARD_RUN, SOURCE_KIND, AdvisoryStore
from ..intelligence.tools.common import EVIDENCE_KIND, RUN_KIND, evidence_entry_id
from ..intelligence.tools.normalize import comparability
from ..intelligence.tools.snapshot import CapturedRows, ReadBudget, StoredTools, capture_rows
from ..owned_publication import OwnedPublicationError
from ..persistence import strict_json
from .errors import SearchError
from .sources.advisory import advisory_specs
from .sources.base import SourceSpec, skipped
from .sources.tools import ENGINES, SIDES, TRUNCATED, tool_specs

CVE_KIND = 'cve-snapshot'
KEY_KINDS = (RUN_KIND, EVIDENCE_KIND, SOURCE_KIND, FACTS_KIND, CVE_KIND)
TOOL_UNREADABLE = 'The stored {title} results for the {side} build could not be read ({error}). Run {title} again.'
ADV_UNREADABLE = 'The stored advisories could not be read ({error}).'
CVE_UNREADABLE = 'The stored CVE records could not be read ({error}).'
_OWNERS: WeakKeyDictionary = WeakKeyDictionary()
PROJECT_NODES = 100_000
PROJECT_BYTES = 16 * 1024 * 1024
PROJECT_DEPTH = 64


def copy_project(project):
    """Bound the desktop copy before allocating independent worker values."""
    pending, nodes, size = [(project, 0)], 0, 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > PROJECT_NODES or depth > PROJECT_DEPTH:
            raise SearchError('PT-SEARCH-LIMIT', 'the project exceeds the desktop snapshot budget; use the CLI')
        if isinstance(value, str):
            size += len(value) * 4
        elif isinstance(value, bytes):
            size += len(value)
        else:
            if isinstance(value, (BaseModel, SimpleNamespace)):
                children = value.__dict__.values()
            elif isinstance(value, dict):
                if len(value) > PROJECT_NODES // 2:
                    raise SearchError('PT-SEARCH-LIMIT', 'the project exceeds the desktop snapshot budget; use the CLI')
                children = (*value.keys(), *value.values())
            elif isinstance(value, (tuple, list, set, frozenset)):
                children = value
            elif value is None or type(value) in (bool, int, float):
                children = ()
            else:
                raise SearchError('PT-SEARCH-SOURCE', 'the project contains an unsupported snapshot value')
            if len(children) + len(pending) + nodes > PROJECT_NODES:
                raise SearchError('PT-SEARCH-LIMIT', 'the project exceeds the desktop snapshot budget; use the CLI')
            pending.extend((child, depth + 1) for child in children)
        if size > PROJECT_BYTES:
            raise SearchError('PT-SEARCH-LIMIT', 'the project exceeds the desktop snapshot budget; use the CLI')
    return project.model_copy(deep=True) if isinstance(project, BaseModel) else deepcopy(project)


def _error(exc):
    return str(getattr(exc, 'code', '') or type(exc).__name__)[:40]


def _key(service) -> tuple | None:
    """A value-only store-owner token and local/external modification counters."""
    try:
        project, db = service.project, service.store.connection
        if db.in_transaction:
            return None  # rollback does not change total_changes; never reuse provisional owner reads
        owner = _OWNERS.setdefault(service.store, object())
        external = db.execute('PRAGMA data_version').fetchone()[0]
        return (owner, str(service.root), project.id, project.revision, db.total_changes, external,
                tuple((a.id, a.side, a.sha256, a.relative_path, a.size) for a in project.artifacts))
    except (AttributeError, TypeError, sqlite3.Error):
        return None


def _current(entry, project):
    if (entry.guard.project_id != project.id or entry.project_revision > project.revision
            or entry.stale or entry.status != 'complete'):
        raise ValueError('stored reference does not belong to current project state')


def _advisory_rows(rows: CapturedRows, project) -> CapturedRows:
    """Check the current source/pointer publication identities before file I/O."""
    source_rows, fact_rows = rows.entries(SOURCE_KIND), rows.entries(FACTS_KIND)
    for entry in source_rows:
        _current(entry, project)
        body = entry.body
        if set(body) != {'contract', 'source'} or body['contract'] != 'intelligence/1':
            raise ValueError('invalid advisory source envelope')
        source = AdvisorySource.model_validate_json(json.dumps(body['source'], allow_nan=False))
        if (entry.id != f'{SOURCE_KIND}:{source.sha256}:{source.retrieval_id}'
                or entry.guard != Guard(project.id, GUARD_RUN, source.sha256, source.retrieval_id)):
            raise ValueError('advisory source ownership differs from its content')
    fields = {'contract', 'facts_id', 'source_id', 'path', 'sha256', 'normalizer_version', 'validator_version',
              'tracking_id', 'revision', 'cves'}
    for entry in fact_rows:
        _current(entry, project)
        body = entry.body
        if (set(body) != fields or body['contract'] != 'intelligence/1'
                or any(type(body[name]) is not int or body[name] < 1
                       for name in ('normalizer_version', 'validator_version'))):
            raise ValueError('invalid advisory facts pointer')
        expected = domain_id('advisory-facts', body['normalizer_version'],
                             {'sha256': body['source_id'], 'validator': body['validator_version']})
        digest = f'normalizer/{body["normalizer_version"]}/validator/{body["validator_version"]}'
        if (body['facts_id'] != expected or entry.id != f'{FACTS_KIND}:{expected}'
                or body['path'] != f'{FACTS_DIR}/{expected}.json'
                or entry.guard != Guard(project.id, GUARD_RUN, body['source_id'], digest)):
            raise ValueError('advisory facts ownership differs from its content')
    return CapturedRows(((SOURCE_KIND, tuple(source_rows)), (FACTS_KIND, tuple(fact_rows))))


class _StoredAdvisories(AdvisoryStore):
    def __init__(self, *args, budget, **kwargs):
        super().__init__(*args, **kwargs)
        self.budget = budget

    def read_verified(self, relative, sha256, *, maximum=None):
        from ..intelligence.tools.snapshot import SIDECAR_BYTES
        try:
            data = self.budget.read(self._path(relative), SIDECAR_BYTES if maximum is None else maximum, sha256)
            strict_json(data)  # preserve duplicate-member refusal before model parsing or normalization
            return data
        except (OSError, ValueError, RecursionError, OwnedPublicationError):
            raise IntelError('PT-INTEL-INTEGRITY', 'stored advisory bytes failed bounded integrity admission') from None


@dataclass(frozen=True, slots=True)
class _ToolRows:
    found: tuple[tuple[tuple[str, str], tuple[Any, Any]], ...] = ()

    def latest(self, engine, side):
        return next((value for where, value in self.found if where == (engine, side)), None)


@dataclass(frozen=True, slots=True)
class _Advisories:
    items: tuple[Any, ...]
    warnings: tuple[str, ...] = ()

    def advisories(self):
        return self.items, self.warnings


@dataclass(frozen=True, slots=True)
class _Snapshots:
    items: tuple[CveSnapshot, ...]

    def snapshots(self):
        return self.items


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    key: tuple | None
    tools: _ToolRows | None = None
    advisories: _Advisories | None = None
    snapshots: _Snapshots | None = None
    unavailable: tuple[tuple[str, str], ...] = ()
    comparable_engines: frozenset[str] = frozenset()
    digests: tuple[tuple[str, str], ...] = ()

    @property
    def required_groups(self) -> tuple[str, ...]:
        """Known capture loss must remain visible for an unqualified query."""
        return tuple(group for group, _reason in self.unavailable)

    def extra_specs(self, _request=None) -> tuple[SourceSpec, ...]:
        reasons, digests = dict(self.unavailable), dict(self.digests)
        specs = tool_specs(self.tools) + advisory_specs(self.advisories, self.snapshots)
        partial = {f'tool:{engine}:{side}' for (engine, side), (_run, evidence) in
                   (self.tools.found if self.tools is not None else ())
                   if evidence.truncated or evidence.truncated_types}
        return tuple(skipped(s.group, s.kinds, s.side, 'unavailable', reasons[s.group]) if s.group in reasons
                     else replace(s, inputs={'source': s.inputs, 'stored_content': digests.get(s.group)},
                                  reason=TRUNCATED if s.group in partial else s.reason)
                     for s in specs)

    def comparable(self, engine):
        return engine in self.comparable_engines

    def identity(self):
        return (self.tools is not None, self.advisories is not None, self.snapshots is not None,
                self.digests, self.unavailable, self.comparable_engines)


@dataclass(frozen=True, slots=True)
class BoundService:
    project: Any
    root: Path | str
    sources: SourceSnapshot
    owner: int | None = None


def same_inputs(left: BoundService, right: BoundService) -> bool:
    return (left.owner == right.owner and str(left.root) == str(right.root) and left.project == right.project
            and left.sources.identity() == right.sources.identity())


def _tools(store, unavailable):
    found = []
    for engine, (title, *_rest) in ENGINES.items():
        for side in SIDES:
            try:
                value = store.latest(engine, side)
            except Exception as exc:  # one classifiable source failure preserves the other groups
                unavailable.append((f'tool:{engine}:{side}',
                                    TOOL_UNREADABLE.format(title=title, side=side, error=_error(exc))))
            else:
                if value is not None:
                    found.append(((engine, side), value))
    result = _ToolRows(tuple(found))
    comparable = set()
    for engine in ENGINES:
        older, newer = result.latest(engine, 'older'), result.latest(engine, 'newer')
        if (older is not None and newer is not None
                and not any(e.truncated or e.truncated_types for _run, e in (older, newer))
                and not comparability(older[0], newer[0])):
            comparable.add(engine)
    return result, frozenset(comparable)


def _advisories(rows, service, budget, unavailable):
    try:
        checked = _advisory_rows(rows, service.project)
        store = _StoredAdvisories(Path(service.root), checked, service.project.id, service.project.revision,
                                  budget=budget)
        items, warnings = store.advisories()
        if warnings:
            raise ValueError('incomplete stored evidence')
        return _Advisories(tuple(items))
    except Exception as exc:  # partial advisory sets cannot justify absence of text
        unavailable.append(('adv', ADV_UNREADABLE.format(error=_error(exc))))
        return None


def _snapshots(rows, project, unavailable):
    try:
        items = []
        for entry in rows.entries(CVE_KIND):
            _current(entry, project)
            items.extend(parse_snapshots(entry.body_json.encode('utf-8')))
        return _Snapshots(tuple(items))
    except Exception as exc:
        unavailable.append(('cve', CVE_UNREADABLE.format(error=_error(exc))))
        return None


def _digest_rows(rows, kinds):
    values = sorted((entry.id, entry.body_sha256) for kind in kinds for entry in rows.entries(kind))
    return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode('utf-8')).hexdigest()


def _failed_snapshot():
    groups = tuple(f'tool:{engine}:{side}' for engine in ENGINES for side in SIDES) + ('adv', 'cve')
    return SourceSnapshot(None, unavailable=tuple((group, 'Stored source snapshot could not be captured.')
                                                 for group in groups))


def snapshot_sources(service, reuse: SourceSnapshot | None = None) -> SourceSnapshot:
    """Owner thread only. Failed and file-dependent snapshots are never reused."""
    from ..intelligence.tools.snapshot import SIDECAR_BYTES
    key = _key(service)
    if reuse is not None and key is not None and reuse.key == key:
        return reuse
    if getattr(service, 'store', None) is None:
        return SourceSnapshot(None)
    try:
        rows = capture_rows(service, KEY_KINDS)
        budget = ReadBudget(remaining=SIDECAR_BYTES, root=Path(service.root))
        store = StoredTools(rows, Path(service.root), service.project.id, service.project.revision,
            artifacts={a.side: a.sha256 for a in service.project.artifacts}, budget=budget)
    except Exception:
        return _failed_snapshot()
    unavailable = []
    tools, comparable = _tools(store, unavailable)
    advisories = _advisories(rows, service, budget, unavailable)
    snapshots = _snapshots(rows, service.project, unavailable)
    digests = [(f'tool:{engine}:{side}', evidence_entry_id(value[1]))
               for (engine, side), value in tools.found]
    if advisories is not None:
        digests.append(('adv', _digest_rows(rows, (SOURCE_KIND, FACTS_KIND))))
    if snapshots is not None:
        digests.append(('cve', _digest_rows(rows, (CVE_KIND,))))
    if key != _key(service):
        return _failed_snapshot()  # the owner/external rows changed while capture was in progress
    if unavailable or budget.touched:
        key = None
    return SourceSnapshot(key, tools, advisories, snapshots, tuple(unavailable), comparable, tuple(digests))
