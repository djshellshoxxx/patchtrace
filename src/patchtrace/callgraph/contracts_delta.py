"""Models and ports of the call-delta layer (workbench-graph-delta/1, workbench-graph-leads/1). Additive only."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, Protocol

from pydantic import Field

from .contracts import Model, Pairing, Side

ChangeClass = Literal['same-link', 'added-call', 'removed-call', 'call-to-new-function', 'callee-deleted',
                      'cannot-determine']
DeltaState = Literal['compared', 'one-sided', 'not-comparable', 'unavailable']
Downgrade = Literal['none', 'renumber-only', 'hub-only']
SignalId = Literal['new-function-called', 'api-hint-called', 'import-called', 'call-dropped',
                   'known-function-called', 'fan-in-context', 'hub-only']
EntryState = Literal['reached', 'not-reached', 'unknown']
MAX_CHANGES = 500  # GL-06


class ApiHit(Model):
    api: str
    rule_id: str
    rule_revision: str
    family: str
    via: Literal['rule-hint', 'advisory-anchor', 'capa']


class CalleeChange(Model):
    cls: ChangeClass
    older_label: str | None = None
    newer_label: str | None = None
    older_node: str | None = None
    newer_node: str | None = None
    pairing: Pairing
    flags: tuple[str, ...] = ()  # import hub trace-helper thunk-suspect api-hint newly-imported inferred
    api: tuple[ApiHit, ...] = ()
    reason: str = ''


class CallDelta(Model):
    contract: Literal['workbench-graph-delta/1'] = 'workbench-graph-delta/1'
    match_id: str
    older_function_id: str | None = None
    newer_function_id: str | None = None
    older_label: str | None = None
    newer_label: str | None = None
    state: DeltaState
    downgrade: Downgrade = 'none'
    changes: tuple[CalleeChange, ...] = ()
    omitted: int = Field(default=0, ge=0)
    ghidriff_diff_types: tuple[str, ...] = ()  # hint text only
    callers_listed_older: int = Field(default=0, ge=0)
    callers_listed_newer: int = Field(default=0, ge=0)
    limitations: tuple[str, ...] = ()


class CallGroup(Model):
    callee: str  # node id (newer side, or older side for removed-call)
    label: str
    cls: ChangeClass
    members: tuple[str, ...]  # match ids
    hub: bool = False


class ClaimRef(Model):
    record_id: str
    field: Literal['callees', 'callers']


class GraphSignal(Model):
    id: SignalId
    rank: int
    meaning: str
    next_step: str
    evidence: ClaimRef


class Origin(Model):
    engine: str
    run_id: str
    raw_sha256: str | None
    group: Literal['calls'] = 'calls'


class Blast(Model):
    direct_callers: int = Field(ge=0)  # length of the listed `calling` (complete, direct, static)
    observed_callers: int = Field(ge=0)  # closure over observed edges only
    unknown_frontier: int = Field(ge=0)  # observed callers whose own call lists are not stored


class EntryDistance(Model):
    state: EntryState
    hops: int | None = None  # upper bound: the shortest observed path, not the shortest real one
    via: str = ''


class GraphLead(Model):
    contract: Literal['workbench-graph-leads/1'] = 'workbench-graph-leads/1'
    match_id: str
    signals: tuple[GraphSignal, ...]
    origin: Origin
    blast: Blast | None = None
    entry: EntryDistance | None = None


class ObservedPaths(Model):
    contract: Literal['workbench-graph-paths/1'] = 'workbench-graph-paths/1'
    side: Side
    paths: tuple[tuple[str, ...], ...]  # node ids, source first
    labels: dict[str, str]
    truncated: bool
    completeness: Literal['changed-set-lists', 'whole-program', 'unknown']
    note: str


class ApiHintPort(Protocol):
    def hints(self, name: str) -> tuple[ApiHit, ...]: ...


class EntryPort(Protocol):
    def entries(self, side: Side) -> Iterable[str]:
        """Labels of entry functions (entry point, exports) on one side."""
        ...
