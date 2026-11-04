"""Restart recovery for interrupted attaches (KB-integration-plan 7.3 and 7.5; slice K2).

A restart marks unfinished operations interrupted and may finish them from the journal; it never fetches, never runs
an engine, never deletes a project or a user file. Everything here is idempotent: running ``repair`` twice changes
nothing the second time. ``preview`` reads the same journal and names, without writing anything, what ``repair`` with
the same arguments would create, add, keep or replace (``kb attach`` without ``--repair``).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

from .contracts import Attempt, ProjectLink
from .errors import KbcIssue, OperationResult
from .ports import ProjectPort
from .store import ProjectAttachment, WorkspaceStore

ContextFor = Callable[[str, dict], tuple[tuple[str, bytes], ...]]


@dataclass(frozen=True)
class Change:
    """One effect of ``repair``. ``target`` is ``project``, ``row`` (``<kind>:<key>``) or ``sidecar`` (a path inside
    the project); ``action`` is ``create``, ``add``, ``keep``, ``replace`` or ``conflict`` (repair stops there and
    replaces nothing). There is no delete action."""
    target: str
    action: str
    name: str | None = None


@dataclass(frozen=True)
class PlannedRepair:
    operation: str
    state: str
    project_id: str | None
    changes: tuple[Change, ...]

    def replaces_rows(self) -> bool:
        return any(c.target == 'row' and c.action == 'replace' for c in self.changes)


def open_operations(workspace: WorkspaceStore) -> tuple[str, ...]:
    """Attach operations that did not reach ``done``."""
    return tuple(op for op, state, _ in workspace.journal_ops() if state != 'done')


def pending_context(workspace: WorkspaceStore) -> tuple[str, ...]:
    """Finished attaches whose project has no documentary context yet (``CONTEXT_PENDING``)."""
    return tuple(op for op, state, body in workspace.journal_ops()
                 if state == 'done' and body.get('link_state') == 'context-pending')


def mark_interrupted(workspace: WorkspaceStore) -> tuple[str, ...]:
    """Record one cancelled ``interrupted:<stage>`` attempt per unfinished operation; returns the operation ids."""
    marked = []
    for op, state, body in workspace.journal_ops():
        if state == 'done' or body.get('interrupted'):
            continue
        inv = body['revision']['investigation_id']
        workspace.append_attempt(inv, Attempt(op='attach', plan_sha=body.get('plan_sha'),
                                              stage=f'interrupted:{state}', result='cancelled',
                                              created_at=workspace.clock.now_utc()))
        workspace.journal_put(op, state, {**body, 'interrupted': True})
        marked.append(op)
    return tuple(marked)


def repair(workspace: WorkspaceStore, project: ProjectPort, *, context_for: ContextFor | None = None,
           only: Callable[[dict], bool] | None = None) -> OperationResult[tuple[ProjectLink, ...]]:
    """Finish every unfinished attach and, when ``context_for`` can rebuild a context, every pending one.

    ``context_for(op_id, journal_body)`` returns ``(key, body)`` rows for ``kb-context``; without it a repaired
    attach stays ``context-pending`` (honest, and still a valid project). ``only(journal_body)`` limits the repair
    to the operations the caller names (the CLI passes one project and investigation)."""
    attachment = ProjectAttachment(workspace, project)
    mark_interrupted(workspace)
    links: list[ProjectLink] = []
    issues: list[KbcIssue] = []
    warnings: list[str] = []
    for op in (*open_operations(workspace), *pending_context(workspace)):
        body = workspace.journal_get(op)[1]  # type: ignore[index]
        if only is not None and not only(body):
            continue
        context = context_for(op, body) if context_for else ()
        result = attachment.resume(op, context)
        if result.value is not None:
            links.append(result.value)
        issues.extend(result.issues)
        warnings.extend(result.warnings)
    if not issues and all(link.state == 'attached' for link in links):
        return OperationResult(status='ok', value=tuple(links))
    return OperationResult(status='partial' if links else 'error', value=tuple(links) or None,
                           issues=tuple(issues), warnings=tuple(dict.fromkeys(warnings)))



def preview(workspace: WorkspaceStore, project: ProjectPort, *, context_for: ContextFor | None = None,
            only: Callable[[dict], bool] | None = None) -> tuple[PlannedRepair, ...]:
    """What ``repair`` with the same arguments would change, per operation; reads the journal, the project rows and
    the sidecar files only. ``context_for`` must return the bytes the repair will write (callers build them once)."""
    attachment = ProjectAttachment(workspace, project)
    planned = []
    for op in (*open_operations(workspace), *pending_context(workspace)):
        state, body = workspace.journal_get(op)  # type: ignore[misc]
        if only is not None and not only(body):
            continue
        context = context_for(op, body) if context_for else ()
        if state == 'done' and not context:  # stays context-pending: nothing to write
            planned.append(PlannedRepair(op, state, body['project_id'], ()))
            continue
        planned.append(PlannedRepair(op, state, body['project_id'],
                                     _changes(attachment, project, state, body, context)))
    return tuple(planned)


def _changes(attachment: ProjectAttachment, project: ProjectPort, state: str, body: dict,
             context: tuple[tuple[str, bytes], ...]) -> tuple[Change, ...]:
    # Until the project-created step commits, the sidecar and the row are named after the next revision and
    # nothing of this operation is in the project yet.
    committed = state == 'done' or body['cas_created']
    rev = body['revision']
    revision = rev['revision'] if committed else rev['revision'] + 1
    changes = [Change('project', 'create')] if state == 'intent' else []
    sidecars = attachment.sidecar_plan(body, investigation=committed)
    if not committed:
        sidecars += ((f'kb/investigations/{rev["investigation_id"]}-{revision}.json', 'add'),)
    changes += [Change('sidecar', action, name) for name, action in sidecars]
    rows = [('kb-investigation', f'{rev["investigation_id"]}:{revision}', json.dumps(rev).encode()),
            *(('kb-context', key, data) for key, data in context)]
    for kind, key, data in rows:
        action = _row_action(project, body['project_id'], kind, key, data) if committed else 'add'
        changes.append(Change('row', action, f'{kind}:{key}'))
    return tuple(changes)


def _row_action(project: ProjectPort, project_id: str, kind: str, key: str, data: bytes) -> str:
    stored = project.get_row(project_id, kind, key)
    if stored is None:
        return 'add'
    return 'keep' if json.loads(stored) == json.loads(data) else 'replace'
