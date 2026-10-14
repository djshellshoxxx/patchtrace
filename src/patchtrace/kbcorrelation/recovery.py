"""Restart recovery for interrupted attaches (KB-integration-plan 7.3 and 7.5; slice K2).

A restart marks unfinished operations interrupted and may finish them from the journal; it never fetches, never runs
an engine, never deletes a project or a user file. Everything here is idempotent: running ``repair`` twice changes
nothing the second time.
"""
from __future__ import annotations

from collections.abc import Callable

from .contracts import Attempt, ProjectLink
from .errors import KbcIssue, OperationResult
from .ports import ProjectPort
from .store import ProjectAttachment, WorkspaceStore

ContextFor = Callable[[str, dict], tuple[tuple[str, bytes], ...]]


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


def repair(workspace: WorkspaceStore, project: ProjectPort, *,
           context_for: ContextFor | None = None) -> OperationResult[tuple[ProjectLink, ...]]:
    """Finish every unfinished attach and, when ``context_for`` can rebuild a context, every pending one.

    ``context_for(op_id, journal_body)`` returns ``(key, body)`` rows for ``kb-context``; without it a repaired
    attach stays ``context-pending`` (honest, and still a valid project)."""
    attachment = ProjectAttachment(workspace, project)
    mark_interrupted(workspace)
    links: list[ProjectLink] = []
    issues: list[KbcIssue] = []
    warnings: list[str] = []
    for op in (*open_operations(workspace), *pending_context(workspace)):
        body = workspace.journal_get(op)[1]  # type: ignore[index]
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

