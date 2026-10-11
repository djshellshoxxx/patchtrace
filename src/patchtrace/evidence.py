"""Deterministic, bounded context and evidence navigation."""
from __future__ import annotations

import hashlib
import json
import math

from .models import AnalysisContext, ComparisonProject, EvidenceReference, FunctionRecord


class EvidenceError(ValueError):
    pass


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def evidence_id(ref: EvidenceReference, artifact_hash: str) -> str:
    content = ref.model_dump(exclude={'id'}) | {'artifact_sha256': artifact_hash}
    return 'ev-' + hashlib.sha256(_json(content).encode()).hexdigest()


def _related(functions: dict[str, FunctionRecord], source: FunctionRecord,
             reference: str) -> FunctionRecord | None:
    """Resolve owned IDs or exact unique upstream names; never guess counted aliases."""
    exact = functions.get(reference)
    if exact is not None:
        return exact if (exact.run_id == source.run_id and exact.artifact_id == source.artifact_id) else None
    candidates = [f for f in functions.values()
                  if f.run_id == source.run_id and f.artifact_id == source.artifact_id
                  and reference in (f.name, f.metadata.get('upstream_name'), f.metadata.get('fullname'))]
    return candidates[0] if len(candidates) == 1 else None


def build_context(project: ComparisonProject, match_ids: list[str], max_chars: int = 24000) -> AnalysisContext:
    if max_chars < 512:
        raise EvidenceError('PT-SCHEMA: context budget must be at least 512 characters')
    selected_ids = sorted(set(match_ids))
    matches = {m.id: m for m in project.matches}
    if not selected_ids or any(i not in matches for i in selected_ids):
        raise EvidenceError('PT-SCHEMA: select existing match IDs')
    artifacts = {a.id: a for a in project.artifacts}
    functions = {f.id: f for m in project.matches for f in m.older + m.newer}
    selected = [matches[i] for i in selected_ids]
    candidates: list[FunctionRecord] = []
    seen: set[str] = set()
    omissions: list[str] = []

    def add(f: FunctionRecord) -> None:
        if f.id not in seen:
            candidates.append(f)
            seen.add(f.id)

    for match in sorted(selected, key=lambda m: (m.category == 'unchanged', m.id)):
        for f in sorted(match.older + match.newer, key=lambda f: (artifacts[f.artifact_id].side, f.id)):
            add(f)
    for f in list(candidates):
        for label, refs in [('caller', f.callers), ('callee', f.callees)]:
            if not refs:
                omissions.append(f'{f.id}: {label} context unavailable (no references supplied)')
            for ref in sorted(refs):
                target = _related(functions, f, ref)
                if target is None:
                    omissions.append(f'{f.id}: {label} {ref[:120]} context unavailable')
                else:
                    add(target)

    scopes: dict[str, list[str]] = {}
    for match in selected:
        owned = {f.id for f in match.older + match.newer}
        for f in match.older + match.newer:
            for ref in f.callers + f.callees:
                target = _related(functions, f, ref)
                if target:
                    owned.add(target.id)
        scopes[match.id] = sorted(owned)
    base = {
        'schema_version': 1, 'project_id': project.id, 'revision': project.revision,
        'artifacts': [{'id': a.id, 'side': a.side, 'sha256': a.sha256}
                      for a in sorted(project.artifacts, key=lambda a: a.side)],
        'matches': [{'id': m.id, 'run_id': m.run_id, 'category': m.category,
                     'function_ids': sorted(f.id for f in m.older + m.newer),
                     'context_function_ids': scopes[m.id]} for m in selected],
        'evidence': [], 'omitted': [],
    }
    # Keep metadata honest; an oversized selection needs narrowing in the UI.
    if len(_json(base)) + 128 > max_chars:
        raise EvidenceError('PT-SCHEMA: selection metadata exceeds context budget; select fewer matches')
    evidence: list[EvidenceReference] = []
    # Summarize excessive omission detail while retaining the full list in the context record.
    def payload_with(entries: list[EvidenceReference], omitted: list[str]) -> str:
        data = base | {'evidence': [e.model_dump() for e in entries], 'omitted': omitted}
        return _json(data)

    omission_budget = min(max_chars // 4, 4000)
    shown: list[str] = []
    for item in omissions:
        if len(_json(shown + [item])) < omission_budget:
            shown.append(item)
    if len(shown) < len(omissions):
        shown.append(f'{len(omissions) - len(shown)} additional unavailable context references')
    # Reserve compact omission messages for candidates whose code cannot fit.
    reserve = min(len(candidates) * 100, max_chars // 4)
    for f in candidates:
        lines = (f.code or '').splitlines()
        if not lines:
            omissions.append(f'{f.id}: decompiled code unavailable')
            continue
        def make(count: int, f=f, lines=lines) -> EvidenceReference:
            ref = EvidenceReference(artifact_id=f.artifact_id, run_id=f.run_id, function_id=f.id,
                                    side=artifacts[f.artifact_id].side, start_line=1,
                                    end_line=count, text='\n'.join(lines[:count]))
            ref.id = evidence_id(ref, artifacts[f.artifact_id].sha256)
            return ref
        lo, hi = 0, len(lines)
        while lo < hi:
            middle = (lo + hi + 1) // 2
            if len(payload_with(evidence + [make(middle)], shown)) + reserve <= max_chars:
                lo = middle
            else:
                hi = middle - 1
        if lo:
            evidence.append(make(lo))
        if lo < len(lines):
            omissions.append(f'{f.id}: omitted lines {lo + 1}-{len(lines)} (context budget)')
    # Every code omission is represented; long lists use an explicit counted summary.
    shown = []
    for item in omissions:
        if len(payload_with(evidence, shown + [item])) + 100 < max_chars:
            shown.append(item)
    if len(shown) < len(omissions):
        shown.append(f'{len(omissions) - len(shown)} additional omissions; see context omission metadata')
    payload = payload_with(evidence, shown)
    if len(payload) > max_chars:
        raise EvidenceError('PT-SCHEMA: context budget too small for selection and omissions')
    digest = context_digest(payload, omissions)
    return AnalysisContext(id='ctx-' + digest, project_id=project.id, revision=project.revision,
                           match_ids=selected_ids, evidence=evidence, omitted=omissions, digest=digest,
                           token_estimate=math.ceil(len(payload.encode()) / 3), payload=payload)


def context_digest(payload: str, omitted: list[str]) -> str:
    return hashlib.sha256(_json({'payload': payload, 'omitted': omitted}).encode()).hexdigest()


def resolve_evidence(project: ComparisonProject, evidence_id_value: str) -> EvidenceReference:
    artifacts = {a.id: a for a in project.artifacts}
    functions = {f.id: f for m in project.matches for f in m.older + m.newer}
    stale = False
    for run in project.interpretations:
        context = run.context
        for ref in context.evidence:
            if ref.id != evidence_id_value:
                continue
            if context.stale or context.revision != project.revision or context.project_id != project.id:
                stale = True
                continue
            # Import lazily to keep context construction independent from providers.
            from .interpretation import validate_context
            try:
                validate_context(context)
            except ValueError:
                raise EvidenceError('PT-SCHEMA: evidence context is invalid') from None
            f = functions.get(ref.function_id)
            a = artifacts.get(ref.artifact_id)
            selected = [m for m in project.matches if m.id in context.match_ids]
            owned = {candidate.id for m in selected for candidate in m.older + m.newer}
            for m in selected:
                for candidate in m.older + m.newer:
                    for linked_id in candidate.callers + candidate.callees:
                        linked = _related(functions, candidate, linked_id)
                        if linked:
                            owned.add(linked.id)
            if (not f or not a or f.artifact_id != ref.artifact_id or f.run_id != ref.run_id
                    or a.side != ref.side or ref.run_id not in {m.run_id for m in selected}
                    or set(context.match_ids) != {m.id for m in selected} or ref.function_id not in owned
                    or context_digest(context.payload, context.omitted) != context.digest
                    or context.id != 'ctx-' + context.digest
                    or ref.end_line > len((f.code or '').splitlines())
                    or '\n'.join((f.code or '').splitlines()[ref.start_line - 1:ref.end_line]) != ref.text
                    or evidence_id(ref, a.sha256) != ref.id):
                raise EvidenceError('PT-SCHEMA: evidence ownership or code range is invalid')
            return ref.model_copy(deep=True)
    if stale:
        raise EvidenceError('PT-SCHEMA: evidence is stale; rebuild context after reanalysis')
    raise EvidenceError('PT-SCHEMA: unknown evidence ID')
