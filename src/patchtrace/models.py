"""PatchTrace-owned v1 contracts; no backend or UI dependencies."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def uid() -> str:
    return str(uuid4())


def now() -> str:
    return datetime.now(UTC).isoformat()


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', validate_assignment=True, strict=True)
    schema_version: Literal[1] = 1
    id: str = Field(default_factory=uid, min_length=1, max_length=128)


class Artifact(Record):
    side: Literal['older', 'newer']
    name: str
    sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    size: int = Field(ge=1, le=1073741824)
    relative_path: str
    architecture: Literal['x86-64'] = 'x86-64'
    format: Literal['PE'] = 'PE'
    @model_validator(mode='after')
    def safe_storage_path(self):
        path = PurePosixPath(self.relative_path.replace('\\', '/'))
        windows = PureWindowsPath(self.relative_path)
        if not self.relative_path or path.is_absolute() or windows.drive or '..' in path.parts:
            raise ValueError('Artifact storage path must remain relative to project')
        return self


class BackendCapabilities(Record):
    name: str = 'ghidriff'
    version: str
    decompiler: bool = True
    instruction_mapping: bool = False
    progress_counts: bool = False
    limitations: list[str] = Field(default_factory=list)


class FunctionRecord(Record):
    artifact_id: str
    run_id: str
    name: str
    address: str | None = None
    address_space: Literal['virtual', 'relative', 'file-offset', 'unknown'] = 'unknown'
    code: str | None = None
    assembly: str | None = None
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class FunctionMatch(Record):
    run_id: str
    older: list[FunctionRecord] = Field(default_factory=list)
    newer: list[FunctionRecord] = Field(default_factory=list)
    category: Literal['modified', 'added', 'removed', 'unmatched', 'ambiguous', 'split', 'merged', 'unchanged']
    match_types: list[str] = Field(default_factory=list)
    quality: str = 'unknown'
    manual: bool = False
    reason: str = ''
    review: Literal['unreviewed', 'accepted', 'rejected', 'needs-review'] = 'unreviewed'
    @model_validator(mode='after')
    def sides(self):
        if not self.older and not self.newer:
            raise ValueError('Match must contain at least one function')
        if self.category == 'added' and (self.older or not self.newer):
            raise ValueError('Added match must have only newer functions')
        if self.category == 'removed' and (self.newer or not self.older):
            raise ValueError('Removed match must have only older functions')
        return self


class DiffHunk(Record):
    match_id: str
    old_start: int = Field(ge=0)
    old_end: int = Field(ge=0)
    new_start: int = Field(ge=0)
    new_end: int = Field(ge=0)
    operation: Literal['equal', 'replace', 'delete', 'insert']


class EvidenceReference(Record):
    artifact_id: str
    run_id: str
    function_id: str
    side: Literal['older', 'newer']
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str
    @model_validator(mode='after')
    def range_valid(self):
        if self.end_line < self.start_line:
            raise ValueError('Invalid evidence range')
        return self


class AnalysisContext(Record):
    project_id: str
    revision: int = Field(ge=0)
    match_ids: list[str]
    evidence: list[EvidenceReference]
    omitted: list[str] = Field(default_factory=list)
    digest: str
    token_estimate: int = Field(ge=0)
    payload: str
    stale: bool = False


class Hypothesis(Record):
    explanation: str
    supporting: list[str] = Field(default_factory=list)
    contradicting: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    verification: list[str] = Field(default_factory=list)
    confidence: Literal['low', 'medium', 'high', 'unknown'] = 'unknown'


class Finding(Record):
    context_id: str
    match_ids: list[str]
    summary: str
    fix_purpose: str
    category: Literal['security-fix', 'ordinary-bug', 'feature', 'refactor', 'compiler-noise', 'unknown']
    hypothesis: Hypothesis
    alternatives: list[Hypothesis] = Field(default_factory=list)
    cwe: str | None = None
    cwe_rationale: str | None = None
    review: Literal['unreviewed', 'accepted', 'rejected', 'needs-review'] = 'unreviewed'
    analyst_conclusion: str = ''
    stale: bool = False


class InterpretationRun(Record):
    context: AnalysisContext
    provider: str
    model: str
    endpoint: str | None = None
    prompt_version: str = 'patchtrace-1'
    created: str = Field(default_factory=now)
    status: Literal['completed', 'failed', 'cancelled']
    findings: list[Finding] = Field(default_factory=list)
    raw_response: str = ''
    error: str | None = None
    duration_seconds: float = Field(default=0, ge=0)


class AnalystAnnotation(Record):
    target_id: str
    kind: Literal['note', 'bookmark', 'match-override', 'validation']
    text: str
    created: str = Field(default_factory=now)
    stale: bool = False


class JobEvent(Record):
    run_id: str
    stage: str
    message: str
    progress: float | None = Field(default=None, ge=0, le=1)
    created: str = Field(default_factory=now)


class AnalysisRun(Record):
    created: str = Field(default_factory=now)
    status: Literal['queued', 'running', 'completed', 'failed', 'cancelled', 'identical']
    backend: str = 'ghidriff'
    backend_version: str = 'unknown'
    settings: dict = Field(default_factory=dict)
    raw_path: str | None = None
    raw_sha256: str | None = None
    error: str | None = None


class ComparisonProject(Record):
    name: str
    created: str = Field(default_factory=now)
    revision: int = Field(default=0, ge=0)
    artifacts: list[Artifact]
    runs: list[AnalysisRun] = Field(default_factory=list)
    matches: list[FunctionMatch] = Field(default_factory=list)
    interpretations: list[InterpretationRun] = Field(default_factory=list)
    annotations: list[AnalystAnnotation] = Field(default_factory=list)
    sample: bool = False
    @model_validator(mode='after')
    def relationships(self):
        if len(self.artifacts) != 2 or {a.side for a in self.artifacts} != {'older', 'newer'}:
            raise ValueError('Exactly one older and one newer artifact required')
        ids = {a.id: a.side for a in self.artifacts}
        if len(ids) != 2:
            raise ValueError('Artifact identities must be unique')
        for records in [self.runs, self.matches, self.interpretations, self.annotations]:
            if len({r.id for r in records}) != len(records):
                raise ValueError('Duplicate record identity')
        runs = {r.id for r in self.runs}
        for match in self.matches:
            if match.run_id not in runs:
                raise ValueError('Match refers to absent analysis run')
            for side, funcs in [('older', match.older), ('newer', match.newer)]:
                for f in funcs:
                    if ids.get(f.artifact_id) != side or f.run_id != match.run_id:
                        raise ValueError('Function ownership mismatch')
        for interpretation in self.interpretations:
            context = interpretation.context
            if context.project_id != self.id or context.revision > self.revision:
                raise ValueError('Context project/revision mismatch')
            evidence_ids = {e.id for e in context.evidence}
            if len(evidence_ids) != len(context.evidence):
                raise ValueError('Duplicate evidence identity')
            for evidence in context.evidence:
                if (evidence.artifact_id not in ids or evidence.run_id not in runs
                        or (not context.stale and ids[evidence.artifact_id] != evidence.side)):
                    raise ValueError('Evidence ownership mismatch')
            for finding in interpretation.findings:
                if finding.context_id != context.id or not set(finding.match_ids) <= set(context.match_ids):
                    raise ValueError('Finding context mismatch')
                for hypothesis in [finding.hypothesis, *finding.alternatives]:
                    if not set(hypothesis.supporting + hypothesis.contradicting) <= evidence_ids:
                        raise ValueError('Finding cites absent evidence')
        return self


class ExportManifest(Record):
    project_id: str
    revision: int
    format: Literal['json', 'html', 'md']
    sha256: str
    finding_ids: list[str]
    include_code: bool
    include_notes: bool
    created: str = Field(default_factory=now)
