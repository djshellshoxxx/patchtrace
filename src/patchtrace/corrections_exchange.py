"""`corrections-exchange/1`: manual corrections and review state as a document (docs/specs/manual-corrections-exchange.md).

No CLI and no Qt. A project's effective corrections are its relations with `manual: true`; the document names their
functions by side and address, so it applies to any project of the same two files. Every change is made by
`ProjectService` methods: an import runs them against an in-memory candidate (a second service whose store validates
as `ProjectStore.save` does and writes nothing) and the caller commits the candidate once, so a document is applied
completely or not at all.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .models import ComparisonProject, Finding, FunctionMatch, FunctionRecord, InterpretationRun
from .persistence import strict_json, validate_project

CONTRACT = 'corrections-exchange/1'
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_IMPORT_WORK_BYTES = 64 * 1024 * 1024
MAX_CORRECTIONS = 2000
MAX_MEMBERS = 256
MAX_NOTE = 32767   # the longest reason the desktop's one-line field accepts
MAX_NAME = 4096
MAX_REVIEWED_MATCHES = 100_000
MAX_REVIEWED_FINDINGS = 10_000
MAX_WARNINGS = 20
SIDES = ('older', 'newer')
_SHA256 = r'^[0-9a-f]{64}$'
# The vocabularies are the models' own, so a new category or review state needs no edit here.
_Category = FunctionMatch.model_fields['category'].annotation
_MatchReview = FunctionMatch.model_fields['review'].annotation
_FindingReview = Finding.model_fields['review'].annotation


class ExchangeError(Exception):
    """A refusal with its `PT-CORR-*` code; nothing was written."""

    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code


class Cancelled(Exception):
    """The caller's cancel signal was seen between two corrections; nothing was written."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Member(_Strict):
    address: str | None = Field(default=None, max_length=64)
    name: str = Field(max_length=MAX_NAME)
    id: str | None = Field(default=None, max_length=128)


class _Relation(_Strict):
    older: list[Member] = Field(max_length=MAX_MEMBERS)
    newer: list[Member] = Field(max_length=MAX_MEMBERS)

    @model_validator(mode='after')
    def names_a_function(self):
        if not self.older and not self.newer:
            raise ValueError('at least one function must be named')
        return self


class Correction(_Relation):
    category: _Category
    note: str = Field(min_length=1, max_length=MAX_NOTE)

    @model_validator(mode='after')
    def has_a_reason(self):
        if not self.note.strip():
            raise ValueError('the note must not be blank')
        return self


class ReviewedMatch(_Relation):
    status: _MatchReview


class ReviewedFinding(_Strict):
    id: str = Field(min_length=1, max_length=128)
    digest: str = Field(pattern=_SHA256)
    summary: str = Field(max_length=MAX_NAME)
    status: _FindingReview
    conclusion: str = Field(max_length=MAX_NOTE)


class Review(_Strict):
    matches: list[ReviewedMatch] = Field(max_length=MAX_REVIEWED_MATCHES)
    findings: list[ReviewedFinding] = Field(max_length=MAX_REVIEWED_FINDINGS)


class Pair(_Strict):
    older_sha256: str = Field(pattern=_SHA256)
    newer_sha256: str = Field(pattern=_SHA256)


class CorrectionsExchange(_Strict):
    contract: Literal['corrections-exchange/1']
    pair: Pair
    corrections: list[Correction] = Field(max_length=MAX_CORRECTIONS)
    review: Review | None = None


# --- export ----------------------------------------------------------------------------------------------------------

def _first_error(exc: ValidationError) -> str:
    error = exc.errors(include_url=False, include_input=False)[0]
    where = '.'.join(str(part) for part in error['loc'])
    return f'{where}: {error["msg"]}'[:300] if where else error['msg'][:300]


def service_text(exc: ValueError) -> str:
    """One line for a refusal raised by the service or the store (a pydantic error prints a page otherwise)."""
    return _first_error(exc) if isinstance(exc, ValidationError) else str(exc)


def pair_of(project: ComparisonProject) -> Pair:
    sha = {artifact.side: artifact.sha256 for artifact in project.artifacts}
    return Pair(older_sha256=sha['older'], newer_sha256=sha['newer'])


def member_of(function: FunctionRecord) -> Member:
    return Member(address=function.address, name=function.name[:MAX_NAME], id=function.id)


def finding_digest(run: InterpretationRun, finding: Finding) -> str:
    """Bind a stored claim to its complete evidence and provider context, excluding review state."""
    payload = [run.provider, run.model, run.prompt_version, run.context.model_dump(mode='json'),
               finding.model_dump(mode='json', exclude={'review', 'analyst_conclusion', 'stale'})]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()



def _review_of(project: ComparisonProject) -> Review:
    matches = [ReviewedMatch(older=[member_of(f) for f in match.older], newer=[member_of(f) for f in match.newer],
                             status=match.review)
               for match in project.matches if match.review != 'unreviewed']
    findings = [ReviewedFinding(id=finding.id, digest=finding_digest(run, finding), summary=finding.summary[:MAX_NAME],
                                status=finding.review, conclusion=finding.analyst_conclusion)
                for run in project.interpretations for finding in run.findings
                if finding.review != 'unreviewed' or finding.analyst_conclusion]
    return Review(matches=matches, findings=findings)


def build_document(project: ComparisonProject, *, include_review: bool = False) -> CorrectionsExchange:
    _project_bytes(project)  # bound the source before constructing review/correction arrays
    try:
        corrections = [Correction(category=match.category, note=match.reason,
                                  older=[member_of(f) for f in match.older], newer=[member_of(f) for f in match.newer])
                       for match in project.matches if match.manual]
        return CorrectionsExchange(contract=CONTRACT, pair=pair_of(project), corrections=corrections,
                                   review=_review_of(project) if include_review else None)
    except ValidationError as exc:
        raise ExchangeError('PT-CORR-LIMIT', 'the project state does not fit the contract bounds '
                            f'({_first_error(exc)})') from None


def render(document: CorrectionsExchange) -> bytes:
    """The bytes of a document: ASCII (a hidden character in a note is a visible escape), sorted keys, one newline."""
    data = document.model_dump(mode='json', exclude_none=True)
    raw = bytearray()
    for chunk in json.JSONEncoder(indent=2, sort_keys=True).iterencode(data):
        encoded = chunk.encode('ascii')
        if len(raw) + len(encoded) + 1 > MAX_DOCUMENT_BYTES:
            raise ExchangeError('PT-CORR-LIMIT', 'the rendered document exceeds 16 MiB')
        raw.extend(encoded)
    raw.extend(b'\n')
    return bytes(raw)


def unresolvable(document: CorrectionsExchange) -> int:
    """Corrections no import will accept because a member has no usable address."""
    from .unified.addressing import parse_va_text
    return sum(any(parse_va_text(member.address) is None for member in item.older + item.newer)
               for item in document.corrections)


# --- import ----------------------------------------------------------------------------------------------------------

def read_document(path: Path) -> CorrectionsExchange:
    path = Path(path)
    try:
        if not path.is_file():
            raise ExchangeError('PT-CORR-JSON', 'the document is not a regular file')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ExchangeError('PT-CORR-JSON', 'the document is not a regular file')
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise ExchangeError('PT-CORR-JSON', f'the document cannot be read ({exc.strerror or type(exc).__name__})') from None
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ExchangeError('PT-CORR-JSON', f'the document is larger than {MAX_DOCUMENT_BYTES} bytes')
    try:
        value = strict_json(raw.decode('utf-8'))
    except UnicodeDecodeError:
        raise ExchangeError('PT-CORR-JSON', 'the document is not UTF-8') from None
    except ValueError as exc:  # json.JSONDecodeError included: syntax errors and data after the document
        raise ExchangeError('PT-CORR-JSON', f'the document is not strict JSON ({exc})') from None
    try:
        return CorrectionsExchange.model_validate(value)
    except ValidationError as exc:
        raise ExchangeError('PT-CORR-CONTRACT', f'the document is not a {CONTRACT} document ({_first_error(exc)})') from None


@dataclass(frozen=True)
class Counts:
    total: int
    new: int

    def as_dict(self) -> dict[str, int]:
        return {'total': self.total, 'new': self.new, 'already_present': self.total - self.new}


@dataclass
class ImportPlan:
    """What a document changes in one project, already applied to `candidate` and not yet stored."""
    candidate: ComparisonProject
    revision_before: int
    source_sha256: str
    corrections: Counts
    matches: Counts | None = None
    findings: Counts | None = None
    changes: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def writes(self) -> bool:
        return any(counts is not None and counts.new for counts in (self.corrections, self.matches, self.findings))


class _CandidateStore:
    """Stands in for `ProjectStore` under a second `ProjectService`: validates as `save` does, writes nothing."""

    def __init__(self):
        self.work_bytes = 0

    def save(self, project: ComparisonProject) -> ComparisonProject:
        size = len(_project_bytes(project))
        self.work_bytes += size
        if size > MAX_DOCUMENT_BYTES or self.work_bytes > MAX_IMPORT_WORK_BYTES:
            raise ExchangeError('PT-CORR-LIMIT', 'candidate growth exceeds the bounded planning work budget')
        return validate_project(project)


def _shown(text: str | None) -> str:
    return repr(text if text is None or len(text) <= 120 else text[:117] + '...')


def _check_pair(project: ComparisonProject, pair: Pair) -> None:
    own = pair_of(project)
    if pair == own:
        return
    if (pair.older_sha256, pair.newer_sha256) == (own.newer_sha256, own.older_sha256):
        raise ExchangeError('PT-CORR-ORIENTATION', 'the document was exported with older and newer the other way '
                            'round (its older file is this project\'s newer file). Nothing was imported: a '
                            'correction is never mirrored silently. Swap the orientation of one of the two projects, '
                            'then export or import again')
    raise ExchangeError('PT-CORR-PAIR', 'the document belongs to another pair of files (older '
                        f'{pair.older_sha256[:16]}, newer {pair.newer_sha256[:16]}; this project: older '
                        f'{own.older_sha256[:16]}, newer {own.newer_sha256[:16]})')


class _Resolver:
    """(side, address) -> the one function of the project that has it; refuses everything else."""

    def __init__(self, project: ComparisonProject):
        from .unified.addressing import parse_va_text  # the parser the unified engine reads corrections with
        self._parse = parse_va_text
        self._found: dict[tuple[str, int], list[FunctionRecord]] = {}
        self.warnings: list[str] = []
        for match in project.matches:
            for side in SIDES:
                for function in getattr(match, side):
                    address = parse_va_text(function.address)
                    if address is not None:
                        self._found.setdefault((side, address), []).append(function)

    def one(self, side: str, member: Member, where: str) -> FunctionRecord:
        address = self._parse(member.address)
        if address is None:
            raise ExchangeError('PT-CORR-MEMBER', f'{where}: the {side} function {_shown(member.name)} has no usable '
                                f'address ({_shown(member.address)}), so it cannot be resolved in this project')
        found = self._found.get((side, address), [])
        if len(found) != 1:
            raise ExchangeError('PT-CORR-MEMBER', f'{where}: this project has {len(found) or "no"} {side} '
                                f'function{"s" if len(found) > 1 else ""} at address {member.address.strip()} '
                                f'({_shown(member.name)} in the document)')
        if found[0].name[:MAX_NAME] != member.name:
            self.warnings.append(f'{where}: the {side} function at {member.address.strip()} is named '
                                 f'{_shown(found[0].name)} in this project and {_shown(member.name)} in the document')
        return found[0]

    def sides(self, relation: _Relation, where: str) -> tuple[list[str], list[str]]:
        return ([self.one('older', member, where).id for member in relation.older],
                [self.one('newer', member, where).id for member in relation.newer])


def _resolve_corrections(resolver: _Resolver, corrections: list[Correction]) -> list[tuple[list[str], list[str]]]:
    resolved, named = [], {}
    for number, correction in enumerate(corrections, 1):
        older, newer = resolver.sides(correction, f'correction {number}')
        for function_id in older + newer:
            if function_id in named:
                first = named[function_id]
                raise ExchangeError('PT-CORR-DUPLICATE', f'correction {number} names a function that '
                                    f'{"it already names" if first == number else f"correction {first} already names"}; '
                                    'one function belongs to one relation')
            named[function_id] = number
        resolved.append((older, newer))
    return resolved


def _apply_corrections(scratch, document: CorrectionsExchange, resolved, cancelled: Callable[[], bool]) -> list[dict]:
    changes, owner = [], None
    for number, (correction, (older, newer)) in enumerate(zip(document.corrections, resolved, strict=True), 1):
        if cancelled():
            raise Cancelled
        if owner is None:  # function id -> the relation that holds it now; rebuilt after every applied correction
            owner = {f.id: match for match in scratch.project.matches for f in match.older + match.newer}
        holders = {owner[function_id].id: owner[function_id] for function_id in older + newer}
        present = any(match.manual and match.category == correction.category and match.reason == correction.note
                      and {f.id for f in match.older} == set(older) and {f.id for f in match.newer} == set(newer)
                      for match in holders.values())
        names = {side: [_name(owner[function_id], function_id) for function_id in ids]
                 for side, ids in (('older', older), ('newer', newer))}
        changes.append({'index': number, 'action': 'already-present' if present else 'apply',
                        'category': correction.category, **names})
        if present:
            continue
        if any(match.manual for match in holders.values()):
            raise ExchangeError('PT-CORR-CONFLICT', f'correction {number} names a function that is part of a '
                                'different manual correction of this project. An import never overwrites an '
                                'existing correction: undo or re-correct it first')
        try:
            scratch.correct_match(owner[(older + newer)[0]].id, older, newer, correction.category, correction.note)
        except ValueError as exc:
            raise ExchangeError('PT-CORR-INVALID', f'correction {number}: {service_text(exc)}') from None
        owner = None
    return changes


def _name(match: FunctionMatch, function_id: str) -> str:
    return next(f.name for f in match.older + match.newer if f.id == function_id)[:MAX_NAME]


def _apply_match_reviews(scratch, entries: list[ReviewedMatch], resolved, cancelled) -> Counts:
    relations = {(frozenset(f.id for f in match.older), frozenset(f.id for f in match.newer)): match
                 for match in scratch.project.matches}
    state = {match.id: match.review for match in scratch.project.matches}
    new = 0
    seen = set()
    for number, (entry, (older, newer)) in enumerate(zip(entries, resolved, strict=True), 1):
        if cancelled():
            raise Cancelled
        identity = (frozenset(older), frozenset(newer))
        if identity in seen or len(set(older + newer)) != len(older + newer):
            raise ExchangeError('PT-CORR-DUPLICATE', 'a relation review target is repeated')
        seen.add(identity)
        match = relations.get(identity)
        if match is None:
            raise ExchangeError('PT-CORR-REVIEW', f'review of relation {number}: this project has no relation with '
                                'exactly these functions')
        if state[match.id] != entry.status:
            scratch.review_match(match.id, entry.status)
            state[match.id] = entry.status
            new += 1
    return Counts(len(entries), new)


def _apply_finding_reviews(scratch, entries: list[ReviewedFinding], cancelled) -> Counts:
    by_digest: dict[str, list[Finding]] = {}
    for run in scratch.project.interpretations:
        for finding in run.findings:
            by_digest.setdefault(finding_digest(run, finding), []).append(finding)
    state = {finding.id: (finding.review, finding.analyst_conclusion)
             for found in by_digest.values() for finding in found}
    new = 0
    seen = set()
    for number, entry in enumerate(entries, 1):
        if cancelled():
            raise Cancelled
        if entry.id in seen:
            raise ExchangeError('PT-CORR-DUPLICATE', 'a finding review target is repeated')
        seen.add(entry.id)
        found = [finding for finding in by_digest.get(entry.digest, []) if finding.id == entry.id]
        if len(found) != 1:
            raise ExchangeError('PT-CORR-REVIEW', f'review of finding {number}: this project has no single finding '
                                f'with the digest {entry.digest[:16]} ({_shown(entry.summary)} in the document)')
        if state[found[0].id] != (entry.status, entry.conclusion):
            scratch.review_finding(found[0].id, entry.status, entry.conclusion)
            state[found[0].id] = (entry.status, entry.conclusion)
            new += 1
    return Counts(len(entries), new)


def plan_import(service, document: CorrectionsExchange, cancelled: Callable[[], bool] = lambda: False) -> ImportPlan:
    """Check the whole document against `service.project` and apply it to a candidate. Raises `ExchangeError` on
    the first broken rule and `Cancelled`; never touches the project's store."""
    from .service import ProjectService
    project = service.project
    if cancelled():
        raise Cancelled
    source = _project_bytes(project)
    count = len(document.corrections)
    if document.review:
        count += len(document.review.matches) + len(document.review.findings)
    if len(source) > MAX_DOCUMENT_BYTES or len(source) * max(1, count) > MAX_IMPORT_WORK_BYTES:
        raise ExchangeError('PT-CORR-LIMIT', 'the project/import exceeds the bounded planning work budget')
    _check_pair(project, document.pair)
    resolver = _Resolver(project)
    resolved = _resolve_corrections(resolver, document.corrections)
    review = document.review
    reviewed = [resolver.sides(entry, f'review of relation {number}')
                for number, entry in enumerate(review.matches, 1)] if review is not None else []
    if cancelled():
        raise Cancelled
    scratch = ProjectService(service.root, project.model_copy(deep=True), _CandidateStore())
    changes = _apply_corrections(scratch, document, resolved, cancelled)
    warnings = resolver.warnings[:MAX_WARNINGS]
    if len(resolver.warnings) > MAX_WARNINGS:
        warnings.append(f'{len(resolver.warnings) - MAX_WARNINGS} more functions are named differently in this project')
    plan = ImportPlan(candidate=project, revision_before=project.revision, source_sha256=hashlib.sha256(source).hexdigest(), changes=changes, warnings=warnings,
                      corrections=Counts(len(changes), sum(change['action'] == 'apply' for change in changes)))
    if review is not None:
        plan.matches = _apply_match_reviews(scratch, review.matches, reviewed, cancelled)
        plan.findings = _apply_finding_reviews(scratch, review.findings, cancelled)
    plan.candidate = scratch.project
    return plan


def _project_bytes(project: ComparisonProject) -> bytes:
    raw = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'))
    for chunk in encoder.iterencode(project.model_dump(mode='json')):
        encoded = chunk.encode('ascii')
        if len(raw) + len(encoded) > MAX_DOCUMENT_BYTES:
            raise ExchangeError('PT-CORR-LIMIT', 'the project snapshot exceeds 16 MiB')
        raw.extend(encoded)
    return bytes(raw)


def commit(service, plan: ImportPlan, cancelled: Callable[[], bool] = lambda: False) -> bool:
    """Store the plan's candidate with one `ProjectService.save()` (one transaction). False when nothing is new."""
    if cancelled():
        raise Cancelled
    if hashlib.sha256(_project_bytes(service.project)).hexdigest() != plan.source_sha256:
        raise ExchangeError('PT-CORR-STALE', 'the project changed after this import was planned')
    if not plan.writes:
        return False
    prior = service.project
    service.project = plan.candidate
    try:
        service.save()
    except BaseException:
        try:
            service.project = service.store.load(recover_interrupted=False)
        except Exception:
            service.project = prior  # disk outcome is uncertain; do not report rollback or delete evidence
        raise
    return True


def list_corrections(project: ComparisonProject) -> list[dict]:
    """The manual relations in stored order; `annotation_id` is set where the service can still restore one."""
    active = {annotation.target_id: annotation.id for annotation in project.annotations
              if annotation.kind == 'match-override' and not annotation.stale}
    rows = []
    for match in project.matches:
        if match.manual:
            rows.append({'index': len(rows) + 1, 'match_id': match.id, 'category': match.category,
                         'review': match.review, 'note': match.reason,
                         'older': [member_of(f).model_dump(mode='json') for f in match.older],
                         'newer': [member_of(f).model_dump(mode='json') for f in match.newer],
                         'annotation_id': active.get(match.id), 'undoable': match.id in active})
    return rows
