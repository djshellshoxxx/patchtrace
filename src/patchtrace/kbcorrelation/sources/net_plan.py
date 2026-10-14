"""Request preview for a monthly CVRF index sync (KB-integration-plan 8.1 `kb index plan`, 6 "consent drift"). PURE.

``build_plan`` lists the exact requests a later consented sync (slice K6) would make, the hosts, the caps and a
``plan_sha`` over all of it. It performs no I/O: no socket, no DNS, no file, no clock (the caller passes the current
month). Consent binds to the digest: a changed URL, host, cap or month changes ``plan_sha`` and so needs new consent.

The URL shape is the one RK1 derived from the published swagger and PowerShell module
(``https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<yyyy-Mmm>?api-version=2023-11-01``). It is UNVERIFIED until live
probe L1, so every plan says so. For a machine without the consent flow, the preview is also the exact list of URLs
and the ``Accept`` header to use by hand, followed by ``kb index import`` (plan open question 15).
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field, model_validator

from ..contracts import Contract, PlanRequest, Reason, Record, ReleaseId, Sha256, Short, domain_id, https_host
from ..limits import DEFAULT_LIMITS, KbcLimits
from .cvrf import DIALECTS, PARSER_VERSION, SourceError
from .scope import month_range, normal_release, release_ordinal

API_HOST = 'api.msrc.microsoft.com'
API_VERSION = '2023-11-01'
CVRF_BASE = f'https://{API_HOST}/cvrf/v3.0'
ACCEPT = 'application/json'
NOTES = (
    'The URL shape is derived from the published swagger and PowerShell module and is unverified until live probe L1.',
    'This preview performs no request. To fetch by hand, save each URL with the Accept header shown, then run '
    '"kb index import" on the files.',
)


class PlanCaps(Record):
    max_bytes_per_document: Annotated[int, Field(gt=0)]
    request_timeout_s: Annotated[int, Field(gt=0)]
    plan_timeout_s: Annotated[int, Field(gt=0)]
    attempts: Annotated[int, Field(gt=0)]
    retry_after_max_s: Annotated[int, Field(gt=0)]
    concurrency: Annotated[int, Field(gt=0)]
    max_redirects: Annotated[int, Field(ge=0)]
    redirect_policy: Short


class IndexPlan(Contract):
    """What a consented sync would request. ``plan_sha`` covers every other field (this record is its own preview)."""
    plan_sha: Sha256
    kind: Literal['cvrf-months'] = 'cvrf-months'
    months: tuple[ReleaseId, ...]
    requests: tuple[PlanRequest, ...] = Field(min_length=1)
    hosts: tuple[Short, ...]
    accept: Short
    caps: PlanCaps
    dialects: tuple[Short, ...]
    parser_version: Annotated[int, Field(ge=1)]
    notes: tuple[Reason, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if tuple(sorted({https_host(r.url) for r in self.requests})) != self.hosts:
            raise ValueError('hosts must equal the hosts of the planned requests')
        if self.plan_sha != digest_of(self):
            raise ValueError('plan_sha does not match the plan content')
        return self


def digest_of(plan: IndexPlan) -> str:
    return domain_id('kbc.indexplan', 1, plan.model_dump(mode='json', exclude={'plan_sha'}))


def _scope_error(message: str) -> SourceError:
    return SourceError('PT-KBC-SCOPE', message)


def months_since(since: str, until: str) -> tuple[str, ...]:
    """Inclusive months from ``since`` to ``until`` (both ``yyyy-MM`` or ``yyyy-Mmm``)."""
    return month_range(since, until)


def build_plan(months: Iterable[str], *, now_release: str | None = None, include_index: bool = False,
               limits: KbcLimits = DEFAULT_LIMITS) -> IndexPlan:
    """The request preview for ``months``. ``now_release`` (the current month) enables the future and age checks."""
    ids = tuple(sorted({normal_release(m) for m in months}, key=release_ordinal))
    if not ids:
        raise _scope_error('no month given')
    if len(ids) > limits.docs_per_plan:
        raise _scope_error(f'at most {limits.docs_per_plan} documents per plan; run several plans')
    if now_release is not None:
        now = release_ordinal(now_release)
        if release_ordinal(ids[-1]) > now:
            raise _scope_error('a requested month is in the future')
        if now - release_ordinal(ids[0]) >= limits.index_months:
            raise _scope_error(f'the index reaches back {limits.index_months} months; the oldest month is older')
    requests = []
    if include_index:
        requests.append(PlanRequest(method='GET', url=f'{CVRF_BASE}/Updates?api-version={API_VERSION}',
                                    why='list of monthly document ids (discovery only; it carries no KB data)'))
    for month in ids:
        requests.append(PlanRequest(method='GET', url=f'{CVRF_BASE}/cvrf/{month}?api-version={API_VERSION}',
                                    why=f'monthly CVRF document {month} (read-only, cap '
                                        f'{limits.cvrf_doc_bytes} bytes)'))
    caps = PlanCaps(max_bytes_per_document=limits.cvrf_doc_bytes, request_timeout_s=limits.request_timeout_s,
                    plan_timeout_s=limits.plan_timeout_s, attempts=limits.attempts,
                    retry_after_max_s=limits.retry_after_max_s, concurrency=limits.fetch_concurrency,
                    max_redirects=3, redirect_policy='https and same host only; anything else is refused')
    body = {'contract': 'kbcorrelation/1', 'kind': 'cvrf-months', 'months': ids,
            'requests': tuple(requests), 'hosts': tuple(sorted({https_host(r.url) for r in requests})),
            'accept': ACCEPT, 'caps': caps, 'dialects': DIALECTS, 'parser_version': PARSER_VERSION, 'notes': NOTES}
    draft = IndexPlan.model_construct(plan_sha='0' * 64, **body)
    return IndexPlan(plan_sha=digest_of(draft), **body)


def verify_consent(plan: IndexPlan, *, consent_hosts: Iterable[str], consent_plan: str) -> None:
    """Raise PT-KBC-CONSENT unless the hosts equal the planned set and ``consent_plan`` equals the plan digest."""
    if plan.plan_sha != digest_of(plan):
        raise SourceError('PT-KBC-CONSENT', 'the plan was altered after its digest was computed')
    given = {h.strip().lower() for h in consent_hosts if h.strip()}
    if given != set(plan.hosts):
        raise SourceError('PT-KBC-CONSENT', f'consent hosts must name exactly: {",".join(plan.hosts)}')
    if consent_plan != plan.plan_sha:
        raise SourceError('PT-KBC-CONSENT', 'consent was given for a different plan; review the new plan_sha')


def render_plan(plan: IndexPlan) -> str:
    """Plain text of the preview: one request per line, then hosts, headers, caps and the digest."""
    lines = [f'{r.method} {r.url}' for r in plan.requests]
    lines += ['', f'Header: Accept: {plan.accept}', f'Hosts: {", ".join(plan.hosts)}',
              f'Per document cap: {plan.caps.max_bytes_per_document} bytes; timeout {plan.caps.request_timeout_s} s; '
              f'attempts {plan.caps.attempts}; concurrency {plan.caps.concurrency}',
              f'Redirects: {plan.caps.redirect_policy} (at most {plan.caps.max_redirects})',
              f'plan_sha: {plan.plan_sha}', '', *plan.notes]
    return '\n'.join(lines)

