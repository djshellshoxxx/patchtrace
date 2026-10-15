"""`kb index sync`: the one consented network verb of the KB correlator (KB-integration-plan 8.1; slice K6). Qt-free.

Own dispatcher (``main(argv)``, arguments after ``kb index sync``) so ``cli_index`` stays offline. Hook for
``kbcorrelation/cli.py`` (applied by the integrator, in ``main`` before the ``index`` branch)::

    from . import cli_online
    if argv[:2] == ['index', 'sync']:
        return cli_online.main(argv[2:], ports=cli_online.OnlinePorts(context.index_ports()), stdout=stdout, stderr=stderr)

Default scan window: the last 12 months ending with the current one; ``--window-months N`` (1-24) extends it,
``--months`` and ``--since`` name an exact scope. Nothing is requested without ``--consent-hosts`` equal to the
planned host set and ``--consent-plan`` equal to the plan digest; without them the verb prints the plan and exits 2.
Each document is stored as it arrives, so a cancel or a failed month leaves the earlier months in the index; the
result always carries the coverage of the whole index and one row per requested month. Exit: 0 every month stored
(or already present), 2 arguments, consent or offline, 3 any month missing or failed (partial), 5 cancelled.
"""
from __future__ import annotations

import argparse
import sys
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any

from .cli_index import (
    ENVIRONMENT,
    OK,
    RUNTIME,
    CliError,
    IndexPorts,
    Parser,
    _emit,
    add_common,
    coverage_block,
    load_index,
    open_existing,
    run_cli,
    workspace_root,
)
from .contracts import CONTRACT
from .index import ReverseIndex
from .limits import DEFAULT_LIMITS, MAX_SEARCH_MONTHS
from .sources import net_plan
from .sources.cvrf import SourceError
from .sources.cvrf_fetch import FetchResult, fetch_months, to_imported
from .sources.scope import MONTHS, release_id_for, release_ordinal
from .store import WorkspaceStore

DEFAULT_WINDOW_MONTHS = 12
ARGUMENT_CODES = ('PT-KBC-INPUT', 'PT-KBC-SCOPE', 'PT-KBC-UNSUPPORTED', 'PT-KBC-CONSENT')
LINEAGE_NOTE = 'revised CVEs may sit in earlier documents; a wider window can find more'


@dataclass(frozen=True)
class OnlinePorts:
    """``fetch`` overrides the transport pieces of ``fetch_months`` (opener, sleep, clock, now, cancel); tests only."""
    index: IndexPorts = field(default_factory=IndexPorts)
    fetch: dict[str, Any] = field(default_factory=dict)


def build_parser(prog: str = 'patchtrace kb index sync') -> argparse.ArgumentParser:
    parser = Parser(prog=prog, description='Fetch monthly CVRF documents from api.msrc.microsoft.com into the index. '
                    'Needs explicit consent for the exact plan; run it once without consent to see the plan.')
    add_common(parser)
    parser.set_defaults(action='sync')
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--months', metavar='YYYY-MM[,..]', help='exact months (at most 24)')
    scope.add_argument('--since', metavar='YYYY-MM', help='every month from here to --until (default: this month)')
    scope.add_argument('--window-months', type=int, metavar='N',
                       help=f'last N months ending this month (default {DEFAULT_WINDOW_MONTHS}, at most '
                            f'{MAX_SEARCH_MONTHS})')
    parser.add_argument('--until', metavar='YYYY-MM', help='last month of --since')
    parser.add_argument('--consent-hosts', metavar='HOST[,..]', help='must equal the planned hosts exactly')
    parser.add_argument('--consent-plan', metavar='SHA256', help='the plan_sha printed for this plan')
    parser.add_argument('--offline', action='store_true', help='refuse to fetch (with any consent flag: exit 2)')
    return parser


def _months(args, now_release: str) -> list[str]:
    if args.months is not None:
        return [m for m in (p.strip() for p in args.months.split(',')) if m]
    if args.since is not None:
        return list(net_plan.months_since(args.since, args.until or now_release))
    count = DEFAULT_WINDOW_MONTHS if args.window_months is None else args.window_months
    if not 1 <= count <= MAX_SEARCH_MONTHS:
        raise CliError(ENVIRONMENT, f'--window-months must be 1 to {MAX_SEARCH_MONTHS}')
    last = release_ordinal(now_release)
    return [release_id_for(n // 12, n % 12 + 1) for n in range(last - count + 1, last + 1)]


def _plan(args, now: str) -> net_plan.IndexPlan:
    now_release = f'{now[:4]}-{MONTHS[int(now[5:7]) - 1]}'
    try:
        return net_plan.build_plan(_months(args, now_release), now_release=now_release)
    except SourceError as exc:
        raise CliError(ENVIRONMENT, exc.message) from None
    except ValueError:
        raise CliError(ENVIRONMENT, 'invalid month list') from None


def _fail(out, args, code: int, message: str, result: dict | None = None, status: str = 'failed') -> int:
    _emit(out, args, status, result, [], message, error=message)
    print(f'error: {message}', file=sys.stderr)
    return code


def _row(result: FetchResult, state: str, sha: str | None = None, error: SourceError | None = None) -> dict:
    row: dict[str, Any] = {'month': result.month, 'state': state, 'sha256': sha}
    if error is not None:
        row.update(code=error.code, message=error.message)
    return row


def _store(result: FetchResult, ws_open) -> dict:
    """Parse and store one fetched month; a damaged document becomes a failed row and leaves the index unchanged."""
    if result.document is None:
        state = 'not-published' if result.state == 'not-published' else 'failed'
        return _row(result, state, error=result.error)
    try:
        doc = to_imported(result.document, DEFAULT_LIMITS)
    except SourceError as exc:
        return _row(result, 'failed', result.document.sha256, exc)
    added = ws_open().add_document(doc, result.document.raw)
    return _row(result, 'added' if added else 'already-present', result.document.sha256)


def _run(plan: net_plan.IndexPlan, args, ports: OnlinePorts, stack: ExitStack) -> tuple[list[dict], bool]:
    workspace = workspace_root(args)
    opened: list[WorkspaceStore] = []

    def ws_open() -> WorkspaceStore:
        if not opened:
            opened.append(stack.enter_context(WorkspaceStore(workspace)))
        return opened[0]

    rows: list[dict] = []
    cancelled = False
    try:
        for result in fetch_months(plan, consent_hosts=(args.consent_hosts or '').split(','),
                                   consent_plan=args.consent_plan or '', offline=args.offline, **ports.fetch):
            rows.append(_store(result, ws_open))
    except SourceError as exc:
        if exc.code != 'PT-KBC-CANCEL':
            raise
        cancelled = True
    return rows, cancelled


def _coverage(args, ports: IndexPorts) -> tuple[dict, list[dict]]:
    ws = open_existing(workspace_root(args))
    try:
        index, unreadable = load_index(ws, ports) if ws else (ReverseIndex(), [])
    finally:
        if ws:
            ws.close()
    return coverage_block(index, ports.now()), unreadable


def _summary(rows: list[dict], requested: tuple[str, ...]) -> str:
    counts = {s: sum(1 for r in rows if r['state'] == s) for s in ('added', 'already-present', 'not-published',
                                                                    'failed')}
    skipped = len(requested) - len(rows)
    text = (f'{len(requested)} month(s) requested ({requested[0]} to {requested[-1]}): {counts["added"]} added, '
            f'{counts["already-present"]} already present, {counts["not-published"]} not published, '
            f'{counts["failed"]} failed' + (f', {skipped} not attempted (cancelled)' if skipped else '') + '.')
    return text


def cmd_sync(args, ports: OnlinePorts, out) -> int:
    plan = _plan(args, ports.index.now())
    consenting = args.consent_hosts is not None or args.consent_plan is not None
    if args.offline:
        raise CliError(ENVIRONMENT, 'offline mode never fetches' + ('; remove the consent flags' if consenting else ''))
    if not consenting:
        text = net_plan.render_plan(plan)
        return _fail(out, args, ENVIRONMENT, 'consent required: nothing was requested; to fetch exactly this plan '
                     f'pass --consent-hosts {",".join(plan.hosts)} --consent-plan {plan.plan_sha}\n{text}',
                     {'contract': CONTRACT, 'plan': plan.model_dump(mode='json'), 'text': text})
    with ExitStack() as stack:
        try:
            rows, cancelled = _run(plan, args, ports, stack)
        except SourceError as exc:
            return _fail(out, args, ENVIRONMENT if exc.code in ARGUMENT_CODES else RUNTIME,
                         f'{exc.code}: {exc.message}')
    coverage, unreadable = _coverage(args, ports.index)
    missing = cancelled or any(r['state'] in ('not-published', 'failed') for r in rows)
    status = 'cancelled' if cancelled else ('partial' if missing else 'complete')
    summary = _summary(rows, plan.months)
    warnings = [LINEAGE_NOTE] + ([f'{len(unreadable)} stored document(s) unreadable'] if unreadable else [])
    result = {'contract': CONTRACT, 'plan_sha': plan.plan_sha, 'requested': list(plan.months), 'months': rows,
              'index_changed': any(r['state'] == 'added' for r in rows), 'coverage': coverage,
              'unreadable': unreadable}
    lines = [f'{r["month"]}: {r["state"]}' + (f' ({r["message"]})' if 'message' in r else '') for r in rows]
    _emit(out, args, status, result, warnings, '\n'.join([*lines, summary, coverage['text'], LINEAGE_NOTE]))
    return 5 if cancelled else (RUNTIME if missing else OK)


HANDLERS = {'sync': cmd_sync}


def main(argv: list[str] | None = None, *, ports: OnlinePorts | None = None, stdout=None, stderr=None) -> int:
    """Run ``kb index sync ...``. ``argv`` excludes the ``kb index sync`` prefix."""
    return run_cli('kb index', build_parser, HANDLERS, list(argv or []), ports=ports or OnlinePorts(), stdout=stdout,
                   stderr=stderr)
