"""PW-01 ``kb inventory`` grammar and presentation. Thin shared-service adapter.

Import, inspection, selection and plan commands are offline. Only ``fetch`` can
request bytes, after the service verifies exact operation-specific consent.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .cli_index import ARGUMENT_CODES, CliError, Parser, add_common, emit, present, run_cli
from .products import clean_text
from .sources.cvrf import SourceError
from .store import KbcStoreError

KINDS = ('file-inventory', 'support-page')
ARCHITECTURES = ('amd64', 'arm64', 'x86', 'unknown')
STATES = ('metadata-only', 'unknown', 'conflicted', 'descriptive-only')


def _context_options(parser, *, required):
    parser.add_argument('--kb', required=required, metavar='KB', help='explicit KB identifier (bare digits accepted)')
    parser.add_argument('--product-scope-id', metavar='ID', help='explicit stored product scope ID, if known')
    parser.add_argument('--product', metavar='TEXT', help='asserted product label; not source authentication')
    parser.add_argument('--release', metavar='TEXT', help='asserted release; do not infer it from the file version')
    parser.add_argument('--build', metavar='TEXT', help='asserted OS build; not the binary version')
    parser.add_argument('--architecture', choices=ARCHITECTURES, default='unknown',
                        help='explicit architecture context (default: unknown); conflicting rows remain conflicts')
    parser.add_argument('--delimiter', choices=('comma', 'semicolon', 'tab'), default='comma',
                        help='explicit CSV delimiter (default: comma); never guessed')
    parser.add_argument('--locale', choices=('invariant', 'en-US', 'de-DE'), default='en-US',
                        help='file-size grouping rules (default: en-US); dates stay uninterpreted text')


def build_parser() -> Parser:
    parser = Parser(prog='patchtrace kb inventory',
                    description='Import and inspect bounded KB file inventories and saved support pages. '
                    'All commands are offline except an explicitly consented fetch. Metadata does not establish '
                    'binary identity or a CVE fix.',
                    epilog='Exit codes: 0 success; 2 input/unsupported/consent; 3 runtime or partial results; '
                    '4 empty; 5 cancelled. See docs/help/kb-file-inventory.md for the saved-source workflow.')
    sub = parser.add_subparsers(dest='action', required=True, parser_class=Parser)
    imp = add_common(sub.add_parser('import', help='import one saved CSV, retaining its exact bytes and row references'))
    imp.add_argument('file', type=Path, metavar='FILE')
    _context_options(imp, required=True)
    imp.add_argument('--asserted-source', metavar='URL', help='optional source assertion; local bytes stay unverified')
    imp.add_argument('--offline', action='store_true', help='accepted for clarity; import never fetches')

    listing = add_common(sub.add_parser('list', help='list saved inventory or support-page summaries'))
    listing.add_argument('--kind', choices=KINDS, default='file-inventory')
    listing.add_argument('--limit', type=int, default=20, metavar='N', help='page size, 1..100 (default: 20)')
    listing.add_argument('--offset', type=int, default=0, metavar='N', help='zero-based page offset (default: 0)')

    show = add_common(sub.add_parser('show', help='verify a saved source and inspect its rows, counts and provenance'))
    show.add_argument('import_id', metavar='IMPORT_ID')
    show.add_argument('--name', default='', metavar='TEXT', help='case-insensitive filename substring')
    show.add_argument('--architecture', choices=ARCHITECTURES, help='filter retained rows by architecture')
    show.add_argument('--state', choices=STATES, help='filter retained metadata states without changing the source')
    show.add_argument('--limit', type=int, default=200, metavar='N', help='page size, 1..500 (default: 200)')
    show.add_argument('--offset', type=int, default=0, metavar='N', help='zero-based filtered-row offset')

    select = add_common(sub.add_parser('select', help='explicitly select one eligible row for a recorded investigation'))
    select.add_argument('import_id', metavar='IMPORT_ID')
    select.add_argument('entry_id', metavar='ENTRY_ID')
    select.add_argument('--investigation', required=True, metavar='ID')
    select.add_argument('--product', required=True, metavar='ID', help='exact product scope ID from kb products')
    select.add_argument('--expected-revision', required=True, type=int, metavar='N',
                        help='current revision from kb products/search JSON; stale selection changes nothing')
    select.add_argument('--assert-scope', action='store_true',
                        help='explicitly assert an unmapped inventory scope; cannot override known conflicts')

    links = add_common(sub.add_parser('links', help='inspect and retain saved HTML links without following them'))
    links.add_argument('file', type=Path, metavar='HTML')
    links.add_argument('--page-url', required=True, metavar='URL', help='explicit validated Microsoft support page URL')

    plan = add_common(sub.add_parser('plan', help='preview exact ordered requests, hosts, limits and plan SHA; no network'))
    plan.add_argument('url', metavar='URL')
    plan.add_argument('--kind', choices=KINDS, default='file-inventory')
    plan.add_argument('--redirect-url', action='append', default=[], metavar='URL',
                      help='approved next URL in order; repeat for each known redirect, at most four')

    fetch = add_common(sub.add_parser('fetch', help='fetch and retain exactly one explicitly consented source'))
    fetch.add_argument('--plan-file', required=True, type=Path, metavar='FILE',
                       help='strict plan JSON, or the full envelope saved from inventory plan --json')
    fetch.add_argument('--consent-plan', required=True, metavar='SHA256', help='exact reviewed plan_sha')
    fetch.add_argument('--consent-host', required=True, action='append', metavar='HOST',
                       help='one exact reviewed hostname; repeat for every planned host')
    fetch.add_argument('--offline', action='store_true', help='refuse all requests even when consent is supplied')
    _context_options(fetch, required=False)
    return parser


def _inventory_context(args):
    from .inventory_service import context_for

    values = {name: getattr(args, name) for name in ('product_scope_id', 'product', 'release', 'build',
                                                   'architecture', 'delimiter', 'locale')}
    if args.kb is None:
        if any(values[name] is not None for name in ('product_scope_id', 'product', 'release', 'build')) or (
                args.architecture != 'unknown' or args.delimiter != 'comma' or args.locale != 'en-US'):
            raise CliError(2, 'CSV context options require --kb; support-page fetching needs no CSV context')
        return None
    return context_for(args.kb, **values)


def _safe_lines(text):
    return '\n'.join(clean_text(line, len(line)) for line in text.splitlines())


def _present(out, args, ports, outcome):
    if outcome.error is None:
        return present(out, f'kb inventory {args.action}', args, outcome)
    error = _safe_lines(outcome.error)
    emit(out, f'kb inventory {args.action}', args.json, outcome.status, outcome.result, outcome.warnings,
         _safe_lines(outcome.text), error)
    print(f'error: {error}', file=ports.stderr)
    return outcome.exit


def cmd_import(args, ports, out):
    return _present(out, args, ports, ports.service(args).import_inventory(
        args.file, _inventory_context(args), asserted_source=args.asserted_source))


def cmd_list(args, ports, out):
    return _present(out, args, ports, ports.service(args).inventories(
        kind=args.kind, limit=args.limit, offset=args.offset))


def cmd_show(args, ports, out):
    return _present(out, args, ports, ports.service(args).inventory_details(
        args.import_id, name=args.name, architecture=args.architecture, state=args.state,
        limit=args.limit, offset=args.offset))


def cmd_select(args, ports, out):
    return _present(out, args, ports, ports.service(args).select_inventory(
        args.investigation, args.import_id, args.entry_id, product=args.product,
        expected_revision=args.expected_revision, assert_scope=args.assert_scope))


def cmd_links(args, ports, out):
    return _present(out, args, ports, ports.service(args).support_links(args.file, page_url=args.page_url))


def cmd_plan(args, ports, out):
    return _present(out, args, ports, ports.service(args).inventory_plan(
        args.url, kind=args.kind, redirects=tuple(args.redirect_url)))


def cmd_fetch(args, ports, out):
    return _present(out, args, ports, ports.service(args).fetch_inventory(
        args.plan_file, context=_inventory_context(args), consent_hosts=tuple(args.consent_host),
        consent_plan=args.consent_plan, offline=args.offline))


def _guard(handler):
    def invoke(args, ports, out):
        try:
            return handler(args, ports, out)
        except (SourceError, KbcStoreError) as exc:
            cancelled = exc.code == 'PT-KBC-CANCEL'
            # Malformed/oversized local input is an input rejection. Damaged
            # stored sources, failed fetches and other runtime failures stay 3.
            local_input = isinstance(exc, SourceError) and args.action in ('import', 'links', 'plan')
            code = 5 if cancelled else 2 if exc.code in ARGUMENT_CODES or local_input else 3
            status = 'cancelled' if cancelled else 'failed'
            message = f'{clean_text(exc.code, 40)}: {clean_text(exc.message, 500)}'
            result = {'contract': 'kbcorrelation/1', 'issue': exc.issue().model_dump(mode='json')}
            details = exc.details or {}
            if exc.code == 'PT-KBC-CONSENT' and isinstance(details.get('proposed_plan'), dict):
                result.update(proposed_plan=details['proposed_plan'], preview=details.get('preview', ''))
            text = message + ('\n' + _safe_lines(result['preview']) if result.get('preview') else '')
            emit(out, f'kb inventory {args.action}', args.json, status, result, [], text, error=message)
            print(f'error: {message}', file=ports.stderr)
            return code
    return invoke


HANDLERS = {name: _guard(handler) for name, handler in (
    ('import', cmd_import), ('list', cmd_list), ('show', cmd_show), ('select', cmd_select),
    ('links', cmd_links), ('plan', cmd_plan), ('fetch', cmd_fetch))}


@dataclass(frozen=True)
class _Ports:
    context: object
    stderr: object

    def service(self, args):
        return self.context.service(args)


def main(argv, *, context=None, stdout=None, stderr=None):
    if context is None:
        from .cli import Context
        context = Context()
    return run_cli('kb inventory', build_parser, HANDLERS, list(argv),
                   ports=_Ports(context, stderr or sys.stderr), stdout=stdout, stderr=stderr)
