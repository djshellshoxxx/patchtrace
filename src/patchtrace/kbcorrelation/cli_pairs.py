"""`kb products|components|pairs|import-pair|plan` (KB-integration-plan 8.1; slice K3). Thin: parse, call the service,
present. Registered by ``cli.register_verbs``; handlers take ``(args, context, out)`` where ``context.service(args)``
builds the :class:`~.service.KbService`. Offline: nothing here can fetch.
"""
from __future__ import annotations

from .cli_index import add_common, present


def _investigation(parser) -> None:
    parser.add_argument('investigation', metavar='INV', help='investigation id printed by "kb search"')


def register(sub) -> None:
    add_common(sub.add_parser('products', help='list the product scopes of an investigation')).add_argument(
        'investigation', metavar='INV')
    comp = add_common(sub.add_parser('components', help='component hints (analyst names and advisory title names)'))
    _investigation(comp)
    comp.add_argument('--product', metavar='ID', help='product scope id; chooses the product when none is chosen')
    comp.add_argument('--file', action='append', default=[], metavar='NAME', help='a file name you know (repeatable)')
    pairs = add_common(sub.add_parser('pairs', help='pair candidates from the saved Winbindex records'))
    _investigation(pairs)
    pairs.add_argument('--product', metavar='ID')
    pairs.add_argument('--file', action='append', default=[], metavar='NAME')
    imp = add_common(sub.add_parser('import-pair', help='compare two files you hold: create and attach a project'))
    _investigation(imp)
    imp.add_argument('--older', required=True, metavar='FILE')
    imp.add_argument('--newer', required=True, metavar='FILE')
    imp.add_argument('--project', required=True, metavar='DIR', help='new project directory (must be empty)')
    imp.add_argument('--name', metavar='N', help='project name')
    imp.add_argument('--confirm-same-component', action='store_true',
                     help='the two differently named files are the same component')
    imp.add_argument('--dry-run', action='store_true', help='show the local plan and grade; create nothing')
    plan = add_common(sub.add_parser('plan', help='preview what a file-index pair needs; makes no request'))
    _investigation(plan)
    plan.add_argument('--pair', metavar='ID', help='pair id (or its first characters) from "kb pairs"')
    plan.add_argument('--product', metavar='ID')
    plan.add_argument('--file', action='append', default=[], metavar='NAME')


def cmd_products(args, context, out) -> int:
    return present(out, 'kb products', args, context.service(args).products(args.investigation))


def cmd_components(args, context, out) -> int:
    return present(out, 'kb components', args,
                   context.service(args).components(args.investigation, product=args.product, files=args.file))


def cmd_pairs(args, context, out) -> int:
    return present(out, 'kb pairs', args,
                   context.service(args).pairs(args.investigation, product=args.product, files=args.file))


def cmd_import_pair(args, context, out) -> int:
    outcome = context.service(args).import_pair(
        args.investigation, args.older, args.newer, args.project, name=args.name,
        confirm_same_component=args.confirm_same_component, dry_run=args.dry_run)
    return present(out, 'kb import-pair', args, outcome)


def cmd_plan(args, context, out) -> int:
    return present(out, 'kb plan', args, context.service(args).plan(
        args.investigation, pair_id=args.pair, product=args.product, files=args.file))


HANDLERS = {'products': cmd_products, 'components': cmd_components, 'pairs': cmd_pairs,
            'import-pair': cmd_import_pair, 'plan': cmd_plan}
