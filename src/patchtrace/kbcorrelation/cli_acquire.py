"""`kb acquire` (KB-integration-plan 8.1; slice K7). Thin: parse, call the service, present.

Without ``--consent-hosts`` and ``--consent-plan`` that match the plan, the exact plan is printed and the exit code is 2;
nothing is requested. Only a matching consent reaches the symbol server, and only from here.
"""
from __future__ import annotations

from .cli_index import add_common, present


def register(sub) -> None:
    acquire = add_common(sub.add_parser('acquire', help='download, verify and compare a file-index pair (needs consent)'))
    acquire.add_argument('investigation', metavar='INV', help='investigation id printed by "kb search"')
    acquire.add_argument('--pair', metavar='ID', help='pair id (or its first characters) from "kb pairs"')
    acquire.add_argument('--project', required=True, metavar='DIR', help='new project directory (absent or empty)')
    acquire.add_argument('--product', metavar='ID')
    acquire.add_argument('--file', action='append', default=[], metavar='NAME')
    acquire.add_argument('--name', metavar='N', help='project name')
    acquire.add_argument('--consent-hosts', default='', metavar='HOST[,..]',
                         help='the hosts of the printed plan, exactly')
    acquire.add_argument('--consent-plan', default='', metavar='SHA', help='the plan_sha of the printed plan')
    acquire.add_argument('--offline', action='store_true', help='never fetch (any consent flag is then refused)')


def cmd_acquire(args, context, out) -> int:
    hosts = [h for h in args.consent_hosts.split(',') if h.strip()]
    return present(out, 'kb acquire', args, context.service(args).acquire(
        args.investigation, args.project, pair_id=args.pair, product=args.product, files=args.file, name=args.name,
        consent_hosts=hosts, consent_plan=args.consent_plan, offline=args.offline))


HANDLERS = {'acquire': cmd_acquire}
