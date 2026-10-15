"""`python -m tools.unified.corpus <command>`: fetch, build, A/A, mutate and manifest the Tier R corpus of the SPEC-31 gates.

Thin glue over the SPEC-32 factory (`tools/calibration/tier_r`). Everything large lives under `PATCHTRACE_CALIB_ROOT`
(outside the work tree); the repository holds only recipes, cards and pins. Network only in `fetch` (one pinned commit per
side over HTTPS to an allow-listed host). Built images are never executed.
Exit codes as SPEC-32: 0 ok, 1 findings, 2 usage or contract error, 3 BLOCKED (a tool is missing; never a pass).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r import fetch as FE
from tools.calibration.tier_r import toolchain as T
from tools.calibration.tier_r.build import OPTS, BuildError
from tools.unified.mutations import classes, driver, templates

from . import aa, catalogue, manifest

OK, FINDINGS, USAGE, BLOCKED = 0, 1, 2, 3


class UsageError(ValueError):
    pass


def _select(spec: str) -> list[C.CaseCard]:
    cards = catalogue.load_cards()
    if spec == 'all':
        return list(cards)
    by_id = {c.id: c for c in cards}
    unknown = [s for s in spec.split(',') if s not in by_id]
    if unknown:
        raise UsageError(f'unknown pair id(s): {", ".join(unknown)}')
    return [by_id[s] for s in spec.split(',')]


def _toolchain(_args) -> int:
    chain = T.probe()
    for name, tool in sorted(chain.tools.items()):
        print(f'{name:16s} {tool.version if tool.ok else "missing: " + str(tool.reason)}')
    status = {profile: chain.profile_status(profile) for profile in T.PROFILE_TOOLS}
    for profile, why in status.items():
        print(f'profile {profile}: {"ready" if why is None else "BLOCKED " + why}')
    return OK if any(why is None for why in status.values()) else BLOCKED


def _check(_args) -> int:
    findings = catalogue.problems()
    print('\n'.join(findings) if findings else 'ok: the catalogue is consistent')
    return FINDINGS if findings else OK


def _fetch_side(book: C.RecipeBook, store: Path, tools: T.Toolchain, project: str, commit: str) -> Path:
    recipe = book.get(project)
    pin = recipe.pin_for(commit)
    dest = FE.checkout_dir(store, project, commit)
    FE.fetch_commit(recipe.upstream_git, commit, dest, tools, license_file=recipe.license_file,
                    expected_license_sha256=pin.license_sha256)
    return dest


def _fetch(args) -> int:
    tools, store, book, pins = T.probe(), F.store_dir(), catalogue.merged_book(), catalogue.load_pins()
    digests: dict[str, dict[str, str]] = {}
    for card in _select(args.pairs):
        for dep in book.get(card.project).depends:
            _fetch_side(book, store, tools, dep.project, dep.commit)
        digests[card.id] = {side: catalogue.tree_sha256(_fetch_side(book, store, tools, card.project, ref.commit))
                            for side, ref in (('old', card.old), ('new', card.new))}
    if args.print_digests:
        print(json.dumps({'contract': 'unified-corpus-pins/1', 'pairs': digests}, indent=1, sort_keys=True))
        return OK
    wrong = [f'PT-UC-PIN: {cid} {side} source tree {got} differs from pins.json'
             for cid, sides in digests.items() for side, got in sides.items()
             if getattr(pins.pairs.get(cid), side, None) != got]
    print('\n'.join(wrong) if wrong else f'ok: {len(digests)} pair(s) fetched, source digests match pins.json')
    return FINDINGS if wrong else OK


def _build(args) -> int:
    session, book = F.Session(T.probe(), F.store_dir()), catalogue.merged_book()
    for card in _select(args.pairs):
        doc = F.run_card(session, book, card, opt=args.opt)
        F.write_doc(session.store, doc)
        by_label = doc['summary']['by_label']
        print(f'built {doc["pair_id"]}: {doc["summary"]["functions"]} functions, {by_label}')
    return OK


def _aa(args) -> int:
    session, book, cards = F.Session(T.probe(), F.store_dir()), catalogue.merged_book(), catalogue.load_cards()
    projects = args.projects.split(',') if args.projects != 'all' else sorted({c.project for c in cards})
    for project in projects:
        card = next((c for c in cards if c.project == project), None)
        if card is None:
            raise UsageError(f'no card for project {project}')
        ref = card.new if args.side == 'new' else card.old
        base = F.recipe_base(book, book.get(project), ref.ref, ref.commit, session.store)
        result = aa.run(session, base, opt=args.opt)
        for doc in result.docs:
            F.write_doc(session.store, doc)
        counts = Counter(aa.classify(doc) for doc in result.docs)
        print(f'{project} {ref.ref}: {dict(sorted(counts.items()))}; skipped {result.skipped}')
    return OK


def _mutate(args) -> int:
    ids = [c.id for c in classes.CLASSES] if args.classes == 'all' else args.classes.split(',')
    unknown = [i for i in ids if i not in classes.BY_ID]
    if unknown:
        raise UsageError(f'unknown mutant class(es): {", ".join(unknown)}')
    if not 1 <= args.per_class <= templates.MAX_COUNT:
        raise UsageError(f'--per-class must be 1..{templates.MAX_COUNT}')
    session = F.Session(T.probe(), F.store_dir())
    exhausted = 0
    for cid in ids:
        module = templates.generate(cid, args.per_class, seed=args.seed)
        result = driver.build_mutants(session, module, work=session.store / 'unified-mutants', opt=args.opt)
        for doc in result.docs:
            F.write_doc(session.store, doc)
        exhausted += len(result.exhausted)
        print(f'{cid}: {len(result.docs)}/{args.per_class} mutants, {len(result.rejected)} rejected edit(s), '
              f'exhausted {result.exhausted}')
    return FINDINGS if exhausted else OK


def _manifest(args) -> int:
    store, chain = F.store_dir(), T.probe()
    docs = [C.load_labels(p.read_bytes()) for p in sorted((store / 'labels').glob('*.json'))]
    built = manifest.build(docs, {n: t.version or 'unknown' for n, t in chain.tools.items() if t.ok})
    out = Path(args.out) if args.out else store / 'reports' / 'unified-corpus-manifest.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(manifest.dump(built))
    print(f'{out}: {len(built.pairs)} pair(s), {len(built.ignored)} ignored, {len(built.pending)} pending, '
          f'manifest_sha256 {built.manifest_sha256}')
    return OK


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog='python -m tools.unified.corpus', description=__doc__.split('\n\n')[0])
    sub = root.add_subparsers(dest='command', required=True)
    sub.add_parser('toolchain', help='probe the compilers and LLVM tools; BLOCKED (exit 3) when no profile can build'
                   ).set_defaults(run=_toolchain)
    sub.add_parser('check', help='offline consistency of recipes, cards and pins').set_defaults(run=_check)
    fetch = sub.add_parser('fetch', help='fetch the pinned commits (network) and verify the source digests')
    fetch.add_argument('--pairs', default='all', help='comma-separated card ids or all')
    fetch.add_argument('--print-digests', action='store_true', help='print the digests (for pins.json), verify nothing')
    fetch.set_defaults(run=_fetch)
    build = sub.add_parser('build', help='build and label release pairs from fetched sources')
    build.add_argument('--pairs', default='all')
    build.add_argument('--opt', default='O2', choices=OPTS)
    build.set_defaults(run=_build)
    aa_cmd = sub.add_parser('aa', help='A/A pairs P0 (rebuild), P1 (link order) and P2 (stress) of a project')
    aa_cmd.add_argument('--projects', default='all', help='comma-separated project names or all')
    aa_cmd.add_argument('--side', default='new', choices=['old', 'new'], help='which pin of the card to rebuild')
    aa_cmd.add_argument('--opt', default='O2', choices=OPTS)
    aa_cmd.set_defaults(run=_aa)
    mutate = sub.add_parser('mutate', help='planted mutants of the G-U2 classes')
    mutate.add_argument('--classes', default='all', help='comma-separated class ids or all')
    mutate.add_argument('--per-class', type=int, default=24, help='mutants per class (the gate needs 20 or more)')
    mutate.add_argument('--seed', type=int, default=1)
    mutate.add_argument('--opt', default='O2', choices=OPTS)
    mutate.set_defaults(run=_mutate)
    man = sub.add_parser('manifest', help='write unified-corpus-manifest/1 from the label documents of the store')
    man.add_argument('--out', help='default: <store>/reports/unified-corpus-manifest.json')
    man.set_defaults(run=_manifest)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.run(args)
    except T.Blocked as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return BLOCKED
    except (UsageError, C.ContractError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return USAGE
    except (FE.FetchError, BuildError, F.FactoryError, T.ToolError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return FINDINGS
