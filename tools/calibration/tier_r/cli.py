"""SPEC-32 s12 CLI: `python -m tools.calibration.tier_r <cmd>` (also `python -m tools.calibration.corpus known-answer <cmd>`).

Exit codes: 0 ok, 1 findings / disagreements / failed engines, 2 usage or contract error, 3 BLOCKED (a tool or input that
is not available here: reported with its reason, never a pass). Output is one JSON document on stdout. Dev-only: nothing
here ships, and no built image is ever executed.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ..label import AnnotationLog
from . import annotate as A
from . import contracts as C
from . import evaluate as E
from . import factory as F
from . import fetch as FE
from . import manifest as M
from . import report_schemas as RS
from . import schemas as S
from .toolchain import PROFILE_TOOLS, Blocked, probe

OK, FINDINGS, USAGE, BLOCKED = 0, 1, 2, 3
REPO = Path(__file__).resolve().parents[3]
CATALOGUE = Path(__file__).resolve().parent / 'catalogue'
CARD_DIRS = (CATALOGUE / 'releases.json', CATALOGUE / 'cves.json')


class Usage(Exception):
    pass


def _emit(document: dict) -> None:
    print(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False))


def _store(args) -> Path:
    if getattr(args, 'store', None):
        store = Path(args.store).expanduser().resolve()
        try:
            store.relative_to(REPO)
        except ValueError:
            return store
        raise Usage(f'--store {store} is inside the work tree: refusing to keep images there')
    try:
        return F.store_dir()
    except F.FactoryError as exc:
        raise Usage(str(exc)) from None


def _labels_dir(args, store: Path) -> Path:
    return Path(args.labels) if getattr(args, 'labels', None) else store / 'labels'


def _load_docs(folder: Path) -> list[C.KnownAnswerLabels]:
    if not folder.is_dir():
        raise Usage(f'label folder {folder} does not exist (build pairs first)')
    docs = E.load_label_dir(folder)
    if not docs:
        raise Usage(f'no label documents in {folder}')
    return docs


def _book() -> C.RecipeBook:
    return C.load_recipes((CATALOGUE / 'recipes.json').read_bytes())


def _cards(extra: Sequence[str] = ()) -> list[C.CaseCard]:
    paths = [p for p in CARD_DIRS if p.is_file()] + [Path(p) for p in extra]
    paths += sorted((REPO / 'corpus' / 'catalog').glob('*.json'))
    return F.load_card_files(paths)


def _card(card_id: str) -> C.CaseCard:
    for card in _cards():
        if card.id == card_id:
            return card
    raise Usage(f'unknown case card {card_id!r}')


def _session(args) -> F.Session:
    store = _store(args)
    return F.Session(probe(), store)


# ---- commands ---------------------------------------------------------------------------------------------------------

def cmd_toolchain(args) -> tuple[int, dict]:
    chain = probe()
    profiles = {name: chain.profile_status(name) or 'ready' for name in PROFILE_TOOLS}
    import shutil
    rz = shutil.which('rz-diff')
    ready = [name for name, status in profiles.items() if status == 'ready']
    doc = {'command': 'toolchain', 'tools': chain.describe(), 'profiles': profiles,
           'rz-diff': rz or 'BLOCKED: rz-diff not found (evaluate reports the rz-diff engine as blocked)',
           'status': 'ok' if ready else 'blocked'}
    return (OK if ready else BLOCKED), doc


def cmd_fetch(args) -> tuple[int, dict]:
    chain, store, book = probe(), _store(args), _book()
    todo: dict[str, tuple[str, str, str, str | None, str | None]] = {}
    for card_id in args.cards:
        card = _card(card_id)
        recipe = book.get(card.project)
        if recipe is None:
            raise Usage(f'no-recipe: {card.project}')
        for ref in (card.old, card.new):
            pin = recipe.pin_for(ref.commit)
            todo[f'{card.project}@{ref.commit}'] = (card.project, recipe.upstream_git, ref.commit, recipe.license_file,
                                                    pin.license_sha256 if pin else None)
        for dep in recipe.depends:
            dep_recipe = book.get(dep.project)
            if dep_recipe:
                pin = dep_recipe.pin_for(dep.commit)
                todo[f'{dep.project}@{dep.commit}'] = (dep.project, dep_recipe.upstream_git, dep.commit,
                                                       dep_recipe.license_file, pin.license_sha256 if pin else None)
    done, errors = [], []
    for key in sorted(todo):
        project, url, commit, license_file, license_sha = todo[key]
        try:
            FE.fetch_commit(url, commit, FE.checkout_dir(store, project, commit), chain, license_file=license_file,
                            expected_license_sha256=license_sha)
            done.append(key)
        except Blocked as exc:
            return BLOCKED, {'command': 'fetch', 'status': 'blocked', 'reason': str(exc), 'fetched': done}
        except FE.FetchError as exc:
            errors.append(f'{key}: {exc}'[:400])
    return (FINDINGS if errors else OK), {'command': 'fetch', 'status': 'failed' if errors else 'ok', 'fetched': done,
                                          'errors': errors}


def _write_pairs(store: Path, docs: Sequence[dict]) -> list[str]:
    return [F.write_doc(store, d).name for d in docs]


def cmd_build_suite(args) -> tuple[int, dict]:
    session = _session(args)
    results = F.run_suite(session, Path(args.dir), opt=args.opt)
    names = _write_pairs(session.store, [d for d, _ in results])
    problems = [p for _, ps in results for p in ps]
    return (FINDINGS if problems else OK), {'command': 'build-suite', 'status': 'findings' if problems else 'ok',
                                            'written': names, 'cross_check_problems': problems[:100]}


def cmd_build_card(args) -> tuple[int, dict]:
    session = _session(args)
    try:
        doc = F.run_card(session, _book(), _card(args.card), opt=args.opt)
    except F.IdenticalImages as exc:
        return OK, {'command': 'build-card', 'status': 'skipped', 'reason': str(exc), 'written': [], 'disagreements': 0}
    name = F.write_doc(session.store, doc).name
    disagree = doc['summary']['disagreements']
    return (FINDINGS if disagree else OK), {'command': 'build-card', 'status': 'findings' if disagree else 'ok',
                                            'written': [name], 'disagreements': disagree}


def _base(args, session: F.Session) -> F.BaseSource:
    if args.suite:
        suite, bases = F.suite_bases(Path(args.suite))
        version = args.version or suite.versions[0]
        if version not in bases:
            raise Usage(f'--version must be one of {sorted(bases)}')
        return bases[version]
    if getattr(args, 'card', None):
        card = _card(args.card)
        recipe = _book().get(card.project)
        if recipe is None:
            raise Usage(f'no-recipe: {card.project}')
        ref = card.old if args.side == 'old' else card.new
        return F.recipe_base(_book(), recipe, ref.ref, ref.commit, session.store)
    raise Usage('give --suite DIR --version V or --card ID --side old|new')


def cmd_aa(args) -> tuple[int, dict]:
    session = _session(args)
    docs = F.run_aa(session, _base(args, session), opt=args.opt, layout=not args.no_layout)
    bad = [d['pair_id'] for d in docs if d.get('reproducibility') and not d['reproducibility']['byte_identical']]
    return (FINDINGS if bad else OK), {'command': 'aa', 'status': 'findings' if bad else 'ok',
                                       'written': _write_pairs(session.store, docs), 'not_byte_identical': bad}


def cmd_noise(args) -> tuple[int, dict]:
    session = _session(args)
    docs, skipped = F.run_noise(session, _base(args, session))
    return OK, {'command': 'noise', 'status': 'ok', 'written': _write_pairs(session.store, docs), 'skipped': skipped}


def cmd_mutate(args) -> tuple[int, dict]:
    from ..mutations.contracts import OPERATORS
    if args.operator not in OPERATORS:
        raise Usage(f'unknown mutation operator {args.operator!r}; choose from {list(OPERATORS)}')
    session = _session(args)
    doc = F.run_mutation(session, _base(args, session), args.operator, args.seed, opt=args.opt)
    name = F.write_doc(session.store, doc).name
    disagree = doc['case']['disagreements']
    return (FINDINGS if disagree else OK), {'command': 'mutate', 'status': 'findings' if disagree else 'ok',
                                            'written': [name], 'disagreements': disagree,
                                            'operator': args.operator, 'seed': args.seed}


def cmd_evaluate(args) -> tuple[int, dict]:
    store = _store(args)
    docs = _load_docs(_labels_dir(args, store))
    engines = tuple(e.strip() for e in args.engines.split(',') if e.strip())
    unknown = sorted(set(engines) - set(E.ENGINES))
    if unknown:
        raise Usage(f'unknown engine(s) {unknown}; choose from {list(E.ENGINES)}')
    imports = Path(args.imports) if args.imports else store / 'imports'
    providers = E.default_providers(store, imports, rz_diff=args.rz_diff or os.environ.get('RZ_DIFF') or None,
                                    engines=engines)
    report = E.evaluate(docs, providers, symbols=args.symbols)
    out = Path(args.out) if args.out else store / 'reports' / f'tier-r-{args.symbols}-{report["report_sha256"][:12]}.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(C.dump_json(report))
    out.with_suffix('.md').write_text(E.render_markdown(report), encoding='utf-8', newline='\n')
    problems = E.blocked_engines(report)
    states = {e['engine']: e['status'] for e in report['engines']}
    doc = {'command': 'evaluate', 'report': out.as_posix(), 'report_sha256': report['report_sha256'],
           'engines': states, 'blocked': {e['engine']: e['reason'] for e in problems if e['status'] == 'blocked'}}
    if all(s == 'blocked' for s in states.values()):
        doc['status'] = 'blocked'
        return BLOCKED, doc
    failed = [e for e in problems if e['status'] == 'failed']
    doc['status'] = 'failed' if failed else 'ok'
    return (FINDINGS if failed else OK), doc


def cmd_manifest(args) -> tuple[int, dict]:
    store = _store(args)
    docs = _load_docs(_labels_dir(args, store))
    try:
        manifest = M.build_manifest(docs, corpus_id=args.corpus_id, tool_git=args.tool_git, created=args.created)
    except (M.ManifestError, ValueError) as exc:
        raise Usage(f'manifest: {str(exc)[:400]}') from None
    out = Path(args.out) if args.out else store / 'manifest.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(C.dump_json(manifest))
    return OK, {'command': 'manifest', 'status': 'ok', 'manifest': out.as_posix(), 'binaries': len(manifest['binaries']),
                'pairs': len(manifest['pairs']), 'lineages': len(manifest['lineages'])}


def cmd_annotate(args) -> tuple[int, dict]:
    store = _store(args)
    docs = _load_docs(_labels_dir(args, store))
    log = AnnotationLog(Path(args.log) if args.log else store / 'annotations.jsonl')
    outputs: dict[str, dict[str, E.EngineOutput]] = {}
    blocked: dict[str, str] = {}
    engines = tuple(e.strip() for e in args.engines.split(',') if e.strip())
    if engines:
        for provider in E.default_providers(store, Path(args.imports) if args.imports else None, engines=engines):
            for labels in docs:
                out = provider(labels, 'hidden')
                if out.status == 'ok':
                    outputs.setdefault(labels.pair_id, {})[provider.engine] = out
                else:
                    blocked.setdefault(provider.engine, out.reason or out.status)
    summary = A.write_log(docs, log, outputs=outputs)
    records, stats = A.consolidate_labels(docs, log, A.StoreBodyReader(store), outputs=outputs)
    out_path = Path(args.out) if args.out else store / 'calibration-labels.jsonl'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(A.dump_jsonl(records))
    return OK, {'command': 'annotate', 'status': 'ok', 'log': log.path.as_posix(), 'labels': out_path.as_posix(),
                'records': len(records), 'blocked_engines': blocked, **summary, **stats}


def cmd_schemas(args) -> tuple[int, dict]:
    root = Path(args.out)
    written = [p.as_posix() for p in S.write_all(root)] + [p.as_posix() for p in RS.write_all(root)]
    return OK, {'command': 'schemas', 'status': 'ok', 'written': sorted(written)}


def _corpus_check():
    spec = importlib.util.spec_from_file_location('corpus_check', REPO / 'tools' / 'corpus_check.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cmd_catalogue_check(args) -> tuple[int, dict]:
    problems = []
    try:
        book = _book()
        cards = []
        for path in CARD_DIRS:
            if path.is_file():
                cards += C.load_cards(path.read_bytes())
                problems += [f'{path.name}: {p}' for p in _corpus_check().check_catalog(path)]
    except (C.ContractError, OSError) as exc:
        return USAGE, {'command': 'catalogue-check', 'status': 'error', 'error': str(exc)[:400]}
    for card in cards:
        recipe = book.get(card.project)
        if recipe is None:
            problems.append(f'{card.id}: no-recipe for {card.project}')
            continue
        for side in (card.old, card.new):
            pin = recipe.pin_for(side.commit)
            if pin is None or pin.ref != side.ref:
                problems.append(f'{card.id}: {side.ref}@{side.commit[:12]} is not a pin of recipe {card.project}')
    return (FINDINGS if problems else OK), {'command': 'catalogue-check', 'status': 'findings' if problems else 'ok',
                                            'recipes': len(book.recipes), 'cards': len(cards), 'problems': problems}


# ---- parser -----------------------------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='python -m tools.calibration.tier_r',
                                     description='SPEC-32 known-answer corpus factory (dev-only). Exit: 0 ok, '
                                                 '1 findings, 2 usage/contract error, 3 BLOCKED.')
    sub = parser.add_subparsers(dest='cmd', required=True)

    def add(name: str, func, help_: str, *, store: bool = True) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_)
        p.set_defaults(func=func)
        if store:
            p.add_argument('--store', help='known-answer store (default: $PATCHTRACE_CALIB_ROOT/known-answer)')
        return p

    add('toolchain', cmd_toolchain, 'probe compilers and inspectors; BLOCKED reasons', store=False)
    p = add('fetch', cmd_fetch, 'fetch the pinned commits of case cards (network, allow-listed host)')
    p.add_argument('cards', nargs='+', metavar='CARD_ID')
    p = add('build-suite', cmd_build_suite, 'build and label an authored suite directory')
    p.add_argument('dir')
    p.add_argument('--opt', default='O2', choices=('O0', 'O1', 'O2', 'O3', 'Os'))
    p = add('build-card', cmd_build_card, 'build and label one case card (needs fetch first)')
    p.add_argument('card', metavar='ID')
    p.add_argument('--opt', default='O2', choices=('O0', 'O1', 'O2', 'O3', 'Os'))
    for name, func, help_ in (('aa', cmd_aa, 'A/A rebuild and layout pairs of one source'),
                              ('noise', cmd_noise, 'toolchain-noise pairs of one source')):
        p = add(name, func, help_)
        p.add_argument('--suite')
        p.add_argument('--version')
        p.add_argument('--card')
        p.add_argument('--side', choices=('old', 'new'), default='old')
        p.add_argument('--opt', default='O2', choices=('O0', 'O1', 'O2', 'O3', 'Os'))
        if name == 'aa':
            p.add_argument('--no-layout', action='store_true')
    p = add('mutate', cmd_mutate, 'plant one mutation (SPEC-32 s8) in a suite version, build and label the pair')
    p.add_argument('--suite', required=True)
    p.add_argument('--version', help='suite version to mutate (default: the first listed)')
    p.add_argument('--operator', required=True)
    p.add_argument('--seed', type=int, required=True)
    p.add_argument('--opt', default='O2', choices=('O0', 'O1', 'O2', 'O3', 'Os'))
    p = add('evaluate', cmd_evaluate, 'score engines against the label documents (tier-r-report/1)')
    p.add_argument('--labels')
    p.add_argument('--imports', help='folder with <pair_id>.BinDiff and <pair_id>.ghidriff.json (default <store>/imports)')
    p.add_argument('--symbols', choices=('hidden', 'visible'), default='hidden')
    p.add_argument('--engines', default=','.join(E.ENGINES))
    p.add_argument('--rz-diff', help='absolute path of rz-diff (default: PATH lookup)')
    p.add_argument('--out', help='report JSON path; a Markdown file is written beside it')
    p = add('manifest', cmd_manifest, 'emit a calibration-corpus/1 manifest of the label documents')
    p.add_argument('--labels')
    p.add_argument('--out')
    p.add_argument('--corpus-id', default='known-answer-tier-r')
    p.add_argument('--tool-git', default='unknown')
    p.add_argument('--created', default=M.DEFAULT_CREATED)
    p = add('annotate', cmd_annotate, 'labels -> annotation log -> calibration-labels/1 (synthetic-exact)')
    p.add_argument('--labels')
    p.add_argument('--log')
    p.add_argument('--out')
    p.add_argument('--engines', default='', help='optional engines whose predicted pairs become candidates')
    p.add_argument('--imports')
    p = add('schemas', cmd_schemas, 'regenerate docs/schemas/corpus (contracts and report schemas)', store=False)
    p.add_argument('--out', default=str(REPO / 'docs' / 'schemas' / 'corpus'))
    add('catalogue-check', cmd_catalogue_check, 'offline consistency of recipes and case cards', store=False)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:      # argparse: 0 for --help, 2 for usage errors
        return int(exc.code or 0)
    try:
        code, doc = args.func(args)
    except Usage as exc:
        _emit({'command': args.cmd, 'status': 'error', 'error': str(exc)})
        return USAGE
    except Blocked as exc:
        _emit({'command': args.cmd, 'status': 'blocked', 'reason': f'BLOCKED: {exc}'})
        return BLOCKED
    except F.IdenticalImages as exc:
        _emit({'command': args.cmd, 'status': 'skipped', 'reason': str(exc)[:500]})
        return OK
    except (C.ContractError, F.FactoryError, ValueError) as exc:
        _emit({'command': args.cmd, 'status': 'error', 'error': str(exc)[:500]})
        return USAGE
    _emit(doc)
    return code


def known_answer_main(argv: Sequence[str]) -> int:
    """Entry for the `corpus known-answer` dispatch hook."""
    return main(argv)


if __name__ == '__main__':
    sys.exit(main())
