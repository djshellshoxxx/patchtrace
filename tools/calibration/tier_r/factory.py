"""Pair factory (SPEC-32 s3, s7, s9): suites (I4), case cards and catalogue pins (I2, I3), A/A rebuilds, layout and
toolchain-noise pairs. Every pair becomes one finalized `known-answer-labels/1` document under
`<calib root>/known-answer/labels/`. Mutations (I5) live in `tools/calibration/mutations/`.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from .. import corpus
from . import contracts as C
from .build import BuildError, BuildResult, BuildSpec, build, select_files
from .fetch import checkout_dir, receipt
from .labeler import (
    SideData,
    analyze,
    image_side,
    label_authored,
    label_construction,
    label_diff,
    summary_extra,
)
from .pe import compare_images, read_pe
from .toolchain import Blocked, Toolchain

NOISE_OPT_PAIRS = (('O0', 'O1'), ('O1', 'O2'), ('O2', 'O3'), ('O2', 'Os'))


class FactoryError(RuntimeError):
    pass


class IdenticalImages(FactoryError):
    """Old and new engine images are byte-identical (e.g. a comment-only commit): there is no pair to label."""


def store_dir(environ=None, worktree: Path | None = None) -> Path:
    root = corpus.calib_root(environ)
    tree = Path(worktree or Path(__file__).resolve().parents[3])
    try:
        root.relative_to(tree.resolve())
        raise FactoryError(f'{corpus.ROOT_ENV} ({root}) is inside the work tree: refusing to write images there')
    except ValueError:
        pass
    return root / 'known-answer'


def pair_id(*parts: str) -> str:
    text = '-'.join(p for p in parts if p)
    text = re.sub(r'[^A-Za-z0-9._-]+', '-', text).strip('-._')
    return (text or 'pair')[:96]


@dataclass(frozen=True)
class BaseSource:
    """Everything needed to build one source version; mutants and toolchain variants derive from it."""
    project: str
    lineage: str
    family: str
    source: dict                      # SourceRef JSON
    root: Path
    files: tuple[str, ...]
    output: str
    profile: str = 'msvc-free'
    include_dirs: tuple[str, ...] = ('.',)
    defines: tuple[str, ...] = ()
    cflags: tuple[str, ...] = ()
    generated: tuple[tuple[str, str], ...] = ()
    dependencies: tuple[tuple[str, Path, tuple[str, ...]], ...] = ()
    source_date_epoch: int = 0
    std: str | None = None
    tag: str = ''
    libs: tuple[str, ...] = ()

    def spec(self, *, opt: str = 'O2', link_order: str = 'sorted', variant: str = '', root: Path | None = None,
             profile: str | None = None, nuisance: str = '') -> BuildSpec:
        return BuildSpec(project=self.project, source_root=Path(root or self.root), files=self.files,
                         output=self.output, profile=profile or self.profile, opt=opt, include_dirs=self.include_dirs,
                         defines=self.defines, cflags=self.cflags, generated=self.generated,
                         dependencies=self.dependencies, link_order=link_order, variant=variant,
                         source_date_epoch=self.source_date_epoch, std=self.std, nuisance=nuisance, libs=self.libs)


@dataclass
class Session:
    """Caches builds and analyses within one run so a base image is built and parsed once."""
    tools: Toolchain
    store: Path
    builds: dict[BuildSpec, BuildResult] = field(default_factory=dict)
    sides: dict[str, SideData] = field(default_factory=dict)

    def build(self, spec: BuildSpec) -> BuildResult:
        if spec not in self.builds:
            self.builds[spec] = build(spec, self.tools, self.store)
        return self.builds[spec]

    def side(self, result: BuildResult, source_root: Path) -> SideData:
        if result.debug_sha256 not in self.sides:
            self.sides[result.debug_sha256] = analyze(result, self.tools, source_root)
        return self.sides[result.debug_sha256]


def finalize(*, pid: str, stratum: str, method: str, base_old: BaseSource, base_new: BaseSource,
             old: SideData, new: SideData, label_source: str, functions: list[dict], case: dict,
             reproducibility: dict | None = None, notes: Sequence[str] = ()) -> dict:
    doc = {'contract': C.LABELS_CONTRACT, 'pair_id': pid, 'stratum': stratum, 'method': method,
           'project': base_old.project, 'lineage': base_old.lineage, 'family': base_old.family,
           'older': image_side(old.build, source=base_old.source), 'newer': image_side(new.build, source=base_new.source),
           'label_source': label_source, 'functions': functions, 'summary': summary_extra(old, new), 'case': case,
           'notes': list(notes)}
    if reproducibility is not None:
        doc['reproducibility'] = reproducibility
    return C.finalize_labels(doc)


def write_doc(store: Path, doc: dict) -> Path:
    folder = Path(store) / 'labels'
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f'{doc["pair_id"]}.json'
    path.write_bytes(C.dump_json(doc))
    return path


# ---- I4 suites ---------------------------------------------------------------------------------------------------

def suite_bases(suite_dir: Path) -> tuple[C.Suite, dict[str, BaseSource]]:
    suite = C.load_suite((Path(suite_dir) / 'suite.json').read_bytes())
    bases = {}
    for version in suite.versions:
        root = Path(suite_dir) / version
        files = tuple(sorted(p.relative_to(root).as_posix() for p in root.rglob('*.c') if p.is_file()))
        bases[version] = BaseSource(
            project=suite.project, lineage=pair_id('L-ours', suite.suite, suite.project), family='synthetic',
            source={'suite': f'{suite.suite}/{suite.project}', 'version': version, 'license_spdx': suite.license_spdx},
            root=root, files=files, output=f'{suite.project}.dll', profile='msvc-free',
            defines=tuple(suite.build.defines), std='c11', tag=version)
    return suite, bases


def run_suite(session: Session, suite_dir: Path, *, opt: str = 'O2') -> list[tuple[dict, list[str]]]:
    suite, bases = suite_bases(suite_dir)
    out = []
    for pair in suite.pairs:
        old_base, new_base = bases[pair.old], bases[pair.new]
        old_b = session.build(old_base.spec(opt=opt, variant=pair.old.lower()[:32]))
        new_b = session.build(new_base.spec(opt=opt, variant=pair.new.lower()[:32]))
        old, new = session.side(old_b, old_base.root), session.side(new_b, new_base.root)
        functions, problems = label_authored(old, new, pair.truth)
        case = {'suite': suite.suite, 'project': suite.project, 'old': pair.old, 'new': pair.new,
                'intent': pair.intent[:2000], 'problems': problems[:100]}
        doc = finalize(pid=pair_id('ours', suite.suite, suite.project, pair.old, pair.new, opt), stratum='authored',
                       method='suite', base_old=old_base, base_new=new_base, old=old, new=new,
                       label_source='authored-truth', functions=functions, case=case)
        out.append((doc, problems))
    return out


def suite_dirs(root: Path) -> list[Path]:
    return sorted(p.parent for p in (Path(root) / 'corpus' / 'ours').glob('*/*/suite.json'))


# ---- I2/I3 recipes and case cards --------------------------------------------------------------------------------

def recipe_base(book: C.RecipeBook, recipe: C.Recipe, ref: str, commit: str, store: Path) -> BaseSource:
    root = checkout_dir(store, recipe.project, commit)
    done = receipt(root)
    if not done or done.get('commit') != commit or not done.get('verified'):
        raise FactoryError(f'{recipe.project}@{commit[:12]} is not fetched (run the fetch subcommand)')
    eff = recipe.resolved(ref, commit)
    generated: list[tuple[str, str]] = []
    for rule in eff['copy_files']:
        path = root / rule.src
        if path.is_symlink() or not path.is_file():
            raise FactoryError(f'{recipe.project}: copy source {rule.src} missing at {commit[:12]}')
        generated.append((rule.dst, path.read_text(encoding='utf-8', errors='replace')))
    generated += [(rule.path, rule.text) for rule in eff['write']]
    files = [f for f in select_files(root, eff['sources'], eff['exclude']) if f.endswith('.c')]
    files += [g for g, _ in generated if g.endswith('.c') and g not in files]
    deps = []
    for dep in recipe.depends:
        dep_recipe = book.get(dep.project)
        if dep_recipe is None:
            raise FactoryError(f'{recipe.project}: dependency recipe {dep.project} missing')
        dep_root = checkout_dir(store, dep.project, dep.commit)
        if not (receipt(dep_root) or {}).get('verified'):
            raise FactoryError(f'{recipe.project}: dependency {dep.project}@{dep.commit[:12]} is not fetched')
        dep_eff = dep_recipe.resolved(dep.ref, dep.commit)
        deps.append((dep.project, dep_root, tuple(f for f in select_files(dep_root, dep_eff['sources'],
                                                                         dep_eff['exclude']) if f.endswith('.c'))))
    if not files:
        raise FactoryError(f'{recipe.project}@{ref}: the recipe selects no C files')
    return BaseSource(project=recipe.project, lineage=pair_id('L', recipe.project), family=recipe.family,
                      source={'git': recipe.upstream_git, 'commit': commit, 'ref': ref,
                              'license_spdx': recipe.license_spdx},
                      root=root, files=tuple(sorted(files)), output=recipe.output,
                      profile='mingw-gcc' if recipe.libc == 'mingw' else 'msvc-free',
                      include_dirs=tuple(eff['include_dirs']) or ('.',), defines=tuple(eff['defines']),
                      cflags=recipe.cflags, generated=tuple(generated), dependencies=tuple(deps),
                      source_date_epoch=int(done.get('commit_time') or 0), tag=ref, libs=tuple(eff['libs']))


CARD_KIND_DEFAULT = {'bounds-only': 'bounds-check-change', 'constant-only': 'constant-change',
                     'cve-fix': 'security-fix', 'release': 'source-diff', 'large-rewrite': 'large-rewrite'}


def card_kinds(card: C.CaseCard) -> dict[str, str]:
    out = {}
    for fn in card.changed_functions:
        kind = (fn.kind or '').strip().lower()
        out[fn.name] = kind if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', kind) else \
            CARD_KIND_DEFAULT.get(card.kind, 'source-diff')
    return out


def run_card(session: Session, book: C.RecipeBook, card: C.CaseCard, *, method: str = 'case-card',
             opt: str = 'O2') -> dict:
    """Build and label one case card. Raises FactoryError('no-recipe ...') / ('... not fetched')."""
    recipe = book.get(card.project)
    if recipe is None:
        raise FactoryError(f'no-recipe: {card.project}')
    old_base = recipe_base(book, recipe, card.old.ref, card.old.commit, session.store)
    new_base = recipe_base(book, recipe, card.new.ref, card.new.commit, session.store)
    old_b = session.build(old_base.spec(opt=opt, variant='old'))
    new_b = session.build(new_base.spec(opt=opt, variant='new'))
    if old_b.sha256 == new_b.sha256:
        raise IdenticalImages(f'{card.id}: old and new build to byte-identical engine images (source-only change); '
                              'no discriminating pair exists, so none is emitted (it is not an A/A pair either)')
    old, new = session.side(old_b, old_base.root), session.side(new_b, new_base.root)
    stratum = card.stratum
    source = 'source-diff' if stratum == 'release' else 'fix-diff'
    functions = label_diff(old, new, label_source=source, declared_changed=card_kinds(card),
                           declared_unchanged=tuple(card.unchanged_controls))
    missing = sorted(set(card_kinds(card)) - {f['name'] for f in functions})
    disagree = sum(1 for f in functions if f['check'] == 'disagree')
    case = {'card': card.id, 'kind': card.kind, 'cve': list(card.cve), 'sources': list(card.sources)[:20],
            'declared_changed': sorted(card_kinds(card)), 'declared_missing_in_images': missing,
            'declared_unchanged': list(card.unchanged_controls), 'disagreements': disagree,
            'semantic_change_declared': card.semantic_change}
    notes = []
    if missing:
        notes.append(f'declared changed functions without code in either image: {", ".join(missing)[:400]}')
    if not card.semantic_change and any(f['label'] == 'changed' for f in functions):
        notes.append('card declares no semantic change but source and code changed in some functions')
    if method == 'case-card':
        pass
    elif method not in ('release-pair', 'cve-pair'):
        raise FactoryError(f'unknown card method {method}')
    return finalize(pid=pair_id(card.id, opt), stratum=stratum, method=method, base_old=old_base,
                    base_new=new_base, old=old, new=new, label_source=source, functions=functions, case=case,
                    notes=notes)


def load_card_files(paths: Iterable[Path]) -> list[C.CaseCard]:
    cards = []
    for path in sorted(paths):
        cards += C.load_cards(Path(path).read_bytes())
    return cards


# ---- I6 same-source pairs: A/A rebuild, layout, toolchain noise ---------------------------------------------------

def run_aa(session: Session, base: BaseSource, *, opt: str = 'O2', layout: bool = True) -> list[dict]:
    a = session.build(base.spec(opt=opt, variant='aa-a'))
    b = session.build(base.spec(opt=opt, variant='aa-b'))
    sa, sb = session.side(a, base.root), session.side(b, base.root)
    same, sections, count = compare_images(read_pe(a.engine_image), read_pe(b.engine_image))
    dsame, dsections, dcount = compare_images(read_pe(a.debug_image), read_pe(b.debug_image))
    repro = {'byte_identical': same and dsame,
             'differing_sections': sorted(set(sections) | {f'debug:{s}' for s in dsections}),
             'differing_bytes': count + dcount,
             'detail': 'engine and debug images rebuilt in two different scratch directories'}
    docs = [finalize(pid=pair_id('aa', base.project, base.tag, opt, 'rebuild'), stratum='aa', method='aa-rebuild',
                     base_old=base, base_new=base, old=sa, new=sb, label_source='same-source',
                     functions=label_construction(sa, sb, label_source='same-source', semantic=False),
                     case={'kind': 'rebuild', 'opt': opt}, reproducibility=repro)]
    if layout and len(base.files) + sum(len(d[2]) for d in base.dependencies) > 1:
        for order in ('reversed', 'rotated'):
            c = session.build(base.spec(opt=opt, link_order=order, variant=f'aa-{order}'))
            if c.sha256 == a.sha256:
                continue
            sc = session.side(c, base.root)
            docs.append(finalize(pid=pair_id('aa', base.project, base.tag, opt, order), stratum='aa',
                                 method='aa-layout', base_old=base, base_new=base, old=sa, new=sc,
                                 label_source='same-source',
                                 functions=label_construction(sa, sc, label_source='same-source', semantic=False),
                                 case={'kind': 'link-order', 'order': order, 'opt': opt}))
    return docs


def run_nuisance(session: Session, base: BaseSource, kinds: Sequence[str], *, opt: str = 'O2'
                 ) -> tuple[list[dict], list[str]]:
    """P1 pairs beyond link order: the rebuild `aa-a` against the same source built with one nuisance. An identical image
    is kept (it is an X-versus-X pair, a stricter check); a variant the toolchain cannot build is listed as skipped."""
    docs, skipped = [], []
    a = session.build(base.spec(opt=opt, variant='aa-a'))
    sa = session.side(a, base.root)
    for kind in kinds:
        try:
            c = session.build(base.spec(opt=opt, variant=f'aa-{kind}', nuisance=kind))
        except (Blocked, BuildError) as exc:
            skipped.append(f'{kind}: {exc}'[:300])
            continue
        sc = session.side(c, base.root)
        docs.append(finalize(pid=pair_id('aa', base.project, base.tag, opt, kind), stratum='aa', method='aa-layout',
                             base_old=base, base_new=base, old=sa, new=sc, label_source='same-source',
                             functions=label_construction(sa, sc, label_source='same-source', semantic=False),
                             case={'kind': 'nuisance', 'nuisance': kind, 'opt': opt}))
    return docs, skipped


def run_chains(session: Session, base: BaseSource, chains: Sequence[tuple[str, str]], *, opt: str = 'O2'
               ) -> tuple[list[dict], list[str]]:
    """Three-build chains of one source for the metamorphic gate: A is the `aa-a` rebuild, B and C are built with the two
    nuisances of a chain; the pairs A-B, B-C and A-C are P1 pairs (same source, so any real change is a bug)."""
    docs, skipped = [], []
    a = session.build(base.spec(opt=opt, variant='aa-a'))
    for first, second in chains:
        name = f'{first}-{second}'
        try:
            b = session.build(base.spec(opt=opt, variant=f'aa-{first}', nuisance=first))
            c = session.build(base.spec(opt=opt, variant=f'aa-{second}', nuisance=second))
        except (Blocked, BuildError) as exc:
            skipped.append(f'chain {name}: {exc}'[:300])
            continue
        sides = [session.side(x, base.root) for x in (a, b, c)]
        for leg, (i, j) in (('ab', (0, 1)), ('bc', (1, 2)), ('ac', (0, 2))):
            docs.append(finalize(pid=pair_id('aa', base.project, base.tag, opt, 'chain', name, leg), stratum='aa',
                                 method='aa-layout', base_old=base, base_new=base, old=sides[i], new=sides[j],
                                 label_source='same-source',
                                 functions=label_construction(sides[i], sides[j], label_source='same-source',
                                                              semantic=False),
                                 case={'kind': 'chain', 'chain': name, 'leg': leg, 'opt': opt}))
    return docs, skipped


def noise_variants(base: BaseSource, tools: Toolchain) -> list[tuple[str, str, str, str]]:
    """(profile_a, opt_a, profile_b, opt_b) pairs that can build here."""
    out = [(base.profile, a, base.profile, b) for a, b in NOISE_OPT_PAIRS]
    if base.profile == 'mingw-gcc' and tools.profile_status('mingw-clang') is None:
        out.append(('mingw-gcc', 'O2', 'mingw-clang', 'O2'))
    if base.profile == 'msvc-free' and tools.profile_status('mingw-gcc') is None:
        out.append(('msvc-free', 'O2', 'mingw-gcc', 'O2'))
    # the real-compiler shift (LBL s2): the base profile against `cl`, and `cl` against the free MSVC-style leg
    if base.profile in ('mingw-gcc', 'msvc-free') and tools.profile_status('msvc') is None:
        out.append((base.profile, 'O2', 'msvc', 'O2'))
    if base.profile == 'msvc' and tools.profile_status('msvc-free') is None:
        out.append(('msvc', 'O2', 'msvc-free', 'O2'))
    return out


def run_noise(session: Session, base: BaseSource, variants: Sequence[tuple[str, str, str, str]] | None = None
              ) -> tuple[list[dict], list[str]]:
    docs, skipped = [], []
    for pa, oa, pb, ob in variants or noise_variants(base, session.tools):
        try:
            a = session.build(base.spec(opt=oa, profile=pa, variant=f'noise-{pa}-{oa}'.lower()))
            b = session.build(base.spec(opt=ob, profile=pb, variant=f'noise-{pb}-{ob}'.lower()))
        except (Blocked, BuildError) as exc:
            skipped.append(f'{pa}-{oa} vs {pb}-{ob}: {exc}'[:300])
            continue
        if a.sha256 == b.sha256:
            skipped.append(f'{pa}-{oa} vs {pb}-{ob}: identical images (no noise to measure)')
            continue
        sa, sb = session.side(a, base.root), session.side(b, base.root)
        old_base, new_base = replace(base, profile=pa), replace(base, profile=pb)
        docs.append(finalize(pid=pair_id('noise', base.project, base.tag, f'{pa}-{oa}', f'{pb}-{ob}'),
                             stratum='noise', method='toolchain-noise', base_old=old_base, base_new=new_base,
                             old=sa, new=sb, label_source='same-source',
                             functions=label_construction(sa, sb, label_source='same-source', semantic=False),
                             case={'kind': 'toolchain', 'older': f'{pa}/{oa}', 'newer': f'{pb}/{ob}'}))
    return docs, skipped


# ---- I5 planted mutations ------------------------------------------------------------------------------------------

def read_sources(root: Path) -> dict[str, str]:
    """Every regular text source/header under `root` as {posix relative path: text} (symlinks are refused)."""
    files = {}
    for path in sorted(Path(root).rglob('*')):
        if path.is_symlink():
            raise FactoryError(f'{path} is a symbolic link; mutation inputs must be plain files')
        if path.is_file() and path.suffix in ('.c', '.h'):
            files[path.relative_to(root).as_posix()] = path.read_text(encoding='utf-8')
    return files


def run_mutation(session: Session, base: BaseSource, operator: str, seed: int, *, opt: str = 'O2') -> dict:
    """Plant one `operator` mutation (deterministic in `seed`), build base and mutant, label by SPEC-32 s7 row 3."""
    from ..mutations import engine as M
    from ..mutations import labels as ML
    files = read_sources(base.root)
    ref = C.SourceRef(**base.source)
    outcome = M.apply_case(files, operator, seed=seed, base=ref, tools=session.tools)
    case = outcome.case
    mut_root = Path(session.store) / 'mutants' / case.case_id
    for rel, text in outcome.files.items():
        target = mut_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8', newline='\n')
    new_base = replace(base, root=mut_root, tag=f'{base.tag}-{case.case_id}'[:64],
                       source={**base.source, 'mutation': case.case_id})
    old_b = session.build(base.spec(opt=opt, variant='base'))
    new_b = session.build(new_base.spec(opt=opt, variant=case.case_id[:32].lower()))
    if old_b.sha256 == new_b.sha256:
        raise IdenticalImages(f'{case.case_id}: the mutant builds to a byte-identical engine image')
    old, new = session.side(old_b, base.root), session.side(new_b, mut_root)
    label, kind = ML.target_label(operator)
    helpers = (case.helper,) if case.helper else ()
    functions = label_construction(old, new, label_source='planted-mutation', semantic=case.kind == 'semantic',
                                   declared={case.target_function: (label, kind)}, helpers=helpers)
    disagree = sum(1 for f in functions if f['check'] == 'disagree')
    info = {'kind': 'mutation', 'mutation_case': case.model_dump(mode='json'), 'opt': opt, 'disagreements': disagree}
    return finalize(pid=pair_id('mutation', base.project, base.tag, operator, str(seed), opt),
                    stratum='mutation', method='mutation', base_old=base, base_new=new_base, old=old, new=new,
                    label_source='planted-mutation', functions=functions, case=info)
