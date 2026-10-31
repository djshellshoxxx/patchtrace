"""Per-function known answers for one older/newer pair (SPEC-32 s5, s7).

Evidence per function: identity join on (file, name, variant) (qualified by compile unit when a key repeats), the source
change of its span (csrc.compare_spans) and the image body fact (raw / address-masked hashes). The decision table of
SPEC-32 s7 turns the evidence into labels; when evidence conflicts the record is `ambiguous` with the reason.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .bodyhash import Disassembly, body_fact, disassemble, hash_functions
from .build import BuildResult
from .contracts import masked_body_must_match
from .csrc import FunctionDef, Source, compare_spans
from .debuginfo import ImageFunction, Inventory, inventory
from .pe import read_pe
from .toolchain import Toolchain

Key = tuple[str | None, str, str | None]
DEPENDENCY_PREFIX = '_dep/'


@dataclass
class SideData:
    build: BuildResult
    inventory: Inventory
    hashes: dict[int, tuple[str, str]]
    source_root: Path
    disasm: Disassembly | None = None
    _sources: dict[str, Source | None] = field(default_factory=dict)

    @property
    def functions(self) -> list[ImageFunction]:
        return [f for f in self.inventory.project() if not (f.file or '').startswith(DEPENDENCY_PREFIX)]

    def source(self, rel: str | None) -> Source | None:
        if rel is None:
            return None
        if rel not in self._sources:
            path = self.source_root / rel
            try:
                ok = path.is_file() and not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024
                self._sources[rel] = Source(path.read_text(encoding='utf-8', errors='replace')) if ok else None
            except OSError:
                self._sources[rel] = None
        return self._sources[rel]

    def span(self, fn: ImageFunction) -> tuple[Source | None, FunctionDef | None]:
        src = self.source(fn.file)
        if src is None:
            return None, None
        hit = src.function_at_line(fn.line) if fn.line else None
        if hit is None:
            named = src.by_name(fn.name)
            hit = named[0] if len(named) == 1 else None
        return src, hit


def analyze(build: BuildResult, tools: Toolchain, source_root: Path) -> SideData:
    image = read_pe(build.debug_image)
    inv = inventory(image, tools, pdb=build.pdb)
    disasm = disassemble(image, tools)
    spans = [(f.rva, f.size) for f in inv.functions if f.origin == 'project']
    return SideData(build, inv, hash_functions(image, disasm, spans), Path(source_root), disasm)


@dataclass(frozen=True)
class Joined:
    old: ImageFunction | None
    new: ImageFunction | None
    ambiguous: str | None = None      # reason when identity is ambiguous


def join(old: list[ImageFunction], new: list[ImageFunction],
         renames: Mapping[str, str] | None = None) -> list[Joined]:
    """Identity join by (file, name, variant); repeated keys are qualified by compile unit; `renames` maps an old
    name to its new name (authored truth) before joining."""
    renames = dict(renames or {})

    def key(f: ImageFunction, side: str) -> Key:
        name = renames.get(f.name, f.name) if side == 'old' else f.name
        return (f.file, name, f.variant)

    def group(items, side):
        out: dict[Key, list[ImageFunction]] = {}
        for f in items:
            out.setdefault(key(f, side), []).append(f)
        return out

    go, gn = group(old, 'old'), group(new, 'new')
    result: list[Joined] = []
    for k in sorted(set(go) | set(gn), key=lambda k: (k[0] or '', k[1], k[2] or '')):
        a, b = go.get(k, []), gn.get(k, [])
        if len(a) <= 1 and len(b) <= 1:
            result.append(Joined(a[0] if a else None, b[0] if b else None))
            continue
        by_unit_a = {f.unit: f for f in a}
        by_unit_b = {f.unit: f for f in b}
        if len(by_unit_a) == len(a) and len(by_unit_b) == len(b):
            for unit in sorted(set(by_unit_a) | set(by_unit_b), key=lambda u: u or ''):
                result.append(Joined(by_unit_a.get(unit), by_unit_b.get(unit)))
            continue
        for f in a:
            result.append(Joined(f, None, f'key {k[1]} repeats in one image'))
        for f in b:
            result.append(Joined(None, f, f'key {k[1]} repeats in one image'))
    return result


def _record(j: Joined, *, identity: str, label: str, kind: str | None, body: str, source: str, check: str = 'unchecked',
            notes: str = '', taxonomy: tuple[str, ...] = ()) -> dict:
    ref = j.old or j.new
    return {'name': ref.name, 'file': ref.file, 'variant': ref.variant,
            'old_rva': j.old.rva if j.old else None, 'new_rva': j.new.rva if j.new else None,
            'old_size': j.old.size if j.old else None, 'new_size': j.new.size if j.new else None,
            'identity': identity, 'label': label, 'change_kind': kind, 'body': body, 'label_source': source,
            'check': check, 'taxonomy': list(taxonomy), 'notes': notes[:500]}


def _body(old: SideData, new: SideData, j: Joined) -> str:
    if j.old is None or j.new is None:
        return 'n/a'
    return body_fact(old.hashes.get(j.old.rva), new.hashes.get(j.new.rva))


def _inline_note(side: SideData, other: ImageFunction | None) -> str:
    if other is not None and (other.file, other.name) in side.inventory.inline_only:
        return 'no out-of-line copy on the other side (inlined away)'
    return ''


def label_diff(old: SideData, new: SideData, *, label_source: str,
               declared_changed: Mapping[str, str] | None = None,
               declared_unchanged: tuple[str, ...] = ()) -> list[dict]:
    """Release / CVE / control pairs (SPEC-32 s7 row 1). `declared_changed` (name -> kind) and
    `declared_unchanged` come from a case card and are cross-checked, never trusted blindly."""
    declared_changed = dict(declared_changed or {})
    out = []
    for j in join(old.functions, new.functions):
        body = _body(old, new, j)
        if j.ambiguous:
            out.append(_record(j, identity='ambiguous', label='ambiguous', kind=None, body='n/a', source=label_source,
                               notes=j.ambiguous))
            continue
        name = (j.old or j.new).name
        if j.old is None or j.new is None:
            check = 'disagree' if name in declared_changed or name in declared_unchanged else 'unchecked'
            note = _inline_note(new if j.new is None else old, j.old or j.new)
            out.append(_record(j, identity='no-counterpart', label='no-counterpart', kind=None, body='n/a',
                               source=label_source, check=check,
                               notes=note or ('declared by the case card but present on one side only'
                                              if check == 'disagree' else '')))
            continue
        src_old, fn_old = old.span(j.old)
        src_new, fn_new = new.span(j.new)
        state = compare_spans(src_old, fn_old, src_new, fn_new) if src_old and src_new else 'unknown'
        masked_equal = body in ('identical', 'address-only')
        if state == 'same-text' and masked_equal:
            label, kind, note = 'unchanged', None, ''
        elif state == 'layout-only' and masked_equal:
            label, kind, note = 'cosmetic', 'comment-whitespace', 'only comments/whitespace changed in the span'
        elif state == 'token-change' and not masked_equal:
            label, kind, note = 'changed', declared_changed.get(name) or 'source-diff', ''
        elif state == 'token-change':
            label, kind, note = 'ambiguous', None, 'source changed but code identical (inactive #if, dead code)'
        elif state in ('same-text', 'layout-only'):
            label, kind, note = 'ambiguous', None, 'source span unchanged but code differs (induced: header, macro, ' \
                                                   'inlining)'
        else:
            label, kind, note = 'ambiguous', None, 'source span not found'
        check = 'unchecked'
        if name in declared_changed:
            # D-04: an ambiguous row is explained but not verified; it must not count as agreement (plan 4.5).
            check = {'changed': 'ok', 'ambiguous': 'unchecked'}.get(label, 'disagree')
            if check == 'disagree':
                note = (note + '; ' if note else '') + f'card declares a change, evidence says {label}'
            elif check == 'unchecked':
                note = (note + '; ' if note else '') + 'card declares a change, evidence is ambiguous: not verified'
        elif name in declared_unchanged:
            check = {'unchanged': 'ok', 'cosmetic': 'ok', 'ambiguous': 'unchecked'}.get(label, 'disagree')
            if check == 'disagree':
                note = (note + '; ' if note else '') + 'card lists it as an unchanged control'
        out.append(_record(j, identity='same', label=label, kind=kind, body=body, source=label_source, check=check,
                           notes=note))
    return out


def label_construction(old: SideData, new: SideData, *, label_source: str, semantic: bool,
                       declared: Mapping[str, tuple[str, str]] | None = None,
                       helpers: tuple[str, ...] = (), renames: Mapping[str, str] | None = None) -> list[dict]:
    """Same-source (aa/noise) and planted-mutation pairs (SPEC-32 s7 rows 2-3). `declared` maps a target function
    name to (label, kind); everything else is unchanged, except that under a semantic mutation a function whose
    masked body changed becomes ambiguous (induced by the target)."""
    declared = dict(declared or {})
    targets = ', '.join(sorted(declared)) or 'none'
    out = []
    for j in join(old.functions, new.functions, renames):
        body = _body(old, new, j)
        name = (j.new or j.old).name
        if j.ambiguous:
            out.append(_record(j, identity='ambiguous', label='ambiguous', kind=None, body='n/a', source=label_source,
                               notes=j.ambiguous))
            continue
        if j.old is None or j.new is None:
            note = 'planted helper' if name in helpers else _inline_note(new if j.new is None else old,
                                                                         j.old or j.new)
            out.append(_record(j, identity='no-counterpart', label='no-counterpart', kind=None, body='n/a',
                               source=label_source, notes=note))
            continue
        if name in declared:
            label, kind = declared[name]
            check = 'ok'
            note = ''
            if label == 'changed' and body != 'different':
                check, note = 'disagree', 'planted semantic change left the masked body unchanged'
            elif label == 'cosmetic' and masked_body_must_match(kind) and body not in ('identical', 'address-only'):
                check, note = 'disagree', 'planted cosmetic change altered the masked body'
            out.append(_record(j, identity='same', label=label, kind=kind, body=body, source='planted-mutation',
                               check=check, notes=note))
            continue
        if semantic and body == 'different':
            out.append(_record(j, identity='same', label='ambiguous', kind=None, body=body, source=label_source,
                               notes=f'code differs although the source is unchanged (induced by {targets})'))
            continue
        out.append(_record(j, identity='same', label='unchanged', kind=None, body=body, source=label_source,
                           check='ok'))
    return out


SUITE_MAP = {'same': ('unchanged', None), 'changed': ('changed', None), 'cosmetic': ('cosmetic', 'cosmetic'),
             'moved': ('cosmetic', 'moved'), 'renamed': ('cosmetic', 'renamed')}


def label_authored(old: SideData, new: SideData, truth) -> tuple[list[dict], list[str]]:
    """Suite pairs (SPEC-32 s7 row 4): authored labels kept, every expectation cross-checked against the images.
    Returns (records, problems) where problems also include truth entries that name absent functions."""
    o_by = {f.name: f for f in old.functions}
    n_by = {f.name: f for f in new.functions}
    used_old, used_new, out, problems = set(), set(), [], []
    source = 'authored-truth'

    def present(name, table, side, entry_label):
        if name in table:
            return table[name]
        problems.append(f'{entry_label}: {name} has no out-of-line code in the {side} image')
        return None

    for entry in truth:
        label = entry.label
        tax = tuple(entry.taxonomy)
        if label in ('same', 'changed', 'cosmetic', 'moved'):
            a = present(entry.function, o_by, 'old', label)
            b = present(entry.function, n_by, 'new', label)
            if a is None or b is None:
                continue
            used_old.add(a.name)
            used_new.add(b.name)
            j = Joined(a, b)
            body = _body(old, new, j)
            mapped, kind = SUITE_MAP[label]
            kind = entry.kind or 'other' if label == 'changed' else kind
            expect_equal = label != 'changed'
            ok = (body in ('identical', 'address-only')) == expect_equal
            note = '' if ok else (f'authored {label} but the masked body '
                                  f'{"differs" if expect_equal else "is identical"}')
            if label == 'moved' and ok and a.file == b.file:
                ok, note = False, 'authored moved but the debug file did not change'
            out.append(_record(j, identity='same', label=mapped, kind=kind, body=body, source=source,
                               check='ok' if ok else 'disagree', notes=note or entry.notes, taxonomy=tax))
        elif label == 'renamed':
            a = present(entry.from_, o_by, 'old', label)
            b = present(entry.to, n_by, 'new', label)
            if a is None or b is None:
                continue
            used_old.add(a.name)
            used_new.add(b.name)
            j = Joined(a, b)
            body = _body(old, new, j)
            ok = body in ('identical', 'address-only')
            out.append(_record(j, identity='same', label='cosmetic', kind='renamed', body=body, source=source,
                               check='ok' if ok else 'disagree',
                               notes=(f'renamed {entry.from_} -> {entry.to}' +
                                      ('' if ok else '; masked body differs')), taxonomy=tax))
        elif label in ('added', 'removed', 'inlined'):
            table, side, other = (n_by, 'new', o_by) if label == 'added' else (o_by, 'old', n_by)
            f = present(entry.function, table, side, label)
            if f is None:
                continue
            (used_new if label == 'added' else used_old).add(f.name)
            j = Joined(None, f) if label == 'added' else Joined(f, None)
            ok = entry.function not in other
            note = f'inlined into {entry.into}' if label == 'inlined' else ''
            if label == 'inlined' and entry.into not in n_by:
                ok, note = False, f'inlined target {entry.into} has no code in the new image'
            out.append(_record(j, identity='no-counterpart', label='no-counterpart', kind=None, body='n/a',
                               source=source, check='ok' if ok else 'disagree',
                               notes=note if ok else (note or f'authored {label} but present on both sides'),
                               taxonomy=tax))
        elif label in ('split', 'merged'):
            olds = [entry.from_] if label == 'split' else list(entry.from_ or [])
            news = list(entry.to or []) if label == 'split' else [entry.to]
            for name in olds:
                f = present(name, o_by, 'old', label)
                if f is not None:
                    used_old.add(f.name)
                    out.append(_record(Joined(f, None), identity='ambiguous', label='ambiguous', kind=None,
                                       body='n/a', source=source, check='ok',
                                       notes=f'{label}: {",".join(olds)} -> {",".join(news)}', taxonomy=tax))
            for name in news:
                f = present(name, n_by, 'new', label)
                if f is not None:
                    used_new.add(f.name)
                    out.append(_record(Joined(None, f), identity='ambiguous', label='ambiguous', kind=None,
                                       body='n/a', source=source, check='ok',
                                       notes=f'{label}: {",".join(olds)} -> {",".join(news)}', taxonomy=tax))
    for name in sorted(set(o_by) - used_old):
        problems.append(f'old function {name} has code but no truth entry')
    for name in sorted(set(n_by) - used_new):
        problems.append(f'new function {name} has code but no truth entry')
    return out, problems


def image_side(build: BuildResult, *, source: dict, profile: str | None = None) -> dict:
    return {'sha256': build.sha256, 'debug_sha256': build.debug_sha256, 'pdb_sha256': build.pdb_sha256,
            'size': build.size, 'file_name': build.spec.output, 'image_base': build.image_base, 'source': source,
            'build': {'profile': profile or build.spec.profile, 'compiler': build.compiler,
                      'compiler_version': build.compiler_version, 'opt': build.spec.opt,
                      'recipe_digest': build.recipe_digest, 'link_order': build.spec.link_order,
                      'variant': build.spec.variant}}


def summary_extra(old: SideData, new: SideData) -> dict:
    absent = len({(f, n) for f, n in old.inventory.inline_only | new.inventory.inline_only})
    return {'runtime_functions': old.inventory.runtime_count() + new.inventory.runtime_count(),
            'absent_functions': absent}
