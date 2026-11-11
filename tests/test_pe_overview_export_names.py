"""PE-7 (audit 20261015): binding many export names to one ordinal is linear, with the output of the list-scan
implementation it replaces (kept below as the oracle). Synthetic PEs from tests/pe_exports_builder.py; nothing is
executed or loaded."""
from __future__ import annotations

import random
import time
from pathlib import Path

from pe_exports_builder import ExportSpec, build_exports, patch

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview import exports_table as module
from patchtrace.pe_overview._common import Ctx
from patchtrace.pe_overview.imports_exports import _name_at
from patchtrace.pe_overview.models import SectionMap

CAP = Limits().max_export_names
_POLL = 1024


def _bind_names_base(ctx: Ctx, smap: SectionMap, pointers: list[int],
                     indexes: list[int]) -> tuple[dict[int, list[str]], set[int], bool]:
    """The implementation at origin/main 882d1ca0, verbatim: the oracle. Do not "fix" it."""
    by_index: dict[int, list[str]] = {}
    mentioned: set[int] = set()
    seen: set[int] = set()
    lost = False
    for j, (pointer, index) in enumerate(zip(pointers, indexes, strict=False)):
        if j % _POLL == 0:
            ctx.check()
        mentioned.add(index)
        if pointer in seen:
            ctx.warn('export_name_table_loop', 'an export name pointer is repeated; later repeats were skipped')
            lost = True
            continue
        seen.add(pointer)
        found = _name_at(ctx, smap, pointer) if pointer else None
        if found is None:
            ctx.warn('export_rva_out_of_file', 'an export name RVA is null or not backed by file data')
            lost = True
            continue
        name, cut = found
        lost = lost or cut
        if name not in by_index.setdefault(index, []):
            by_index[index].append(name)
    return by_index, mentioned, lost


def parse_with(monkeypatch, path: Path, data: bytes, binder=None, limits: Limits | None = None):
    """(table, warnings, what the binder returned) with `binder` in place of the module's `_bind_names`."""
    binder = binder or module._bind_names
    bound = []

    def recording(*args):
        result = binder(*args)
        bound.append((list(result[0].items()), sorted(result[1]), result[2]))  # key order and name order kept
        return result

    path.write_bytes(data)
    with monkeypatch.context() as patched, VerifiedArtifactReader.open_path(path) as reader:
        patched.setattr(module, '_bind_names', recording)
        ov = inspect_pe(reader)
        directory = ov.directory('Export')
        ctx = Ctx(reader, None, limits or Limits())
        table = module.parse_export_entries(ctx, ov.section_map(), directory.rva, directory.size)
        return table, [(w.code, w.message) for w in ctx.warnings], bound


def random_table(rng: random.Random) -> bytes:
    """A small table that binds several names to few slots. `\\x01` and `\\x02` both display as `?`, so two different
    strings can give the same name, and patched pointers add repeats, suffixes, nulls and unreadable names."""
    slots = rng.randint(1, 4)
    texts = [''.join(rng.choice('ab\x01\x02') for _ in range(rng.randint(1, 3))) for _ in range(rng.randint(1, 14))]
    spec = ExportSpec(functions=[rng.choice([0x1000, 0x1010, None, 'F.g']) for _ in range(slots)],
                      names=[(text, rng.randint(0, slots + 1)) for text in texts], base=rng.randint(0, 3))
    data, lay = build_exports(spec)
    for i in range(len(texts)):
        kind = rng.randint(0, 9)
        at = lay.off(lay.names_rva) + 4 * i
        other = lay.strings[rng.choice(texts)]
        if kind == 0:
            data = patch(data, at, '<I', 0)
        elif kind == 1:
            data = patch(data, at, '<I', 0x7FFF0000)          # outside every section
        elif kind == 2:
            data = patch(data, at, '<I', other)               # another entry's pointer: possibly a repeat
        elif kind == 3:
            data = patch(data, at, '<I', other + 1)           # a suffix of another name (or its empty tail)
    return data


def test_same_binding_as_the_list_scan_on_200_seeded_tables(tmp_path, monkeypatch):
    rng = random.Random(20261015)
    aliased = lossy = looped = 0
    for case in range(200):
        data = random_table(rng)
        new = parse_with(monkeypatch, tmp_path / 'new.dll', data)
        old = parse_with(monkeypatch, tmp_path / 'old.dll', data, _bind_names_base)
        assert new == old, f'case {case}'
        (by_index, _mentioned, lost), = new[2]
        aliased += any(len(names) > 1 for _index, names in by_index)
        lossy += lost
        looped += any(code == 'export_name_table_loop' for code, _message in new[1])
    assert aliased >= 50 and lossy >= 50 and looped >= 20     # the generator really reaches the interesting cases


def test_two_strings_with_the_same_display_text_on_one_slot_are_one_entry(tmp_path, monkeypatch):
    spec = ExportSpec(functions=[0x1000, 0x1010], names=[('n\x01', 0), ('n\x02', 0), ('n\x01x', 0), ('n\x03', 1)])
    table, warnings, bound = parse_with(monkeypatch, tmp_path / 's.dll', build_exports(spec)[0])
    assert bound == [([(0, ['n?', 'n?x']), (1, ['n?'])], [0, 1], False)]
    assert [(e.name, e.ordinal) for e in table.entries] == [('n?', 1), ('n?x', 1), ('n?', 2)] and warnings == []


class _Counted(str):
    """A name that counts how often it is compared for equality, and stops a run that compares far too often."""
    __slots__ = ()
    calls = 0
    budget = 0

    def __eq__(self, other):
        cls = type(self)
        cls.calls += 1
        assert cls.calls <= cls.budget, 'name binding compared names more often than a linear pass may'
        return str.__eq__(self, other)

    __hash__ = str.__hash__


def _counting(monkeypatch, budget: int) -> None:
    _Counted.calls, _Counted.budget = 0, budget

    def name_at(ctx, smap, rva):
        found = _name_at(ctx, smap, rva)
        return found if found is None else (_Counted(found[0]), found[1])

    monkeypatch.setattr(module, '_name_at', name_at)


def test_names_on_one_ordinal_are_compared_a_linear_number_of_times(tmp_path, monkeypatch):
    spec = ExportSpec(functions=[0x1000], names=[(f'n{i:05}', 0) for i in range(CAP)])
    data = build_exports(spec)[0]
    _counting(monkeypatch, 2 * CAP)      # the list scan needs CAP * (CAP - 1) / 2 = 199,990,000 comparisons
    table, warnings, _bound = parse_with(monkeypatch, tmp_path / 's.dll', data)
    assert [(e.name, e.ordinal, e.rva, e.forwarder) for e in table.entries] == [
        (f'n{i:05}', 1, 0x1000, None) for i in range(CAP)]
    assert not table.truncated and warnings == [] and _Counted.calls <= 2 * CAP


def test_equal_names_from_different_strings_on_one_ordinal_stay_linear(tmp_path, monkeypatch):
    # 20,000 different strings that display as 2,500 names (runs of `?`), eight strings to a name.
    count = 20_000
    spec = ExportSpec(functions=[0x1000], names=[(chr(1 + i % 8) * (1 + i // 8), 0) for i in range(count)])
    limits = Limits(max_name_length=4096)
    _counting(monkeypatch, 2 * count)
    table, warnings, bound = parse_with(monkeypatch, tmp_path / 's.dll', build_exports(spec)[0], limits=limits)
    lengths = sorted(len(name) for name in bound[0][0][0][1])
    assert lengths == list(range(1, count // 8 + 1)) and len(table.entries) == count // 8 and warnings == []


def _best_of_three(tmp_path, spec: ExportSpec) -> float:
    """Seconds for the export-entry parse alone (not for hashing and inspecting the file), best of three."""
    path = tmp_path / 't.dll'
    path.write_bytes(build_exports(spec)[0])
    best = None
    with VerifiedArtifactReader.open_path(path) as reader:
        ov = inspect_pe(reader)
        directory, smap = ov.directory('Export'), ov.section_map()
        for _ in range(3):
            ctx = Ctx(reader, None, Limits())
            started = time.perf_counter()
            table = module.parse_export_entries(ctx, smap, directory.rva, directory.size)
            spent = time.perf_counter() - started
            assert len(table.entries) == CAP and not table.truncated
            best = spent if best is None else min(best, spent)
    return best


def test_twenty_thousand_names_on_one_ordinal_cost_about_what_one_name_per_ordinal_costs(tmp_path):
    # A relative bound, never an absolute time: the same number of names spread over as many slots is the yardstick.
    # Measured at 882d1ca0: 1.62 s on one ordinal against 0.25 s spread (6.5 times); a linear pass is about 1 time.
    spread = _best_of_three(tmp_path, ExportSpec(
        functions=[0x1000] * CAP, names=[(f'n{i:05}', i) for i in range(CAP)]))
    one = _best_of_three(tmp_path, ExportSpec(
        functions=[0x1000], names=[(f'n{i:05}', 0) for i in range(CAP)]))
    assert 3 * spread >= one, f'one ordinal {one:.3f} s, one name per ordinal {spread:.3f} s'
