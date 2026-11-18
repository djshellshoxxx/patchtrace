"""PE-6 (audit 20261015): an import table that ENDS exactly at a cap is complete. Only a table with a further entry
past the cap is over cap. Synthetic PEs from tests/pe_builder.py; nothing is executed."""
from __future__ import annotations

from pathlib import Path

import pytest
from pe_builder import PeSpec, build_pe, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview.api_delta import compute_api_delta
from patchtrace.pe_overview.inspect import DEFAULT_LIMITS
from patchtrace.pe_overview.tables import PeTables

DLLS, PER_DLL, TOTAL = 512, 4096, 20000
BOUNDARY = [(-1, False), (0, False), (1, True)]
IDS = ['cap_minus_1', 'at_cap', 'cap_plus_1']


def run(tmp_path: Path, data: bytes, **kw):
    path = tmp_path / 'sample.bin'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader, **kw)


def codes(ov) -> set[str]:
    return {w.code for w in ov.warnings}


def test_the_caps_under_test_are_the_documented_defaults():
    assert (DEFAULT_LIMITS.max_import_dlls, DEFAULT_LIMITS.max_functions_per_dll,
            DEFAULT_LIMITS.max_total_names) == (DLLS, PER_DLL, TOTAL)


@pytest.mark.parametrize(('extra', 'over'), BOUNDARY, ids=IDS)
def test_dll_cap_boundary(tmp_path, extra, over):
    count = DLLS + extra
    ov = run(tmp_path, build_pe(PeSpec(imports={f'd{i:03}.dll': ['f', i + 1] for i in range(count)})))
    assert ('import_dlls_over_cap' in codes(ov)) is over
    assert ov.imports.truncated is over and ov.status == ('partial' if over else 'ok')
    kept = min(count, DLLS)
    assert [d.name for d in ov.imports.dlls] == [f'd{i:03}.dll' for i in range(kept)]
    assert ov.imports.total_dlls == kept and ov.imports.total_functions == 2 * kept
    assert not any(d.truncated for d in ov.imports.dlls)


@pytest.mark.parametrize(('extra', 'over'), BOUNDARY, ids=IDS)
def test_per_dll_function_cap_boundary(tmp_path, extra, over):
    count = PER_DLL + extra
    funcs = ['first'] + list(range(2, count)) + ['last']
    ov = run(tmp_path, build_pe(PeSpec(imports={'big.dll': funcs, 'next.dll': ['after']})))
    assert ('import_functions_over_cap' in codes(ov)) is over
    big, nxt = ov.imports.dlls
    assert big.truncated is over and ov.imports.truncated is over and ov.status == ('partial' if over else 'ok')
    kept = min(count, PER_DLL)
    assert big.function_count == kept == len(big.functions) and big.functions[:2] == ('first', '#2')
    assert (big.functions[-1] == 'last') is not over
    assert nxt.functions == ('after',) and not nxt.truncated   # one DLL over its cap does not hide the next one


@pytest.mark.parametrize(('extra', 'over'), BOUNDARY, ids=IDS)
def test_total_name_cap_boundary(tmp_path, extra, over):
    sizes = [4000, 4000, 4000, 4000, 4000 + extra]
    spec = PeSpec(imports={f'd{n}.dll': list(range(1, size + 1)) for n, size in enumerate(sizes)})
    ov = run(tmp_path, build_pe(spec))
    assert ('import_names_over_cap' in codes(ov)) is over
    assert ov.imports.truncated is over and ov.status == ('partial' if over else 'ok')
    assert ov.imports.total_functions == min(sum(sizes), TOTAL) and len(ov.imports.dlls) == 5
    assert [d.truncated for d in ov.imports.dlls] == [False] * 4 + [over]


def test_total_name_cap_reached_exactly_still_lists_later_dlls_without_names(tmp_path):
    spec = PeSpec(imports={'a.dll': [1, 2], 'b.dll': [3, 4], 'c.dll': []})
    ov = run(tmp_path, build_pe(spec), limits=Limits(max_total_names=4))
    assert ov.status == 'ok' and not ov.imports.truncated
    assert [(d.name, d.function_count) for d in ov.imports.dlls] == [('a.dll', 2), ('b.dll', 2), ('c.dll', 0)]
    over = run(tmp_path, build_pe(PeSpec(imports={'a.dll': [1, 2], 'b.dll': [3, 4], 'c.dll': [5]})),
               limits=Limits(max_total_names=4))
    assert 'import_names_over_cap' in codes(over) and over.imports.truncated
    assert [(d.name, d.function_count, d.truncated) for d in over.imports.dlls] == [
        ('a.dll', 2, False), ('b.dll', 2, False), ('c.dll', 0, True)]


def test_entry_at_the_cap_that_is_not_the_terminator(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'a.dll': ['f'], 'b.dll': ['g']}))
    off = info['import_desc_off']
    repeated = bytearray(data)
    repeated[off + 40:off + 60] = repeated[off:off + 20]     # a third descriptor (a repeat of the first), no terminator
    ov = run(tmp_path, bytes(repeated), limits=Limits(max_import_dlls=2))
    assert 'import_dlls_over_cap' in codes(ov) and 'import_descriptor_loop' not in codes(ov)
    assert ov.imports.truncated and [d.name for d in ov.imports.dlls] == ['a.dll', 'b.dll']
    cut = data[:off + 40]                                     # the file ends where the terminator should be
    ov = run(tmp_path, cut, limits=Limits(max_import_dlls=2))
    assert 'import_rva_out_of_file' in codes(ov) and 'import_dlls_over_cap' not in codes(ov)
    assert ov.imports.truncated and ov.imports.total_dlls == 2


def test_cancellation_is_still_polled_once_per_descriptor_and_thunk(tmp_path):
    data = build_pe(PeSpec(imports={'a.dll': [1, 2, 3], 'b.dll': [4, 5, 6]}))
    polls = []

    def cancel() -> bool:
        polls.append(1)
        return False

    run(tmp_path, data, cancel=cancel)
    baseline = len(polls)
    polls.clear()
    at_cap = run(tmp_path, data, cancel=cancel, limits=Limits(max_import_dlls=2, max_functions_per_dll=3,
                                                              max_total_names=6))
    assert at_cap.status == 'ok' and len(polls) == baseline   # reading the terminators costs no extra poll


def test_complete_table_at_the_dll_cap_feeds_api_delta_and_import_slots(tmp_path):
    older = PeSpec(imports={f'd{i:03}.dll': ['f'] for i in range(DLLS)})
    newer = PeSpec(imports={f'd{i:03}.dll': ['f', 'g'] if i == 7 else ['f'] for i in range(DLLS)})
    old_ov, new_ov = run(tmp_path, build_pe(older)), run(tmp_path, build_pe(newer))
    delta = compute_api_delta(older=old_ov, newer=new_ov)
    assert delta.status == 'changed' and (delta.older_count, delta.newer_count) == (DLLS, DLLS + 1)
    assert [(c.dll, c.name, c.change) for c in delta.changes] == [('d007.dll', 'g', 'added')]
    path = tmp_path / 'slots.bin'
    path.write_bytes(build_pe(older))
    with VerifiedArtifactReader.open_path(path) as reader:
        slots = PeTables.open(reader).import_slots()
    assert len(slots) == DLLS and set(slots.values()) == {(f'd{i:03}.dll', 'f') for i in range(DLLS)}
