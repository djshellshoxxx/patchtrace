"""RB-01 measurement defects of the SPEC-31 live gates, found in run 41774865819.

G-U3: the `path` nuisance leaves the scratch source directory in the debug info; it was normalised to "no project file",
so the nuisance side had no project function and every function of the other side was labelled `no-counterpart`, which
contradicted every correct identity pairing. G-U2: the mutant images have no entry point, export or unwind table, so a
disassembler has no function seed and every planted function was `unpaired`. Pure inputs are synthetic; the compiler
part builds real images with the SPEC-32 `msvc-free` profile (BLOCKED, never a pass, without the tools)."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS)]
from tier_r_helpers import require  # noqa: E402

from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import debuginfo, labeler  # noqa: E402
from tools.calibration.tier_r.pe import read_pe  # noqa: E402
from tools.unified.mutations import driver, templates  # noqa: E402

SCRATCH = ('/tmp/store/build/proj-aa-path-x1y2/src', r'C:\Users\ci\store\build\proj-aa-path-x1y2\src')


@pytest.mark.parametrize('raw', ['/tmp/store/build/proj-aa-path-x1y2/src/a/b.c',
                                 r'C:\Users\CI\store\build\proj-aa-path-x1y2\src\a\b.c',
                                 'c:/users/ci/store/build/proj-aa-path-x1y2/src/a/b.c'], ids=['posix', 'drive', 'lower'])
def test_a_file_below_the_recorded_scratch_source_directory_is_project_relative(raw):
    assert debuginfo.normalize_path(raw) is None
    assert debuginfo.normalize_path(raw, SCRATCH) == 'a/b.c'


def test_a_file_outside_every_root_stays_runtime():
    assert debuginfo.normalize_path('/usr/lib/x.c', SCRATCH) is None
    assert debuginfo.normalize_path('/tmp/store/build/proj-aa-path-x1y2/srcother/x.c', SCRATCH) is None


def test_every_planted_candidate_is_exported_so_a_disassembler_has_a_function_seed():
    module = templates.generate('constant', 3, seed=1)
    for index in range(3):
        assert module.function_source(index).startswith(templates.EXPORT)
        assert all(module.function_source(index, a).startswith(templates.EXPORT) for a in range(module.attempts(index)))


class _Side:
    def __init__(self, functions):
        self.functions = functions


def test_a_same_source_pair_with_one_side_unlabelled_is_refused_not_labelled_no_counterpart():
    with pytest.raises(C.ContractError, match='no project function'):
        labeler.label_construction(_Side([object()]), _Side([]), label_source='same-source', semantic=False)


def _export_names(path: Path) -> list[str]:
    image = read_pe(path)
    rva, size = image.directories[0]
    if not rva:
        return []
    table = image.read(rva, 40)
    count, names_rva = struct.unpack_from('<I', table, 24)[0], struct.unpack_from('<I', table, 32)[0]
    pointers = struct.unpack(f'<{count}I', image.read(names_rva, 4 * count))
    return [image.read(p, 64).split(b'\0', 1)[0].decode() for p in pointers]


def _base(tmp_path, cid='constant', count=3):
    module = templates.generate(cid, count, seed=1)
    return module, driver._base(module, driver._write(tmp_path / 'base', module.base_source()), 'base')


def test_the_engine_image_of_a_mutant_module_exports_every_candidate(record_live_status, tmp_path):
    from tools.calibration.tier_r import factory as F
    session = F.Session(require(record_live_status, 'msvc-free'), tmp_path / 'store')
    module, base = _base(tmp_path)
    built = session.build(base.spec(variant='base'))
    assert sorted(_export_names(built.engine_image)) == sorted(module.names)


def test_the_path_nuisance_pair_labels_every_function_the_same_function(record_live_status, tmp_path):
    from tools.calibration.tier_r import factory as F
    session = F.Session(require(record_live_status, 'msvc-free'), tmp_path / 'store')
    module, base = _base(tmp_path)
    plain = session.side(session.build(base.spec(variant='aa-a')), base.root)
    path = session.side(session.build(base.spec(variant='aa-path', nuisance='path')), base.root)
    assert [f.file for f in path.functions] == [f.file for f in plain.functions] == ['mod.c'] * 3
    labels = labeler.label_construction(plain, path, label_source='same-source', semantic=False)
    assert {(f['identity'], f['old_rva'] == f['new_rva']) for f in labels} == {('same', True)}
