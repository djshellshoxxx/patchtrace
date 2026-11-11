"""PE-8 (audit 20261015): the `name_truncated` message names the limit that really cut the name. Only a name with more
than `max_name_length` bytes is "longer than" the cap; a name that meets the end of its section data first is reported
as that. Synthetic files and PEs (tests/pe_builder.py, tests/pe_exports_builder.py); nothing is executed."""
from __future__ import annotations

from pathlib import Path

import pytest
from pe_builder import PeSpec, build_pe
from pe_exports_builder import ExportSpec, build_exports, patch

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview._common import MAX_STRUCT_READ, Ctx
from patchtrace.pe_overview.exports_table import parse_export_entries

CAP = Limits().max_name_length
CAP_TEXT = f'a name longer than {CAP} bytes was truncated'


def cstring(tmp_path: Path, size: int, offset: int, limit: int | None, limits: Limits | None = None):
    """(result, name_truncated messages) of `Ctx.cstring` on a file of `size` bytes that holds no NUL at all."""
    path = tmp_path / 'blob.bin'
    path.write_bytes(b'A' * size)
    with VerifiedArtifactReader.open_path(path) as reader:
        ctx = Ctx(reader, None, limits or Limits())
        result = ctx.cstring(offset, limit)
        assert {w.code for w in ctx.warnings} <= {'name_truncated'}
        return result, [w.message for w in ctx.warnings]


def test_the_cap_under_test_is_the_documented_default():
    assert CAP == 512


def test_section_bounded_name_is_not_called_longer_than_the_cap(tmp_path):
    # The audit's reproduction: 300 mapped bytes, no terminator, 2000-byte file.
    result, messages = cstring(tmp_path, 2000, 0, 300)
    assert result == ('A' * 300, True)
    assert messages == [f'a name has no terminator before its section data ends; cut there after 300 bytes '
                        f'(the name limit is {CAP})']
    assert 'longer than' not in messages[0]


@pytest.mark.parametrize(('limit', 'kept', 'by_cap'), [
    (1, 1, False), (CAP - 1, CAP - 1, False), (CAP, CAP, False), (CAP + 1, CAP, True), (CAP + 300, CAP, True),
    (None, CAP, True),
], ids=['one_byte', 'cap_minus_1', 'at_cap', 'cap_plus_1', 'far_over', 'no_limit'])
def test_which_limit_applied_at_the_boundary(tmp_path, limit, kept, by_cap):
    # Exactly `CAP` mapped bytes without a terminator are not known to be a longer name: the section ended first.
    result, messages = cstring(tmp_path, 2000, 0, limit)
    assert result == ('A' * kept, True) and len(messages) == 1
    assert (messages[0] == CAP_TEXT) is by_cap
    assert ('section data ends' in messages[0]) is not by_cap


@pytest.mark.parametrize('limit', [None, 300, CAP + 1], ids=['no_limit', 'limit_at_eof', 'limit_past_eof'])
def test_name_that_runs_to_the_end_of_the_file_is_whole_and_silent(tmp_path, limit):
    # Unchanged behaviour, pinned: the file boundary is not reported as a truncation.
    assert cstring(tmp_path, 2000, 1700, limit) == (('A' * 300, False), [])


def test_read_clip_is_named_when_the_name_limit_is_above_one_read(tmp_path):
    limits = Limits(max_name_length=2 * MAX_STRUCT_READ)
    result, messages = cstring(tmp_path, 3 * MAX_STRUCT_READ, 0, None, limits)
    assert result == ('A' * MAX_STRUCT_READ, True)
    assert messages == [f'a name has no terminator within the {MAX_STRUCT_READ} bytes of one read; cut there '
                        f'(the name limit is {2 * MAX_STRUCT_READ})']
    bounded, messages = cstring(tmp_path, 3 * MAX_STRUCT_READ, 0, MAX_STRUCT_READ + 7, limits)
    assert bounded == ('A' * MAX_STRUCT_READ, True) and 'of one read' in messages[0]   # the read ended first


def test_export_name_cut_by_the_end_of_its_section(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000], names=[('Tail', 0)]))
    end = lay.off(lay.header_rva + lay.size)          # the last blob byte is the terminator of 'Tail'
    assert data[end - 5:end] == b'Tail\0' and len(data) > end
    path = tmp_path / 'cut.dll'
    path.write_bytes(patch(data, end - 1, '<B', ord('!')))
    with VerifiedArtifactReader.open_path(path) as reader:
        ov = inspect_pe(reader)
        directory = ov.directory('Export')
        ctx = Ctx(reader, None, Limits())
        table = parse_export_entries(ctx, ov.section_map(), directory.rva, directory.size)
    assert [(e.name, e.ordinal, e.rva) for e in table.entries] == [('Tail!', 1, 0x1000)] and table.truncated
    assert [(w.code, w.message) for w in ctx.warnings] == [
        ('name_truncated', f'a name has no terminator before its section data ends; cut there after 5 bytes '
                           f'(the name limit is {CAP})')]
    assert [w.message for w in ov.warnings if w.code == 'name_truncated'] == [ctx.warnings[0].message]


def test_overlong_import_name_keeps_the_cap_wording(tmp_path):
    path = tmp_path / 'long.exe'
    path.write_bytes(build_pe(PeSpec(imports={'A' * 700 + '.dll': ['f']})))
    with VerifiedArtifactReader.open_path(path) as reader:
        ov = inspect_pe(reader)
    assert [w.message for w in ov.warnings if w.code == 'name_truncated'] == [CAP_TEXT]
    assert ov.imports.dlls[0].name == 'A' * CAP
