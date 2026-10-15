"""WB3-S4 string to function links (L1 ghidra-xref, L4 decompiled-literal, L5 floss-frame) on the SYN-WB3-1 pair."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from strings_pe import IMAGE_BASE, builtin_table, floss_table, synergy_pair

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools.normalize import FunctionPairing, PeMap
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.strings import links
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.links import SideFunctions, ghidriff_strings, link_strings
from patchtrace.strings.scan import BuiltinScanSource
from patchtrace.strings.sources import SourceRow

PDIFF = Path(__file__).resolve().parent / 'fixtures' / 'strings' / 'pdiff' / 'synthetic-ghidriff-strings.json'
GROUP = 'ghidra:' + 'f' * 64
BASES = {'older': IMAGE_BASE, 'newer': IMAGE_BASE}


def sha(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


def src(text: str, *, type='static', enc='ASCII', rva=None, fn_rva=None) -> SourceRow:
    return SourceRow(sha(text), text, len(text), type, enc, None if rva is None else 0x400 + rva, rva, fn_rva,
                     None, None, None, 'tool-reported' if type != 'static' else 'verified-bytes')


def record(side: str, name: str, code: str | None = None, rva: int | None = 0x1000, **meta) -> FunctionRecord:
    return FunctionRecord(artifact_id=side, run_id='r', name=name, code=code, metadata=meta,
                          address=None if rva is None else hex(IMAGE_BASE + rva), address_space='virtual')


def project(older: list[FunctionRecord], newer: list[FunctionRecord], category='modified'):
    """One modified match per positional pair, plus the pairing and per-side function indexes."""
    matches = [FunctionMatch(run_id='r', category=category, older=[o], newer=[n]) for o, n in zip(older, newer, strict=True)]
    pairing = FunctionPairing.from_project(matches, None, older_base=IMAGE_BASE, newer_base=IMAGE_BASE)
    return matches, pairing, {side: SideFunctions.from_matches(matches, side, IMAGE_BASE) for side in BASES}


@pytest.fixture(scope='module')
def tables(tmp_path_factory):
    pair = synergy_pair()
    out = {}
    for side, data in (('older', pair.older), ('newer', pair.newer)):
        path = tmp_path_factory.mktemp(side) / 'a.bin'
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        reader = VerifiedArtifactReader.open_path(path, digest)
        try:
            pe = PeMap.from_reader(reader)
            result = BuiltinScanSource(path, artifact_sha256=digest, side=side,
                                       offset_to_rva=lambda off, pe=pe: pe.offset_to_rva(off)[0]).load()
        finally:
            reader.close()
        out[side] = builtin_table(side, digest, list(result.rows))
    return out


@pytest.fixture(scope='module')
def pdiff():
    raw = PDIFF.read_bytes()
    return ghidriff_strings(raw, expected_raw_sha256=hashlib.sha256(raw).hexdigest(), image_bases=BASES)


def by_text(result, side, text):
    return result.links.get((side, sha(text)), ())


def test_fixture_addresses_match_the_synthetic_images():
    document = json.loads(PDIFF.read_text(encoding='utf-8'))
    rva = synergy_pair().rva
    expected = {('added', 'index %u exceeds length %u'): rva['newer']['s_exceeds'],
                ('added', 'configuration loaded'): rva['newer']['s_loaded'],
                ('deleted', 'configuration loaded'): rva['older']['s_loaded'],
                ('deleted', 'debug dump of internal state'): rva['older']['s_debug']}
    got = {(k, item['name'].rsplit('_', 1)[0]): int(item['address'], 16) - IMAGE_BASE
           for k, items in document['strings'].items() for item in items}
    assert {v for v in expected.values()} <= set(got.values())


def test_l1_exact_join_names_the_modified_function(tables, pdiff):
    older, newer = [record('older', 'ParseHeader', upstream_name='ParseHeader')], [record('newer', 'ParseHeader')]
    _, pairing, functions = project(older, newer)
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    (link,) = by_text(result, 'newer', 'index %u exceeds length %u')
    assert (link.tier, link.join, link.pair_status) == ('L1', 'exact', 'modified')
    assert link.function.name == 'ParseHeader' and link.function.rva == 0x1000
    assert link.function.project_function_id == newer[0].id and link.function.match_id is not None
    assert link.evidence_ref == 'rva:0x2070' and link.lineage_group == GROUP


def test_l1_contains_join_when_the_address_falls_inside_a_string(tables, pdiff):
    _, pairing, functions = project([record('older', 'ParseHeader')], [record('newer', 'ParseHeader')])
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    (link,) = by_text(result, 'older', 'bad header (%s)')
    assert (link.tier, link.join, link.evidence_ref) == ('L1', 'contains', 'rva:0x2092')


def test_relocated_string_links_on_each_side_by_its_own_address(tables, pdiff):
    _, pairing, functions = project([record('older', 'ParseHeader')], [record('newer', 'ParseHeader')])
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    older = by_text(result, 'older', 'configuration loaded')
    newer = by_text(result, 'newer', 'configuration loaded')
    assert [lk.evidence_ref for lk in older] == ['rva:0x2070'] and [lk.evidence_ref for lk in newer] == ['rva:0x20b0']


def test_name_outside_the_match_set_is_shown_with_unknown_status(tables, pdiff):
    _, pairing, functions = project([record('older', 'ParseHeader')], [record('newer', 'ParseHeader')])
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    (link,) = by_text(result, 'newer', 'Software\\Vendor\\Product\\Mode')
    assert link.function.name == 'InitRegistry' and link.pair_status == 'unknown'
    assert link.function.project_function_id is None and link.function.rva is None and not link.function.ambiguous


def test_ambiguous_names_unlinked(tables, pdiff):
    newer = [record('newer', 'ParseHeader', rva=0x1000), record('newer', 'ParseHeader', rva=0x1100)]
    older = [record('older', 'ParseHeader', rva=0x1000), record('older', 'ParseHeader', rva=0x1100)]
    _, pairing, functions = project(older, newer)
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    (link,) = by_text(result, 'newer', 'index %u exceeds length %u')
    assert link.function.ambiguous and link.function.project_function_id is None and link.function.rva is None


def test_name_resolves_through_the_upstream_name(tables, pdiff):
    older = [record('older', 'FUN_140001000', upstream_name='ParseHeader')]
    newer = [record('newer', 'FUN_140001000', upstream_name='ParseHeader')]
    _, pairing, functions = project(older, newer)
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    (link,) = by_text(result, 'newer', 'index %u exceeds length %u')
    assert link.function.project_function_id == newer[0].id and link.pair_status == 'modified'


def test_l4_literal_with_newline_links_the_segment(tables):
    code_old = 'void ParseHeader(void)\n{\n  log("bad header (%s)\\n");\n}\n'
    code_new = 'void ParseHeader(void)\n{\n\n  log("bad header (%.64s)\\n");\n}\n'
    older, newer = [record('older', 'ParseHeader', code_old)], [record('newer', 'ParseHeader', code_new)]
    _, pairing, functions = project(older, newer)
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP)
    (old_link,) = by_text(result, 'older', 'bad header (%s)')
    (new_link,) = by_text(result, 'newer', 'bad header (%.64s)')
    assert (old_link.tier, old_link.join, old_link.line, old_link.pair_status) == ('L4', 'exact', 3, 'modified')
    assert new_link.line == 4 and new_link.evidence_ref == f'{newer[0].id}:line:4'
    assert by_text(result, 'older', 'bad header (%.64s)') == ()


def test_l1_and_l4_share_one_origin_and_sort_strongest_first(tables, pdiff):
    code = 'void ParseHeader(void)\n{\n  fail("index %u exceeds length %u");\n}\n'
    older, newer = [record('older', 'ParseHeader', '')], [record('newer', 'ParseHeader', code)]
    _, pairing, functions = project(older, newer)
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    first, second = by_text(result, 'newer', 'index %u exceeds length %u')
    assert (first.tier, second.tier) == ('L1', 'L4') and first.lineage_group == second.lineage_group == GROUP


@pytest.mark.parametrize('literal,row_enc,linked', [
    ('"wide text"', 'ASCII', True), ('L"wide text"', 'UTF-16LE', True),
    ('L"wide text"', 'ASCII', False), ('"wide text"', 'UTF-16LE', False)],
    ids=['narrow', 'wide', 'wide-vs-ascii', 'narrow-vs-utf16'])
def test_l4_needs_the_same_width_class(literal, row_enc, linked):
    table = floss_table('newer', [src('wide text', enc=row_enc, rva=0x2000)])
    fn = [record('newer', 'f', f'void f(void) {{ g({literal}); }}')]
    _, pairing, functions = project([record('older', 'f')], fn)
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    assert bool(by_text(result, 'newer', 'wide text')) is linked


def test_l4_truncated_literal_links_by_prefix_and_is_marked():
    value = 'a very long diagnostic message that the decompiler cut after a while, then more text'
    table = floss_table('newer', [src(value, rva=0x2000)])
    code = f'void f(void) {{ g("{value[:50]}..." /* TRUNCATED STRING LITERAL */); }}'
    _, pairing, functions = project([record('older', 'f')], [record('newer', 'f', code)])
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    (link,) = by_text(result, 'newer', value)
    assert link.join == 'contains' and link.evidence_ref.endswith(':prefix')


def test_l4_prefix_needs_a_truncation_marker_and_enough_text():
    value = 'a very long diagnostic message that the decompiler cut after a while, then more text'
    short = 'a very long'
    table = floss_table('newer', [src(value, rva=0x2000)])
    for body in (f'"{value[:50]}"', f'"{short}..." /* TRUNCATED STRING LITERAL */'):
        _, pairing, functions = project([record('older', 'f')], [record('newer', 'f', f'g({body});')])
        result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
        assert by_text(result, 'newer', value) == ()


def test_l4_links_are_capped_per_string_with_a_note():
    table = floss_table('newer', [src('shared message', rva=0x2000)])
    newer = [record('newer', f'f{i}', 'g("shared message");', rva=0x1000 + 16 * i) for i in range(12)]
    older = [record('older', f'f{i}', rva=0x1000 + 16 * i) for i in range(12)]
    _, pairing, functions = project(older, newer)
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    assert len(by_text(result, 'newer', 'shared message')) == 8 and any('more than 8 links' in n for n in result.notes)


def test_l5_stack_string_links_to_the_function_starting_at_its_frame():
    rows = [src('stack text', type='stack', fn_rva=0x1000), src('tight text', type='tight', fn_rva=0x5000),
            src('decoded text', type='decoded', fn_rva=0x1000)]
    table = floss_table('newer', rows, run_id='run-9')
    _, pairing, functions = project([record('older', 'f')], [record('newer', 'f')])
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    (link,) = by_text(result, 'newer', 'stack text')
    assert (link.tier, link.join, link.pair_status, link.lineage_group) == ('L5', 'exact', 'modified', 'emulation:run-9')
    assert by_text(result, 'newer', 'tight text') == () and by_text(result, 'newer', 'decoded text') == ()


def test_l5_two_functions_at_one_frame_are_ambiguous():
    table = floss_table('newer', [src('stack text', type='stack', fn_rva=0x1000)])
    newer = [record('newer', 'f'), record('newer', 'g')]
    matches = [FunctionMatch(run_id='r', category='added', newer=[n]) for n in newer]
    pairing = FunctionPairing.from_project(matches, None, older_base=IMAGE_BASE, newer_base=IMAGE_BASE)
    functions = {'newer': SideFunctions.from_matches(matches, 'newer', IMAGE_BASE)}
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    (link,) = by_text(result, 'newer', 'stack text')
    assert link.function.ambiguous and link.function.project_function_id is None and link.pair_status == 'ambiguous'


def test_unlinked_strings_stay_unlinked(tables, pdiff):
    _, pairing, functions = project([record('older', 'Other')], [record('newer', 'Other')])
    result = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP)
    assert result.links == {}


def test_table_for_the_wrong_side_is_refused(tables):
    _, pairing, functions = project([record('older', 'f')], [record('newer', 'f')])
    with pytest.raises(StringsError) as caught:
        link_strings({'older': tables['newer']}, pairing=pairing, functions=functions, ghidra_group=GROUP)
    assert caught.value.code == 'PT-STR-LINK'


def doc(**sections) -> bytes:
    return json.dumps({'strings': sections}).encode()


def parse(raw: bytes, **kw):
    return ghidriff_strings(raw, expected_raw_sha256=hashlib.sha256(raw).hexdigest(), image_bases=BASES, **kw)


def test_stale_raw_rejected():
    raw = doc(added=[])
    with pytest.raises(StringsError) as caught:
        ghidriff_strings(raw, expected_raw_sha256='0' * 64, image_bases=BASES)
    assert caught.value.code == 'PT-STR-STALE'


@pytest.mark.parametrize('raw', [b'not json', b'[]', b'{"strings": 3}'], ids=['garbage', 'list', 'scalar'])
def test_unusable_documents_give_no_entries_or_a_typed_error(raw):
    try:
        assert parse(raw).entries == ()
    except StringsError as exc:
        assert exc.code == 'PT-STR-INPUT'


def test_hostile_entries_are_skipped_with_a_note():
    raw = doc(added=[3, {'address': 5}, {'address': 'zz'}, {'address': '1000'}, {'address': '140001000',
              'calling': 'f'}, {'address': '140001000', 'calling': ['ok', 7, '', 'x' * 300]}], deleted='no')
    result = parse(raw)
    assert [(e.side, e.rva, e.calling) for e in result.entries] == [('newer', 0x1000, ('ok',))]
    assert any('unusable' in note for note in result.notes)


def test_calling_list_is_bounded():
    names = [f'f{i}' for i in range(200)]
    result = parse(doc(added=[{'address': '140001000', 'calling': names}]))
    assert len(result.entries[0].calling) == links.MAX_CALLING and any('ignored' in n for n in result.notes)


def test_too_many_entries_is_a_limit_error(monkeypatch):
    monkeypatch.setattr(links, 'MAX_GHIDRIFF_STRINGS', 3)
    with pytest.raises(StringsError) as caught:
        parse(doc(added=[{'address': '140001000'}] * 4))
    assert caught.value.code == 'PT-STR-LIMIT'


def test_ambiguous_containment_joins_nothing():
    table = floss_table('newer', [src('AAAAAAAA', rva=0x2000), src('BBBBBBBB', rva=0x2004)])
    raw = doc(added=[{'address': '140002006', 'calling': ['f']}])
    _, pairing, functions = project([record('older', 'f')], [record('newer', 'f')])
    result = link_strings({'newer': table}, pairing=pairing, functions=functions, ghidra_group=GROUP,
                          ghidriff=parse(raw))
    assert result.links == {} and any('fit several' in n for n in result.notes)
