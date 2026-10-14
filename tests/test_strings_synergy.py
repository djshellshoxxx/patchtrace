"""SYN-WB3-1 (SYNTHETIC inputs): the combined known answers that no single channel gives.

Channels: built-in scan of two synthetic PEs (offsets), a Ghidriff-shaped `strings` section (L1), decompiled
literals (L4) and a cue context (advisory phrase, API hint, import lists). Every expected row is in the plan's
section 5 table.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from strings_pe import builtin_table, synergy_pair
from test_strings_delta import with_basis
from test_strings_links import BASES, GROUP, PDIFF, project, record, sha, src

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools.normalize import FunctionPairing, PeMap
from patchtrace.strings import contracts as c
from patchtrace.strings.cues import CueContext
from patchtrace.strings.delta import compute_delta
from patchtrace.strings.links import ghidriff_strings, link_strings
from patchtrace.strings.scan import BuiltinScanSource
from patchtrace.strings.table import ENCODINGS, TYPES, StringRow

ANCHORS = json.loads((Path(__file__).parent / 'fixtures' / 'strings' / 'synergy' / 'anchors.json')
                     .read_text(encoding='utf-8'))
CODE_OLD = 'void ParseHeader(void)\n{\n  log("bad header (%s)\\n");\n}\n'
CODE_NEW = 'void ParseHeader(void)\n{\n  log("bad header (%.64s)\\n");\n}\n'
CYRILLIC_ERROR = 'Еrror'


def scanned_rows(tmp_path_factory, side, data):
    path = tmp_path_factory.mktemp(side) / 'a.bin'
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    reader = VerifiedArtifactReader.open_path(path, digest)
    try:
        pe = PeMap.from_reader(reader)
        result = BuiltinScanSource(path, artifact_sha256=digest, side=side,
                                   offset_to_rva=lambda off: pe.offset_to_rva(off)[0]).load()
    finally:
        reader.close()
    return digest, list(result.rows)


@pytest.fixture(scope='module')
def delta(tmp_path_factory):
    pair = synergy_pair()
    tables = {}
    extras = {'older': ['AKIAIOSFODNN7EXAMPLE', 'Error'],
              'newer': ['AKIAIOSFODNN7EXAMPLE', CYRILLIC_ERROR, 'RtlULongAdd']}
    for side, data in (('older', pair.older), ('newer', pair.newer)):
        digest, rows = scanned_rows(tmp_path_factory, side, data)
        tables[side] = builtin_table(side, digest, rows + [src(t) for t in extras[side]])
    raw = PDIFF.read_bytes()
    pdiff = ghidriff_strings(raw, expected_raw_sha256=hashlib.sha256(raw).hexdigest(), image_bases=BASES)
    # ParseHeader is the one modified pair; InitRegistry is deliberately not in the match set.
    matches, pairing, functions = project([record('older', 'ParseHeader', CODE_OLD)],
                                          [record('newer', 'ParseHeader', CODE_NEW)])
    found = link_strings(tables, pairing=pairing, functions=functions, ghidra_group=GROUP, ghidriff=pdiff)
    contexts = {side: CueContext(imports=ANCHORS['imports'][side], advisory_phrases=ANCHORS['advisory_phrases'],
                                 api_hints=ANCHORS['api_hints'], other_side_imports=ANCHORS['imports'][other])
                for side, other in (('older', 'newer'), ('newer', 'older'))}
    return compute_delta(tables['older'], tables['newer'], pairing=pairing, links=found, contexts=contexts)


def row(delta, text):
    (found,) = [ch for ch in delta.changes if ch.value_sha256 == sha(text).hex()]
    return found


def test_added_message_in_modified_function_is_first_to_read(delta):
    change = row(delta, 'index %u exceeds length %u')
    assert change.status == 'only-newer' and change.review_tier == 1
    assert {'message', 'format', 'advisory-text'} <= set(change.cues)
    assert {link.tier for link in change.links} >= {'L1'}
    assert all(link.pair_status == 'modified' for link in change.links)
    assert 'pair-modified' in change.reasons


def test_edited_format_string_is_one_row(delta):
    edited = [ch for ch in delta.changes if ch.status == 'edited' and ch.edit.of == sha('bad header (%s)').hex()]
    (change,) = edited
    assert change.display == 'bad header (%.64s)' and change.review_tier == 1
    assert change.edit.kind == 'insert' and 'format-spec' in change.reasons
    assert change.older is not None and change.newer is not None
    assert not [ch for ch in delta.changes if ch.display in ('bad header (%s)',)]


def test_removed_debug_message_is_read_after_the_added_one(delta):
    change = row(delta, 'debug dump of internal state')
    assert change.status == 'only-older' and change.review_tier == 4 and 'message' in change.cues


def test_relocated_string_is_in_both_with_the_labels_only_supplying_links(delta):
    change = row(delta, 'configuration loaded')
    assert change.status == 'both' and {link.tier for link in change.links} == {'L1'}
    assert change.older.rvas != change.newer.rvas


def test_registry_path_with_an_unpaired_caller_keeps_its_name_and_unknown_status(delta):
    change = row(delta, 'Software\\Vendor\\Product\\Mode')
    assert change.status == 'only-newer' and change.review_tier == 3 and 'registry' in change.cues
    (link,) = change.links
    assert link.function.name == 'InitRegistry' and link.pair_status == 'unknown'


def test_api_name_in_no_import_table_is_a_dynamic_api_hint(delta):
    change = row(delta, 'RtlULongAdd')
    assert change.review_tier == 3 and {'dynamic-api', 'advisory-api'} <= set(change.cues)
    assert 'api-name' not in change.cues


def test_lookalike_is_edited_with_its_origin(delta):
    change = row(delta, CYRILLIC_ERROR)
    assert change.status == 'edited' and change.review_tier == 6 and 'lookalike' in change.cues
    assert change.lookalike_of == sha('Error').hex() and change.edit.of == change.lookalike_of
    assert not [ch for ch in delta.changes if ch.display == 'Error']


def test_secret_in_both_builds_is_not_a_change_and_never_shown(delta):
    assert 'AKIAIOSFODNN7EXAMPLE' not in json.dumps(delta.model_dump(mode='json'))
    assert not [ch for ch in delta.changes if ch.value_sha256 == sha('AKIAIOSFODNN7EXAMPLE').hex()]


def test_reading_order_follows_the_tiers(delta):
    tiers = [ch.review_tier for ch in delta.changes]
    assert tiers == sorted(tiers) and tiers[0] == 1 and delta.changes[0].review_tier == 1


def test_emulation_variant_says_found_only_by_emulation():
    def side_table(side, text):
        part = c.BasisPart(source='floss', semantics_id=c.STATIC_SEMANTICS_ID, run_id=f'run-{side}',
                           raw_sha256='e' * 64, types=('static', 'decoded'), config_digest='c' * 64,
                           executable_sha256='a' * 64, consent_sha256='b' * 64)
        base = c.StringBasis(artifact_sha256='1' * 64, side=side, min_length=4, rows_seen=1, rows_kept=1,
                             stages={'static': c.StageState(state='complete'),
                                     'decoded': c.StageState(state='heuristic')}, parts=(part,))
        return with_basis([StringRow(sha(text), TYPES.index('decoded'), ENCODINGS.index('ASCII'), len(text),
                                     display=text)], base)
    result = compute_delta(side_table('older', 'build one'), side_table('newer', 'build two'),
                           pairing=FunctionPairing.empty())
    assert {ch.status for ch in result.changes} == {'only-older', 'only-newer'}
    for change in result.changes:
        assert change.review_tier == 5 and any('absence is not evidence' in n for n in change.notes)
