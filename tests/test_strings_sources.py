"""WB3-S1: string sources over the recorded FLOSS 3.1.1 goldens (SYNTHETIC PE pairs, no tool runs here)."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools import floss
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError
from patchtrace.intelligence.tools.normalize import PeMap
from patchtrace.intelligence.tools.process import ArtifactCopy
from patchtrace.strings.sources import (
    STATIC_SEMANTICS_ID,
    FlossEvidenceSource,
    RawFlossSource,
    StringSource,
)

FLOSS_DIR = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools' / 'floss'
CONSENT = floss.EMULATION_CONSENT_SHA256


def golden(name: str) -> bytes:
    return (FLOSS_DIR / name).read_bytes()


@pytest.fixture
def image(tmp_path):
    opened = []

    def get(pair: str, side: str):
        data = dict(zip(('older', 'newer'), PAIRS[pair](), strict=True))[side]
        path = tmp_path / f'{pair}-{side}.bin'
        path.write_bytes(data)
        copy = ArtifactCopy(path, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(),
                            hashlib.sha1(data).hexdigest(), len(data))
        reader = VerifiedArtifactReader.open_path(path, copy.sha256)
        opened.append(reader)
        return copy, reader, PeMap.from_reader(reader)
    yield get
    for reader in opened:
        reader.close()


def parsed(image, pair: str, side: str, name: str, *, deobfuscate: bool = False):
    copy, reader, pe = image(pair, side)
    ctx = floss.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'],
                             deobfuscate)
    return floss.parse(golden(name), ctx), copy, pe


def comparable(rows):
    return [(r.value_sha256, r.type, r.encoding, r.length, r.offset, r.rva, r.fn_rva, r.site_rva, r.data_rva)
            for r in rows]


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['older', 'newer'])
def test_static_goldens_table_rows_equal_parser_output(image, side):
    evidence, _copy, _pe = parsed(image, 'floss-static', side, f'floss-static-{side}.static.json')
    result = FlossEvidenceSource(evidence).load()
    assert len(result.rows) == len(evidence.strings) == 10
    for row, item in zip(result.rows, evidence.strings, strict=True):
        assert row.value_sha256.hex() == item.value_hash
        assert (row.type, row.encoding, row.length, row.display) == (item.type, item.encoding, item.length,
                                                                     item.display_value)
        assert (row.offset, row.rva, row.secret_kind) == (item.source_location.file_offset,
                                                          item.source_location.rva, item.secret_kind)
    assert result.part.source == 'floss' and result.part.semantics_id == STATIC_SEMANTICS_ID
    assert result.min_length == 4 and result.language == 'unknown'
    assert result.stages['static'].state == 'complete'
    assert {result.stages[t].state for t in ('stack', 'tight', 'decoded')} == {'not-run'}
    assert any(r.secret_kind == 'aws-access-key' for r in result.rows)


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['older', 'newer'])
def test_raw_source_rows_equal_the_evidence_source(image, side):
    name = f'floss-static-{side}.static.json'
    evidence, copy, pe = parsed(image, 'floss-static', side, name)
    raw = golden(name)
    from_raw = RawFlossSource(raw, artifact_sha256=copy.sha256, side=side, run_id=f'run-{side}',
                              config_digest='d' * 64, image_base=pe.image_base,
                              offset_to_rva=lambda off: pe.offset_to_rva(off)[0]).load()
    from_evidence = FlossEvidenceSource(evidence, raw_sha256=hashlib.sha256(raw).hexdigest()).load()
    assert comparable(from_raw.rows) == comparable(from_evidence.rows)
    assert from_raw.part.raw_sha256 == hashlib.sha256(raw).hexdigest() == from_evidence.part.raw_sha256


def test_decoded_goldens_carry_function_site_and_stage_states(image):
    name = 'floss-decode-newer.deobfuscate.json'
    evidence, copy, pe = parsed(image, 'floss-decode', 'newer', name, deobfuscate=True)
    raw = golden(name)
    from_evidence = FlossEvidenceSource(evidence, consent_sha256=CONSENT).load()
    from_raw = RawFlossSource(raw, artifact_sha256=copy.sha256, side='newer', run_id='run-newer',
                              config_digest='d' * 64, image_base=pe.image_base,
                              offset_to_rva=lambda off: pe.offset_to_rva(off)[0], consent_sha256=CONSENT).load()
    decoded = [r for r in from_raw.rows if r.type == 'decoded']
    assert decoded and all(r.fn_rva is not None and r.site_rva is not None for r in decoded)
    assert comparable(from_raw.rows) == comparable(from_evidence.rows)
    for result in (from_raw, from_evidence):
        assert {result.stages[t].state for t in ('stack', 'tight', 'decoded')} == {'heuristic'}
        assert result.part.consent_sha256 == CONSENT
        assert set(result.part.types) == {'static', 'stack', 'tight', 'decoded'}


def test_empty_stdout_marks_static_none_found_and_emulation_not_run():
    result = RawFlossSource(b'', artifact_sha256='a' * 64, side='older', run_id='r', config_digest='d' * 64).load()
    assert result.rows == () and result.rows_seen == 0
    assert result.stages['static'].state == 'complete' and result.stages['static'].detail == 'none-found'
    assert {result.stages[t].state for t in ('stack', 'tight', 'decoded')} == {'not-run'}


def test_truncation_is_per_type_and_recorded():
    import json
    doc = json.loads(golden('floss-decode-newer.deobfuscate.json'))
    doc['strings']['static_strings'] = [
        {'encoding': 'ASCII', 'offset': 100 + 10 * i, 'string': f'static value {i:03d}'} for i in range(40)]
    raw = json.dumps(doc).encode()
    result = RawFlossSource(raw, artifact_sha256='a' * 64, side='newer', run_id='r', config_digest='d' * 64,
                            max_rows=10).load()
    assert result.rows_seen == 40 + len(doc['strings']['decoded_strings'])
    assert len(result.rows) == 10
    assert result.stages['static'].state == 'truncated'
    assert result.stages['decoded'].state in {'heuristic', 'truncated'}
    kept = [r.offset for r in result.rows if r.type == 'static']
    assert kept == sorted(kept) and kept[0] == 100  # the first by position, not by document order


def test_unknown_keys_are_refused_as_output_errors():
    import json
    doc = json.loads(golden('floss-static-older.static.json'))
    doc['metadata']['sha256'] = 'x'  # a master build adds keys (F2)
    with pytest.raises(ToolError) as info:
        RawFlossSource(json.dumps(doc).encode(), artifact_sha256='a' * 64, side='older', run_id='r',
                       config_digest='d' * 64).load()
    assert info.value.code == 'PT-TOOL-OUTPUT'


def test_sources_satisfy_the_port():
    source = RawFlossSource(b'', artifact_sha256='a' * 64, side='older', run_id='r', config_digest='d' * 64)
    assert isinstance(source, StringSource)
