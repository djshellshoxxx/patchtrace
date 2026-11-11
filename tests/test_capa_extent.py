"""CAP-9: instruction-scope capa matches are attributed to a function only through a .pdata-confirmed extent."""
from __future__ import annotations

import pytest

from patchtrace.intelligence.tools import capa_extent
from patchtrace.intelligence.tools.common import CapabilityEvidence, EvidenceLink, ToolEvidenceSet
from patchtrace.unified.ir.reader import IrReader

SHA = 'a' * 64


def _cap(scope: str, rva: int | None, *, function_id: str | None = None, attribution: str = 'none') -> CapabilityEvidence:
    link = EvidenceLink(tool_run_id='r1', artifact_sha256=SHA, function_id=function_id, rva=rva,
                        attribution=attribution)
    return CapabilityEvidence(rule_id='r', rule_sha256=SHA, scope=scope, address_space='relative', location=link,
                              kind='capability', source_run_id='r1')


def _set(*caps: CapabilityEvidence) -> ToolEvidenceSet:
    return ToolEvidenceSet(run_id='r1', engine='capa', side='older', artifact_sha256=SHA, cache_key=SHA,
                           config_digest=SHA, capabilities=caps)


def _reader(rows: list[tuple[int, int, int]]) -> IrReader:
    return IrReader.from_columns({'rva': [r[0] for r in rows], 'size': [r[1] for r in rows],
                                  'extent_src': [r[2] for r in rows]})


def _one(rva: int, rows, scope='instruction', **kw):
    out = capa_extent.attribute(_set(_cap(scope, rva, **kw)), _reader(rows))
    return out.capabilities[0].location


@pytest.mark.parametrize('rva,rows,expected', [
    (0x1010, [(0x1000, 0x40, 1)], 'rva:0x1000'),
    (0x1000, [(0x1000, 0x40, 1)], 'rva:0x1000'),
    (0x1040, [(0x1000, 0x40, 1)], None),
    (0x1010, [(0x1000, 0x40, 0)], None),
    (0x1010, [(0x1000, 0x40, 2)], None),
    (0x0f00, [(0x1000, 0x40, 1)], None),
    (0x1010, [(0x1000, 0x40, 1), (0x1008, 0x10, 1)], None),
    (0x1010, [], None),
], ids=['inside', 'start', 'end-exclusive', 'unknown-extent', 'conflict', 'before-all', 'overlap', 'no-functions'])
def test_attribution(rva, rows, expected):
    link = _one(rva, rows)
    assert link.function_id == expected
    assert link.attribution == ('contained-in-function' if expected else 'none')


def test_only_unlocalized_instruction_matches_change():
    rows = [(0x1000, 0x40, 1)]
    assert _one(0x1010, rows, scope='file').attribution == 'none'
    assert _one(0x1010, rows, scope='function').attribution == 'none'
    kept = _one(0x1010, rows, function_id='rva:0x1000', attribution='basic-block-in-function')
    assert kept.attribution == 'basic-block-in-function'


def test_match_without_rva_stays_unattributed():
    out = capa_extent.attribute(_set(_cap('instruction', None)), _reader([(0x1000, 0x40, 1)]))
    assert out.capabilities[0].location.attribution == 'none'


def test_other_artifact_is_refused():
    class _M:
        artifact_sha256 = 'b' * 64
    reader = _reader([(0x1000, 0x40, 1)])
    reader.manifest = _M()
    evidence = _set(_cap('instruction', 0x1010))
    assert capa_extent.attribute(evidence, reader) is evidence


def test_input_unchanged_and_idempotent():
    evidence = _set(_cap('instruction', 0x1010))
    reader = _reader([(0x1000, 0x40, 1)])
    out = capa_extent.attribute(evidence, reader)
    assert evidence.capabilities[0].location.attribution == 'none'
    assert capa_extent.attribute(out, reader) == out
