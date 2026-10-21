"""Function pairing for strings (panel and CLI share `strings.pairing`): links only from evidence, unknown otherwise."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from strings_pe import builtin_table, synergy_pair
from test_strings_links import project, record, sha

from patchtrace.strings import pairing
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.scan import BuiltinScanSource

CODE_OLD = 'void ParseHeader(void)\n{\n  log("bad header (%s)\\n");\n}\n'
CODE_NEW = 'void ParseHeader(void)\n{\n  log("bad header (%.64s)\\n");\n}\n'


@pytest.fixture(scope='module')
def built(tmp_path_factory):
    pair = synergy_pair()
    images, tables = {}, {}
    for side, data in (('older', pair.older), ('newer', pair.newer)):
        path = tmp_path_factory.mktemp(side) / 'a.bin'
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        image = pairing.inspect_image(path, digest)
        images[side] = image
        result = BuiltinScanSource(path, artifact_sha256=digest, side=side,
                                   offset_to_rva=lambda off, pe=image.pe: pe.offset_to_rva(off)[0]).load()
        tables[side] = builtin_table(side, digest, list(result.rows))
    return images, tables


def snapshot(matches, runs=True):
    done = [SimpleNamespace(id='run-1', status='completed', raw_path=None, raw_sha256=None)] if runs else []
    return SimpleNamespace(matches=matches, runs=done)


def test_no_project_means_unknown_with_the_reason(built):
    images, tables = built
    found = pairing.project_links(None, None, tables, images, [])
    assert found.linked is None and found.reason == pairing.NO_ANALYSIS and not found.pairing.available


def test_matches_without_a_completed_run_mean_unknown(built):
    images, tables = built
    matches, *_ = project([record('older', 'ParseHeader', CODE_OLD)], [record('newer', 'ParseHeader', CODE_NEW)])
    found = pairing.project_links(None, snapshot(matches, runs=False), tables, images, [])
    assert found.linked is None and found.reason == pairing.NO_ANALYSIS


def test_an_unparsable_image_means_unknown_not_a_guess(built):
    images, tables = built
    matches, *_ = project([record('older', 'ParseHeader', CODE_OLD)], [record('newer', 'ParseHeader', CODE_NEW)])
    broken = {'older': pairing.Image(None, None), 'newer': images['newer']}
    found = pairing.project_links(None, snapshot(matches), tables, broken, [])
    assert found.linked is None and found.reason == pairing.NO_IMAGE


def test_a_literal_in_the_decompiled_function_links_with_its_pair_status(built):
    images, tables = built
    matches, *_ = project([record('older', 'ParseHeader', CODE_OLD)], [record('newer', 'ParseHeader', CODE_NEW)])
    found = pairing.project_links(None, snapshot(matches), tables, images, [])
    assert found.reason is None and found.pairing.available
    (link,) = found.linked.links[('older', sha('bad header (%s)'))]
    assert (link.tier, link.pair_status, link.function.name) == ('L4', 'modified', 'ParseHeader')
    # a string no function text mentions has no link at all: unlinked stays unlinked
    assert ('older', sha('debug dump of internal state')) not in found.linked.links


def test_an_unreadable_artifact_is_a_typed_error(tmp_path):
    with pytest.raises(StringsError) as caught:
        pairing.inspect_image(tmp_path / 'missing.bin', 'a' * 64)
    assert caught.value.code == 'PT-STR-INPUT'
