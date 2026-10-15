"""SPEC-31 S6b: the pure parts of `tools/unified/live_pairs.py` (selection, image lookup, the join from a stored unified
result to `unified-outcomes/1`). The live part (a real Ghidra, Ghidriff and extractor) runs only in the workflow."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s0_fixtures import make_project  # noqa: E402
from unified_s6_helpers import label_doc, mutation_doc  # noqa: E402
from unified_wire_support import place_pair  # noqa: E402

from patchtrace.unified import pipeline  # noqa: E402
from tools.unified import live_pairs, outcomes  # noqa: E402


def docs():
    return [label_doc('aa-p0', 'aa'), label_doc('aa-p1', 'aa', method='aa-layout'), label_doc('rel', 'release'),
            mutation_doc('mut-constant-00', 'constant', 'ka_constant_00')]


def test_select_filters_by_pair_id_and_role_and_drops_documents_that_belong_to_spec_32_alone():
    every = [*docs(), label_doc('authored-x', 'authored')]
    assert [d.pair_id for d in live_pairs.select(every, 'all', 'all')] == ['aa-p0', 'aa-p1', 'rel', 'mut-constant-00']
    assert [d.pair_id for d in live_pairs.select(every, 'all', 'P0,P1')] == ['aa-p0', 'aa-p1']
    assert [d.pair_id for d in live_pairs.select(every, 'rel,aa-p0', 'all')] == ['aa-p0', 'rel']
    assert [d.pair_id for d in live_pairs.select(every, 'all', 'all', prefix='mut-constant-')] == ['mut-constant-00']


def test_image_path_finds_the_engine_image_by_digest_and_names_a_missing_one(tmp_path):
    doc = label_doc('rel', 'release')
    folder = tmp_path / 'images' / doc.older.sha256
    folder.mkdir(parents=True)
    (folder / doc.older.file_name).write_bytes(b'MZ')
    assert live_pairs.image_path(tmp_path, doc.older) == folder / doc.older.file_name
    with pytest.raises(FileNotFoundError, match=doc.newer.sha256[:12]):
        live_pairs.image_path(tmp_path, doc.newer)


def test_the_stored_result_of_a_project_reduces_to_outcome_rows_for_both_orientations(tmp_path):
    service = make_project(tmp_path / 'project')
    try:
        place_pair(service, scratch=tmp_path)
        pipeline.run_unified(service, pipeline.UnifiedOptions(isolate=False))
        loaded = pipeline.load_current(service, pipeline.make_plan(service))
        forward = live_pairs.outcome_of(service, label_doc('rel', 'release'), 'forward')
        swapped = live_pairs.outcome_of(service, label_doc('rel', 'release'), 'swapped')
    finally:
        service.close()
    assert len(forward.rows) == loaded.manifest.counts.total() and forward.rows
    assert {r.decision for r in forward.rows} <= {'matched', 'older-only', 'newer-only', 'tentative', 'candidate',
                                                  'contested', 'ambiguous', 'unknown'}
    assert any(r.older and r.newer and r.materiality in ('material', 'review') for r in forward.rows)
    assert forward.rows_sha256 == swapped.rows_sha256 and (forward.orientation, swapped.orientation) == ('forward', 'swapped')
    assert outcomes.load(outcomes.dump(outcomes.build('t', 'x', [forward]))).pairs[0].rows == forward.rows


def test_a_label_document_without_a_unique_planted_function_is_a_contract_error(tmp_path):
    from tools.calibration.tier_r.contracts import ContractError
    doc = mutation_doc('mut-constant-00', 'constant', 'ka_constant_00')
    broken = doc.model_copy(update={'functions': tuple(f for f in doc.functions if f.label != 'changed')})
    with pytest.raises(ContractError, match='exactly one planted'):
        outcomes.planted_of(broken)
