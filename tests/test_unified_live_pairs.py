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
    assert any(r.basis and r.truth for r in forward.rows)         # supports joined to their atoms, truth joined to the labels
    assert forward.rows_sha256 == swapped.rows_sha256 and (forward.orientation, swapped.orientation) == ('forward', 'swapped')
    assert outcomes.load(outcomes.dump(outcomes.build('t', 'x', [forward]))).pairs[0].rows == forward.rows


def test_a_label_document_without_a_unique_planted_function_is_a_contract_error(tmp_path):
    from tools.calibration.tier_r.contracts import ContractError
    doc = mutation_doc('mut-constant-00', 'constant', 'ka_constant_00')
    broken = doc.model_copy(update={'functions': tuple(f for f in doc.functions if f.label != 'changed')})
    with pytest.raises(ContractError, match='exactly one planted'):
        outcomes.planted_of(broken)


def test_live_pair_commits_completed_native_run_before_unified(tmp_path, monkeypatch):
    """Regression for 41063115449: a raw backend return is not a project run."""
    from types import SimpleNamespace

    from patchtrace.backend import BackendConfig

    doc = label_doc('rel', 'release')
    older = tmp_path / 'old.dll'
    newer = tmp_path / 'new.dll'
    older.write_bytes(b'old')
    newer.write_bytes(b'new')
    monkeypatch.setattr(live_pairs, 'image_path',
                        lambda _store, side: older if side == doc.older else newer)

    class Service:
        root = tmp_path / 'case'

        def __init__(self):
            self.project = SimpleNamespace(runs=[])
            self.imports = []

        def apply_analysis(self, path, run):
            self.imports.append((path, run))
            self.project.runs.append(run)

        def close(self):
            pass

    service = Service()
    native = SimpleNamespace(id='native-run', status='completed', error=None)
    raw = tmp_path / 'native.json'
    monkeypatch.setattr(live_pairs.ProjectService, 'create', lambda *args: service)
    monkeypatch.setattr(live_pairs.backend_module, 'run_comparison',
                        lambda *args: (raw, native))

    class Side:
        def __init__(self, *args):
            pass

        def run(self, *args):
            return {'directory': tmp_path}

        def close(self):
            pass

    monkeypatch.setattr(live_pairs, 'Side', Side)
    monkeypatch.setattr(live_pairs, 'file_sha256', lambda _: '0' * 64)
    monkeypatch.setattr(live_pairs, 'place_ir', lambda *args: None)

    def run_unified(owned_service, _options):
        assert owned_service.project.runs == [native], 'native run was not committed'
        assert owned_service.imports == [(raw, native)], 'raw output was not imported'

    monkeypatch.setattr(live_pairs.pipeline, 'run_unified', run_unified)
    monkeypatch.setattr(live_pairs, 'outcome_of', lambda *args: 'evaluated')
    backend = BackendConfig(sys.executable, str(tmp_path), 1800)
    assert live_pairs.analyse_pair(doc, tmp_path, backend, tmp_path, 'forward') == 'evaluated'
