"""SPEC-32 s11: calibration-corpus/1 manifest and annotation-log conversions from SYNTHETIC label documents."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from test_tier_r_eval_metrics import FUNCS, make_labels, out, pred

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration import contracts as K  # noqa: E402
from tools.calibration import corpus, lineage  # noqa: E402
from tools.calibration.label import AnnotationLog, ChainError  # noqa: E402
from tools.calibration.tier_r import annotate as A  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402
from tools.calibration.tier_r import manifest as M  # noqa: E402

P1 = make_labels(FUNCS, pair_id='syn-one', stratum='release')
P2 = make_labels(FUNCS, pair_id='syn-two', stratum='authored')


def test_manifest_loads_and_assigns_roles():
    doc = M.build_manifest([P2, P1], tool_git='abc1234')
    manifest = corpus.load_manifest(C.dump_json(doc))
    assert manifest.contract == 'calibration-corpus/1'
    assert [b.tier for b in manifest.binaries] == ['R'] * 4
    assert {p.id: p.kind for p in manifest.pairs} == {'syn-one': 'cross-version', 'syn-two': 'adjacent-patch'}
    assert [lin.id for lin in manifest.lineages] == ['L-ours-_template-tiny']
    assert len(manifest.lineages[0].members) == 4
    roles = lineage.assign_roles([lin.id for lin in manifest.lineages], manifest.split.salt)
    assert set(roles.values()) <= {'dev', 'locked-test', 'shift-test'}


def test_manifest_is_deterministic_and_order_independent():
    assert C.dump_json(M.build_manifest([P1, P2])) == C.dump_json(M.build_manifest([P2, P1]))
    assert M.build_manifest([P1])['created'] == M.DEFAULT_CREATED


def test_manifest_suite_source_has_no_fake_git_url():
    binary = M.build_manifest([P1])['binaries'][0]
    assert binary['source']['git'].startswith('suite:') and len(binary['source']['commit']) == 40
    assert binary['redistribution'] == 'not-committed' and binary['recipe']['strip'] is True


def test_manifest_rejects_an_image_in_two_lineages():
    clone = P1.model_dump(mode='json')
    clone.update(pair_id='syn-other', lineage='L-other')
    clone.pop('digest_sha256')
    other = C.load_labels(C.dump_json(C.finalize_labels(clone)))
    with pytest.raises(M.ManifestError, match='claimed by lineages'):
        M.build_manifest([P1, other])


def _reader(sha, rva, size):
    return f'{sha[:8]}|{rva}|{size}'.encode()


ENGINE = {'syn-one': {'rz-diff': out(pred(0x1000, 0x1000, False), pred(0x1060, 0x1070, True),
                                     pred(0x1020, 0x1030, True), pred(0x1080, 0x1080, False),
                                     pred(0x9000, 0x9000, False))}}


def test_candidates_answers_are_constructed_from_truth():
    found, skipped = A.candidates(P1, ENGINE['syn-one'])
    by_id = {c.match_id: c for c in found}
    assert len([c for c in found if c.answer == 'same']) == 6
    assert by_id['1060:1070'].answer == 'no-counterpart' and by_id['1060:1070'].engines == ('rz-diff',)
    assert by_id['1020:1030'].answer == 'different'
    assert by_id['1080:1080'].answer == 'indeterminate'
    assert by_id['1000:1000'].sampling['stratum'] == 'natural' and by_id['1020:1030'].sampling['stratum'] == 'natural'
    assert skipped == {'unlabelled-side': 1}


def test_log_is_a_valid_chain_idempotent_and_tamper_evident(tmp_path):
    log = AnnotationLog(tmp_path / 'ann.jsonl')
    first = A.write_log([P1, P2], log, outputs=ENGINE)
    assert first['appended'] == 6 + 3 + 6 and first['skipped'] == {'unlabelled-side': 1}
    events = log.events()                        # raises ChainError on any broken link
    assert {e['annotator'] for e in events} == {'known-answer/source-diff', 'known-answer/authored-truth'}
    assert {(e['phase'], e['guideline'], e['ts']) for e in events} == {('blind', 'ka-1', A.TS)}
    assert A.write_log([P1, P2], log, outputs=ENGINE)['appended'] == 0
    assert len(log.events()) == 15
    raw = (tmp_path / 'ann.jsonl').read_text().replace('"A":"same"', '"A":"different"', 1)
    (tmp_path / 'ann.jsonl').write_text(raw)
    with pytest.raises(ChainError):
        AnnotationLog(tmp_path / 'ann.jsonl').events()


def test_log_bytes_are_reproducible(tmp_path):
    for name in ('a', 'b'):
        A.write_log([P1, P2], AnnotationLog(tmp_path / f'{name}.jsonl'), outputs=ENGINE)
    assert (tmp_path / 'a.jsonl').read_bytes() == (tmp_path / 'b.jsonl').read_bytes()


def test_consolidation_gives_synthetic_exact_calibration_labels(tmp_path):
    log = AnnotationLog(tmp_path / 'ann.jsonl')
    A.write_log([P1], log, outputs=ENGINE)
    records, stats = A.consolidate_labels([P1], log, _reader, outputs=ENGINE)
    assert stats == {'pending': 0, 'reveal_changes': 0} and len(records) == 9
    parsed = K.load_labels(A.dump_jsonl(records))            # the production calibration-labels/1 loader
    assert {r.source for r in parsed} == {'synthetic-exact'} and {r.annotators for r in parsed} == {
        ('known-answer/source-diff',)}
    answers = {r.match_id: (r.A, r.y) for r in parsed}
    assert answers['1000:1000'] == ('same', 1) and answers['1020:1030'] == ('different', 0)
    assert answers['1080:1080'] == ('indeterminate', None)
    same = next(r for r in parsed if r.match_id == '1000:1000')
    assert same.older.size == 16 and same.older.rva == 0x1000
    assert A.dump_jsonl(records) == A.dump_jsonl(A.consolidate_labels([P1], log, _reader, outputs=ENGINE)[0])


def test_consolidation_ignores_candidates_without_events(tmp_path):
    log = AnnotationLog(tmp_path / 'empty.jsonl')
    assert A.consolidate_labels([P1], log, _reader)[0] == []


def test_engine_outputs_that_are_not_ok_add_no_candidates():
    blocked = {'bindiff': E.blocked('bindiff', 'no import')}
    found, _ = A.candidates(P1, blocked)
    assert len(found) == 6 and all(c.engines == () for c in found)
