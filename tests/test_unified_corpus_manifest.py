"""SPEC-31 S6a corpus manifest and A/A naming (tools/unified/corpus/{aa,manifest}.py). Pure: the label documents are
built through the SPEC-32 contract (`finalize_labels`), nothing is compiled, no image exists."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS)]
from unified_s6_helpers import label_doc, mutation_doc  # noqa: E402

from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.unified.corpus import aa, manifest  # noqa: E402
from tools.unified.mutations import classes  # noqa: E402


def sample():
    return [label_doc('aa-p0', 'aa', older='a' * 64, newer='a' * 64),
            label_doc('aa-p0b', 'aa'),
            label_doc('aa-p1', 'aa', method='aa-layout'),
            label_doc('noise-p2', 'noise'),
            label_doc('rel', 'release'), label_doc('cve', 'cve'), label_doc('ctl', 'control'),
            mutation_doc('mut-constant-00'), mutation_doc('mut-buf-resize-00', 'buf-resize', 'ka_buf_resize_00')]


def roles(docs):
    return {p.pair_id: p.role for p in manifest.build(docs, {}).pairs}


def test_aa_methods_get_the_names_of_the_gate():
    assert [aa.classify({'method': m}) for m in ('aa-rebuild', 'aa-layout', 'toolchain-noise', 'mutation')] == \
        ['P0', 'P1', 'P2', None]


def test_every_label_stratum_maps_to_one_role_and_authored_suites_are_left_to_spec_32():
    assert roles(sample()) == {'aa-p0': 'P0', 'aa-p0b': 'P0', 'aa-p1': 'P1', 'noise-p2': 'P2', 'rel': 'release',
                               'cve': 'cve-fix', 'ctl': 'control', 'mut-constant-00': 'mutation',
                               'mut-buf-resize-00': 'mutation'}
    built = manifest.build([*sample(), label_doc('suite-1', 'authored')], {})
    assert built.ignored == ('suite-1: stratum authored belongs to the SPEC-32 evaluation',)


def test_a_mutation_without_a_known_class_is_listed_as_ignored_not_dropped():
    built = manifest.build([label_doc('mut-x', 'mutation', target='t', case={'unified_class': 'nope'})], {})
    assert built.pairs == () and 'mut-x' in built.ignored[0] and 'unified_class' in built.ignored[0]


def test_gates_per_role_and_only_the_stress_pairs_are_not_gated():
    by_id = {p.pair_id: p for p in manifest.build(sample(), {}).pairs}
    assert by_id['rel'].gates == ('G-U3', 'G-U5', 'G-U7') and by_id['cve'].gates == ('G-U3', 'G-U7')
    assert by_id['aa-p0'].gates == ('G-U1',) and by_id['mut-constant-00'].gates == ('G-U2', 'G-U6')
    assert {p.pair_id for p in by_id.values() if not p.gated} == {'noise-p2'}


def test_x_vs_x_is_a_fact_of_the_images_not_of_the_method():
    by_id = {p.pair_id: p for p in manifest.build(sample(), {}).pairs}
    assert by_id['aa-p0'].x_vs_x is True and by_id['aa-p0b'].x_vs_x is False and by_id['rel'].x_vs_x is False


def test_mutation_facts_come_from_the_label_case():
    by_id = {p.pair_id: p for p in manifest.build(sample(), {}).pairs}
    assert by_id['mut-constant-00'].mutation.model_dump() == {
        'unified_class': 'constant', 'target': 'ka_constant_00', 'verdicts': ('material', 'review')}
    assert by_id['mut-buf-resize-00'].mutation.verdicts == ('review',)
    assert by_id['rel'].mutation is None


def test_counts_and_digests_are_copied_from_the_documents():
    doc = label_doc('rel', 'release')
    pair = manifest.build([doc], {}).pairs[0]
    assert (pair.functions, pair.by_label, pair.labels_sha256) == (2, {'unchanged': 2}, doc.digest_sha256)
    assert pair.older.sha256 == 'a' * 64 and pair.newer.file_name == 'x.dll'


def test_the_manifest_is_the_same_for_every_input_order_and_its_digest_is_checked():
    docs = sample()
    first = manifest.dump(manifest.build(docs, {'clang': '18'}))
    shuffled = list(docs)
    random.Random(7).shuffle(shuffled)
    assert manifest.dump(manifest.build(shuffled, {'clang': '18'})) == first
    assert manifest.load(first).manifest_sha256 == json.loads(first)['manifest_sha256']
    tampered = json.loads(first)
    tampered['pairs'][0]['functions'] += 1
    with pytest.raises(C.ContractError, match='digest'):
        manifest.load(json.dumps(tampered).encode('utf-8'))
    with pytest.raises(C.ContractError):
        manifest.load(first.replace(b'unified-corpus-manifest/1', b'unified-corpus-manifest/2'))


def test_duplicate_pair_ids_are_refused():
    with pytest.raises(C.ContractError, match='twice'):
        manifest.build([label_doc('rel', 'release'), label_doc('rel', 'release', project='q')], {})


def test_pending_work_is_listed_with_reasons_and_never_silently_absent():
    items = {p.item: p.reason for p in manifest.build([], {}).pending}
    assert {f'mutation:{p.id}' for p in classes.PENDING} <= set(items)
    assert all(len(reason) > 30 for reason in items.values())
