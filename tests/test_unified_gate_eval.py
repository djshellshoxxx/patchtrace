"""SPEC-31 S6b: the evaluators of G-U1 (A/A null) and G-U2 (planted mutations) over `unified-outcomes/1`, and the outcome
documents themselves. Pure and hermetic: label documents come from the SPEC-32 contract, outcome rows are written by hand
(the engine is not run here; the pipeline-to-outcome join has its own test in test_unified_outcomes_join.py)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s6_helpers import label_doc, mutation_doc  # noqa: E402

from tools.calibration.tier_r.contracts import ContractError  # noqa: E402
from tools.unified import gates_u, outcomes  # noqa: E402
from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402
from tools.unified.mutations import classes, templates  # noqa: E402

R = outcomes.OutcomeRow


def rows(n=20, *, materiality='unchanged', decision='matched'):
    return [R(older=(0x1000 + 16 * i,), newer=(0x1000 + 16 * i,), decision=decision, materiality=materiality)
            for i in range(n)]


def pair(doc, rs, orientation='forward'):
    return outcomes.collect_rows(rs, doc, orientation=orientation)


def run(name, *pairs):
    return outcomes.build(name, 'Linux-6', pairs)


def inputs(manifest, *sets):
    return gates_u.Inputs(manifest=manifest, outcomes=list(sets))


def gate(built, gid):
    return {g.id: g for g in built.gates}[gid]


# ---- G-U1 ---------------------------------------------------------------------------------------------------------------------

def aa_manifest():
    return corpus_manifest.build([
        label_doc('aa-x', 'aa', older='a' * 64, newer='a' * 64), label_doc('aa-p0', 'aa'),
        label_doc('aa-p1', 'aa', method='aa-layout'), label_doc('noise-p2', 'noise')], {})


def aa_run(x=None, p0=None, p1=None, p2=None):
    docs = {d.pair_id: d for d in (label_doc('aa-x', 'aa', older='a' * 64, newer='a' * 64), label_doc('aa-p0', 'aa'),
                                   label_doc('aa-p1', 'aa', method='aa-layout'), label_doc('noise-p2', 'noise'))}
    given = {'aa-x': x, 'aa-p0': p0, 'aa-p1': p1, 'noise-p2': p2}
    return run('linux', *(pair(docs[k], v) for k, v in given.items() if v is not None))


def good_aa():
    return aa_run(x=rows(), p0=rows(), p1=rows(), p2=rows(5, materiality='material'))


def test_g_u1_clean_aa_pairs_pass_the_data_but_the_unbuilt_p1_variants_keep_it_pending():
    g1 = gate(gates_u.build_report(inputs(aa_manifest(), good_aa())), 'G-U1')
    assert g1.status == 'pending'
    assert any('P1:icf-toggle' in r for r in g1.reasons) and not any('fail' in r for r in g1.reasons)
    assert g1.observed['evaluated'] == {'aa-p0': 'pass', 'aa-p1': 'pass', 'aa-x': 'pass'}      # P2 is reported, never gated


def test_g_u1_passes_when_nothing_is_pending():
    m = aa_manifest()
    done = m.model_copy(update={'pending': tuple(p for p in m.pending if not p.item.startswith('P1:'))})
    assert gate(gates_u.build_report(inputs(done, good_aa())), 'G-U1').status == 'pass'


@pytest.mark.parametrize('bad', ['changed-row', 'one-sided', 'contested'], ids=['changed', 'one-sided', 'contested'])
def test_g_u1_x_vs_x_must_be_all_matched_and_unchanged(bad):
    broken = rows()
    broken[3] = R(older=broken[3].older, newer=broken[3].newer, decision='matched', materiality='review') \
        if bad == 'changed-row' else R(older=broken[3].older, newer=(), decision='older-only', materiality='not-applicable') \
        if bad == 'one-sided' else R(older=broken[3].older, newer=broken[3].newer, decision='contested',
                                     materiality='unchanged')
    g1 = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(x=broken, p0=rows(), p1=rows()))), 'G-U1')
    assert g1.status == 'fail' and any('aa-x' in r for r in g1.reasons)


def test_g_u1_a_material_row_on_a_rebuild_or_a_nuisance_pair_fails():
    for which in ('p0', 'p1'):
        broken = rows()
        broken[0] = R(older=broken[0].older, newer=broken[0].newer, decision='matched', materiality='material')
        args = {'x': rows(), 'p0': rows(), 'p1': rows(), which: broken}
        g1 = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(**args))), 'G-U1')
        assert g1.status == 'fail' and any(f'aa-{which}' in r and 'material' in r for r in g1.reasons)


def test_g_u1_review_rows_on_a_rebuild_are_bounded_at_a_tenth_of_a_percent():
    one = rows(1000)
    one[5] = R(older=one[5].older, newer=one[5].newer, decision='matched', materiality='review')
    ok = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(x=rows(), p0=one, p1=rows()))), 'G-U1')
    assert ok.status == 'pending'                                            # 1 of 1000 = 0.1 %, at the limit
    two = list(one)
    two[6] = R(older=two[6].older, newer=two[6].newer, decision='matched', materiality='review')
    bad = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(x=rows(), p0=two, p1=rows()))), 'G-U1')
    assert bad.status == 'fail' and any('review' in r for r in bad.reasons)


def test_g_u1_a_missing_pair_or_an_empty_result_is_insufficient_data_never_a_pass():
    g1 = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(x=rows(), p0=rows()))), 'G-U1')
    assert g1.status == 'insufficient-data' and any('aa-p1' in r and 'no outcome' in r for r in g1.reasons)
    empty = gate(gates_u.build_report(inputs(aa_manifest(), aa_run(x=rows(), p0=rows(), p1=[]))), 'G-U1')
    assert empty.status == 'insufficient-data' and any('no rows' in r for r in empty.reasons)
    assert gate(gates_u.build_report(inputs(aa_manifest())), 'G-U1').status == 'insufficient-data'


def test_g_u1_a_failure_in_any_run_fails_even_if_another_run_is_clean():
    broken = rows()
    broken[0] = R(older=broken[0].older, newer=broken[0].newer, decision='matched', materiality='material')
    other = aa_run(x=rows(), p0=broken, p1=rows())
    g1 = gate(gates_u.build_report(inputs(aa_manifest(), good_aa(), run_named(other, 'windows'))), 'G-U1')
    assert g1.status == 'fail'


def run_named(outcome_set, name):
    return outcomes.build(name, 'Windows-11', outcome_set.pairs)


# ---- G-U2 ---------------------------------------------------------------------------------------------------------------------

def mutants(per_class=20):
    out = []
    for c in classes.CLASSES:
        names = templates.generate(c.id, per_class, seed=1).names
        out += [mutation_doc(f'mut-{c.id}-{i:02d}', c.id, names[i]) for i in range(per_class)]
    return out


def mut_manifest(per_class=20):
    return corpus_manifest.build(mutants(per_class), {})


def planted_row(doc, materiality):
    p = outcomes.planted_of(doc)
    return R(older=(p.older_rva,), newer=(p.newer_rva,), decision='matched', materiality=materiality)


def accepted(doc, cls):
    return 'review' if cls == 'buf-resize' else 'material'


def mut_run(per_class=20, verdict=accepted, skip=()):
    ps = []
    for doc in mutants(per_class):
        cls = doc.case['unified_class']
        if (doc.pair_id) in skip:
            continue
        ps.append(pair(doc, [*rows(3), planted_row(doc, verdict(doc, cls))]))
    return run('linux', *ps)


def test_g_u2_every_planted_function_detected_passes_the_data_and_pending_classes_keep_it_pending():
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), mut_run())), 'G-U2')
    assert g2.status == 'pending' and not any('leak' in r for r in g2.reasons)
    assert any('moved-rva-call' in r for r in g2.reasons) and any('try-scope' in r for r in g2.reasons)
    per = g2.observed['classes']
    assert set(per) == {c.id for c in classes.CLASSES}
    assert all(v['mutants'] == 20 and v['detected'] == 20 and v['leaks'] == 0 for v in per.values())


@pytest.mark.parametrize('leak', ['cosmetic', 'unchanged'])
def test_g_u2_one_leak_into_cosmetic_or_unchanged_fails_whatever_the_recall(leak):
    def verdict(doc, cls):
        return leak if doc.pair_id == 'mut-constant-03' else accepted(doc, cls)
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), mut_run(verdict=verdict))), 'G-U2')
    assert g2.status == 'fail' and any('mut-constant-03' in r and 'leak' in r for r in g2.reasons)


def test_g_u2_recall_below_95_percent_fails_and_exactly_95_percent_does_not():
    def run_missing(count):
        ps = []
        for doc in mutants():
            body = rows(3)
            if doc.case['unified_class'] == 'bound' and int(doc.pair_id[-2:]) < count:
                p = outcomes.planted_of(doc)
                body.append(R(older=(p.older_rva,), newer=(), decision='older-only', materiality='not-applicable'))
            else:
                body.append(planted_row(doc, accepted(doc, doc.case['unified_class'])))
            ps.append(pair(doc, body))
        return run('linux', *ps)

    assert gate(gates_u.build_report(inputs(mut_manifest(), run_missing(1))), 'G-U2').observed['classes']['bound']['recall'] == 0.95
    assert not any('recall' in r for r in gate(gates_u.build_report(inputs(mut_manifest(), run_missing(1))), 'G-U2').reasons)
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), run_missing(2))), 'G-U2')
    assert g2.status == 'fail' and any('bound' in r and 'recall' in r for r in g2.reasons)


def test_g_u2_the_frame_only_class_must_land_in_review_not_material():
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), mut_run(verdict=lambda d, c: 'material'))), 'G-U2')
    assert g2.observed['classes']['buf-resize']['detected'] == 0 and g2.status == 'fail'
    ok = gate(gates_u.build_report(inputs(mut_manifest(), mut_run(verdict=lambda d, c: 'review' if c == 'buf-resize' else 'material'))), 'G-U2')
    assert ok.observed['classes']['buf-resize']['detected'] == 20


def test_g_u2_fewer_than_20_mutants_with_outcomes_is_insufficient_data():
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), mut_run(skip={'mut-constant-00'}))), 'G-U2')
    assert g2.status == 'insufficient-data' and any('constant' in r and '19' in r for r in g2.reasons)


def test_g_u2_a_planted_function_that_pairs_with_another_function_is_a_miss_not_a_hit():
    ps = []
    for doc in mutants():
        p = outcomes.planted_of(doc)
        wrong = doc.pair_id == 'mut-constant-00'
        ps.append(pair(doc, [R(older=(p.older_rva,), newer=(p.newer_rva + 0x40 if wrong else p.newer_rva,), decision='matched',
                               materiality='material')]))
    g2 = gate(gates_u.build_report(inputs(mut_manifest(), run('linux', *ps))), 'G-U2')
    assert g2.observed['classes']['constant']['detected'] == 19 and g2.observed['classes']['constant']['mispaired'] == 1


# ---- outcome documents -------------------------------------------------------------------------------------------------------

def test_outcome_documents_round_trip_are_deterministic_and_reject_edits():
    doc = mutation_doc('mut-constant-00', 'constant', 'ka_constant_00')
    first = outcomes.dump(run('linux', pair(doc, rows(2))))
    assert outcomes.dump(run('linux', pair(doc, list(reversed(rows(2)))))) == first          # row order is not a fact
    assert outcomes.load(first).pairs[0].planted.name == 'ka_constant_00'
    with pytest.raises(ContractError, match='digest'):
        outcomes.load(first.replace(b'"matched"', b'"contested"', 1))
    with pytest.raises(ContractError):
        outcomes.build('linux', 'x', [pair(doc, rows(1)), pair(doc, rows(1))])


def test_a_mutant_label_document_needs_exactly_one_planted_function():
    plain = label_doc('rel', 'release')
    assert outcomes.planted_of(plain) is None


def test_the_command_line_reads_manifest_and_outcome_files_into_the_report(tmp_path, capsys):
    man = tmp_path / 'm.json'
    man.write_bytes(corpus_manifest.dump(aa_manifest()))
    out = tmp_path / 'o.json'
    out.write_bytes(outcomes.dump(good_aa()))
    report = tmp_path / 'r.json'
    assert gates_u.main(['--manifest', str(man), '--outcomes', str(out), '--out', str(report)]) == 0
    loaded = gates_u.load(report.read_bytes())
    g1 = {g.id: g for g in loaded.gates}['G-U1']
    assert g1.status == 'pending' and loaded.inputs['outcomes'][0]['run'] == 'linux'
    capsys.readouterr()
    assert gates_u.main(['--outcomes', str(tmp_path / 'missing.json')]) == 2


# ---- G-U4 ---------------------------------------------------------------------------------------------------------------------

def swapped(rs):
    flip = {'older-only': 'newer-only', 'newer-only': 'older-only'}
    return [R(older=r.newer, newer=r.older, decision=flip.get(r.decision, r.decision), materiality=r.materiality) for r in rs]


def det_rows():
    return [*rows(4), R(older=(0x2000,), newer=(), decision='older-only', materiality='not-applicable'),
            R(older=(), newer=(0x3000,), decision='newer-only', materiality='not-applicable')]


def g4(manifest, *sets):
    return gate(gates_u.build_report(inputs(manifest, *sets)), 'G-U4')


def test_g_u4_equal_rows_across_runs_and_a_mirrored_swap_leave_only_the_unbuilt_chain_pending():
    doc = label_doc('rel', 'release')
    m = corpus_manifest.build([doc], {})
    a = run('linux', pair(doc, det_rows()), pair(doc, swapped(det_rows()), orientation='swapped'))
    b = run('windows', pair(doc, list(reversed(det_rows()))))
    g = g4(m, a, b)
    assert g.status == 'pending' and g.observed['compared'] == {'rel': 'equal'} and g.observed['mirrored'] == {'rel': 'mirrored'}
    assert any('3-build chain' in r for r in g.reasons)


def test_g_u4_rows_that_differ_between_two_runs_fail():
    doc = label_doc('rel', 'release')
    other = det_rows()
    other[0] = R(older=other[0].older, newer=other[0].newer, decision='matched', materiality='review')
    g = g4(corpus_manifest.build([doc], {}), run('linux', pair(doc, det_rows())), run('windows', pair(doc, other)))
    assert g.status == 'fail' and any('rel' in r and 'linux' in r and 'windows' in r for r in g.reasons)


def test_g_u4_a_swap_that_is_not_the_mirror_image_fails():
    doc = label_doc('rel', 'release')
    broken = swapped(det_rows())[1:]
    g = g4(corpus_manifest.build([doc], {}), run('linux', pair(doc, det_rows()), pair(doc, broken, orientation='swapped')))
    assert g.status == 'fail' and any('mirror' in r for r in g.reasons)


def test_g_u4_one_run_without_a_swap_has_nothing_to_compare():
    doc = label_doc('rel', 'release')
    g = g4(corpus_manifest.build([doc], {}), run('linux', pair(doc, det_rows())))
    assert g.status == 'insufficient-data' and g.observed['compared'] == {} and g.observed['mirrored'] == {}


def test_g_u4_runs_over_different_image_bytes_are_not_compared_and_never_a_failure():
    doc, rebuilt = label_doc('rel', 'release'), label_doc('rel', 'release', older='c' * 64, newer='d' * 64)
    other = det_rows()[1:]
    g = g4(corpus_manifest.build([doc], {}), run('linux', pair(doc, det_rows())), run('windows', pair(rebuilt, other)))
    assert g.status == 'insufficient-data' and g.observed['compared'] == {}
    assert g.observed['not_comparable'] == {'rel': ['linux', 'windows']} and any('bytes' in r for r in g.reasons)
