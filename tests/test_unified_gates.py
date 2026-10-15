"""SPEC-31 S6a gate-report generator skeleton (tools/unified/gates_u.py; 08-evaluation s1, U-05).

Pure and hermetic: bench reports, manifests and JUnit files are built in the tests. What the gates that wait for S3 would say
about real data is deliberately not asserted here: those stay `pending`, which is the behaviour under test."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS), str(ROOT / 'src')]
from unified_s6_helpers import evaluated, label_doc, mutation_doc, row  # noqa: E402

from tools.calibration.tier_r.contracts import ContractError  # noqa: E402
from tools.unified import bench, gates_u  # noqa: E402
from tools.unified.corpus import manifest as corpus_manifest  # noqa: E402
from tools.unified.mutations import classes, templates  # noqa: E402

SPEC = (ROOT / 'docs' / 'specs' / 'unified-engine' / '08-evaluation.md').read_text(encoding='utf-8')
S3_GATES = ('G-U1', 'G-U2', 'G-U3', 'G-U4', 'G-U6', 'G-U7')


def spec_rows():
    """The 08-evaluation s1 table: gate, question, metric and threshold, data, first slice able to run it."""
    out = {}
    for line in SPEC.splitlines():
        cells = [cell.strip() for cell in line.strip().strip('|').split(' | ')]
        if len(cells) == 5 and re.fullmatch(r'G-U\d .*', cells[0]):
            out[cells[0][:4]] = {'question': cells[1], 'first_slice': cells[4]}
    return out


def junit(passed=(), failed=(), skipped=()):
    cases = [f'<testcase classname="tests.{m}" name="{n}"/>' for m, n in passed]
    cases += [f'<testcase classname="tests.{m}" name="{n}"><failure message="x">trace</failure></testcase>' for m, n in failed]
    cases += [f'<testcase classname="tests.{m}" name="{n}"><skipped message="why"/></testcase>' for m, n in skipped]
    return ('<?xml version="1.0"?><testsuites><testsuite name="pytest">' + ''.join(cases) + '</testsuite></testsuites>').encode()


ALL_G_U8 = [pair for check in gates_u.G_U8_CHECKS for pair in check.tests]
PASS_ALL = junit(passed=[tuple(p.split('::')) for p in ALL_G_U8])


def inputs(*, manifest=None, benches=(), xml=None, attested=None):
    return gates_u.Inputs(
        manifest=manifest, benches=list(benches), junit=gates_u.parse_junit(xml) if xml else None,
        attested=attested or {}, digests={})


def by_id(built):
    return {g.id: g for g in built.gates}


def good_bench(platform='Linux-6'):
    env = {**bench.environment(), 'platform': platform}
    rows = evaluated(row(n=10_000, ticks=60_000), row(n=60_000, ticks=360_000), row('ingest', 60_000))
    return bench.report(rows, env)


def corpus(per_class=20):
    docs = [label_doc('aa-p0', 'aa', older='a' * 64, newer='a' * 64), label_doc('aa-p1', 'aa', method='aa-layout'),
            label_doc('noise-p2', 'noise'), label_doc('rel', 'release')]
    for c in classes.CLASSES:
        docs += [mutation_doc(f'mut-{c.id}-{i:02d}', c.id, templates.generate(c.id, per_class, seed=1).names[i])
                 for i in range(per_class)]
    return corpus_manifest.build(docs, {})


# ---- registry ----------------------------------------------------------------------------------------------------------------------

def test_the_registry_has_the_eight_gates_with_the_questions_and_first_slices_of_the_spec():
    spec = spec_rows()
    assert [g.id for g in gates_u.GATES] == [f'G-U{i}' for i in range(1, 9)] == sorted(spec)
    for gate in gates_u.GATES:
        assert (gate.question, gate.first_slice) == (spec[gate.id]['question'], spec[gate.id]['first_slice']), gate.id


def test_each_waiting_gate_names_what_it_waits_for_and_never_a_slice_that_is_built():
    needs = {g.id: g.needs for g in gates_u.GATES}
    assert needs['G-U1'] == needs['G-U2'] == needs['G-U4'] == needs['G-U7'] == ('S3',)
    assert needs['G-U3'] == ('IR-to-ladder adapter', 'S6b')                         # S2 is built: its first-slice cell is no wait
    assert needs['G-U6'] == ('S3', 'SPEC-32 evaluation core')
    reported = {g.id: g.needs for g in gates_u.build_report(inputs()).gates}
    assert all(reported[i] == needs[i] for i in S3_GATES)


def test_every_gate_that_waits_says_for_what_and_what_it_will_read():
    for gate in gates_u.GATES:
        if gate.id in S3_GATES:
            assert gate.waits and all(len(w) > 30 for w in gate.waits) and gate.consumes, gate.id
    assert gates_u.BY_ID['G-U3'].blocked and 'bindiff' in gates_u.BY_ID['G-U3'].blocked[0].lower()


# ---- the skeleton ------------------------------------------------------------------------------------------------------------------

def test_with_no_input_no_gate_passes_and_each_says_why():
    built = gates_u.build_report(inputs())
    assert len(built.gates) == 8 and all(g.status != 'pass' for g in built.gates)
    assert {g.id: g.status for g in built.gates} == {**dict.fromkeys(S3_GATES, 'pending'),
                                                      'G-U5': 'insufficient-data', 'G-U8': 'insufficient-data'}
    assert all(g.reasons for g in built.gates) and built.flag.decision_ready is False


def test_gates_that_need_s3_stay_pending_whatever_the_corpus_and_the_other_inputs_look_like():
    built = gates_u.build_report(inputs(manifest=corpus(), benches=[good_bench()], xml=PASS_ALL,
                                        attested={'frozen-smoke': 'pass'}))
    assert {g.id: g.status for g in built.gates if g.id in S3_GATES} == dict.fromkeys(S3_GATES, 'pending')
    assert built.flag.decision_ready is False and 'U-05' in built.flag.rule


def test_the_decision_is_ready_only_when_g_u1_to_g_u6_pass_and_nothing_else_counts():
    rows = [gates_u.GateRow(id=g.id, question=g.question, first_slice=g.first_slice, status='pass', reasons=(),
                            needs=(), observed={}) for g in gates_u.GATES]
    assert gates_u.decision_ready(rows) is True
    for index in range(6):
        weaker = [r.model_copy(update={'status': 'pending' if i == index else 'pass'}) for i, r in enumerate(rows)]
        assert gates_u.decision_ready(weaker) is False
    rows[6] = rows[6].model_copy(update={'status': 'fail'})
    assert gates_u.decision_ready(rows) is True                                      # U-05 names G-U1..G-U6


def test_readiness_counts_the_corpus_the_gates_will_read_and_flags_what_is_short():
    full = gates_u.build_report(inputs(manifest=corpus(per_class=20)))
    g2 = by_id(full)['G-U2'].observed['corpus']
    assert g2['classes_below_minimum'] == [] and set(g2['mutants_per_class'].values()) == {20}
    assert {p['class'] for p in g2['pending_classes']} == {'moved-rva-call', 'try-scope'}
    g1 = by_id(full)['G-U1'].observed['corpus']
    assert (g1['P0'], g1['P0_x_vs_x'], g1['P1'], g1['P2']) == (1, 1, 1, 1) and len(g1['pending_p1']) == 4
    short = gates_u.build_report(inputs(manifest=corpus(per_class=19)))
    assert set(by_id(short)['G-U2'].observed['corpus']['classes_below_minimum']) == {c.id for c in classes.CLASSES}
    g3 = by_id(full)['G-U3'].observed['corpus']
    assert g3['lineages'] == 1 and g3['anti_conservative'] is True                      # B = 2000 over 1 lineage is no interval


# ---- G-U5 ---------------------------------------------------------------------------------------------------------------------------

def test_g_u5_a_passing_bench_still_waits_for_facts_the_read_model_and_the_windows_run():
    g5 = by_id(gates_u.build_report(inputs(benches=[good_bench()])))['G-U5']
    assert g5.status == 'pending' and g5.observed['measured'] == ['pass']
    text = ' '.join(g5.reasons)
    assert 'facts' in text and 'read_model' in text and 'Windows' in text


def test_g_u5_a_windows_report_removes_only_the_windows_reason():
    g5 = by_id(gates_u.build_report(inputs(benches=[good_bench(), good_bench('Windows-11')])))['G-U5']
    assert g5.status == 'pending' and 'Windows' not in ' '.join(g5.reasons) and g5.observed['windows_report'] is True


def test_g_u5_a_measured_failure_is_a_failure_even_while_other_parts_wait():
    slow = bench.report(evaluated(row(n=10_000, ladder=10**6)), bench.environment())
    g5 = by_id(gates_u.build_report(inputs(benches=[good_bench(), slow])))['G-U5']
    assert g5.status == 'fail' and any('l35_ladder_10k_s' in r for r in g5.reasons)


def test_g_u5_without_a_gated_size_there_is_not_enough_data():
    informational = bench.report(evaluated(row(n=250_000)), bench.environment())
    g5 = by_id(gates_u.build_report(inputs(benches=[informational])))['G-U5']
    assert g5.status == 'insufficient-data' and 'gated' in ' '.join(g5.reasons)


# ---- G-U8 ---------------------------------------------------------------------------------------------------------------------------

def test_g_u8_every_check_names_tests_that_exist_in_the_repository():
    defined = {}
    for path in (ROOT / 'tests').glob('test_*.py'):
        defined[path.stem] = set(re.findall(r'^def (test_\w+)', path.read_text(encoding='utf-8'), re.M))
    for check in gates_u.G_U8_CHECKS:
        for name in check.tests:
            module, test = name.split('::')
            assert test in defined.get(module, set()), name
    assert {c.id for c in gates_u.G_U8_CHECKS if not c.tests} == {'ui-policy', 'frozen-smoke'}


def test_g_u8_all_present_checks_pass_but_the_ui_policy_waits_for_s4_and_the_smoke_has_no_attestation():
    g8 = by_id(gates_u.build_report(inputs(xml=PASS_ALL)))['G-U8']
    assert g8.status == 'pending'
    states = {c['id']: c['status'] for c in g8.observed['checks']}
    assert states['ui-policy'] == 'pending' and states['frozen-smoke'] == 'missing'
    assert {s for k, s in states.items() if k not in ('ui-policy', 'frozen-smoke')} == {'pass'}


def test_g_u8_stays_pending_on_the_ui_policy_until_s4_names_its_tests_even_with_everything_else_green():
    g8 = by_id(gates_u.build_report(inputs(xml=PASS_ALL, attested={'frozen-smoke': 'pass'})))['G-U8']
    assert g8.status == 'pending' and 'S4' in ' '.join(g8.reasons)
    states = {c['id']: c['status'] for c in g8.observed['checks']}
    assert states['frozen-smoke'] == 'pass' and states['ui-policy'] == 'pending'
    assert {s for k, s in states.items() if k != 'ui-policy'} == {'pass'}


def test_g_u8_a_failing_test_is_a_failure_and_a_skipped_one_is_blocked_not_a_pass():
    first = tuple(ALL_G_U8[0].split('::'))
    rest = [tuple(p.split('::')) for p in ALL_G_U8[1:]]
    failed = by_id(gates_u.build_report(inputs(xml=junit(passed=rest, failed=[first]))))['G-U8']
    assert failed.status == 'fail' and any('failed' in r for r in failed.reasons)
    skipped = by_id(gates_u.build_report(inputs(xml=junit(passed=rest, skipped=[first]))))['G-U8']
    assert skipped.status != 'pass' and skipped.status != 'fail'
    assert {c['id']: c['status'] for c in skipped.observed['checks']}['primary-snapshot-unchanged'] == 'blocked'


def test_g_u8_a_parametrised_test_passes_only_if_every_instance_passes():
    module, name = ALL_G_U8[1].split('::')
    xml = junit(passed=[(m, n) for m, n in (p.split('::') for p in ALL_G_U8 if p != ALL_G_U8[1])] +
                [(module, f'{name}[a]')], failed=[(module, f'{name}[b]')])
    assert by_id(gates_u.build_report(inputs(xml=xml)))['G-U8'].status == 'fail'


def test_a_failed_attestation_fails_the_gate():
    built = gates_u.build_report(inputs(xml=PASS_ALL, attested={'frozen-smoke': 'fail'}))
    assert by_id(built)['G-U8'].status == 'fail'


def test_junit_files_are_parsed_defensively():
    parsed = gates_u.parse_junit(junit(passed=[('test_a', 'test_x[1]'), ('test_a', 'test_x[2]')],
                                       failed=[('test_a', 'test_y')], skipped=[('test_b', 'test_z')]))
    assert parsed == {'test_a::test_x': ['passed', 'passed'], 'test_a::test_y': ['failed'], 'test_b::test_z': ['skipped']}
    declared = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY a "b">]><testsuites/>'
    for bad in (b'<!DOCTYPE x [<!ENTITY a "b">]><testsuites/>', b'<!doctype x><testsuites/>', b'not xml', b'<root/>',
                b'x' * (9 * 2**20), declared.encode('utf-16'), declared.encode('utf-16-le'),
                b'<testsuites>\x00</testsuites>'):
        with pytest.raises(ContractError):
            gates_u.parse_junit(bad)


# ---- report -----------------------------------------------------------------------------------------------------------------------

def test_the_report_is_deterministic_strict_and_its_digest_is_checked():
    args = dict(manifest=corpus(), benches=[good_bench()], xml=PASS_ALL)
    first = gates_u.dump(gates_u.build_report(inputs(**args)))
    assert gates_u.dump(gates_u.build_report(inputs(**args))) == first and b'\r' not in first
    assert gates_u.load(first).report_sha256 == json.loads(first)['report_sha256']
    tampered = json.loads(first)
    tampered['gates'][0]['status'] = 'pass'
    with pytest.raises(ContractError, match='digest'):
        gates_u.load(json.dumps(tampered).encode('utf-8'))


def test_the_markdown_names_every_gate_its_status_and_the_claim_and_never_a_percentage_of_accuracy():
    text = gates_u.render_markdown(gates_u.build_report(inputs(manifest=corpus(), benches=[good_bench()])))
    for gate in gates_u.GATES:
        assert f'| {gate.id} |' in text
    assert 'says nothing about Windows system files' in text and 'U-05' in text
    assert not re.search(r'accura', text, re.I) or 'no accuracy claim' in text


# ---- command line ---------------------------------------------------------------------------------------------------------------------

def write(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    return str(path)


def test_the_command_line_writes_json_and_markdown_and_is_advisory_unless_strict(tmp_path, capsys):
    man = write(tmp_path / 'm.json', corpus_manifest.dump(corpus()))
    ben = write(tmp_path / 'b.json', bench.dump(good_bench()))
    xml = write(tmp_path / 'j.xml', PASS_ALL)
    out, md = tmp_path / 'gates.json', tmp_path / 'gates.md'
    args = ['--manifest', man, '--bench', ben, '--junit', xml, '--out', str(out), '--markdown', str(md)]
    assert gates_u.main(args) == 0
    built = gates_u.load(out.read_bytes())
    assert built.inputs['manifest']['sha256'] and built.inputs['bench'][0]['verdict'] == 'pass'
    assert md.read_text(encoding='utf-8').startswith('# SPEC-31 gate report')
    assert gates_u.main([*args, '--strict']) == 1                                     # advisory by default, strict on demand
    capsys.readouterr()


def test_unreadable_or_tampered_inputs_are_a_usage_error_not_a_report(tmp_path, capsys):
    bad = write(tmp_path / 'b.json', b'{"contract": "bench-report/1"}')
    assert gates_u.main(['--bench', bad, '--out', str(tmp_path / 'o.json')]) == 2
    assert gates_u.main(['--manifest', str(tmp_path / 'missing.json'), '--out', str(tmp_path / 'o.json')]) == 2
    assert gates_u.main(['--attest', 'nonsense', '--out', str(tmp_path / 'o.json')]) == 2
    assert gates_u.main(['--attest', 'unknown-check=pass', '--out', str(tmp_path / 'o.json')]) == 2
    assert not (tmp_path / 'o.json').exists() and 'error' in capsys.readouterr().err
