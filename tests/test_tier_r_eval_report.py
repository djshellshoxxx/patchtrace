"""SPEC-32 s10 report: determinism, BLOCKED/partial/failed engine states, Markdown, truncation, schemas. Engine output is
SYNTHETIC (StaticProvider over hand-made predictions); no live engine evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from test_tier_r_eval_metrics import FUNCS, make_labels, out, pred

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402
from tools.calibration.tier_r import report_schemas as RS  # noqa: E402

PAIRS = [make_labels(FUNCS, pair_id='syn-b', stratum='release'), make_labels(FUNCS, pair_id='syn-a', stratum='authored')]
GOOD = out(pred(0x1000, 0x1000, False), pred(0x1020, 0x1020, True), pred(0x1060, 0x1070, True))


def provider(engine='rz-diff', outputs=None):
    outputs = {'syn-a': GOOD, 'syn-b': GOOD} if outputs is None else outputs
    return E.StaticProvider(engine, {k: E.EngineOutput(engine, v.status, v.version, v.reason, v.predictions)
                                     for k, v in outputs.items()})


def test_report_is_deterministic_and_order_independent():
    first = E.evaluate(PAIRS, [provider()])
    second = E.evaluate(list(reversed(PAIRS)), [provider()])
    assert C.dump_json(first) == C.dump_json(second)
    assert C.load_report(C.dump_json(first)).report_sha256 == first['report_sha256']
    assert [i['pair_id'] for i in first['inputs']] == ['syn-a', 'syn-b']
    assert list(first['strata']) == ['authored', 'release']


def test_report_changes_when_a_metric_changes_and_tamper_is_detected():
    base = E.evaluate(PAIRS, [provider()])
    other = E.evaluate(PAIRS, [provider(outputs={'syn-a': out(), 'syn-b': GOOD})])
    assert base['report_sha256'] != other['report_sha256']
    tampered = json.loads(C.dump_json(base))
    tampered['strata']['authored']['rz-diff']['identity_tp'] += 1
    with pytest.raises(C.ContractError, match='digest'):
        C.load_report(json.dumps(tampered).encode())


def test_absent_engines_are_blocked_with_reasons_and_have_no_metrics():
    report = E.evaluate(PAIRS, [provider(), provider('bindiff', {}), provider('ghidriff', {})])
    states = {e['engine']: (e['status'], e['reason']) for e in report['engines']}
    assert states['rz-diff'][0] == 'ok'
    for engine in ('bindiff', 'ghidriff'):
        assert states[engine][0] == 'blocked' and 'no recorded output' in states[engine][1]
    assert set(report['strata']['authored']) == {'rz-diff'}
    assert {p['status'] for p in report['pairs'] if p['engine'] == 'bindiff'} == {'blocked'}
    assert all(p['metrics'] is None and p['output_sha256'] is None for p in report['pairs'] if p['engine'] == 'bindiff')
    md = E.render_markdown(report)
    assert '| bindiff | BLOCKED |' in md and 'no recorded output' in md


def test_partial_and_failed_states_and_provider_exceptions_are_isolated():
    class Boom:
        engine = 'rz-diff'

        def __call__(self, labels, symbols):
            if labels.pair_id == 'syn-a':
                raise RuntimeError('secret path /home/x')
            return GOOD
    report = E.evaluate(PAIRS, [Boom()])
    engine = report['engines'][0]
    assert (engine['status'], engine['runs'], engine['failures']) == ('partial', 1, 1)
    assert 'secret' not in json.dumps(report) and 'RuntimeError' in engine['reason']
    failing = E.StaticProvider('rz-diff', {p.pair_id: E.failed('rz-diff', 'rz-diff exited with 3') for p in PAIRS})
    report = E.evaluate(PAIRS, [failing])
    assert report['engines'][0]['status'] == 'failed' and report['strata'] == {}
    assert 'and 1 more pairs' in report['engines'][0]['reason']


def test_no_labels_and_duplicate_ids():
    assert E.evaluate([], [provider()])['engines'][0]['status'] == 'blocked'
    with pytest.raises(C.ContractError, match='duplicate'):
        E.evaluate([PAIRS[0], PAIRS[0]], [provider()])


def test_wrong_match_list_is_sorted_and_bounded():
    many = out(pred(0x1060, 0x1070, True), pred(0x1020, 0x1030, True), pred(0x1010, 0x1020, True))
    report = E.evaluate(PAIRS, [provider(outputs={'syn-a': many, 'syn-b': many})], max_wrong=2)
    keys = [(w['pair_id'], w['old_rva'], w['new_rva']) for w in report['wrong_matches']]
    assert keys == sorted(keys) and len(keys) == 2
    assert report['wrong_matches_truncated'] == 4          # 3 wrong pairs x 2 label sets = 6, 2 kept
    assert 'more wrong matches' in E.render_markdown(report)


def test_markdown_escapes_hostile_names():
    labels = make_labels([('evil|name`<b>', 0x1000, 0x1000, 'unchanged'), ('x', 0x1010, 0x1010, 'unchanged')],
                         pair_id='syn-evil')
    bad = out(pred(0x1000, 0x1010, False))
    md = E.render_markdown(E.evaluate([labels], [E.StaticProvider('rz-diff', {'syn-evil': bad})]))
    row = next(line for line in md.splitlines() if 'wrong-counterpart' in line)
    assert 'evil name' in row and row.count('|') == 8


def test_visible_symbols_note_and_flag():
    report = E.evaluate(PAIRS, [provider()], symbols='visible')
    assert report['symbols'] == 'visible' and any('not comparable' in n for n in report['notes'])


def test_pair_output_hash_covers_the_normalised_output():
    a = E.evaluate(PAIRS, [provider()])
    b = E.evaluate(PAIRS, [provider(outputs={'syn-a': GOOD, 'syn-b': out(pred(0x1000, 0x1000, True))})])
    sha = {p['pair_id']: p['output_sha256'] for p in a['pairs']}
    other = {p['pair_id']: p['output_sha256'] for p in b['pairs']}
    assert sha['syn-a'] == other['syn-a'] and sha['syn-b'] != other['syn-b']


def test_report_schema_files_and_examples_are_current():
    folder = ROOT / 'docs' / 'schemas' / 'corpus'
    for name, text in RS.render().items():
        assert (folder / name).read_text(encoding='utf-8') == text, name
    examples = RS.examples()
    on_disk = sorted((folder / RS.EXAMPLES).glob('*.json'))
    assert {p.name for p in on_disk} == set(examples)
    for path in on_disk:
        assert path.read_bytes() == C.dump_json(examples[path.name]), path.name
        ok, _ = RS.check_example(path)
        assert ok == path.name.startswith('valid-'), path.name


def test_example_report_is_labelled_synthetic():
    assert any('SYNTHETIC' in n for n in RS.example_report()['notes'])
