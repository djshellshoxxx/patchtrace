"""Deterministic smoke run of the hostile-input fuzz harness (tools/fuzz_parsers.py, RB-06 / WS-H).

Every registered target gets a small fixed run with seed 0. The long run is the nightly job; this keeps the
harness itself honest and re-checks the declared rejection types on every CI run.
"""
from __future__ import annotations

import importlib.util
import random
import sys
from contextlib import ExitStack
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'fuzz_parsers.py'
spec = importlib.util.spec_from_file_location('fuzz_parsers', TOOL)
fuzz = importlib.util.module_from_spec(spec)
sys.modules['fuzz_parsers'] = fuzz
spec.loader.exec_module(fuzz)

TARGETS = fuzz._targets()
ITERATIONS = 200


@pytest.mark.parametrize('name', sorted(TARGETS))
def test_target_rejects_hostile_input_only_with_declared_errors(name, tmp_path):
    report = fuzz.run_target(TARGETS[name], iterations=ITERATIONS, seed=0, time_budget=None, crash_dir=tmp_path)
    assert report.iterations == ITERATIONS
    assert [(f.kind, f.detail) for f in report.findings] == []
    assert not list(tmp_path.iterdir())


def test_registry_covers_every_untrusted_input_parser():
    assert {'strict_json', 'ghidriff', 'csaf', 'kb_import', 'kev', 'winbindex_rows', 'capa', 'floss',
            'diec'} <= set(TARGETS)
    assert 'kb_csv' in fuzz.TARGETS_SKIPPED


def test_mutation_is_deterministic_and_bounded():
    seed = TARGETS['kev'].seeds()[0]
    first = [fuzz.mutate(random.Random(7), seed) for _ in range(5)]
    again = [fuzz.mutate(random.Random(7), seed) for _ in range(5)]
    assert first == again
    rng = random.Random(1)
    assert all(len(fuzz.mutate(rng, seed)) <= fuzz.MAX_INPUT_BYTES for _ in range(200))


def _planted(entry, allowed=(ValueError,), cap=1000):
    return fuzz.Target('planted', lambda _stack, _tmp: entry, lambda: [b'{"a": 1}', b'seed-two'], allowed,
                       max_result_chars=cap)


def _bug(data: bytes):
    if b'a' in data:
        raise KeyError('planted')
    return None


def test_harness_flags_an_undeclared_exception_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    report = fuzz.run_target(_planted(_bug), iterations=50, seed=0, time_budget=None, crash_dir=tmp_path)
    assert report.findings and report.findings[0].kind == 'exception'
    assert 'KeyError' in report.findings[0].detail
    saved = list(tmp_path.iterdir())
    assert {f'planted-{f.digest}.bin' for f in report.findings} == {p.name for p in saved}
    assert {f.data for f in report.findings} == {p.read_bytes() for p in saved}
    monkeypatch.setattr(fuzz, '_targets', lambda: {'planted': _planted(_bug)})
    assert fuzz.main(['--target', 'planted', '--iterations', '20', '--crash-dir', str(tmp_path / 'c')]) == 1
    assert 'KeyError' in capsys.readouterr().err


def test_harness_accepts_declared_rejections(tmp_path):
    def reject(_data):
        raise ValueError('PT-SCHEMA: no')
    report = fuzz.run_target(_planted(reject), iterations=30, seed=0, time_budget=None, crash_dir=tmp_path)
    assert report.findings == [] and report.rejected == 30


def test_harness_flags_slow_input_and_result_blowup(tmp_path):
    slow = fuzz.run_target(_planted(lambda _d: None), iterations=3, seed=0, time_budget=None, deadline=-1.0,
                           crash_dir=tmp_path)
    assert slow.findings and slow.findings[0].kind == 'slow'
    big = fuzz.run_target(_planted(lambda _d: 'x' * 5000), iterations=3, seed=0, time_budget=None,
                          crash_dir=tmp_path)
    assert big.findings and big.findings[0].kind == 'blowup'


def test_unknown_target_is_a_usage_error():
    assert fuzz.main(['--target', 'no-such-target']) == 2


def test_resources_are_closed_after_a_run(tmp_path):
    closed = []

    def build(stack: ExitStack, _tmp):
        stack.callback(closed.append, True)
        return lambda _d: None
    target = fuzz.Target('closer', build, lambda: [b'{}'], (ValueError,))
    fuzz.run_target(target, iterations=2, seed=0, time_budget=None, crash_dir=tmp_path)
    assert closed == [True]
