"""Rule engine facade and runner against the real YARA-X wheel (synthetic PE images only, no network)."""
from __future__ import annotations

import hashlib
import struct
import threading
from importlib import metadata

import pytest

yara_x = pytest.importorskip('yara_x')

from patchtrace import optional_deps  # noqa: E402
from patchtrace.yarax import engine, runner  # noqa: E402
from patchtrace.yarax.contracts import RuleText, WorkerTarget  # noqa: E402
from patchtrace.yarax.errors import RulesError  # noqa: E402
from patchtrace.yarax.limits import RuleLimits  # noqa: E402

TEXT_RVA, TEXT_RAW = 0x1000, 0x200
GUARD = 'uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64'


def make_pe(body: bytes) -> bytes:
    """A minimal PE32+ image with one executable section holding `body`."""
    dos = b'MZ' + b'\0' * 58 + struct.pack('<I', 0x40)
    coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = struct.pack('<HBBIIIIIQIIHHHHHHIIIIHHQQQQII', 0x20b, 14, 0, 0x200, 0, 0, TEXT_RVA, TEXT_RVA,
                           0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, TEXT_RVA + 0x1000, 0x200, 0, 3, 0,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16).ljust(240, b'\0')
    section = struct.pack('<8sIIIIIIHHI', b'.text', 0x200, TEXT_RVA, 0x200, TEXT_RAW, 0, 0, 0, 0, 0x60000020)
    return (dos + b'PE\0\0' + coff + optional + section).ljust(TEXT_RAW, b'\0') + body.ljust(0x200, b'\0')


def rule(name: str, pattern: str, extra: str = '') -> RuleText:
    text = f'import "pe"\n\nrule {name} {{\n  strings:\n    $b = {{ {pattern} }}\n  condition:\n    {GUARD} and $b{extra}\n}}\n'
    return RuleText(name=name, text=text)


OLDER = rule('PT_0123456789ab_older', '41 42 ?? 44')
NEWER = rule('PT_0123456789ab_newer', '5A 5B ?? 5D')
IMAGES = {'older': make_pe(b'\x90' * 8 + b'ABCD' + b'ABXD'), 'newer': make_pe(b'\x90' * 8 + b'ZZZZ' + b'\x5a\x5b\x5c\x5d'),
          'plain': b'not a portable executable' * 4}


def target(tmp_path, tid: str, data: bytes | None, **overrides) -> WorkerTarget:
    path = tmp_path / f'{tid}.bin'
    if data is not None:
        path.write_bytes(data)
    fields = {'target_id': tid, 'path': str(path), 'sha256': hashlib.sha256(data or b'').hexdigest(),
              'size': len(data or b'')} | overrides
    return WorkerTarget(**fields)


LIMITS = runner.worker_limits()


def grid(cells):
    return {(c.target_id, c.rule_name.rsplit('_', 1)[1]): (c.state, c.hits, c.offsets, c.rvas, c.reason) for c in cells}


def build_targets(tmp_path):
    return [target(tmp_path, 'older', IMAGES['older']), target(tmp_path, 'newer', IMAGES['newer']),
            target(tmp_path, 'plain', IMAGES['plain']), target(tmp_path, 'missing', None, size=5, sha256=None),
            target(tmp_path, 'moved', IMAGES['older'], sha256='1' * 64)]


# offsets: file offset 0x200 + 8; rvas: 0x1000 + 8
GOLDEN = {
    ('older', 'older'): ('hit', 2, (0x208, 0x20c), (0x1008, 0x100c), ''),
    ('older', 'newer'): ('no-hit', 0, (), (), ''),
    ('newer', 'older'): ('no-hit', 0, (), (), ''),
    ('newer', 'newer'): ('hit', 1, (0x20c,), (0x100c,), ''),
    ('plain', 'older'): ('not-scanned', 0, (), (), 'not a PE image'),
    ('plain', 'newer'): ('not-scanned', 0, (), (), 'not a PE image'),
    ('missing', 'older'): ('not-scanned', 0, (), (), 'file could not be read'),
    ('missing', 'newer'): ('not-scanned', 0, (), (), 'file could not be read'),
    ('moved', 'older'): ('not-scanned', 0, (), (), 'file changed while reading'),
    ('moved', 'newer'): ('not-scanned', 0, (), (), 'file changed while reading'),
}


def test_engine_scan_grid_equals_golden(tmp_path):
    cells = engine.scan([OLDER, NEWER], build_targets(tmp_path), LIMITS)
    assert grid(cells) == GOLDEN
    assert all(c.verdict == 'unscored' for c in cells)


def test_unreadable_files_are_never_counted_as_no_hit(tmp_path):
    cells = engine.scan([OLDER], build_targets(tmp_path), LIMITS)
    assert {c.state for c in cells if c.target_id in ('plain', 'missing', 'moved')} == {'not-scanned'}


def test_oversized_file_is_not_scanned(tmp_path):
    cells = engine.scan([OLDER], [target(tmp_path, 'big', IMAGES['older'])], LIMITS | {'target_file_bytes': 100})
    assert [(c.state, c.reason) for c in cells] == [('not-scanned', 'file is larger than the limit')]


def test_offsets_are_capped_and_sorted(tmp_path):
    many = make_pe(b'ABCD' * 100)
    cells = engine.scan([OLDER], [target(tmp_path, 'many', many)], LIMITS | {'cell_offsets': 3})
    assert cells[0].hits == 64 and cells[0].offsets == (0x200, 0x204, 0x208)  # max_matches_per_pattern == 64


class _Engine:
    """The real module with a scanner that fails as the engine would."""

    def __init__(self, error):
        self._error = error

    def __getattr__(self, name):
        return getattr(yara_x, name)

    def Scanner(self, rules):  # noqa: N802 - mirrors the module attribute
        error = self._error

        class Failing:
            set_timeout = max_matches_per_pattern = staticmethod(lambda _value: None)

            @staticmethod
            def scan(_data):
                raise error
        return Failing()


@pytest.mark.parametrize('error, state, reason', [
    (yara_x.TimeoutError(), 'timeout', 'scan exceeded the time limit'),
    (yara_x.ScanError(), 'error', 'the engine could not scan this file'),
], ids=['timeout', 'scan-error'])
def test_engine_failures_become_cells_not_no_hits(tmp_path, monkeypatch, error, state, reason):
    monkeypatch.setattr(optional_deps, 'yara_x', _Engine(error))
    cells = engine.scan([OLDER], [target(tmp_path, 'older', IMAGES['older'])], LIMITS)
    assert [(c.state, c.reason, c.hits) for c in cells] == [(state, reason, 0)]


def test_stamp_reports_the_installed_wheel():
    stamp = engine.stamp()
    assert (stamp.version, stamp.version_source) == (metadata.version('yara-x'), 'metadata')
    assert (stamp.grammar, stamp.worker) == ('yrx-gen/1', 'rules-worker/1')


def test_missing_wheel_is_the_unavailable_state(monkeypatch):
    monkeypatch.setattr(optional_deps, 'yara_x', None)
    for call in (engine.stamp, lambda: engine.lint([OLDER]), lambda: engine.scan([OLDER], [], LIMITS)):
        with pytest.raises(RulesError) as caught:
            call()
        assert caught.value.code == 'PT-RULE-UNAVAILABLE'


def test_lint_is_clean_for_a_generated_shape():
    assert engine.lint([OLDER, NEWER]) == ()


@pytest.mark.parametrize('text, name, severity, code', [
    ('rule PT_0123456789ab_older { strings: $a = { 41 42 43 44 } condition: $a }', 'PT_0123456789ab_older',
     'warning', 'text_as_hex'),
    ('rule PT_0123456789ab_older { strings: $a = /a.*/ condition: $a }', 'PT_0123456789ab_older', 'error', None),
    ('rule PT_0123456789ab_older { condition: bogus }', 'PT_0123456789ab_older', 'error', 'E009'),
    ('rule PT_0123456789ab_older { condition: true }\nrule PT_0123456789ab_older { condition: true }',
     'PT_0123456789ab_older', 'error', None),
], ids=['text-as-hex', 'slow-pattern', 'unknown-identifier', 'duplicate-rule'])
def test_lint_reports_warnings_and_errors_per_rule(text, name, severity, code):
    findings = engine.lint([RuleText(name=name, text=text)])
    assert findings and all(f.rule_name == name for f in findings)
    assert any(f.severity == severity and (code is None or f.code == code) for f in findings)


def test_lint_refuses_a_foreign_rule_name():
    findings = engine.lint([RuleText(name='PT_0123456789ab_older', text='rule evil { condition: true }')])
    assert [f.severity for f in findings] == ['error']


def test_scan_compile_failure_is_typed_and_message_is_bounded():
    with pytest.raises(RulesError) as caught:
        engine.scan([RuleText(name='PT_0123456789ab_older', text='rule evil { condition: true }')], [], LIMITS)
    assert caught.value.code == 'PT-RULE-COMPILE' and len(caught.value.message) <= 600


def test_rules_never_include_files(tmp_path):
    (tmp_path / 'inc.yar').write_text('rule PT_aaaaaaaaaaaa_older { condition: true }', encoding='utf-8')
    text = f'include "{(tmp_path / "inc.yar").as_posix()}"\nrule PT_0123456789ab_older {{ condition: true }}'
    assert any(f.severity == 'error' for f in engine.lint([RuleText(name='PT_0123456789ab_older', text=text)]))


# --- end to end through the capped child process -----------------------------------------------------------------

def test_runner_probe_lint_and_scan_in_a_real_child(tmp_path):
    cancel = threading.Event()
    stamp = runner.probe(cancel=cancel, private_dir=tmp_path)
    assert stamp.version == metadata.version('yara-x')
    engine_stamp, findings = runner.lint([OLDER, NEWER], cancel=cancel, private_dir=tmp_path)
    assert (engine_stamp, findings) == (stamp, ())
    engine_stamp, cells = runner.scan([OLDER, NEWER], build_targets(tmp_path), cancel=cancel, private_dir=tmp_path)
    assert engine_stamp == stamp
    assert {(c.target_id, c.rule_name.rsplit('_', 1)[1]): (c.state, c.hits, c.offsets, c.rvas, c.reason)
            for c in cells} == GOLDEN
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith('rules-')] == []


def test_runner_reports_compile_errors_from_the_child(tmp_path):
    bad = RuleText(name='PT_0123456789ab_older', text='rule evil { condition: true }')
    with pytest.raises(RulesError) as caught:
        runner.scan([bad], [target(tmp_path, 'older', IMAGES['older'])], cancel=threading.Event(),
                    private_dir=tmp_path)
    assert caught.value.code == 'PT-RULE-COMPILE'


def test_runner_child_is_stopped_by_the_memory_cap(tmp_path):
    big = make_pe(b'ABCD') + b'\0' * (100 * 1024 * 1024)
    capped = RuleLimits(worker_memory_bytes=128 * 1024 * 1024)
    with pytest.raises(RulesError) as caught:
        runner.scan([OLDER], [target(tmp_path, 'big', big)], cancel=threading.Event(), private_dir=tmp_path,
                    limits=capped)
    assert caught.value.code == 'PT-RULE-ENGINE'
    assert str(tmp_path) not in caught.value.message
