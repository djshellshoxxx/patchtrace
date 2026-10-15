"""R2 engine facade against the REAL YARA-X (no mocks): the compile policy, lint, scan cells, offset to RVA mapping, caps
and timeouts in-process, and the whole grid through a real worker child equal to a golden table
(docs/specs/program-e/YRX-integration-plan.md s2, s6, s7, s9). Every image is SYNTHETIC and only ever read as bytes.

The tests need the `rules` extra. Locally a missing engine skips them with a reason; in CI the extra is installed and
`test_rules_worker.py::test_engine_extra_is_installed_in_the_qa_matrix` fails instead, so a matrix cannot pass hollow.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest
from pe_builder import CODE, PeSpec, SectionSpec, build_pe_ex

from patchtrace.rules import contracts as c
from patchtrace.rules import runner
from patchtrace.rules.limits import MIB, RuleLimits

pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
engine = pytest.importorskip('patchtrace.rules.engine')

ROOT = Path(__file__).resolve().parents[1]


def _generator():
    spec = importlib.util.spec_from_file_location('generate_rules_schemas', ROOT / 'tools' / 'generate_rules_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _generator()
BASE = GEN.example_rule_text()  # the R0 example: bytes window plus the import gate, in the Formatter's own layout
HEAD = BASE.split('  strings:')[0]  # import, rule line and meta
MODULES = ('console', 'crx', 'cuckoo', 'dex', 'dotnet', 'elf', 'hash', 'lnk', 'macho', 'math', 'pe', 'string', 'time',
           'vt', 'zip')


def rule(condition: str, strings: tuple[str, ...] = ()) -> str:
    body = ('  strings:\n' + ''.join(f'    {s}\n' for s in strings) + '\n') if strings else ''
    return HEAD + body + '  condition:\n    ' + condition + '\n}\n'


IMPORT_GATE = 'uint16(0) == 0x5A4D and pe.is_pe and pe.imports("KERNEL32.dll", "TerminateProcess")'
IMPORT_ONLY = rule(IMPORT_GATE)
BROKEN = BASE.replace('older_side', 'rogue_tag')  # E040: a tag outside the whitelist


def term(disp: int) -> bytes:
    """The 24-byte function of the example rule with a chosen RIP displacement (the four wildcarded bytes)."""
    return bytes.fromhex('4883EC2831C9BA0100000090') + bytes.fromhex('48FF15') + disp.to_bytes(4, 'little') \
        + bytes.fromhex('4883C428C3')


OTHER = bytes.fromhex('4883EC28B801000000') + bytes.fromhex('4883C428C3')


def image(code: bytes, imports: dict | None = None, overlay: bytes = b'') -> bytes:
    spec = PeSpec(sections=[SectionSpec('.text', code, CODE)], imports=imports or {}, overlay=overlay)
    return build_pe_ex(spec)[0]


TERMINATE = {'KERNEL32.dll': ['TerminateProcess', 'CloseHandle']}
TEXT_RAW, TEXT_RVA = 0x200, 0x1000  # the builder's layout of the first section (asserted below)


def lint(text: str, **kw) -> c.LintResult:
    return engine.lint('x', text, **kw)


def view(cell: c.CellResult) -> tuple:
    return cell.state, cell.hits, cell.offsets, cell.rvas, cell.reason


def short(cell: c.CellResult) -> tuple:
    return cell.state, cell.reason


# --- identity and start-up check ------------------------------------------------------------------------------------

def test_image_builder_layout_is_what_the_expected_offsets_assume():
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec('.text', term(0), CODE)]))
    assert info['sections'][0][1:4:2] == (TEXT_RVA, TEXT_RAW) and data[TEXT_RAW:TEXT_RAW + 4] == term(0)[:4]


def test_probe_reports_the_installed_engine_and_the_fifteen_modules():
    stamp, modules = engine.probe()
    assert stamp.version == importlib.metadata.version('yara-x') and stamp.version_source == 'metadata'
    assert (stamp.engine, stamp.grammar, stamp.worker) == ('yara-x', 'yrx-gen/1', 'rules-worker/1')
    assert modules == MODULES


def test_installed_engine_is_the_pinned_version():
    """A YARA-X bump belongs in a dedicated PR that re-runs the plan's grid and these goldens (plan s10)."""
    assert importlib.metadata.version('yara-x') == c.ENGINE_PIN


def test_stamp_states_the_pin_when_the_distribution_metadata_is_missing(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(engine.metadata, 'version', missing)
    stamp = engine.stamp()
    assert (stamp.version, stamp.version_source) == (c.ENGINE_PIN, 'pin')


def test_decoder_is_reported_only_when_it_imports(monkeypatch):
    monkeypatch.setitem(sys.modules, 'iced_x86', None)  # a failing import
    assert engine.decoder_stamp() == ('none', None)
    assert engine.probe()[0].decoder == 'none'
    monkeypatch.setitem(sys.modules, 'iced_x86', types.ModuleType('iced_x86'))
    monkeypatch.setattr(engine.metadata, 'version', lambda name: '9.9.9' if name == 'iced-x86' else '1.21.0')
    assert engine.decoder_stamp() == ('iced-x86', '9.9.9')
    stamp, _ = engine.probe()
    assert (stamp.decoder, stamp.decoder_version) == ('iced-x86', '9.9.9')
    assert engine.stamp().decoder == 'none'  # scan and lint results do not pay for the decoder check


def test_probe_failures_are_unavailable_not_crashes(monkeypatch):
    class Broken:
        def __init__(self, *a, **kw):
            raise RuntimeError('jit blocked')
    monkeypatch.setattr(engine.yara_x, 'Compiler', Broken)
    with pytest.raises(engine.RuleError) as info:
        engine.probe()
    assert (info.value.code, info.value.reason) == ('PT-RULE-UNAVAILABLE', 'probe-failed')
    assert 'jit blocked' not in str(info.value)


# --- compile policy and lint -------------------------------------------------------------------------------------------

def test_the_r0_example_rule_is_clean_under_the_engine_policy():
    """The example in docs/schemas/rules/ is a rule the grammar could emit: zero warnings and the Formatter's layout."""
    result = lint(BASE)
    assert result.ok and result.warnings == () and result.errors == () and result.formatter_stable
    assert (result.identifiers, result.imports, result.patterns) == (('PT_0123456789ab_older',), ('pe',), 1)
    for record in GEN.valid_records()['RuleVersion']:
        assert lint(record.rule_text).ok


A64 = 'a' * 64
CASES = {
    'syntax': (BASE.replace('condition:', 'condition: ((('), 'E001'),
    'unknown-identifier': (BASE.replace('pe.is_pe', 'pe.is_nope'), 'E008'),
    'missing-meta': (BASE.replace('    statement', '    statement_x'), 'E038'),
    'meta-type': (re.sub(r'(patchtrace_version\s+= )1', r'\1"1"', BASE), 'E037'),
    'meta-hash': (BASE.replace(A64, 'zz'), 'E037'),
    'rule-name': (BASE.replace('PT_0123456789ab_older', 'rogue_rule'), 'E039'),
    'tag': (BROKEN, 'E040'),
    'include': ('include "x.yar"\n' + BASE, 'E044'),
    'slow-pattern': (BASE.replace(GEN.PATTERN, '48'), 'E018'),
    'two-rules': (BASE + '\n' + BASE.replace('0123456789ab', 'ba9876543210'), 'pt_rule_count'),
    'no-import': (HEAD.replace('import "pe"\n\n', '') + '  strings:\n    $b = { 4D 5A 90 00 03 00 00 00 }\n\n'
                  '  condition:\n    $b\n}\n', 'pt_imports'),
    'extra-import': (BASE.replace('import "pe"', 'import "pe"\nimport "math"'), 'pt_imports'),
    'empty': ('', 'pt_rule_count'),
}


@pytest.mark.parametrize('name', list(CASES), ids=list(CASES))
def test_lint_refuses_what_the_closed_grammar_cannot_emit(name):
    text, code = CASES[name]
    result = lint(text)
    assert not result.ok and result.formatter_stable is False
    assert code in [d.code for d in result.errors], [(d.code, d.title) for d in result.errors]
    assert all(d.title and d.title.isprintable() and len(d.title) <= 200 for d in result.errors)


def test_pattern_ceiling_is_enforced_after_a_successful_compile():
    many = tuple(f'$s{i} = "abcd{i}"' for i in range(13))
    text = rule('uint16(0) == 0x5A4D and pe.is_pe and any of ($s*)', many)
    result = lint(text)
    assert not result.ok and [d.code for d in result.errors] == ['pt_patterns'] and result.patterns == 13
    assert lint(rule('uint16(0) == 0x5A4D and pe.is_pe and any of ($s*)', many[:12])).ok


def test_style_warning_is_reported_but_does_not_fail_the_rule():
    text = BASE.replace(GEN.PATTERN, '41 42 43 44 45 46 47 48')
    result = lint(text)
    assert result.ok and [d.code for d in result.warnings] == ['text_as_hex']
    assert (result.warnings[0].line, result.warnings[0].column) != (None, None)


def test_formatter_stability_is_a_separate_fact_and_text_is_unchanged_by_it():
    messy = BASE.replace('  meta:', '    meta:')
    result = lint(messy)
    assert result.ok and not result.formatter_stable
    assert engine.format_text(messy) == BASE and engine.format_text(BASE) == BASE


def test_diagnostics_keep_a_code_a_bounded_clean_title_and_a_position_only():
    hostile = {'code': 'E001', 'title': 'bad ‮\x00 title ' + 'x' * 500, 'line': 3, 'column': 0,
               'text': 'rule excerpt with SECRET', 'labels': [{'text': 'SECRET'}]}
    diagnostic = engine._diagnostic(hostile)
    assert (diagnostic.code, diagnostic.line, diagnostic.column) == ('E001', 3, None)
    assert len(diagnostic.title) == 200 and diagnostic.title.startswith('bad title x') and 'SECRET' not in repr(diagnostic)
    assert engine._diagnostic({'code': 'not a code!', 'title': ''}).code == 'unknown'
    assert engine._diagnostic({}).title == 'unknown'
    assert len(engine._diagnostics([hostile] * 50, 16)) == 16


def test_rendered_source_excerpts_are_dropped_and_only_a_token_may_remain_in_a_title():
    """The engine's `text`, `labels` and `footers` quote whole rule lines; a title may name the offending token."""
    token = 'zq9_unknown_member'
    compiler = engine._compiler(engine.DEFAULT_LIMITS)
    bad = BASE.replace('pe.is_pe', f'pe.{token}')
    with pytest.raises(engine.yara_x.CompileError):
        compiler.add_source(bad)
    [raw] = compiler.errors()
    assert '0x5A4D' in raw['text'] and token in raw['title']  # the engine quotes the condition line and the token
    result = lint(bad)
    dump = result.model_dump_json()
    assert not result.ok and '0x5A4D' not in dump and 'condition' not in dump
    [error] = result.errors
    assert error.code == 'E008' and token in error.title and (error.line, error.column) == (raw['line'], raw['column'])


# --- scanning: cells, mapping, caps ------------------------------------------------------------------------------------

def compile_rules(*texts: str, limits: c.WorkerLimits = engine.DEFAULT_LIMITS):
    return engine.RuleSet.compile([c.WorkerRule(name=f'r{i}', text=t) for i, t in enumerate(texts)], limits)


def test_a_hit_carries_its_file_offset_and_module_relative_address():
    rules = compile_rules(BASE)
    data = image(b'\xcc' * 16 + term(0x11111111), TERMINATE)
    [cell] = rules.scan(data)
    assert view(cell) == ('hit', 1, (TEXT_RAW + 16,), (TEXT_RVA + 16,), None)
    assert data[TEXT_RAW + 16:TEXT_RAW + 40] == term(0x11111111)


def test_masking_survives_a_rebuild_exact_bytes_would_miss():
    """The four displacement bytes differ between builds; the wildcards make the same rule match both (plan s5)."""
    rules = compile_rules(BASE)
    [a] = rules.scan(image(b'\xcc' * 16 + term(0x11111111), TERMINATE))
    [b] = rules.scan(image(b'\xcc' * 80 + term(0x7fffffff), TERMINATE))
    assert (a.state, b.state) == ('hit', 'hit') and b.rvas == (TEXT_RVA + 80,)
    exact = BASE.replace(GEN.PATTERN, GEN.PATTERN.replace('?? ?? ?? ??', '11 11 11 11'))
    assert [c_.state for c_ in compile_rules(exact).scan(image(b'\xcc' * 80 + term(0x7fffffff), TERMINATE))] == ['no-hit']


def test_a_miss_is_zero_hits_and_never_confused_with_not_scanned():
    [cell] = compile_rules(BASE).scan(image(OTHER, TERMINATE))
    assert view(cell) == ('no-hit', 0, (), (), None)
    [cell] = compile_rules(BASE).scan(b'plain text, not a PE image')
    assert view(cell) == ('not-scanned', None, (), (), 'not-pe')


@pytest.mark.parametrize('data', [b'', b'MZ', b'MZ' + bytes(200), image(OTHER)[:100], image(OTHER)[:0x80]],
                         ids=['empty', 'magic-only', 'zeros', 'truncated-100', 'truncated-dos'])
def test_not_a_pe_is_decided_by_the_engines_own_parser(data):
    assert [short(cell) for cell in compile_rules(BASE, IMPORT_ONLY).scan(data)] == [('not-scanned', 'not-pe')] * 2


def test_a_rule_without_patterns_hits_once_with_no_offsets():
    [cell] = compile_rules(IMPORT_ONLY).scan(image(OTHER, TERMINATE))
    assert view(cell) == ('hit', 1, (), (), None)


def test_versions_of_one_lineage_share_a_yara_identifier_and_stay_apart():
    """v1 and v2 of a lineage have the same `PT_..._older` name; each lives in its own namespace."""
    changed = BASE.replace(GEN.PATTERN, GEN.PATTERN.replace('BA 01 00 00 00', 'BA 02 00 00 00'))
    assert lint(changed).identifiers == lint(BASE).identifiers
    rules = compile_rules(BASE, changed, IMPORT_ONLY)
    cells = rules.scan(image(b'\xcc' * 16 + term(0), TERMINATE))
    assert [view(x)[0] for x in cells] == ['hit', 'no-hit', 'hit']


def test_matches_per_pattern_are_capped_and_offsets_are_the_first_ascending():
    data = image(b''.join(term(i) + b'\xcc' * 8 for i in range(10)), TERMINATE)
    [cell] = compile_rules(BASE).scan(data)
    assert cell.hits == 10 and len(cell.offsets) == 8 and list(cell.offsets) == sorted(cell.offsets)
    assert cell.offsets[:2] == (TEXT_RAW, TEXT_RAW + 32) and cell.rvas[1] == TEXT_RVA + 32
    [capped] = compile_rules(BASE, limits=c.WorkerLimits(max_matches_per_pattern=3)).scan(data)
    assert capped.hits == 3 and capped.offsets == cell.offsets[:3]
    [few] = compile_rules(BASE, limits=c.WorkerLimits(offsets_per_cell=2)).scan(data)
    assert few.hits == 10 and few.offsets == cell.offsets[:2] and len(few.rvas) == 2


def test_the_first_pattern_that_matched_is_the_anchor_of_hits_and_offsets():
    text = rule('uint16(0) == 0x5A4D and pe.is_pe and ($a or $b)',
                ('$a = "no-such-string-anywhere"', f'$b = {{ {GEN.PATTERN} }}'))
    [cell] = compile_rules(text).scan(image(term(0), TERMINATE))
    assert view(cell) == ('hit', 1, (TEXT_RAW,), (TEXT_RVA,), None)


def test_a_rule_that_failed_its_lint_reads_error_on_every_target_while_the_others_scan():
    rules = compile_rules(BASE, BROKEN)
    assert [r.ok for r in rules.lint] == [True, False]
    assert [short(x) for x in rules.scan(image(term(0), TERMINATE))] == [('hit', None), ('error', 'compile-failed')]
    assert [short(x) for x in rules.skip('unreadable')] == [('not-scanned', 'unreadable'), ('error', 'compile-failed')]
    nothing = compile_rules(BROKEN)
    assert [short(x) for x in nothing.scan(image(term(0)))] == [('error', 'compile-failed')]


def test_overlay_and_header_offsets_map_to_a_rva_only_where_the_loader_would():
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec('.text', term(0), CODE)], imports=TERMINATE,
                                    overlay=b'OVERLAY'))
    pe = engine.pe_map(data)
    assert pe is not None and pe.sections[0] == (TEXT_RAW, 0x200, TEXT_RVA) and pe.headers == info['size_of_headers']
    assert engine.offset_to_rva(pe, 0x40) == 0x40  # inside the headers
    assert engine.offset_to_rva(pe, TEXT_RAW + 5) == TEXT_RVA + 5
    assert engine.offset_to_rva(pe, TEXT_RAW + 0x200 - 1) == TEXT_RVA + 0x1ff
    assert engine.offset_to_rva(pe, info['overlay_off'] + 2) is None  # the overlay is not mapped
    assert engine.offset_to_rva(pe, len(data) + 10) is None
    huge = engine.PeMap(0, ((0, 100, 2**32 - 10),))
    assert engine.offset_to_rva(huge, 50) is None  # an RVA that does not fit the contract is dropped, not wrapped


def test_a_real_timeout_becomes_timeout_cells_and_the_scanner_stays_usable():
    """A condition loop over 16 MiB needs about 3.7 s here; the engine aborts it at the per-file limit. Its timer ticks
    once a second on a grid of its own, so a limit of T seconds fires between T-1 and T seconds after the scan starts
    (measured at offsets 0 to 0.9 s into the tick: 1.1 to 2.0 s for T=2)."""
    small = image(term(0), TERMINATE)
    big = image(term(0), TERMINATE, overlay=b'\x01' * (16 * MIB))
    absent = next(b for b in range(256) if b not in small and b != 1)
    slow = rule(f'for all i in (0..filesize - 1): (for all j in (0..15): (uint8(i) != {absent})) and pe.is_pe')
    rules = compile_rules(slow, IMPORT_ONLY, limits=c.WorkerLimits(target_timeout_s=2))
    assert rules.lint[0].ok and [d.code for d in rules.lint[0].warnings] == ['potentially_slow_loop']
    cells = rules.scan(big)
    assert [(x.state, x.hits, x.reason) for x in cells] == [('timeout', None, None)] * 2
    spent = [x.elapsed_ms for x in cells]
    assert all(900 <= ms < 2900 for ms in spent), spent  # >= : the Windows monotonic clock is coarse
    assert [view(x)[0] for x in rules.scan(small)] == ['hit', 'hit']  # the same scanner serves the next target


# --- the grid through a real worker child equals the golden table ---------------------------------------------------------

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_fixtures(root: Path):
    """(target, expected cells for [bytes rule, import rule, broken rule]) in grid order. Limits: file_bytes 4096."""
    old = image(b'\xcc' * 16 + term(0x11111111), TERMINATE)
    rebuilt = image(b'\xcc' * 80 + term(0x22222222), TERMINATE)
    new = image(OTHER, {'KERNEL32.dll': ['CloseHandle']})
    importer = image(OTHER, TERMINATE)
    files = {'old.bin': old, 'rebuilt.bin': rebuilt, 'new.bin': new, 'importer.bin': importer, 'junk.txt': b'not a PE',
             'big.bin': image(OTHER, TERMINATE, overlay=bytes(8000)), 'empty.bin': b'', 'truncated.bin': old[:100]}
    for name, data in files.items():
        (root / name).write_bytes(data)
    (root / 'folder').mkdir()
    err = ('error', None, (), (), 'compile-failed')
    wrong = bytes(reversed(old))

    def skip(reason):
        return [('not-scanned', None, (), (), reason)] * 2 + [err]

    def target(name, **kw):
        data = files.get(name)
        fields = {'target_id': name.replace('.', '-'), 'path': str(root / name),
                  'sha256': sha(data) if data is not None else None, 'size': len(data) if data is not None else 1}
        return c.WorkerTarget(**(fields | kw))
    return [
        (target('old.bin'), [('hit', 1, (TEXT_RAW + 16,), (TEXT_RVA + 16,), None), ('hit', 1, (), (), None), err]),
        (target('rebuilt.bin'), [('hit', 1, (TEXT_RAW + 80,), (TEXT_RVA + 80,), None), ('hit', 1, (), (), None), err]),
        (target('new.bin'), [('no-hit', 0, (), (), None), ('no-hit', 0, (), (), None), err]),
        (target('importer.bin'), [('no-hit', 0, (), (), None), ('hit', 1, (), (), None), err]),
        (target('junk.txt'), skip('not-pe')),
        (target('missing.bin'), skip('unreadable')),
        (target('big.bin'), skip('too-large')),
        (target('changed-hash.bin', path=str(root / 'old.bin'), sha256=sha(wrong), size=len(old)), skip('file-changed')),
        (target('changed-size.bin', path=str(root / 'old.bin'), sha256=None, size=len(old) + 1), skip('file-changed')),
        (target('folder', sha256=None, size=1), skip('unreadable')),
        (target('empty.bin'), skip('not-pe')),
        (target('truncated.bin'), skip('not-pe')),
    ]


def test_grid_through_a_real_worker_child_equals_the_golden_table(tmp_path):
    fixtures = build_fixtures(tmp_path)
    rules = [c.WorkerRule(name='bytes-v1', text=BASE), c.WorkerRule(name='import-v2', text=IMPORT_ONLY),
             c.WorkerRule(name='broken-v3', text=BROKEN)]
    limits = RuleLimits(file_bytes=4096)
    outcome = runner.scan(rules, [t for t, _ in fixtures], limits=limits)
    assert len(outcome.cells) == len(fixtures) * 3
    golden = [row for _, expected in fixtures for row in expected]
    assert [view(cell) for cell in outcome.cells] == golden
    assert all(cell.verdict == 'unscored' for cell in outcome.cells)
    assert [(r.name, r.ok) for r in outcome.lint] == [('bytes-v1', True), ('import-v2', True), ('broken-v3', False)]
    assert outcome.lint[2].errors[0].code == 'E040'
    assert outcome.engine.version == c.ENGINE_PIN and outcome.engine.decoder == 'none'
    again = runner.scan(rules, [t for t, _ in fixtures], limits=limits)  # deterministic apart from elapsed time
    assert [view(x) for x in again.cells] == golden and again.lint == outcome.lint


def test_a_real_child_lints_and_probes(tmp_path):
    probe = runner.probe(scratch_dir=tmp_path)
    assert probe.engine.version == c.ENGINE_PIN and probe.modules == MODULES
    results = runner.lint([c.WorkerRule(name='good', text=BASE), c.WorkerRule(name='bad', text=BROKEN)],
                          scratch_dir=tmp_path)
    assert [(r.name, r.ok) for r in results] == [('good', True), ('bad', False)] and results[0].formatter_stable
    assert list(tmp_path.iterdir()) == []  # the private scratch directory is gone
