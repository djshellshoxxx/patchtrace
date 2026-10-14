"""Regression tests for the tool-adapter audit `docs/audits/20261014-C-tool-adapters.md` (TA-1 .. TA-12, TA-16).

Each test was written red against the pre-fix adapters. Parsers run on REAL tool output captured on SYNTHETIC PE
pairs (see test_intel_tools_parsers.py), mutated into hostile variants; probes run against a fake runner (no tool
is executed); `execute` runs a real Python child through `jobs.run_process`. None of this is live evidence."""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import unicodedata
from pathlib import Path

import pytest
from intel_tools_support import FIXTURES, golden, image_getter
from test_intel_tools_parsers import _Match, _run, parse_capa

from patchtrace.intelligence.tools import capa, delta, diec, floss, pins, process
from patchtrace.intelligence.tools.common import (
    DEFAULT_LIMITS,
    ToolError,
    ToolLimits,
    ToolManifest,
    ToolRun,
    load_json_strict,
)
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.jobs import ProcessResult

BASE = 0x140000000


@pytest.fixture
def imgs(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def capa_doc(name='capa-api-older') -> dict:
    return json.loads(golden(f'capa/{name}.json'))


def as_bytes(doc: dict) -> bytes:
    return json.dumps(doc).encode()


# ---- TA-1: out-of-range addresses are anomalies or typed errors, never a pydantic ValidationError ---------------

@pytest.mark.parametrize('kind', ['absolute', 'file'])
def test_ta1_capa_address_beyond_64_bits_is_an_anomaly(imgs, kind):
    doc = capa_doc()
    doc['rules']['get hostname']['matches'][0][0] = {'type': kind, 'value': 2**70}
    result = parse_capa(imgs, 'capa-api', 'older', as_bytes(doc))
    host = next(c for c in result.capabilities if c.rule_id == 'get hostname')
    assert host.address is None and host.location.rva is None
    assert any(a.startswith('address-out-of-range') for a in result.anomalies)


def test_ta1_capa_base_beyond_64_bits_is_a_typed_error(imgs):
    doc = capa_doc()
    doc['meta']['analysis']['base_address']['value'] = 2**70
    with pytest.raises(ToolError) as info:
        parse_capa(imgs, 'capa-api', 'older', as_bytes(doc))
    assert info.value.code == 'PT-TOOL-ADDRESS'


def floss_ctx(imgs, deobfuscate=False, pair='floss-static', side='newer'):
    copy, reader, pe = imgs(pair, side)
    return floss.ParseContext('r', side, copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], deobfuscate)


def test_ta1_floss_offset_beyond_the_file_limit_is_an_anomaly(imgs):
    doc = json.loads(golden('floss/floss-static-newer.static.json'))
    doc['strings']['static_strings'][0]['offset'] = 2**41
    result = floss.parse(as_bytes(doc), floss_ctx(imgs))
    assert any(a.startswith('offset-out-of-range') for a in result.anomalies)
    assert all(s.source_location.file_offset is None or s.source_location.file_offset < 2**40 for s in result.strings)


def test_ta1_floss_imagebase_beyond_64_bits_is_a_typed_error(imgs):
    doc = json.loads(golden('floss/floss-decode-older.deobfuscate.json'))
    doc['metadata']['imagebase'] = 2**70
    with pytest.raises(ToolError) as info:
        floss.parse(as_bytes(doc), floss_ctx(imgs, True, 'floss-decode', 'older'))
    assert info.value.code == 'PT-TOOL-ADDRESS'


# ---- TA-2: a capability appearing in an added or changed function is not hidden by an older match elsewhere ---

def _manifest():
    return ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                        rules_source='embedded', supported=True)


def _with_second_match(newer, function_rva):
    host = next(c for c in newer.capabilities if c.rule_id == 'get hostname')
    link = host.location.model_copy(update={'function_id': f'rva:0x{function_rva:x}', 'rva': function_rva})
    extra = host.model_copy(update={'location': link, 'address': BASE + function_rva})
    return newer.model_copy(update={'capabilities': (*newer.capabilities, extra)})


def test_ta2_second_match_in_an_added_function_is_newly_introduced(imgs):
    older = parse_capa(imgs, 'capa-api', 'older')
    newer = _with_second_match(parse_capa(imgs, 'capa-api', 'newer'), 0x1030)
    pairing = FunctionPairing.from_project([_Match('added', newer=['140001030'])], None,
                                           older_base=BASE, newer_base=BASE)
    result = delta.compute(_run('older', older, _manifest()), older, _run('newer', newer, _manifest()), newer,
                           pairing=pairing)
    entries = [c for c in result.capabilities if c.rule_id == 'get hostname']
    added = [c for c in entries if c.change == 'added']
    assert len(added) == 1 and added[0].classification == 'newly-introduced'
    assert [link.function_id for link in added[0].newer] == ['rva:0x1030']
    assert delta.has_changes(result)


def test_ta2_equal_function_sets_stay_unchanged(imgs):
    older = parse_capa(imgs, 'capa-control', 'older')
    newer = parse_capa(imgs, 'capa-control', 'newer')
    result = delta.compute(_run('older', older, _manifest()), older, _run('newer', newer, _manifest()), newer)
    assert result.comparable and not delta.has_changes(result)


def test_ta2_without_pairing_a_larger_match_count_is_unknown_not_hidden(imgs):
    older = parse_capa(imgs, 'capa-api', 'older')
    newer = _with_second_match(parse_capa(imgs, 'capa-api', 'newer'), 0x1030)
    result = delta.compute(_run('older', older, _manifest()), older, _run('newer', newer, _manifest()), newer)
    added = [c for c in result.capabilities if c.rule_id == 'get hostname' and c.change == 'added']
    assert len(added) == 1 and added[0].classification == 'unknown'


# ---- TA-3: a truncated side never produces definite added / removed entries ------------------------------------

def test_ta3_truncated_older_side_makes_added_capabilities_unknown(imgs):
    newer = parse_capa(imgs, 'capa-api', 'newer')
    full_older = parse_capa(imgs, 'capa-api', 'older')
    older = full_older.model_copy(update={'capabilities': full_older.capabilities[:2], 'truncated': True})
    result = delta.compute(_run('older', older, _manifest()), older, _run('newer', newer, _manifest()), newer)
    added = [c for c in result.capabilities if c.change == 'added']
    assert added and all(c.classification == 'unknown' for c in added)
    assert all(any('truncated' in n for n in c.notes) for c in added)
    assert result.truncated


def test_ta3_truncated_newer_side_makes_removed_capabilities_unknown(imgs):
    older = parse_capa(imgs, 'capa-api', 'older')
    full_newer = parse_capa(imgs, 'capa-api', 'newer')
    newer = full_newer.model_copy(update={'capabilities': full_newer.capabilities[:2], 'truncated': True})
    result = delta.compute(_run('older', older, _manifest()), older, _run('newer', newer, _manifest()), newer)
    removed = [c for c in result.capabilities if c.change == 'removed']
    assert removed and all(c.classification == 'unknown' for c in removed)


def test_ta3_truncated_string_side_is_indeterminate(imgs):
    sets = {}
    for side in ('older', 'newer'):
        sets[side] = floss.parse(golden(f'floss/floss-static-{side}.static.json'), floss_ctx(imgs, False,
                                                                                            'floss-static', side))
    manifest = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    older = sets['older'].model_copy(update={'strings': sets['older'].strings[:3], 'truncated': True})
    runs = {side: ToolRun(run_id=s.run_id, engine='floss', side=side, input_artifact_hash=s.artifact_sha256,
                          config_digest='d' * 64, cache_key=s.cache_key, started_at='t', elapsed=0, status='ok',
                          evidence_count=s.evidence_count(), profile='context', manifest=manifest)
            for side, s in (('older', older), ('newer', sets['newer']))}
    result = delta.compute(runs['older'], older, runs['newer'], sets['newer'])
    assert result.strings and all(s.change != 'added' for s in result.strings)
    assert any(s.change == 'indeterminate' for s in result.strings)
    assert not any(s.change == 'added' for s in result.strings)


def test_ta3_capa_truncation_keeps_a_deterministic_prefix(imgs):
    copy, _reader, pe = imgs('capa-api', 'older')
    limits = ToolLimits(64 * 1024 * 1024, max_rule_matches=3)
    ctx = capa.ParseContext('r', 'older', copy, 'c' * 64, 'd' * 64, pe, limits)
    doc = capa_doc()
    shuffled = dict(reversed(list(doc['rules'].items())))
    first = capa.parse(golden('capa/capa-api-older.json'), ctx)
    second = capa.parse(as_bytes(dict(doc, rules=shuffled)), ctx)
    assert first.truncated and [c.rule_id for c in first.capabilities] == [c.rule_id for c in second.capabilities]


# ---- TA-4 / TA-5: byte-exact, bounded stdout; output flood stops early; memory cap is passed on ------------------

def run_child(tmp_path: Path, code: str, *, limit: int, timeout: float = 30, **kw):
    scratch = process.make_scratch('audit', tmp_path)
    env = process.tool_env(Path(sys.executable), scratch)
    return process.execute([sys.executable, '-c', code], scratch=scratch, env=env, cancel=threading.Event(),
                           timeout=timeout, limits=ToolLimits(limit, 4096), **kw)


def test_ta4_invalid_utf8_reaches_the_strict_parser_and_digest_is_of_the_raw_bytes(tmp_path):
    raw = b'{"a":"\xff"}'
    run = run_child(tmp_path, 'import sys; sys.stdout.buffer.write(b\'{"a":"\\xff"}\')', limit=64)
    assert run.stdout_bytes == raw
    assert run.digests()[0] == hashlib.sha256(raw).hexdigest()
    with pytest.raises(ToolError, match='UTF-8') as info:
        load_json_strict(run.stdout_bytes, max_bytes=64)
    assert info.value.code == 'PT-TOOL-OUTPUT'


def test_ta4_oversize_is_judged_on_bytes_not_on_replacement_text(tmp_path):
    run = run_child(tmp_path, 'import sys; sys.stdout.buffer.write(b"\\xff" * 4)', limit=10)
    assert not run.oversize and run.stdout_bytes == b'\xff' * 4


def test_ta5_output_flood_is_stopped_at_the_limit_not_at_the_timeout(tmp_path):
    code = ('import sys\nwhile True:\n    sys.stdout.buffer.write(b"x" * 65536)\n    sys.stdout.buffer.flush()')
    run = run_child(tmp_path, code, limit=1024 * 1024, timeout=60)
    assert run.oversize and run.reason == 'output-limit'
    assert run.elapsed_ms < 20_000


def test_ta5_execute_passes_limits_to_the_runner(tmp_path):
    seen = {}

    def runner(argv, **kw):
        seen.update(kw)
        return ProcessResult(0, '{}', None, '', None, b'{}', b'', 2, 0)
    scratch = process.make_scratch('audit', tmp_path)
    result = process.execute(['/x'], scratch=scratch, env={}, cancel=threading.Event(), timeout=5,
                             limits=ToolLimits(1000, 500), runner=runner, memory_limit_bytes=1 << 30)
    assert seen['memory_limit_bytes'] == 1 << 30 and seen['max_output_bytes'] == 1000
    assert result.stdout_bytes == b'{}'
    assert not result.oversize


# ---- TA-6: the pin is enforced, and what runs is what was probed ------------------------------------------------

def version_help_runner(engine: str, calls: list | None = None):
    texts = {'capa': ('capa/version.stdout.txt', 'capa/help.stdout.txt', '--help'),
             'floss': ('floss/version.stdout.txt', 'floss/help-advanced.stdout.txt', '-H'),
             'diec': ('diec/version.stdout.txt', 'diec/help.stdout.txt', '--help')}
    version, help_text, help_flag = (golden(texts[engine][0]).decode(), golden(texts[engine][1]).decode(),
                                     texts[engine][2])

    def runner(argv, **_kw):
        if calls is not None:
            calls.append(argv[1:])
        return ProcessResult(0, version if argv[1] == '--version' else help_text, None, '')
    assert help_flag
    return runner


def dummy_exe(tmp_path: Path, name: str = 'tool') -> tuple[Path, str]:
    exe = tmp_path / name
    exe.write_bytes(b'not really a tool')
    return exe, hashlib.sha256(exe.read_bytes()).hexdigest()


@pytest.mark.parametrize('engine', ['capa', 'floss'])
def test_ta6_unpinned_build_needs_an_explicit_opt_in(tmp_path, monkeypatch, engine):
    module, config_type = {'capa': (capa, capa.CapaConfig), 'floss': (floss, floss.FlossConfig)}[engine]
    exe, sha = dummy_exe(tmp_path)
    runner = version_help_runner(engine)
    plain = module.probe(config_type(exe), runner=runner, use_cache=False)
    assert not plain.supported and 'pinned' in plain.reason and plain.pin_status == 'unpinned'
    opted = module.probe(config_type(exe, accept_untested=True), runner=runner, use_cache=False)
    assert opted.supported and opted.untested_version and opted.pin_status == 'unpinned'
    monkeypatch.setitem(pins.PINNED_EXECUTABLES[engine], sha, 'test build')
    pinned = module.probe(config_type(exe), runner=runner, use_cache=False)
    assert pinned.supported and pinned.pin_status == 'pinned' and not pinned.untested_version


def test_ta6_diec_needs_pinned_executable_and_database(tmp_path, monkeypatch):
    exe, sha = dummy_exe(tmp_path)
    database = tmp_path / 'db'
    database.mkdir()
    (database / 'sig.txt').write_text('signature')
    monkeypatch.setitem(diec.KNOWN_DATABASES, process.tree_digest(database), 'test database')
    runner = version_help_runner('diec')
    config = diec.DiecConfig(exe, database=database)
    plain = diec.probe(config, runner=runner, use_cache=False)
    assert not plain.supported and 'pinned' in plain.reason
    monkeypatch.setitem(pins.PINNED_EXECUTABLES['diec'], sha, 'test build')
    assert diec.probe(config, runner=runner, use_cache=False).supported


def test_ta6_executable_is_rehashed_before_it_is_spawned(tmp_path):
    exe, sha = dummy_exe(tmp_path)
    assert process.verify_executable(exe, sha) == exe.resolve()
    exe.write_bytes(b'swapped after the probe')
    with pytest.raises(ToolError) as info:
        process.verify_executable(exe, sha)
    assert info.value.code == 'PT-TOOL-STALE'
    with pytest.raises(ToolError) as info:
        process.verify_executable(tmp_path / 'missing', sha)
    assert info.value.code == 'PT-TOOL-STALE'


def test_ta6_prepared_rule_copy_must_equal_the_probed_digest(tmp_path):
    rules = tmp_path / 'rules'
    rules.mkdir()
    (rules / 'a.yml').write_text('rule: one')
    manifest = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='directory', rules_sha256=process.tree_digest(rules), supported=True)
    config = capa.CapaConfig(tmp_path / 'capa', rules_dir=rules)
    scratch = process.make_scratch('audit', tmp_path)
    assert capa.prepare(config, scratch, manifest)['rules'] == manifest.rules_sha256
    (rules / 'a.yml').write_text('rule: swapped after the probe')
    scratch2 = process.make_scratch('audit', tmp_path)
    with pytest.raises(ToolError) as info:
        capa.prepare(config, scratch2, manifest)
    assert info.value.code == 'PT-TOOL-STALE'


# ---- TA-7 / TA-12: FLOSS flags and base --------------------------------------------------------------------------

def test_ta7_deobfuscation_must_report_the_requested_types_enabled(imgs):
    doc = json.loads(golden('floss/floss-decode-older.deobfuscate.json'))
    for key in ('enable_stack_strings', 'enable_tight_strings', 'enable_decoded_strings'):
        doc['analysis'][key] = False
    doc['strings']['decoded_strings'] = []
    with pytest.raises(ToolError) as info:
        floss.parse(as_bytes(doc), floss_ctx(imgs, True, 'floss-decode', 'older'))
    assert info.value.code == 'PT-TOOL-OUTPUT'


def test_ta12_floss_base_that_differs_from_the_header_leaves_addresses_unlocalized(imgs):
    doc = json.loads(golden('floss/floss-decode-older.deobfuscate.json'))
    doc['metadata']['imagebase'] = 0x10000000
    result = floss.parse(as_bytes(doc), floss_ctx(imgs, True, 'floss-decode', 'older'))
    decoded = [s for s in result.strings if s.type == 'decoded']
    assert decoded and all(s.source_location.function_id is None for s in decoded)
    assert any(a.startswith('base-differs') for a in result.anomalies)


# ---- TA-8 / TA-9: DiE names keep their slashes and never carry control or bidi characters -----------------------

def diec_doc(name: str, version: str = '', kind: str = 'Compiler', string: str = '') -> bytes:
    value = {'info': '', 'name': name, 'string': string or f'{kind}: {name}', 'type': kind, 'version': version}
    return as_bytes({'detects': [{'filetype': 'PE64', 'info': '', 'offset': '0', 'parentfilepart': 'Header',
                                  'size': '1', 'values': [value]}]})


def diec_parse(raw: bytes):
    ctx = diec.ParseContext('r', 'older', 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec'])
    return diec.parse(raw, ctx)


@pytest.mark.parametrize('name', ['Microsoft Visual C/C++', 'UPX/LZMA', 'Borland Delphi/Lazarus'],
                         ids=['msvc', 'upx', 'delphi'])
def test_ta8_detector_names_keep_slashes(name):
    item = diec_parse(diec_doc(name, '(19.29.30133)[LTCG/C++]')).environment[0]
    assert item.detector_rule == name and item.version == '(19.29.30133)[LTCG/C++]'


def test_ta8_distinct_detections_stay_distinct():
    a = diec_parse(diec_doc('UPX/LZMA', kind='Packer')).environment[0]
    b = diec_parse(diec_doc('UPXLZMA', kind='Packer')).environment[0]
    assert a.detector_rule != b.detector_rule


def test_ta9_hostile_detection_text_is_escaped_everywhere():
    item = diec_parse(diec_doc('MSVC\u202e\x1b[31mevil\x00', '1\u2066', string='x\u202ey\x00')).environment[0]
    for text in (item.toolchain, item.detector_rule, item.version, item.detect_string):
        assert text and not any(unicodedata.category(c) in ('Cc', 'Cf') for c in text)


# ---- TA-10: probes never raise and do not cache transient failures -------------------------------------------------

def test_ta10_probe_survives_an_unusable_environment(tmp_path, monkeypatch):
    exe, _sha = dummy_exe(tmp_path)

    def broken(*_a, **_k):
        raise OSError('SystemRoot is not set')
    monkeypatch.setattr(process, 'tool_env', broken)
    manifest = capa.probe(capa.CapaConfig(exe), runner=version_help_runner('capa'), use_cache=False)
    assert not manifest.supported and manifest.reason


@pytest.mark.parametrize('reason, wording', [('timeout', 'timed out'), ('cancelled', 'cancel')])
def test_ta10_transient_outcomes_are_not_cached_and_name_the_reason(tmp_path, reason, wording):
    exe, _sha = dummy_exe(tmp_path)
    calls: list = []

    def runner(argv, **_kw):
        calls.append(argv)
        return ProcessResult(-9, '', reason, '')
    capa.clear_probe_cache()
    try:
        first = capa.probe(capa.CapaConfig(exe), runner=runner)
        second = capa.probe(capa.CapaConfig(exe), runner=runner)
    finally:
        capa.clear_probe_cache()
    assert not first.supported and wording in first.reason
    assert len(calls) >= 2 and not second.supported
    if reason == 'timeout':
        assert len(calls) == 4  # the timeout was not remembered


def test_ta10_spawn_failure_is_reported_not_raised(tmp_path):
    exe, _sha = dummy_exe(tmp_path)

    def runner(argv, **_kw):
        raise PermissionError('denied')
    manifest = floss.probe(floss.FlossConfig(exe), runner=runner, use_cache=False)
    assert not manifest.supported and 'PermissionError' in manifest.reason


# ---- TA-11: long rule names do not collide ------------------------------------------------------------------------

def test_ta11_long_rule_names_get_distinct_bounded_ids(imgs):
    doc = capa_doc()
    template = doc['rules']['get hostname']
    for index in range(3):
        name = 'x' * 300 + f'|{index}'
        doc['rules'][name] = json.loads(json.dumps(template)) | {}
        doc['rules'][name]['meta']['name'] = name
    result = parse_capa(imgs, 'capa-api', 'older', as_bytes(doc))
    long_ids = [c.rule_id for c in result.capabilities if c.rule_id.startswith('x' * 50)]
    assert len(long_ids) == 3 and len(set(long_ids)) == 3 and all(len(i) <= 256 for i in long_ids)
    assert any(a.startswith('rule-id-shortened') for a in result.anomalies)


# ---- TA-16 --------------------------------------------------------------------------------------------------------

def test_ta16_overflowing_float_is_rejected():
    with pytest.raises(ToolError) as info:
        load_json_strict(b'{"a": 1e999}', max_bytes=100)
    assert info.value.code == 'PT-TOOL-OUTPUT'
    assert load_json_strict(b'{"a": 1.5}', max_bytes=100) == {'a': 1.5}


def test_fixtures_directory_is_the_shared_one():
    assert (FIXTURES / 'manifest.json').is_file()
