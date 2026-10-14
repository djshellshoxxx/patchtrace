"""WB3-S1b FLOSS adapter amendments (docs/specs/program-e/WB3-integration-plan.md s9, F21): consent v2, `-n`, `-L`,
PT-TOOL-LIMIT classification, memory cap, per-type truncation quotas, decoded call-site/string RVAs. Parsers run on
REAL FLOSS 3.1.1 output captured on SYNTHETIC PE pairs, mutated; nothing here is live evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from intel_tools_support import golden, image_getter

from patchtrace.intelligence.tools import floss, pins
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError, ToolLimits
from patchtrace.jobs import ProcessResult

OLD_CONSENT_SHA256 = 'f1582ad470f9c60a3c90310091d20c32efaa4459825744816d4c8e1a02f5c771'
CONSENT = floss.EMULATION_CONSENT_SHA256


@pytest.fixture
def imgs(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def ctx(imgs, *, deobfuscate=False, pair='floss-decode', side='older', limits=None):
    copy, reader, pe = imgs(pair, side)
    return floss.ParseContext('r', side, copy, 'c' * 64, 'd' * 64, pe, reader, limits or DEFAULT_LIMITS['floss'],
                              deobfuscate)


def decode_doc() -> dict:
    return json.loads(golden('floss/floss-decode-older.deobfuscate.json'))


def test_consent_v2_names_the_new_risks_and_changes_the_hash():
    text = floss.EMULATION_CONSENT
    for phrase in ('calls to other imports are skipped with a zero result', 'end of life',
                   'memory and time are capped but not guaranteed'):
        assert phrase in text
    assert hashlib.sha256(text.encode()).hexdigest() == CONSENT != OLD_CONSENT_SHA256
    old = floss.FlossConfig(Path('/x'), deobfuscate=True, consent_sha256=OLD_CONSENT_SHA256)
    with pytest.raises(ToolError) as info:
        floss.build_argv(old, '/x', Path('/a'))
    assert info.value.code == 'PT-TOOL-CONSENT'


def test_minimum_length_argv_options_and_bounds():
    config = floss.FlossConfig(Path('/x'), min_length=6)
    argv = floss.build_argv(config, '/x', Path('/a'))
    assert argv[argv.index('-n') + 1] == '6' and argv.index('-n') < argv.index('--only')
    assert floss.options(config)['min_length'] == '6'
    assert floss.options(floss.FlossConfig(Path('/x')))['min_length'] == 'default'
    assert '-n' not in floss.build_argv(floss.FlossConfig(Path('/x')), '/x', Path('/a'))
    for bad in (0, -1, 5000):
        with pytest.raises(ToolError) as info:
            floss.build_argv(floss.FlossConfig(Path('/x'), min_length=bad), '/x', Path('/a'))
        assert info.value.code == 'PT-TOOL-INPUT'


def test_large_file_flag_needs_deobfuscation_and_consent():
    with pytest.raises(ToolError) as info:
        floss.build_argv(floss.FlossConfig(Path('/x'), large_file=True), '/x', Path('/a'))
    assert info.value.code == 'PT-TOOL-INPUT'
    config = floss.FlossConfig(Path('/x'), deobfuscate=True, consent_sha256=CONSENT, large_file=True)
    argv = floss.build_argv(config, '/x', Path('/a'))
    assert '-L' in argv and argv.index('-L') < argv.index('--only')
    assert floss.options(config)['large_file'] == 'yes'
    assert '-L' not in floss.build_argv(floss.FlossConfig(Path('/x'), deobfuscate=True, consent_sha256=CONSENT),
                                        '/x', Path('/a'))


def probe_with_help(tmp_path, monkeypatch, config_kwargs, drop: tuple[str, ...]):
    exe = tmp_path / 'floss'
    exe.write_bytes(b'fake')
    monkeypatch.setitem(pins.PINNED_EXECUTABLES['floss'], hashlib.sha256(b'fake').hexdigest(), 'test')
    help_text = golden('floss/help-advanced.stdout.txt').decode()
    for flag in drop:
        help_text = help_text.replace(flag, 'XX')

    def runner(argv, **_kw):
        return ProcessResult(0, golden('floss/version.stdout.txt').decode() if argv[1] == '--version' else help_text,
                             None, '')
    return floss.probe(floss.FlossConfig(exe, **config_kwargs), runner=runner, use_cache=False)


def test_probe_checks_the_options_it_will_pass(tmp_path, monkeypatch):
    assert probe_with_help(tmp_path, monkeypatch, {'min_length': 5}, ()).supported
    missing = probe_with_help(tmp_path, monkeypatch, {'min_length': 5}, ('--minimum-length', '-n MIN_LENGTH'))
    assert not missing.supported and '-n' in missing.reason
    assert probe_with_help(tmp_path, monkeypatch, {}, ('--minimum-length', '-n MIN_LENGTH')).supported
    large = probe_with_help(tmp_path, monkeypatch, {'deobfuscate': True, 'consent_sha256': CONSENT,
                                                    'large_file': True}, ('--large-file',))
    assert not large.supported and 'large-file' in large.reason


def test_classify_exit_maps_size_and_memory_to_limit():
    status, code, message = floss.classify_exit(
        255, '', 'ERROR: cannot deobfuscate strings from files larger than 0x1000000 bytes')
    assert (status, code) == ('unsupported', 'PT-TOOL-LIMIT') and '16 MiB' in message and '-L' in message
    status, code, message = floss.classify_exit(1, '', 'Traceback\nMemoryError', memory_limit_bytes=1 << 30)
    assert (status, code) == ('failed', 'PT-TOOL-LIMIT') and 'memory' in message
    assert floss.classify_exit(1, '', 'MemoryError')[1] == 'PT-TOOL-RUN'   # no cap configured: just a failure
    assert floss.classify_exit(1, '', '', memory_limit_bytes=1 << 30, peak_memory_bytes=(1 << 30))[1] == \
        'PT-TOOL-LIMIT'
    stderr = golden('floss/error-not-pe-deobfuscate.stderr.txt').decode()
    assert floss.classify_exit(255, '', stderr)[1] == 'PT-TOOL-UNSUPPORTED'


def test_memory_cap_defaults():
    plain = floss.FlossConfig(Path('/x'))
    emulate = floss.FlossConfig(Path('/x'), deobfuscate=True, consent_sha256=CONSENT)
    assert plain.effective_memory_limit() is None and emulate.effective_memory_limit() == 4 * 1024 ** 3
    assert floss.FlossConfig(Path('/x'), memory_limit_bytes=1 << 30).effective_memory_limit() == 1 << 30
    with pytest.raises(ToolError):
        floss.FlossConfig(Path('/x'), memory_limit_bytes=1 << 20).effective_memory_limit()


def test_decoded_strings_carry_call_site_and_string_rvas(imgs):
    result = floss.parse(json.dumps(decode_doc()).encode(), ctx(imgs, deobfuscate=True))
    link = next(s for s in result.strings if s.type == 'decoded').source_location
    assert link.site_rva == 5368713232 - 0x140000000 and link.data_rva == 5368721408 - 0x140000000
    assert link.attribution == 'decoding-routine'


def test_language_strings_missed_are_counted_not_stored(imgs):
    doc = decode_doc()
    doc['strings']['language_strings_missed'] = [{'encoding': 'ASCII', 'offset': 77, 'string': 'missed one'},
                                                 {'encoding': 'ASCII', 'offset': 200, 'string': 'missed two'}]
    result = floss.parse(json.dumps(doc).encode(), ctx(imgs, deobfuscate=True))
    assert result.counts['language_missed'] == 2
    assert not any(s.display_value.startswith('missed') for s in result.strings)


def many_static_doc(count: int) -> dict:
    doc = decode_doc()
    base = doc['strings']['static_strings'][0]
    doc['strings']['static_strings'] = [dict(base, string=f'static string number {i:05d}') for i in range(count)]
    return doc


def test_truncation_uses_per_type_quotas_and_records_the_cut_types(imgs):
    limits = ToolLimits(64 * 1024 * 1024, max_strings=20)
    result = floss.parse(json.dumps(many_static_doc(200)).encode(), ctx(imgs, deobfuscate=True, limits=limits))
    kinds = [s.type for s in result.strings]
    assert 'decoded' in kinds                      # the rare type is never starved by the flood of static strings
    assert result.truncated and result.truncated_types == ('static',)
    assert len(result.strings) == 20 and result.counts['total_static'] == 200 and result.counts['total_decoded'] == 1


def test_truncated_selection_does_not_depend_on_document_order(imgs):
    limits = ToolLimits(64 * 1024 * 1024, max_strings=10)
    doc = many_static_doc(80)
    shuffled = json.loads(json.dumps(doc))
    shuffled['strings']['static_strings'].reverse()
    one = floss.parse(json.dumps(doc).encode(), ctx(imgs, deobfuscate=True, limits=limits))
    two = floss.parse(json.dumps(shuffled).encode(), ctx(imgs, deobfuscate=True, limits=limits))
    assert [s.value_hash for s in one.strings] == [s.value_hash for s in two.strings]


def test_untruncated_set_has_no_truncated_types(imgs):
    result = floss.parse(json.dumps(decode_doc()).encode(), ctx(imgs, deobfuscate=True))
    assert not result.truncated and result.truncated_types == ()
