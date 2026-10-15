"""CAP-1: capa parser v2 (function coverage, matched features, taxonomy labels), exit codes 11/13, Ghidra >= 12.0,
the memory cap and the in-memory re-parse. REAL capa 9.4.0 goldens on SYNTHETIC PEs, plus DERIVED variants (hand
edited, labelled in `fixtures/intel_tools/capa/MANIFEST.capa-v2.json`). Hermetic: no tool is run."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from intel_tools_support import FIXTURES, fake_engine, golden, image_getter
from pydantic import ValidationError

from patchtrace.intelligence.tools import capa, common
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError

BASE = 0x140000000
DERIVED = json.loads((FIXTURES / 'capa' / 'MANIFEST.capa-v2.json').read_text(encoding='utf-8'))


@pytest.fixture
def images(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def context(images, pair, side, limits=DEFAULT_LIMITS['capa']):
    copy, _reader, pe = images(pair, side)
    return capa.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, limits)


def parse(images, pair, side, name=None, limits=DEFAULT_LIMITS['capa']):
    return capa.parse(golden(f'capa/{name or f"{pair}-{side}"}.json'), context(images, pair, side, limits))


def by_rule(evidence):
    return {c.rule_id: c for c in evidence.capabilities}


def test_derived_fixtures_match_their_manifest():
    for name, entry in DERIVED['files'].items():
        assert hashlib.sha256((FIXTURES / 'capa' / name).read_bytes()).hexdigest() == entry['sha256'], name
        source = (FIXTURES / 'capa' / entry['derived_from']).read_bytes()
        assert hashlib.sha256(source).hexdigest() == entry['source_sha256'], name
    assert DERIVED['label'].startswith('DERIVED')


def test_coverage_lists_evaluated_functions_on_real_output(images):
    older = parse(images, 'capa-api', 'older')
    assert older.coverage is not None
    assert older.coverage.evaluated == (0x1000, 0x1030, 0x104d, 0x1065, 0x108b, 0x108e)
    assert older.coverage.library == () and older.coverage.truncated is False


def test_library_and_unrecovered_functions_are_kept_apart(images):
    older = parse(images, 'capa-api', 'older', 'capa-library-derived-older')
    assert older.coverage.library == (0x1030,)
    assert 0x1030 not in older.coverage.evaluated and 0x1065 not in older.coverage.evaluated
    assert 'get hostname' not in by_rule(older)
    newer = parse(images, 'capa-api', 'newer', 'capa-library-derived-newer')
    assert 0x1070 not in newer.coverage.evaluated + newer.coverage.library


def test_features_are_the_successful_leaves_of_the_match(images):
    hostname = by_rule(parse(images, 'capa-api', 'newer'))['get hostname']
    kinds = {f.kind for f in hostname.features}
    assert 'api' in kinds and not kinds & {'os', 'arch', 'format'}
    assert 0 < len(hostname.features) <= common.MAX_FEATURES
    keys = [(f.kind, f.value, -1 if f.rva is None else f.rva) for f in hostname.features]
    assert keys == sorted(keys) and len({k[:2] for k in keys}) == len(keys)
    located = [f for f in hostname.features if f.kind == 'api']
    assert all(f.rva is not None and 0x1053 <= f.rva < 0x1070 for f in located)


def test_failed_branches_are_not_features(images):
    raw = json.loads(golden('capa/capa-api-newer.json'))
    rule = raw['rules']['get hostname']
    failed = {'success': False, 'node': {'type': 'feature', 'feature': {'type': 'api', 'api': 'NeverCalled'}},
              'children': [], 'locations': [], 'captures': {}}
    rule['matches'][0][1]['children'].append(failed)
    evidence = parse_raw(images, raw)
    assert all(f.value != 'NeverCalled' for f in by_rule(evidence)['get hostname'].features)


def parse_raw(images, raw, side='newer', limits=DEFAULT_LIMITS['capa']):
    return capa.parse(json.dumps(raw).encode(), context(images, 'capa-api', side, limits))


def test_labels_carry_names_for_grouping(images):
    xor = by_rule(parse(images, 'capa-api', 'newer'))['encode data using XOR']
    assert [(x.scheme, x.group, x.name, x.ident) for x in xor.labels] == [
        ('attack', 'Defense Evasion', 'Obfuscated Files or Information', 'T1027'),
        ('mbc', 'Data', 'Encode Data::XOR', 'C0026.002'),
        ('mbc', 'Defense Evasion', 'Obfuscated Files or Information::Encoding-Standard Algorithm', 'E1027.m02')]
    assert xor.attack == ('T1027',) and xor.mbc == ('E1027.m02', 'C0026.002')   # the id tuples are unchanged
    assert by_rule(parse(images, 'capa-api', 'newer'))['write file on Windows'].labels[0].scheme == 'mbc'


def test_hostile_label_text_is_escaped(images):
    raw = json.loads(golden('capa/capa-api-newer.json'))
    raw['rules']['get hostname']['meta']['attack'][0]['tactic'] = 'Disc‮overy\x00'
    group = by_rule(parse_raw(images, raw))['get hostname'].labels[0].group
    assert group == 'Disc\\u202eovery\\x00'


def test_oversized_label_text_is_cut_not_rejected(images):
    raw = json.loads(golden('capa/capa-api-newer.json'))
    raw['rules']['get hostname']['meta']['attack'][0]['technique'] = 'T' * 400
    label = by_rule(parse_raw(images, raw))['get hostname'].labels[0]
    assert len(label.name) <= 120


def test_records_stored_before_cap1_stay_readable_and_keep_their_ids(images):
    evidence = parse(images, 'capa-api', 'older')
    old_dump = evidence.model_dump(mode='json', exclude={'coverage'})
    for cap in old_dump['capabilities']:
        del cap['features'], cap['labels']
    revived = common.ToolEvidenceSet.model_validate_json(json.dumps(old_dump))
    assert revived.coverage is None and all(c.features == () and c.labels == () for c in revived.capabilities)
    assert common.evidence_entry_id(revived) == 'capa-older-da98606e7099e8f980db7fce4f3c9368c40dc3f8'
    assert common.evidence_entry_id(evidence) != common.evidence_entry_id(revived)


def test_coverage_must_be_sorted_and_unique():
    with pytest.raises(ValidationError):
        common.FunctionCoverage(evaluated=(2, 1))
    with pytest.raises(ValidationError):
        common.FunctionCoverage(library=(1, 1))
    assert common.FunctionCoverage(evaluated=(1, 2), library=(3,)).truncated is False


def test_extent_attribution_is_reserved_not_emitted(images):
    link = common.EvidenceLink(tool_run_id='r', artifact_sha256='a' * 64, function_id='rva:0x10', rva=0x10,
                               attribution='contained-in-function')
    assert link.attribution not in common.LOCALIZED
    for side in ('older', 'newer'):
        assert all(c.location.attribution != 'contained-in-function'
                   for c in parse(images, 'capa-api', side).capabilities)


def test_a_cut_keeps_function_and_block_matches_before_instruction_and_file_matches(images):
    tight = dataclasses.replace(DEFAULT_LIMITS['capa'], max_rule_matches=5)
    evidence = parse(images, 'capa-api', 'newer', limits=tight)
    assert evidence.truncated and len(evidence.capabilities) == 5
    assert {c.scope for c in evidence.capabilities} <= {'function', 'basic block'}


@pytest.mark.parametrize('code', [11, 13], ids=['missing-file', 'corrupt-file'])
def test_input_file_exit_codes_are_input_errors(code):
    status, error, message = capa.classify_exit(code, '', 'ERROR: bad input')
    assert (status, error) == ('failed', 'PT-TOOL-INPUT') and message.startswith('capa: the input file is')


def test_pairing_error_code_exists():
    assert 'PT-TOOL-PAIRING' in common.ErrorCode.__args__


def ghidra_config(tmp_path: Path, exe: Path, version: str) -> capa.CapaConfig:
    ghidra, java = tmp_path / 'ghidra', tmp_path / 'jdk'
    (ghidra / 'Ghidra').mkdir(parents=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text(f'application.version={version}\n', encoding='utf-8')
    (java / 'bin').mkdir(parents=True)
    (java / 'bin' / ('java.exe' if capa.os.name == 'nt' else 'java')).write_text('', encoding='utf-8')
    return capa.CapaConfig(executable=exe, backend='ghidra', ghidra_dir=ghidra, java_home=java, accept_untested=True)


@pytest.mark.parametrize(('version', 'supported'), [('11.3.2', False), ('11.99', False), ('12.0.4', True),
                                                    ('12.1', True), ('13.0', True)],
                         ids=['11.3', '11.99', '12.0.4', '12.1', '13.0'])
def test_ghidra_backend_needs_ghidra_12(tmp_path, version, supported):
    exe = fake_engine(tmp_path / 'bin', 'capa')
    manifest = capa.probe(ghidra_config(tmp_path, exe, version), use_cache=False)
    assert manifest.supported is supported
    if not supported:
        assert '12.0' in manifest.reason and version in manifest.reason


def test_memory_cap_defaults_to_8_gib_and_zero_turns_it_off():
    config = capa.CapaConfig(executable=None)
    assert config.effective_memory_limit() == 8 * 1024 ** 3
    assert dataclasses.replace(config, memory_limit_bytes=0).effective_memory_limit() is None
    assert dataclasses.replace(config, memory_limit_bytes=2 * 1024 ** 3).effective_memory_limit() == 2 * 1024 ** 3
    with pytest.raises(ToolError) as caught:
        dataclasses.replace(config, memory_limit_bytes=1024).effective_memory_limit()
    assert caught.value.code == 'PT-TOOL-INPUT'


def test_reparse_needs_the_recorded_digest_and_adds_coverage(images):
    raw = golden('capa/capa-api-older.json')
    ctx = context(images, 'capa-api', 'older')
    again = capa.reparse(raw, hashlib.sha256(raw).hexdigest(), ctx)
    assert again == capa.parse(raw, ctx) and again.coverage is not None
    for wrong in ('0' * 64, None):
        with pytest.raises(ToolError) as caught:
            capa.reparse(raw, wrong, ctx)
        assert caught.value.code == 'PT-TOOL-STORE'


def test_parse_of_20000_matches_stays_inside_the_budget(images):
    raw = json.loads(golden('capa/capa-api-newer.json'))
    rule = raw['rules']['get hostname']
    rule['matches'] = [[{'type': 'absolute', 'value': BASE + 0x1053 + (i % 16)}, rule['matches'][0][1]]
                       for i in range(20_000)]
    evidence = parse_raw(images, raw)
    assert len(evidence.capabilities) == 20_000 and evidence.coverage is not None
