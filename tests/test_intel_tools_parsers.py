"""SPEC-29 tools T3/T5/T6: strict parsers and deltas on REAL capa 9.4.0 / FLOSS 3.1.1 / diec 3.21 output captured on
SYNTHETIC PE pairs (tests/fixtures/intel_tools/manifest.json). No tool runs here; negatives are derived from the
goldens and labelled as such. Real-tool behaviour on synthetic input is not evidence about real binaries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_intel_tools_pe import PAIRS

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools import capa, delta, diec, floss
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError, ToolManifest, ToolRun, cache_key
from patchtrace.intelligence.tools.normalize import FunctionPairing, PeMap
from patchtrace.intelligence.tools.process import ArtifactCopy

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'intel_tools'
MANIFEST = json.loads((FIXTURES / 'manifest.json').read_text(encoding='utf-8'))


def golden(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def images(tmp_path):
    """name -> side -> (ArtifactCopy, reader, PeMap); readers are closed after the test."""
    opened, out = [], {}

    def get(pair: str, side: str):
        if (pair, side) not in out:
            data = dict(zip(('older', 'newer'), PAIRS[pair](), strict=True))[side]
            path = tmp_path / f'{pair}-{side}.bin'
            path.write_bytes(data)
            copy = ArtifactCopy(path, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(),
                                hashlib.sha1(data).hexdigest(), len(data))
            reader = VerifiedArtifactReader.open_path(path, copy.sha256)
            opened.append(reader)
            out[(pair, side)] = (copy, reader, PeMap.from_reader(reader))
        return out[(pair, side)]
    yield get
    for reader in opened:
        reader.close()


def test_fixture_inputs_are_the_deterministic_builder_output(images):
    for name, entry in MANIFEST['files'].items():
        if (entry.get('input') or '').endswith('.exe'):
            pair, side = entry['input'][:-4].rsplit('-', 1)
            assert images(pair, side)[0].sha256 == entry['input_sha256'], name
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == entry['sha256'], name


def parse_capa(images, pair, side, raw=None):
    copy, _reader, pe = images(pair, side)
    ctx = capa.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
    return capa.parse(raw if raw is not None else golden(f'capa/{pair}-{side}.json'), ctx)


def test_capa_scopes_locations_and_whole_file_matches(images):
    older = {c.rule_id: c for c in parse_capa(images, 'capa-api', 'older').capabilities}
    newer = {c.rule_id: c for c in parse_capa(images, 'capa-api', 'newer').capabilities}
    host = newer['get hostname']
    assert (host.scope, host.location.attribution, host.location.function_id) == ('function', 'function-start',
                                                                                  'rva:0x1053')
    assert host.feature_rvas == (0x1065,)  # the GetComputerNameA call site inside the function
    xor = newer['encode data using XOR']
    assert xor.location.attribution == 'basic-block-in-function' and xor.location.rva == 0x10be
    assert xor.location.function_id == 'rva:0x10bc'  # from capa's own layout, not a guess
    link = newer['link function at runtime on Windows']
    assert link.scope == 'instruction' and link.location.rva == 0x108b and link.location.attribution == 'none'
    tls = newer['contain a thread local storage (.tls) section']
    assert tls.scope == 'file' and tls.address_space == 'no address' and tls.location.rva is None
    assert tls.location.attribution == 'none'  # whole-file match never names a function
    assert older['contain loop'].kind == 'library'
    assert 'terminate process' in older and 'terminate process' not in newer


def test_capa_rejects_wrong_artifact_contract_and_truncation(images):
    raw = json.loads(golden('capa/capa-api-older.json'))
    with pytest.raises(ToolError) as info:  # output of the newer file presented for the older artifact
        parse_capa(images, 'capa-api', 'older', golden('capa/capa-api-newer.json'))
    assert info.value.code == 'PT-TOOL-ARTIFACT'
    wrong = json.loads(json.dumps(raw))
    wrong['meta']['version'] = '8.0.1'
    with pytest.raises(ToolError, match='not 9.x'):
        parse_capa(images, 'capa-api', 'older', json.dumps(wrong).encode())
    extra = dict(raw, surprise=1)
    with pytest.raises(ToolError, match='parser contract'):
        parse_capa(images, 'capa-api', 'older', json.dumps(extra).encode())
    full = golden('capa/capa-api-older.json').rstrip()
    for cut in (1, len(full) // 2, len(full) - 1):  # derived truncated negatives (the closing brace is cut)
        with pytest.raises(ToolError) as info:
            parse_capa(images, 'capa-api', 'older', full[:cut])
        assert info.value.code == 'PT-TOOL-OUTPUT'


def test_capa_invalid_and_ambiguous_addresses_become_anomalies(images):
    raw = json.loads(golden('capa/capa-api-older.json'))
    rule = raw['rules']['get hostname']
    rule['matches'][0][0] = {'type': 'absolute', 'value': 0x7FFF0000}  # outside the image
    raw['meta']['analysis']['base_address']['value'] = 0x140000000
    result = parse_capa(images, 'capa-api', 'older', json.dumps(raw).encode())
    host = next(c for c in result.capabilities if c.rule_id == 'get hostname')
    assert host.location.rva is None and host.location.attribution == 'none'
    assert any(a.startswith('address-out-of-image') for a in result.anomalies)


def test_floss_static_default_never_emulates_and_verifies_offsets(images):
    config = floss.FlossConfig(Path('/opt/floss/floss'))
    argv = floss.build_argv(config, '/opt/floss/floss', Path('/s/in/artifact.bin'))
    assert argv[argv.index('--only') + 1:argv.index('--')] == ['static']
    assert not {'stack', 'tight', 'decoded'} & set(argv)
    assert floss.options(config)['types'] == 'static' and 'emulation_consent_sha256' not in floss.options(config)
    with pytest.raises(ToolError) as info:
        floss.build_argv(floss.FlossConfig(Path('/x'), deobfuscate=True), '/x', Path('/a'))
    assert info.value.code == 'PT-TOOL-CONSENT'
    opted = floss.FlossConfig(Path('/x'), deobfuscate=True, consent_sha256=floss.EMULATION_CONSENT_SHA256)
    assert floss.build_argv(opted, '/x', Path('/a'))[-6:-2] == ['static', 'stack', 'tight', 'decoded']
    copy, reader, pe = images('floss-static', 'newer')
    ctx = floss.ParseContext('r', 'newer', copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], False)
    result = floss.parse(golden('floss/floss-static-newer.static.json'), ctx)
    assert all(s.type == 'static' and s.confidence_class == 'verified-bytes' for s in result.strings)
    secret = next(s for s in result.strings if s.secret_kind)
    assert secret.secret_kind == 'aws-access-key'
    wide = next(s for s in result.strings if s.encoding == 'UTF-16LE')
    assert wide.source_location.rva is not None and wide.source_location.file_offset is not None
    with pytest.raises(ToolError, match='not requested'):  # emulation output while emulation was off
        floss.parse(golden('floss/floss-decode-older.deobfuscate.json'), ctx)


def test_floss_decoded_strings_need_the_opt_in_and_name_the_decoding_routine(images):
    copy, reader, pe = images('floss-decode', 'older')
    ctx = floss.ParseContext('r', 'older', copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], True)
    result = floss.parse(golden('floss/floss-decode-older.deobfuscate.json'), ctx)
    decoded = [s for s in result.strings if s.type == 'decoded']
    assert [s.display_value for s in decoded] == ['PatchTrace decoded: build one']
    assert decoded[0].source_location.attribution == 'decoding-routine'
    assert decoded[0].source_location.function_id == 'rva:0x1036'
    assert floss.empty_set(ctx).evidence_count() == 0  # FLOSS prints nothing when there is no static string
    assert golden('floss/empty-no-static-strings.stdout.txt') == b''


def diec_set(name: str, side: str):
    ctx = diec.ParseContext('r', side, 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec'])
    return diec.parse(golden(f'diec/{name}.json'), ctx)


def test_diec_certainty_and_quality_flags():
    same = delta.quality_flags((diec_set('diec-same-older', 'older'), diec_set('diec-same-newer', 'newer')))
    assert same == ()  # stable same-toolchain pair: no flag
    changed = delta.quality_flags((diec_set('diec-toolchain-older', 'older'),
                                   diec_set('diec-toolchain-newer', 'newer')))
    assert [f.code for f in changed] == ['toolchain-changed']
    unknown = delta.quality_flags((diec_set('diec-unknown-older', 'older'), diec_set('diec-unknown-newer', 'newer')))
    assert [f.code for f in unknown] == ['environment-unknown']  # never read as a toolchain change
    heur = diec_set('diec-unknown-newer.heuristic', 'newer')
    assert [(e.certainty, e.heuristic) for e in heur.environment] == [('heuristic', True)]
    with pytest.raises(ToolError):
        diec.parse(b'{"detects": [{"filetype": "PE64"}]}', diec.ParseContext('r', 'older', 'a' * 64, 'c' * 64,
                                                                            'd' * 64, DEFAULT_LIMITS['diec']))


def _run(side: str, evidence, manifest: ToolManifest) -> ToolRun:
    return ToolRun(run_id=evidence.run_id, engine='capa', side=side, input_artifact_hash=evidence.artifact_sha256,
                   config_digest='d' * 64, cache_key=evidence.cache_key, started_at='2026-10-14T00:00:00+00:00',
                   elapsed=1, status='ok', evidence_count=evidence.evidence_count(), profile='basic', manifest=manifest)


class _Fn:
    def __init__(self, address: str):
        self.id, self.address, self.address_space = f'fn-{address}', address, 'virtual'


class _Match:
    def __init__(self, category, older=(), newer=()):
        self.category, self.older, self.newer = category, [_Fn(a) for a in older], [_Fn(a) for a in newer]


def test_capa_delta_classifies_introduced_detectable_unlocalized_and_removed(images):
    manifest = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    older = parse_capa(images, 'capa-api', 'older').model_copy(update={'cache_key': 'c' * 64})
    newer = parse_capa(images, 'capa-api', 'newer').model_copy(update={'cache_key': 'c' * 64})
    pairing = FunctionPairing.from_project(
        [_Match('added', newer=['140001030']), _Match('modified', ['14000108b'], ['140001096']),
         _Match('removed', older=['14000104d'])],
        {'address_matches': {'140001030': [['140001053', ['SymbolsHash']]]}},
        older_base=0x140000000, newer_base=0x140000000)
    result = delta.compute(_run('older', older, manifest), older, _run('newer', newer, manifest), newer,
                           pairing=pairing)
    by_rule = {c.rule_id: c for c in result.capabilities if c.kind == 'capability'}
    assert by_rule['query environment variable'].classification == 'newly-introduced'   # new function
    assert by_rule['write file on Windows'].classification == 'newly-introduced'        # modified function
    assert by_rule['terminate process'].classification == 'removed-with-code'
    assert by_rule['contain a thread local storage (.tls) section'].classification == 'unlocalized'
    assert by_rule['get hostname'].change == 'unchanged'
    assert by_rule['query environment variable'].newer[0].project_function_id == 'fn-140001030'
    assert result.value_gate == 'unvalidated' and delta.has_changes(result)
    # same code, different detection: a function the pairing calls unchanged gains a capability
    same_code = FunctionPairing.from_project([], {'address_matches': {'140001030': [['140001030', ['x']]]}},
                                             older_base=0x140000000, newer_base=0x140000000)
    detectable = delta.compute(_run('older', older, manifest), older, _run('newer', newer, manifest), newer,
                               pairing=same_code)
    env = next(c for c in detectable.capabilities if c.rule_id == 'query environment variable')
    assert env.classification == 'newly-detectable'
    no_pairing = delta.compute(_run('older', older, manifest), older, _run('newer', newer, manifest), newer)
    assert next(c for c in no_pairing.capabilities if c.rule_id == 'query environment variable'
                ).classification == 'unknown' and no_pairing.pairing == 'unavailable'


def test_capa_control_pair_has_no_capability_change(images):
    manifest = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    older = parse_capa(images, 'capa-control', 'older')
    newer = parse_capa(images, 'capa-control', 'newer')
    result = delta.compute(_run('older', older, manifest), older, _run('newer', newer, manifest), newer)
    assert result.comparable and not delta.has_changes(result)  # every RVA moved by 0x40, nothing changed


def test_delta_refuses_runs_with_different_configurations(images):
    manifest = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    older = parse_capa(images, 'capa-control', 'older')
    newer = parse_capa(images, 'capa-control', 'newer')
    other = _run('newer', newer, manifest.model_copy(update={'executable_sha256': 'f' * 64})).model_copy(
        update={'config_digest': 'e' * 64})
    result = delta.compute(_run('older', older, manifest), older, other, newer)
    assert not result.comparable and any('configuration differs' in r for r in result.reasons)
    assert result.capabilities == ()


def test_string_delta_redacts_secrets_by_default(images):
    sets = {}
    for side in ('older', 'newer'):
        copy, reader, pe = images('floss-static', side)
        ctx = floss.ParseContext(f'r-{side}', side, copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'],
                                 False)
        sets[side] = floss.parse(golden(f'floss/floss-static-{side}.static.json'), ctx)
    manifest = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    runs = {side: ToolRun(run_id=s.run_id, engine='floss', side=side, input_artifact_hash=s.artifact_sha256,
                          config_digest='d' * 64, cache_key=s.cache_key, started_at='t', elapsed=0, status='ok',
                          evidence_count=s.evidence_count(), profile='context', manifest=manifest)
            for side, s in sets.items()}
    result = delta.compute(runs['older'], sets['older'], runs['newer'], sets['newer'])
    changes = {c.display_value: c.change for c in result.strings}
    assert changes['PatchTrace synthetic: index %u exceeds length %u'] == 'added'
    assert changes['PatchTrace synthetic: debug dump of internal state'] == 'removed'
    assert result.counts['strings_unchanged'] >= 3
    revealed = delta.compute(runs['older'], sets['older'], runs['newer'], sets['newer'], show_secrets=True,
                             include_unchanged_strings=True)
    assert any('AKIAIOSFODNN7EXAMPLE' in c.display_value for c in revealed.strings)
    hidden = delta.compute(runs['older'], sets['older'], runs['newer'], sets['newer'], include_unchanged_strings=True)
    assert not any('AKIA' in c.display_value for c in hidden.strings)


def test_cache_key_is_stable_for_identical_inputs():
    manifest = ToolManifest(engine='diec', version='3.21', executable_sha256='e' * 64, license='MIT',
                            rules_source='directory', rules_sha256=next(iter(diec.KNOWN_DATABASES)), supported=True)
    options = diec.options(diec.DiecConfig(None))
    assert cache_key('a' * 64, manifest, options) == cache_key('a' * 64, manifest, dict(options))
    assert options == {'argv': 'diec/1', 'mode': 'signature'}
    argv = diec.build_argv(diec.DiecConfig(None), '/d/diec', Path('/s'), Path('/s/in/artifact.bin'))
    assert '-u' not in argv and argv[argv.index('-E') + 1] == argv[argv.index('-C') + 1]
