"""R3 candidates without bytes: strings, imports and capabilities on the floss-static and capa-api goldens, gates
unit-tested. SYNTHETIC images and committed real-tool output only; no engine, no network, no target execution."""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import itertools
from pathlib import Path

import pytest
import yarax_fixtures as fx
from intel_tools_support import image_getter

from patchtrace.intelligence.tools.common import EvidenceLink
from patchtrace.intelligence.tools.delta import StringChange, ToolDelta
from patchtrace.pe_overview.models import ImportDll, ImportsInfo
from patchtrace.yarax import candidates, features, gates
from patchtrace.yarax.adapters import pe_imports, tools_delta
from patchtrace.yarax.contracts import (
    BytesFeature,
    CapabilityFeature,
    CellResult,
    Gate,
    ImportFeature,
    LintFinding,
    StringFeature,
)
from patchtrace.yarax.errors import RulesError

SRC = Path(__file__).resolve().parents[1] / 'src' / 'patchtrace' / 'yarax'
SHA = 'a' * 64


@pytest.fixture
def images(tmp_path):
    get, close = image_getter(tmp_path)
    yield get
    close()


def gate_states(candidate):
    return {g.gate_id: g.state for g in candidate.gates}


def string_feature(text='abcdefgh', side='newer', **kw):
    values = dict(side=side, value_sha256=hashlib.sha256(text.encode()).hexdigest(), length=len(text), text=text,
                  encoding='ascii', offset=16, evidence_run_id='r', linked_by='file-level',
                  separation='newer-only' if side == 'newer' else 'older-only')
    return StringFeature(**(values | kw))


def window(literal=20, length=24, run=15, **kw):
    pattern = ' '.join(['AA'] * literal + ['??'] * (length - literal))
    values = dict(side='older', window_rva=0x104D, length=length, pattern=pattern, literal=literal, longest_run=run,
                  mask_source='iced-x86', source_hits=1, other_hits=0, separation='older-only')
    return BytesFeature(**(values | kw))


class Fixed:
    """A source stub offering exactly the given features."""

    def __init__(self, items):
        self.items = list(items)

    def string_features(self, pair):
        return self.items

    capability_features = import_features = string_features


# ---- features -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('older,newer,expected', [
    (True, False, 'older-only'), (False, True, 'newer-only'), (True, True, 'both'), (False, False, 'neither'),
    (None, True, 'unknown'), (False, None, 'unknown')], ids=['o', 'n', 'both', 'none', 'u1', 'u2'])
def test_separation_never_turns_an_unreadable_side_into_a_negative(older, newer, expected):
    assert features.separation_of(older, newer) == expected


@pytest.mark.parametrize('raw,expected', [
    (b'plain text', 'plain text'), (b'say "hi"', 'say \\"hi\\"'), (b'a\\b', 'a\\\\b'), (b'x\ty\n', 'x\\ty\\n'),
    (b'a\x00\x7f', 'a\\x00\\x7f'), (b'caf\xc3\xa9', None)], ids=['plain', 'quote', 'slash', 'ws', 'ctrl', 'utf8'])
def test_escape_text(raw, expected):
    assert features.escape_text(raw) == expected


def test_canonical_order_ignores_input_order_and_duplicates():
    items = [string_feature('bbbbbbbb'), string_feature('aaaaaaaaaa'), window(),
             ImportFeature(dll='KERNEL32.dll', name='WriteFile', origin='pe-imports', separation='newer-only'),
             CapabilityFeature(rule_id='r', namespace='n', separation='newer-only')]
    ordered = features.canonical(items)
    assert [f.kind for f in ordered] == ['bytes', 'string', 'string', 'import', 'capability']
    assert ordered[1].text == 'aaaaaaaaaa'      # longer text first
    for permutation in itertools.permutations(items[:4]):
        assert features.canonical([*permutation, items[4], items[0]]) == ordered


# ---- gates --------------------------------------------------------------------------------------------------------

def test_length_gate_thresholds():
    assert gates.length_gate([window()]).state == 'pass'
    assert gates.length_gate([window(literal=15, length=24)]).state == 'fail'
    assert gates.length_gate([window(run=5)]).state == 'fail'
    assert gates.length_gate([string_feature('abcdef').model_copy(update={'included': True})]).state == 'pass'
    short = gates.length_gate([string_feature('abcde').model_copy(update={'included': True})])
    assert short.state == 'fail' and short.measured == 5
    import_only = gates.length_gate([ImportFeature(dll='K.dll', name='F', origin='capa-api', separation='both',
                                                   included=True)])
    assert import_only.state == 'fail' and 'no byte or text pattern' in import_only.detail


def test_unticked_features_do_not_count():
    assert gates.length_gate([string_feature('abcdefgh')]).state == 'fail'


@pytest.mark.parametrize('literal,state', [(24, 'pass'), (15, 'pass'), (14, 'fail')], ids=['none', 'at-40', 'over'])
def test_wildcard_gate_limit_is_forty_percent(literal, state):
    gate = gates.wildcard_gate([window(literal=literal, length=24, run=min(literal, 6))])
    assert gate.state == state and gate.measured == 100 * (24 - literal) // 24


def test_wildcard_gate_is_waived_without_a_byte_pattern():
    assert gates.wildcard_gate([string_feature()]).state == 'waived'


@pytest.mark.parametrize('flags,state', [((), 'pass'), (('toolchain-changed',), 'unknown'),
                                         (('packed', 'installer'), 'fail'), (('protected',), 'fail')],
                         ids=['none', 'toolchain', 'packed', 'protected'])
def test_distortion_gate(flags, state):
    assert gates.distortion_gate(flags).state == state


def test_compile_gate_allows_only_the_style_warning():
    def finding(code, severity='warning'):
        return LintFinding(rule_name='r', code=code, severity=severity, message='m')
    base = gates.evaluate(_pair(), [])
    assert _state(gates.with_compile(base, [finding('text_as_hex')]), 'compile') == 'pass'
    assert _state(gates.with_compile(base, []), 'compile') == 'pass'
    assert _state(gates.with_compile(base, [finding('slow_pattern')]), 'compile') == 'fail'
    assert _state(gates.with_compile(base, [finding('syntax_error', 'error')]), 'compile') == 'fail'


def _pair(**kw):
    from patchtrace.yarax.contracts import FunctionRef, PairSource
    ref = FunctionRef(rva=0x1000, size=32, extent='pdata')
    values = dict(project_id='p', revision=1, run_id='run', older_sha256=SHA, newer_sha256='b' * 64, match_id='m',
                  category='modified', materiality='material', older=ref, newer=ref)
    return PairSource(**(values | kw))


def _state(gate_list, gate_id):
    return next(g.state for g in gate_list if g.gate_id == gate_id)


def _cell(state, hits=0, rvas=()):
    return CellResult(rule_name='r', target_id='t', state=state, hits=hits, rvas=rvas, offsets=(0,) * len(rvas))


@pytest.mark.parametrize('own,other,sep', [
    (_cell('hit', 1, (0x104D,)), _cell('no-hit'), 'pass'),
    (_cell('hit', 1, (0x104D,)), _cell('hit', 1), 'fail'),
    (_cell('no-hit'), _cell('no-hit'), 'fail'),
    (_cell('hit', 1, (0x2000,)), _cell('no-hit'), 'fail'),
    (_cell('hit', 1), None, 'unknown'),
    (_cell('timeout'), _cell('no-hit'), 'unknown'),
    (_cell('hit', 1), _cell('not-scanned'), 'unknown')],
    ids=['ok', 'both', 'miss', 'elsewhere', 'no-other', 'timeout', 'unscanned'])
def test_sep_gate_never_reads_an_unscanned_cell_as_clean(own, other, sep):
    base = gates.evaluate(_pair(), [window(included=True)])
    assert _state(gates.with_scan(base, [window(included=True)], own, other), 'sep') == sep


def test_uniq_gate_needs_exactly_one_hit_and_only_applies_to_byte_windows():
    base = gates.evaluate(_pair(), [window(included=True)])
    one = gates.with_scan(base, [window(included=True)], _cell('hit', 1), _cell('no-hit'))
    two = gates.with_scan(base, [window(included=True)], _cell('hit', 2), _cell('no-hit'))
    assert (_state(one, 'uniq'), _state(two, 'uniq')) == ('pass', 'fail')
    text = gates.with_scan(base, [string_feature(included=True)], _cell('hit', 1), _cell('no-hit'))
    assert _state(text, 'uniq') == 'waived'


def test_refused_lists_only_failed_gates():
    listed = [Gate(gate_id='len', state='fail'), Gate(gate_id='sep', state='unknown'),
              Gate(gate_id='wild', state='waived'), Gate(gate_id='dist', state='pass')]
    assert gates.refused(listed) == ['len']


# ---- string adapter (floss-static golden) -------------------------------------------------------------------------

def test_floss_static_strings_become_side_only_features_from_exact_bytes(images):
    delta, readers = fx.floss_delta(images)
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')
    found = {f.side: f for f in tools_delta.FlossStringSource(delta, readers).string_features(pair)}
    assert found['newer'].text == 'PatchTrace synthetic: index %u exceeds length %u'
    assert found['older'].text == 'PatchTrace synthetic: debug dump of internal state'
    assert found['newer'].separation == 'newer-only' and found['older'].separation == 'older-only'
    assert all(f.encoding == 'ascii' and f.linked_by == 'file-level' and not f.included for f in found.values())
    raw = readers['newer'].read(found['newer'].offset, found['newer'].length)
    assert raw.decode() == found['newer'].text and hashlib.sha256(raw).hexdigest() == found['newer'].value_sha256


def test_string_whose_bytes_do_not_hash_to_the_tool_value_is_dropped(images):
    delta, readers = fx.floss_delta(images)
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')

    class Tampered:
        sha256 = readers['newer'].sha256

        def read(self, offset, length, *, clip=True):
            return b'X' * length

    source = tools_delta.FlossStringSource(delta, {'older': readers['older'], 'newer': Tampered()})
    assert [f.side for f in source.string_features(pair)] == ['older']


def test_string_features_require_the_pairs_own_artifacts(images):
    delta, readers = fx.floss_delta(images)
    other = fx.pair_source(images, 'floss-static', match_id='m', category='modified').model_copy(
        update={'older_sha256': SHA, 'newer_sha256': 'b' * 64})
    assert tools_delta.FlossStringSource(delta, readers).string_features(other) == ()
    assert tools_delta.FlossStringSource(None, readers).string_features(other) == ()


def _delta_with(change: StringChange) -> ToolDelta:
    return ToolDelta(engine='floss', older_run_id='o', newer_run_id='n', comparable=True, strings=(change,))


class _Bytes:
    def __init__(self, data: bytes, sha256=SHA):
        self.data, self.sha256 = data, sha256

    def read(self, offset, length, *, clip=True):
        return self.data[offset:offset + length]


def _change(value: str, *, encoding='UTF-16LE', secret=None, types=('static',), offset=4):
    link = EvidenceLink(tool_run_id='n', artifact_sha256=SHA, file_offset=offset)
    return StringChange(value_hash=hashlib.sha256(value.encode()).hexdigest(), display_value=value[:256],
                        secret_kind=secret, length=len(value), change='added', newer_types=types,
                        newer_encodings=(encoding,), newer=(link,))


def test_wide_string_is_read_as_utf16_and_emitted_as_wide():
    value = 'wide value'
    reader = _Bytes(b'\0' * 4 + value.encode('utf-16-le'))
    pair = _pair(newer_sha256=SHA)
    [feature] = tools_delta.FlossStringSource(_delta_with(_change(value)), {'newer': reader}).string_features(pair)
    assert (feature.encoding, feature.text, feature.length, feature.offset) == ('wide', value, len(value), 4)


@pytest.mark.parametrize('change', [
    _change('secret value', secret='aws-access-key'), _change('decoded one', types=('decoded',)),
    _change('x' * 300, encoding='ASCII'), _change('café value', encoding='UTF-8')],
    ids=['secret', 'decoded', 'too-long', 'non-ascii'])
def test_strings_that_must_not_seed_a_pattern_are_left_out(change):
    reader = _Bytes(b'\0' * 4 + change.display_value.encode('utf-8'))
    assert tools_delta.FlossStringSource(_delta_with(change), {'newer': reader}).string_features(_pair(
        newer_sha256=SHA)) == ()


def test_secret_strings_are_counted_not_offered():
    secret = _change('AKIAIOSFODNN7EXAMPLE', encoding='ASCII', secret='aws-access-key')
    assert tools_delta.secrets_excluded(_delta_with(secret)) == 1 and tools_delta.secrets_excluded(None) == 0


# ---- capability and import adapters (capa-api golden) ------------------------------------------------------------

@pytest.mark.parametrize('match,category,rule,side,gate', [
    ('term', 'removed', 'terminate process', 'older-only', 'TerminateProcess'),
    ('log', 'modified', 'write file on Windows', 'newer-only', 'WriteFile'),
    ('env', 'added', 'query environment variable', 'newer-only', 'GetEnvironmentVariable')],
    ids=['term', 'log', 'env'])
def test_capa_gained_and_lost_behaviour_of_the_pair(images, match, category, rule, side, gate):
    pair = fx.pair_source(images, 'capa-api', match_id=match, category=category)
    [feature] = tools_delta.CapaCapabilitySource(fx.capa_pairs_golden()).capability_features(pair)
    assert (feature.rule_id, feature.separation, feature.api_gates) == (rule, side, (gate,))
    assert not feature.included


def test_unchanged_pair_and_unavailable_pairing_offer_no_capability(images):
    golden = fx.capa_pairs_golden()
    pair = fx.pair_source(images, 'capa-api', match_id='main', category='modified')
    assert tools_delta.CapaCapabilitySource(golden).capability_features(pair) == ()
    env = fx.pair_source(images, 'capa-api', match_id='env', category='added')
    assert tools_delta.CapaCapabilitySource(golden.model_copy(update={'pairing': 'unavailable'})
                                            ).capability_features(env) == ()
    assert tools_delta.CapaCapabilitySource(None).capability_features(env) == ()


def test_moved_and_detection_only_rows_are_not_offered(images):
    golden = fx.capa_pairs_golden()
    env = fx.pair_source(images, 'capa-api', match_id='env', category='added')
    for update in ({'change': 'moved'}, {'noise': 'detection-difference'}, {'relocation': 'candidate'}):
        rows = tuple(r.model_copy(update=update) if r.match_id == 'env' else r for r in golden.changes)
        source = tools_delta.CapaCapabilitySource(golden.model_copy(update={'changes': rows}))
        assert source.capability_features(env) == (), update


def test_import_gates_resolve_capa_names_to_the_dll_of_that_build(images):
    older, newer = fx.overviews(images, 'capa-api')
    source = pe_imports.PeImportSource(older, newer, tools_delta.CapaCapabilitySource(fx.capa_pairs_golden()))
    got = {(f.name, f.origin, f.separation) for f in source.import_features(
        fx.pair_source(images, 'capa-api', match_id='term', category='removed'))}
    assert ('TerminateProcess', 'capa-api', 'older-only') in got
    assert ('WriteFile', 'pe-imports', 'newer-only') in got
    suffix = {(f.dll, f.name, f.origin) for f in source.import_features(
        fx.pair_source(images, 'capa-api', match_id='env', category='added'))}
    assert ('KERNEL32.dll', 'GetEnvironmentVariableA', 'capa-api') in suffix     # capa says GetEnvironmentVariable


def test_unreadable_or_cut_import_tables_make_separation_unknown_not_a_difference(images):
    older, newer = fx.overviews(images, 'capa-api')
    pair = fx.pair_source(images, 'capa-api', match_id='term', category='removed')
    assert pe_imports.PeImportSource(older, None).import_features(pair) == ()
    cut = dataclasses.replace(newer, imports=ImportsInfo(
        dlls=(ImportDll('KERNEL32.dll', ('ExitProcess',), 1, True),), total_dlls=1, total_functions=1, truncated=True))
    assert 'TerminateProcess' not in {f.name for f in pe_imports.PeImportSource(older, cut).import_features(pair)}


def test_ordinal_imports_and_unreadable_names():
    overview = fx_overview(('#12', '<unreadable @ 0x10>', 'Real'))
    empty = fx_overview(())
    [ordinal, real] = pe_imports.PeImportSource(overview, empty).import_features(_pair())
    assert (ordinal.name, ordinal.ordinal) == (None, 12) and real.name == 'Real'


def fx_overview(functions):
    from patchtrace.pe_overview.models import PeOverview
    dll = ImportDll('USER32.dll', tuple(functions), len(functions), False)
    return PeOverview(size=1, sha256=SHA, status='ok',
                      imports=ImportsInfo((dll,), 1, len(functions), False))


# ---- candidates ---------------------------------------------------------------------------------------------------

def floss_candidates(images, **kw):
    delta, readers = fx.floss_delta(images)
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')
    source = tools_delta.FlossStringSource(delta, readers)
    return pair, source, candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=source, **kw)


def test_floss_static_gives_one_candidate_per_direction_with_its_own_string(images):
    pair, _source, found = floss_candidates(images)
    assert [c.direction for c in found] == ['older', 'newer']
    for candidate in found:
        [text] = [f for f in candidate.features if f.included]
        assert text.side == candidate.direction and text.separation == f'{candidate.direction}-only'
        assert candidate.rule_name == f'PT_{candidate.lineage_id[:12]}_{candidate.direction}'
        assert candidate.rule_sha256 == hashlib.sha256(candidate.rule_text.encode()).hexdigest()
        assert gate_states(candidate) == {'elig': 'pass', 'len': 'pass', 'wild': 'waived', 'uniq': 'unknown',
                                          'sep': 'unknown', 'compile': 'unknown', 'secret': 'pass', 'dist': 'pass'}
        assert not candidate.unvetted and candidate.engine == fx.ENGINE
    assert found[0].lineage_id != found[1].lineage_id


def test_proposal_is_deterministic_and_independent_of_source_order(images):
    pair, source, first = floss_candidates(images)
    items = source.string_features(pair)
    for ordering in (items, items[::-1]):
        again = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=Fixed(ordering))
        assert [(c.candidate_id, c.rule_sha256) for c in again] == [(c.candidate_id, c.rule_sha256) for c in first]


def test_pair_that_is_neither_material_nor_confirmed_is_refused(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified', materiality='cosmetic')
    with pytest.raises(RulesError) as info:
        candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=Fixed([string_feature()]))
    assert info.value.code == 'PT-RULE-INPUT'


def test_analyst_confirmed_pair_is_flagged_unvetted(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified', materiality='cosmetic',
                          confirmed=True)
    [candidate] = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE,
                                     strings=Fixed([string_feature()]))
    assert candidate.unvetted and gate_states(candidate)['elig'] == 'waived'


def test_a_removed_pair_has_no_newer_rule_and_an_added_pair_no_older_rule(images):
    both = Fixed([string_feature('older text', 'older'), string_feature('newer text', 'newer')])
    for category, expected in (('removed', ['older']), ('added', ['newer']), ('modified', ['older', 'newer'])):
        pair = fx.pair_source(images, 'floss-static', match_id='m', category=category)
        found = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=both)
        assert [c.direction for c in found] == expected


def test_capa_api_pair_gives_a_weak_import_only_candidate_for_the_removed_function(images):
    older, newer = fx.overviews(images, 'capa-api')
    capa = tools_delta.CapaCapabilitySource(fx.capa_pairs_golden())
    pair = fx.pair_source(images, 'capa-api', match_id='term', category='removed')
    [candidate] = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, capabilities=capa,
                                     imports=pe_imports.PeImportSource(older, newer, capa))
    assert candidate.direction == 'older'
    included = [f for f in candidate.features if f.included]
    assert [(f.kind, f.name, f.origin) for f in included] == [('import', 'TerminateProcess', 'capa-api')]
    assert any(isinstance(f, CapabilityFeature) and f.rule_id == 'terminate process' and not f.included
               for f in candidate.features)
    states = gate_states(candidate)
    assert states['len'] == 'fail' and states['elig'] == 'pass'
    assert gates.refused(candidate.gates) == ['len']      # an import alone is not a rule worth accepting
    assert 'import' in candidate.rule_text and 'string' not in candidate.rule_text


def test_modified_pair_keeps_each_direction_to_its_own_capability(images):
    older, newer = fx.overviews(images, 'capa-api')
    capa = tools_delta.CapaCapabilitySource(fx.capa_pairs_golden())
    pair = fx.pair_source(images, 'capa-api', match_id='log', category='modified')
    found = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, capabilities=capa,
                               imports=pe_imports.PeImportSource(older, newer, capa))
    assert [c.direction for c in found] == ['newer']      # nothing anchors an older rule for `log`
    names = {f.name for f in found[0].features if isinstance(f, ImportFeature) and f.included}
    assert names == {'WriteFile'}


def test_a_gate_both_builds_import_is_still_a_gate_for_its_own_capability_only(images):
    pair = fx.pair_source(images, 'capa-api', match_id='m', category='modified')
    items = [CapabilityFeature(rule_id='lost one', namespace='n', api_gates=('CloseHandle',),
                               separation='older-only'),
             ImportFeature(dll='KERNEL32.dll', name='CloseHandle', origin='capa-api', separation='both'),
             ImportFeature(dll='KERNEL32.dll', name='Other', origin='capa-api', separation='both')]
    found = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, imports=Fixed(items),
                               capabilities=Fixed(items[:1]))
    [candidate] = found
    assert [f.name for f in candidate.features if isinstance(f, ImportFeature)] == ['CloseHandle']


def test_flags_and_excluded_secrets_reach_the_gates(images):
    pair, source, _ = floss_candidates(images)
    found = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=source,
                               flag_codes=('packed',), secrets_excluded=3)
    secret = next(g for g in found[0].gates if g.gate_id == 'secret')
    assert gate_states(found[0])['dist'] == 'fail' and secret.measured == 3


def test_offered_features_are_bounded_and_only_four_texts_are_ticked(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')
    many = Fixed([string_feature(f'string number {i:02d}') for i in range(30)])
    [candidate] = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=many)
    assert len(candidate.features) == 24 and sum(f.included for f in candidate.features) == 4


def test_byte_window_present_leaves_file_level_strings_unticked(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='removed')
    linked = string_feature('linked text', 'older', linked_by='xref')
    plain = string_feature('plain text!', 'older')
    [candidate] = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE,
                                     strings=Fixed([window(), linked, plain]))
    assert {f.kind + str(f.included) for f in candidate.features} == {'bytesTrue', 'stringTrue', 'stringFalse'}
    assert [f.text for f in candidate.features if isinstance(f, StringFeature) and f.included] == ['linked text']


def test_no_sources_or_no_difference_gives_no_candidate(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')
    assert candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE) == ()
    both = string_feature('same text!', 'older', separation='both')
    assert candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=Fixed([both])) == ()


# ---- revisions ----------------------------------------------------------------------------------------------------

def test_toggling_a_feature_is_a_new_revision_with_the_same_lineage_and_fresh_gates(images):
    _pair_, _source, found = floss_candidates(images)
    candidate = found[1]
    scanned = candidate.model_copy(update={'gates': gates.with_scan(
        candidate.gates, candidate.features, _cell('hit', 1), _cell('no-hit'))})
    assert gate_states(scanned)['sep'] == 'pass'
    [text] = [f for f in candidate.features if f.included]
    off = candidates.recompose(scanned, [], writer=fx.fake_writer)
    assert off.lineage_id == candidate.lineage_id and off.rule_name == candidate.rule_name
    assert off.candidate_id != candidate.candidate_id and not any(f.included for f in off.features)
    assert gate_states(off)['len'] == 'fail' and gate_states(off)['sep'] == 'unknown'
    on = candidates.recompose(off, [features.feature_id(text)], writer=fx.fake_writer)
    assert on.candidate_id == candidate.candidate_id and gate_states(on)['len'] == 'pass'
    assert gate_states(on)['sep'] == 'unknown'          # the earlier scan no longer describes this selection


def test_revision_selection_is_validated(images):
    pair = fx.pair_source(images, 'floss-static', match_id='m', category='modified')
    many = Fixed([string_feature(f'string number {i:02d}') for i in range(8)])
    [candidate] = candidates.propose(pair, writer=fx.fake_writer, engine=fx.ENGINE, strings=many)
    ids = [features.feature_id(f) for f in candidate.features]
    with pytest.raises(RulesError) as unknown:
        candidates.recompose(candidate, ['string:newer:nope'], writer=fx.fake_writer)
    with pytest.raises(RulesError) as limit:
        candidates.recompose(candidate, ids[:5], writer=fx.fake_writer)
    assert (unknown.value.code, limit.value.code) == ('PT-RULE-INPUT', 'PT-RULE-LIMIT')


# ---- purity -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('module', ['features', 'gates', 'candidates', 'adapters/tools_delta',
                                    'adapters/pe_imports'])
def test_r3_modules_import_no_engine_decoder_qt_or_network(module):
    tree = ast.parse((SRC / f'{module}.py').read_text(encoding='utf-8'))
    imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split('.')[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module and node.level == 0}
    assert not imported & {'yara_x', 'iced_x86', 'PySide6', 'socket', 'urllib', 'http', 'requests', 'subprocess'}
