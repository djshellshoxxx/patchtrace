"""CAP-3: the pure view-model of the capability changes (rows, filters, grouping, states, detail, provenance block,
teach hooks, wording). No Qt here; the panel (CAP-6) only draws these strings."""
from __future__ import annotations

import colorsys
import dataclasses
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
from intel_tools_support import golden, image_getter
from test_capa_pairs import both, group, pairs, run_for
from test_capa_synergy import CHANGED, UNCHANGED_RAW

from patchtrace.intelligence.tools import capa, capa_view
from patchtrace.intelligence.tools.capa_pairs import (
    CoverageSummary,
    PairCapabilityDelta,
    PairCell,
    PairChange,
    groups_from_project,
)
from patchtrace.intelligence.tools.capa_view import (
    CapabilityView,
    RunInfo,
    StateInputs,
    ViewOptions,
    cell_text,
    resolve_state,
    rule_hashes,
    rules_label,
)
from patchtrace.intelligence.tools.common import (
    DEFAULT_LIMITS,
    FeatureRef,
    TaxonomyLabel,
    ToolManifest,
)
from patchtrace.intelligence.tools.delta import QualityFlag

SRC = Path(__file__).resolve().parents[1] / 'src'
BASE = 0x140000000
HOST = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                    rules_source='embedded', supported=True)


@pytest.fixture(scope='module')
def api(tmp_path_factory):
    """The REAL capa-api pair through the synergy pairing."""
    get, close = image_getter(tmp_path_factory.mktemp('images'))
    sides = {}
    for side in ('older', 'newer'):
        copy, _reader, pe = get('capa-api', side)
        ctx = capa.ParseContext(f'run-{side}', side, copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
        sides[side] = capa.parse(golden(f'capa/capa-api-{side}.json'), ctx)
    close()
    groups = groups_from_project(CHANGED, UNCHANGED_RAW, (BASE, BASE))
    delta = pairs(sides['older'], sides['newer'], groups, include_unchanged=True)
    info = RunInfo('demo', 'run-1', False, run_for('older', sides['older']), run_for('newer', sides['newer']))
    return CapabilityView(delta, groups, rule_hashes(sides['older'].capabilities, sides['newer'].capabilities), info)


def row_for(view: CapabilityView, rule: str, change: str | None = None):
    return next(r for r in view.rows if r.rule == rule and (change is None or r.change.change == change))


def labels(arrangement) -> list[str]:
    return [g.label for g in arrangement.groups]


# ---- cells, summary, table --------------------------------------------------------------------------------------

@pytest.mark.parametrize(('cell', 'text'), [
    (PairCell(state='present', matches=1), 'present, 1 match'),
    (PairCell(state='present', matches=3), 'present, 3 matches'),
    (PairCell(state='absent'), 'absent'),
    (PairCell(state='no-function'), 'no function'),
    (PairCell(state='not-evaluated', reason='library-function'), 'not evaluated: library function'),
    (PairCell(state='not-evaluated', reason='function-not-recovered'),
     'not evaluated: function not found by capa'),
    (PairCell(state='not-evaluated', reason='evidence-truncated'), 'not evaluated: capa output was cut')],
    ids=['one', 'many', 'absent', 'no-function', 'library', 'not-found', 'cut'])
def test_cell_texts(cell, text):
    assert cell_text(cell) == text


def test_summary_and_default_table_on_real_output(api):
    assert api.summary() == ('2 gained | 1 lost | 0 moved | 2 unchanged | 0 not compared | capa evaluated both '
                             'sides of 5 of 5 matched pairs')
    shown = api.arrange()
    assert labels(shown) == ['host-interaction/environment-variable', 'host-interaction/file-system',
                             'host-interaction/process']
    rows = [(r.rule, r.status, r.older, r.newer, r.pair) for g in shown.groups for r in g.rows]
    assert ('write file on Windows', '+ Gained', 'absent', 'present, 1 match', 'modified: 0x108b -> 0x1096') in rows
    assert ('query environment variable', '+ Gained', 'no function', 'present, 1 match', 'added: -> 0x1030') in rows
    assert ('terminate process', '- Lost', 'present, 1 match', 'no function', 'removed: 0x104d ->') in rows
    assert shown.shown == 3 and shown.expanded


def test_rows_are_ordered_by_namespace_then_rule_never_by_count(api):
    shown = api.arrange(ViewOptions(filter='all', show_library=True))
    assert labels(shown) == sorted(labels(shown), key=str.lower)
    for group_ in shown.groups:
        keys = [(r.namespace, r.rule) for r in group_.rows]
        assert keys == sorted(keys)


@pytest.mark.parametrize(('mode', 'rules'), [
    ('changes', {'write file on Windows', 'query environment variable', 'terminate process'}),
    ('gained', {'write file on Windows', 'query environment variable'}), ('lost', {'terminate process'}),
    ('moved', set()), ('unchanged', {'get hostname', 'encode data using XOR'}), ('not-compared', set()),
    ('all', {'write file on Windows', 'query environment variable', 'terminate process', 'get hostname',
             'encode data using XOR'})],
    ids=['changes', 'gained', 'lost', 'moved', 'same', 'not-compared', 'all'])
def test_filters(api, mode, rules):
    shown = api.arrange(ViewOptions(filter=mode))
    assert {r.rule for g in shown.groups for r in g.rows} == rules


def test_library_rules_and_noise_are_hidden_until_asked(api):
    plain = api.arrange(ViewOptions(filter='all'))
    assert 'contain loop' not in {r.rule for g in plain.groups for r in g.rows}
    full = api.arrange(ViewOptions(filter='all', show_library=True))
    assert 'contain loop' in {r.rule for g in full.groups for r in g.rows}


def test_detection_noise_is_one_collapsed_group_never_called_new(api):
    groups = [group('m:a', 'unchanged', [1], [1]), group('m:b', 'modified', [2], [2])]
    delta = both([], [('x', 1, {}), ('y', 2, {})], groups)
    view = CapabilityView(delta, groups)
    assert [r.rule for g in view.arrange().groups for r in g.rows] == ['y']
    shown = view.arrange(ViewOptions(show_noise=True))
    assert labels(shown)[-1] == 'Detection differences (same code, different detection)'
    assert [r.rule for r in shown.groups[-1].rows] == ['x']


def test_search_matches_rule_namespace_and_function_names(api):
    names = lambda text: {r.rule for g in api.arrange(ViewOptions(filter='all', search=text)).groups  # noqa: E731
                          for r in g.rows}
    assert names('FILE') == {'write file on Windows'}
    assert names('environment-variable') == {'query environment variable'}
    assert names('o_104d') == {'terminate process'}
    assert names('no such thing') == set()


def test_unattributed_matches_are_a_separate_opt_in_list(api):
    assert api.arrange().unattributed == ()
    lines = api.arrange(ViewOptions(show_unattributed=True)).unattributed
    assert lines == ('contain a thread local storage (.tls) section (file): only in the newer file, matches the '
                     'whole file',
                     'link function at runtime on Windows (instruction): in both files, matches one instruction, '
                     'no function named')


def test_few_rows_start_expanded_many_do_not():
    groups = [group(f'm:{i}', 'added', newer=[i]) for i in range(1, 31)]
    delta = both([], [(f'r{i}', i, {'namespace': f'ns{i}/x'}) for i in range(1, 31)], groups,
                 new_eval=range(1, 31))
    view = CapabilityView(delta, groups)
    assert view.arrange().expanded is False and view.arrange(ViewOptions(search='r1')).expanded is True


def test_too_many_rows_show_nothing_and_say_so(monkeypatch):
    monkeypatch.setattr(capa_view, 'MAX_DISPLAY_ROWS', 2)
    groups = [group(f'm:{i}', 'added', newer=[i]) for i in range(1, 4)]
    view = CapabilityView(both([], [(f'r{i}', i, {}) for i in range(1, 4)], groups), groups)
    shown = view.arrange()
    assert shown.groups == () and shown.too_many == 3
    assert resolve_state(StateInputs(has_results=True, delta=view.delta, too_many=3)).text == \
        'Too many rows to display (3). Narrow the filter.'


# ---- grouping and labels ---------------------------------------------------------------------------------------

def label_view():
    attack = TaxonomyLabel(scheme='attack', group='Execution', name='Shared Modules', ident='T1129')
    mbc = TaxonomyLabel(scheme='mbc', group='Data', name='Encode Data', ident='C0026')
    groups = [group('m:a', 'added', newer=[1]), group('m:b', 'added', newer=[2])]
    delta = both([], [('x', 1, {'labels': [attack, mbc]}), ('y', 2, {})], groups)
    return CapabilityView(delta, groups)


def test_attack_and_mbc_labels_group_only_when_chosen():
    view = label_view()
    assert labels(view.arrange(ViewOptions(group_by='attack'))) == [
        'Rule label (grouping only): Execution', 'Rule label (grouping only): none (ATTACK)']
    assert labels(view.arrange(ViewOptions(group_by='mbc')))[0] == 'Rule label (grouping only): Data'
    assert labels(view.arrange(ViewOptions(group_by='namespace'))) == ['host-interaction/x']
    assert labels(view.arrange(ViewOptions(group_by='none'))) == ['All changes']
    for row in view.rows:   # no label text in any table cell
        assert not {'Execution', 'Shared Modules', 'T1129'} & set(f'{row.rule} {row.older} {row.newer} '
                                                                  f'{row.status} {row.pair}'.split())


def test_labels_never_change_classification_or_order():
    view = label_view()
    plain = CapabilityView(view.delta.model_copy(update={'changes': tuple(
        c.model_copy(update={'labels': ()}) for c in view.delta.changes)}), view.groups.values())
    key = lambda v: [(r.rule, r.status) for g in v.arrange().groups for r in g.rows]  # noqa: E731
    assert key(view) == key(plain)


def test_function_pair_grouping_names_the_pair(api):
    shown = api.arrange(ViewOptions(group_by='function-pair'))
    assert 'modified: 0x108b -> 0x1096' in labels(shown)


# ---- states ---------------------------------------------------------------------------------------------------

def delta_with(**fields) -> PairCapabilityDelta:
    base = dict(comparable=True, older_run_id='a', newer_run_id='b', pairing='available',
                coverage=CoverageSummary(matched_groups=1, both_evaluated=1, older_library=0, newer_library=0,
                                         older_not_recovered=0, newer_not_recovered=0, ambiguous_groups=0,
                                         attributed_matches=0, total_matches=0),
                counts={'gained': 1, 'lost': 0, 'moved': 0, 'unchanged': 0, 'not-compared': 0})
    return PairCapabilityDelta(**(base | fields))


@pytest.mark.parametrize(('sid', 'inputs', 'text'), [
    ('C0', StateInputs(project_open=False), 'Open a project to compare capabilities.'),
    ('C1', StateInputs(tool_configured=False), 'capa is not set up. Capability comparison needs the separate '
     'program capa 9.x. PatchTrace never downloads it by itself. Choose an installed capa on the Setup tab or '
     'follow the setup steps there.'),
    ('C2', StateInputs(tool_configured=True), 'No capability results for this project yet. Run capa on the Setup '
     'tab to compare the behaviours capa recognises in the older and the newer file.'),
    ('C3', StateInputs(running=('older', 1)), 'Running capa on the older file (1 of 2). This can take several '
     'minutes per file.'),
    ('C5', StateInputs(failed_side=('newer', 'timeout'), has_results=True),
     "capa did not finish for the newer file (timeout). A missing result is unknown, not 'no capabilities'. No "
     'comparison is shown.'),
    ('C6', StateInputs(assembly_error=('PT-TOOL-STORE', 'row unreadable')), 'Capability results could not be '
     'assembled: PT-TOOL-STORE: row unreadable. Stored capa results are unchanged.'),
    ('C7', StateInputs(stale=True, has_results=True, delta=delta_with()), 'These results describe a different file '
     'pair, capa setup or analysis than the one on screen. Values are kept for reference only. Run capa again to '
     'refresh.'),
    ('C8', StateInputs(has_results=True, delta=delta_with(pairing='unavailable')), 'Function pairs are not '
     'available for this project (no completed comparison), so changes cannot be tied to functions. Totals per '
     'side are shown without pairs.'),
    ('C9', StateInputs(has_results=True, delta=delta_with(counts={'gained': 0, 'lost': 0, 'moved': 0,
                                                                  'unchanged': 3, 'not-compared': 0})),
     'capa recognises the same behaviours in the matched functions of both files. This does not mean the code is '
     'the same: capa only recognises behaviours its rules describe.'),
    ('C10', StateInputs(tool_reason='no --backend option'), 'The configured capa cannot be used: no --backend '
     'option.'),
    ('C13', StateInputs(has_results=True, needs_refresh=True), "Stored capa results predate this panel's coverage "
     'data. Refresh re-reads the saved capa output; capa is not run again.')],
    ids=['c0', 'c1', 'c2', 'c3', 'c5', 'c6', 'c7', 'c8', 'c9', 'c10', 'c13'])
def test_state_texts_are_exact(sid, inputs, text):
    state = resolve_state(inputs)
    assert (state.id, state.text) == (sid, text)


def test_state_c4_c11_c12_and_the_table_flags():
    ready = resolve_state(StateInputs(has_results=True, delta=delta_with()))
    assert (ready.id, ready.table, ready.banner) == ('C4', True, '')
    cut = resolve_state(StateInputs(has_results=True, delta=delta_with(truncated=True), reported_matches=30000,
                                    kept_matches=20000))
    assert cut.id == 'C4' and cut.banner == 'capa reported 30000 matches; PatchTrace kept 20000. The list is ' \
                                            'incomplete.'
    assert resolve_state(StateInputs(has_results=True, delta=delta_with(), stale=True)).table is True
    assert resolve_state(StateInputs(has_results=True, failed_side=('older', 'x'), delta=delta_with())).table is False


def test_precedence_assembly_over_stale_over_unfinished_over_unusable_tool():
    everything = StateInputs(has_results=True, delta=delta_with(), stale=True, failed_side=('older', 'x'),
                             tool_reason='broken', assembly_error=('PT-TOOL-STORE', 'bad'))
    order = []
    for field, value in (('assembly_error', None), ('stale', False), ('failed_side', None)):
        order.append(resolve_state(everything).id)
        everything = dataclasses.replace(everything, **{field: value})
    order.append(resolve_state(dataclasses.replace(everything, has_results=False)).id)
    order.append(resolve_state(everything).id)
    assert order == ['C6', 'C7', 'C5', 'C10', 'C4']


def test_hostile_text_in_state_messages_is_escaped():
    state = resolve_state(StateInputs(assembly_error=('PT-TOOL-X', 'bad‮\x00 <b>text</b>')))
    assert '‮' not in state.text and '\x00' not in state.text and '\\u202e' in state.text


def test_flags_banner_uses_plain_words():
    delta = delta_with(flags=(QualityFlag(code='toolchain-changed', detail='x', source='diec'),
                              QualityFlag(code='packed', detail='y', source='diec')))
    assert capa_view.flags_banner(delta) == ('Comparison may be distorted: a file looks packed; the compiler or '
                                             'linker differs between the files.')
    assert capa_view.flags_banner(delta_with()) == ''


# ---- detail, teach hooks, provenance -------------------------------------------------------------------------

DETAIL_HEADS = ['Change', 'Where', 'Older', 'Newer', 'Why capa matched', 'Rule', 'Rule labels (grouping only)',
                'Cautions', 'Next steps', 'Provenance']


def test_detail_has_fixed_headers_and_the_features_that_made_capa_match(api):
    row = row_for(api, 'write file on Windows')
    text = api.detail(row)
    heads = [line for line in text.split('\n\n') if line.split('\n')[0] in DETAIL_HEADS]
    assert [h.split('\n')[0] for h in heads] == DETAIL_HEADS
    assert 'modified: 0x108b -> 0x1096 (o_108b -> n_1096), match log' in text and 'api ' in text
    assert re.search(r'rule sha256 [0-9a-f]{12}\b', text)
    assert 'capa 9.4.0, executable sha256 eeeeeeeeeeee, built-in rules of capa 9.4.0 (embedded)' in text
    assert capa_view.TEACH['cap.gained'] in text and len(text) <= capa_view.DETAIL_LIMIT


def test_detail_redacts_secret_looking_features_and_escapes_names():
    key = FeatureRef(kind='string', value='AKIAIOSFODNN7EXAMPLE', rva=0x10)
    cell = PairCell(state='present', matches=1, features=(key,))
    change = PairChange.model_construct(
        change_id='c', group_id='m:a', match_id='a', category='added', rule_id='bad‮<b>name</b>', namespace='x/y',
        scope='function', kind='capability', change='gained', noise='none', relocation='none',
        older=PairCell(state='no-function'), newer=cell, labels=(), observation_key='k')
    view = CapabilityView(delta_with(changes=(change,)), [group('m:a', 'added', newer=[0x10])])
    text = view.detail(view.rows[0])
    assert 'AKIAIOSFODNN7EXAMPLE' not in text and '[redacted: aws-access-key]' in text
    assert '‮' not in text and '\\u202e<b>name</b>' in text   # text, never markup


def test_detail_is_bounded():
    feature = FeatureRef(kind='api', value='A' * 120)
    cell = PairCell(state='present', matches=1, features=(feature,) * 16)
    change = PairChange.model_construct(
        change_id='c', group_id='m:a', match_id='a', category='added', rule_id='r' * 256, namespace='n' * 256,
        scope='function', kind='capability', change='gained', noise='none', relocation='none',
        older=PairCell(state='no-function'), newer=cell, labels=(), observation_key='k')
    view = CapabilityView(delta_with(changes=(change,)), [])
    assert len(view.detail(view.rows[0])) <= capa_view.DETAIL_LIMIT


def test_teach_hooks_cover_every_row_kind(api):
    def teach(change: str, older: PairCell, newer: PairCell, **fields) -> str:
        row = capa_view.build_row(PairChange.model_construct(
            change_id='c', group_id='m:a', match_id='a', category='modified', rule_id='r', namespace='n/x',
            scope='function', kind='capability', change=change, noise='none', relocation='none', older=older,
            newer=newer, labels=(), observation_key='k', **fields), {}, {})
        return api.explain(row)[0]
    present, absent, nothing = (PairCell(state='present', matches=1), PairCell(state='absent'),
                                PairCell(state='no-function'))
    library = PairCell(state='not-evaluated', reason='library-function')
    lost_track = PairCell(state='not-evaluated', reason='function-not-recovered')
    cut = PairCell(state='not-evaluated', reason='evidence-truncated')
    assert teach('gained', absent, present) == 'cap.gained'
    assert teach('gained', nothing, present) == 'cap.new_function'
    assert teach('lost', present, absent) == 'cap.lost'
    assert teach('lost', present, nothing) == 'cap.removed_function'
    assert teach('moved', absent, present) == 'cap.moved'
    assert teach('unchanged', present, present) == 'cap.same'
    assert teach('not-compared', library, present) == 'cap.not_compared.library'
    assert teach('not-compared', lost_track, present) == 'cap.not_compared.not_found'
    assert teach('not-compared', present, cut) == 'cap.not_compared.truncated'
    noise = api.explain(dataclasses.replace(row_for(api, 'get hostname'), change=row_for(api, 'get hostname').change
                                            .model_copy(update={'noise': 'detection-difference'})))
    assert noise[0] == 'cap.detection_difference'
    assert set(capa_view.TEACH) >= {'cap.gained', 'cap.moved', 'cap.not_compared.library',
                                    'cap.not_compared.not_found', 'cap.detection_difference',
                                    'cap.unattributed.file', 'cap.unattributed.instruction', 'cap.new_function',
                                    'cap.removed_function'}
    assert all(' Next: ' in text for key, text in capa_view.TEACH.items())


def test_unattributed_items_have_teach_hooks(api):
    keys = {api.explain_unattributed(item)[0] for item in api.delta.unattributed}
    assert keys == {'cap.unattributed.file', 'cap.unattributed.instruction'}


def test_provenance_block_is_deterministic_lf_text(api):
    row = row_for(api, 'write file on Windows')
    text = api.provenance_text(row)
    assert text == api.provenance_text(row) and '\r' not in text and text.endswith('\n')
    lines = text.split('\n')
    assert lines[0] == 'PatchTrace capability change (behaviours recognised by capa rules; says nothing about defects)'
    assert lines[1] == 'Project: demo, analysis run: run-1'
    assert lines[2].startswith('Pair: m:log, match log, modified, older 0x108b ')
    assert lines[3] == 'Change: Gained, rule write file on Windows, scope function, namespace ' \
                       'host-interaction/file-system/write'
    assert lines[4:6] == ['Older: absent', 'Newer: present, 1 match']
    assert lines[6].startswith('capa 9.4.0, executable sha256 ' + 'e' * 64 + ', rules built-in rules of capa 9.4.0 '
                                                                              '(embedded) (embedded:' + 'e' * 64)
    assert lines[7].startswith('Older run run-older artifact sha256 ') and 'newer run run-newer' in lines[7]
    assert 'Cautions:' in lines and any(line.startswith('- capa\'s rules are written mainly') for line in lines)


def test_stale_results_say_so_in_the_copy_block(api):
    stale = CapabilityView(api.delta, api.groups.values(), info=dataclasses.replace(api.info, stale=True))
    assert 'Project: demo, analysis run: run-1, STALE' in stale.provenance_text(row_for(stale, 'terminate process'))


def test_copy_block_is_bounded_to_16_kib():
    row_change = PairChange.model_construct(
        change_id='c', group_id='g' * 160, match_id='a', category='added', rule_id='é' * 256, namespace='n' * 256,
        scope='function', kind='capability', change='gained', noise='none', relocation='none',
        older=PairCell(state='no-function'), newer=PairCell(state='present', matches=1), labels=(),
        observation_key='k')
    view = CapabilityView(delta_with(changes=(row_change,)), [], info=RunInfo('p' * 100_000, 'r' * 100_000))
    assert len(view.provenance_text(view.rows[0]).encode('utf-8')) <= capa_view.CLIPBOARD_LIMIT


def test_accessible_texts_use_the_exact_phrasing(api):
    row = row_for(api, 'write file on Windows')
    assert api.accessible_text(row) == ('Capability write file on Windows, gained, older absent, newer present 1 '
                                        'match, function pair 0x108b to 0x1096')
    added = api.accessible_text(row_for(api, 'query environment variable'))
    assert added.endswith('function pair none to 0x1030')
    group_ = api.arrange().groups[0]
    assert api.group_accessible_text(group_) == f'Namespace {group_.label}, 1 change'
    assert capa_view.ACCESSIBLE_NAMES['tree'] == 'Capability changes by function pair'


def test_go_to_pair_targets_only_stored_matches(api):
    assert api.goto(row_for(api, 'write file on Windows')) == ('log', 'modified: 0x108b -> 0x1096')
    match_id, text = api.goto(row_for(api, 'encode data using XOR'))
    assert match_id is None and text.startswith('unchanged: 0x108e')


def test_rules_label_names_embedded_and_custom_rule_sets():
    assert rules_label(HOST) == 'built-in rules of capa 9.4.0 (embedded)'
    custom = HOST.model_copy(update={'rules_source': 'directory', 'rules_sha256': 'abcd1234' + 'f' * 56})
    assert rules_label(custom) == 'custom folder, digest abcd1234'
    assert rules_label(HOST.model_copy(update={'rules_source': 'none'})) == 'no rule set'


# ---- wording ------------------------------------------------------------------------------------------------

STEMS = ('probab', 'likelihood', 'vulnerab', 'exploit', 'risk', 'threat', 'malicious', 'malware', 'suspicious',
         'dangerous', 'severity', 'critical', 'finding')
WORDS = ('safe', 'secure', 'fix', 'fixed', 'verified', 'proven', 'certain')


def authored_strings(view: CapabilityView) -> list[str]:
    texts = [capa_view.FOOTER, *capa_view.STATE_TEXT.values(), *capa_view.TEACH.values(),
             *capa_view.FLAG_WORDS.values(), *capa_view.REASON_TEXT.values(), *capa_view.UNATTRIBUTED_TEXT.values(),
             *capa_view.ACCESSIBLE_NAMES.values(), *capa_view.LABELS.values(), *(t for _k, t in capa_view.FILTERS),
             *(t for _k, t in capa_view.GROUPINGS), capa_view.CAUTION_RULES, capa_view.CAUTION_SAME,
             capa_view.CAUTION_MOVED, capa_view.CAUTION_NOISE, capa_view.CAUTION_LIBRARY, view.summary(),
             *view.unattributed_lines()]
    for row in view.rows:
        texts += [row.older, row.newer, row.status, row.pair, view.accessible_text(row), view.explain(row)[1],
                  *view.cautions(row)]
    return texts


def test_banned_strings_never_appear(api):
    for text in authored_strings(api):
        lowered = text.lower()
        for stem in STEMS:
            assert not re.search(r'\b' + stem, lowered), (stem, text[:200])
        for word in WORDS:
            assert not re.search(rf'\b{word}\b', lowered), (word, text[:200])


def test_neutral_wording_never_calls_a_change_good_or_bad(api):
    assert set(capa_view.LABELS.values()) == {'Gained', 'Lost', 'Moved', 'Same', 'Not compared'}
    assert capa_view.FOOTER.endswith('so a behaviour may only have moved.')
    assert 'nothing about defects' in capa_view.FOOTER


def test_badges_are_neutral_with_enough_contrast():
    from patchtrace.ui_evidence import contrast_ratio  # the C6 pure helper
    for change, fill in capa_view.BADGE_COLORS.items():
        hue, saturation, _value = colorsys.rgb_to_hsv(*(int(fill[i:i + 2], 16) / 255 for i in (1, 3, 5)))
        assert not ((hue < 0.05 or hue > 0.95) and saturation > 0.3), change   # never red
        assert not (0.2 < hue < 0.45 and saturation > 0.2), change             # never green
        assert contrast_ratio(fill, capa_view.BADGE_TEXT) >= 4.5, change
        assert contrast_ratio(fill, '#161b22') >= 3.0, change
    assert set(capa_view.BADGE_COLORS) == set(capa_view.GLYPHS) == set(capa_view.LABELS)


# ---- bounds and imports ---------------------------------------------------------------------------------------

def bulk_delta(count: int) -> PairCapabilityDelta:
    present, nothing = PairCell(state='present', matches=1), PairCell(state='no-function')
    changes = tuple(PairChange.model_construct(
        change_id=f'c{i}', group_id=f'm:{i}', match_id=str(i), category='added', rule_id=f'rule {i % 997}',
        namespace=f'ns{i % 40}/sub{i % 7}/leaf', scope='function', kind='capability', change='gained', noise='none',
        relocation='none', older=nothing, newer=present, labels=(), observation_key='k') for i in range(count))
    return delta_with(changes=changes)


def test_view_model_for_100000_rows_builds_and_rearranges_inside_the_budget():
    delta = bulk_delta(100_000)
    start = time.perf_counter()
    view = CapabilityView(delta, ())
    built = time.perf_counter() - start
    start = time.perf_counter()
    shown = view.arrange(ViewOptions(search='rule 5'))
    arranged = time.perf_counter() - start
    assert built < 2.0 and arranged < 2.0 and shown.shown > 0
    assert view.arrange().too_many is None


def test_drawing_a_row_needs_no_work_and_detail_is_built_on_demand(monkeypatch):
    calls = []
    original = CapabilityView.detail
    monkeypatch.setattr(CapabilityView, 'detail', lambda self, row: calls.append(row) or original(self, row))
    view = CapabilityView(bulk_delta(2000), ())
    view.arrange()
    row = view.rows[0]
    assert calls == [] and all(type(value) is str for value in (row.rule, row.older, row.newer, row.status, row.pair))


def test_module_imports_no_qt():
    code = (f'import sys; sys.path.insert(0, {str(SRC)!r}); import patchtrace.intelligence.tools.capa_view; '
            "assert not [m for m in sys.modules if m.startswith(('PySide6', 'PyQt'))]")
    subprocess.run([sys.executable, '-I', '-c', code], check=True, timeout=120)


def test_unchanged_rows_need_the_unchanged_filter_and_a_materialised_delta():
    groups = [group('m:a', 'modified', [1], [1])]
    delta = both([('keep', 1, {})], [('keep', 1, {})], groups, include_unchanged=True)
    view = CapabilityView(delta, groups)
    assert view.arrange().shown == 0 and view.arrange(ViewOptions(filter='unchanged')).shown == 1
    assert row_for(view, 'keep').status == '= Same'

