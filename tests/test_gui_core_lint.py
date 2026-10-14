"""GUI core (slice F1): the manifest and spec lint behind `patchtrace panels check` (GUI-integration-plan 8.1, 8.2).

Static rules over manifest slots are checked by examples and by a hypothesis differential test; spec rules by one
failing and one passing example each. Pure and hermetic: specs are built in the tests, nothing is imported.
"""
from __future__ import annotations

from collections import Counter

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui import registry
from patchtrace.gui.registry import (
    AREAS,
    MAX_PANELS,
    CommandSpec,
    Finding,
    Loaded,
    ManifestEntry,
    PanelSpec,
    TeachTopic,
    lint,
    lint_entries,
    load_manifest,
)
from patchtrace.gui.text import CLAIMS_PAIRING
from patchtrace.tooltips import REGISTRY, TooltipEntry

PROPS = settings(max_examples=400, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])


def unused_factory(ctx):
    raise AssertionError('not called here')


def slot(panel_id, area='right', tabify=None, shortcut=None, module=None):
    module = 'patchtrace.fixture.panel' if module is None else module
    return ManifestEntry(panel_id, module, lambda: None, area, tabify, shortcut)


def tip(what, why='Fixture why.', effect='Fixture effect.', **kwargs):
    return TooltipEntry(what, why, effect, **kwargs)


def spec(panel_id='alpha', **overrides):
    tips = overrides.pop('tips', {f'{panel_id}.dock': tip(f'Fixture {panel_id} dock.'),
                                  f'{panel_id}.action': tip(f'Fixture {panel_id} toggle.')})
    fields = dict(id=panel_id, title=panel_id.title(), factory=unused_factory, area='right', tips=tips)
    return PanelSpec(**{**fields, **overrides})


def findings(entries, specs, forbidden=None):
    """Lint with `specs` (a list keyed by spec id, or a dict keyed by manifest id) as the loaded panels."""
    built = specs if isinstance(specs, dict) else {s.id: s for s in specs}
    return lint(entries, Loaded(built, (), {}, forbidden or {}))


def rules(report_or_list):
    items = report_or_list.findings if hasattr(report_or_list, 'findings') else report_or_list
    return Counter((f.rule, f.panel) for f in items)


# ---- manifest slots ---------------------------------------------------------------------------------------------


def test_a_clean_manifest_has_no_findings():
    entries = [slot('evidence', shortcut='Ctrl+Shift+E'), slot('unified', tabify='evidence', shortcut='Ctrl+Shift+U'),
               slot('series', area='bottom'), slot('card', area='none')]
    assert lint_entries(entries) == []
    assert lint_entries([]) == []


def test_findings_are_values_with_a_code_and_a_bounded_plain_message():
    finding = Finding('PT-GUI-MANIFEST', 'search', 'area', 'bad\narea ' + 'x' * 400)
    assert '\n' not in finding.message and len(finding.message) == 200
    assert finding.as_dict() == {'code': 'PT-GUI-MANIFEST', 'panel': 'search', 'rule': 'area',
                                 'message': finding.message}


@pytest.mark.parametrize('bad', ['A', 'a', 'a b', '1ab', 'ab-c', '', 'a' * 25], ids=['upper', 'short', 'space',
                                 'digit', 'dash', 'empty', 'long'])
def test_ids_must_follow_the_grammar(bad):
    assert rules(lint_entries([slot(bad)])) == {('id', bad): 1}


def test_a_duplicate_id_is_reported_on_the_later_entry_only():
    report = lint_entries([slot('alpha'), slot('beta'), slot('alpha')])
    assert [(f.rule, f.panel, f.code) for f in report] == [('duplicate-id', 'alpha', 'PT-GUI-MANIFEST')]


def test_more_than_the_maximum_number_of_panels_is_one_manifest_wide_finding():
    entries = [slot(f'p{i:02d}') for i in range(MAX_PANELS)]
    assert lint_entries(entries) == []
    report = lint_entries([*entries, slot('extra')])
    assert [(f.rule, f.panel) for f in report] == [('count', '')]


def test_unknown_areas_are_findings():
    assert rules(lint_entries([slot('alpha', area='middle'), slot('beta', area='')])) == {
        ('area', 'alpha'): 1, ('area', 'beta'): 1}
    assert lint_entries([slot(f'p{i}x', area=area) for i, area in enumerate(AREAS)]) == []


@pytest.mark.parametrize('module', ['', 'search.panel', 'patchtrace', 'os', 'patchtrace.'], ids=['empty', 'outside',
                         'bare-package', 'stdlib', 'trailing-dot'])
def test_the_module_must_live_inside_patchtrace(module):
    assert rules(lint_entries([slot('alpha', module=module)])) == {('module', 'alpha'): 1}


@pytest.mark.parametrize('shortcut', ['Ctrl+E', 'garbage', 'Ctrl+Shift+1', 'F6', 'Ctrl+Alt+Shift+E', ''],
                         ids=['one-modifier', 'garbage', 'digit', 'function', 'three-modifiers', 'empty'])
def test_panel_shortcuts_must_be_ctrl_shift_letter(shortcut):
    assert rules(lint_entries([slot('alpha', shortcut=shortcut)])) == {('shortcut', 'alpha'): 1}


def test_the_palette_key_is_reserved_in_any_spelling():
    assert rules(lint_entries([slot('alpha', shortcut='ctrl+shift+p')])) == {('reserved-shortcut', 'alpha'): 1}


def test_a_shortcut_taken_in_another_spelling_is_a_duplicate_on_the_later_entry():
    report = lint_entries([slot('alpha', shortcut='Ctrl+Shift+F'), slot('beta', shortcut='shift+ctrl+f'),
                           slot('gamma', shortcut='Ctrl+Shift+G')])
    assert [(f.rule, f.panel) for f in report] == [('duplicate-shortcut', 'beta')]
    assert 'alpha' in report[0].message and 'Ctrl+Shift+F' in report[0].message


def test_a_dockless_slot_has_no_shortcut_and_does_not_tabify():
    report = lint_entries([slot('anchor_a'), slot('card', area='none', shortcut='Ctrl+Shift+C'),
                           slot('chip', area='none', tabify='anchor_a')])
    assert rules(report) == {('none-dock', 'card'): 1, ('none-dock', 'chip'): 1, ('tabify', 'chip'): 1}


@pytest.mark.parametrize('entries,expected', [
    ([slot('alpha'), slot('beta', tabify='alpha')], {}),
    ([slot('alpha'), slot('beta', tabify='missing')], {('tabify', 'beta'): 1}),
    ([slot('alpha', tabify='alpha')], {('tabify', 'alpha'): 1}),
    ([slot('alpha'), slot('beta', tabify='alpha'), slot('gamma', tabify='beta')], {('tabify', 'gamma'): 1}),
    ([slot('alpha', tabify='beta'), slot('beta', tabify='alpha')], {('tabify', 'alpha'): 1, ('tabify', 'beta'): 1}),
    ([slot('alpha', area='left'), slot('beta', area='bottom', tabify='alpha')], {('tabify', 'beta'): 1}),
], ids=['ok', 'unknown-target', 'self', 'chain', 'cycle', 'other-area'])
def test_tabify_targets_must_be_a_real_group_anchor_in_the_same_area(entries, expected):
    assert rules(lint_entries(entries)) == Counter(expected)


def test_hostile_ids_never_put_control_characters_into_messages():
    report = lint_entries([slot('bad\n\x1b[31m' + chr(0x202e), shortcut='x\ny', area='\x00')])
    assert report and all('\n' not in f.message and '\x1b' not in f.message and chr(0x202e) not in f.message
                          for f in report)


# ---- the differential property ----------------------------------------------------------------------------------

IDS = st.sampled_from(['alpha', 'beta', 'gamma', 'delta_1', 'Bad', 'x y', 'a'])
SHORTCUTS = st.sampled_from([None, 'Ctrl+Shift+E', 'ctrl+shift+e', 'Shift+Ctrl+E', 'Ctrl+Shift+F', 'CTRL+SHIFT+F',
                             'Ctrl+Shift+P', 'ctrl+shift+p', 'Ctrl+E', 'F6', 'garbage', 'Ctrl+Shift+1'])
AREA_CHOICES = st.sampled_from([*AREAS, 'bogus'])


def shortcut_letter(shortcut):
    """The letter of a Ctrl+Shift+<letter> shortcut in any case or modifier order, else None."""
    parts = [part.lower() for part in shortcut.split('+')]
    rest = [part for part in parts if part not in ('ctrl', 'shift')]
    ok = len(parts) == 3 and 'ctrl' in parts and 'shift' in parts and len(rest) == 1 and rest[0].isalpha()
    return rest[0] if ok and len(rest[0]) == 1 else None


def expected_findings(rows):
    """The contract restated naively: one pass per rule, no shared code with the implementation."""
    out: Counter = Counter()
    first_by_id: dict[str, tuple] = {}
    claimed: dict[str, str] = {}
    for panel_id, area, tabify, shortcut in rows:
        if not (2 <= len(panel_id) <= 24 and panel_id[0].islower() and panel_id.isascii()
                and all(c.islower() or c.isdigit() or c == '_' for c in panel_id)):
            out[('id', panel_id)] += 1
        if panel_id in first_by_id:
            out[('duplicate-id', panel_id)] += 1
        first_by_id.setdefault(panel_id, (area, tabify))
        if area not in AREAS:
            out[('area', panel_id)] += 1
        if area == 'none' and (shortcut is not None or tabify is not None):
            out[('none-dock', panel_id)] += 1
        if shortcut is None:
            continue
        letter = shortcut_letter(shortcut)
        if letter is None:
            out[('shortcut', panel_id)] += 1
        elif letter == 'p':  # Ctrl+Shift+P is the command palette
            out[('reserved-shortcut', panel_id)] += 1
        elif letter in claimed:
            out[('duplicate-shortcut', panel_id)] += 1
        else:
            claimed[letter] = panel_id
    for panel_id, area, tabify, _ in rows:
        target = None if tabify is None else first_by_id.get(tabify)
        if tabify is not None and (target is None or tabify == panel_id or target[1] is not None
                                   or target[0] != area):
            out[('tabify', panel_id)] += 1
    if len(rows) > 32:
        out[('count', '')] += 1
    return out


@PROPS
@given(st.lists(st.tuples(IDS, AREA_CHOICES, st.none() | IDS, SHORTCUTS), max_size=9))
def test_manifest_rules_equal_the_naive_oracle(rows):
    entries = [slot(i, area, tabify, shortcut) for i, area, tabify, shortcut in rows]
    assert rules(lint_entries(entries)) == expected_findings(rows)


@PROPS
@given(st.lists(st.tuples(IDS, AREA_CHOICES, st.none() | IDS, SHORTCUTS), max_size=9), st.randoms(use_true_random=False))
def test_the_rules_broken_do_not_depend_on_manifest_order(rows, random):
    """Which of two duplicates is "later" (and which entry a tabify target means) depends on order; nothing else."""
    shuffled = list(rows)
    random.shuffle(shuffled)

    def broken(order):
        return {rule for rule, _ in rules(lint_entries([slot(i, a, t, s) for i, a, t, s in order]))} - {'tabify'}

    assert broken(rows) == broken(shuffled)


@PROPS
@given(st.lists(st.from_regex(r'[a-z][a-z0-9_]{1,23}', fullmatch=True), unique=True, max_size=MAX_PANELS),
       st.permutations('abcdefghijklmnopqrstuvwxyz'))
def test_unique_valid_ids_with_unique_valid_shortcuts_are_always_clean(ids, letters):
    letters = [c for c in letters if c != 'p']
    entries = [slot(panel_id, shortcut=f'Ctrl+Shift+{letters[i % 25]}' if i < 25 else None)
               for i, panel_id in enumerate(ids)]
    assert lint_entries(entries) == []


# ---- built specs ------------------------------------------------------------------------------------------------


def test_a_well_formed_spec_is_clean():
    alpha = spec('alpha', shortcut='Ctrl+Shift+A', requires=('project', 'tool:capa'),
                 anchors_in=frozenset({'string'}), anchors_out=frozenset({'function'}),
                 commands=(CommandSpec(id='alpha.focus', title='Focus alpha', run=lambda: None),),
                 teach=(TeachTopic('alpha.first', 'Meaning.', ('Step.',), ('alpha.focus',)),))
    report = findings([slot('alpha', shortcut='Ctrl+Shift+A')], [alpha])
    assert report.findings == () and report.warnings == ()


def test_specs_that_are_not_built_get_only_the_static_rules():
    entries = [slot('alpha'), slot('beta')]
    assert lint(entries, load_manifest([])).findings == ()
    assert lint(entries).findings == ()


@pytest.mark.parametrize('change,rule', [
    (dict(id='wrong'), 'spec-id'),
    (dict(contract=2), 'contract'),
    (dict(title=''), 'title'),
    (dict(title='T' * 33), 'title'),
    (dict(title='Bad\ntitle'), 'title'),
    (dict(area='left'), 'placement'),
    (dict(tabify_with='beta'), 'placement'),
    (dict(shortcut='Ctrl+Shift+Q'), 'placement'),
    (dict(focus_order=99), 'focus-order'),
], ids=['id', 'contract', 'empty-title', 'long-title', 'control-title', 'area', 'tabify', 'shortcut', 'focus'])
def test_spec_must_match_its_manifest_slot(change, rule):
    entries = [slot('alpha', shortcut='Ctrl+Shift+A'), slot('beta')]
    broken = spec('alpha', **{'shortcut': 'Ctrl+Shift+A', **change})
    report = findings(entries, {'alpha': broken})
    assert rules(report) == {(rule, 'alpha'): 1}
    assert {f.code for f in report.findings} == {'PT-GUI-MANIFEST'}


def test_equivalent_spellings_of_the_slot_shortcut_are_fine_on_either_side():
    assert findings([slot('alpha', shortcut='Ctrl+Shift+A')], [spec('alpha', shortcut='shift+CTRL+a')]).findings == ()
    assert findings([slot('alpha', shortcut='ctrl+shift+a')], [spec('alpha', shortcut='Ctrl+Shift+A')]).findings == ()


def test_requirements_must_be_known_capability_ids():
    report = findings([slot('alpha')], [spec('alpha', requires=('project', 'tool:nope', 'wifi'))])
    assert rules(report) == {('requires', 'alpha'): 2} and {f.code for f in report.findings} == {'PT-GUI-CAP'}


# ---- tips -------------------------------------------------------------------------------------------------------


def tip_findings(panel_id='alpha', area='right', **overrides):
    return findings([slot(panel_id, area=area), slot('other')], [spec(panel_id, area=area, **overrides)])


def test_tips_belong_to_the_panel_prefix_and_findings_use_the_tips_code():
    report = tip_findings(tips={'alpha.dock': tip('Fixture alpha dock.'), 'alpha.action': tip('Fixture alpha toggle.'),
                                'beta.table': tip('Fixture beta table.')})
    assert rules(report) == {('tip-prefix', 'alpha'): 1} and {f.code for f in report.findings} == {'PT-GUI-TIPS'}


def test_a_declared_extra_prefix_allows_its_ids_but_only_with_the_trailing_dot():
    tips = {'alpha.dock': tip('Fixture alpha dock.'), 'alpha.action': tip('Fixture alpha toggle.'),
            'viewer.pane': tip('Fixture viewer pane.')}
    assert tip_findings(tips=tips, extra_tip_prefixes=('viewer.',)).findings == ()
    assert rules(tip_findings(tips=tips, extra_tip_prefixes=('viewer',))) == {
        ('tip-prefix', 'alpha'): 1, ('tip-extra-prefix', 'alpha'): 1}


def test_an_extra_prefix_may_extend_an_existing_namespace_but_not_take_another_panels():
    tips = {'alpha.dock': tip('Fixture alpha dock.'), 'alpha.action': tip('Fixture alpha toggle.'),
            'viewer.zz_fixture': tip('Fixture viewer tip.')}
    assert any(key.startswith('viewer.') for key in REGISTRY)  # 'viewer.' tips exist today: adding to them is the use
    assert tip_findings(tips=tips, extra_tip_prefixes=('viewer.',)).findings == ()
    foreign = {**tips, 'other.zz_fixture': tip('Fixture foreign tip.')}
    assert ('tip-extra-prefix', 'alpha') in rules(tip_findings(tips=foreign, extra_tip_prefixes=('other.',)))
    assert ('tip-prefix', 'alpha') in rules(tip_findings(tips=foreign, extra_tip_prefixes=('other.',)))


def test_declaring_ones_own_prefix_as_an_extra_one_is_harmless():
    assert tip_findings(extra_tip_prefixes=('alpha.',)).findings == ()


def test_two_panels_may_not_declare_the_same_extra_prefix():
    one = spec('alpha', extra_tip_prefixes=('viewer.',), tips={
        'alpha.dock': tip('Fixture alpha dock.'), 'alpha.action': tip('Fixture alpha toggle.')})
    two = spec('beta', extra_tip_prefixes=('viewer.',), tips={
        'beta.dock': tip('Fixture beta dock.'), 'beta.action': tip('Fixture beta toggle.')})
    assert ('tip-extra-prefix', 'beta') in rules(findings([slot('alpha'), slot('beta')], [one, two]))


def test_dock_and_toggle_tips_are_required_unless_the_panel_has_no_dock():
    assert rules(tip_findings(tips={})) == {('tip-required', 'alpha'): 2}
    assert rules(tip_findings(tips={'alpha.dock': tip('Fixture alpha dock.')})) == {('tip-required', 'alpha'): 1}
    assert tip_findings(area='none', tips={}).findings == ()


@pytest.mark.parametrize('bad', [
    'text', None, tip('', 'why', 'effect'), tip('what', '', 'effect'), tip('what', 'why', ''),
    tip('Uses <b>markup</b>.'), tip('Fixture alpha dock.', 'Why > this.'),
    tip('Fixture alpha dock.', source='<script>'), tip('Fixture alpha dock.', availability='needs a > b'),
], ids=['string', 'none', 'no-what', 'no-why', 'no-effect', 'angle-brackets', 'greater-than', 'source-line',
        'availability-line'])
def test_tip_entries_must_be_complete_plain_text(bad):
    tips = {'alpha.dock': bad, 'alpha.action': tip('Fixture alpha toggle.')}
    assert rules(tip_findings(tips=tips)) == {('tip-entry', 'alpha'): 1}


def test_what_lines_must_be_unique_inside_the_spec_and_against_existing_tooltips():
    twin = {'alpha.dock': tip('Same words.'), 'alpha.action': tip('Same words.')}
    assert rules(tip_findings(tips=twin)) == {('tip-duplicate', 'alpha'): 1}
    existing = REGISTRY['evidence.dock'].what
    stolen = {'alpha.dock': tip(existing), 'alpha.action': tip('Fixture alpha toggle.')}
    assert rules(tip_findings(tips=stolen)) == {('tip-duplicate', 'alpha'): 1}


def test_registering_an_existing_tip_again_is_idempotent_but_changing_it_conflicts():
    same = {'evidence.dock': REGISTRY['evidence.dock'], 'evidence.action': REGISTRY['evidence.action']}
    assert tip_findings('evidence', tips=same).findings == ()
    changed = {'evidence.dock': tip('Fixture changed evidence dock.'), 'evidence.action': REGISTRY['evidence.action']}
    assert rules(tip_findings('evidence', tips=changed)) == {('tip-conflict', 'evidence'): 1}


def test_a_template_may_not_reuse_a_tip_id_but_follows_the_same_prefix_rules():
    clash = tip_findings(tip_templates={'alpha.dock': tip('Fixture {x} template.')})
    assert rules(clash) == {('tip-conflict', 'alpha'): 1}
    assert tip_findings(tip_templates={'alpha.row': tip('Fixture {x} row template.')}).findings == ()
    assert rules(tip_findings(tip_templates={'beta.row': tip('Fixture {x} row template.')})) == {
        ('tip-prefix', 'alpha'): 1}


# ---- claims, commands, teach, anchors, imports ------------------------------------------------------------------


def claim_findings(**overrides):
    return findings([slot('alpha')], [spec('alpha', claims=CLAIMS_PAIRING, **overrides)])


def test_every_string_the_spec_carries_is_swept_with_its_claims_profile():
    assert claim_findings().findings == ()
    cases = {
        'title': dict(title='Safe view'),
        'tip': dict(tips={'alpha.dock': tip('Shows the fixed bug.'), 'alpha.action': tip('Fixture alpha toggle.')}),
        'command': dict(commands=(CommandSpec(id='alpha.go', title='Verified lookup', run=lambda: None),)),
        'keyword': dict(commands=(CommandSpec(id='alpha.go', title='Go', keywords=('exploit',), run=lambda: None),)),
        'meaning': dict(teach=(TeachTopic('alpha.t', 'Probably a patch.', ('Look.',)),)),
        'step': dict(teach=(TeachTopic('alpha.t', 'Meaning.', ('This is a vulnerability.',)),)),
    }
    for name, change in cases.items():
        assert ('claims', 'alpha') in rules(claim_findings(**change)), name


def test_the_neutral_profile_lets_advisory_vocabulary_through():
    advisory = spec('alpha', tips={'alpha.dock': tip('Lists the advisory vulnerability and exploit text.'),
                                   'alpha.action': tip('Fixture alpha toggle.')})
    assert findings([slot('alpha')], [advisory]).findings == ()


def test_command_rules():
    ok = CommandSpec(id='alpha.go', title='Go', shortcut='Ctrl+Alt+G', run=lambda: None)
    assert findings([slot('alpha')], [spec('alpha', commands=(ok,))]).findings == ()
    cases = {
        'command-id': (CommandSpec(id='beta.go', title='Go', run=lambda: None),),
        'command-duplicate': (ok, CommandSpec(id='alpha.go', title='Again', run=lambda: None)),
        'command-title': (CommandSpec(id='alpha.go', title='', run=lambda: None),),
        'command-title-long': (CommandSpec(id='alpha.go', title='T' * 81, run=lambda: None),),
        'command-framework-key': (CommandSpec(id='alpha.go', title='Go', shortcut='f6', run=lambda: None),),
        'command-shortcut': (CommandSpec(id='alpha.go', title='Go', shortcut='Ctrl+Q+Q', run=lambda: None),),
        'command-reserved': (CommandSpec(id='alpha.go', title='Go', shortcut='ctrl+s', run=lambda: None),),
        'command-taken': (CommandSpec(id='alpha.go', title='Go', shortcut='Ctrl+Shift+A', run=lambda: None),),
    }
    for rule, commands in cases.items():
        report = findings([slot('alpha', shortcut='Ctrl+Shift+A'), slot('beta')],
                          [spec('alpha', shortcut='Ctrl+Shift+A', commands=commands)])
        expected = {'command-title-long': 'command-title', 'command-framework-key': 'command-reserved'}.get(rule, rule)
        assert (expected, 'alpha') in rules(report), rule
    longest = CommandSpec(id='alpha.go', title='T' * 80, run=lambda: None)
    assert findings([slot('alpha')], [spec('alpha', commands=(longest,))]).findings == ()


def test_two_panels_may_not_bind_one_command_shortcut():
    def with_command(name):
        return spec(name, commands=(CommandSpec(id=f'{name}.go', title='Go', shortcut='Ctrl+Alt+G',
                                                run=lambda: None),))
    report = findings([slot('alpha'), slot('beta')], [with_command('alpha'), with_command('beta')])
    assert rules(report) == {('command-taken', 'beta'): 1}


def test_teach_rules():
    ok = TeachTopic('alpha.first', 'M' * 300, ('s' * 200,) * 4)
    assert findings([slot('alpha')], [spec('alpha', teach=(ok,))]).findings == ()
    cases = {
        'teach-id': (TeachTopic('beta.first', 'm', ('s',)),),
        'teach-duplicate': (ok, TeachTopic('alpha.first', 'm', ('s',))),
        'teach-meaning': (TeachTopic('alpha.first', 'M' * 301, ('s',)),),
        'teach-steps': (TeachTopic('alpha.first', 'm', ('s',) * 5),),
        'teach-step': (TeachTopic('alpha.first', 'm', ('s' * 201,)),),
        'teach-empty-step': (TeachTopic('alpha.first', 'm', ('s', '')),),
        'teach-empty': (TeachTopic('alpha.first', '', ('s',)),),
    }
    for rule, topics in cases.items():
        expected = 'teach-step' if rule == 'teach-empty-step' else rule
        assert (expected, 'alpha') in rules(findings([slot('alpha')], [spec('alpha', teach=topics)])), rule


def test_anchor_kinds_are_the_closed_set_and_unhandled_emitted_kinds_only_warn():
    broken = findings([slot('alpha')], [spec('alpha', anchors_in=frozenset({'banana'}), anchors_out=frozenset({'zzz'}))])
    assert rules(broken) == {('anchors', 'alpha'): 2} and broken.warnings == ()
    emits = spec('alpha', anchors_out=frozenset({'string', 'function'}))
    quiet = findings([slot('alpha')], [emits])
    assert quiet.findings == () and len(quiet.warnings) == 1 and 'string' in quiet.warnings[0]
    handler = spec('beta', anchors_in=frozenset({'string'}))
    assert findings([slot('alpha'), slot('beta')], [emits, handler]).warnings == ()  # 'function' is the code panes'


def test_imports_of_qt_or_heavy_libraries_are_a_finding_per_panel():
    report = findings([slot('alpha')], [spec('alpha')], forbidden={'alpha': ('PySide6', 'networkx')})
    assert rules(report) == {('imports', 'alpha'): 1} and report.findings[0].code == 'PT-GUI-MANIFEST'
    assert 'PySide6' in report.findings[0].message and 'networkx' in report.findings[0].message


def test_findings_come_out_in_manifest_order():
    entries = [slot('beta', area='x'), slot('alpha', area='y')]
    assert [f.panel for f in lint_entries(entries)] == ['beta', 'alpha']


def test_module_level_names_exist():
    assert registry.MANIFEST_CODE == 'PT-GUI-MANIFEST' and registry.TIPS_CODE == 'PT-GUI-TIPS'
