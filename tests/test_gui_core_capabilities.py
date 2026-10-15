"""GUI core (slice F1): capability ids, states and the requires check (GUI-integration-plan 7 and 8.2). Pure."""
from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.gui.capabilities import (
    CAP_CODE,
    KINDS,
    Availability,
    CapabilityState,
    check,
    is_capability_id,
)

PROPS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])


class FakeProvider:
    """Answers from a table; anything not listed is `missing`. Records what was asked, in order."""

    def __init__(self, states=None):
        self.states = states or {}
        self.asked: list[str] = []

    def capability(self, capability_id):
        self.asked.append(capability_id)
        return self.states.get(capability_id, CapabilityState('missing'))


@pytest.mark.parametrize('text', [
    'project', 'run', 'idle', 'tool:capa', 'tool:floss', 'tool:diec', 'tool:yara-x', 'engine:bindiff',
    'engine:rzdiff', 'feature:kev_fetch', 'feature:a', 'feature:x-1_b', 'os:windows',
], ids=['project', 'run', 'idle', 'capa', 'floss', 'diec', 'yara', 'bindiff', 'rzdiff', 'flag', 'short-flag',
        'flag-chars', 'windows'])
def test_known_capability_ids(text):
    assert is_capability_id(text)


@pytest.mark.parametrize('text', [
    '', 'Project', 'projects', 'tool', 'tool:', 'tool:capaa', 'tool:Capa', 'engine:ghidra', 'os:linux', 'os:',
    'feature:', 'feature:1x', 'feature:Upper', 'feature:' + 'a' * 33, 'tool: capa', ' project', 'project ',
    'tool:capa:x', None, 5,
], ids=['empty', 'case', 'plural', 'bare-tool', 'empty-tool', 'unknown-tool', 'tool-case', 'unknown-engine',
        'other-os', 'empty-os', 'empty-flag', 'digit-first', 'upper-flag', 'long-flag', 'inner-space',
        'leading-space', 'trailing-space', 'extra-colon', 'none', 'int'])
def test_everything_else_is_not_a_capability_id(text):
    assert not is_capability_id(text)


def test_state_kinds_are_the_documented_five():
    assert KINDS == ('available', 'missing', 'unsupported', 'unchecked', 'policy')
    assert CAP_CODE == 'PT-GUI-CAP'


def test_state_defaults_and_validation():
    assert CapabilityState() == CapabilityState('available', '', None)
    with pytest.raises(ValueError):
        CapabilityState('broken')


def test_state_text_is_sanitized_and_bounded():
    state = CapabilityState('missing', 'tool\nnot found ' + 'x' * 400, 'patchtrace intel-tools probe\x1b[0m')
    assert '\n' not in state.reason and len(state.reason) == 200
    assert state.remedy_command == 'patchtrace intel-tools probe[0m'


def test_no_requirements_is_available_without_asking_anyone():
    provider = FakeProvider()
    assert check((), provider) == Availability(True)
    assert provider.asked == []


def test_all_available_is_available():
    provider = FakeProvider({'project': CapabilityState(), 'tool:capa': CapabilityState()})
    assert check(('project', 'tool:capa'), provider).enabled
    assert provider.asked == ['project', 'tool:capa']


def test_the_first_blocker_wins_and_later_requirements_are_not_probed():
    provider = FakeProvider({
        'project': CapabilityState(),
        'run': CapabilityState('unchecked', 'No analysis run yet.', 'patchtrace rank <project>'),
        'tool:capa': CapabilityState('missing', 'capa was not found.')})
    result = check(('project', 'run', 'tool:capa'), provider)
    assert result == Availability(False, 'No analysis run yet.', 'patchtrace rank <project>', CAP_CODE)
    assert provider.asked == ['project', 'run']


@pytest.mark.parametrize('kind,expected', [
    ('missing', 'tool:capa is not available.'),
    ('unsupported', 'tool:capa is not supported here.'),
    ('unchecked', 'tool:capa has not been checked yet.'),
    ('policy', 'tool:capa is turned off.'),
], ids=list(KINDS[1:]))
def test_a_blocker_without_a_reason_gets_a_default_per_kind(kind, expected):
    result = check(('tool:capa',), FakeProvider({'tool:capa': CapabilityState(kind)}))
    assert (result.enabled, result.reason, result.code) == (False, expected, CAP_CODE)


def test_an_unknown_requirement_blocks_and_is_never_sent_to_the_provider():
    provider = FakeProvider()
    result = check(('tool:nope',), provider)
    assert (result.enabled, result.code) == (False, CAP_CODE) and 'tool:nope' in result.reason
    assert provider.asked == []


def test_hostile_requirement_text_is_sanitized_in_the_reason():
    result = check(('<b>x</b>\nVerdict',), FakeProvider())
    assert '\n' not in result.reason and not result.enabled


@PROPS
@given(st.lists(st.sampled_from(['project', 'run', 'idle', 'tool:capa', 'engine:bindiff', 'os:windows']),
                max_size=6),
       st.sets(st.sampled_from(['project', 'run', 'idle', 'tool:capa', 'engine:bindiff', 'os:windows'])))
def test_check_is_enabled_exactly_when_every_requirement_is_available(requires, available):
    provider = FakeProvider({name: CapabilityState() for name in available})
    result = check(requires, provider)
    assert result.enabled == all(name in available for name in requires)
    assert result.enabled == (result.code is None)
