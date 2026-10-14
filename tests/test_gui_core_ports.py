"""GUI core (slice F1): the four ports and the legacy WindowPort union as structural Protocols (plan 8.2)."""
from __future__ import annotations

import pytest

from patchtrace.gui.ports import MutationPort, NavigationPort, ProjectPort, ShellPort, WindowPort

MEMBERS = {
    ProjectPort: {'key', 'project', 'busy', 'artifact_paths', 'match_index'},
    MutationPort: {'annotate', 'review_match'},
    NavigationPort: {'select_match', 'reveal_lines', 'show_raw_offset', 'show_pair', 'navigate', 'focus_panel', 'back',
                     'forward'},
    ShellPort: {'status', 'announce', 'notice', 'settings', 'theme', 'tasks', 'copy_text', 'choose_file', 'spotlight'},
}


def members(protocol):
    return {name for base in protocol.__mro__ for name in vars(base) if not name.startswith('_')}


@pytest.mark.parametrize('port', list(MEMBERS), ids=lambda port: port.__name__)
def test_each_port_has_the_members_of_the_plan(port):
    assert members(port) == MEMBERS[port]


def test_the_window_port_is_the_union_of_the_four_for_legacy_code():
    assert members(WindowPort) == set().union(*MEMBERS.values())


def make_window(without=()):
    """An object that has every member of every port except those named."""
    namespace = {name: (lambda self, *a, **k: None) for names in MEMBERS.values() for name in names}
    for name in ('settings', 'theme', 'tasks'):
        namespace[name] = property(lambda self: None)
    for name in without:
        namespace.pop(name)
    return type('FakeWindow', (), namespace)()


def test_a_complete_object_satisfies_every_port_and_the_union():
    window = make_window()
    for port in (*MEMBERS, WindowPort):
        assert isinstance(window, port)


@pytest.mark.parametrize('missing,satisfied', [
    ('key', {MutationPort, NavigationPort, ShellPort}),
    ('review_match', {ProjectPort, NavigationPort, ShellPort}),
    ('back', {ProjectPort, MutationPort, ShellPort}),
    ('announce', {ProjectPort, MutationPort, NavigationPort}),
    ('tasks', {ProjectPort, MutationPort, NavigationPort}),
], ids=['project-port', 'mutation-port', 'navigation-port', 'shell-method', 'shell-property'])
def test_a_missing_member_breaks_only_its_port_and_the_union(missing, satisfied):
    window = make_window(without=(missing,))
    assert {port for port in MEMBERS if isinstance(window, port)} == satisfied
    assert not isinstance(window, WindowPort)
