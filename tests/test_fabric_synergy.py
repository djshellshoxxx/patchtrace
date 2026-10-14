"""FAB-0 synergy test (docs/specs/program-e/FAB-integration-plan.md s5): one advisory hint met by independent channels.

Synthetic and in code. A project holds two changed function pairs, F and G. Both newly call `RtlULongAdd`, and an
advisory hints at that API for CWE-190. For F the call is reported by capa's vivisect backend and by Ghidra call
labels (two independent origins); for G by capa's Ghidra backend and the same Ghidra call labels (one origin). The
join (hint, observed anchors by key, origin components) says more than any channel alone. Nothing here is live evidence.
"""
from __future__ import annotations

import fabric_support as fs
import pytest

from patchtrace.fabric import ids, origins
from patchtrace.fabric.contracts import AnchorQuery
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.memory import MemoryAnchorStore

P = 'proj-synergy'
F_PAIR = fs.pair_key()
G_PAIR = fs.pair_key(older=(fs.G_OLD,), newer=(fs.G_NEW,))
F_NEW_IMAGE = ids.image_key(fs.NEWER, fs.F_NEW)
API = 'RtlULongAdd'


def pairs_by_ue():
    return [fs.pair_anchor(batch='ue1'), fs.pair_anchor(older=(fs.G_OLD,), newer=(fs.G_NEW,), batch='ue1')]


def cap_vivisect():
    return [fs.anchor('capability', 'create process', 'newer', 'observed', subject=F_PAIR, batch='cap1'),
            fs.import_anchor(API, subject=F_PAIR, batch='cap1')]


def ue_call_sets():
    return [fs.import_anchor(API, subject=F_PAIR, producer='ue', source='call-label', batch='calls1'),
            fs.import_anchor(API, subject=G_PAIR, producer='ue', source='call-label', batch='calls1')]


def cap_ghidra_for_g():
    return [fs.import_anchor(API, subject=G_PAIR, source='capa-ghidra', batch='cap2')]


def pe_import_delta():
    return [fs.import_anchor(API, producer='wbq', source='pe-import', batch='pe1')]


def strings_of_f():
    return [fs.anchor('string', ids.string_key('integer overflow'), 'newer', 'observed', subject=F_NEW_IMAGE,
                      producer='wb3', source='floss', batch='str1')]


def advisory():
    sources = (('kb', 'advisory-text', 'adv1'), ('kb', 'nvd-cwe', 'adv2'), ('kb', 'msrc-cwe', 'adv3'),
               ('kev', 'kev-cwe', 'adv4'))
    cwe = [fs.cwe_anchor(190, producer=p, source=s, batch=b) for p, s, b in sources]
    hint = fs.import_anchor(API, role='hint', producer='kb', source='advisory-text', batch='adv1')
    return [*cwe, hint]


def full_store(project: str = P) -> MemoryAnchorStore:
    s = MemoryAnchorStore()
    s.bind_pair(project, fs.OLDER, fs.NEWER)
    for batch in (pairs_by_ue(), cap_vivisect(), ue_call_sets(), cap_ghidra_for_g(), pe_import_delta(), strings_of_f(),
                  advisory()):
        s.publish(project, batch)
    return s


def observed_components(s: MemoryAnchorStore, subject: str | None) -> int:
    """Independent origin components over every observed import anchor about `subject` (the join, not a score)."""
    found = s.find(P, AnchorQuery(kind='import', key='rtlulongadd', role='observed')).items
    return origins.independent_count(w.origins for a in found if a.subject == subject for w in a.witnesses)


def hint_met_by(s: MemoryAnchorStore, subject: str) -> int:
    hints = s.find(P, AnchorQuery(kind='import', key='rtlulongadd', role='hint')).items
    return observed_components(s, subject) if hints else 0


def test_one_api_three_channels_count_independently():
    s = full_store()
    f_import = s.get(P, fs.import_anchor(API, subject=F_PAIR).anchor_id)
    g_import = s.get(P, fs.import_anchor(API, subject=G_PAIR).anchor_id)
    assert len(f_import.witnesses) == 2 and len(origins.anchor_components(f_import)) == 2
    assert len(g_import.witnesses) == 2 and len(origins.anchor_components(g_import)) == 1

    cwe = s.get(P, fs.cwe_anchor(190).anchor_id)
    assert len(cwe.witnesses) == 4 and origins.anchor_components(cwe) == (('D_vendor_text',),)

    by_key = s.find(P, AnchorQuery(kind='import', key='rtlulongadd')).items
    expected = [('observed', None), *[('observed', subject) for subject in sorted((F_PAIR, G_PAIR))], ('hint', None)]
    assert [(a.role, a.subject) for a in by_key] == expected  # the file-level, F's and G's observations, then the hint

    about_f = s.find(P, AnchorQuery(subject=F_PAIR)).items
    assert sorted(a.kind for a in about_f) == ['capability', 'import', 'string']  # the string via the pair's member
    assert all(a.subject in (F_PAIR, F_NEW_IMAGE) for a in about_f)

    assert hint_met_by(s, F_PAIR) == 2 and hint_met_by(s, G_PAIR) == 1


@pytest.mark.parametrize('channel,expected', [('cap', 1), ('ue', 1), ('kb', 0), ('pairs', 0)],
                         ids=['cap-alone', 'ue-alone', 'kb-alone', 'pairs-alone'])
def test_each_channel_alone_cannot_say_what_the_join_says(channel, expected):
    batches = {'cap': [pairs_by_ue(), cap_vivisect()], 'ue': [pairs_by_ue(), ue_call_sets()],
               'kb': [advisory()], 'pairs': [pairs_by_ue()]}[channel]
    s = MemoryAnchorStore()
    for batch in batches:
        s.publish(P, batch)
    observed = observed_components(s, F_PAIR)
    assert observed == expected
    assert hint_met_by(s, F_PAIR) == 0  # the hint and the observed evidence never meet inside one channel


def test_a_third_independent_channel_adds_a_component_and_a_repeat_does_not():
    s = full_store()
    s.publish(P, [fs.import_anchor(API, subject=F_PAIR, producer='wbq', source='pe-import', batch='pe2')])
    assert hint_met_by(s, F_PAIR) == 3
    s.publish(P, [fs.import_anchor(API, subject=F_PAIR, producer='core', source='pairing', batch='core1')])
    assert hint_met_by(s, F_PAIR) == 3  # D_ghidra again: the same component as the call labels


def test_swapping_older_and_newer_is_rejected_and_changes_nothing():
    swapped = MemoryAnchorStore()
    swapped.bind_pair(P, fs.NEWER, fs.OLDER)
    with pytest.raises(FabricError) as info:
        swapped.publish(P, pairs_by_ue())
    assert (info.value.code, info.value.reason) == ('PT-FAB-ORIENTATION', 'orientation-swapped')
    with pytest.raises(FabricError) as info:
        swapped.publish(P, cap_vivisect())  # one-sided observations of the newer image, claimed for the older side
    assert info.value.code == 'PT-FAB-ORIENTATION'
    assert swapped.find(P, AnchorQuery()).total == 0


def test_missing_evidence_is_unknown_not_absent():
    s = full_store()
    assert s.resolve(P, 'capability', 'create process', 'newer').status == 'found'
    only_pairs = MemoryAnchorStore()
    only_pairs.publish(P, pairs_by_ue())
    assert only_pairs.resolve(P, 'capability', 'create process', 'newer').status == 'unknown'
    assert only_pairs.resolve(P, 'import', API, 'newer').status == 'unknown'


def test_republishing_one_batch_replaces_only_that_batch():
    s = full_store()
    s.publish(P, [fs.import_anchor(API, subject=F_PAIR, batch='cap1')])  # CAP now reports one anchor
    assert s.resolve(P, 'capability', 'create process', 'newer').status == 'unknown'
    assert len(s.get(P, fs.import_anchor(API, subject=F_PAIR).anchor_id).witnesses) == 2  # the call labels remain
    assert s.resolve(P, 'cwe', '190', None).status == 'found' and hint_met_by(s, F_PAIR) == 2
