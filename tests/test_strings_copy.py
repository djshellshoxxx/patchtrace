"""WB3-S7a copy: fixed wording, one teach entry per id, banned-word sweep, tooltip entries."""
from __future__ import annotations

import re
from typing import get_args

import pytest

from patchtrace.secondary.evidence_view import BANNED
from patchtrace.strings import copy
from patchtrace.strings.contracts import CUES, ChangeStatus, LinkTier
from patchtrace.strings.rank import REASONS
from patchtrace.strings.tooltip_entries import ENTRIES
from patchtrace.tooltips import TooltipEntry

EXPECTED_TIPS = (
    ['strings.dock', 'strings.action', 'strings.table', 'strings.export']
    + [f'strings.col.{k}' for k in 'change string type older newer function cues source'.split()]
    + [f'strings.filter.{k}' for k in 'change type side cue minlen text linked scope noise'.split()]
    + [f'strings.run.{k}' for k in ('builtin', 'floss', 'emulation')]
    + [f'strings.{k}' for k in 'cancel probe browse basis detail rescan'.split()]
    + ['strings.copy.safe', 'strings.copy.exact', 'strings.open.function', 'strings.open.hex'])


def assert_no_banned(text: str) -> None:
    lowered = text.lower()
    for word in BANNED:  # stems match as prefixes, the rest as whole words ('provenance' is fine)
        tail = '' if word in ('probab', 'vulnerab', 'exploit', 'likelihood') else r'\b'
        assert not re.search(r'\b' + re.escape(word) + tail, lowered), (word, text[:200])
    assert '%' not in text, text[:200]


def all_visible_text() -> list[str]:
    texts = [*copy.CHANGE_LABELS.values(), *copy.TYPE_LABELS.values(), *copy.TYPE_NOUNS.values(),
             *copy.CUE_LABELS.values(), *copy.PAIR_LABELS.values(), *copy.STATES.values(), *copy.ACTIONS.values(),
             *copy.SCOPES.values()]
    texts += [part for pair in copy.TEACH.values() for part in pair]
    texts += [part for entry in ENTRIES.values() for part in entry]
    return texts


def test_every_id_has_teach_text():
    wanted = ({f'strings.cue.{c}' for c in CUES} | {f'strings.reason.{r}' for r in REASONS}
              | {f'strings.link.{t}' for t in get_args(LinkTier)} | {f'strings.state.{s}' for s in copy.STATES})
    assert set(copy.TEACH) == wanted
    assert all(len(pair) == 2 and all(pair) for pair in copy.TEACH.values())


def test_labels_cover_every_vocabulary():
    assert set(copy.CHANGE_LABELS) == set(get_args(ChangeStatus))
    assert set(copy.CUE_LABELS) == set(CUES)


def test_banned_words():
    for text in all_visible_text():
        assert_no_banned(text)


def test_change_labels_carry_a_glyph_and_a_word():
    for label in copy.CHANGE_LABELS.values():
        assert label[0] in '+-~=?' and label[1] == ' ' and label[2:].strip()


def test_state_text_is_exact_for_the_card():
    assert copy.STATES['no-project'] == 'Open a project to compare the strings of two builds.'
    assert copy.STATES['failed'].endswith('Earlier results were not changed.')


@pytest.mark.parametrize('tip_id', EXPECTED_TIPS)
def test_tooltip_entries_follow_the_card(tip_id):
    what, why, effect, source, availability = ENTRIES[tip_id]
    assert what and why and effect
    rendered = TooltipEntry(what, why, effect, source, availability).render()
    assert len(rendered) <= 450 and '{' not in rendered
    assert_no_banned(rendered)


def test_tooltip_ids_are_exactly_the_card_list():
    assert sorted(ENTRIES) == sorted(EXPECTED_TIPS) and len(set(EXPECTED_TIPS)) == len(EXPECTED_TIPS)
