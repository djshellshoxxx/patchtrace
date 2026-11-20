"""Independent current-source saved-search boundary controls."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QDialog
from test_ui_search_saved import prepare, rig  # noqa: F401

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.search import saved_actions
from patchtrace.search.query import parse_query
from patchtrace.search.saved import EnrichmentSavedStore, MemorySavedStore, rerun_plan


def test_effective_plan_keeps_every_nonfilter_clause_and_matching_mode():
    queries = (
        'word', 'foo side:older scope:changed', '"side:newer" foo',
        '"two  words" side:older', 'foo -bar', 'kind:function', 'std::vector foo',
        'ReadItem 0x140001000', 'prefix* scope:changed', 'is:modified kind:function',
    )
    for text in queries:
        for mode in ('auto', 'words', 'exact', 'prefix', 'substring', 'similar'):
            original = parse_query(text, mode=mode)
            recovered = saved_actions.effective_plan(text, mode=mode)
            assert recovered.model_dump(exclude={'text'}) == original.model_dump(exclude={'text'})
            store = MemorySavedStore()
            item = store.save('Independent query', recovered)
            assert rerun_plan(item).digest() == recovered.digest()


def test_saved_modal_revision_change_refuses_write_to_same_project(rig, monkeypatch):  # noqa: F811
    controller = rig.controller
    prepare(controller)
    service = rig.port.service

    def changed():
        service.project = service.project.model_copy(update={'revision': service.project.revision + 1})
        controller.saved.widgets.name_dialog.name.setText('Stale revision')
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(controller.saved.widgets.name_dialog, 'exec', changed)
    controller.saved.save_current()
    store = EnrichmentSavedStore(EnrichmentStore(service.store), service.project.id)
    assert store.list().items == ()
    assert 'project changed' in controller.saved.widgets.note.text().lower()
    assert rig.calls == []


@pytest.mark.parametrize('action', ['save', 'run', 'delete'])
def test_shutdown_refuses_saved_mutations_and_query_execution(rig, action):  # noqa: F811
    controller = rig.controller
    prepare(controller)
    controller.saved.save_current('Original')
    store = EnrichmentSavedStore(EnrichmentStore(rig.port.service.store), rig.port.service.project.id)
    original = store.list().items
    controller.shutdown()
    if action == 'save':
        controller.saved.save_current('After shutdown')
    elif action == 'run':
        controller.saved.run_selected()
    else:
        controller.saved.delete_selected()
    assert store.list().items == original
    assert rig.calls == []
