"""Deferred worker callbacks cannot certify an old visible lead using a newer receipt."""
from __future__ import annotations

from dataclasses import replace

import pytest
from leads_support import CVE_A, lead_of
from pilot_freshness_support import add_advisory
from test_ui_leads import put, real_start, settle

from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.qt.tasks import CancelToken
from patchtrace.pilot import current_inputs
from patchtrace.service import ProjectService


@pytest.fixture
def displayed(qtbot, tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        old = put(service)
        lead = lead_of(old, 'read_item', CVE_A)
        match = next(m for m in service.project.matches if m.older and m.older[0].name == 'read_item')
        controller, nav, shell, _project = real_start(
            qtbot, service, resolver=lambda _root, _snapshot, _token: {lead.candidate_key: match.id})
        controller.select_key(f'{CVE_A}|{lead.candidate_key}')
        assert controller.model.assessment == old
        yield service, old, lead, controller, nav, shell


def defer(controller, monkeypatch, channel):
    pending = []
    submit = controller.tasks.submit

    def delay(name, *args, **kwargs):
        if name == channel:
            pending.append((args[0], args[1]))
            return None
        return submit(name, *args, **kwargs)

    monkeypatch.setattr(controller.tasks, 'submit', delay)
    return pending


def replacement(service):
    add_advisory(service, revision=2, cves=(CVE_A,))
    return put(service)


@pytest.mark.parametrize('action', ['button', 'direct', 'evidence-line', 'anchor'])
def test_pending_replacement_refuses_old_locations_without_staling_new_receipt(displayed, monkeypatch, action):
    service, old, lead, controller, nav, shell = displayed
    new = replacement(service)
    assert new.result_id != old.result_id
    pending = defer(controller, monkeypatch, 'leads.build')
    controller.reload()
    assert pending and controller.stored.loaded.assessment == new
    assert controller.model.assessment == old
    if action == 'button':
        assert not controller.panel.buttons['goto'].isEnabled()
    elif action == 'direct':
        controller.go()
    elif action == 'evidence-line':
        found = next(o for o in controller.model.observations(controller.current_row()) if o.nav is not None)
        controller._observation_activated(found.obs_id)
    else:
        found = controller.model.observations(controller.current_row())[0]
        obs = controller.model.pool[found.obs_id]
        controller.model.pool[found.obs_id] = obs.model_copy(update={'anchor_ids': ('advisory_phrase:authored',)})
        controller._open_anchor(replace(found, nav=None))
    assert not nav.selected and not nav.revealed and not nav.anchors
    assert controller.stored.loaded.state == 'current'
    assert current_inputs.capture(service, EnrichmentStore(service.store)).changed(new) == ()
    controller.copy_explanation()
    assert shell.copied and 'Summary' in shell.copied[-1]

    work, accept = pending.pop()
    accept(work(CancelToken(), lambda *_args: None))
    assert controller.model.assessment == new
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    assert controller.panel.buttons['goto'].isEnabled()
    controller.go()
    assert nav.selected and controller.stored.loaded.state == 'current'


def test_failed_reload_cannot_authorize_retained_view_without_a_receipt(displayed):
    _service, old, _lead, controller, nav, shell = displayed

    def unavailable(*_args):
        raise EnrichmentError('PT-ENRICH-INPUT', 'authored missing receipt')

    controller.loader = unavailable
    controller.reload()
    assert controller.model.assessment == old and controller.stored is None
    controller.go()
    assert not nav.selected and not nav.revealed and not nav.anchors
    assert not controller.panel.buttons['goto'].isEnabled()
    controller.copy_explanation()
    assert shell.copied and 'Summary' in shell.copied[-1]


def test_late_rows_from_an_old_model_cannot_replace_current_rows(displayed, monkeypatch, qtbot):
    service, old, lead, controller, _nav, _shell = displayed
    pending = defer(controller, monkeypatch, 'leads.rows')
    controller._refilter()
    work, accept = pending.pop()
    old_rows = work(CancelToken(), lambda *_args: None)
    new = replacement(service)
    controller.reload()
    settle(qtbot, controller)
    assert controller.model.assessment == new and new.result_id != old.result_id
    controller.select_key(f'{CVE_A}|{lead.candidate_key}')
    visible = controller.current_row()
    assert any(visible.lead is item for item in controller.model.assessment.leads)

    accept(old_rows)
    assert controller.current_row() is visible
    assert controller.stored.loaded.state == 'current'


def test_late_build_cannot_install_after_its_receipt_became_unavailable(displayed, monkeypatch):
    service, old, _lead, controller, _nav, _shell = displayed
    replacement(service)
    pending = defer(controller, monkeypatch, 'leads.build')
    controller.reload()
    work, accept = pending.pop()
    ready = work(CancelToken(), lambda *_args: None)

    def unavailable(*_args):
        raise EnrichmentError('PT-ENRICH-INPUT', 'authored missing receipt')

    controller.loader = unavailable
    controller.reload()
    assert controller.stored is None and controller.model.assessment == old
    accept(ready)
    assert controller.stored is None and controller.model.assessment == old
